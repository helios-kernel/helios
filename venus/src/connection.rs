//! Ordered command and reply streams for one Venus renderer context.

use core::num::{NonZeroU64, NonZeroUsize};
use core::ptr::null;
use core::time::Duration;

use crate::capset::Capset;
use crate::protocol::{
    VK_STRUCTURE_TYPE_RING_CREATE_INFO_MESA, VkCommandStreamDescriptionMESA, VkDeviceMemory,
    VkRingCreateInfoMESA, vn_encode_vkCreateRingMESA, vn_encode_vkDestroyRingMESA,
    vn_encode_vkExecuteCommandStreamsMESA, vn_encode_vkNotifyRingMESA,
    vn_encode_vkSetReplyCommandStreamMESA, vn_encode_vkWaitRingSeqnoMESA,
};
use crate::ring::{Layout, Ring, RingError};
use crate::transport::{
    Completion, MappedBlob, SignalPoint, SignalTimeline, Timeline, TimelinePoint, Transport,
    WaitPoint,
};
use crate::{DecodeError, EncodeError, Encoder, RendererProtocol};

/// Mesa reserves 256 bytes for its largest inline transport command,
/// `vkCreateRingMESA`; Helios's inline execute contract uses the same size.
const INLINE_BYTES: usize = 256;
/// Virtio GPU permits 64 context fencing timelines, including CPU ring 0.
const TIMELINES: usize = 64;

struct InlineCommand {
    bytes: [u8; INLINE_BYTES],
    length: usize,
}

impl core::ops::Deref for InlineCommand {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error<E: std::error::Error> {
    #[error("renderer transport failed: {0}")]
    Transport(#[source] E),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Ring(#[from] RingError),
    #[error("renderer requires guest VRAM instead of host blob storage")]
    GuestVram,
    #[error("renderer does not support multiple fencing timelines")]
    Timelines,
    #[error("Venus command serialization and transport extension versions must be nonzero")]
    ProtocolVersion,
    #[error("ring idle timeout does not fit the protocol's nanosecond counter")]
    IdleTimeout,
    #[error("renderer mapping has {actual} bytes; {required} were requested")]
    MappingSize { required: usize, actual: usize },
    #[error("renderer acknowledged ring sequence {sequence} before consuming it")]
    IncompleteWait { sequence: u32 },
    #[error("Vulkan object identifiers are exhausted")]
    ObjectIds,
    #[error("fence identifiers are exhausted on ring {ring}")]
    FenceIds { ring: u8 },
    #[error("ring {ring} exceeds the virtio GPU timeline range")]
    Timeline { ring: u8 },
}

struct QueueTimeline<S: SignalTimeline> {
    source: S,
    reader: S::Timeline,
}

impl<S: SignalTimeline> QueueTimeline<S> {
    fn new() -> Self {
        let source = S::new(0);
        let reader = source.reader();
        Self { source, reader }
    }
}

/// Single owner of the renderer's command ring. The transport is destroyed
/// before its mapped blobs, so dropping a connection ends the context even
/// when a command failed. `close` additionally destroys the Venus ring and
/// confirms completion before returning the transport to its caller.
pub struct Connection<T: Transport> {
    transport: T,
    ring: Ring<'static>,
    _ring_blob: T::Blob,
    uploads: Vec<T::Blob>,
    reply: Option<T::Blob>,
    protocol: RendererProtocol,
    ring_id: u64,
    next_object: u64,
    fences: [u64; TIMELINES],
    signals: [Option<QueueTimeline<T::Signal>>; TIMELINES],
}

impl<T: Transport> Connection<T> {
    pub fn new(
        mut transport: T,
        capset: Capset,
        layout: Layout,
        idle_timeout: Duration,
    ) -> Result<Self, Error<T::Error>> {
        if capset.guest_vram {
            return Err(Error::GuestVram);
        }
        if !capset.multiple_timelines {
            return Err(Error::Timelines);
        }
        if capset.serialization_version == 0 || capset.venus_version == 0 {
            return Err(Error::ProtocolVersion);
        }
        let idle_timeout =
            u64::try_from(idle_timeout.as_nanos()).map_err(|_| Error::IdleTimeout)?;
        let ring_blob = transport
            .create_blob(NonZeroU64::new(layout.size() as u64).unwrap(), 0)
            .map_err(Error::Transport)?;
        check_size::<T>(&ring_blob, layout.size())?;
        // SAFETY: MappedBlob supplies the aligned coherent mapping. The
        // owning blob stays in this connection, after `ring`, and the ring
        // borrow never escapes it. Registration happens only below.
        let ring = unsafe { Ring::new(ring_blob.pointer(), layout) };
        // The first identifier belongs to the ring; every subsequent
        // renderer object is allocated from the same connection-local space.
        let ring_id = 1;
        let info = VkRingCreateInfoMESA {
            sType: VK_STRUCTURE_TYPE_RING_CREATE_INFO_MESA,
            pNext: null(),
            flags: 0,
            resourceId: ring_blob.resource_id(),
            offset: 0,
            size: layout.size(),
            idleTimeout: idle_timeout,
            headOffset: Layout::HEAD,
            tailOffset: Layout::TAIL,
            statusOffset: Layout::STATUS,
            bufferOffset: Layout::BUFFER,
            bufferSize: layout.capacity() as usize,
            extraOffset: layout.size(),
            extraSize: 0,
        };
        let mut connection = Self {
            transport,
            ring,
            _ring_blob: ring_blob,
            uploads: Vec::new(),
            reply: None,
            protocol: capset.protocol,
            ring_id,
            next_object: ring_id + 1,
            fences: [0; TIMELINES],
            signals: core::array::from_fn(|_| None),
        };
        let command = connection.inline(|encoder| {
            // SAFETY: all fields of info describe the owned ring mapping.
            unsafe { vn_encode_vkCreateRingMESA(encoder, 0, ring_id, &info) };
        })?;
        connection.execute_and_wait(&command, 0)?;
        Ok(connection)
    }

    pub fn protocol(&self) -> &RendererProtocol {
        &self.protocol
    }

    pub fn object_id(&mut self) -> Result<u64, Error<T::Error>> {
        let id = self.next_object;
        self.next_object = id.checked_add(1).ok_or(Error::ObjectIds)?;
        Ok(id)
    }

    /// Create a persistently mapped host blob for a Vulkan allocation.
    /// CPU consumption precedes resource creation so the renderer has
    /// installed the memory object before it resolves the blob identifier.
    /// The caller releases this blob before freeing its Vulkan memory.
    pub fn memory_blob(
        &mut self,
        memory: VkDeviceMemory,
        size: NonZeroUsize,
    ) -> Result<T::Blob, Error<T::Error>> {
        self.flush()?;
        let blob = self
            .transport
            .create_blob(NonZeroU64::new(size.get() as u64).unwrap(), memory.0)
            .map_err(Error::Transport)?;
        check_size::<T>(&blob, size.get())?;
        Ok(blob)
    }

    fn inline(
        &self,
        encode: impl FnOnce(&mut Encoder<'_>),
    ) -> Result<InlineCommand, Error<T::Error>> {
        let mut command = InlineCommand {
            bytes: [0; INLINE_BYTES],
            length: 0,
        };
        let mut encoder = Encoder::new(&mut command.bytes, &self.protocol);
        encode(&mut encoder);
        command.length = encoder.finish()?;
        Ok(command)
    }

    fn execute_fenced(
        &mut self,
        commands: &[u8],
        ring: u8,
    ) -> Result<WaitPoint<T>, Error<T::Error>> {
        let fence = self
            .fences
            .get_mut(usize::from(ring))
            .ok_or(Error::Timeline { ring })?;
        *fence = fence.checked_add(1).ok_or(Error::FenceIds { ring })?;
        let fence = *fence;
        let timeline = self.signals[usize::from(ring)].get_or_insert_with(QueueTimeline::new);
        let signals = [SignalPoint {
            source: &timeline.source,
            value: fence,
        }];
        self.transport
            .execute(
                commands,
                ring,
                Some(Completion {
                    fence,
                    signals: &signals,
                }),
            )
            .map_err(Error::Transport)?;
        Ok(TimelinePoint {
            timeline: timeline.reader.clone(),
            value: fence,
        })
    }

    fn execute_and_wait(&mut self, commands: &[u8], ring: u8) -> Result<(), Error<T::Error>> {
        let point = self.execute_fenced(commands, ring)?;
        <T::Signal as SignalTimeline>::Timeline::wait(&[point], true, None)
            .map(|_| ())
            .map_err(Error::Transport)
    }

    fn publish(&mut self, commands: &[u8]) -> Result<u32, Error<T::Error>> {
        let published = match self.ring.publish(commands)? {
            Some(published) => published,
            None => {
                self.flush()?;
                self.ring.publish(commands)?.ok_or(Error::IncompleteWait {
                    sequence: self.ring.sequence(),
                })?
            }
        };
        if published.notify {
            let command = self.inline(|encoder| {
                // SAFETY: this command has only scalar parameters.
                unsafe {
                    vn_encode_vkNotifyRingMESA(encoder, 0, self.ring_id, published.sequence, 0)
                };
            })?;
            self.transport
                .execute(&command, 0, None)
                .map_err(Error::Transport)?;
        }
        Ok(published.sequence)
    }

    /// Submit encoded Vulkan commands. Upload storage stays alive until
    /// the ring has consumed its indirect command-stream references.
    pub fn send(&mut self, commands: &[u8]) -> Result<u32, Error<T::Error>> {
        let capacity = self.ring.capacity() as usize;
        if commands.len() <= capacity {
            return self.publish(commands);
        }
        let blob = self
            .transport
            .create_blob(NonZeroU64::new(commands.len() as u64).unwrap(), 0)
            .map_err(Error::Transport)?;
        check_size::<T>(&blob, commands.len())?;
        // SAFETY: this newly created upload has not been shared with the
        // renderer's command ring yet; it is exclusively producer-owned.
        unsafe {
            blob.pointer()
                .as_ptr()
                .copy_from_nonoverlapping(commands.as_ptr(), commands.len())
        };
        let stream = VkCommandStreamDescriptionMESA {
            resourceId: blob.resource_id(),
            offset: 0,
            size: commands.len(),
        };
        let indirect = self.inline(|encoder| {
            // SAFETY: one live stream descriptor; optional arrays are null.
            unsafe {
                vn_encode_vkExecuteCommandStreamsMESA(encoder, 0, 1, &stream, null(), 0, null(), 0)
            };
        })?;
        // A full ring may flush earlier uploads during publication. Keep
        // this blob local until that flush is over, then retain it even if
        // a notification failed after the command was published.
        let result = self.publish(&indirect);
        self.uploads.push(blob);
        result
    }

    /// Wait for CPU consumption of all commands, then reclaim uploads.
    pub fn flush(&mut self) -> Result<(), Error<T::Error>> {
        self.wait_queue(0)?;
        if !self.ring.is_drained()? {
            return Err(Error::IncompleteWait {
                sequence: self.ring.sequence(),
            });
        }
        self.uploads.clear();
        Ok(())
    }

    /// Wait for a renderer queue's prior GPU work. The queue must have
    /// been bound to this timeline by `VkDeviceQueueTimelineInfoMESA`.
    pub fn wait_queue(&mut self, ring: u8) -> Result<(), Error<T::Error>> {
        if usize::from(ring) >= TIMELINES {
            return Err(Error::Timeline { ring });
        }
        self.wait_queues(1u64 << ring)
    }

    /// Join prior work on the timelines selected by this virtio ring mask.
    /// All completion fences are submitted before the first wait, allowing
    /// independent GPU queues to retire concurrently.
    pub fn wait_queues(&mut self, timelines: u64) -> Result<(), Error<T::Error>> {
        let points = self.completion_points(timelines)?;
        <T::Signal as SignalTimeline>::Timeline::wait(&points, true, None)
            .map(|_| ())
            .map_err(Error::Transport)
    }

    /// Submit markers for prior work, then return read-only points which
    /// remain valid after releasing the connection's submission lock.
    pub fn completion_points(
        &mut self,
        timelines: u64,
    ) -> Result<Vec<WaitPoint<T>>, Error<T::Error>> {
        let command = self.inline(|encoder| {
            // SAFETY: this command has only scalar parameters.
            unsafe {
                vn_encode_vkWaitRingSeqnoMESA(
                    encoder,
                    0,
                    self.ring_id,
                    u64::from(self.ring.sequence()),
                )
            };
        })?;
        let mut points = Vec::with_capacity(timelines.count_ones() as usize);
        let mut remaining = timelines;
        while remaining != 0 {
            let ring = remaining.trailing_zeros() as u8;
            remaining &= remaining - 1;
            points.push(self.execute_fenced(&command, ring)?);
        }
        Ok(points)
    }

    /// Submit a reply-generating command and borrow its reply only after
    /// the renderer has consumed the command. The borrow prevents another
    /// submission from reusing the storage while it is being decoded.
    /// Each call installs its reply stream before the command.
    pub fn call(&mut self, commands: &[u8], reply_size: usize) -> Result<&[u8], Error<T::Error>> {
        if let Some(size) = NonZeroU64::new(reply_size as u64) {
            if self
                .reply
                .as_ref()
                .is_none_or(|blob| blob.len() < reply_size)
            {
                self.flush()?;
                let blob = self
                    .transport
                    .create_blob(size, 0)
                    .map_err(Error::Transport)?;
                check_size::<T>(&blob, reply_size)?;
                self.reply = Some(blob);
            }
            let blob = self.reply.as_ref().expect("reply storage allocated above");
            let stream = VkCommandStreamDescriptionMESA {
                resourceId: blob.resource_id(),
                offset: 0,
                size: reply_size,
            };
            let command = self.inline(|encoder| {
                // SAFETY: the descriptor is live and names the owned blob.
                unsafe { vn_encode_vkSetReplyCommandStreamMESA(encoder, 0, &stream) };
            })?;
            self.publish(&command)?;
        }
        self.send(commands)?;
        self.flush()?;
        if reply_size == 0 {
            return Ok(&[]);
        }
        let blob = self.reply.as_ref().expect("nonempty replies have storage");
        // SAFETY: the completed CPU fence establishes that the renderer has
        // finished writing this reply. No subsequent command has been sent.
        Ok(unsafe { core::slice::from_raw_parts(blob.pointer().as_ptr(), reply_size) })
    }

    pub fn close(mut self) -> Result<T, Error<T::Error>> {
        self.flush()?;
        let command = self.inline(|encoder| {
            // SAFETY: this command has only scalar parameters.
            unsafe { vn_encode_vkDestroyRingMESA(encoder, 0, self.ring_id) };
        })?;
        self.execute_and_wait(&command, 0)?;
        Ok(self.transport)
    }
}

fn check_size<T: Transport>(blob: &T::Blob, required: usize) -> Result<(), Error<T::Error>> {
    if blob.len() < required {
        return Err(Error::MappingSize {
            required,
            actual: blob.len(),
        });
    }
    Ok(())
}
