//! Buffers and their mappings on the content timeline.
//!
//! A mapped range lives in content-side memory, the way a browser's content
//! process holds its shared copy: `mapped-at-creation` starts from zeroed
//! memory, and a settled `map-async` from the bytes the device timeline
//! read. The mapped-range calls copy in and out of that memory without
//! reaching the device, and `unmap` queues the write-back of a writable
//! mapping before the device timeline unmaps.

use core::cell::{Cell, RefCell};
use core::future::{Future, poll_fn};
use core::ops::Range;
use core::pin::pin;
use core::task::Poll;
use std::rc::Rc;

use wgpu_core::id::markers;

use super::{command::Command, content::Handle, convert::Convert, wit};

#[derive(Debug, thiserror::Error)]
#[error("buffer range is outside the allocation or overflows its address space")]
pub struct InvalidRange;

pub fn range(
    size: u64,
    offset: Option<u64>,
    length: Option<u64>,
) -> Result<Range<u64>, InvalidRange> {
    let start = offset.unwrap_or(0);
    let length = length
        .or_else(|| size.checked_sub(start))
        .ok_or(InvalidRange)?;
    let end = start.checked_add(length).ok_or(InvalidRange)?;
    if start > size || end > size {
        return Err(InvalidRange);
    }
    Ok(start..end)
}

struct Mapping {
    range: Range<u64>,
    writable: bool,
    pending: Cell<bool>,
    /// The mapped bytes, `range.start` at index zero.
    data: RefCell<Vec<u8>>,
    cancel: async_channel::Sender<()>,
}

impl Mapping {
    fn new(range: Range<u64>, writable: bool, pending: bool, data: Vec<u8>) -> Rc<Self> {
        let (cancel, _) = async_channel::bounded(1);
        Rc::new(Self {
            range,
            writable,
            pending: Cell::new(pending),
            data: RefCell::new(data),
            cancel,
        })
    }

    /// Indices into `data` for `requested`, which lies within `range`.
    fn local(&self, requested: &Range<u64>) -> Range<usize> {
        let start = (requested.start - self.range.start) as usize;
        start..start + (requested.end - requested.start) as usize
    }
}

#[derive(Default)]
struct MappingSlot(RefCell<Option<Rc<Mapping>>>);

impl MappingSlot {
    fn owns(&self, mapping: &Rc<Mapping>) -> bool {
        self.0
            .borrow()
            .as_ref()
            .is_some_and(|current| Rc::ptr_eq(current, mapping))
    }

    fn take(&self) -> Option<Rc<Mapping>> {
        let mapping = self.0.borrow_mut().take()?;
        mapping.cancel.close();
        Some(mapping)
    }
}

pub struct Buffer {
    pub handle: Handle<markers::Buffer>,
    pub size: u64,
    pub usage: wit::GpuBufferUsage,
    mapping: MappingSlot,
    destroyed: Cell<bool>,
}

impl Buffer {
    pub fn new(handle: Handle<markers::Buffer>, descriptor: &wit::GpuBufferDescriptor) -> Self {
        let mapping = MappingSlot::default();
        if descriptor.mapped_at_creation.unwrap_or(false) {
            // WebGPU maps the whole buffer at creation even when the device
            // timeline rejects the buffer, so the memory is the content
            // timeline's own.
            match zeroed(descriptor.size) {
                Some(data) => {
                    *mapping.0.borrow_mut() =
                        Some(Mapping::new(0..descriptor.size, true, false, data));
                }
                None => handle.device.invalid(format!(
                    "a mapped-at-creation range of {} bytes cannot be allocated",
                    descriptor.size
                )),
            }
        }
        Self {
            handle,
            size: descriptor.size,
            usage: descriptor.usage,
            mapping,
            destroyed: Cell::new(false),
        }
    }

    fn unmap(&self) {
        let Some(mapping) = self.mapping.take() else {
            return;
        };
        let write_back = (mapping.writable && !mapping.pending.get())
            .then(|| (mapping.range.start, mapping.data.take()));
        self.handle.device.enqueue(Command::Unmap {
            buffer: self.handle.id,
            write_back,
        });
    }

    /// The mapping and the indices of `requested` within its memory.
    fn mapped_range(
        &self,
        offset: Option<u64>,
        size: Option<u64>,
        write: bool,
    ) -> Result<(Rc<Mapping>, Range<usize>), wit::GetMappedRangeError> {
        let error = |message: String| wit::GetMappedRangeError {
            kind: wit::GetMappedRangeErrorKind::OperationError,
            message,
        };
        let requested = range(self.size, offset, size).map_err(|e| error(e.to_string()))?;
        let mapping = self
            .mapping
            .0
            .borrow()
            .clone()
            .ok_or_else(|| error("buffer is not mapped".into()))?;
        if mapping.pending.get()
            || (write && !mapping.writable)
            || requested.start < mapping.range.start
            || requested.end > mapping.range.end
            || !requested.start.is_multiple_of(wgpu_types::MAP_ALIGNMENT)
            || !(requested.end - requested.start).is_multiple_of(wgpu_types::COPY_BUFFER_ALIGNMENT)
        {
            return Err(error(
                "requested range is not accessible in the current mapping".into(),
            ));
        }
        let local = mapping.local(&requested);
        Ok((mapping, local))
    }
}

fn zeroed(size: u64) -> Option<Vec<u8>> {
    let size = usize::try_from(size).ok()?;
    let mut data = Vec::new();
    data.try_reserve_exact(size).ok()?;
    data.resize(size, 0);
    Some(data)
}

/// Dropping an async invocation cancels only the mapping it started.
struct PendingMap<'a> {
    buffer: &'a Buffer,
    mapping: Rc<Mapping>,
}

impl Drop for PendingMap<'_> {
    fn drop(&mut self) {
        if self.mapping.pending.get() && self.buffer.mapping.owns(&self.mapping) {
            self.buffer.unmap();
        }
    }
}

impl wit::GuestGpuBuffer for Buffer {
    fn size(&self) -> u64 {
        self.size
    }
    fn usage(&self) -> wit::GpuBufferUsage {
        self.usage
    }
    fn label(&self) -> String {
        self.handle.label()
    }
    fn set_label(&self, label: String) {
        self.handle.set_label(label);
    }
    fn map_state(&self) -> wit::GpuBufferMapState {
        match self.mapping.0.borrow().as_ref() {
            None => wit::GpuBufferMapState::Unmapped,
            Some(mapping) if mapping.pending.get() => wit::GpuBufferMapState::Pending,
            Some(_) => wit::GpuBufferMapState::Mapped,
        }
    }

    async fn map_async(
        &self,
        mode: wit::GpuMapMode,
        offset: Option<u64>,
        size: Option<u64>,
    ) -> Result<(), wit::MapAsyncError> {
        let invalid = |message: String| {
            self.handle.device.invalid(message.clone());
            wit::MapAsyncError {
                kind: wit::MapAsyncErrorKind::OperationError,
                message,
            }
        };
        if self.mapping.0.borrow().is_some() || self.destroyed.get() {
            return Err(invalid(
                "buffer is already mapped, pending, or destroyed".into(),
            ));
        }
        let (host, required) = match mode.bits() {
            bits if bits == wit::GpuMapMode::READ.bits() => (
                wgpu_core::device::HostMap::Read,
                wgpu_types::BufferUsages::MAP_READ,
            ),
            bits if bits == wit::GpuMapMode::WRITE.bits() => (
                wgpu_core::device::HostMap::Write,
                wgpu_types::BufferUsages::MAP_WRITE,
            ),
            _ => return Err(invalid("map mode must be exactly read or write".into())),
        };
        let requested = range(self.size, offset, size).map_err(|e| invalid(e.to_string()))?;
        if !requested.start.is_multiple_of(wgpu_types::MAP_ALIGNMENT)
            || !(requested.end - requested.start).is_multiple_of(wgpu_types::COPY_BUFFER_ALIGNMENT)
        {
            return Err(invalid(
                "map offset must be aligned to 8 bytes and size to 4 bytes".into(),
            ));
        }
        if !self.usage.convert().contains(required) {
            return Err(invalid(
                "buffer usage does not permit the requested map mode".into(),
            ));
        }
        let (cancel, cancelled) = async_channel::bounded(1);
        let mapping = Rc::new(Mapping {
            range: requested.clone(),
            writable: matches!(host, wgpu_core::device::HostMap::Write),
            pending: Cell::new(true),
            data: RefCell::new(Vec::new()),
            cancel,
        });
        *self.mapping.0.borrow_mut() = Some(mapping.clone());
        let pending = PendingMap {
            buffer: self,
            mapping,
        };
        let (reply, answer) = async_channel::bounded(1);
        self.handle.device.enqueue(Command::Map {
            buffer: self.handle.id,
            host,
            range: requested,
            reply,
        });
        let mut answer = pin!(answer.recv());
        let mut cancelled = pin!(cancelled.recv());
        let result = poll_fn(|cx| {
            // An unmap or destroy on the content timeline settles the
            // mapping before the device timeline answers.
            if cancelled.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(wit::MapAsyncError {
                    kind: wit::MapAsyncErrorKind::AbortError,
                    message: "buffer mapping was cancelled".into(),
                }));
            }
            answer.as_mut().poll(cx).map(|answer| {
                // The caller holds the buffer and so its device, whose task
                // answers every mapping.
                answer.unwrap_or_else(|_| unreachable!("the device task answers every mapping"))
            })
        })
        .await;
        let data = result?;
        *pending.mapping.data.borrow_mut() = data;
        pending.mapping.pending.set(false);
        Ok(())
    }

    fn get_mapped_range_get_with_copy(
        &self,
        offset: Option<u64>,
        size: Option<u64>,
    ) -> Result<Vec<u8>, wit::GetMappedRangeError> {
        let (mapping, local) = self.mapped_range(offset, size, false)?;
        let data = mapping.data.borrow();
        let mut copy = Vec::new();
        copy.try_reserve_exact(local.len())
            .map_err(|e| wit::GetMappedRangeError {
                kind: wit::GetMappedRangeErrorKind::RangeError,
                message: e.to_string(),
            })?;
        copy.extend_from_slice(&data[local]);
        Ok(copy)
    }

    fn get_mapped_range_set_with_copy(
        &self,
        data: Vec<u8>,
        offset: Option<u64>,
        size: Option<u64>,
    ) -> Result<(), wit::GetMappedRangeError> {
        let (mapping, local) = self.mapped_range(offset, size, true)?;
        if local.len() != data.len() {
            return Err(wit::GetMappedRangeError {
                kind: wit::GetMappedRangeErrorKind::RangeError,
                message: "copy length does not match the mapped range".into(),
            });
        }
        mapping.data.borrow_mut()[local].copy_from_slice(&data);
        Ok(())
    }

    fn unmap(&self) -> Result<(), wit::UnmapError> {
        self.unmap();
        Ok(())
    }
    fn destroy(&self) {
        self.unmap();
        self.destroyed.set(true);
        self.handle
            .device
            .enqueue(Command::DestroyBuffer(self.handle.id));
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // The write-back precedes the drop the handle queues after this.
        self.unmap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::{command::Queued, content::tests::new_device};
    use wit::GuestGpuBuffer;

    fn descriptor(size: u64, mapped: bool) -> wit::GpuBufferDescriptor {
        wit::GpuBufferDescriptor {
            size,
            usage: wit::GpuBufferUsage::MAP_WRITE | wit::GpuBufferUsage::COPY_SRC,
            mapped_at_creation: Some(mapped),
            label: None,
        }
    }

    #[test]
    fn ranges_allow_empty_and_reject_overflow() {
        assert_eq!(range(0, None, None).unwrap(), 0..0);
        assert_eq!(range(16, Some(16), Some(0)).unwrap(), 16..16);
        assert_eq!(range(16, Some(8), None).unwrap(), 8..16);
        assert!(range(16, Some(17), None).is_err());
        assert!(range(u64::MAX, Some(u64::MAX), Some(1)).is_err());
        assert!(range(16, Some(8), Some(12)).is_err());
    }

    #[test]
    fn stale_mapping_does_not_own_a_replacement() {
        let slot = MappingSlot::default();
        let old = Mapping::new(0..8, true, true, Vec::new());
        *slot.0.borrow_mut() = Some(old.clone());
        assert!(slot.owns(&old));
        assert!(slot.take().is_some());
        assert!(old.cancel.is_closed());
        let new = Mapping::new(0..8, true, true, Vec::new());
        *slot.0.borrow_mut() = Some(new.clone());
        assert!(!slot.owns(&old));
        assert!(slot.owns(&new));
    }

    #[test]
    fn mapped_at_creation_writes_reach_the_device_only_through_unmap() {
        let (device, queue) = new_device();
        let buffer = Buffer::new(Handle::new(&device, None), &descriptor(16, true));
        assert!(matches!(buffer.map_state(), wit::GpuBufferMapState::Mapped));
        buffer
            .get_mapped_range_set_with_copy(vec![1, 2, 3, 4, 5, 6, 7, 8], Some(8), None)
            .unwrap();
        assert_eq!(
            buffer
                .get_mapped_range_get_with_copy(Some(8), Some(8))
                .unwrap(),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
        // Mapped-range calls never queue a command.
        assert!(queue.try_recv().is_err());
        GuestGpuBuffer::unmap(&buffer).unwrap();
        let Queued {
            command:
                Command::Unmap {
                    buffer: id,
                    write_back: Some((0, data)),
                },
            ..
        } = queue.try_recv().unwrap()
        else {
            panic!("unmap did not queue the write-back");
        };
        assert_eq!(id, buffer.handle.id);
        assert_eq!(data, [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(matches!(
            buffer.map_state(),
            wit::GpuBufferMapState::Unmapped
        ));
        assert!(buffer.get_mapped_range_get_with_copy(None, None).is_err());
        GuestGpuBuffer::unmap(&buffer).unwrap();
        assert!(queue.try_recv().is_err());
    }

    #[test]
    fn dropping_a_mapped_buffer_writes_back_before_its_release() {
        let (device, queue) = new_device();
        drop(Buffer::new(
            Handle::new(&device, None),
            &descriptor(4, true),
        ));
        assert!(matches!(
            queue.try_recv().unwrap().command,
            Command::Unmap {
                write_back: Some(_),
                ..
            }
        ));
        assert!(matches!(
            queue.try_recv().unwrap().command,
            Command::Release(super::super::ids::Release::Buffer(_))
        ));
    }

    #[test]
    fn mapped_ranges_respect_alignment_and_bounds() {
        let (device, _queue) = new_device();
        let buffer = Buffer::new(Handle::new(&device, None), &descriptor(32, true));
        assert!(
            buffer
                .get_mapped_range_get_with_copy(Some(4), Some(4))
                .is_err()
        );
        assert!(
            buffer
                .get_mapped_range_get_with_copy(Some(8), Some(6))
                .is_err()
        );
        assert!(
            buffer
                .get_mapped_range_get_with_copy(Some(24), Some(16))
                .is_err()
        );
        assert!(
            buffer
                .get_mapped_range_set_with_copy(vec![0; 4], Some(8), Some(8))
                .is_err()
        );
        assert_eq!(
            buffer
                .get_mapped_range_get_with_copy(Some(24), None)
                .unwrap()
                .len(),
            8
        );
    }
}
