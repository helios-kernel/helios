use core::cell::UnsafeCell;
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use helios_venus::capset::Capset;
use helios_venus::connection::{Connection, Error};
use helios_venus::protocol::{
    VK_COMMAND_TYPE_vkCreateRingMESA_EXT, VK_COMMAND_TYPE_vkEnumerateInstanceVersion_EXT,
    VK_COMMAND_TYPE_vkEnumeratePhysicalDevices_EXT,
    VK_COMMAND_TYPE_vkExecuteCommandStreamsMESA_EXT,
    VK_COMMAND_TYPE_vkSetReplyCommandStreamMESA_EXT, VK_COMMAND_TYPE_vkWaitRingSeqnoMESA_EXT,
    VK_SUCCESS, VkInstance, VkPhysicalDevice, vn_call_vkEnumerateInstanceVersion,
    vn_call_vkEnumeratePhysicalDevices,
};
use helios_venus::ring::Layout;
use helios_venus::transport::{
    Completion, MappedBlob, SignalTimeline, Timeline, TimelinePoint, Transport,
};
use helios_venus::{ObjectBase, RendererProtocol, api_version};

struct Memory(Box<[UnsafeCell<u32>]>);

impl Memory {
    fn pointer(&self) -> NonNull<u8> {
        NonNull::new(self.0.as_ptr().cast_mut().cast()).unwrap()
    }

    fn word(&self, offset: usize) -> &AtomicU32 {
        // SAFETY: the test accesses aligned control words atomically.
        unsafe { &*self.pointer().as_ptr().add(offset).cast() }
    }
}

// SAFETY: the test renderer obeys the ring publication protocol; shared
// control words are atomic and payload access follows acquired tail/head.
unsafe impl Send for Memory {}
// SAFETY: the same ownership protocol governs cross-thread payload access.
unsafe impl Sync for Memory {}

struct Blob {
    id: u32,
    memory: Arc<Memory>,
}

// SAFETY: the allocation is aligned, does not move, and lives until the
// blob is dropped. The recording transport uses the same ownership rules
// as the renderer when reading commands.
unsafe impl MappedBlob for Blob {
    fn resource_id(&self) -> u32 {
        self.id
    }
    fn pointer(&self) -> NonNull<u8> {
        self.memory.pointer()
    }
    fn len(&self) -> usize {
        self.memory.0.len() * 4
    }
}

#[derive(Default)]
struct Recorded {
    next: u32,
    timelines: Vec<Weak<Mutex<TimelineState>>>,
    blobs: BTreeMap<u32, Weak<Memory>>,
    ring: Option<u32>,
    sequences: Vec<u64>,
    submitted: Vec<(u8, u64)>,
    waited: Vec<(u8, u64)>,
    submissions_at_wait: Vec<usize>,
    consumed: Vec<Vec<u8>>,
    pending: Option<u32>,
    premature_completion: bool,
    #[cfg(feature = "driver")]
    gpu_wait_hold: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    reply_command: i32,
    reply: Vec<u8>,
    blob_ids: Vec<u64>,
    #[cfg(feature = "driver")]
    scripted: bool,
}

struct Recording(Arc<Mutex<Recorded>>);

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[derive(Debug, thiserror::Error)]
#[error("timeline producer closed")]
struct TestError;

struct Binding {
    recorded: Arc<Mutex<Recorded>>,
    ring: u8,
    fence: u64,
    value: u64,
}

struct TimelineState {
    value: u64,
    producers: usize,
    failed: bool,
    wait_started: Option<std::sync::mpsc::Sender<()>>,
    bindings: Vec<Binding>,
    waiters: Vec<Weak<std::sync::mpsc::Sender<()>>>,
}

impl TimelineState {
    fn notify(&mut self) {
        self.waiters.retain(|waiter| {
            let Some(waiter) = waiter.upgrade() else {
                return false;
            };
            waiter.send(()).is_ok()
        });
    }
}

struct TestSignal(Arc<Mutex<TimelineState>>);

#[derive(Clone)]
struct TestReader(Arc<Mutex<TimelineState>>);

impl Clone for TestSignal {
    fn clone(&self) -> Self {
        self.0.lock().unwrap().producers += 1;
        Self(self.0.clone())
    }
}

impl Drop for TestSignal {
    fn drop(&mut self) {
        let mut state = self.0.lock().unwrap();
        state.producers -= 1;
        if state.producers == 0 {
            state.notify();
        }
    }
}

impl SignalTimeline for TestSignal {
    type Error = TestError;
    type Timeline = TestReader;

    fn reader(&self) -> TestReader {
        TestReader(self.0.clone())
    }

    fn signal(&self, value: u64) -> Result<(), TestError> {
        let mut state = self.0.lock().unwrap();
        if state.failed {
            return Err(TestError);
        }
        state.value = state.value.max(value);
        state.notify();
        Ok(())
    }

    fn fail(&self) {
        let mut state = self.0.lock().unwrap();
        state.failed = true;
        state.notify();
    }
}

impl TestReader {
    fn retire(&self) -> Result<(), TestError> {
        let bindings = core::mem::take(&mut self.0.lock().unwrap().bindings);
        for binding in bindings {
            Recording(binding.recorded).retire(binding.ring, binding.fence)?;
            let mut state = self.0.lock().unwrap();
            state.value = state.value.max(binding.value);
            state.producers -= 1;
            state.notify();
        }
        Ok(())
    }
}

impl Timeline for TestReader {
    type Error = TestError;

    fn value(&self) -> Result<u64, TestError> {
        let state = self.0.lock().unwrap();
        if state.failed {
            Err(TestError)
        } else {
            Ok(state.value)
        }
    }

    fn wait(
        points: &[TimelinePoint<Self>],
        wait_all: bool,
        timeout: Option<Duration>,
    ) -> Result<bool, TestError> {
        let deadline = timeout.map(|timeout| std::time::Instant::now() + timeout);
        let (sender, receiver) = std::sync::mpsc::channel();
        let sender = Arc::new(sender);
        for point in points {
            let mut state = point.timeline.0.lock().unwrap();
            state.waiters.push(Arc::downgrade(&sender));
            if let Some(started) = state.wait_started.take() {
                started.send(()).unwrap();
            }
        }
        loop {
            let mut completed = 0;
            for point in points {
                point.timeline.retire()?;
                let state = point.timeline.0.lock().unwrap();
                if state.failed {
                    return Err(TestError);
                }
                if state.value >= point.value {
                    completed += 1;
                } else if state.producers == 0 {
                    return Err(TestError);
                }
            }
            if if wait_all {
                completed == points.len()
            } else {
                completed != 0
            } {
                return Ok(true);
            }
            if let Some(deadline) = deadline {
                match receiver
                    .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                {
                    Ok(()) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return Ok(false),
                    Err(error) => panic!("waiter's own sender remains alive: {error}"),
                }
            } else {
                receiver.recv().expect("waiter's own sender remains alive");
            }
        }
    }
}

impl Transport for Recording {
    type Error = TestError;
    type Blob = Blob;
    type Signal = TestSignal;

    fn timeline(&self, value: u64) -> TestSignal {
        let state = Arc::new(Mutex::new(TimelineState {
            value,
            producers: 1,
            failed: false,
            wait_started: None,
            bindings: Vec::new(),
            waiters: Vec::new(),
        }));
        self.0
            .lock()
            .unwrap()
            .timelines
            .push(Arc::downgrade(&state));
        TestSignal(state)
    }

    fn create_blob(&mut self, size: NonZeroU64, blob_id: u64) -> Result<Blob, TestError> {
        let memory = Arc::new(Memory(
            (0..size.get().div_ceil(4))
                .map(|_| UnsafeCell::new(0))
                .collect(),
        ));
        let mut state = self.0.lock().unwrap();
        state.blob_ids.push(blob_id);
        state.next += 1;
        let id = state.next;
        state.blobs.insert(id, Arc::downgrade(&memory));
        Ok(Blob { id, memory })
    }

    fn execute(
        &mut self,
        commands: &[u8],
        ring: u8,
        completion: Option<Completion<'_, TestSignal>>,
    ) -> Result<(), TestError> {
        let mut state = self.0.lock().unwrap();
        let command = word(commands, 0) as i32;
        if command == VK_COMMAND_TYPE_vkCreateRingMESA_EXT.0 {
            // Header, ring id, pointer count, sType, pNext, flags precede
            // the resource id in the Venus wire layout.
            state.ring = Some(word(commands, 40));
        } else if command == VK_COMMAND_TYPE_vkWaitRingSeqnoMESA_EXT.0 {
            // Header and ring id precede the 64-bit sequence number.
            state.pending = Some(word(commands, 16));
        }
        if let Some(completion) = completion {
            let fence = completion.fence;
            state.sequences.push(fence);
            state.submitted.push((ring, fence));
            for signal in completion.signals {
                let mut timeline = signal.source.0.lock().unwrap();
                timeline.producers += 1;
                timeline.bindings.push(Binding {
                    recorded: self.0.clone(),
                    ring,
                    fence,
                    value: signal.value,
                });
                timeline.notify();
            }
        }
        Ok(())
    }
}

impl Recording {
    fn retire(&mut self, ring: u8, fence: u64) -> Result<(), TestError> {
        #[cfg(feature = "driver")]
        if ring != 0 {
            let hold = self.0.lock().unwrap().gpu_wait_hold.take();
            if let Some((entered, release)) = hold {
                entered.send(()).unwrap();
                release
                    .recv_timeout(Duration::from_secs(5))
                    .expect("test releases GPU completion within its deadline");
            }
        }
        let mut state = self.0.lock().unwrap();
        assert!(state.submitted.contains(&(ring, fence)));
        state.waited.push((ring, fence));
        let count = state.submitted.len();
        state.submissions_at_wait.push(count);
        let Some(sequence) = state.pending.take() else {
            return Ok(());
        };
        if state.premature_completion {
            return Ok(());
        }
        let memory = state.blobs[&state.ring.unwrap()]
            .upgrade()
            .expect("ring must remain mapped");
        let head = memory.word(Layout::HEAD).load(Ordering::Relaxed);
        let tail = memory.word(Layout::TAIL).load(Ordering::Acquire);
        assert_eq!(tail, sequence);
        let capacity = memory.0.len() * 4 - Layout::BUFFER;
        let mut commands = Vec::new();
        for at in head..tail {
            // SAFETY: the acquired tail published these bytes, and head
            // has not yet released them to the producer.
            commands.push(unsafe {
                *memory
                    .pointer()
                    .as_ptr()
                    .add(Layout::BUFFER + at as usize % capacity)
            });
        }
        if !commands.is_empty()
            && word(&commands, 0) as i32 == VK_COMMAND_TYPE_vkExecuteCommandStreamsMESA_EXT.0
        {
            // Header, streamCount and array count precede the descriptor.
            let upload = state.blobs[&word(&commands, 20)]
                .upgrade()
                .expect("indirect upload was freed before consumption");
            let size = word(&commands, 32) as usize;
            // SAFETY: the ring publication also publishes this upload;
            // the driver keeps it immutable until the wait completes.
            let bytes = unsafe { core::slice::from_raw_parts(upload.pointer().as_ptr(), size) };
            state.consumed.push(bytes.to_vec());
        } else if !commands.is_empty()
            && word(&commands, 0) as i32 == VK_COMMAND_TYPE_vkSetReplyCommandStreamMESA_EXT.0
        {
            #[cfg(feature = "driver")]
            if state.scripted {
                entry_tests::reply(&mut state, &commands[36..]);
            }
            assert_eq!(word(&commands, 36) as i32, state.reply_command);
            assert_eq!(word(&commands, 40), 1, "command requests a reply");
            let reply = state.blobs[&word(&commands, 16)]
                .upgrade()
                .expect("reply must remain mapped");
            let bytes = &state.reply;
            assert!(word(&commands, 28) as usize >= bytes.len());
            // SAFETY: the driver does not read until we publish head and
            // complete its CPU timeline wait.
            unsafe {
                reply
                    .pointer()
                    .as_ptr()
                    .copy_from_nonoverlapping(bytes.as_ptr(), bytes.len())
            };
            state.consumed.push(commands);
        } else if !commands.is_empty() {
            state.consumed.push(commands);
        }
        memory.word(Layout::HEAD).store(tail, Ordering::Release);
        Ok(())
    }
}

fn connection(state: Arc<Mutex<Recorded>>) -> Connection<Recording> {
    connection_with_capacity(state, 64)
}

fn connection_with_capacity(state: Arc<Mutex<Recorded>>, capacity: u32) -> Connection<Recording> {
    let capset = Capset {
        protocol: RendererProtocol::with_all_extensions(api_version(1, 3)),
        serialization_version: 1,
        venus_version: 4,
        allows_wait_syncs: true,
        multiple_timelines: true,
        guest_vram: false,
    };
    Connection::new(
        Recording(state),
        capset,
        Layout::new(NonZeroU32::new(capacity).unwrap()).unwrap(),
        Duration::from_millis(1),
    )
    .unwrap()
}

#[test]
fn independent_queue_fences_are_submitted_before_either_waits() {
    let state = Arc::new(Mutex::new(Recorded::default()));
    let mut connection = connection(state.clone());
    connection.wait_queues((1 << 1) | (1 << 2)).unwrap();
    {
        let state = state.lock().unwrap();
        assert_eq!(&state.waited[state.waited.len() - 2..], &[(1, 1), (2, 1)]);
        assert!(
            state
                .submissions_at_wait
                .iter()
                .rev()
                .take(2)
                .all(|count| *count == state.submitted.len())
        );
    }
    connection.close().unwrap();
}

#[test]
fn an_indirect_upload_survives_the_flush_needed_to_publish_it() {
    let state = Arc::new(Mutex::new(Recorded::default()));
    let mut connection = connection(state.clone());
    let direct = [0xff; 64];
    let indirect = vec![0x5a; 1024];
    connection.send(&direct).unwrap();
    connection.send(&indirect).unwrap();
    assert_eq!(state.lock().unwrap().consumed, [direct.to_vec()]);
    assert!(state.lock().unwrap().blobs[&2].upgrade().is_some());
    connection.flush().unwrap();
    assert_eq!(state.lock().unwrap().consumed, [direct.to_vec(), indirect]);
    assert!(state.lock().unwrap().blobs[&2].upgrade().is_none());
    connection.close().unwrap();
    assert!(state.lock().unwrap().blobs[&1].upgrade().is_none());
    assert!(
        state
            .lock()
            .unwrap()
            .sequences
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
}

#[test]
fn a_transport_acknowledgement_does_not_replace_ring_consumption() {
    let state = Arc::new(Mutex::new(Recorded::default()));
    let mut connection = connection(state.clone());
    connection.send(&[0xff; 4]).unwrap();
    state.lock().unwrap().premature_completion = true;
    assert!(matches!(
        connection.flush(),
        Err(Error::IncompleteWait { sequence: 4 })
    ));
}

#[test]
fn memory_blobs_follow_allocation_consumption_and_use_its_object_id() {
    let state = Arc::new(Mutex::new(Recorded::default()));
    let mut connection = connection(state.clone());
    connection.send(&[0xff; 4]).unwrap();
    let blob = connection
        .memory_blob(
            helios_venus::protocol::VkDeviceMemory(77),
            NonZeroUsize::new(64).unwrap(),
        )
        .unwrap();
    assert_eq!(state.lock().unwrap().consumed, [vec![0xff; 4]]);
    assert_eq!(state.lock().unwrap().blob_ids, [0, 77]);
    assert_eq!(blob.len(), 64);
    drop(blob);
    connection.close().unwrap();
}

#[test]
fn generated_calls_select_a_reply_stream_and_decode_the_renderer_result() {
    let state = Arc::new(Mutex::new(Recorded {
        reply_command: VK_COMMAND_TYPE_vkEnumerateInstanceVersion_EXT.0,
        reply: [
            VK_COMMAND_TYPE_vkEnumerateInstanceVersion_EXT.0 as u32,
            0,
            1,
            0,
            api_version(1, 3),
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect(),
        ..Recorded::default()
    }));
    let mut connection = connection(state);
    let mut version = 0;
    // SAFETY: version is live for request and reply processing.
    let result =
        unsafe { vn_call_vkEnumerateInstanceVersion(&mut connection, &mut version) }.unwrap();
    assert_eq!(result, VK_SUCCESS);
    assert_eq!(version, api_version(1, 3));
    connection.close().unwrap();
}

#[test]
fn enumeration_accepts_fewer_handles_than_the_reply_capacity() {
    // Command, success, non-null count pointer, one returned device,
    // one-element handle array, and its renderer object id.
    let reply = [
        VK_COMMAND_TYPE_vkEnumeratePhysicalDevices_EXT.0 as u32,
        0,
        1,
        0,
        1,
        1,
        0,
        3,
        0,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();
    let state = Arc::new(Mutex::new(Recorded {
        reply_command: VK_COMMAND_TYPE_vkEnumeratePhysicalDevices_EXT.0,
        reply,
        ..Recorded::default()
    }));
    let mut connection = connection_with_capacity(state, 256);
    let mut instance = ObjectBase { id: 2 };
    let mut devices = [ObjectBase { id: 3 }, ObjectBase { id: 4 }];
    let mut handles = devices.each_mut().map(|device| VkPhysicalDevice(device));
    let mut count = 2;
    // SAFETY: every handle has stable object storage, and the count
    // describes the live output array for the duration of the call.
    let result = unsafe {
        vn_call_vkEnumeratePhysicalDevices(
            &mut connection,
            VkInstance(&mut instance),
            &mut count,
            handles.as_mut_ptr(),
        )
    }
    .unwrap();
    assert_eq!(result, VK_SUCCESS);
    assert_eq!(count, 1);
    assert_eq!(devices, [ObjectBase { id: 3 }, ObjectBase { id: 4 }]);
    connection.close().unwrap();
}

#[test]
fn enumeration_cannot_expand_the_callers_output_capacity() {
    use helios_venus::protocol::vn_decode_vkEnumeratePhysicalDevices_reply;
    use helios_venus::{DecodeError, Decoder};

    let reply: Vec<_> = [
        VK_COMMAND_TYPE_vkEnumeratePhysicalDevices_EXT.0 as u32,
        0,
        1,
        0,
        3,
        3,
        0,
        3,
        0,
        4,
        0,
        99,
        0,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();
    let mut instance = ObjectBase { id: 2 };
    // The third slot is a canary outside the declared capacity. Keeping
    // it allocated makes a regression observable without test-side UB.
    let mut devices = [
        ObjectBase { id: 3 },
        ObjectBase { id: 4 },
        ObjectBase { id: 5 },
    ];
    let mut handles = devices.each_mut().map(|device| VkPhysicalDevice(device));
    let mut count = 2;
    let mut decoder = Decoder::new(&reply);
    // SAFETY: two writable output slots are declared, with live object
    // storage; the renderer-controlled wire count is the decoder's input.
    unsafe {
        vn_decode_vkEnumeratePhysicalDevices_reply(
            &mut decoder,
            VkInstance(&mut instance),
            &mut count,
            handles.as_mut_ptr(),
        );
    }
    assert_eq!(
        decoder.finish(),
        Err(DecodeError::ArrayCapacity {
            capacity: 2,
            found: 3
        })
    );
    assert_eq!(devices[2].id, 5);
}

#[test]
fn structure_reply_counts_cannot_expand_or_create_output_storage() {
    use helios_venus::protocol::{
        VkImageLayout, VkPhysicalDeviceHostImageCopyProperties,
        vn_decode_VkPhysicalDeviceHostImageCopyProperties_self,
    };
    use helios_venus::{DecodeError, Decoder};

    // A count of three followed by a three-element array. Decoding must
    // stop at its prefix, before any array payload or later member.
    let reply: Vec<_> = [3u32, 3, 0, 1, 2, 99]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    for capacity in [0, 2] {
        let mut layouts = [VkImageLayout(7); 3];
        // SAFETY: this C-layout structure consists of integer newtypes,
        // integer arrays and nullable pointers, all admitting zero.
        let mut properties: VkPhysicalDeviceHostImageCopyProperties =
            unsafe { core::mem::zeroed() };
        properties.copySrcLayoutCount = capacity;
        if capacity != 0 {
            properties.pCopySrcLayouts = layouts.as_mut_ptr();
        }
        let mut decoder = Decoder::new(&reply);
        // SAFETY: the declared array capacity has live storage. This
        // member decoder does not read the structure's sType or pNext.
        unsafe {
            vn_decode_VkPhysicalDeviceHostImageCopyProperties_self(&mut decoder, &mut properties);
        }
        assert_eq!(
            decoder.finish(),
            Err(DecodeError::ArrayCapacity {
                capacity: u64::from(capacity),
                found: 3,
            })
        );
        assert_eq!(layouts, [VkImageLayout(7); 3]);
    }
}

#[cfg(feature = "driver")]
mod entry_tests {
    use super::*;
    use ash::vk::{self, Handle};
    use helios_venus::driver::{Factory, SubmissionLock, entry};
    use helios_venus::protocol as wire;
    use helios_venus::transport::TransportFactory;

    pub(super) fn reply(state: &mut Recorded, commands: &[u8]) {
        let command = word(commands, 0) as i32;
        let mut words = vec![command as u32, 0];
        if [
            wire::VK_COMMAND_TYPE_vkCreateInstance_EXT.0,
            wire::VK_COMMAND_TYPE_vkCreateDevice_EXT.0,
            wire::VK_COMMAND_TYPE_vkCreateBuffer_EXT.0,
            wire::VK_COMMAND_TYPE_vkAllocateMemory_EXT.0,
            wire::VK_COMMAND_TYPE_vkCreateCommandPool_EXT.0,
            wire::VK_COMMAND_TYPE_vkCreateFence_EXT.0,
            wire::VK_COMMAND_TYPE_vkCreateSemaphore_EXT.0,
        ]
        .contains(&command)
        {
            words.extend([
                1,
                0,
                word(commands, commands.len() - 8),
                word(commands, commands.len() - 4),
            ]);
        } else if command == wire::VK_COMMAND_TYPE_vkAllocateCommandBuffers_EXT.0 {
            // The allocate-info ends with commandBufferCount; the output
            // array carries an eight-byte count followed by object IDs.
            let count = word(commands, 48);
            words.extend([count, 0]);
            for index in 0..count as usize {
                words.extend([
                    word(commands, 60 + index * 8),
                    word(commands, 64 + index * 8),
                ]);
            }
        } else if [
            wire::VK_COMMAND_TYPE_vkBeginCommandBuffer_EXT.0,
            wire::VK_COMMAND_TYPE_vkEndCommandBuffer_EXT.0,
            wire::VK_COMMAND_TYPE_vkResetFences_EXT.0,
            wire::VK_COMMAND_TYPE_vkSignalSemaphore_EXT.0,
            wire::VK_COMMAND_TYPE_vkQueueSubmit_EXT.0,
            wire::VK_COMMAND_TYPE_vkQueueSubmit2_EXT.0,
        ]
        .contains(&command)
        {
            // These commands return only VkResult.
        } else if command == wire::VK_COMMAND_TYPE_vkGetDeviceQueue2_EXT.0 {
            // Void-returning commands omit VkResult from their reply.
            words.truncate(1);
            words.extend([
                1,
                0,
                word(commands, commands.len() - 8),
                word(commands, commands.len() - 4),
            ]);
        } else if command == wire::VK_COMMAND_TYPE_vkEnumerateInstanceVersion_EXT.0 {
            words.extend([1, 0, api_version(1, 3)]);
        } else if command == wire::VK_COMMAND_TYPE_vkEnumeratePhysicalDevices_EXT.0 {
            let capacity = word(commands, 28);
            words.extend([1, 0, 2, capacity, 0]);
            for index in 0..capacity as usize {
                words.extend([
                    word(commands, 36 + index * 8),
                    word(commands, 40 + index * 8),
                ]);
            }
        } else {
            panic!("unexpected scripted command {command}");
        }
        state.reply_command = command;
        state.reply = words.into_iter().flat_map(u32::to_le_bytes).collect();
    }

    struct TestLock(Mutex<()>);

    // SAFETY: tests run on native test threads, outside an executor. The
    // standard mutex implements mutual exclusion and acquire/release ordering.
    unsafe impl SubmissionLock for TestLock {
        type Guard<'a> = std::sync::MutexGuard<'a, ()>;
        fn new() -> Self {
            Self(Mutex::new(()))
        }
        fn lock(&self) -> Self::Guard<'_> {
            self.0.lock().unwrap()
        }
    }

    struct TestFactory;

    impl TransportFactory for TestFactory {
        type Transport = Recording;
        fn create() -> Result<(Recording, Capset), TestError> {
            let transport = Recording(Arc::new(Mutex::new(Recorded {
                scripted: true,
                ..Recorded::default()
            })));
            let capset = Capset {
                protocol: RendererProtocol::with_all_extensions(api_version(1, 3)),
                serialization_version: 1,
                venus_version: 4,
                allows_wait_syncs: false,
                multiple_timelines: true,
                guest_vram: false,
            };
            Ok((transport, capset))
        }
    }

    impl Factory for TestFactory {
        type Lock = TestLock;
    }

    struct SyncDevice {
        instance: ash::Instance,
        device: ash::Device,
        queue: vk::Queue,
        recorded: Arc<Mutex<Recorded>>,
    }

    impl SyncDevice {
        fn new() -> Self {
            let (transport, capset) = TestFactory::create().unwrap();
            let recorded = transport.0.clone();
            let configuration = TestFactory::configuration();
            let connection = Connection::new(
                transport,
                capset,
                configuration.layout,
                configuration.idle_timeout,
            )
            .unwrap();
            // SAFETY: the test renderer accepts these live creation structures.
            unsafe {
                let instance = helios_venus::driver::instance_from_connection::<TestFactory>(
                    connection,
                    &vk::InstanceCreateInfo::default(),
                    None,
                )
                .unwrap();
                let physical = instance.enumerate_physical_devices().unwrap()[0];
                let priorities = [1.0];
                let queues = [vk::DeviceQueueCreateInfo::default()
                    .queue_family_index(0)
                    .queue_priorities(&priorities)];
                let device = instance
                    .create_device(
                        physical,
                        &vk::DeviceCreateInfo::default().queue_create_infos(&queues),
                        None,
                    )
                    .unwrap();
                let queue = device.get_device_queue(0, 0);
                Self {
                    instance,
                    device,
                    queue,
                    recorded,
                }
            }
        }

        fn observe_latest_wait(&self) -> std::sync::mpsc::Receiver<()> {
            let timeline = self
                .recorded
                .lock()
                .unwrap()
                .timelines
                .last()
                .unwrap()
                .upgrade()
                .unwrap();
            let (entered, receiver) = std::sync::mpsc::channel();
            timeline.lock().unwrap().wait_started = Some(entered);
            receiver
        }
    }

    impl Drop for SyncDevice {
        fn drop(&mut self) {
            // SAFETY: tests join their threads and destroy children before the fixture.
            unsafe {
                self.device.destroy_device(None);
                self.instance.destroy_instance(None);
            }
        }
    }

    #[test]
    fn fences_wait_for_future_submissions_and_reset_by_generation() {
        let fixture = SyncDevice::new();
        let device = &fixture.device;
        // SAFETY: all handles are owned here; reset occurs after completion and threads join before destruction.
        unsafe {
            let fence = device
                .create_fence(&vk::FenceCreateInfo::default(), None)
                .unwrap();
            assert!(!device.get_fence_status(fence).unwrap());
            assert_eq!(
                device.wait_for_fences(&[fence], true, 0),
                Err(vk::Result::TIMEOUT)
            );
            let started = fixture.observe_latest_wait();
            std::thread::scope(|scope| {
                let waiting = scope.spawn(|| device.wait_for_fences(&[fence], true, 5_000_000_000));
                started
                    .recv_timeout(Duration::from_secs(1))
                    .expect("fence wait is registered before submission");
                device.queue_submit(fixture.queue, &[], fence).unwrap();
                waiting.join().unwrap().unwrap();
            });
            assert!(device.get_fence_status(fence).unwrap());
            device.reset_fences(&[fence]).unwrap();
            assert!(!device.get_fence_status(fence).unwrap());
            assert_eq!(
                device.wait_for_fences(&[fence], true, 0),
                Err(vk::Result::TIMEOUT)
            );
            let signaled = device
                .create_fence(
                    &vk::FenceCreateInfo::default().flags(vk::FenceCreateFlags::SIGNALED),
                    None,
                )
                .unwrap();
            device
                .wait_for_fences(&[fence, signaled], false, 0)
                .unwrap();
            assert_eq!(
                device.wait_for_fences(&[fence, signaled], true, 0),
                Err(vk::Result::TIMEOUT)
            );
            device.queue_submit2(fixture.queue, &[], fence).unwrap();
            device.wait_for_fences(&[fence, signaled], true, 0).unwrap();
            device.destroy_fence(fence, None);
            device.destroy_fence(signaled, None);
        }
    }

    #[test]
    fn timeline_semaphore_waits_allow_future_cpu_signals_and_any_all_selection() {
        let fixture = SyncDevice::new();
        let device = &fixture.device;
        // SAFETY: semaphore values advance, and every wait's arrays live until it returns.
        unsafe {
            let mut kind = vk::SemaphoreTypeCreateInfo::default()
                .semaphore_type(vk::SemaphoreType::TIMELINE)
                .initial_value(3);
            let left = device
                .create_semaphore(
                    &vk::SemaphoreCreateInfo::default().push_next(&mut kind),
                    None,
                )
                .unwrap();
            assert_eq!(device.get_semaphore_counter_value(left).unwrap(), 3);
            let handles = [left];
            let values = [4];
            assert_eq!(
                device.wait_semaphores(
                    &vk::SemaphoreWaitInfo::default()
                        .semaphores(&handles)
                        .values(&values),
                    0
                ),
                Err(vk::Result::TIMEOUT)
            );
            let started = fixture.observe_latest_wait();
            std::thread::scope(|scope| {
                let waiting = scope.spawn(|| {
                    device.wait_semaphores(
                        &vk::SemaphoreWaitInfo::default()
                            .semaphores(&handles)
                            .values(&values),
                        5_000_000_000,
                    )
                });
                started
                    .recv_timeout(Duration::from_secs(1))
                    .expect("timeline wait is registered before CPU signal");
                device
                    .signal_semaphore(&vk::SemaphoreSignalInfo::default().semaphore(left).value(4))
                    .unwrap();
                waiting.join().unwrap().unwrap();
            });
            assert_eq!(device.get_semaphore_counter_value(left).unwrap(), 4);
            kind.initial_value = 0;
            let right = device
                .create_semaphore(
                    &vk::SemaphoreCreateInfo::default().push_next(&mut kind),
                    None,
                )
                .unwrap();
            let handles = [left, right];
            let values = [4, 1];
            device
                .wait_semaphores(
                    &vk::SemaphoreWaitInfo::default()
                        .flags(vk::SemaphoreWaitFlags::ANY)
                        .semaphores(&handles)
                        .values(&values),
                    0,
                )
                .unwrap();
            assert_eq!(
                device.wait_semaphores(
                    &vk::SemaphoreWaitInfo::default()
                        .semaphores(&handles)
                        .values(&values),
                    0
                ),
                Err(vk::Result::TIMEOUT)
            );
            device.destroy_semaphore(left, None);
            device.destroy_semaphore(right, None);
        }
    }

    #[test]
    fn each_submit_batch_signals_its_timeline_values_before_the_next_batch() {
        let fixture = SyncDevice::new();
        let device = &fixture.device;
        // SAFETY: all submissions use live semaphores and increasing timeline values.
        unsafe {
            let mut kind =
                vk::SemaphoreTypeCreateInfo::default().semaphore_type(vk::SemaphoreType::TIMELINE);
            let semaphore = device
                .create_semaphore(
                    &vk::SemaphoreCreateInfo::default().push_next(&mut kind),
                    None,
                )
                .unwrap();
            let handles = [semaphore];
            let first = [3];
            let second = [7];
            let mut first_timeline =
                vk::TimelineSemaphoreSubmitInfo::default().signal_semaphore_values(&first);
            let mut second_timeline =
                vk::TimelineSemaphoreSubmitInfo::default().signal_semaphore_values(&second);
            let submits = [
                vk::SubmitInfo::default()
                    .signal_semaphores(&handles)
                    .push_next(&mut first_timeline),
                vk::SubmitInfo::default()
                    .signal_semaphores(&handles)
                    .push_next(&mut second_timeline),
            ];
            let before = fixture
                .recorded
                .lock()
                .unwrap()
                .submitted
                .iter()
                .filter(|(ring, _)| *ring != 0)
                .count();
            device
                .queue_submit(fixture.queue, &submits, vk::Fence::null())
                .unwrap();
            let after = fixture
                .recorded
                .lock()
                .unwrap()
                .submitted
                .iter()
                .filter(|(ring, _)| *ring != 0)
                .count();
            assert_eq!(after - before, 2);
            device
                .wait_semaphores(
                    &vk::SemaphoreWaitInfo::default()
                        .semaphores(&handles)
                        .values(&second),
                    0,
                )
                .unwrap();
            assert_eq!(device.get_semaphore_counter_value(semaphore).unwrap(), 7);
            let signals = [vk::SemaphoreSubmitInfo::default()
                .semaphore(semaphore)
                .value(11)
                .stage_mask(vk::PipelineStageFlags2::ALL_COMMANDS)];
            device
                .queue_submit2(
                    fixture.queue,
                    &[vk::SubmitInfo2::default().signal_semaphore_infos(&signals)],
                    vk::Fence::null(),
                )
                .unwrap();
            device
                .wait_semaphores(
                    &vk::SemaphoreWaitInfo::default()
                        .semaphores(&handles)
                        .values(&[11]),
                    0,
                )
                .unwrap();
            device.destroy_semaphore(semaphore, None);
        }
    }

    #[test]
    fn connection_failure_wakes_an_unsignaled_fence_wait() {
        let fixture = SyncDevice::new();
        let device = &fixture.device;
        // SAFETY: the failure is injected through the recording transport; cleanup still uses live handles.
        unsafe {
            let fence = device
                .create_fence(&vk::FenceCreateInfo::default(), None)
                .unwrap();
            let started = fixture.observe_latest_wait();
            std::thread::scope(|scope| {
                let waiting = scope.spawn(|| device.wait_for_fences(&[fence], true, 5_000_000_000));
                started
                    .recv_timeout(Duration::from_secs(1))
                    .expect("fence wait is registered before failure");
                fixture.recorded.lock().unwrap().premature_completion = true;
                assert_eq!(
                    device.create_buffer(
                        &vk::BufferCreateInfo::default()
                            .size(64)
                            .usage(vk::BufferUsageFlags::STORAGE_BUFFER),
                        None
                    ),
                    Err(vk::Result::ERROR_DEVICE_LOST)
                );
                assert_eq!(waiting.join().unwrap(), Err(vk::Result::ERROR_DEVICE_LOST));
            });
            device.destroy_fence(fence, None);
        }
    }

    #[test]
    fn explicit_connection_is_used_for_instance_creation() {
        let (transport, capset) = TestFactory::create().unwrap();
        let recorded = transport.0.clone();
        let configuration = TestFactory::configuration();
        let connection = Connection::new(
            transport,
            capset,
            configuration.layout,
            configuration.idle_timeout,
        )
        .unwrap();
        // SAFETY: the test owns the connection and the complete object tree.
        unsafe {
            let instance = helios_venus::driver::instance_from_connection::<TestFactory>(
                connection,
                &vk::InstanceCreateInfo::default(),
                None,
            )
            .unwrap();
            assert!(recorded.lock().unwrap().consumed.iter().any(|commands| {
                word(commands, 0) as i32 == wire::VK_COMMAND_TYPE_vkSetReplyCommandStreamMESA_EXT.0
                    && word(commands, 36) as i32 == wire::VK_COMMAND_TYPE_vkCreateInstance_EXT.0
            }));
            assert_eq!(instance.enumerate_physical_devices().unwrap().len(), 2);
            instance.destroy_instance(None);
        }
        assert!(
            recorded
                .lock()
                .unwrap()
                .blobs
                .values()
                .all(|blob| blob.upgrade().is_none())
        );
    }

    #[test]
    fn ash_instances_have_independent_connections_and_stable_physical_handles() {
        let entry = entry::<TestFactory>();
        // SAFETY: the factory's recorded renderer implements these requests.
        unsafe {
            assert_eq!(
                entry.try_enumerate_instance_version().unwrap(),
                Some(api_version(1, 3))
            );
            let info = vk::InstanceCreateInfo::default();
            let first = entry.create_instance(&info, None).unwrap();
            let second = entry.create_instance(&info, None).unwrap();
            assert_ne!(first.handle(), second.handle());
            let first_base = &*(first.handle().as_raw() as usize as *const ObjectBase);
            let second_base = &*(second.handle().as_raw() as usize as *const ObjectBase);
            assert_eq!(
                first_base.id, second_base.id,
                "each context owns its identifier space"
            );
            let physical = first.enumerate_physical_devices().unwrap();
            assert_eq!(physical.len(), 2);
            assert_eq!(physical, first.enumerate_physical_devices().unwrap());
            assert_ne!(physical, second.enumerate_physical_devices().unwrap());
            let mut count = 1;
            let mut single = vk::PhysicalDevice::null();
            assert_eq!(
                (first.fp_v1_0().enumerate_physical_devices)(
                    first.handle(),
                    &mut count,
                    &mut single
                ),
                vk::Result::INCOMPLETE
            );
            assert_eq!(count, 1);
            assert_eq!(single, physical[0]);
            first.destroy_instance(None);
            assert_eq!(second.enumerate_physical_devices().unwrap().len(), 2);
            second.destroy_instance(None);
        }
    }

    #[test]
    fn gpu_idle_waits_release_the_submission_lock() {
        let (transport, capset) = TestFactory::create().unwrap();
        let recorded = transport.0.clone();
        let configuration = TestFactory::configuration();
        let connection = Connection::new(
            transport,
            capset,
            configuration.layout,
            configuration.idle_timeout,
        )
        .unwrap();
        // SAFETY: the test owns every Vulkan object and joins both threads
        // before destruction. Queue lookup does not externally synchronize
        // with queue-idle or device-idle.
        unsafe {
            let instance = helios_venus::driver::instance_from_connection::<TestFactory>(
                connection,
                &vk::InstanceCreateInfo::default(),
                None,
            )
            .unwrap();
            let physical = instance.enumerate_physical_devices().unwrap()[0];
            let priorities = [1.0];
            let queues = [vk::DeviceQueueCreateInfo::default()
                .queue_family_index(0)
                .queue_priorities(&priorities)];
            let device = instance
                .create_device(
                    physical,
                    &vk::DeviceCreateInfo::default().queue_create_infos(&queues),
                    None,
                )
                .unwrap();
            let queue = device.get_device_queue(0, 0);
            for device_wide in [false, true] {
                let (entered, started) = std::sync::mpsc::channel();
                let (release, held) = std::sync::mpsc::channel();
                recorded.lock().unwrap().gpu_wait_hold = Some((entered, held));
                std::thread::scope(|scope| {
                    let waiting = scope.spawn(|| {
                        if device_wide {
                            device.device_wait_idle()
                        } else {
                            device.queue_wait_idle(queue)
                        }
                    });
                    started
                        .recv_timeout(Duration::from_secs(5))
                        .expect("idle call enters its GPU wait");
                    let (completed, progress) = std::sync::mpsc::channel();
                    let lookup_device = &device;
                    let lookup = scope.spawn(move || {
                        completed
                            .send(lookup_device.get_device_queue(0, 0))
                            .unwrap()
                    });
                    let result = progress.recv_timeout(Duration::from_secs(1));
                    release.send(()).unwrap();
                    waiting.join().unwrap().unwrap();
                    lookup.join().unwrap();
                    assert_eq!(
                        result.expect("queue lookup progresses while GPU completion is held"),
                        queue
                    );
                });
            }
            device.destroy_device(None);
            instance.destroy_instance(None);
        }
    }

    #[test]
    fn ash_devices_own_stable_queues_and_generated_object_ids() {
        let entry = entry::<TestFactory>();
        // SAFETY: all objects below follow Vulkan creation and lifetime rules;
        // the recorded transport supplies their renderer replies.
        unsafe {
            let instance = entry
                .create_instance(&vk::InstanceCreateInfo::default(), None)
                .unwrap();
            let physical = instance.enumerate_physical_devices().unwrap()[0];
            let priorities = [0.5, 1.0];
            let queues = [vk::DeviceQueueCreateInfo::default()
                .queue_family_index(0)
                .queue_priorities(&priorities)];
            let info = vk::DeviceCreateInfo::default().queue_create_infos(&queues);
            let first = instance.create_device(physical, &info, None).unwrap();
            let second = instance.create_device(physical, &info, None).unwrap();
            let queue = first.get_device_queue(0, 0);
            assert_eq!(
                queue,
                first.get_device_queue2(
                    &vk::DeviceQueueInfo2::default()
                        .queue_family_index(0)
                        .queue_index(0)
                )
            );
            assert_ne!(queue, first.get_device_queue(0, 1));
            assert_ne!(queue, second.get_device_queue(0, 0));
            let buffer_info = vk::BufferCreateInfo::default()
                .size(4096)
                .usage(vk::BufferUsageFlags::STORAGE_BUFFER)
                .sharing_mode(vk::SharingMode::EXCLUSIVE);
            let first_buffer = first.create_buffer(&buffer_info, None).unwrap();
            let second_buffer = second.create_buffer(&buffer_info, None).unwrap();
            assert_ne!(first_buffer, vk::Buffer::null());
            assert_ne!(first_buffer, second_buffer);
            first.destroy_buffer(first_buffer, None);
            first.queue_wait_idle(queue).unwrap();
            first.destroy_device(None);
            second.destroy_buffer(second_buffer, None);
            second.device_wait_idle().unwrap();
            second.destroy_device(None);
            instance.destroy_instance(None);
        }
    }

    #[test]
    fn ash_command_buffers_dispatch_through_their_pool_owner() {
        let entry = entry::<TestFactory>();
        // SAFETY: buffers are recorded and freed without any pending GPU use.
        unsafe {
            let instance = entry
                .create_instance(&vk::InstanceCreateInfo::default(), None)
                .unwrap();
            let physical = instance.enumerate_physical_devices().unwrap()[0];
            let priorities = [1.0];
            let queues = [vk::DeviceQueueCreateInfo::default()
                .queue_family_index(0)
                .queue_priorities(&priorities)];
            let device = instance
                .create_device(
                    physical,
                    &vk::DeviceCreateInfo::default().queue_create_infos(&queues),
                    None,
                )
                .unwrap();
            let pool = device
                .create_command_pool(
                    &vk::CommandPoolCreateInfo::default().queue_family_index(0),
                    None,
                )
                .unwrap();
            let buffers = device
                .allocate_command_buffers(
                    &vk::CommandBufferAllocateInfo::default()
                        .command_pool(pool)
                        .level(vk::CommandBufferLevel::PRIMARY)
                        .command_buffer_count(3),
                )
                .unwrap();
            assert_eq!(buffers.len(), 3);
            assert_ne!(buffers[0], buffers[1]);
            assert_ne!(buffers[1], buffers[2]);
            for &buffer in &buffers {
                device
                    .begin_command_buffer(buffer, &vk::CommandBufferBeginInfo::default())
                    .unwrap();
                device.end_command_buffer(buffer).unwrap();
            }
            device.free_command_buffers(pool, &[buffers[0], vk::CommandBuffer::null()]);
            // Pool destruction implicitly frees the remaining two buffers.
            device.destroy_command_pool(pool, None);
            device.device_wait_idle().unwrap();
            device.destroy_device(None);
            instance.destroy_instance(None);
        }
    }

    #[test]
    fn ash_memory_maps_offsets_and_retains_its_blob_across_remaps() {
        let entry = entry::<TestFactory>();
        // SAFETY: the test owns every object and performs no GPU work while
        // accessing its coherent mapped allocation.
        unsafe {
            let instance = entry
                .create_instance(&vk::InstanceCreateInfo::default(), None)
                .unwrap();
            let physical = instance.enumerate_physical_devices().unwrap()[0];
            let priorities = [1.0];
            let queues = [vk::DeviceQueueCreateInfo::default()
                .queue_family_index(0)
                .queue_priorities(&priorities)];
            let device = instance
                .create_device(
                    physical,
                    &vk::DeviceCreateInfo::default().queue_create_infos(&queues),
                    None,
                )
                .unwrap();
            let memory = device
                .allocate_memory(
                    &vk::MemoryAllocateInfo::default()
                        .allocation_size(4096)
                        .memory_type_index(0),
                    None,
                )
                .unwrap();
            let part = device
                .map_memory(memory, 256, 256, vk::MemoryMapFlags::empty())
                .unwrap()
                .cast::<u32>();
            for index in 0..8 {
                part.add(index).write_volatile(index as u32 + 17);
            }
            let range = [vk::MappedMemoryRange::default()
                .memory(memory)
                .offset(256)
                .size(256)];
            device.flush_mapped_memory_ranges(&range).unwrap();
            device.unmap_memory(memory);
            let full = device
                .map_memory(memory, 0, vk::WHOLE_SIZE, vk::MemoryMapFlags::empty())
                .unwrap()
                .cast::<u32>();
            device.invalidate_mapped_memory_ranges(&range).unwrap();
            assert_eq!(full.add(64), part);
            for index in 0..8 {
                assert_eq!(full.add(index + 64).read_volatile(), index as u32 + 17);
            }
            device.unmap_memory(memory);
            device.free_memory(memory, None);
            device.destroy_device(None);
            instance.destroy_instance(None);
        }
    }

    #[test]
    fn freeing_memory_after_device_loss_releases_its_mapping() {
        let (transport, capset) = TestFactory::create().unwrap();
        let recorded = transport.0.clone();
        let configuration = TestFactory::configuration();
        let connection = Connection::new(
            transport,
            capset,
            configuration.layout,
            configuration.idle_timeout,
        )
        .unwrap();
        // SAFETY: the test owns all objects and submits no GPU work using
        // this allocation; a recorded transport fault exercises cleanup.
        unsafe {
            let instance = helios_venus::driver::instance_from_connection::<TestFactory>(
                connection,
                &vk::InstanceCreateInfo::default(),
                None,
            )
            .unwrap();
            let physical = instance.enumerate_physical_devices().unwrap()[0];
            let priorities = [1.0];
            let queues = [vk::DeviceQueueCreateInfo::default()
                .queue_family_index(0)
                .queue_priorities(&priorities)];
            let device = instance
                .create_device(
                    physical,
                    &vk::DeviceCreateInfo::default().queue_create_infos(&queues),
                    None,
                )
                .unwrap();
            let memory = device
                .allocate_memory(
                    &vk::MemoryAllocateInfo::default()
                        .allocation_size(4096)
                        .memory_type_index(0),
                    None,
                )
                .unwrap();
            device
                .map_memory(memory, 0, vk::WHOLE_SIZE, vk::MemoryMapFlags::empty())
                .unwrap();
            let mapping = {
                let mut recorded = recorded.lock().unwrap();
                let mapping = recorded.blobs[&recorded.next].clone();
                recorded.premature_completion = true;
                mapping
            };
            assert!(mapping.upgrade().is_some());
            let error = device
                .create_buffer(
                    &vk::BufferCreateInfo::default()
                        .size(4096)
                        .usage(vk::BufferUsageFlags::STORAGE_BUFFER),
                    None,
                )
                .unwrap_err();
            assert_eq!(error, vk::Result::ERROR_DEVICE_LOST);
            device.free_memory(memory, None);
            assert!(
                mapping.upgrade().is_none(),
                "device loss must not defer memory release to device destruction"
            );
            device.destroy_device(None);
            instance.destroy_instance(None);
        }
    }

    #[derive(Default)]
    struct Allocations {
        live: Mutex<BTreeMap<usize, std::alloc::Layout>>,
        created: std::sync::atomic::AtomicUsize,
        freed: std::sync::atomic::AtomicUsize,
        refuse: bool,
    }

    unsafe extern "system" fn allocate(
        user: *mut core::ffi::c_void,
        size: usize,
        alignment: usize,
        scope: vk::SystemAllocationScope,
    ) -> *mut core::ffi::c_void {
        // SAFETY: the test keeps userdata alive until instance destruction.
        let state = unsafe { &*user.cast::<Allocations>() };
        assert_eq!(scope.as_raw(), vk::SystemAllocationScope::INSTANCE.as_raw());
        if state.refuse {
            return core::ptr::null_mut();
        }
        let layout = std::alloc::Layout::from_size_align(size, alignment).unwrap();
        // SAFETY: the driver requests a valid nonempty object layout.
        let pointer = unsafe { std::alloc::alloc(layout) };
        if !pointer.is_null() {
            state.live.lock().unwrap().insert(pointer as usize, layout);
            state.created.fetch_add(1, Ordering::Relaxed);
        }
        pointer.cast()
    }

    unsafe extern "system" fn release(
        user: *mut core::ffi::c_void,
        pointer: *mut core::ffi::c_void,
    ) {
        if pointer.is_null() {
            return;
        }
        // SAFETY: userdata and this allocation were supplied by the test.
        let state = unsafe { &*user.cast::<Allocations>() };
        let layout = state
            .live
            .lock()
            .unwrap()
            .remove(&(pointer as usize))
            .unwrap();
        // SAFETY: the stored layout is exactly the original allocation's.
        unsafe { std::alloc::dealloc(pointer.cast(), layout) };
        state.freed.fetch_add(1, Ordering::Relaxed);
    }

    unsafe extern "system" fn reallocate(
        user: *mut core::ffi::c_void,
        old: *mut core::ffi::c_void,
        size: usize,
        alignment: usize,
        scope: vk::SystemAllocationScope,
    ) -> *mut core::ffi::c_void {
        if size == 0 {
            // SAFETY: the callback caller returns its existing allocation.
            unsafe { release(user, old) };
            return core::ptr::null_mut();
        }
        // SAFETY: the same valid callback parameters as allocation.
        let pointer = unsafe { allocate(user, size, alignment, scope) };
        if !pointer.is_null() && !old.is_null() {
            let state = unsafe { &*user.cast::<Allocations>() };
            let old_size = state.live.lock().unwrap()[&(old as usize)].size();
            // SAFETY: distinct live allocations; the smaller size bounds both.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    old.cast::<u8>(),
                    pointer.cast::<u8>(),
                    old_size.min(size),
                );
                release(user, old);
            }
        }
        pointer
    }

    #[test]
    fn instance_allocations_use_and_release_the_supplied_callbacks() {
        for refuse in [false, true] {
            let mut allocations = Allocations {
                refuse,
                ..Allocations::default()
            };
            let callbacks = vk::AllocationCallbacks::default()
                .user_data((&raw mut allocations).cast())
                .pfn_allocation(Some(allocate))
                .pfn_reallocation(Some(reallocate))
                .pfn_free(Some(release));
            let entry = entry::<TestFactory>();
            // SAFETY: callback state outlives every instance and child object.
            let result = unsafe {
                entry.create_instance(&vk::InstanceCreateInfo::default(), Some(&callbacks))
            };
            if refuse {
                assert!(matches!(result, Err(vk::Result::ERROR_OUT_OF_HOST_MEMORY)));
            } else {
                let instance = result.unwrap();
                // SAFETY: the instance is live and owns its physical devices.
                unsafe {
                    assert_eq!(instance.enumerate_physical_devices().unwrap().len(), 2);
                    instance.destroy_instance(Some(&callbacks));
                }
                assert_eq!(allocations.created.load(Ordering::Relaxed), 3);
            }
            assert!(allocations.live.lock().unwrap().is_empty());
            assert_eq!(
                allocations.created.load(Ordering::Relaxed),
                allocations.freed.load(Ordering::Relaxed)
            );
        }
    }
}
