use core::cell::UnsafeCell;
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};
use std::collections::BTreeMap;
use std::convert::Infallible;
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
use helios_venus::transport::{MappedBlob, Transport};
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
    blobs: BTreeMap<u32, Weak<Memory>>,
    ring: Option<u32>,
    sequences: Vec<u64>,
    consumed: Vec<Vec<u8>>,
    pending: Option<u32>,
    premature_completion: bool,
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

impl Transport for Recording {
    type Error = Infallible;
    type Blob = Blob;

    fn create_blob(&mut self, size: NonZeroU64, blob_id: u64) -> Result<Blob, Infallible> {
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

    fn execute(&mut self, commands: &[u8], ring: u8, fence: Option<u64>) -> Result<(), Infallible> {
        assert_eq!(ring, 0);
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
        if let Some(fence) = fence {
            state.sequences.push(fence);
        }
        Ok(())
    }

    fn wait(&mut self, ring: u8, fence: u64) -> Result<(), Infallible> {
        assert_eq!(ring, 0);
        let mut state = self.0.lock().unwrap();
        assert_eq!(state.sequences.last(), Some(&fence));
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
        if command == wire::VK_COMMAND_TYPE_vkCreateInstance_EXT.0 {
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
        fn create() -> Result<(Recording, Capset), Infallible> {
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
