use core::cell::{RefCell, UnsafeCell};
use core::num::{NonZeroU32, NonZeroU64};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::rc::{Rc, Weak};
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

struct Blob {
    id: u32,
    memory: Rc<Memory>,
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
}

struct Recording(Rc<RefCell<Recorded>>);

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

impl Transport for Recording {
    type Error = Infallible;
    type Blob = Blob;

    fn create_blob(&mut self, size: NonZeroU64, _blob_id: u64) -> Result<Blob, Infallible> {
        let memory = Rc::new(Memory(
            (0..size.get().div_ceil(4))
                .map(|_| UnsafeCell::new(0))
                .collect(),
        ));
        let mut state = self.0.borrow_mut();
        state.next += 1;
        let id = state.next;
        state.blobs.insert(id, Rc::downgrade(&memory));
        Ok(Blob { id, memory })
    }

    fn execute(&mut self, commands: &[u8], ring: u8, fence: Option<u64>) -> Result<(), Infallible> {
        assert_eq!(ring, 0);
        let mut state = self.0.borrow_mut();
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
        let mut state = self.0.borrow_mut();
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

fn connection(state: Rc<RefCell<Recorded>>) -> Connection<Recording> {
    connection_with_capacity(state, 64)
}

fn connection_with_capacity(state: Rc<RefCell<Recorded>>, capacity: u32) -> Connection<Recording> {
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
    let state = Rc::new(RefCell::new(Recorded::default()));
    let mut connection = connection(state.clone());
    let direct = [0xff; 64];
    let indirect = vec![0x5a; 1024];
    connection.send(&direct).unwrap();
    connection.send(&indirect).unwrap();
    assert_eq!(state.borrow().consumed, [direct.to_vec()]);
    assert!(state.borrow().blobs[&2].upgrade().is_some());
    connection.flush().unwrap();
    assert_eq!(state.borrow().consumed, [direct.to_vec(), indirect]);
    assert!(state.borrow().blobs[&2].upgrade().is_none());
    connection.close().unwrap();
    assert!(state.borrow().blobs[&1].upgrade().is_none());
    assert!(
        state
            .borrow()
            .sequences
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
}

#[test]
fn a_transport_acknowledgement_does_not_replace_ring_consumption() {
    let state = Rc::new(RefCell::new(Recorded::default()));
    let mut connection = connection(state.clone());
    connection.send(&[0xff; 4]).unwrap();
    state.borrow_mut().premature_completion = true;
    assert!(matches!(
        connection.flush(),
        Err(Error::IncompleteWait { sequence: 4 })
    ));
}

#[test]
fn generated_calls_select_a_reply_stream_and_decode_the_renderer_result() {
    let state = Rc::new(RefCell::new(Recorded {
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
    let state = Rc::new(RefCell::new(Recorded {
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
