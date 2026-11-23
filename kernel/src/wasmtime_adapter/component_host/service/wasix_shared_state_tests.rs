use super::*;
use crate::TaskFunding;
use crate::isa::GuestIsa;
use crate::test_support::{TestCpu, TestNetworkService, UnsupportedStorage};
use crate::wasmtime_adapter::engine::build_component_engine_for_platform;
use crate::wasmtime_adapter::preemption::GuestInterrupts;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

/// WASI preview1 `oflags::creat` bit (`__WASI_OFLAGS_CREAT`).
const TEST_OFLAG_CREAT: u16 = 1;
/// WASI preview1 `oflags::trunc` bit (`__WASI_OFLAGS_TRUNC`).
const TEST_OFLAG_TRUNC: u16 = 8;
use futures_lite::future::block_on;
use helios_hal::cpu::{Cpu, ProcessorId};
use helios_hal::watchdog::ProgressCounter;
use helios_unix::ChildTermination;
use triomphe::Arc as SharedArc;
use wasmtime::{MemoryType, SharedMemory};

type TestProgramStore = Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>;
type TestStore = wasmtime::Store<TestProgramStore>;

fn read_nothing(_: &mut Vec<u8>, _: u32) {}

#[derive(Default)]
struct CountingWaker {
    wakes: AtomicUsize,
}

impl CountingWaker {
    fn wakes(&self) -> usize {
        self.wakes.load(Ordering::Acquire)
    }
}

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::AcqRel);
    }
}

struct SharedStateFixture {
    engine: wasmtime::Engine,
    cpu: TestCpu,
    timer: crate::Timer<TestCpu>,
    spawner: crate::InstanceSpawner<TestCpu>,
    runtime_state: HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage>,
    interrupts: Arc<GuestInterrupts>,
    registry: crate::InstanceRegistry,
    authority: ProcessAuthority,
}

impl SharedStateFixture {
    fn new() -> Self {
        let cpu = TestCpu::with_entropy(0x62);
        let engine = build_component_engine_for_platform(&cpu)
            .expect("component engine builds on test platform");
        let interrupts = Arc::new(GuestInterrupts::new(1, cpu.timebase()));
        let runtime_state: HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage> =
            crate::RuntimeState::new(
                cpu.timebase(),
                1,
                0,
                crate::BootPayload::for_tests(),
                GuestIsa::for_build_target(cpu.native_feature_probe()),
            );
        runtime_state.install_root_entropy(SharedArc::new(
            crate::RootEntropy::from_platform(
                &cpu,
                None,
                None,
                crate::MachineGeneration::new(None),
            )
            .expect("fixture CPU has entropy"),
        ));
        let executor = crate::Executor::new(
            ProgressCounter::new(),
            crate::test_support::single_node_pool(4),
            ProcessorId::new(0),
        );
        let registry = crate::InstanceRegistry::new();
        let parent_instance = registry.register("shared-state-fixture", 0);
        let spawner = executor
            .spawner(cpu)
            .instance_spawner(TaskFunding::Instance, &parent_instance);
        let timer = executor.timer(cpu);

        let mut authority = ProcessAuthority::empty();
        authority.grant_process_rights(
            crate::ProcessAuthorityRights::SPAWN
                | crate::ProcessAuthorityRights::EXEC
                | crate::ProcessAuthorityRights::JOIN
                | crate::ProcessAuthorityRights::SIGNAL,
        );
        authority.insert_directory_preopen(
            crate::DirectoryPreopen::new(
                "/workspace",
                "/workspace",
                crate::DirectoryAuthorityRights::READ
                    | crate::DirectoryAuthorityRights::WRITE
                    | crate::DirectoryAuthorityRights::MUTATE_DIRECTORY,
            )
            .expect("workspace preopen is valid"),
        );
        let cwd_cap = authority
            .derive_directory_cap(
                "/workspace",
                "/workspace",
                crate::DirectoryAuthorityRights::READ
                    | crate::DirectoryAuthorityRights::WRITE
                    | crate::DirectoryAuthorityRights::MUTATE_DIRECTORY,
            )
            .expect("workspace cwd cap derives");
        authority.chdir(cwd_cap);

        Self {
            engine,
            cpu,
            timer,
            spawner,
            runtime_state,
            interrupts,
            registry,
            authority,
        }
    }

    fn make_process_store(
        &self,
        name: &str,
        authority: ProcessAuthority,
        descriptors: DescriptorOrigin<TestNetworkService>,
        filesystem: Option<Namespace<UnsupportedStorage>>,
    ) -> (TestStore, SharedMemory) {
        let instance = self.registry.register(name, 0);
        let memory = SharedMemory::new(
            &self.engine,
            MemoryType::shared(1, 2).expect("shared memory type builds"),
        )
        .expect("shared memory allocates");
        let threads = WasixProcessThreads::new();
        let signal_state = WasixSignalState::new();
        let store_data = Preview1ProgramStore::new(
            self.cpu,
            self.timer.clone(),
            self.spawner.clone(),
            self.runtime_state.clone(),
            self.interrupts.clone(),
            instance,
            None,
            alloc::vec![name.to_owned()],
            Vec::new(),
            authority,
            OutputMode::Serial,
            read_nothing,
            crate::DebugSerialWriter::of::<test_store::DiscardPort>(),
            Some(memory.clone()),
            filesystem,
            descriptors,
            signal_state,
            threads.main_mailbox(),
            Vec::new(),
            None,
            true,
            threads,
        );
        let store = wasmtime::Store::new(&self.engine, store_data);
        (store, memory)
    }

    fn make_sibling_store(
        &self,
        parent: &TestProgramStore,
    ) -> (u32, Arc<WasixThreadExit>, TestStore) {
        let mailbox = WasixSignalState::new();
        let exit = Arc::new(WasixThreadExit::new());
        let tid = parent
            .threads
            .admit(mailbox.clone(), exit.clone())
            .expect("live process admits sibling thread");
        let mut store_data = parent.spawn_thread_store(mailbox);
        store_data.set_thread_id(tid);
        let store = wasmtime::Store::new(&self.engine, store_data);
        (tid, exit, store)
    }

    fn run_in_caller<R: Send + 'static>(
        &self,
        store: &mut TestStore,
        probe: impl FnOnce(
            wasmtime::Caller<'_, TestProgramStore>,
        ) -> Pin<Box<dyn Future<Output = R> + Send + '_>>
        + Send
        + Sync
        + 'static,
    ) -> R {
        let result = std::sync::Arc::new(std::sync::Mutex::new(None));
        let result_slot = result.clone();
        let probe = std::sync::Mutex::new(Some(probe));
        let func = wasmtime::Func::wrap_async(&mut *store, move |caller, (): ()| {
            let probe = probe
                .lock()
                .expect("probe mutex")
                .take()
                .expect("probe runs once");
            let result_slot = result_slot.clone();
            Box::new(async move {
                let value = probe(caller).await;
                *result_slot.lock().expect("result mutex") = Some(value);
                Ok(())
            })
        });
        block_on(async {
            let typed = func
                .typed::<(), ()>(&*store)
                .expect("probe has unit signature");
            typed
                .call_async(&mut *store, ())
                .await
                .expect("probe call succeeds");
        });
        result
            .lock()
            .expect("result mutex")
            .take()
            .expect("probe produced result")
    }
}

fn write_guest_bytes(memory: &SharedMemory, offset: usize, bytes: &[u8]) {
    for (idx, &byte) in bytes.iter().enumerate() {
        // SAFETY: tests write to disjoint scratch regions inside the shared memory.
        unsafe {
            memory.data()[offset + idx].get().write(byte);
        }
    }
}

fn read_guest_bytes(memory: &SharedMemory, offset: usize, len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| {
            // SAFETY: reading initialized test scratch bytes in shared memory.
            unsafe { memory.data()[offset + idx].get().read() }
        })
        .collect()
}

fn write_guest_u32(memory: &SharedMemory, offset: usize, value: u32) {
    write_guest_bytes(memory, offset, &value.to_le_bytes());
}

fn read_guest_u32(memory: &SharedMemory, offset: usize) -> u32 {
    u32::from_le_bytes(
        read_guest_bytes(memory, offset, 4)
            .try_into()
            .expect("4 bytes"),
    )
}

fn read_guest_u16(memory: &SharedMemory, offset: usize) -> u16 {
    u16::from_le_bytes(
        read_guest_bytes(memory, offset, 2)
            .try_into()
            .expect("2 bytes"),
    )
}

fn read_guest_u64(memory: &SharedMemory, offset: usize) -> u64 {
    u64::from_le_bytes(
        read_guest_bytes(memory, offset, 8)
            .try_into()
            .expect("8 bytes"),
    )
}

fn write_guest_iov(memory: &SharedMemory, iov_offset: usize, buf_ptr: u32, buf_len: u32) {
    write_guest_u32(memory, iov_offset, buf_ptr);
    write_guest_u32(memory, iov_offset + 4, buf_len);
}

fn seed_workspace_dirs(ns: &Namespace<UnsupportedStorage>) {
    block_on(async {
        let root_dir = FsDescriptor {
            path: String::from("/"),
            kind: FsNodeKind::Directory,
            flags: FsDescriptorFlags::READ
                | FsDescriptorFlags::WRITE
                | FsDescriptorFlags::MUTATE_DIRECTORY,
            identity: None,
            mount: None,
            open: None,
        };
        let grant = p1_grant(&root_dir).expect("root grant");
        wasi_fs::create_directory_at(ns, grant, "workspace", 0)
            .await
            .expect("create /workspace");
        let workspace_dir = FsDescriptor {
            path: String::from("/workspace"),
            kind: FsNodeKind::Directory,
            flags: FsDescriptorFlags::READ
                | FsDescriptorFlags::WRITE
                | FsDescriptorFlags::MUTATE_DIRECTORY,
            identity: None,
            mount: None,
            open: None,
        };
        let ws_grant = p1_grant(&workspace_dir).expect("workspace grant");
        wasi_fs::create_directory_at(ns, ws_grant, "sub", 0)
            .await
            .expect("create /workspace/sub");
    });
}

/// Descriptors produced by `fd_dup`, `fd_dup2`, `fd_renumber`, spawn
/// descriptor actions, and exec inheritance share one open file description:
/// offset and POSIX-shared status flags (`APPEND`) stay shared while
/// `close_on_exec` stays per slot. Writing through fd `1` and a duplicate of
/// it into one file reads back both writes in order.
#[test]
fn duplicated_fd1_and_dup_share_open_file_description_and_write_in_order() {
    let fixture = SharedStateFixture::new();
    let (mut store, memory) = fixture.make_process_store(
        "dup-fd1",
        fixture.authority.clone(),
        DescriptorOrigin::Fresh,
        None,
    );
    seed_workspace_dirs(&store.data().filesystem);

    let mem = memory.clone();
    fixture.run_in_caller(&mut store, move |mut caller| {
        Box::pin(async move {
            // Open `/workspace/output.txt` with CREATE | TRUNCATE and read+write.
            let path = b"output.txt";
            write_guest_bytes(&mem, 64, path);
            let rights = P1_RIGHT_FD_READ
                | P1_RIGHT_FD_WRITE
                | P1_RIGHT_FD_SEEK
                | P1_RIGHT_FD_TELL
                | P1_RIGHT_FD_FDSTAT_SET_FLAGS;
            assert_eq!(
                wasix_path_open(
                    &mut caller,
                    Preview1ProgramStore::<TestCpu, TestNetworkService, UnsupportedStorage>::WASIX_AT_FDCWD,
                    0,
                    64,
                    path.len() as u32,
                    TEST_OFLAG_CREAT | TEST_OFLAG_TRUNC,
                    rights,
                    0,
                    128,
                )
                .await,
                Ok(p1::errno::SUCCESS)
            );
            let orig_fd = read_guest_u32(&mem, 128) as i32;

            // Redirect fd `1` onto the opened file via WASIX `fd_renumber` (dup2),
            // then duplicate fd `1` via `fd_dup` and `fd_dup2(..., cloexec=true)`.
            assert_eq!(wasix_fd_renumber(&mut caller, orig_fd, 1), p1::errno::SUCCESS);
            assert_eq!(wasix_fd_dup(&mut caller, 1, 132), p1::errno::SUCCESS);
            let dup_fd = read_guest_u32(&mem, 132) as i32;
            assert_ne!(dup_fd, 1);

            assert_eq!(
                wasix_fd_dup2(&mut caller, 1, 12, true, 136),
                p1::errno::SUCCESS
            );
            let cloexec_dup_fd = read_guest_u32(&mem, 136) as i32;
            assert_eq!(cloexec_dup_fd, 12);

            // `close_on_exec` is per slot.
            assert_eq!(wasix_fd_fdflags_get(&mut caller, 1, 140), p1::errno::SUCCESS);
            assert_eq!(read_guest_u16(&mem, 140), 0);
            assert_eq!(
                wasix_fd_fdflags_get(&mut caller, dup_fd, 142),
                p1::errno::SUCCESS
            );
            assert_eq!(read_guest_u16(&mem, 142), 0);
            assert_eq!(
                wasix_fd_fdflags_get(&mut caller, cloexec_dup_fd, 144),
                p1::errno::SUCCESS
            );
            assert_eq!(read_guest_u16(&mem, 144), WASIX_FDFLAGSEXT_CLOEXEC);

            assert_eq!(
                wasix_fd_fdflags_set(&mut caller, dup_fd, WASIX_FDFLAGSEXT_CLOEXEC),
                p1::errno::SUCCESS
            );
            assert_eq!(caller.data().descriptors.close_on_exec(1), Ok(false));
            assert_eq!(caller.data().descriptors.close_on_exec(dup_fd), Ok(true));

            // POSIX-shared status flag `APPEND` set on one duplicate is visible on all others.
            assert_eq!(
                p1_fd_fdstat_set_flags(&mut caller, dup_fd, P1_FDFLAG_APPEND),
                p1::errno::SUCCESS
            );
            assert_eq!(p1_fd_fdstat_get(&mut caller, 1, 160), p1::errno::SUCCESS);
            assert_eq!(read_guest_u16(&mem, 162), P1_FDFLAG_APPEND);
            assert_eq!(
                p1_fd_fdstat_get(&mut caller, cloexec_dup_fd, 192),
                p1::errno::SUCCESS
            );
            assert_eq!(read_guest_u16(&mem, 194), P1_FDFLAG_APPEND);

            // Clear `APPEND` through fd `1` so writes advance the shared offset directly.
            assert_eq!(
                p1_fd_fdstat_set_flags(&mut caller, 1, 0),
                p1::errno::SUCCESS
            );
            assert_eq!(caller.data().descriptors.fdflags(dup_fd), Ok(0));

            // Write `"first-"` through fd `1` and `"second"` through its duplicate.
            let first = b"first-";
            write_guest_bytes(&mem, 256, first);
            write_guest_iov(&mem, 240, 256, first.len() as u32);
            assert_eq!(p1_fd_write(&mut caller, 1, 240, 1, 248).await, Ok(p1::errno::SUCCESS));
            assert_eq!(read_guest_u32(&mem, 248), first.len() as u32);

            let second = b"second";
            write_guest_bytes(&mem, 300, second);
            write_guest_iov(&mem, 280, 300, second.len() as u32);
            assert_eq!(
                p1_fd_write(&mut caller, dup_fd, 280, 1, 288).await,
                Ok(p1::errno::SUCCESS)
            );
            assert_eq!(read_guest_u32(&mem, 288), second.len() as u32);

            // Both slots observe offset 12, and seeking fd `1` to 0 moves the duplicate's offset too.
            assert_eq!(p1_fd_tell(&mut caller, dup_fd, 320).await, Ok(p1::errno::SUCCESS));
            assert_eq!(read_guest_u64(&mem, 320), 12);

            assert_eq!(p1_fd_seek(&mut caller, 1, 0, 0, 328).await, Ok(p1::errno::SUCCESS));
            assert_eq!(read_guest_u64(&mem, 328), 0);
            assert_eq!(p1_fd_tell(&mut caller, dup_fd, 336).await, Ok(p1::errno::SUCCESS));
            assert_eq!(read_guest_u64(&mem, 336), 0);

            // Read back both writes in order.
            write_guest_iov(&mem, 360, 400, 32);
            assert_eq!(p1_fd_read(&mut caller, 1, 360, 1, 368).await, Ok(p1::errno::SUCCESS));
            let nread = read_guest_u32(&mem, 368) as usize;
            assert_eq!(read_guest_bytes(&mem, 400, nread), b"first-second");

            // Spawn `DUP2` action and `clone_for_exec` both preserve the shared description
            // (offset + `APPEND`) while stripping `close_on_exec` slots.
            assert_eq!(
                p1_fd_fdstat_set_flags(&mut caller, 1, P1_FDFLAG_APPEND),
                p1::errno::SUCCESS
            );
            let exec_table = caller.data().descriptors.clone_for_exec();
            assert!(exec_table.get(dup_fd).is_none(), "cloexec dup stripped on exec");
            assert!(
                exec_table.get(cloexec_dup_fd).is_none(),
                "cloexec dup2 stripped on exec"
            );
            assert_eq!(exec_table.fdflags(1), Ok(P1_FDFLAG_APPEND));
            let exec_open = match exec_table.get(1) {
                Some(Preview1Descriptor::File(file)) => file.clone(),
                _ => panic!("exec table must inherit fd 1 file"),
            };
            let parent_open = match caller.data().descriptors.get_cloned(1) {
                Some(Preview1Descriptor::File(file)) => file,
                _ => panic!("parent fd 1 file"),
            };
            assert!(exec_open.same_description(&parent_open));

            // Spawn `DUP2` of `cloexec_dup_fd` onto fd 7 without cloexec shares the same description.
            let op_base = 512_usize;
            write_guest_bytes(
                &mem,
                op_base + WASIX_PROC_SPAWN_FD_OP_CMD_OFFSET as usize,
                &[WASIX_PROC_SPAWN_FD_OP_DUP2],
            );
            write_guest_u32(
                &mem,
                op_base + WASIX_PROC_SPAWN_FD_OP_FD_OFFSET as usize,
                7,
            );
            write_guest_u32(
                &mem,
                op_base + WASIX_PROC_SPAWN_FD_OP_SRC_FD_OFFSET as usize,
                cloexec_dup_fd as u32,
            );
            write_guest_bytes(
                &mem,
                op_base + WASIX_PROC_SPAWN_FD_OP_FDFLAGSEXT_OFFSET as usize,
                &0_u16.to_le_bytes(),
            );
            let async_mem = p1_async_memory(&mut caller).expect("async memory");
            let spawn_snap = wasix_spawn_descriptor_snapshot(&mut caller, &async_mem, op_base as u32, 1)
                .await
                .expect("spawn snapshot succeeds");
            assert_eq!(spawn_snap.descriptors.fdflags(7), Ok(P1_FDFLAG_APPEND));
            match spawn_snap.descriptors.get(7) {
                Some(Preview1Descriptor::File(file)) => {
                    assert!(file.same_description(&parent_open));
                }
                _ => panic!("spawn dup2 fd 7 must share open file description"),
            }
        })
    });
}

/// The descriptor table and cwd are owned by the process and shared across
/// every thread store: a file opened on one thread is usable on another, a
/// `chdir` on one thread is observed on another, and an exec snapshot taken
/// from a spawned thread inherits the process's current table and cwd.
#[test]
fn descriptors_and_cwd_are_shared_across_threads_and_inherited_on_exec() {
    let fixture = SharedStateFixture::new();
    let (mut main_store, memory) = fixture.make_process_store(
        "shared-proc",
        fixture.authority.clone(),
        DescriptorOrigin::Fresh,
        None,
    );
    seed_workspace_dirs(&main_store.data().filesystem);

    // Spawn worker BEFORE main opens a file or chdirs, so any visibility proves
    // live sharing rather than initial copying.
    let (_tid, _exit, mut worker_store) = fixture.make_sibling_store(main_store.data());

    // Thread 1 (main) opens `/workspace/shared.txt`, writes `"from-main:"`,
    // opens a cloexec file, and chdirs into `/workspace/sub`.
    let mem_main = memory.clone();
    let (shared_fd, cloexec_fd) = fixture.run_in_caller(&mut main_store, move |mut caller| {
        Box::pin(async move {
            let path = b"shared.txt";
            write_guest_bytes(&mem_main, 64, path);
            let rights = P1_RIGHT_FD_READ | P1_RIGHT_FD_WRITE | P1_RIGHT_FD_SEEK | P1_RIGHT_FD_TELL;
            assert_eq!(
                wasix_path_open(
                    &mut caller,
                    Preview1ProgramStore::<TestCpu, TestNetworkService, UnsupportedStorage>::WASIX_AT_FDCWD,
                    0,
                    64,
                    path.len() as u32,
                    TEST_OFLAG_CREAT | TEST_OFLAG_TRUNC,
                    rights,
                    0,
                    128,
                )
                .await,
                Ok(p1::errno::SUCCESS)
            );
            let shared_fd = read_guest_u32(&mem_main, 128) as i32;

            let cloexec_path = b"secret.txt";
            write_guest_bytes(&mem_main, 96, cloexec_path);
            assert_eq!(
                wasix_path_open2(
                    &mut caller,
                    Preview1ProgramStore::<TestCpu, TestNetworkService, UnsupportedStorage>::WASIX_AT_FDCWD,
                    0,
                    96,
                    cloexec_path.len() as u32,
                    TEST_OFLAG_CREAT | TEST_OFLAG_TRUNC,
                    rights,
                    0,
                    WASIX_FDFLAGSEXT_CLOEXEC,
                    132,
                )
                .await,
                Ok(p1::errno::SUCCESS)
            );
            let cloexec_fd = read_guest_u32(&mem_main, 132) as i32;

            let payload = b"from-main:";
            write_guest_bytes(&mem_main, 200, payload);
            write_guest_iov(&mem_main, 180, 200, payload.len() as u32);
            assert_eq!(
                p1_fd_write(&mut caller, shared_fd, 180, 1, 188).await,
                Ok(p1::errno::SUCCESS)
            );

            let sub = b"sub";
            write_guest_bytes(&mem_main, 240, sub);
            assert_eq!(
                wasix_chdir(&mut caller, 240, sub.len() as u32).await,
                Ok(p1::errno::SUCCESS)
            );
            (shared_fd, cloexec_fd)
        })
    });

    // Thread 2 (worker) uses `shared_fd`, observes `getcwd == "/workspace/sub"`,
    // opens a relative file in `/workspace/sub`, and checks what an exec from
    // the worker thread inherits.
    let mem_worker = memory.clone();
    let worker_fd = fixture.run_in_caller(&mut worker_store, move |mut caller| {
        Box::pin(async move {
            let payload = b"from-worker";
            write_guest_bytes(&mem_worker, 300, payload);
            write_guest_iov(&mem_worker, 280, 300, payload.len() as u32);
            assert_eq!(
                p1_fd_write(&mut caller, shared_fd, 280, 1, 288).await,
                Ok(p1::errno::SUCCESS)
            );

            assert_eq!(
                p1_fd_seek(&mut caller, shared_fd, 0, 0, 320).await,
                Ok(p1::errno::SUCCESS)
            );
            write_guest_iov(&mem_worker, 340, 360, 64);
            assert_eq!(
                p1_fd_read(&mut caller, shared_fd, 340, 1, 348).await,
                Ok(p1::errno::SUCCESS)
            );
            let nread = read_guest_u32(&mem_worker, 348) as usize;
            assert_eq!(read_guest_bytes(&mem_worker, 360, nread), b"from-main:from-worker");

            // `getcwd` on the worker reflects main's `chdir`.
            write_guest_u32(&mem_worker, 440, 64);
            assert_eq!(wasix_getcwd(&mut caller, 448, 440), p1::errno::SUCCESS);
            let cwd_len = read_guest_u32(&mem_worker, 440) as usize;
            assert_eq!(read_guest_bytes(&mem_worker, 448, cwd_len), b"/workspace/sub");

            // Relative open on the worker resolves inside `/workspace/sub`.
            let rel = b"in_sub.txt";
            write_guest_bytes(&mem_worker, 520, rel);
            let rights = P1_RIGHT_FD_READ | P1_RIGHT_FD_WRITE;
            assert_eq!(
                wasix_path_open(
                    &mut caller,
                    Preview1ProgramStore::<TestCpu, TestNetworkService, UnsupportedStorage>::WASIX_AT_FDCWD,
                    0,
                    520,
                    rel.len() as u32,
                    TEST_OFLAG_CREAT | TEST_OFLAG_TRUNC,
                    rights,
                    0,
                    540,
                )
                .await,
                Ok(p1::errno::SUCCESS)
            );
            let worker_fd = read_guest_u32(&mem_worker, 540) as i32;

            // An exec from the worker inherits the process's current descriptor
            // table (minus `close_on_exec` slots) and its current cwd.
            let exec_descriptors = caller.data().descriptors.clone_for_exec();
            assert!(exec_descriptors.get(shared_fd).is_some());
            assert!(exec_descriptors.get(worker_fd).is_some());
            assert!(exec_descriptors.get(cloexec_fd).is_none());
            let exec_authority = caller.data().effective_authority();
            assert_eq!(
                exec_authority.cwd().map(|cap| cap.guest_name()),
                Some("/workspace/sub")
            );
            worker_fd
        })
    });

    // Main thread immediately sees the descriptor opened by the worker and
    // sees `/workspace/sub/in_sub.txt` on the shared table.
    match main_store.data().descriptors.get_cloned(worker_fd) {
        Some(Preview1Descriptor::File(file)) => {
            assert_eq!(file.node().path, "/workspace/sub/in_sub.txt");
        }
        _ => panic!("main must see descriptor opened by worker thread"),
    }

    // Closing `worker_fd` on main makes it `EBADF` on the worker.
    assert_eq!(
        main_store.data().descriptors.close(worker_fd),
        p1::errno::SUCCESS
    );
    assert!(
        worker_store
            .data()
            .descriptors
            .get_cloned(worker_fd)
            .is_none()
    );
}

/// The child table is shared across every thread of the process; non-blocking
/// probes (`proc_signal(pid, 0)` and `WNOHANG proc_join`) on one thread never
/// clobber a blocking `proc_join` waker on another thread, and dropping one
/// blocking joiner wakes sibling joiners so no wakeup is lost.
#[test]
fn child_table_is_shared_and_nonblocking_probes_preserve_blocking_join_waker() {
    let fixture = SharedStateFixture::new();
    let (mut main_store, _memory) = fixture.make_process_store(
        "shared-children",
        fixture.authority.clone(),
        DescriptorOrigin::Fresh,
        None,
    );
    let (_tid, _exit, mut worker_store) = fixture.make_sibling_store(main_store.data());

    let (tx, rx) = futures::channel::oneshot::channel();
    main_store
        .data_mut()
        .insert_child(42, WasixSignalState::new(), rx);

    // Worker sees the child spawned by main and registers a blocking join.
    let (mut worker_wait, worker_guard) = worker_store.data().children.begin_blocking_join();
    let worker_wakes = Arc::new(CountingWaker::default());
    let worker_waker = Waker::from(worker_wakes.clone());
    let mut worker_cx = Context::from_waker(&worker_waker);
    assert!(
        worker_store
            .data_mut()
            .poll_child_join(Some(42), &mut worker_cx, &mut worker_wait)
            .is_pending()
    );

    // Main runs non-blocking probes (`live_child_signal_target` + `try_child_join`):
    // neither may clobber the worker's waker on child 42's oneshot channel.
    assert!(main_store.data_mut().live_child_signal_target(42).is_some());
    assert!(main_store.data_mut().try_child_join(Some(42)).is_pending());

    // Completing child 42 wakes the worker's blocking join directly.
    tx.send(Ok(ChildExit {
        instance_id: crate::InstanceId::from_raw(42),
        termination: ChildTermination::Exited(9),
        filesystem: None,
    }))
    .expect("child exit sends");
    assert!(
        worker_wakes.wakes() >= 1,
        "non-blocking probes must not clobber blocking joiner's waker"
    );
    assert_eq!(
        worker_store
            .data_mut()
            .poll_child_join(Some(42), &mut worker_cx, &mut worker_wait),
        Poll::Ready(Some(WasixJoinedChild {
            pid: 42,
            outcome: Ok(ChildTermination::Exited(9)),
        }))
    );
    drop(worker_guard);
    assert!(main_store.data().children.is_empty());

    // Two concurrent blocking joiners: when the second overwrites the oneshot
    // waker and drops (e.g. EINTR or cancellation), its drop guard wakes the
    // first so it re-registers its waker and receives the child's exit.
    let (tx10, rx10) = futures::channel::oneshot::channel();
    main_store
        .data_mut()
        .insert_child(10, WasixSignalState::new(), rx10);
    let (mut wait_a, _guard_a) = main_store.data().children.begin_blocking_join();
    let wakes_a = Arc::new(CountingWaker::default());
    let waker_a = Waker::from(wakes_a.clone());
    let mut cx_a = Context::from_waker(&waker_a);
    assert!(
        main_store
            .data_mut()
            .poll_child_join(Some(10), &mut cx_a, &mut wait_a)
            .is_pending()
    );

    let (mut wait_b, guard_b) = worker_store.data().children.begin_blocking_join();
    let wakes_b = Arc::new(CountingWaker::default());
    let waker_b = Waker::from(wakes_b.clone());
    let mut cx_b = Context::from_waker(&waker_b);
    assert!(
        worker_store
            .data_mut()
            .poll_child_join(None, &mut cx_b, &mut wait_b)
            .is_pending()
    );
    let before_drop = wakes_a.wakes();
    drop(guard_b);
    assert!(
        wakes_a.wakes() > before_drop,
        "dropping sibling joiner must wake remaining joiner to re-arm"
    );
    assert!(
        main_store
            .data_mut()
            .poll_child_join(Some(10), &mut cx_a, &mut wait_a)
            .is_pending()
    );
    let before_exit = wakes_a.wakes();
    tx10.send(Ok(ChildExit {
        instance_id: crate::InstanceId::from_raw(10),
        termination: ChildTermination::Exited(5),
        filesystem: None,
    }))
    .expect("child 10 exit sends");
    assert!(
        wakes_a.wakes() > before_exit,
        "re-armed joiner wakes when child 10 exits"
    );
    assert_eq!(
        main_store
            .data_mut()
            .poll_child_join(Some(10), &mut cx_a, &mut wait_a),
        Poll::Ready(Some(WasixJoinedChild {
            pid: 10,
            outcome: Ok(ChildTermination::Exited(5)),
        }))
    );
}

/// Finished threads leave the tid-keyed thread table once their exit is
/// published; `wasix_thread_join` returns `SUCCESS` on an already-ended
/// admitted thread, `ESRCH` on unadmitted or cancelled admissions, and
/// `EINVAL` on the caller's own thread id.
#[test]
fn thread_join_succeeds_for_already_ended_thread_and_table_stays_bounded() {
    let fixture = SharedStateFixture::new();
    let (mut store, _memory) = fixture.make_process_store(
        "thread-table",
        fixture.authority.clone(),
        DescriptorOrigin::Fresh,
        None,
    );

    let mut finished_tids = Vec::new();
    for _ in 0..32 {
        let exit = Arc::new(WasixThreadExit::new());
        let tid = store
            .data()
            .threads
            .admit(WasixSignalState::new(), exit.clone())
            .expect("thread admits");
        store.data().threads.finish(tid, &exit, 0);
        finished_tids.push(tid);
    }
    assert_eq!(
        store.data().threads.live_count(),
        0,
        "finished threads leave the live table immediately"
    );

    // Admit two more: keep `live_tid`, cancel `cancelled_tid`.
    let cancelled_tid = store
        .data()
        .threads
        .admit(WasixSignalState::new(), Arc::new(WasixThreadExit::new()))
        .expect("cancelled thread admits");
    let live_exit = Arc::new(WasixThreadExit::new());
    let live_tid = store
        .data()
        .threads
        .admit(WasixSignalState::new(), live_exit.clone())
        .expect("live thread admits");
    store.data().threads.cancel_admission(cancelled_tid);
    assert_eq!(store.data().threads.live_count(), 1);
    let unadmitted_tid = live_tid + 1;

    fixture.run_in_caller(&mut store, move |mut caller| {
        Box::pin(async move {
            // Joining own tid is EINVAL.
            assert_eq!(wasix_thread_join(&mut caller, 0).await, p1::errno::INVAL);
            // Already-ended admitted threads return SUCCESS.
            for tid in finished_tids {
                assert_eq!(
                    wasix_thread_join(&mut caller, tid).await,
                    p1::errno::SUCCESS
                );
            }
            // Cancelled admission and unadmitted ids return ESRCH.
            assert_eq!(
                wasix_thread_join(&mut caller, cancelled_tid).await,
                p1::errno::SRCH
            );
            assert_eq!(
                wasix_thread_join(&mut caller, unadmitted_tid).await,
                p1::errno::SRCH
            );
            // Finishing `live_tid` lets join succeed immediately.
            caller.data().threads.finish(live_tid, &live_exit, 0);
            assert_eq!(
                wasix_thread_join(&mut caller, live_tid).await,
                p1::errno::SUCCESS
            );
            assert_eq!(caller.data().threads.live_count(), 0);
        })
    });
}

/// `wasix_thread_spawn_v2` requires the per-process `InstancePre` built once
/// at process bring-up (never rebuilding a linker per spawn), and
/// `spawn_thread_store` shares every process-wide handle across sibling stores.
#[test]
fn thread_spawn_requires_process_instance_pre_and_shares_process_state() {
    let fixture = SharedStateFixture::new();
    let (mut main_store, memory) = fixture.make_process_store(
        "instance-pre",
        fixture.authority.clone(),
        DescriptorOrigin::Fresh,
        None,
    );

    // Without a per-process `InstancePre`, `thread_spawn_v2` returns `NOTSUP`
    // rather than constructing a fresh per-thread linker.
    fixture.run_in_caller(&mut main_store, |mut caller| {
        Box::pin(async move {
            assert_eq!(
                wasix_thread_spawn_v2(&mut caller, 64, 128).await,
                Ok(p1::errno::NOTSUP)
            );
        })
    });

    // Sibling thread stores share descriptors, cwd, children, threads, signals,
    // and imported shared memory with the spawning store.
    let (_tid, _exit, worker_store) = fixture.make_sibling_store(main_store.data());
    assert!(worker_store.data().thread_instance_pre.is_none());
    assert!(worker_store.data().imported_memory.is_some());
    write_guest_u32(&memory, 64, 0xCAFE_BABE);
    let worker_mem = worker_store
        .data()
        .imported_memory
        .as_ref()
        .expect("worker shares imported memory");
    assert_eq!(read_guest_u32(worker_mem, 64), 0xCAFE_BABE);
}
