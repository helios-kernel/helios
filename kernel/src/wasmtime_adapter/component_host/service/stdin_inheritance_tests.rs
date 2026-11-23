use alloc::sync::Arc as SharedArc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::VecDeque;
use std::sync::Mutex;

use bytes::Bytes;
use helios_hal::cpu::{Cpu, ProcessorId};
use helios_hal::serial::ByteSerial;
use helios_hal::watchdog::ProgressCounter;

use super::descriptor::{DescriptorOrigin, P1Readiness};
use super::preview1::Preview1ProgramStore;
use super::wasix_proc::{WasixSpawnIo, WasixStdioMode, wasix_prepare_child_io};
use super::{
    HostRuntimeState, OutputMode, OutputRoute, WasixImageThreads, WasixSignalDisposition,
    WasixSignalState,
};
use crate::isa::GuestIsa;
use crate::test_support::{TestCpu, TestNetworkService, UnsupportedStorage};
use crate::wasmtime_adapter::preemption::GuestInterrupts;
use crate::{
    ComponentInputRoute, DebugConsole, DebugSerialAccess, DebugSerialWriter, Executor,
    InstanceRegistry, ProcessAuthority, RootEntropy, RuntimeState, read_debug_serial,
};

type TestProgramStore = Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>;

struct TestSerialPort {
    fifo: Mutex<VecDeque<u8>>,
    receive_interrupt_enabled: AtomicBool,
}

impl TestSerialPort {
    const fn new() -> Self {
        Self {
            fifo: Mutex::new(VecDeque::new()),
            receive_interrupt_enabled: AtomicBool::new(false),
        }
    }

    fn push_bytes(&'static self, console: &'static DebugConsole, bytes: &[u8]) {
        {
            let mut fifo = self.fifo.lock().expect("test serial FIFO poisoned");
            fifo.extend(bytes);
        }
        console.receive_signal().notify_all();
    }
}

impl ByteSerial for &'static TestSerialPort {
    fn try_read_byte(&self) -> Option<u8> {
        self.fifo
            .lock()
            .expect("test serial FIFO poisoned")
            .pop_front()
    }

    fn write_bytes(&self, _bytes: &[u8]) {}

    fn enable_receive_interrupt(&self) {
        self.receive_interrupt_enabled
            .store(true, Ordering::Release);
    }

    fn disable_receive_interrupt(&self) {
        self.receive_interrupt_enabled
            .store(false, Ordering::Release);
    }
}

macro_rules! define_test_serial {
    ($access:ident, $port:ident, $console:ident) => {
        struct $access;
        static $port: TestSerialPort = TestSerialPort::new();
        static $console: DebugConsole = DebugConsole::new();

        impl DebugSerialAccess for $access {
            type Port = &'static TestSerialPort;

            fn port() -> &'static TestSerialPort {
                &$port
            }

            fn console() -> &'static DebugConsole {
                &$console
            }
        }
    };
}

fn new_program_store<Access: DebugSerialAccess>(
    output_mode: OutputMode,
    descriptors: DescriptorOrigin<TestNetworkService>,
) -> TestProgramStore {
    let cpu = TestCpu::with_entropy(0x5a);
    let runtime_state: HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage> =
        RuntimeState::new(
            cpu.timebase(),
            1,
            0,
            crate::BootPayload::for_tests(),
            GuestIsa::for_build_target(cpu.native_feature_probe()),
        );
    runtime_state.install_root_entropy(triomphe::Arc::new(
        RootEntropy::from_platform(&cpu, None, None, crate::MachineGeneration::new(None))
            .expect("the fixture CPU has an entropy source"),
    ));
    let executor = Executor::new(
        ProgressCounter::new(),
        crate::test_support::single_node_pool(1),
        ProcessorId::new(0),
    );
    let registry = InstanceRegistry::new();
    let instance = registry.register("stdin-inheritance-test", 0);
    let authority = ProcessAuthority::root();
    Preview1ProgramStore::new(
        cpu,
        executor.timer(cpu),
        executor
            .spawner(cpu)
            .instance_spawner(crate::TaskFunding::Instance, &instance),
        runtime_state,
        SharedArc::new(GuestInterrupts::new(1, cpu.timebase())),
        instance,
        None,
        Vec::new(),
        Vec::new(),
        authority,
        output_mode,
        read_debug_serial::<Access>,
        DebugSerialWriter::of::<Access>(),
        None,
        None,
        descriptors,
        WasixSignalState::new(),
        WasixSignalState::new(),
        Vec::<WasixSignalDisposition>::new(),
        None,
        true,
        WasixImageThreads::new(),
    )
}

fn read_stdin(store: &mut TestProgramStore, max_bytes: u32) -> Bytes {
    futures_lite::future::block_on(store.read_stdin(0, max_bytes))
}

#[test]
fn forked_child_shares_parent_channel_stdin_stream() {
    define_test_serial!(ChannelForkAccess, CHANNEL_FORK_PORT, CHANNEL_FORK_CONSOLE);

    let (stdin_tx, stdin_rx) = crate::byte_channel();
    let (stdout_tx, _stdout_rx) = crate::byte_channel();
    let (stderr_tx, _stderr_rx) = crate::byte_channel();
    let mut parent = new_program_store::<ChannelForkAccess>(
        OutputMode::Child {
            stdin_rx,
            stdout_tx,
            stderr_tx,
        },
        DescriptorOrigin::Fresh,
    );
    let mut child = new_program_store::<ChannelForkAccess>(
        parent.fork_output_mode(),
        DescriptorOrigin::NewProcess(parent.descriptors.snapshot()),
    );

    assert!(matches!(
        stdin_tx.try_write(Bytes::from_static(b"abcdef")),
        crate::TryWrite::Written
    ));
    drop(stdin_tx);

    // Partial reads from child and parent share the underlying stream once:
    // the child must not buffer the unread tail privately in its descriptor.
    assert_eq!(read_stdin(&mut child, 2).as_ref(), b"ab");
    assert_eq!(read_stdin(&mut parent, 2).as_ref(), b"cd");
    assert_eq!(read_stdin(&mut child, 4).as_ref(), b"ef");
    assert_eq!(read_stdin(&mut child, 4).as_ref(), b"");
    assert_eq!(read_stdin(&mut parent, 4).as_ref(), b"");
}

#[test]
fn forked_child_inherits_serial_stdin_stream() {
    define_test_serial!(SerialForkAccess, SERIAL_FORK_PORT, SERIAL_FORK_CONSOLE);

    let parent = new_program_store::<SerialForkAccess>(OutputMode::Serial, DescriptorOrigin::Fresh);
    let mut child = new_program_store::<SerialForkAccess>(
        parent.fork_output_mode(),
        DescriptorOrigin::NewProcess(parent.descriptors.snapshot()),
    );
    assert!(matches!(child.stdin_route(), ComponentInputRoute::Serial));

    SERIAL_FORK_PORT.push_bytes(&SERIAL_FORK_CONSOLE, b"hello");
    assert_eq!(read_stdin(&mut child, 2).as_ref(), b"he");
    assert_eq!(read_stdin(&mut child, 8).as_ref(), b"llo");
}

#[test]
fn spawned_inherit_child_shares_parent_channel_and_serial_stdin() {
    define_test_serial!(
        SpawnInheritAccess,
        SPAWN_INHERIT_PORT,
        SPAWN_INHERIT_CONSOLE
    );

    let (stdin_tx, stdin_rx) = crate::byte_channel();
    let (stdout_tx, _stdout_rx) = crate::byte_channel();
    let (stderr_tx, _stderr_rx) = crate::byte_channel();
    let mut channel_parent = new_program_store::<SpawnInheritAccess>(
        OutputMode::Child {
            stdin_rx,
            stdout_tx,
            stderr_tx,
        },
        DescriptorOrigin::Fresh,
    );
    let channel_io = wasix_prepare_child_io(&channel_parent, WasixSpawnIo::inherit())
        .expect("inherit spawn io succeeds");
    assert!(channel_io.stdin_writer.is_none());
    let mut channel_child =
        new_program_store::<SpawnInheritAccess>(channel_io.output_mode, DescriptorOrigin::Fresh);

    assert!(matches!(
        stdin_tx.try_write(Bytes::from_static(b"123456")),
        crate::TryWrite::Written
    ));
    drop(stdin_tx);

    assert_eq!(read_stdin(&mut channel_child, 3).as_ref(), b"123");
    assert_eq!(read_stdin(&mut channel_parent, 3).as_ref(), b"456");
    assert_eq!(read_stdin(&mut channel_child, 3).as_ref(), b"");

    let serial_parent =
        new_program_store::<SpawnInheritAccess>(OutputMode::Serial, DescriptorOrigin::Fresh);
    let serial_io = wasix_prepare_child_io(&serial_parent, WasixSpawnIo::inherit())
        .expect("inherit spawn io succeeds on serial");
    assert!(serial_io.stdin_writer.is_none());
    let mut serial_child =
        new_program_store::<SpawnInheritAccess>(serial_io.output_mode, DescriptorOrigin::Fresh);
    assert!(matches!(
        serial_child.stdin_route(),
        ComponentInputRoute::Serial
    ));

    SPAWN_INHERIT_PORT.push_bytes(&SPAWN_INHERIT_CONSOLE, b"ser");
    assert_eq!(read_stdin(&mut serial_child, 8).as_ref(), b"ser");
}

#[test]
fn exec_from_forked_child_preserves_inherited_stdin_stream() {
    define_test_serial!(ExecForkAccess, EXEC_FORK_PORT, EXEC_FORK_CONSOLE);

    let (stdin_tx, stdin_rx) = crate::byte_channel();
    let (stdout_tx, _stdout_rx) = crate::byte_channel();
    let (stderr_tx, _stderr_rx) = crate::byte_channel();
    let parent = new_program_store::<ExecForkAccess>(
        OutputMode::Child {
            stdin_rx,
            stdout_tx,
            stderr_tx,
        },
        DescriptorOrigin::Fresh,
    );
    let forked_mode = parent.fork_output_mode();
    let exec_descriptors = parent.descriptors.clone_for_exec();
    let mut exec_child = new_program_store::<ExecForkAccess>(
        forked_mode.clone(),
        DescriptorOrigin::SameProcess(exec_descriptors.clone()),
    );

    assert!(matches!(
        stdin_tx.try_write(Bytes::from_static(b"exec-ok")),
        crate::TryWrite::Written
    ));
    drop(stdin_tx);
    assert_eq!(read_stdin(&mut exec_child, 16).as_ref(), b"exec-ok");

    // Replacing into a component over the same stdio preserves the route too.
    let component_mode = exec_descriptors
        .component_output_mode(&forked_mode)
        .expect("inherited stdio table converts cleanly");
    assert!(matches!(
        component_mode.stdin_route(),
        ComponentInputRoute::Child(_)
    ));

    let serial_parent =
        new_program_store::<ExecForkAccess>(OutputMode::Serial, DescriptorOrigin::Fresh);
    let serial_fork_mode = serial_parent.fork_output_mode();
    let mut serial_exec_child = new_program_store::<ExecForkAccess>(
        serial_fork_mode,
        DescriptorOrigin::SameProcess(serial_parent.descriptors.clone_for_exec()),
    );
    EXEC_FORK_PORT.push_bytes(&EXEC_FORK_CONSOLE, b"serial-exec");
    assert_eq!(
        read_stdin(&mut serial_exec_child, 16).as_ref(),
        b"serial-exec"
    );
}

#[test]
fn spawn_null_and_log_stdin_modes_end_at_eof() {
    define_test_serial!(ClosedSpawnAccess, CLOSED_SPAWN_PORT, CLOSED_SPAWN_CONSOLE);

    let (stdin_tx, stdin_rx) = crate::byte_channel();
    let (stdout_tx, _stdout_rx) = crate::byte_channel();
    let (stderr_tx, _stderr_rx) = crate::byte_channel();
    let parent = new_program_store::<ClosedSpawnAccess>(
        OutputMode::Child {
            stdin_rx,
            stdout_tx,
            stderr_tx,
        },
        DescriptorOrigin::Fresh,
    );
    assert!(matches!(
        stdin_tx.try_write(Bytes::from_static(b"unseen")),
        crate::TryWrite::Written
    ));

    for mode in [WasixStdioMode::Null, WasixStdioMode::Log] {
        let raw_mode = match mode {
            WasixStdioMode::Null => 2,
            WasixStdioMode::Log => 3,
            _ => unreachable!(),
        };
        let prepared = wasix_prepare_child_io(&parent, WasixSpawnIo::from_modes(raw_mode, 1, 1))
            .expect("null and log spawn io succeed");
        assert!(prepared.stdin_writer.is_none());
        let mut child =
            new_program_store::<ClosedSpawnAccess>(prepared.output_mode, DescriptorOrigin::Fresh);
        assert!(matches!(child.stdin_route(), ComponentInputRoute::Closed));
        assert_eq!(child.probe_stdin(0), P1Readiness::Hangup);
        assert_eq!(read_stdin(&mut child, 16).as_ref(), b"");
    }

    // Also verify Null and Log end the stream when parent is Serial.
    let serial_parent =
        new_program_store::<ClosedSpawnAccess>(OutputMode::Serial, DescriptorOrigin::Fresh);
    CLOSED_SPAWN_PORT.push_bytes(&CLOSED_SPAWN_CONSOLE, b"console-bytes");
    for raw_mode in [2, 3] {
        let prepared =
            wasix_prepare_child_io(&serial_parent, WasixSpawnIo::from_modes(raw_mode, 1, 1))
                .expect("null and log spawn io succeed on serial");
        let mut child =
            new_program_store::<ClosedSpawnAccess>(prepared.output_mode, DescriptorOrigin::Fresh);
        assert!(matches!(child.stdin_route(), ComponentInputRoute::Closed));
        assert!(matches!(
            child.output_mode,
            OutputMode::RoutedChild {
                stdout: OutputRoute::Serial | OutputRoute::Discard,
                ..
            }
        ));
        assert_eq!(child.probe_stdin(0), P1Readiness::Hangup);
        assert_eq!(read_stdin(&mut child, 16).as_ref(), b"");
    }
}
