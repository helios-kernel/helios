use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;
use spin::Mutex;

use helios_artifact::bootfs::{self, EntryKind};
use helios_hal::cpu::{Cpu, ProcessorId};
use helios_hal::numa::SingleNode;
use helios_hal::serial::ByteSerial;
use helios_hal::{DeviceInventory, DmaModel, Platform, ProcessorStartupPolicy, ProcessorTopology};

use super::{boot_init_output_mode, install_component_host_program_service, launch_boot_init};
use crate::component::{ComponentInputRoute, ComponentOutputMode, ComponentOutputRoute};
use crate::test_support::{TestCpu, TestNetworkService, UnsupportedStorage};
use crate::wasmtime_adapter::cwasm::sign_bootfs_image_for_tests;
use crate::{DebugConsole, DebugSerialAccess, DebugSerialWriter};

#[derive(Default)]
struct NullConsole;

impl core::fmt::Write for NullConsole {
    fn write_str(&mut self, _s: &str) -> core::fmt::Result {
        Ok(())
    }
}

struct RecordingSerialPort;

static RECORDED_SERIAL: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static RECORDED_CONSOLE: DebugConsole = DebugConsole::new();

impl ByteSerial for RecordingSerialPort {
    fn try_read_byte(&self) -> Option<u8> {
        None
    }

    fn write_bytes(&self, bytes: &[u8]) {
        RECORDED_SERIAL.lock().extend_from_slice(bytes);
    }

    fn enable_receive_interrupt(&self) {}

    fn disable_receive_interrupt(&self) {}
}

impl DebugSerialAccess for RecordingSerialPort {
    type Port = Self;

    fn port() -> Self {
        Self
    }

    fn console() -> &'static DebugConsole {
        &RECORDED_CONSOLE
    }
}

const RECORDING_WRITER: DebugSerialWriter = DebugSerialWriter::of::<RecordingSerialPort>();

fn signed_test_payload(init_name: &str, init_bytes: &[u8], argv0: &str) -> crate::BootPayload {
    let image = bootfs::write_image(&[
        bootfs::WriteEntry {
            kind: EntryKind::InitComponent,
            path: init_name,
            data: init_bytes,
            modified_nanos: 0,
        },
        bootfs::WriteEntry {
            kind: EntryKind::InitArgv0,
            path: argv0,
            data: b"",
            modified_nanos: 0,
        },
        bootfs::WriteEntry {
            kind: EntryKind::File,
            path: "init.txt",
            data: b"boot-init test\n",
            modified_nanos: 0,
        },
    ]);
    let signed = Box::leak(sign_bootfs_image_for_tests(image).into_boxed_slice());
    crate::BootPayload::parse(signed).expect("signed test payload parses")
}

#[test]
fn boot_init_stdio_keeps_serial_input_for_debugger_when_system_component_exists() {
    let alongside_debugger = boot_init_output_mode(true, true);
    assert!(matches!(
        alongside_debugger,
        ComponentOutputMode::RoutedChild {
            stdin: ComponentInputRoute::Closed,
            stdout: ComponentOutputRoute::Serial,
            stderr: ComponentOutputRoute::Serial,
        }
    ));

    let standalone = boot_init_output_mode(true, false);
    assert!(matches!(standalone, ComponentOutputMode::Serial));

    let headless_with_debugger = boot_init_output_mode(false, true);
    assert!(matches!(headless_with_debugger, ComponentOutputMode::Trace));

    let headless_standalone = boot_init_output_mode(false, false);
    assert!(matches!(headless_standalone, ComponentOutputMode::Trace));
}

#[test]
fn boot_payload_exposes_init_component_and_argv0_on_runtime_state() {
    let cpu = TestCpu::with_entropy(0x71);
    let payload = signed_test_payload("init_component.cwasm", b"synthetic-bytes", "/sbin/init");
    let state: crate::HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage> =
        crate::RuntimeState::new(
            cpu.timebase(),
            1,
            0,
            payload,
            crate::GuestIsa::for_build_target(cpu.native_feature_probe()),
        );

    assert_eq!(
        state.embedded_init().component().name(),
        "init_component.cwasm"
    );
    assert_eq!(
        state.embedded_init().component().bytes(),
        b"synthetic-bytes"
    );
    assert_eq!(state.embedded_init().argv0(), "/sbin/init");
    assert!(!state.boot_init_completed());
}

#[test]
fn wait_for_boot_init_stays_pending_before_launch_and_wakes_on_completion() {
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    let cpu = TestCpu::with_entropy(0x73);
    let payload = signed_test_payload("init_component.cwasm", b"synthetic-bytes", "/init.wasm");
    let state: crate::HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage> =
        crate::RuntimeState::new(
            cpu.timebase(),
            2,
            0,
            payload,
            crate::GuestIsa::for_build_target(cpu.native_feature_probe()),
        );

    // Simulate a secondary processor reaching `wait_for_boot_init()`
    // before the bootstrap processor has even called `launch_boot_init()`.
    let mut waiter = pin!(state.wait_for_boot_init());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        matches!(waiter.as_mut().poll(&mut cx), Poll::Pending),
        "wait_for_boot_init must stay Pending before boot init is launched"
    );

    state.mark_boot_init_launched();
    assert!(
        matches!(waiter.as_mut().poll(&mut cx), Poll::Pending),
        "wait_for_boot_init must stay Pending while boot init is still running"
    );

    state.mark_boot_init_completed();
    assert!(
        matches!(waiter.as_mut().poll(&mut cx), Poll::Ready(())),
        "wait_for_boot_init must resolve once boot init completes"
    );
}

#[test]
fn launch_boot_init_completes_and_wakes_system_waiters_even_when_artifact_is_invalid() {
    let backing: &'static mut [u8] =
        Box::leak(alloc::vec![0u8; 64 * 1024 * 1024].into_boxed_slice());
    // SAFETY: `backing` is a leaked `'static` slice owned exclusively by this
    // test's bootstrap allocator, so it outlives the test kernel.
    let region = unsafe {
        helios_hal::memory::MemoryRegion::new(
            core::ptr::NonNull::from(backing),
            helios_hal::numa::NodeId::FIRST,
        )
    };
    let bootstrap = ProcessorId::new(0);
    crate::test_processor_identity::set(bootstrap);
    crate::prime_bootstrap_allocator(core::iter::once(region), &SingleNode::new(1), bootstrap);

    let cpu = TestCpu::with_entropy(0x99);
    let platform = Platform::new(NullConsole, cpu)
        .with_topology(
            ProcessorTopology::start_all_secondaries(bootstrap, 1)
                .with_startup_policy(ProcessorStartupPolicy::BootstrapOnly),
        )
        .with_dma_model(DmaModel::Translated)
        .with_devices(DeviceInventory::new().with_debug_serial());
    let kernel = crate::init(platform);

    let payload = signed_test_payload("init_component.cwasm", b"not-a-valid-wasm", "/init.wasm");
    let debug_state: crate::HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage> =
        crate::RuntimeState::new(
            cpu.timebase(),
            1,
            0,
            payload,
            crate::GuestIsa::for_build_target(cpu.native_feature_probe()),
        );
    let generation = crate::MachineGeneration::new(None);
    debug_state.install_machine_generation(generation.clone());
    debug_state.install_root_entropy(crate::seed_root_entropy(
        &cpu,
        None,
        None::<&crate::NoEntropyDevice>,
        generation,
    ));

    let installed = install_component_host_program_service(
        &kernel,
        &cpu,
        &debug_state,
        |_, _| {},
        RECORDING_WRITER,
    );
    assert!(installed.is_some());

    launch_boot_init(
        &cpu,
        &kernel,
        &debug_state,
        |_, _| {},
        RECORDING_WRITER,
        true,
    );
    assert!(!debug_state.boot_init_completed());

    let wait_state = debug_state.clone();
    let timer = kernel.timer();
    kernel.run_local_future(async move {
        futures_lite::future::or(
            async {
                wait_state.wait_for_boot_init().await;
            },
            async {
                timer.sleep_for(Duration::from_secs(5)).await;
                panic!("timed out waiting for boot init completion");
            },
        )
        .await;
    });
    assert!(
        debug_state.boot_init_completed(),
        "completion guard must release system component waiters even when init fails to load"
    );
    let _ = String::from_utf8_lossy(&RECORDED_SERIAL.lock());
}
