use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use helios_artifact::bootfs::{self, EntryKind};
use helios_hal::cpu::{Cpu, ProcessorId};
use helios_hal::numa::SingleNode;
use helios_hal::serial::ByteSerial;
use helios_hal::{DeviceInventory, DmaModel, Platform, ProcessorStartupPolicy, ProcessorTopology};

use super::super::root_component_output_mode;
use super::{install_component_host_program_service, run_root_component_once};
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
fn root_component_stdio_keeps_serial_input_for_supervised_children() {
    let with_serial = root_component_output_mode(true);
    assert!(matches!(
        with_serial,
        ComponentOutputMode::RoutedChild {
            stdin: ComponentInputRoute::Closed,
            stdout: ComponentOutputRoute::Serial,
            stderr: ComponentOutputRoute::Serial,
        }
    ));

    let headless = root_component_output_mode(false);
    assert!(matches!(headless, ComponentOutputMode::Trace));
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
}

#[test]
fn run_root_component_once_returns_error_when_artifact_is_invalid() {
    let backing: &'static mut [u8] =
        Box::leak(alloc::vec![0u8; 64 * 1024 * 1024].into_boxed_slice());
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

    let result = run_root_component_once(
        debug_state.embedded_init(),
        cpu,
        &kernel,
        debug_state,
        |_, _| {},
        RECORDING_WRITER,
    );
    assert!(
        result.is_err(),
        "an invalid root component artifact must fail cleanly instead of panicking"
    );
    let _ = String::from_utf8_lossy(&RECORDED_SERIAL.lock());
}
