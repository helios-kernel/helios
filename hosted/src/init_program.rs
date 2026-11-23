#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use helios_hal::cpu::{Cpu, ProcessorId};
    use helios_hal::numa::SingleNode;
    use helios_hal::serial::ByteSerial;
    use helios_hal::{
        DeviceInventory, DmaModel, Platform, ProcessorStartupPolicy, ProcessorTopology,
    };

    use crate::config::DEFAULT_HEAP_BYTES;
    use crate::console::HostedConsole;
    use crate::cpu::{HostedCpu, detect_host_native_feature};
    use crate::net::HostedNetworkDevice;
    use crate::rtc::HostRtc;
    use crate::runtime::{HostedMachine, HostedStorage};

    type TestNetworkService = helios_kernel::NetworkService<HostedCpu, HostedNetworkDevice>;
    type TestRuntimeState =
        helios_kernel::HostRuntimeState<HostedCpu, TestNetworkService, HostedStorage>;

    static CAPTURED_SERIAL_OUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    static CAPTURED_SERIAL_IN: Mutex<VecDeque<u8>> = Mutex::new(VecDeque::new());
    static TEST_DEBUG_CONSOLE: helios_kernel::DebugConsole = helios_kernel::DebugConsole::new();

    struct CapturedDebugPort;

    impl ByteSerial for CapturedDebugPort {
        fn try_read_byte(&self) -> Option<u8> {
            CAPTURED_SERIAL_IN.lock().unwrap().pop_front()
        }

        fn write_bytes(&self, bytes: &[u8]) {
            CAPTURED_SERIAL_OUT.lock().unwrap().extend_from_slice(bytes);
        }

        fn enable_receive_interrupt(&self) {}

        fn disable_receive_interrupt(&self) {}
    }

    impl helios_kernel::DebugSerialAccess for CapturedDebugPort {
        type Port = Self;

        fn port() -> Self {
            Self
        }

        fn console() -> &'static helios_kernel::DebugConsole {
            &TEST_DEBUG_CONSOLE
        }
    }

    const CAPTURED_SERIAL_WRITER: helios_kernel::DebugSerialWriter =
        helios_kernel::DebugSerialWriter::of::<CapturedDebugPort>();

    fn read_captured_serial(buffer: &mut Vec<u8>, max_bytes: u32) {
        helios_kernel::read_debug_serial::<CapturedDebugPort>(buffer, max_bytes);
    }

    /// The payload `kernel-prebuild` wrote for this host, named in the
    /// `HELIOS_BOOTFS` path the Justfile exports for the test.
    fn test_payload() -> helios_kernel::BootPayload {
        let bootfs = PathBuf::from(
            std::env::var_os("HELIOS_BOOTFS")
                .expect("HELIOS_BOOTFS must name the kernel-prebuild payload"),
        );
        let bytes = std::fs::read(&bootfs)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", bootfs.display()));
        helios_kernel::BootPayload::parse(Box::leak(bytes.into_boxed_slice()))
            .unwrap_or_else(|error| panic!("{} is not a valid payload: {error}", bootfs.display()))
    }

    fn run_payload_init(has_system_component: bool) -> (String, Vec<u8>) {
        CAPTURED_SERIAL_OUT.lock().unwrap().clear();
        {
            let mut incoming = CAPTURED_SERIAL_IN.lock().unwrap();
            incoming.clear();
            incoming.extend(b"\xff\x00HRPC\xaa\x55".iter().copied());
        }

        let bootstrap = ProcessorId::new(0);
        let machine = HostedMachine::new(1, bootstrap, DEFAULT_HEAP_BYTES);
        machine.register_thread(bootstrap, std::thread::current());
        let cpu = HostedCpu::new(bootstrap, machine.clone());

        helios_kernel::prime_bootstrap_allocator(
            machine.bootstrap_memory_regions(),
            &SingleNode::new(1),
            bootstrap,
        );
        let platform = Platform::new(HostedConsole::new(), cpu.clone())
            .with_topology(
                ProcessorTopology::start_all_secondaries(bootstrap, 1)
                    .with_startup_policy(ProcessorStartupPolicy::BootstrapOnly),
            )
            .with_dma_model(DmaModel::Translated)
            .with_devices(DeviceInventory::new().with_debug_serial());
        let kernel = helios_kernel::init(platform);
        cpu.install_timer(kernel.timer());

        let payload = test_payload();
        let debug_state: TestRuntimeState = helios_kernel::RuntimeState::new(
            machine.timebase(),
            1,
            machine.now().ticks(),
            payload,
            helios_kernel::GuestIsa::for_build_target(Some(detect_host_native_feature)),
        );
        let generation = helios_kernel::MachineGeneration::new(None);
        debug_state.install_machine_generation(generation.clone());
        debug_state.install_root_entropy(helios_kernel::seed_root_entropy(
            &cpu,
            None,
            None::<&helios_kernel::NoEntropyDevice>,
            generation,
        ));
        debug_state.seed_wall_clock(cpu.now().ticks(), &HostRtc);

        helios_kernel::install_component_host_program_service(
            &kernel,
            &cpu,
            &debug_state,
            read_captured_serial,
            CAPTURED_SERIAL_WRITER,
        )
        .expect("bootstrap processor installs program service");

        helios_kernel::launch_boot_init(
            &cpu,
            &kernel,
            &debug_state,
            read_captured_serial,
            CAPTURED_SERIAL_WRITER,
            has_system_component,
        );

        let wait_state = debug_state.clone();
        kernel.run_local_future(async move {
            wait_state.wait_for_boot_init().await;
        });
        assert!(debug_state.boot_init_completed());

        let output = String::from_utf8(CAPTURED_SERIAL_OUT.lock().unwrap().clone())
            .expect("init serial output must be valid UTF-8");
        let remaining_in: Vec<u8> = CAPTURED_SERIAL_IN.lock().unwrap().iter().copied().collect();
        (output, remaining_in)
    }

    #[test]
    fn embedded_debugger_is_provisioned() {
        let payload = test_payload();
        let component = payload
            .system_component()
            .expect("kernel prebuild bootfs must carry /bin/debugger");
        assert_eq!(component.name(), "bin/debugger");
        assert!(
            !component.bytes().is_empty(),
            "embedded debugger payload must not be empty"
        );

        let init = payload.embedded_init();
        assert_eq!(init.argv0(), "/init.wasm");
        assert!(
            !init.component().bytes().is_empty(),
            "embedded init component payload must not be empty"
        );
    }

    #[test]
    fn embedded_debugger_boots_alongside_payload_init() {
        let (output, remaining_in) = run_payload_init(true);
        assert!(
            output
                .lines()
                .any(|line| line == "helios init: online root=/"),
            "boot init must emit its online banner, got:\n{output}"
        );
        assert!(
            output.lines().any(|line| line == "file init.txt"),
            "boot init must list root bootfs entries, got:\n{output}"
        );
        assert!(
            output.contains("Helios init loaded from bootfs."),
            "boot init must print /init.txt, got:\n{output}"
        );
        assert_eq!(
            remaining_in, b"\xff\x00HRPC\xaa\x55",
            "boot init must not consume incoming debugger RPC bytes when system component is present"
        );
    }

    #[test]
    fn payload_init_runs_without_embedded_debugger() {
        let (output, _) = run_payload_init(false);
        assert!(
            output
                .lines()
                .any(|line| line == "helios init: online root=/"),
            "standalone boot init must emit its online banner, got:\n{output}"
        );
        assert!(
            output.contains("Helios init loaded from bootfs."),
            "standalone boot init must print /init.txt, got:\n{output}"
        );
    }
}
