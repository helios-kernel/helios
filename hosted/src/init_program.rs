#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

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

    #[test]
    fn embedded_debugger_is_provisioned() {
        let payload = test_payload();
        let debugger = payload
            .bootfs()
            .files()
            .iter()
            .find(|file| file.path() == "bin/debugger")
            .expect("kernel prebuild bootfs must carry /bin/debugger");
        assert!(
            !debugger.contents().is_empty(),
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
        CAPTURED_SERIAL_OUT.lock().unwrap().clear();
        CAPTURED_SERIAL_IN.lock().unwrap().clear();

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

        let service = helios_kernel::install_component_host_program_service(
            &kernel,
            &cpu,
            &debug_state,
            read_captured_serial,
            CAPTURED_SERIAL_WRITER,
        )
        .expect("bootstrap processor installs program service");

        let root_init = debug_state.embedded_init();
        let root_name = root_init.component().name().to_owned();
        let observed_debugger = std::sync::Arc::new(AtomicBool::new(false));
        let observed_root = std::sync::Arc::new(AtomicBool::new(false));
        let stop_timer = kernel.timer();
        let stop_state = debug_state.clone();
        let stop_cpu = cpu.clone();
        let stop_service = service.clone();
        let stop_observed_debugger = observed_debugger.clone();
        let stop_observed_root = observed_root.clone();

        // Once the root supervisor completes init, spawns `/bin/debugger`, and
        // invokes `signal-ready` (emitting `[KDBG run:begin]`), verify both
        // instances are live and stop `/bin/debugger` so the root component
        // finishes cleanly.
        kernel.spawn_local_detached(async move {
            let deadline = Duration::from_secs(30);
            let mut waited = Duration::ZERO;
            while waited < deadline {
                let ready = {
                    let bytes = CAPTURED_SERIAL_OUT.lock().unwrap();
                    String::from_utf8_lossy(&bytes).contains("[KDBG run:begin]")
                };
                if ready {
                    let now = stop_state.uptime_nanos(stop_cpu.now().ticks());
                    let instances = stop_state.instance_registry().snapshot(now);
                    if instances.iter().any(|inst| inst.name == root_name) {
                        stop_observed_root.store(true, Ordering::Release);
                    }
                    if let Some(debugger) = instances.iter().find(|inst| inst.name == "debugger") {
                        stop_observed_debugger.store(true, Ordering::Release);
                        let residency = helios_kernel::UserResidency::default();
                        let _ = stop_state.instance_registry().request_kill(
                            debugger.id,
                            helios_kernel::KillReason::Operator,
                            now,
                            &residency,
                        );
                        stop_service.interrupt_instance(debugger.id);
                        CAPTURED_SERIAL_IN.lock().unwrap().push_back(0);
                        TEST_DEBUG_CONSOLE.receive_signal().notify_all();
                        return;
                    }
                }
                stop_timer.sleep_for(Duration::from_millis(5)).await;
                waited += Duration::from_millis(5);
            }
            panic!("timed out waiting for root supervisor readiness and debugger launch");
        });

        helios_kernel::run_root_component_once(
            root_init,
            cpu,
            &kernel,
            debug_state,
            read_captured_serial,
            CAPTURED_SERIAL_WRITER,
        )
        .expect("root supervisor component must boot and exit cleanly");

        assert!(
            observed_root.load(Ordering::Acquire),
            "root supervisor component instance must be live at readiness"
        );
        assert!(
            observed_debugger.load(Ordering::Acquire),
            "root supervisor must spawn /bin/debugger before signaling ready"
        );

        let output = String::from_utf8(CAPTURED_SERIAL_OUT.lock().unwrap().clone())
            .expect("init serial output must be valid UTF-8");
        assert!(
            output
                .lines()
                .any(|line| line == "helios init: online root=/"),
            "root supervisor must emit its online banner, got:\n{output}"
        );
        assert!(
            output.lines().any(|line| line == "file init.txt"),
            "root supervisor must list root bootfs entries, got:\n{output}"
        );
        let init_txt_pos = output
            .find("Helios init loaded from bootfs.")
            .unwrap_or_else(|| panic!("root supervisor must print /init.txt, got:\n{output}"));
        let ready_pos = output.find("[KDBG run:begin]").unwrap_or_else(|| {
            panic!("root supervisor must emit [KDBG run:begin], got:\n{output}")
        });
        assert!(
            init_txt_pos < ready_pos,
            "boot-readiness marker must follow init banner output, got:\n{output}"
        );
    }
}
