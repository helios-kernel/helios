//! Shared runner, lifecycle step, and instantiation helpers for WASI 0.3 kernel
//! plugins.
//!
//! Two kinds of WASI 0.3 kernel plugins live under `service/`:
//! - Singleton plugins with exclusive hardware ownership (such as `compositor`)
//!   that run one instance via [`crate::ProviderSlot`].
//! - Per-processor sharded plugins (such as `http-client`) that share one
//!   precompiled [`PreparedComponent`] across all cores while lazily running a
//!   core-local `Store` on every processor serving [`PerProcessorProvider`].
//!
//! # Concurrency contract
//!
//! - [`PerProcessorPluginStep`] is `!Send` (holds `RefCell` around this
//!   processor's local task handle) and lives exclusively on the processor it
//!   starts on, matching [`super::NetworkStep`].
//! - `in_flight` tracks active dispatched requests inside this shard's `Store`
//!   on the owning processor alone (no cross-core contention).
//! - `offline(successor)` refuses with [`OfflineRefusal::PinnedTasks`] while
//!   `in_flight > 0`; once idle (`0`), it atomically marks this shard
//!   redirected in [`PerProcessorProvider`], forwards queued un-popped requests
//!   to `successor`, and cancels the local supervisor task so `ExecutorStep`
//!   drops the idle `Store` (flushing socket FINs through `NetworkStep`) and
//!   clears `local_live`.

use alloc::sync::Arc as AllocArc;
use core::cell::RefCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use crossbeam_utils::CachePadded;
use helios_hal::cpu::{Cpu, ProcessorId, current_processor};
use helios_hal::measured_boot::MeasuredBoot;
use helios_hal::watchdog::Watchdog;
use wasmtime::component::{Accessor, Instance, InstancePre, ResourceTable};

use super::*;
use crate::PerProcessorProvider;
use crate::exec::{LocalJoinHandle, OfflineRefusal, PinnedTasks, ProcessorStep};
use crate::wasmtime_adapter::preemption::StoreInterrupts;

/// Prepares one bootfs plugin artifact into a shared [`PreparedComponent`].
pub(super) fn load_kernel_plugin_instance_pre<CpuImpl, Net, StorageImpl>(
    service: &UserProgramService<CpuImpl, Net, StorageImpl>,
    bootfs_path: &str,
    artifact: &BootfsBytes,
    write_serial: crate::DebugSerialWriter,
    started_at: u64,
) -> Result<PreparedComponent<CpuImpl, Net, StorageImpl>, ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let payload = trusted_bootfs_payload(artifact);
    service.load_precompiled_component(
        bootfs_path,
        payload,
        write_serial,
        started_at,
        &phases::Timeline::disabled(),
    )
}

/// Identity and capability settings for instantiating one kernel plugin store.
pub(super) struct KernelPluginSpec<'a> {
    pub(super) instance_name: &'a str,
    pub(super) bootfs_path: &'a str,
    pub(super) authority: ProcessAuthority,
    pub(super) started_at: u64,
}

/// Allocates a [`Store`] with `TaskFunding::Kernel`, `OomPolicy::KernelPlugin`,
/// and the caller-supplied authority.
pub(super) fn open_kernel_plugin_store<CpuImpl, Net, StorageImpl>(
    service: &UserProgramService<CpuImpl, Net, StorageImpl>,
    exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
    spec: KernelPluginSpec<'_>,
) -> (
    wasmtime::Store<StoreData<CpuImpl, Net, StorageImpl>>,
    StoreInterrupts<CpuImpl>,
    crate::InstanceId,
)
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let registry = exec_context.runtime_state.instance_registry();
    let instance = registry.register_with_policy(
        spec.instance_name,
        spec.started_at,
        crate::OomPolicy::KernelPlugin,
    );
    let instance_id = instance.id();
    let (store, interrupts) = crate::wasmtime_adapter::store_with_state(
        &service.inner.engine,
        StoreData::<CpuImpl, Net, StorageImpl>::new(
            ResourceTable::new(),
            exec_context.cpu.clone(),
            exec_context.timer.clone(),
            // Kernel plugins draw from the arena's kernel reserve so user-mode
            // load cannot starve core infrastructure.
            exec_context
                .spawner
                .instance_spawner(crate::TaskFunding::Kernel, &instance),
            exec_context.runtime_state.clone(),
            registry,
            instance,
            exec_context.runtime_state.root_namespace().descend(),
            alloc::vec![String::from(spec.bootfs_path)],
            Vec::new(),
            spec.authority,
            OutputMode::Serial,
            exec_context.read_serial,
            exec_context.write_serial,
        ),
    );
    (store, interrupts, instance_id)
}

/// RAII guard keeping a shard's in-flight request count elevated until the
/// dispatched plugin task completes, traps, or drops.
pub(super) struct PluginInFlight {
    count: AllocArc<CachePadded<AtomicUsize>>,
}

impl PluginInFlight {
    fn acquire(count: &AllocArc<CachePadded<AtomicUsize>>) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self {
            count: count.clone(),
        }
    }
}

impl Drop for PluginInFlight {
    fn drop(&mut self) {
        let previous = self.count.fetch_sub(1, Ordering::AcqRel);
        assert!(previous != 0, "plugin in-flight counter underflowed");
    }
}

/// Contract implemented by each per-processor sharded WASI 0.3 kernel plugin.
pub(super) trait PerProcessorWasiPlugin<CpuImpl, Net, StorageImpl>:
    Clone + Send + Sync + 'static
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    type Request: Send + 'static;
    type Guest: Clone + 'static;

    fn bootfs_path(&self) -> &'static str;
    fn instance_name(&self) -> &'static str;
    fn authority(&self) -> ProcessAuthority;
    fn provider<'a>(
        &'a self,
        runtime_state: &'a HostRuntimeState<CpuImpl, Net, StorageImpl>,
    ) -> &'a PerProcessorProvider<Self::Request>;
    fn precompiled<'a>(
        &self,
        service: &'a UserProgramService<CpuImpl, Net, StorageImpl>,
    ) -> Option<&'a InstancePre<StoreData<CpuImpl, Net, StorageImpl>>>;
    fn bind_guest(
        &self,
        store: &mut wasmtime::Store<StoreData<CpuImpl, Net, StorageImpl>>,
        instance: &Instance,
    ) -> Result<Self::Guest, wasmtime::Error>;
    fn dispatch(
        &self,
        accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
        guest: &Self::Guest,
        request: Self::Request,
        in_flight: PluginInFlight,
    ) -> wasmtime::Result<()>;
}

/// Core-local supervisor step for a sharded WASI 0.3 kernel plugin.
pub(super) struct PerProcessorPluginStep<P, CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    plugin: P,
    debug_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    cpu: CpuImpl,
    spawner: crate::Spawner<CpuImpl>,
    timer: crate::Timer<CpuImpl>,
    in_flight: AllocArc<CachePadded<AtomicUsize>>,
    supervisor: RefCell<Option<LocalJoinHandle<()>>>,
}

impl<P, CpuImpl, Net, StorageImpl> PerProcessorPluginStep<P, CpuImpl, Net, StorageImpl>
where
    P: PerProcessorWasiPlugin<CpuImpl, Net, StorageImpl>,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    /// Starts this processor's lazy plugin shard on boot bring-up.
    pub(super) fn start<WatchdogImpl, MeasuredBootImpl>(
        cpu: &CpuImpl,
        kernel: &crate::Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
        debug_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
        plugin: P,
    ) -> Self
    where
        WatchdogImpl: Watchdog + Clone,
        MeasuredBootImpl: MeasuredBoot,
    {
        let step = Self {
            plugin,
            debug_state: debug_state.clone(),
            cpu: cpu.clone(),
            spawner: kernel.spawner(),
            timer: kernel.timer(),
            in_flight: AllocArc::new(CachePadded::new(AtomicUsize::new(0))),
            supervisor: RefCell::new(None),
        };
        step.online_on(current_processor());
        step
    }

    fn online_on(&self, processor: ProcessorId) {
        self.plugin
            .provider(&self.debug_state)
            .activate_shard(processor);
        let plugin = self.plugin.clone();
        let debug_state = self.debug_state.clone();
        let cpu = self.cpu.clone();
        let spawner = self.spawner.clone();
        let timer = self.timer.clone();
        let in_flight = self.in_flight.clone();
        let handle = self.spawner.spawn_local(async move {
            run_shard_supervisor(
                plugin,
                debug_state,
                cpu,
                spawner,
                timer,
                processor,
                in_flight,
            )
            .await;
        });
        let previous = self.supervisor.replace(Some(handle));
        assert!(
            previous.is_none(),
            "processor {} started {} shard supervisor twice",
            processor.id(),
            self.plugin.instance_name(),
        );
    }

    fn offline_on(
        &self,
        processor: ProcessorId,
        successor: ProcessorId,
    ) -> Result<(), OfflineRefusal> {
        let live = self.in_flight.load(Ordering::Acquire);
        if live != 0 {
            return Err(OfflineRefusal::PinnedTasks(PinnedTasks { processor, live }));
        }
        self.plugin
            .provider(&self.debug_state)
            .redirect_shard(processor, successor);
        drop(self.supervisor.borrow_mut().take());
        Ok(())
    }
}

impl<P, CpuImpl, Net, StorageImpl> ProcessorStep
    for PerProcessorPluginStep<P, CpuImpl, Net, StorageImpl>
where
    P: PerProcessorWasiPlugin<CpuImpl, Net, StorageImpl>,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn online<KernelCpu, WatchdogImpl, MeasuredBootImpl>(
        &self,
        _kernel: &crate::Kernel<KernelCpu, WatchdogImpl, MeasuredBootImpl>,
    ) where
        KernelCpu: Cpu + Clone,
        WatchdogImpl: Watchdog + Clone,
        MeasuredBootImpl: MeasuredBoot,
    {
        self.online_on(current_processor());
    }

    fn offline<KernelCpu, WatchdogImpl, MeasuredBootImpl>(
        &self,
        _kernel: &crate::Kernel<KernelCpu, WatchdogImpl, MeasuredBootImpl>,
        successor: ProcessorId,
    ) -> Result<(), OfflineRefusal>
    where
        KernelCpu: Cpu + Clone,
        WatchdogImpl: Watchdog + Clone,
        MeasuredBootImpl: MeasuredBoot,
    {
        self.offline_on(current_processor(), successor)
    }
}

async fn run_shard_supervisor<P, CpuImpl, Net, StorageImpl>(
    plugin: P,
    debug_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    cpu: CpuImpl,
    spawner: crate::Spawner<CpuImpl>,
    timer: crate::Timer<CpuImpl>,
    processor: ProcessorId,
    in_flight: AllocArc<CachePadded<AtomicUsize>>,
) where
    P: PerProcessorWasiPlugin<CpuImpl, Net, StorageImpl>,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let service = debug_state.wait_for_program_service().await;
    if plugin.precompiled(&service).is_none() {
        return;
    }
    let exec_context = ProgramExecContext {
        cpu,
        timer,
        spawner,
        runtime_state: debug_state.clone(),
        instance_registry: debug_state.instance_registry(),
        parent_instance_id: None,
        read_serial: service.inner.plugin_read_serial,
        write_serial: service.inner.plugin_write_serial,
    };
    let provider = plugin.provider(&debug_state);
    loop {
        // Lazily defer instantiation until a request arrives on this core.
        let Some(first) = provider.recv_on(processor).await else {
            return;
        };
        match run_shard_once(
            &plugin,
            &service,
            &exec_context,
            processor,
            first,
            &in_flight,
        )
        .await
        {
            Ok(()) => return,
            Err(error) if plugin_runtime_should_be_recycled(&error) => {
                tracing::warn!(
                    target: "helios_kernel::supervisor",
                    plugin = plugin.instance_name(),
                    processor = processor.id(),
                    ?error,
                    "per-processor plugin shard died; rebuilding on next request"
                );
            }
            Err(error) => {
                tracing::error!(
                    target: "helios_kernel::supervisor",
                    plugin = plugin.instance_name(),
                    processor = processor.id(),
                    ?error,
                    "per-processor plugin shard failed unrecoverably"
                );
                return;
            }
        }
    }
}

async fn run_shard_once<P, CpuImpl, Net, StorageImpl>(
    plugin: &P,
    service: &UserProgramService<CpuImpl, Net, StorageImpl>,
    exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
    processor: ProcessorId,
    first: P::Request,
    in_flight: &AllocArc<CachePadded<AtomicUsize>>,
) -> Result<(), ProgramExecError>
where
    P: PerProcessorWasiPlugin<CpuImpl, Net, StorageImpl>,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let instance_pre = plugin
        .precompiled(service)
        .expect("plugin precompiled component checked by shard supervisor");
    let started_at = exec_context
        .runtime_state
        .uptime_nanos(exec_context.cpu.now().ticks());

    let (mut store, interrupts, _) = open_kernel_plugin_store(
        service,
        exec_context,
        KernelPluginSpec {
            instance_name: plugin.instance_name(),
            bootfs_path: plugin.bootfs_path(),
            authority: plugin.authority(),
            started_at,
        },
    );

    let turns = store.data().guest_turns();
    let wasm_instance = interrupts
        .drive(turns.drive(instance_pre.instantiate_async(&mut store)))
        .await
        .map_err(map_program_runtime_error)?;
    let guest = plugin
        .bind_guest(&mut store, &wasm_instance)
        .map_err(map_program_runtime_error)?;

    let provider = plugin.provider(&exec_context.runtime_state);
    let mut first = Some(first);
    let turns = store.data().guest_turns();
    interrupts
        .drive(turns.drive(store.run_concurrent(async move |accessor| {
            let req = first.take().expect("the first request is dispatched once");
            plugin.dispatch(accessor, &guest, req, PluginInFlight::acquire(in_flight))?;
            while let Some(req) = provider.recv_on(processor).await {
                plugin.dispatch(accessor, &guest, req, PluginInFlight::acquire(in_flight))?;
            }
            Ok::<(), wasmtime::Error>(())
        })))
        .await
        .and_then(|result| result)
        .map_err(map_program_runtime_error)
}

#[cfg(test)]
mod tests {
    use core::future::pending;

    use futures_lite::future::block_on;
    use helios_hal::watchdog::ProgressCounter;

    use super::*;
    use crate::Executor;
    use crate::test_support::{RecordingSmpCpu, TestCpu, TestNetworkService, UnsupportedStorage};

    #[derive(Clone)]
    struct DummyShardedPlugin {
        provider: AllocArc<PerProcessorProvider<u32>>,
    }

    impl PerProcessorWasiPlugin<RecordingSmpCpu, TestNetworkService, UnsupportedStorage>
        for DummyShardedPlugin
    {
        type Request = u32;
        type Guest = ();

        fn bootfs_path(&self) -> &'static str {
            "/bin/dummy"
        }

        fn instance_name(&self) -> &'static str {
            "dummy-plugin"
        }

        fn authority(&self) -> ProcessAuthority {
            ProcessAuthority::empty()
        }

        fn provider<'a>(
            &'a self,
            _runtime_state: &'a HostRuntimeState<
                RecordingSmpCpu,
                TestNetworkService,
                UnsupportedStorage,
            >,
        ) -> &'a PerProcessorProvider<u32> {
            &self.provider
        }

        fn precompiled<'a>(
            &self,
            _service: &'a UserProgramService<
                RecordingSmpCpu,
                TestNetworkService,
                UnsupportedStorage,
            >,
        ) -> Option<
            &'a InstancePre<StoreData<RecordingSmpCpu, TestNetworkService, UnsupportedStorage>>,
        > {
            None
        }

        fn bind_guest(
            &self,
            _store: &mut wasmtime::Store<
                StoreData<RecordingSmpCpu, TestNetworkService, UnsupportedStorage>,
            >,
            _instance: &Instance,
        ) -> Result<(), wasmtime::Error> {
            Ok(())
        }

        fn dispatch(
            &self,
            _accessor: &Accessor<
                StoreData<RecordingSmpCpu, TestNetworkService, UnsupportedStorage>,
            >,
            _guest: &(),
            _request: u32,
            _in_flight: PluginInFlight,
        ) -> wasmtime::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn per_processor_step_refuses_while_in_flight_redirects_and_clears_local_live_when_idle() {
        let pool = crate::test_support::TestMachine {
            processor_nodes: alloc::vec![0, 0],
            distances: alloc::vec![10],
        }
        .pool(crate::test_support::TEST_POOL_NODE_BYTES);

        let p0 = ProcessorId::new(0);
        let p1 = ProcessorId::new(1);
        let cpu0 = RecordingSmpCpu::new(0, 2);
        let executor0 = Executor::isolated(ProgressCounter::new(), pool, p0);
        executor0.group().bring_processor_online(p0);

        crate::test_processor_identity::set(p1);
        let cpu1 = RecordingSmpCpu::new(1, 2);
        let executor1 = executor0.sibling(ProgressCounter::new(), p1);
        executor0.group().bring_processor_online(p1);

        let runtime_state: HostRuntimeState<
            RecordingSmpCpu,
            TestNetworkService,
            UnsupportedStorage,
        > = crate::RuntimeState::new(
            cpu1.timebase(),
            2,
            0,
            crate::BootPayload::for_tests(),
            GuestIsa::for_build_target(TestCpu::with_entropy(1).native_feature_probe()),
        );

        let plugin = DummyShardedPlugin {
            provider: AllocArc::new(PerProcessorProvider::new()),
        };
        plugin
            .provider
            .install(pool, 4)
            .expect("install dummy shards");
        let spawner1 = executor1.spawner(cpu1.clone());
        let timer1 = executor1.timer(cpu1.clone());
        let step1 = PerProcessorPluginStep {
            plugin: plugin.clone(),
            debug_state: runtime_state,
            cpu: cpu1.clone(),
            spawner: spawner1.clone(),
            timer: timer1,
            in_flight: AllocArc::new(CachePadded::new(AtomicUsize::new(0))),
            supervisor: RefCell::new(None),
        };
        let handle = spawner1.spawn_local(pending::<()>());
        *step1.supervisor.borrow_mut() = Some(handle);

        // Simulate an active in-flight exchange on processor 1.
        let active = PluginInFlight::acquire(&step1.in_flight);
        assert_eq!(
            step1.offline_on(p1, p0),
            Err(OfflineRefusal::PinnedTasks(PinnedTasks {
                processor: p1,
                live: 1,
            }))
        );
        assert!(step1.supervisor.borrow().is_some());

        // Drop the in-flight guard and queue a message on core 1 before going offline.
        drop(active);
        crate::test_processor_identity::set(p1);
        block_on(plugin.provider.send(42)).expect("queue onto core 1 shard");

        assert_eq!(step1.offline_on(p1, p0), Ok(()));
        assert_eq!(plugin.provider.try_recv_on(p0), Ok(42));
        assert_eq!(executor1.take_offline(&cpu1, p0), Ok(()));

        // Coming back online reactivates shard 1 cleanly.
        executor0.group().bring_processor_online(p1);
        step1.online_on(p1);
        crate::test_processor_identity::set(p1);
        block_on(plugin.provider.send(99)).expect("reactivated shard 1 accepts work");
        assert_eq!(plugin.provider.try_recv_on(p1), Ok(99));
        drop(step1.supervisor.borrow_mut().take());
        let _ = cpu0;
    }
}
