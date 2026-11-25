//! Shared per-processor shard runner, lifecycle step, and store helpers for
//! root-supervisor-managed kernel providers.
//!
//! # Concurrency contract
//!
//! - [`PerProcessorHttpStep`] is `!Send` (holds `RefCell` around this
//!   processor's local task handle) and lives exclusively on the processor it
//!   starts on, matching [`super::NetworkStep`].
//! - `in_flight` tracks active dispatched HTTP exchanges inside this shard's
//!   `Store` on the owning processor alone (no cross-core contention).
//! - `offline(successor)` refuses with [`OfflineRefusal::PinnedTasks`] while
//!   `in_flight > 0`; once idle (`0`), it atomically marks this shard
//!   redirected in [`PerProcessorProvider`], forwards queued un-popped
//!   exchanges to `successor`, and cancels the local shard task so
//!   `ExecutorStep` drops the idle `Store` (flushing socket FINs through
//!   `NetworkStep`) before executor teardown.
//! - Provider activation, hot-replacement, and deactivation are driven purely
//!   by the root supervisor through `helios:system/root-supervisor`; no plugin
//!   path, authority, or restart loop is hardcoded here.

use alloc::sync::Arc as AllocArc;
use core::cell::RefCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use crossbeam_utils::CachePadded;
use helios_hal::cpu::{Cpu, ProcessorId, current_processor};
use helios_hal::measured_boot::MeasuredBoot;
use helios_hal::watchdog::Watchdog;
use wasmtime::component::{Accessor, ResourceTable};

use super::root_supervisor::HttpProviderRegistration;
use super::*;
use crate::exec::{LocalJoinHandle, OfflineRefusal, PinnedTasks, ProcessorStep};
use crate::wasmtime_adapter::preemption::StoreInterrupts;
use crate::wasmtime_adapter::wasi::WasiRequest;
use crate::wasmtime_adapter::wasi::http::kernel_error_code;
use crate::wasmtime_adapter::wasi::http_bindings::{HttpHost, exports};
use crate::{HttpErrorCode, HttpExchange, OomPolicy};

/// Per-processor HTTP exchanges that may be queued before `wasi:http/client.send`
/// applies backpressure to callers on that core.
pub(super) const HTTP_PROVIDER_QUEUE_DEPTH: usize = 16;

/// Identity, memory-policy, and capability settings for instantiating one
/// root-supervisor-managed provider store.
pub(super) struct ProviderStoreSpec<'a> {
    pub(super) instance_name: &'a str,
    pub(super) bootfs_path: &'a str,
    pub(super) authority: ProcessAuthority,
    pub(super) oom_policy: OomPolicy,
    pub(super) started_at: u64,
}

/// Allocates a [`wasmtime::Store`] for a root-supervisor-managed provider with
/// its bounded [`OomPolicy`], derived [`crate::TaskFunding`], and attenuated
/// [`ProcessAuthority`].
pub(super) fn open_provider_store<CpuImpl, Net, StorageImpl>(
    service: &UserProgramService<CpuImpl, Net, StorageImpl>,
    exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
    spec: ProviderStoreSpec<'_>,
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
    let instance = registry.register_child_with_policy(
        exec_context.parent_instance_id,
        spec.instance_name,
        spec.started_at,
        spec.oom_policy,
    );
    let instance_id = instance.id();
    let (store, interrupts) = crate::wasmtime_adapter::store_with_state(
        &service.inner.engine,
        StoreData::<CpuImpl, Net, StorageImpl>::new(
            ResourceTable::new(),
            exec_context.cpu.clone(),
            exec_context.timer.clone(),
            exec_context
                .spawner
                .instance_spawner(spec.oom_policy.task_funding(), &instance),
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
/// dispatched provider task completes, traps, or drops.
pub(super) struct PluginInFlight {
    count: AllocArc<CachePadded<AtomicUsize>>,
}

impl PluginInFlight {
    pub(super) fn acquire(count: &AllocArc<CachePadded<AtomicUsize>>) -> Self {
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

/// Core-local lifecycle step driving whichever per-processor `wasi:http/client`
/// provider the root supervisor currently has installed.
pub(super) struct PerProcessorHttpStep<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    debug_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    cpu: CpuImpl,
    spawner: crate::Spawner<CpuImpl>,
    timer: crate::Timer<CpuImpl>,
    in_flight: AllocArc<CachePadded<AtomicUsize>>,
    supervisor: RefCell<Option<LocalJoinHandle<()>>>,
}

impl<CpuImpl, Net, StorageImpl> PerProcessorHttpStep<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    /// Starts this processor's lazy HTTP shard listener on boot bring-up.
    ///
    /// Parks with zero stores allocated until the root supervisor installs an
    /// HTTP provider and an exchange arrives on this processor.
    pub(super) fn start<WatchdogImpl, MeasuredBootImpl>(
        cpu: &CpuImpl,
        kernel: &crate::Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
        debug_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    ) -> Self
    where
        WatchdogImpl: Watchdog + Clone,
        MeasuredBootImpl: MeasuredBoot,
    {
        let step = Self {
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
        self.debug_state.http_client().activate_shard(processor);
        let debug_state = self.debug_state.clone();
        let cpu = self.cpu.clone();
        let spawner = self.spawner.clone();
        let timer = self.timer.clone();
        let in_flight = self.in_flight.clone();
        let handle = self.spawner.spawn_local(async move {
            run_http_shard_loop(debug_state, cpu, spawner, timer, processor, in_flight).await;
        });
        let previous = self.supervisor.replace(Some(handle));
        assert!(
            previous.is_none(),
            "processor {} started http shard supervisor twice",
            processor.id(),
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
        self.debug_state
            .http_client()
            .redirect_shard(processor, successor);
        drop(self.supervisor.borrow_mut().take());
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl> ProcessorStep for PerProcessorHttpStep<CpuImpl, Net, StorageImpl>
where
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

async fn run_http_shard_loop<CpuImpl, Net, StorageImpl>(
    debug_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    cpu: CpuImpl,
    spawner: crate::Spawner<CpuImpl>,
    timer: crate::Timer<CpuImpl>,
    processor: ProcessorId,
    in_flight: AllocArc<CachePadded<AtomicUsize>>,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let service = debug_state.wait_for_program_service().await;
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
    let provider = debug_state.http_client();
    loop {
        let changed = provider.changed();
        let Some(registration) = service.http_provider_registration() else {
            changed.await;
            continue;
        };
        if !provider.is_installed() || provider.generation() != registration.generation {
            changed.await;
            continue;
        }
        // Lazily defer store instantiation until an exchange actually arrives
        // on this processor for this active generation.
        let Some(first) = provider
            .recv_on_for_generation(processor, registration.generation)
            .await
        else {
            continue;
        };
        if let Err(error) = run_http_shard_once(
            &service,
            &exec_context,
            &registration,
            processor,
            first,
            &in_flight,
        )
        .await
        {
            tracing::warn!(
                target: "helios_kernel::supervisor",
                plugin = registration.name.as_str(),
                processor = processor.id(),
                ?error,
                "per-processor http provider shard faulted; notifying root supervisor"
            );
            service.fault_http_provider(
                &debug_state,
                registration.generation,
                alloc::format!("processor {} shard faulted: {error:?}", processor.id()),
            );
        }
    }
}

async fn run_http_shard_once<CpuImpl, Net, StorageImpl>(
    service: &UserProgramService<CpuImpl, Net, StorageImpl>,
    exec_context: &ProgramExecContext<CpuImpl, Net, StorageImpl>,
    registration: &HttpProviderRegistration<CpuImpl, Net, StorageImpl>,
    processor: ProcessorId,
    first: HttpExchange,
    in_flight: &AllocArc<CachePadded<AtomicUsize>>,
) -> Result<(), ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let started_at = exec_context
        .runtime_state
        .uptime_nanos(exec_context.cpu.now().ticks());
    let mut shard_context = exec_context.clone();
    shard_context.parent_instance_id = registration.parent_instance_id;
    let (mut store, interrupts, _) = open_provider_store(
        service,
        &shard_context,
        ProviderStoreSpec {
            instance_name: &registration.name,
            bootfs_path: &registration.path,
            authority: registration.authority.clone(),
            oom_policy: registration.oom_policy,
            started_at,
        },
    );

    let turns = store.data().guest_turns();
    let wasm_instance = interrupts
        .drive(turns.drive(registration.precompiled.instantiate_async(&mut store)))
        .await
        .map_err(map_program_runtime_error)?;
    let handler = HttpHost::new(&mut store, &wasm_instance).map_err(map_program_runtime_error)?;
    let guest = handler.wasi_http_handler().clone();

    let provider = exec_context.runtime_state.http_client();
    let generation = registration.generation;
    let mut first = Some(first);
    let turns = store.data().guest_turns();
    interrupts
        .drive(turns.drive(store.run_concurrent(async move |accessor| {
            let req = first.take().expect("the first exchange is dispatched once");
            let dispatch_guest = guest.clone();
            let guard = PluginInFlight::acquire(in_flight);
            accessor.spawn(async move |accessor| {
                handle_http_exchange::<CpuImpl, Net, StorageImpl>(
                    accessor,
                    dispatch_guest,
                    req,
                    guard,
                )
                .await
            })?;
            while let Some(req) = provider.recv_on_for_generation(processor, generation).await {
                let dispatch_guest = guest.clone();
                let guard = PluginInFlight::acquire(in_flight);
                accessor.spawn(async move |accessor| {
                    handle_http_exchange::<CpuImpl, Net, StorageImpl>(
                        accessor,
                        dispatch_guest,
                        req,
                        guard,
                    )
                    .await
                })?;
            }
            Ok::<(), wasmtime::Error>(())
        })))
        .await
        .and_then(|result| result)
        .map_err(map_program_runtime_error)
}

/// One `wasi:http/handler.handle` call, start to finish.
async fn handle_http_exchange<CpuImpl, Net, StorageImpl>(
    accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
    guest: exports::wasi::http::handler::Guest,
    exchange: HttpExchange,
    _in_flight: PluginInFlight,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let HttpExchange {
        head,
        body,
        response,
    } = exchange;

    let request =
        accessor.with(|mut access| access.get().table.push(WasiRequest::from_host(head, body)));
    let request = match request {
        Ok(request) => request,
        Err(error) => {
            let _ = response.send(Err(http_internal_error(&error)));
            return Err(error.into());
        }
    };

    match guest.call_handle(accessor, request).await {
        Ok(Ok(produced)) => {
            let converted = accessor.with(|mut access| {
                let produced = access.get().table.delete(produced)?;
                produced.into_host_response(&mut access)
            });
            match converted {
                Ok(http_response) => {
                    let _ = response.send(Ok(http_response));
                    Ok(())
                }
                Err(error) => {
                    let _ = response.send(Err(http_internal_error(&error)));
                    Err(error)
                }
            }
        }
        Ok(Err(code)) => {
            let _ = response.send(Err(kernel_error_code(code)));
            Ok(())
        }
        Err(trap) => {
            let _ = response.send(Err(http_internal_error(&trap)));
            Err(trap)
        }
    }
}

fn http_internal_error(error: &impl core::fmt::Debug) -> HttpErrorCode {
    HttpErrorCode::InternalError(Some(alloc::format!("{error:?}")))
}

#[cfg(test)]
mod tests {
    use core::future::pending;

    use futures_lite::future::block_on;
    use helios_hal::watchdog::ProgressCounter;

    use super::*;
    use crate::Executor;
    use crate::test_support::{RecordingSmpCpu, TestCpu, TestNetworkService, UnsupportedStorage};

    #[test]
    fn per_processor_http_step_refuses_while_in_flight_redirects_and_clears_local_live_when_idle() {
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

        let generation = runtime_state.http_client().install_or_activate(pool, 4);
        assert_eq!(generation, 1);

        let spawner1 = executor1.spawner(cpu1.clone());
        let timer1 = executor1.timer(cpu1.clone());
        let step1 = PerProcessorHttpStep {
            debug_state: runtime_state.clone(),
            cpu: cpu1.clone(),
            spawner: spawner1.clone(),
            timer: timer1,
            in_flight: AllocArc::new(CachePadded::new(AtomicUsize::new(0))),
            supervisor: RefCell::new(None),
        };
        let handle = spawner1.spawn_local(pending::<()>());
        *step1.supervisor.borrow_mut() = Some(handle);

        // Simulate an active in-flight HTTP exchange on processor 1.
        let active = PluginInFlight::acquire(&step1.in_flight);
        assert_eq!(
            step1.offline_on(p1, p0),
            Err(OfflineRefusal::PinnedTasks(PinnedTasks {
                processor: p1,
                live: 1,
            }))
        );
        assert!(step1.supervisor.borrow().is_some());

        // Drop the in-flight guard and enqueue an HTTP exchange on core 1 before going offline.
        drop(active);
        crate::test_processor_identity::set(p1);
        let (tx, _rx) = futures::channel::oneshot::channel();
        let (_body_tx, body_rx) = crate::byte_channel();
        let (_trailers_tx, trailers_rx) = futures::channel::oneshot::channel();
        let (result_tx, _result_rx) = futures::channel::oneshot::channel();
        let exchange = crate::HttpExchange {
            head: crate::HttpRequestHead {
                method: crate::HttpMethod::Get,
                scheme: Some(crate::HttpScheme::Http),
                authority: Some(String::from("example.test")),
                path_with_query: Some(String::from("/")),
                headers: crate::HttpFields::new_mutable(),
                options: None,
            },
            body: crate::HttpBody {
                contents: body_rx,
                trailers: trailers_rx,
                result: result_tx,
            },
            response: tx,
        };
        block_on(runtime_state.http_client().send(exchange)).expect("queue onto core 1 shard");

        assert_eq!(step1.offline_on(p1, p0), Ok(()));
        assert!(runtime_state.http_client().try_recv_on(p0).is_ok());
        assert_eq!(executor1.take_offline(&cpu1, p0), Ok(()));

        // Coming back online reactivates shard 1 cleanly, and hot-replacing bumps generation.
        executor0.group().bring_processor_online(p1);
        step1.online_on(p1);
        let next_gen = runtime_state.http_client().install_or_activate(pool, 4);
        assert_eq!(next_gen, 2);
        crate::test_processor_identity::set(p1);
        let (tx2, _rx2) = futures::channel::oneshot::channel();
        let (_body_tx2, body_rx2) = crate::byte_channel();
        let (_trailers_tx2, trailers_rx2) = futures::channel::oneshot::channel();
        let (result_tx2, _result_rx2) = futures::channel::oneshot::channel();
        let exchange2 = crate::HttpExchange {
            head: crate::HttpRequestHead {
                method: crate::HttpMethod::Get,
                scheme: Some(crate::HttpScheme::Http),
                authority: Some(String::from("example.test")),
                path_with_query: Some(String::from("/next")),
                headers: crate::HttpFields::new_mutable(),
                options: None,
            },
            body: crate::HttpBody {
                contents: body_rx2,
                trailers: trailers_rx2,
                result: result_tx2,
            },
            response: tx2,
        };
        block_on(runtime_state.http_client().send(exchange2))
            .expect("reactivated shard 1 accepts work");
        assert!(runtime_state.http_client().try_recv_on(p1).is_ok());
        drop(step1.supervisor.borrow_mut().take());
        let _ = cpu0;
    }
}
