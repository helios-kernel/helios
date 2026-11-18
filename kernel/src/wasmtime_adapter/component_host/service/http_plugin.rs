//! Per-processor runner and supervisor for the `http-client` kernel plugin.
//!
//! `wasi:http/client.send` does not speak HTTP; it pushes an [`HttpExchange`]
//! onto the calling processor's shard of `RuntimeState::http_client()` and
//! waits. Each processor running [`NetworkStep`](super::NetworkStep) hosts a
//! lazy shard of `bin/http-client` via [`PerProcessorPluginStep`], sharing one
//! precompiled `ComponentInstancePre` across cores while owning its own
//! core-local `Store` and socket handles.
//!
//! # Lifecycle
//!
//! Instantiation is lazy per processor. A shard parks on its own queue until
//! the first exchange arrives on that core, so processors that never issue HTTP
//! requests never instantiate a store. Traps or OOMs drop that shard's store and
//! rebuild on its next exchange; `offline(successor)` refuses while an exchange
//! is in flight on the departing shard, and otherwise redirects queued work to
//! `successor` and drops the idle local store before executor teardown.

use wasmtime::component::{Accessor, Instance, InstancePre};

use super::*;
use crate::wasmtime_adapter::wasi::WasiRequest;
use crate::wasmtime_adapter::wasi::http::kernel_error_code;
use crate::wasmtime_adapter::wasi::http_bindings::{HttpHost, exports};
use crate::{HttpErrorCode, HttpExchange, PerProcessorProvider, ProcessAuthority};

/// Bootfs path of the plugin. Absent on a kernel image built without it, in
/// which case `wasi:http/client` reports `configuration-error`.
pub(super) const HTTP_CLIENT_PLUGIN_PATH: &str = "/bin/http-client";

/// Per-processor exchanges that may be queued before `client.send` applies
/// backpressure to callers on that core.
const HTTP_PLUGIN_QUEUE_DEPTH: usize = 16;

/// Instance-registry name, so plugin shards show up in `stats`/`instances`
/// alongside other kernel plugins.
const HTTP_PLUGIN_INSTANCE_NAME: &str = "http-client-plugin";

/// Zero-sized plugin descriptor driving core-local `http-client` shards.
#[derive(Clone, Copy)]
pub(super) struct HttpClientPlugin;

/// Provision the `http-client` sharded provider and prepare the shared
/// precompiled component before `program_service` becomes visible to workers.
pub(super) fn provision_http_client_plugin<CpuImpl, Net, StorageImpl>(
    service: &UserProgramService<CpuImpl, Net, StorageImpl>,
    cpu: &CpuImpl,
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    write_serial: crate::DebugSerialWriter,
) -> Option<PreparedComponent<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let Some(artifact) = read_bootfs_artifact(runtime_state, HTTP_CLIENT_PLUGIN_PATH) else {
        tracing::info!(
            path = HTTP_CLIENT_PLUGIN_PATH,
            "http client plugin is not provisioned; wasi:http/client will report a configuration error"
        );
        return None;
    };

    let started_at = runtime_state.uptime_nanos(cpu.now().ticks());
    let pre = match load_kernel_plugin_instance_pre(
        service,
        HTTP_CLIENT_PLUGIN_PATH,
        &artifact,
        write_serial,
        started_at,
    ) {
        Ok(pre) => pre,
        Err(error) => {
            tracing::error!(
                target: "helios_kernel::supervisor",
                path = HTTP_CLIENT_PLUGIN_PATH,
                ?error,
                "failed to prepare http client plugin; wasi:http/client is now unavailable"
            );
            return None;
        }
    };

    runtime_state
        .http_client()
        .install(crate::memory::user_memory_pool(), HTTP_PLUGIN_QUEUE_DEPTH)
        .unwrap_or_else(|error| panic!("http client provider was installed twice: {error}"));

    Some(pre)
}

impl<CpuImpl, Net, StorageImpl> PerProcessorWasiPlugin<CpuImpl, Net, StorageImpl>
    for HttpClientPlugin
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    type Request = HttpExchange;
    type Guest = exports::wasi::http::handler::Guest;

    fn bootfs_path(&self) -> &'static str {
        HTTP_CLIENT_PLUGIN_PATH
    }

    fn instance_name(&self) -> &'static str {
        HTTP_PLUGIN_INSTANCE_NAME
    }

    fn authority(&self) -> ProcessAuthority {
        // Same authority system components receive: the plugin needs the
        // network and is bootfs-provisioned and signed like they are.
        ProcessAuthority::root()
    }

    fn provider<'a>(
        &'a self,
        runtime_state: &'a HostRuntimeState<CpuImpl, Net, StorageImpl>,
    ) -> &'a PerProcessorProvider<Self::Request> {
        runtime_state.http_client()
    }

    fn precompiled<'a>(
        &self,
        service: &'a UserProgramService<CpuImpl, Net, StorageImpl>,
    ) -> Option<&'a InstancePre<StoreData<CpuImpl, Net, StorageImpl>>> {
        service
            .inner
            .http_client_pre
            .get()
            .and_then(|entry| entry.as_deref())
    }

    fn bind_guest(
        &self,
        store: &mut wasmtime::Store<StoreData<CpuImpl, Net, StorageImpl>>,
        instance: &Instance,
    ) -> Result<Self::Guest, wasmtime::Error> {
        let handler = HttpHost::new(store, instance)?;
        Ok(handler.wasi_http_handler().clone())
    }

    fn dispatch(
        &self,
        accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
        guest: &Self::Guest,
        exchange: HttpExchange,
        in_flight: PluginInFlight,
    ) -> wasmtime::Result<()> {
        let guest = guest.clone();
        accessor.spawn(async move |accessor| {
            handle_exchange::<CpuImpl, Net, StorageImpl>(accessor, guest, exchange, in_flight).await
        })?;
        Ok(())
    }
}

/// One `wasi:http/handler.handle` call, start to finish.
async fn handle_exchange<CpuImpl, Net, StorageImpl>(
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

    // Push the request into the plugin's own table. Its headers are
    // already immutable, so the plugin reads the caller's request exactly
    // as the caller built it.
    let request =
        accessor.with(|mut access| access.get().table.push(WasiRequest::from_host(head, body)));
    let request = match request {
        Ok(request) => request,
        Err(error) => {
            let _ = response.send(Err(internal_error(&error)));
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
                    let _ = response.send(Err(internal_error(&error)));
                    Err(error)
                }
            }
        }
        // The plugin reported a protocol-level failure; that is a normal
        // answer, not a reason to rebuild the instance.
        Ok(Err(code)) => {
            let _ = response.send(Err(kernel_error_code(code)));
            Ok(())
        }
        // A trap leaves the store unusable, so tell the caller and let the
        // supervisor rebuild.
        Err(trap) => {
            let _ = response.send(Err(internal_error(&trap)));
            Err(trap)
        }
    }
}

/// Render a host-side failure as the error code the caller receives.
fn internal_error(error: &impl core::fmt::Debug) -> HttpErrorCode {
    HttpErrorCode::InternalError(Some(alloc::format!("{error:?}")))
}
