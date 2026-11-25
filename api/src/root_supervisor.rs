//! Root-only kernel supervisor bindings (`helios:system/root-supervisor@0.1.0`).
//!
//! Only the single signed root component booted by the kernel receives this
//! interface; ordinary components fail linking and any attempt to delegate it
//! to children is rejected by the kernel.

use crate::bindings::helios::system::root_supervisor as raw;
use crate::programs::Child;
use crate::wit_bindgen::StreamReader;

pub use crate::bindings::helios::system::root_supervisor::{
    DeviceGrantInfo, EscalationAction, FatalReport, HardwareInventory, ManagedSpawnRequest,
    OomPolicy, ProviderExit, ProviderRequest, SupervisorError, SupervisorErrorKind,
};

/// Owned handle to a root-supervisor-installed kernel provider endpoint.
///
/// Dropping this handle stops the provider and detaches it from its kernel
/// slot if it is still the active generation.
pub struct ProviderHandle {
    inner: raw::ProviderHandle,
}

impl ProviderHandle {
    /// Instance identifier of the active provider, when singleton-instantiated.
    pub fn instance_id(&self) -> Option<u64> {
        self.inner.instance_id()
    }

    /// Await exit, replacement, stop, or fault of this provider endpoint.
    pub async fn wait_exit(&self) -> ProviderExit {
        self.inner.wait_exit().await
    }

    /// Stop this provider and detach it from its kernel slot if still active.
    pub fn stop(&self) {
        self.inner.stop();
    }
}

/// Snapshot discovered user-mode hardware device grants and platform capabilities.
pub fn hardware_inventory() -> Result<HardwareInventory, SupervisorError> {
    raw::get_hardware_inventory()
}

/// Subscribe to hardware inventory snapshots as discovery and bring-up progress.
pub fn subscribe_hardware() -> Result<StreamReader<HardwareInventory>, SupervisorError> {
    raw::subscribe_hardware()
}

/// Spawn a managed component or process with a bounded `oom_policy` and
/// optional named hardware device grants.
pub async fn spawn(request: ManagedSpawnRequest) -> Result<Child, SupervisorError> {
    let child = raw::spawn(request).await?;
    Ok(Child::from_raw(child))
}

/// Install or atomically replace the singleton `surface` compositor provider.
pub async fn install_surface_provider(
    request: ProviderRequest,
) -> Result<ProviderHandle, SupervisorError> {
    let inner = raw::install_surface_provider(request).await?;
    Ok(ProviderHandle { inner })
}

/// Install or atomically replace the per-processor `wasi:http/client` provider.
pub async fn install_http_provider(
    request: ProviderRequest,
) -> Result<ProviderHandle, SupervisorError> {
    let inner = raw::install_http_provider(request).await?;
    Ok(ProviderHandle { inner })
}

/// Install or atomically replace the AOT `compiler` session provider.
pub async fn install_compiler_provider(
    request: ProviderRequest,
) -> Result<ProviderHandle, SupervisorError> {
    let inner = raw::install_compiler_provider(request).await?;
    Ok(ProviderHandle { inner })
}

/// Flush writable mounts and emit the boot-readiness marker on debug serial.
pub async fn signal_ready() -> Result<(), SupervisorError> {
    raw::signal_ready().await
}

/// Escalate an unrecoverable failure of a `critical = "system"` component into
/// a controlled kernel halt or reboot.
pub async fn escalate_fatal(report: FatalReport) -> Result<(), SupervisorError> {
    raw::escalate_fatal(report).await
}
