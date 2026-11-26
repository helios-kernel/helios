//! Typed Python exception hierarchy mirroring `helios-ops` errors.

use helios_ops::{OpsError, TargetError as OpsTargetError};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(
    helios._native,
    HeliosError,
    PyException,
    "Base exception for all Helios operations SDK errors."
);
create_exception!(
    helios._native,
    AttenuationDeniedError,
    HeliosError,
    "Raised when an operation or scope widening violates session capability attenuation."
);
create_exception!(
    helios._native,
    TransportError,
    HeliosError,
    "Raised when opening or driving a Helios node transport fails."
);
create_exception!(
    helios._native,
    RpcError,
    HeliosError,
    "Raised when a remote RPC invocation fails, times out, or is refused by the guest."
);
create_exception!(
    helios._native,
    TargetError,
    HeliosError,
    "Raised when parsing, resolving, or storing a Helios target fails."
);

/// Convert a [`helios_ops::TargetError`] into a Python [`TargetError`].
pub(crate) fn target_err_to_py(err: OpsTargetError) -> PyErr {
    TargetError::new_err(err.to_string())
}

/// Convert a [`helios_ops::OpsError`] into the matching typed Python exception.
pub(crate) fn ops_err_to_py(err: OpsError) -> PyErr {
    match err {
        OpsError::AttenuationDenied { .. } => AttenuationDeniedError::new_err(err.to_string()),
        OpsError::Transport(_) => TransportError::new_err(err.to_string()),
        OpsError::Target(_) => TargetError::new_err(err.to_string()),
        OpsError::TimedOut { .. }
        | OpsError::Rpc { .. }
        | OpsError::Fs(_)
        | OpsError::FilterRefused { .. }
        | OpsError::NoInstanceNamed { .. }
        | OpsError::KillRefused { .. }
        | OpsError::TraceTargetRefused { .. }
        | OpsError::ProfilingControlRefused { .. }
        | OpsError::InstructionProfileRefused { .. }
        | OpsError::RawProfileRefused { .. }
        | OpsError::ProcessorOfflineRefused { .. }
        | OpsError::ProcessorOnlineRefused { .. }
        | OpsError::SnapshotRefused { .. }
        | OpsError::ComponentControlRefused { .. }
        | OpsError::MountRefused { .. }
        | OpsError::BtrfsRefused { .. }
        | OpsError::ExecRefused { .. } => RpcError::new_err(err.to_string()),
        OpsError::Auth(_)
        | OpsError::Http(_)
        | OpsError::Oci(_)
        | OpsError::Bundle(_)
        | OpsError::Symbolize(_)
        | OpsError::StdinClosed
        | OpsError::InvalidVmConfig { .. }
        | OpsError::InvalidPath { .. }
        | OpsError::NotFound { .. }
        | OpsError::InvalidGrant { .. }
        | OpsError::InvalidSignal { .. } => HeliosError::new_err(err.to_string()),
    }
}

/// Register every Helios exception type on the native Python module.
pub(crate) fn register(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("HeliosError", py.get_type::<HeliosError>())?;
    module.add(
        "AttenuationDeniedError",
        py.get_type::<AttenuationDeniedError>(),
    )?;
    module.add("TransportError", py.get_type::<TransportError>())?;
    module.add("RpcError", py.get_type::<RpcError>())?;
    module.add("TargetError", py.get_type::<TargetError>())?;
    Ok(())
}
