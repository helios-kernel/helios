//! PyO3 native extension (`helios._native`) exposing the async `helios-ops` SDK to Python.

mod error;
mod fleet;
mod session;
mod types;

use pyo3::prelude::*;

use crate::fleet::PyFleet;
use crate::session::PySession;
use crate::types::{
    PyBundleManifest, PyChild, PyComponentPublication, PyDiagnosticBundle, PyExecResult,
    PyInspectEntry, PyInspectSnapshot, PyInstance, PyNodeOutcome, PyRemoteEntry, PyRemoteStat,
    PyTarget, PyTargetStore, PyTraceEvent,
};

#[pymodule]
fn _native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    error::register(py, m)?;
    m.add_class::<PyTarget>()?;
    m.add_class::<PyTargetStore>()?;
    m.add_class::<PyInspectEntry>()?;
    m.add_class::<PyComponentPublication>()?;
    m.add_class::<PyInspectSnapshot>()?;
    m.add_class::<PyInstance>()?;
    m.add_class::<PyTraceEvent>()?;
    m.add_class::<PyExecResult>()?;
    m.add_class::<PyChild>()?;
    m.add_class::<PyRemoteEntry>()?;
    m.add_class::<PyRemoteStat>()?;
    m.add_class::<PyBundleManifest>()?;
    m.add_class::<PyDiagnosticBundle>()?;
    m.add_class::<PyNodeOutcome>()?;
    m.add_class::<PySession>()?;
    m.add_class::<PyFleet>()?;
    Ok(())
}
