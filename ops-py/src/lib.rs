//! PyO3 native extension (`helios._native`) exposing the async `helios-ops` SDK to Python.

mod clients;
mod error;
mod fleet;
mod session;
mod types;

use pyo3::prelude::*;

use crate::clients::{
    PyBalanceReport, PyBtrfsClient, PyByteStream, PyComponentStatus, PyComponentsClient,
    PyContainer, PyDedupeOutcome, PyDefaultLinuxImage, PyFleetComponents, PyFleetOci, PyGrants,
    PyHvVm, PyInstructionProfile, PyLinuxClient, PyMicroVm, PyMountInfo, PyMountSpec,
    PyMountsClient, PyOciClient, PyPulledImage, PyQgroupInfo, PyQuotaStatus, PySamplingSession,
    PyScrubReport, PySubvolumeInfo, PySymbolizedInstructionProfile, PySymbolizedSample, PyVmClient,
    PyVmDisk, PyVmShare, PyVolumeDeviceInfo,
};
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
    m.add_class::<PyGrants>()?;
    m.add_class::<PyMountSpec>()?;
    m.add_class::<PyVmDisk>()?;
    m.add_class::<PyVmShare>()?;
    m.add_class::<PyByteStream>()?;
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
    m.add_class::<PyComponentStatus>()?;
    m.add_class::<PyComponentsClient>()?;
    m.add_class::<PyFleetComponents>()?;
    m.add_class::<PyPulledImage>()?;
    m.add_class::<PyOciClient>()?;
    m.add_class::<PyFleetOci>()?;
    m.add_class::<PyDefaultLinuxImage>()?;
    m.add_class::<PyContainer>()?;
    m.add_class::<PyLinuxClient>()?;
    m.add_class::<PyMountInfo>()?;
    m.add_class::<PyMountsClient>()?;
    m.add_class::<PySubvolumeInfo>()?;
    m.add_class::<PyDedupeOutcome>()?;
    m.add_class::<PyVolumeDeviceInfo>()?;
    m.add_class::<PyBalanceReport>()?;
    m.add_class::<PyScrubReport>()?;
    m.add_class::<PyQuotaStatus>()?;
    m.add_class::<PyQgroupInfo>()?;
    m.add_class::<PyBtrfsClient>()?;
    m.add_class::<PyHvVm>()?;
    m.add_class::<PyMicroVm>()?;
    m.add_class::<PyVmClient>()?;
    m.add_class::<PyInstructionProfile>()?;
    m.add_class::<PySymbolizedSample>()?;
    m.add_class::<PySymbolizedInstructionProfile>()?;
    m.add_class::<PySamplingSession>()?;
    m.add_class::<PySession>()?;
    m.add_class::<PyFleet>()?;
    Ok(())
}
