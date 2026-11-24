//! PyO3 value types and conversion helpers for `helios-ops`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use helios_inspector_protocol::debugger::filesystem::EntryKind;
use helios_inspector_protocol::system::{
    inspect::{
        ComponentPublication, Entry as InspectEntry, KernelSnapshot, MemoryPressure,
        PublicationStatus, SnapshotResult, Value as InspectValue,
    },
    instances::Instance,
    programs::ExecResult,
    tracing::{Event as TraceEvent, Level as TraceLevel, Value as TraceValue},
};
use helios_ops::{
    Attenuation, BundleManifest, Child, DiagnosticBundle, GrantRight, IdentityProfile, OpsError,
    RemoteEntry, RemoteStat, SecurityMode, SessionOptions, Target, TargetStore, TargetUri,
};
use pyo3::IntoPyObjectExt as _;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use tokio::sync::Mutex;

use crate::error::{HeliosError, ops_err_to_py, target_err_to_py};

/// Build [`SessionOptions`] from optional Python keyword arguments.
pub(crate) fn build_session_options(
    timeout_secs: Option<f64>,
    scope: Option<String>,
    only: Option<Vec<String>>,
    identity: Option<String>,
) -> PyResult<SessionOptions> {
    let mut rights = BTreeSet::new();
    if let Some(items) = only {
        for raw in items {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let right = GrantRight::parse(trimmed).ok_or_else(|| {
                PyValueError::new_err(format!("unknown capability right `{trimmed}` in `only`"))
            })?;
            rights.insert(right);
        }
    }

    let profile = match identity {
        Some(name_or_path) => {
            let loaded = IdentityProfile::load(&name_or_path)
                .map_err(|err| ops_err_to_py(OpsError::from(err)))?;
            Some(loaded)
        }
        None => None,
    };

    let security = match profile.as_ref().and_then(|id| id.cert.clone()) {
        Some(cert) => SecurityMode::CapabilityTls { cert: Some(cert) },
        None => SecurityMode::Plain,
    };

    let timeout = match timeout_secs {
        Some(secs) if secs.is_finite() && secs > 0.0 => Duration::from_secs_f64(secs),
        Some(other) => {
            return Err(PyValueError::new_err(format!(
                "timeout_secs must be a positive finite number, got {other}"
            )));
        }
        None => helios_ops::session::DEFAULT_RPC_TIMEOUT,
    };

    Ok(SessionOptions {
        timeout,
        attenuation: Attenuation {
            scope,
            only: rights,
        },
        identity: profile,
        security,
    })
}

/// Parse a `Target | str` Python argument into a [`Target`].
pub(crate) fn extract_target_arg(
    target: &Bound<'_, PyAny>,
    targets_path: Option<&str>,
) -> PyResult<Target> {
    if let Ok(py_target) = target.extract::<PyRef<'_, PyTarget>>() {
        return Ok(py_target.inner.clone());
    }
    if let Ok(raw) = target.extract::<String>() {
        let store = match targets_path {
            Some(path) => TargetStore::load(path).map_err(target_err_to_py)?,
            None => TargetStore::load_default().map_err(target_err_to_py)?,
        };
        return store.resolve(Some(&raw)).map_err(target_err_to_py);
    }
    Err(PyValueError::new_err(
        "target must be a helios.Target, target name, or URI string",
    ))
}

/// Convert a [`helios_inspector_protocol::system::inspect::Value`] into a native Python object.
pub(crate) fn inspect_value_to_py(py: Python<'_>, value: &InspectValue) -> PyResult<Py<PyAny>> {
    match value {
        InspectValue::Boolean(v) => v.into_py_any(py),
        InspectValue::Signed64(v) => v.into_py_any(py),
        InspectValue::Unsigned64(v) => v.into_py_any(py),
        InspectValue::Float64(v) => v.into_py_any(py),
        InspectValue::Text(v) => v.into_py_any(py),
        InspectValue::Blob(v) => Ok(PyBytes::new(py, v).into_any().unbind()),
    }
}

/// Convert a tracing [`TraceValue`] into a native Python object.
pub(crate) fn trace_value_to_py(py: Python<'_>, value: &TraceValue) -> PyResult<Py<PyAny>> {
    match value {
        TraceValue::Boolean(v) => v.into_py_any(py),
        TraceValue::Signed64(v) => v.into_py_any(py),
        TraceValue::Unsigned64(v) => v.into_py_any(py),
        TraceValue::Float64(v) => v.into_py_any(py),
        TraceValue::Text(v) => v.into_py_any(py),
        TraceValue::Blob(v) => Ok(PyBytes::new(py, v).into_any().unbind()),
    }
}

/// Parse an optional tracing level string (`none`, `error`, `warn`, `info`, `debug`, `trace`).
pub(crate) fn parse_trace_level(level: Option<&str>) -> PyResult<Option<TraceLevel>> {
    match level.map(str::trim) {
        None | Some("") | Some("none") => Ok(None),
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "error" => Ok(Some(TraceLevel::Error)),
            "warn" | "warning" => Ok(Some(TraceLevel::Warn)),
            "info" => Ok(Some(TraceLevel::Info)),
            "debug" => Ok(Some(TraceLevel::Debug)),
            "trace" => Ok(Some(TraceLevel::Trace)),
            other => Err(PyValueError::new_err(format!(
                "unknown tracing level `{other}`; expected none|error|warn|info|debug|trace"
            ))),
        },
    }
}

/// Convert a decoded [`KernelSnapshot`] into a structured Python dictionary.
pub(crate) fn kernel_snapshot_to_py(py: Python<'_>, snap: &KernelSnapshot) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(py);
    dict.set_item("timestamp_ns", snap.timestamp)?;
    dict.set_item("uptime_ns", snap.uptime)?;
    dict.set_item("wall_clock_ns", snap.wall_clock)?;

    let procs = PyDict::new(py);
    procs.set_item("configured", snap.processors.configured)?;
    procs.set_item("online", snap.processors.online)?;
    procs.set_item("guest_isa_level", &snap.processors.guest_isa_level)?;
    procs.set_item("guest_isa_extras", &snap.processors.guest_isa_extras)?;
    let util_list = PyList::empty(py);
    for cpu in &snap.processors.utilization {
        let entry = PyDict::new(py);
        entry.set_item("id", cpu.id)?;
        entry.set_item("busy_permille", cpu.busy)?;
        util_list.append(entry)?;
    }
    procs.set_item("utilization", util_list)?;
    dict.set_item("processors", procs)?;

    let mem = PyDict::new(py);
    mem.set_item("total_bytes", snap.memory.total_bytes)?;
    mem.set_item("available_bytes", snap.memory.available_bytes)?;
    mem.set_item(
        "pressure",
        match snap.memory.pressure {
            MemoryPressure::Nominal => "nominal",
            MemoryPressure::Elevated => "elevated",
            MemoryPressure::High => "high",
            MemoryPressure::Critical => "critical",
        },
    )?;
    let nodes_list = PyList::empty(py);
    for node in &snap.memory.nodes {
        let entry = PyDict::new(py);
        entry.set_item("id", node.id)?;
        entry.set_item("total_bytes", node.total_bytes)?;
        entry.set_item("available_bytes", node.available_bytes)?;
        entry.set_item("off_node_allocations", node.off_node_allocations)?;
        nodes_list.append(entry)?;
    }
    mem.set_item("nodes", nodes_list)?;
    dict.set_item("memory", mem)?;

    Ok(dict.into_any().unbind())
}

/// Named Helios node target descriptor (`Target`).
#[pyclass(name = "Target", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyTarget {
    pub(crate) inner: Target,
}

#[pymethods]
impl PyTarget {
    #[new]
    #[pyo3(signature = (name, uri, *, labels=None, identity=None, default_scope=None))]
    fn new(
        name: String,
        uri: String,
        labels: Option<BTreeMap<String, String>>,
        identity: Option<String>,
        default_scope: Option<String>,
    ) -> PyResult<Self> {
        let mut target = Target::new(name, uri).map_err(target_err_to_py)?;
        if let Some(map) = labels {
            target.labels = map;
        }
        target.identity = identity;
        target.default_scope = default_scope;
        Ok(Self { inner: target })
    }

    /// Construct an ad-hoc target directly from a URI (`serial://`, `vsock://`, `helios://`, `tcp://`).
    #[staticmethod]
    fn from_uri(uri: String) -> PyResult<Self> {
        let target = Target::from_uri(uri).map_err(target_err_to_py)?;
        Ok(Self { inner: target })
    }

    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    #[getter]
    fn uri(&self) -> &str {
        &self.inner.uri
    }

    #[getter]
    fn labels(&self) -> BTreeMap<String, String> {
        self.inner.labels.clone()
    }

    #[getter]
    fn identity(&self) -> Option<&str> {
        self.inner.identity.as_deref()
    }

    #[getter]
    fn default_scope(&self) -> Option<&str> {
        self.inner.default_scope.as_deref()
    }

    /// Parsed transport scheme (`serial`, `vsock`, `helios`, or `tcp`).
    #[getter]
    fn scheme(&self) -> PyResult<&'static str> {
        let parsed = self.inner.parsed_uri().map_err(target_err_to_py)?;
        Ok(match parsed {
            TargetUri::Serial { .. } => "serial",
            TargetUri::Vsock { .. } => "vsock",
            TargetUri::Helios { tls: true, .. } => "helios",
            TargetUri::Helios { tls: false, .. } => "tcp",
        })
    }

    /// Return `True` if this target matches every `key=value` filter in `filters`.
    fn matches_labels(&self, filters: Vec<String>) -> PyResult<bool> {
        let parsed = helios_ops::target::parse_label_filters(&filters).map_err(target_err_to_py)?;
        Ok(self.inner.matches_labels(&parsed))
    }

    fn __repr__(&self) -> String {
        format!(
            "Target(name={:?}, uri={:?})",
            self.inner.name, self.inner.uri
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

/// Persistent `targets.toml` store.
#[pyclass(name = "TargetStore")]
pub(crate) struct PyTargetStore {
    inner: TargetStore,
}

#[pymethods]
impl PyTargetStore {
    /// Load a `targets.toml` file (or the default config path when `path` is `None`).
    #[staticmethod]
    #[pyo3(signature = (path=None))]
    fn load(path: Option<String>) -> PyResult<Self> {
        let inner = match path {
            Some(p) => TargetStore::load(p).map_err(target_err_to_py)?,
            None => TargetStore::load_default().map_err(target_err_to_py)?,
        };
        Ok(Self { inner })
    }

    #[getter]
    fn path(&self) -> String {
        self.inner.path().display().to_string()
    }

    #[getter]
    fn default_target_name(&self) -> Option<&str> {
        self.inner.default_target_name()
    }

    fn list(&self) -> Vec<PyTarget> {
        self.inner
            .list()
            .iter()
            .cloned()
            .map(|inner| PyTarget { inner })
            .collect()
    }

    #[pyo3(signature = (spec=None))]
    fn resolve(&self, spec: Option<&str>) -> PyResult<PyTarget> {
        let inner = self.inner.resolve(spec).map_err(target_err_to_py)?;
        Ok(PyTarget { inner })
    }

    fn select_by_labels(&self, filters: Vec<String>) -> PyResult<Vec<PyTarget>> {
        let matched = self
            .inner
            .select_by_labels(&filters)
            .map_err(target_err_to_py)?;
        Ok(matched
            .into_iter()
            .map(|inner| PyTarget { inner })
            .collect())
    }

    fn upsert(&mut self, target: &PyTarget) {
        self.inner.upsert(target.inner.clone());
    }

    fn set_default(&mut self, name: &str) -> PyResult<()> {
        self.inner.set_default(name).map_err(target_err_to_py)
    }

    fn remove(&mut self, name: &str) -> PyResult<PyTarget> {
        let inner = self.inner.remove(name).map_err(target_err_to_py)?;
        Ok(PyTarget { inner })
    }

    fn save(&self) -> PyResult<()> {
        self.inner.save().map_err(target_err_to_py)
    }
}

/// One entry in a Helios inspect snapshot.
#[pyclass(name = "InspectEntry", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyInspectEntry {
    pub(crate) inner: InspectEntry,
}

#[pymethods]
impl PyInspectEntry {
    #[getter]
    fn path(&self) -> &str {
        &self.inner.path
    }

    #[getter]
    fn value(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        inspect_value_to_py(py, &self.inner.value)
    }

    fn __repr__(&self) -> String {
        format!(
            "InspectEntry(path={:?}, value={:?})",
            self.inner.path, self.inner.value
        )
    }
}

/// Component inspect publication metadata.
#[pyclass(name = "ComponentPublication", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyComponentPublication {
    pub(crate) inner: ComponentPublication,
}

#[pymethods]
impl PyComponentPublication {
    #[getter]
    fn instance_id(&self) -> u64 {
        self.inner.instance_id
    }

    #[getter]
    fn instance_name(&self) -> &str {
        &self.inner.instance_name
    }

    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    #[getter]
    fn generation(&self) -> u64 {
        self.inner.generation
    }

    #[getter]
    fn status(&self) -> &'static str {
        match self.inner.status {
            PublicationStatus::Ok => "ok",
            PublicationStatus::Busy => "busy",
            PublicationStatus::Corrupt => "corrupt",
            PublicationStatus::SwappedOut => "swapped-out",
        }
    }
}

/// Snapshot returned by `Session.inspect`.
#[pyclass(name = "InspectSnapshot", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyInspectSnapshot {
    pub(crate) inner: SnapshotResult,
}

#[pymethods]
impl PyInspectSnapshot {
    #[getter]
    fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    #[getter]
    fn truncated(&self) -> bool {
        self.inner.truncated
    }

    #[getter]
    fn entries(&self) -> Vec<PyInspectEntry> {
        self.inner
            .entries
            .iter()
            .cloned()
            .map(|inner| PyInspectEntry { inner })
            .collect()
    }

    #[getter]
    fn publications(&self) -> Vec<PyComponentPublication> {
        self.inner
            .publications
            .iter()
            .cloned()
            .map(|inner| PyComponentPublication { inner })
            .collect()
    }

    /// Return a flat `dict[str, Any]` mapping inspect paths to decoded values.
    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        for entry in &self.inner.entries {
            dict.set_item(&entry.path, inspect_value_to_py(py, &entry.value)?)?;
        }
        Ok(dict.unbind())
    }

    fn __len__(&self) -> usize {
        self.inner.entries.len()
    }

    fn __repr__(&self) -> String {
        format!(
            "InspectSnapshot(timestamp={}, entries={}, truncated={})",
            self.inner.timestamp,
            self.inner.entries.len(),
            self.inner.truncated
        )
    }
}

/// Live guest instance descriptor returned by `Session.ps`.
#[pyclass(name = "Instance", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyInstance {
    pub(crate) inner: Instance,
}

#[pymethods]
impl PyInstance {
    #[getter]
    fn id(&self) -> u64 {
        self.inner.id
    }

    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    #[getter]
    fn started_at(&self) -> u64 {
        self.inner.started_at
    }

    #[getter]
    fn uptime_ns(&self) -> u64 {
        self.inner.uptime
    }

    #[getter]
    fn uptime_ms(&self) -> f64 {
        self.inner.uptime as f64 / 1_000_000.0
    }

    #[getter]
    fn memory_bytes(&self) -> u64 {
        self.inner.memory_bytes
    }

    #[getter]
    fn storage_bytes(&self) -> u64 {
        self.inner.storage_bytes
    }

    #[getter]
    fn cpu_busy(&self) -> u16 {
        self.inner.cpu_busy
    }

    fn __repr__(&self) -> String {
        format!(
            "Instance(id={}, name={:?}, memory_bytes={}, cpu_busy={})",
            self.inner.id, self.inner.name, self.inner.memory_bytes, self.inner.cpu_busy
        )
    }
}

/// Guest tracing event returned by `Session.trace_recent`.
#[pyclass(name = "TraceEvent", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyTraceEvent {
    pub(crate) inner: TraceEvent,
}

#[pymethods]
impl PyTraceEvent {
    #[getter]
    fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    #[getter]
    fn level(&self) -> &'static str {
        match self.inner.level {
            TraceLevel::Error => "error",
            TraceLevel::Warn => "warn",
            TraceLevel::Info => "info",
            TraceLevel::Debug => "debug",
            TraceLevel::Trace => "trace",
        }
    }

    #[getter]
    fn target(&self) -> &str {
        &self.inner.target
    }

    #[getter]
    fn fields(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        for field in &self.inner.fields {
            dict.set_item(&field.key, trace_value_to_py(py, &field.value)?)?;
        }
        Ok(dict.unbind())
    }

    fn __repr__(&self) -> String {
        format!(
            "TraceEvent(timestamp={}, level={:?}, target={:?})",
            self.inner.timestamp,
            self.level(),
            self.inner.target
        )
    }
}

/// Output of `Session.exec` or `Child.wait`.
#[pyclass(name = "ExecResult", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyExecResult {
    pub(crate) inner: ExecResult,
}

#[pymethods]
impl PyExecResult {
    #[getter]
    fn instance_id(&self) -> u64 {
        self.inner.instance_id
    }

    #[getter]
    fn exit_code(&self) -> u32 {
        self.inner.exit_code
    }

    #[getter]
    fn stdout<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.output.stdout)
    }

    #[getter]
    fn stderr<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.output.stderr)
    }

    #[getter]
    fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.inner.output.stdout).into_owned()
    }

    #[getter]
    fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.inner.output.stderr).into_owned()
    }

    fn __repr__(&self) -> String {
        format!(
            "ExecResult(instance_id={}, exit_code={}, stdout_bytes={}, stderr_bytes={})",
            self.inner.instance_id,
            self.inner.exit_code,
            self.inner.output.stdout.len(),
            self.inner.output.stderr.len()
        )
    }
}

/// Streaming handle to a remotely spawned program (`Session.spawn`).
#[pyclass(name = "Child")]
pub(crate) struct PyChild {
    child: Arc<Mutex<Option<Child>>>,
    stdout: async_channel::Receiver<Result<Vec<u8>, OpsError>>,
    stderr: async_channel::Receiver<Result<Vec<u8>, OpsError>>,
}

impl PyChild {
    pub(crate) fn new(child: Child) -> Self {
        let stdout = child.stdout.clone();
        let stderr = child.stderr.clone();
        Self {
            child: Arc::new(Mutex::new(Some(child))),
            stdout,
            stderr,
        }
    }
}

#[pymethods]
impl PyChild {
    /// Live instance ID if reported by the guest.
    #[getter]
    fn instance_id(&self) -> Option<u64> {
        self.child
            .try_lock()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(Child::instance_id))
    }

    /// Read the next stdout chunk asynchronously, returning `None` on EOF.
    fn read_stdout<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = self.stdout.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match rx.recv().await {
                Ok(Ok(bytes)) => {
                    Python::attach(|py| Ok(Some(PyBytes::new(py, &bytes).into_any().unbind())))
                }
                Ok(Err(err)) => Err(ops_err_to_py(err)),
                Err(_) => Ok(None),
            }
        })
    }

    /// Read the next stderr chunk asynchronously, returning `None` on EOF.
    fn read_stderr<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = self.stderr.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match rx.recv().await {
                Ok(Ok(bytes)) => {
                    Python::attach(|py| Ok(Some(PyBytes::new(py, &bytes).into_any().unbind())))
                }
                Ok(Err(err)) => Err(ops_err_to_py(err)),
                Err(_) => Ok(None),
            }
        })
    }

    /// Deliver a termination signal to this remote child instance.
    #[pyo3(signature = (sig="TERM"))]
    fn signal<'py>(&self, py: Python<'py>, sig: &str) -> PyResult<Bound<'py, PyAny>> {
        let holder = Arc::clone(&self.child);
        let sig = sig.to_owned();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = holder.lock().await;
            if let Some(child) = guard.as_ref() {
                child.signal(&sig).await.map_err(ops_err_to_py)?;
            }
            Ok(())
        })
    }

    /// Await completion of the spawned process and return its [`PyExecResult`].
    fn wait<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let holder = Arc::clone(&self.child);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let child = holder
                .lock()
                .await
                .take()
                .ok_or_else(|| HeliosError::new_err("Child.wait() has already been awaited"))?;
            let result = child.wait().await.map_err(ops_err_to_py)?;
            Ok(PyExecResult { inner: result })
        })
    }
}

/// Remote VFS directory entry returned by `Session.list_dir`.
#[pyclass(name = "RemoteEntry", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyRemoteEntry {
    pub(crate) inner: RemoteEntry,
}

#[pymethods]
impl PyRemoteEntry {
    #[getter]
    fn path(&self) -> &str {
        &self.inner.path
    }

    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    #[getter]
    fn kind(&self) -> &'static str {
        entry_kind_str(self.inner.kind)
    }

    fn __repr__(&self) -> String {
        format!(
            "RemoteEntry(path={:?}, kind={:?})",
            self.inner.path,
            self.kind()
        )
    }
}

/// Remote VFS metadata returned by `Session.stat`.
#[pyclass(name = "RemoteStat", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyRemoteStat {
    pub(crate) inner: RemoteStat,
}

#[pymethods]
impl PyRemoteStat {
    #[getter]
    fn path(&self) -> &str {
        &self.inner.path
    }

    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    #[getter]
    fn kind(&self) -> &'static str {
        entry_kind_str(self.inner.kind)
    }

    #[getter]
    fn size(&self) -> u64 {
        self.inner.size
    }

    fn __repr__(&self) -> String {
        format!(
            "RemoteStat(path={:?}, kind={:?}, size={})",
            self.inner.path,
            self.kind(),
            self.inner.size
        )
    }
}

fn entry_kind_str(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Directory => "directory",
        EntryKind::File => "file",
        EntryKind::Other => "other",
    }
}

/// Diagnostic bundle manifest metadata.
#[pyclass(name = "BundleManifest", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyBundleManifest {
    pub(crate) inner: BundleManifest,
}

#[pymethods]
impl PyBundleManifest {
    #[getter]
    fn target_name(&self) -> &str {
        &self.inner.target_name
    }

    #[getter]
    fn target_uri(&self) -> &str {
        &self.inner.target_uri
    }

    #[getter]
    fn collected_at_rfc3339(&self) -> &str {
        &self.inner.collected_at_rfc3339
    }

    #[getter]
    fn entries(&self) -> Vec<String> {
        self.inner.entries.clone()
    }
}

/// Collected `.tar.zst` diagnostic bundle.
#[pyclass(name = "DiagnosticBundle", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyDiagnosticBundle {
    pub(crate) inner: DiagnosticBundle,
}

#[pymethods]
impl PyDiagnosticBundle {
    #[getter]
    fn manifest(&self) -> PyBundleManifest {
        PyBundleManifest {
            inner: self.inner.manifest.clone(),
        }
    }

    #[getter]
    fn entries(&self, py: Python<'_>) -> PyResult<Vec<(String, Py<PyBytes>)>> {
        Ok(self
            .inner
            .entries
            .iter()
            .map(|e| (e.path.clone(), PyBytes::new(py, &e.bytes).unbind()))
            .collect())
    }

    /// Write this bundle to `path` as a `.tar.zst` archive asynchronously.
    fn write_tar_zst<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let bundle = self.inner.clone();
        let out = PathBuf::from(path);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let written = bundle
                .write_tar_zst(out)
                .await
                .map_err(|err| ops_err_to_py(OpsError::from(err)))?;
            Ok(written.display().to_string())
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "DiagnosticBundle(target={:?}, entries={})",
            self.inner.manifest.target_name,
            self.inner.entries.len()
        )
    }
}

/// Per-node result from a bounded-concurrency [`PyFleet`] fan-out.
#[pyclass(name = "NodeOutcome")]
pub(crate) struct PyNodeOutcome {
    pub(crate) target: PyTarget,
    pub(crate) elapsed_ms: f64,
    pub(crate) value: Option<Py<PyAny>>,
    pub(crate) error_message: Option<String>,
    pub(crate) error_kind: Option<OutcomeErrorKind>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum OutcomeErrorKind {
    AttenuationDenied,
    Transport,
    Rpc,
    Target,
    Other,
}

impl OutcomeErrorKind {
    pub(crate) fn from_ops_error(err: &OpsError) -> Self {
        match err {
            OpsError::AttenuationDenied { .. } => Self::AttenuationDenied,
            OpsError::Transport(_) => Self::Transport,
            OpsError::Target(_) => Self::Target,
            OpsError::TimedOut { .. }
            | OpsError::Rpc { .. }
            | OpsError::FilterRefused { .. }
            | OpsError::NoInstanceNamed { .. }
            | OpsError::KillRefused { .. }
            | OpsError::TraceTargetRefused { .. }
            | OpsError::ProfilingControlRefused { .. }
            | OpsError::InstructionProfileRefused { .. }
            | OpsError::RawProfileRefused { .. }
            | OpsError::ProcessorOfflineRefused { .. }
            | OpsError::ProcessorOnlineRefused { .. }
            | OpsError::ExecRefused { .. } => Self::Rpc,
            _ => Self::Other,
        }
    }

    fn to_py_err(self, message: String) -> PyErr {
        match self {
            Self::AttenuationDenied => crate::error::AttenuationDeniedError::new_err(message),
            Self::Transport => crate::error::TransportError::new_err(message),
            Self::Rpc => crate::error::RpcError::new_err(message),
            Self::Target => crate::error::TargetError::new_err(message),
            Self::Other => HeliosError::new_err(message),
        }
    }
}

#[pymethods]
impl PyNodeOutcome {
    #[getter]
    fn target(&self) -> PyTarget {
        self.target.clone()
    }

    #[getter]
    fn elapsed_ms(&self) -> f64 {
        self.elapsed_ms
    }

    #[getter]
    fn ok(&self) -> bool {
        self.error_message.is_none()
    }

    #[getter]
    fn value(&self, py: Python<'_>) -> Py<PyAny> {
        match &self.value {
            Some(v) => v.clone_ref(py),
            None => py.None(),
        }
    }

    #[getter]
    fn error(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Return the outcome value or raise the typed Helios exception for this node.
    fn unwrap(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        if let Some(msg) = &self.error_message {
            let kind = self.error_kind.unwrap_or(OutcomeErrorKind::Other);
            return Err(kind.to_py_err(msg.clone()));
        }
        Ok(match &self.value {
            Some(v) => v.clone_ref(py),
            None => py.None(),
        })
    }

    fn __repr__(&self) -> String {
        if let Some(err) = &self.error_message {
            format!(
                "NodeOutcome(target={:?}, ok=False, error={err:?})",
                self.target.inner.name
            )
        } else {
            format!(
                "NodeOutcome(target={:?}, ok=True, elapsed_ms={:.2})",
                self.target.inner.name, self.elapsed_ms
            )
        }
    }
}
