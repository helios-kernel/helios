//! Typed Python descriptors (`Grants`, `MountSpec`, `VmDisk`, `VmShare`),
//! streaming iterators (`ByteStream`), and async sub-clients (`components`,
//! `oci`, `linux`, `mounts`, `btrfs`, `vm`, `SamplingSession`) for `helios-ops-py`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use helios_oci::{Arch as OciArch, PulledImage};
use helios_ops::linux::{Container, ContainerBuilder, ContainerMount, ContainerMountSharing};
use helios_ops::{
    BtrfsClient, ComponentsClient, FleetComponents, FleetOci, MicroVm, MicroVmBuilder, MountInfo,
    MountsClient, NonFsGrant, NonFsGrants, OciClient, OpsError, ProcessGrants, PullOptions,
    SamplingSession, Session, SymbolizedInstructionProfile, SymbolizedSample, VmClient, VmDisk,
    VmShare,
};
use helios_wit_rpc::inspector::helios::system::{
    btrfs::{
        BalanceFilter, BalanceReport, DedupeOutcome, QgroupId, QgroupInfo, QgroupLimit,
        QuotaStatus, ResizeTarget, ScrubReport, SubvolumeInfo, VolumeDeviceInfo,
    },
    component_control::ComponentStatus,
    ipc::Endpoint,
    mounts::{MountRequest, MountSharing, MountSource},
    profiling::InstructionProfile,
    programs::{
        CapabilityGrant, ContainerCredentials, DefaultLinuxImage, DirectoryGrant, FilesystemRight,
    },
};
use helios_wit_rpc::inspector_snapshot::HvVm;
use pyo3::IntoPyObjectExt as _;
use pyo3::exceptions::{PyStopAsyncIteration, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use tokio::sync::Mutex;

use crate::error::{HeliosError, ops_err_to_py};
use crate::fleet::convert_outcome;
use crate::types::{PyChild, PyExecResult, PyNodeOutcome};

// ---------------------------------------------------------------------------
// Async byte stream iterator (`child.stdout`, `child.stderr`, `vm.console`)
// ---------------------------------------------------------------------------

/// `AsyncIterator[bytes]` backed by a bounded `async_channel::Receiver`.
#[pyclass(name = "ByteStream", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyByteStream {
    rx: async_channel::Receiver<Result<Vec<u8>, OpsError>>,
}

impl PyByteStream {
    pub(crate) fn new(rx: async_channel::Receiver<Result<Vec<u8>, OpsError>>) -> Self {
        Self { rx }
    }
}

#[pymethods]
impl PyByteStream {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = self.rx.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match rx.recv().await {
                Ok(Ok(bytes)) => {
                    Python::attach(|py| Ok(PyBytes::new(py, &bytes).into_any().unbind()))
                }
                Ok(Err(err)) => Err(ops_err_to_py(err)),
                Err(_) => Err(PyStopAsyncIteration::new_err(())),
            }
        })
    }

    /// Read the next chunk or return `None` on EOF.
    fn read_chunk<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = self.rx.clone();
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

    /// Drain all remaining chunks into a single `bytes` object.
    fn read_all<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = self.rx.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut buf = Vec::new();
            while let Ok(item) = rx.recv().await {
                let chunk = item.map_err(ops_err_to_py)?;
                buf.extend_from_slice(&chunk);
            }
            Python::attach(|py| Ok(PyBytes::new(py, &buf).into_any().unbind()))
        })
    }
}

// ---------------------------------------------------------------------------
// Typed descriptors: Grants, MountSpec, VmDisk, VmShare
// ---------------------------------------------------------------------------

fn parse_bool_or_strings(
    val: Option<&Bound<'_, PyAny>>,
    field: &str,
) -> PyResult<Option<Vec<String>>> {
    let Some(obj) = val else {
        return Ok(None);
    };
    if obj.is_none() {
        return Ok(None);
    }
    if let Ok(flag) = obj.extract::<bool>() {
        return Ok(flag.then(|| vec!["all".to_owned()]));
    }
    if let Ok(single) = obj.extract::<String>() {
        let trimmed = single.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        return Ok(Some(vec![trimmed.to_owned()]));
    }
    if let Ok(list) = obj.extract::<Vec<String>>() {
        return Ok((!list.is_empty()).then_some(list));
    }
    Err(PyValueError::new_err(format!(
        "`{field}` must be a bool, str, or sequence of strings"
    )))
}

fn parse_fs_mode(mode: &str) -> PyResult<Vec<FilesystemRight>> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "ro" | "r" => Ok(vec![FilesystemRight::Read]),
        "rx" => Ok(vec![FilesystemRight::Read, FilesystemRight::Execute]),
        "rw" => Ok(vec![
            FilesystemRight::Read,
            FilesystemRight::Write,
            FilesystemRight::MutateDirectory,
        ]),
        "rwx" => Ok(vec![
            FilesystemRight::Read,
            FilesystemRight::Write,
            FilesystemRight::MutateDirectory,
            FilesystemRight::Execute,
        ]),
        other => Err(PyValueError::new_err(format!(
            "unknown filesystem mode `{other}`; expected ro|rx|rw|rwx"
        ))),
    }
}

/// Typed capability grant descriptor for `Session.exec`, `Session.spawn`, and
/// `Session.linux.container`.
#[pyclass(name = "Grants", from_py_object)]
#[derive(Clone, Debug, Default)]
pub(crate) struct PyGrants {
    pub(crate) specs: Vec<String>,
    pub(crate) directories: Vec<(String, String, String)>,
}

impl PyGrants {
    pub(crate) fn to_capability_grants(&self) -> PyResult<Vec<CapabilityGrant<Endpoint>>> {
        let mut grants = Vec::with_capacity(self.specs.len() + self.directories.len());
        for (src, dst, mode) in &self.directories {
            let rights = parse_fs_mode(mode)?;
            grants.push(CapabilityGrant::Directory(DirectoryGrant {
                source_path: src.clone(),
                guest_name: dst.clone(),
                rights,
            }));
        }
        for spec in &self.specs {
            let parsed =
                helios_ops::session::parse_capability_grant(spec).map_err(ops_err_to_py)?;
            grants.push(parsed);
        }
        Ok(grants)
    }

    pub(crate) fn to_non_fs_grants(&self) -> PyResult<NonFsGrants> {
        if !self.directories.is_empty() {
            return Err(PyValueError::new_err(
                "container grants cannot include directory grants; pass filesystem mounts via `mounts=`",
            ));
        }
        let mut non_fs = NonFsGrants::new();
        for spec in &self.specs {
            let parsed =
                helios_ops::session::parse_capability_grant(spec).map_err(ops_err_to_py)?;
            match parsed {
                CapabilityGrant::Directory(_) => {
                    return Err(PyValueError::new_err(
                        "container grants cannot include directory grants; use `mounts=`",
                    ));
                }
                CapabilityGrant::Network(g) => non_fs = non_fs.grant(NonFsGrant::Network(g)),
                CapabilityGrant::Clock(g) => non_fs = non_fs.grant(NonFsGrant::Clock(g)),
                CapabilityGrant::Terminal(g) => non_fs = non_fs.grant(NonFsGrant::Terminal(g)),
                CapabilityGrant::Process(g) => non_fs = non_fs.grant(NonFsGrant::Process(g)),
                CapabilityGrant::Link(g) => non_fs = non_fs.grant(NonFsGrant::Link(g)),
                CapabilityGrant::Mount(g) => non_fs = non_fs.grant(NonFsGrant::Mount(g)),
                CapabilityGrant::Device(g) => non_fs = non_fs.grant(NonFsGrant::Device(g)),
                CapabilityGrant::Diagnostics(g) => {
                    non_fs = non_fs.grant(NonFsGrant::Diagnostics(g))
                }
                CapabilityGrant::InstanceControl(s) => {
                    non_fs = non_fs.grant(NonFsGrant::InstanceControl(s))
                }
                CapabilityGrant::Settings(g) => non_fs = non_fs.grant(NonFsGrant::Settings(g)),
                CapabilityGrant::Machine(g) => non_fs = non_fs.grant(NonFsGrant::Machine(g)),
                CapabilityGrant::Ipc(_) => {
                    return Err(PyValueError::new_err(
                        "IPC endpoint grants are not supported in `Grants`",
                    ));
                }
            }
        }
        Ok(non_fs)
    }

    pub(crate) fn to_process_grants(&self) -> PyResult<ProcessGrants> {
        let non_fs = PyGrants {
            specs: self.specs.clone(),
            directories: Vec::new(),
        }
        .to_non_fs_grants()?;
        let mut pg = ProcessGrants::from(non_fs);
        for (src, dst, mode) in &self.directories {
            pg = pg.directory(src.clone(), dst.clone(), parse_fs_mode(mode)?);
        }
        Ok(pg)
    }
}

#[pymethods]
impl PyGrants {
    #[new]
    #[pyo3(signature = (
        *,
        net=None,
        process=None,
        terminal=None,
        clock=None,
        link=None,
        mount=None,
        device=None,
        diagnostics=None,
        instance_control=None,
        settings=false,
        machine=None,
        virtualize=false,
        directories=None,
    ))]
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the typed Python Grants(...) keyword-only constructor surface"
    )]
    fn new(
        net: Option<&Bound<'_, PyAny>>,
        process: Option<&Bound<'_, PyAny>>,
        terminal: Option<&Bound<'_, PyAny>>,
        clock: Option<&Bound<'_, PyAny>>,
        link: Option<&Bound<'_, PyAny>>,
        mount: Option<&Bound<'_, PyAny>>,
        device: Option<&Bound<'_, PyAny>>,
        diagnostics: Option<Vec<String>>,
        instance_control: Option<String>,
        settings: bool,
        machine: Option<&Bound<'_, PyAny>>,
        virtualize: bool,
        directories: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let mut specs = Vec::new();
        if let Some(items) = parse_bool_or_strings(net, "net")? {
            specs.push(format!("net:{}", items.join(",")));
        }
        if let Some(items) = parse_bool_or_strings(process, "process")? {
            specs.push(format!("process:{}", items.join(",")));
        }
        if let Some(items) = parse_bool_or_strings(terminal, "terminal")? {
            specs.push(format!("terminal:{}", items.join(",")));
        }
        if let Some(items) = parse_bool_or_strings(clock, "clock")? {
            specs.push(format!("clock:{}", items.join(",")));
        }
        if let Some(items) = parse_bool_or_strings(link, "link")? {
            specs.push(format!("link:{}", items.join(",")));
        }
        if let Some(items) = parse_bool_or_strings(mount, "mount")? {
            specs.push(format!("mount:{}", items.join(",")));
        }
        if let Some(items) = parse_bool_or_strings(device, "device")? {
            specs.push(format!("device:{}", items.join(",")));
        }
        if let Some(diags) = diagnostics {
            specs.extend(diags);
        }
        if let Some(scope) = instance_control {
            specs.push(format!("instance-control:{scope}"));
        }
        if settings {
            specs.push("settings:write".to_owned());
        }
        if let Some(items) = parse_bool_or_strings(machine, "machine")? {
            specs.push(format!("machine:{}", items.join(",")));
        }
        if virtualize {
            specs.push("virtualize".to_owned());
        }

        let mut dir_list = Vec::new();
        if let Some(dirs) = directories
            && !dirs.is_none()
        {
            if let Ok(dict) = dirs.cast::<PyDict>() {
                for (k, v) in dict.iter() {
                    let path: String = k.extract()?;
                    if !path.starts_with('/') {
                        return Err(PyValueError::new_err(format!(
                            "directory grant path `{path}` must be absolute"
                        )));
                    }
                    let mode: String = v.extract()?;
                    let _ = parse_fs_mode(&mode)?;
                    dir_list.push((path.clone(), path, mode));
                }
            } else if let Ok(items) = dirs.extract::<Vec<String>>() {
                for item in items {
                    if let Some((path, mode)) = item.rsplit_once(':') {
                        if !path.starts_with('/') {
                            return Err(PyValueError::new_err(format!(
                                "directory grant path `{path}` must be absolute"
                            )));
                        }
                        let _ = parse_fs_mode(mode)?;
                        dir_list.push((path.to_owned(), path.to_owned(), mode.to_owned()));
                    } else {
                        if !item.starts_with('/') {
                            return Err(PyValueError::new_err(format!(
                                "directory grant path `{item}` must be absolute"
                            )));
                        }
                        dir_list.push((item.clone(), item, "ro".to_owned()));
                    }
                }
            } else {
                return Err(PyValueError::new_err(
                    "`directories` must be a dict[path, mode] or list[str]",
                ));
            }
        }

        let built = Self {
            specs,
            directories: dir_list,
        };
        // Validate all grant specs eagerly at construction time.
        let _ = built.to_capability_grants()?;
        Ok(built)
    }

    #[getter]
    fn specs(&self) -> Vec<String> {
        let mut all = self.specs.clone();
        for (src, _dst, mode) in &self.directories {
            all.push(format!("dir:{src}:{mode}"));
        }
        all
    }

    fn __repr__(&self) -> String {
        format!("Grants(specs={:?})", self.specs())
    }
}

/// Extract either a `Grants` object or `list[str]` into wire `CapabilityGrant`s.
pub(crate) fn extract_process_grants(
    grants: Option<&Bound<'_, PyAny>>,
) -> PyResult<Vec<CapabilityGrant<Endpoint>>> {
    let Some(obj) = grants else {
        return Ok(Vec::new());
    };
    if obj.is_none() {
        return Ok(Vec::new());
    }
    if let Ok(typed) = obj.extract::<PyRef<'_, PyGrants>>() {
        return Ok(typed.to_process_grants()?.into_capability_grants());
    }
    if let Ok(specs) = obj.extract::<Vec<String>>() {
        let mut out = Vec::with_capacity(specs.len());
        for spec in specs {
            out.push(helios_ops::session::parse_capability_grant(&spec).map_err(ops_err_to_py)?);
        }
        return Ok(out);
    }
    Err(PyValueError::new_err(
        "`grants` must be a `helios.Grants` instance or a list of grant specification strings",
    ))
}

/// Typed container bind-mount descriptor (`MountSpec(source, mode=..., sharing=...)`).
#[pyclass(name = "MountSpec", from_py_object)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PyMountSpec {
    pub(crate) source: String,
    pub(crate) target: Option<String>,
    pub(crate) mode: String,
    pub(crate) sharing: String,
}

impl PyMountSpec {
    pub(crate) fn to_container_mount(
        &self,
        target_override: Option<&str>,
    ) -> PyResult<ContainerMount> {
        let target = target_override.or(self.target.as_deref()).ok_or_else(|| {
            PyValueError::new_err(format!(
                "MountSpec(source={:?}) requires a target path (pass `target=` or use a dict)",
                self.source
            ))
        })?;
        let rights = parse_fs_mode(&self.mode)?;
        let sharing = match self.sharing.trim().to_ascii_lowercase().as_str() {
            "shared" => ContainerMountSharing::Shared,
            "private" => ContainerMountSharing::Private,
            "ephemeral-overlay" | "overlay" => ContainerMountSharing::EphemeralOverlay,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown mount sharing `{other}`; expected shared|private|ephemeral-overlay"
                )));
            }
        };
        Ok(ContainerMount {
            source_path: self.source.clone(),
            target_path: target.to_owned(),
            rights,
            sharing,
        })
    }
}

#[pymethods]
impl PyMountSpec {
    #[new]
    #[pyo3(signature = (source, target=None, *, mode="ro", sharing="shared"))]
    fn new(source: String, target: Option<String>, mode: &str, sharing: &str) -> PyResult<Self> {
        let _ = parse_fs_mode(mode)?;
        match sharing.trim().to_ascii_lowercase().as_str() {
            "shared" | "private" | "ephemeral-overlay" | "overlay" => {}
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown mount sharing `{other}`; expected shared|private|ephemeral-overlay"
                )));
            }
        }
        Ok(Self {
            source,
            target,
            mode: mode.to_owned(),
            sharing: sharing.to_owned(),
        })
    }

    #[getter]
    fn source(&self) -> &str {
        &self.source
    }

    #[getter]
    fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    #[getter]
    fn mode(&self) -> &str {
        &self.mode
    }

    #[getter]
    fn sharing(&self) -> &str {
        &self.sharing
    }

    fn __repr__(&self) -> String {
        format!(
            "MountSpec(source={:?}, target={:?}, mode={:?}, sharing={:?})",
            self.source, self.target, self.mode, self.sharing
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self == other
    }
}

/// Typed `virtio-blk` raw disk descriptor (`VmDisk(path, writable=...)`).
#[pyclass(name = "VmDisk", from_py_object)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PyVmDisk {
    pub(crate) inner: VmDisk,
}

#[pymethods]
impl PyVmDisk {
    #[new]
    #[pyo3(signature = (path, *, writable=false))]
    fn new(path: String, writable: bool) -> Self {
        Self {
            inner: VmDisk::new(path, writable),
        }
    }

    #[getter]
    fn path(&self) -> &str {
        &self.inner.path
    }

    #[getter]
    fn writable(&self) -> bool {
        self.inner.writable
    }

    fn __repr__(&self) -> String {
        format!(
            "VmDisk(path={:?}, writable={})",
            self.inner.path, self.inner.writable
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

/// Typed `virtio-fs` host directory share descriptor (`VmShare(path, tag=..., writable=...)`).
#[pyclass(name = "VmShare", from_py_object)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PyVmShare {
    pub(crate) inner: VmShare,
}

#[pymethods]
impl PyVmShare {
    #[new]
    #[pyo3(signature = (path, *, tag=None, writable=false))]
    fn new(path: String, tag: Option<String>, writable: bool) -> PyResult<Self> {
        let inner = match tag {
            Some(t) => VmShare::new(t, path, writable).map_err(ops_err_to_py)?,
            None => VmShare::from_path(path, writable).map_err(ops_err_to_py)?,
        };
        Ok(Self { inner })
    }

    #[getter]
    fn tag(&self) -> &str {
        &self.inner.tag
    }

    #[getter]
    fn path(&self) -> &str {
        &self.inner.path
    }

    #[getter]
    fn writable(&self) -> bool {
        self.inner.writable
    }

    fn __repr__(&self) -> String {
        format!(
            "VmShare(tag={:?}, path={:?}, writable={})",
            self.inner.tag, self.inner.path, self.inner.writable
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

// ---------------------------------------------------------------------------
// Component control (`s.components` and `fleet.components`)
// ---------------------------------------------------------------------------

#[pyclass(name = "ComponentStatus", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyComponentStatus {
    pub(crate) inner: ComponentStatus,
}

#[pymethods]
impl PyComponentStatus {
    #[getter]
    fn moniker(&self) -> &str {
        &self.inner.moniker
    }

    #[getter]
    fn program(&self) -> &str {
        &self.inner.program
    }

    #[getter]
    fn state(&self) -> &str {
        &self.inner.state
    }

    #[getter]
    fn instance_id(&self) -> Option<u64> {
        self.inner.instance_id
    }

    #[getter]
    fn restarts(&self) -> u64 {
        self.inner.restarts
    }

    fn __repr__(&self) -> String {
        format!(
            "ComponentStatus(moniker={:?}, state={:?}, instance_id={:?}, restarts={})",
            self.inner.moniker, self.inner.state, self.inner.instance_id, self.inner.restarts
        )
    }
}

#[pyclass(name = "ComponentsClient", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyComponentsClient {
    inner: ComponentsClient,
}

impl PyComponentsClient {
    pub(crate) fn new(session: Session) -> Self {
        Self {
            inner: session.components(),
        }
    }
}

#[pymethods]
impl PyComponentsClient {
    fn list<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let items = client.list().await.map_err(ops_err_to_py)?;
            Ok(items
                .into_iter()
                .map(|inner| PyComponentStatus { inner })
                .collect::<Vec<_>>())
        })
    }

    fn status<'py>(&self, py: Python<'py>, moniker: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let status = client.status(&moniker).await.map_err(ops_err_to_py)?;
            Ok(PyComponentStatus { inner: status })
        })
    }

    fn start<'py>(&self, py: Python<'py>, moniker: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let status = client.start(&moniker).await.map_err(ops_err_to_py)?;
            Ok(PyComponentStatus { inner: status })
        })
    }

    fn stop<'py>(&self, py: Python<'py>, moniker: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client.stop(&moniker).await.map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    fn restart<'py>(&self, py: Python<'py>, moniker: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let status = client.restart(&moniker).await.map_err(ops_err_to_py)?;
            Ok(PyComponentStatus { inner: status })
        })
    }

    #[pyo3(signature = (parent_moniker, *, guest_dir=None, subtree_name=None, manifests=None))]
    fn mount_dynamic<'py>(
        &self,
        py: Python<'py>,
        parent_moniker: String,
        guest_dir: Option<String>,
        subtree_name: Option<String>,
        manifests: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let source = parse_dynamic_subtree_source(guest_dir, subtree_name, manifests)?;
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .mount_dynamic(&parent_moniker, source)
                .await
                .map_err(ops_err_to_py)
        })
    }

    fn unmount_dynamic<'py>(
        &self,
        py: Python<'py>,
        moniker: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .unmount_dynamic(&moniker)
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }
}

fn parse_dynamic_subtree_source(
    guest_dir: Option<String>,
    subtree_name: Option<String>,
    manifests: Option<&Bound<'_, PyAny>>,
) -> PyResult<helios_ops::DynamicSubtreeSource> {
    let has_manifests = manifests.is_some_and(|obj| !obj.is_none());
    match (guest_dir, has_manifests) {
        (Some(path), false) => {
            let name = match subtree_name {
                Some(explicit) if !explicit.trim().is_empty() => explicit.trim().to_owned(),
                _ => std::path::Path::new(&path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        PyValueError::new_err(format!(
                            "cannot infer `subtree_name` from guest_dir `{path}`; pass `subtree_name=`"
                        ))
                    })?
                    .to_owned(),
            };
            Ok(helios_ops::DynamicSubtreeSource::GuestDir(
                helios_ops::DynamicDirSource {
                    subtree_name: name,
                    path,
                },
            ))
        }
        (None, true) => {
            let obj = manifests.expect("checked Some");
            let mut pairs = Vec::new();
            if let Ok(dict) = obj.cast::<PyDict>() {
                for (k, v) in dict.iter() {
                    let rel: String = k.extract()?;
                    let toml: String = v.extract()?;
                    pairs.push((rel, toml));
                }
            } else if let Ok(list) = obj.extract::<Vec<(String, String)>>() {
                pairs = list;
            } else {
                return Err(PyValueError::new_err(
                    "`manifests` must be a dict[str, str] or list[tuple[str, str]]",
                ));
            }
            if pairs.is_empty() {
                return Err(PyValueError::new_err("`manifests` must not be empty"));
            }
            Ok(helios_ops::DynamicSubtreeSource::Manifests(pairs))
        }
        (Some(_), true) => Err(PyValueError::new_err(
            "pass either `guest_dir=` or `manifests=`, not both",
        )),
        (None, false) => Err(PyValueError::new_err(
            "mount_dynamic() requires either `guest_dir=` or `manifests=`",
        )),
    }
}

#[pyclass(name = "FleetComponents", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyFleetComponents {
    pub(crate) inner: FleetComponents,
}

#[pymethods]
impl PyFleetComponents {
    fn list<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let fc = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fc.list().await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| {
                        convert_outcome(py, outcome, |py, list| {
                            let wrapped: Vec<PyComponentStatus> = list
                                .into_iter()
                                .map(|inner| PyComponentStatus { inner })
                                .collect();
                            wrapped.into_py_any(py)
                        })
                    })
                    .collect::<PyResult<Vec<PyNodeOutcome>>>()
            })
        })
    }

    fn status<'py>(&self, py: Python<'py>, moniker: String) -> PyResult<Bound<'py, PyAny>> {
        let fc = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fc.status(moniker).await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| {
                        convert_outcome(py, outcome, |py, st| {
                            PyComponentStatus { inner: st }.into_py_any(py)
                        })
                    })
                    .collect::<PyResult<Vec<PyNodeOutcome>>>()
            })
        })
    }

    fn start<'py>(&self, py: Python<'py>, moniker: String) -> PyResult<Bound<'py, PyAny>> {
        let fc = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fc.start(moniker).await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| {
                        convert_outcome(py, outcome, |py, st| {
                            PyComponentStatus { inner: st }.into_py_any(py)
                        })
                    })
                    .collect::<PyResult<Vec<PyNodeOutcome>>>()
            })
        })
    }

    fn stop<'py>(&self, py: Python<'py>, moniker: String) -> PyResult<Bound<'py, PyAny>> {
        let fc = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fc.stop(moniker).await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| convert_outcome(py, outcome, |py, ()| Ok(py.None())))
                    .collect::<PyResult<Vec<PyNodeOutcome>>>()
            })
        })
    }

    fn restart<'py>(&self, py: Python<'py>, moniker: String) -> PyResult<Bound<'py, PyAny>> {
        let fc = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fc.restart(moniker).await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| {
                        convert_outcome(py, outcome, |py, st| {
                            PyComponentStatus { inner: st }.into_py_any(py)
                        })
                    })
                    .collect::<PyResult<Vec<PyNodeOutcome>>>()
            })
        })
    }

    #[pyo3(signature = (parent_moniker, *, guest_dir=None, subtree_name=None, manifests=None))]
    fn mount_dynamic<'py>(
        &self,
        py: Python<'py>,
        parent_moniker: String,
        guest_dir: Option<String>,
        subtree_name: Option<String>,
        manifests: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let source = parse_dynamic_subtree_source(guest_dir, subtree_name, manifests)?;
        let fc = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fc.mount_dynamic(parent_moniker, source).await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| convert_outcome(py, outcome, |py, m| m.into_py_any(py)))
                    .collect::<PyResult<Vec<PyNodeOutcome>>>()
            })
        })
    }

    fn unmount_dynamic<'py>(
        &self,
        py: Python<'py>,
        moniker: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let fc = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fc.unmount_dynamic(moniker).await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| convert_outcome(py, outcome, |py, ()| Ok(py.None())))
                    .collect::<PyResult<Vec<PyNodeOutcome>>>()
            })
        })
    }
}

// ---------------------------------------------------------------------------
// OCI image management (`s.oci` and `fleet.oci`)
// ---------------------------------------------------------------------------

#[pyclass(name = "PulledImage", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyPulledImage {
    pub(crate) inner: PulledImage,
}

#[pymethods]
impl PyPulledImage {
    #[getter]
    fn reference(&self) -> String {
        self.inner.reference.to_string()
    }

    #[getter]
    fn manifest_digest(&self) -> String {
        self.inner.manifest_digest.to_string()
    }

    #[getter]
    fn arch(&self) -> &'static str {
        self.inner.arch.oci_arch()
    }

    #[getter]
    fn rootfs_path(&self) -> String {
        self.inner.rootfs_path.display().to_string()
    }

    #[getter]
    fn btrfs_backed(&self) -> bool {
        self.inner.btrfs_backed
    }

    #[getter]
    fn layer_chain_ids(&self) -> Vec<String> {
        self.inner
            .layer_chain_ids
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[getter]
    fn entrypoint(&self) -> Vec<String> {
        self.inner.config.config.entrypoint.clone()
    }

    #[getter]
    fn cmd(&self) -> Vec<String> {
        self.inner.config.config.cmd.clone()
    }

    #[getter]
    fn env(&self) -> Vec<(String, String)> {
        self.inner.config.config.env_pairs()
    }

    #[getter]
    fn working_dir(&self) -> Option<&str> {
        self.inner.config.config.effective_working_dir()
    }

    #[getter]
    fn user(&self) -> Option<&str> {
        self.inner.config.config.user.as_deref()
    }

    fn __repr__(&self) -> String {
        format!(
            "PulledImage(reference={:?}, arch={:?}, layers={}, rootfs={:?})",
            self.reference(),
            self.arch(),
            self.inner.layer_chain_ids.len(),
            self.rootfs_path()
        )
    }
}

fn parse_oci_arch(raw: Option<&str>) -> PyResult<Option<OciArch>> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some("x86_64" | "x86-64" | "amd64") => Ok(Some(OciArch::X86_64)),
        Some("aarch64" | "arm64") => Ok(Some(OciArch::Aarch64)),
        Some(other) => Err(PyValueError::new_err(format!(
            "unsupported OCI architecture `{other}`; expected x86-64|amd64|aarch64|arm64"
        ))),
    }
}

#[pyclass(name = "OciClient", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyOciClient {
    inner: OciClient,
}

impl PyOciClient {
    pub(crate) fn new(session: Session) -> Self {
        Self {
            inner: session.oci(),
        }
    }
}

#[pymethods]
impl PyOciClient {
    #[getter]
    fn store_root(&self) -> &str {
        self.inner.store_root()
    }

    #[pyo3(signature = (reference, *, arch=None))]
    fn pull<'py>(
        &self,
        py: Python<'py>,
        reference: String,
        arch: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        let parsed_arch = parse_oci_arch(arch)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let img = client
                .pull_with_options(
                    &reference,
                    PullOptions {
                        arch: parsed_arch,
                        ..PullOptions::default()
                    },
                )
                .await
                .map_err(ops_err_to_py)?;
            Ok(PyPulledImage { inner: img })
        })
    }

    fn list<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let imgs = client.list().await.map_err(ops_err_to_py)?;
            Ok(imgs
                .into_iter()
                .map(|inner| PyPulledImage { inner })
                .collect::<Vec<_>>())
        })
    }

    fn inspect<'py>(&self, py: Python<'py>, reference: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let img = client.inspect(&reference).await.map_err(ops_err_to_py)?;
            Ok(PyPulledImage { inner: img })
        })
    }

    fn remove<'py>(&self, py: Python<'py>, reference: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let img = client.remove(&reference).await.map_err(ops_err_to_py)?;
            Ok(PyPulledImage { inner: img })
        })
    }
}

#[pyclass(name = "FleetOci", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyFleetOci {
    pub(crate) inner: FleetOci,
}

#[pymethods]
impl PyFleetOci {
    #[pyo3(signature = (reference, *, arch=None))]
    fn pull<'py>(
        &self,
        py: Python<'py>,
        reference: String,
        arch: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let fo = self.inner.clone();
        let parsed_arch = parse_oci_arch(arch)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fo
                .pull_with_options(
                    reference,
                    PullOptions {
                        arch: parsed_arch,
                        ..PullOptions::default()
                    },
                )
                .await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| {
                        convert_outcome(py, outcome, |py, img| {
                            PyPulledImage { inner: img }.into_py_any(py)
                        })
                    })
                    .collect::<PyResult<Vec<PyNodeOutcome>>>()
            })
        })
    }

    fn list<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let fo = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fo.list().await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| {
                        convert_outcome(py, outcome, |py, imgs| {
                            let wrapped: Vec<PyPulledImage> = imgs
                                .into_iter()
                                .map(|inner| PyPulledImage { inner })
                                .collect();
                            wrapped.into_py_any(py)
                        })
                    })
                    .collect::<PyResult<Vec<PyNodeOutcome>>>()
            })
        })
    }

    fn inspect<'py>(&self, py: Python<'py>, reference: String) -> PyResult<Bound<'py, PyAny>> {
        let fo = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fo.inspect(reference).await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| {
                        convert_outcome(py, outcome, |py, img| {
                            PyPulledImage { inner: img }.into_py_any(py)
                        })
                    })
                    .collect::<PyResult<Vec<PyNodeOutcome>>>()
            })
        })
    }

    fn remove<'py>(&self, py: Python<'py>, reference: String) -> PyResult<Bound<'py, PyAny>> {
        let fo = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fo.remove(reference).await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| {
                        convert_outcome(py, outcome, |py, img| {
                            PyPulledImage { inner: img }.into_py_any(py)
                        })
                    })
                    .collect::<PyResult<Vec<PyNodeOutcome>>>()
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Linux client (`s.linux`: default_image, set_default_image, container)
// ---------------------------------------------------------------------------

#[pyclass(name = "DefaultLinuxImage", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyDefaultLinuxImage {
    pub(crate) inner: DefaultLinuxImage,
}

#[pymethods]
impl PyDefaultLinuxImage {
    #[new]
    #[pyo3(signature = (root_path, *, env=None, uid=None, gid=None, supplementary_groups=None))]
    fn new(
        root_path: String,
        env: Option<BTreeMap<String, String>>,
        uid: Option<u32>,
        gid: Option<u32>,
        supplementary_groups: Option<Vec<u32>>,
    ) -> Self {
        let credentials = match (uid, gid, supplementary_groups) {
            (None, None, None) => None,
            (u, g, groups) => Some(ContainerCredentials {
                uid: u.unwrap_or(0),
                gid: g.unwrap_or(0),
                supplementary_groups: groups.unwrap_or_default(),
            }),
        };
        Self {
            inner: DefaultLinuxImage {
                root_path,
                env: env.unwrap_or_default().into_iter().collect(),
                credentials,
            },
        }
    }

    #[getter]
    fn root_path(&self) -> &str {
        &self.inner.root_path
    }

    #[getter]
    fn env(&self) -> Vec<(String, String)> {
        self.inner.env.clone()
    }

    #[getter]
    fn uid(&self) -> Option<u32> {
        self.inner.credentials.as_ref().map(|c| c.uid)
    }

    #[getter]
    fn gid(&self) -> Option<u32> {
        self.inner.credentials.as_ref().map(|c| c.gid)
    }

    #[getter]
    fn supplementary_groups(&self) -> Vec<u32> {
        self.inner
            .credentials
            .as_ref()
            .map_or_else(Vec::new, |c| c.supplementary_groups.clone())
    }

    fn __repr__(&self) -> String {
        format!(
            "DefaultLinuxImage(root_path={:?}, env_vars={})",
            self.inner.root_path,
            self.inner.env.len()
        )
    }
}

/// Helper for parsing `(argv_or_path, args)` in `Session`/`Container` `exec`/`spawn`.
pub(crate) fn extract_path_and_args(
    path_or_argv: &Bound<'_, PyAny>,
    args: Option<Vec<String>>,
) -> PyResult<(String, Vec<String>)> {
    if let Ok(path) = path_or_argv.extract::<String>() {
        return Ok((path, args.unwrap_or_default()));
    }
    if let Ok(argv) = path_or_argv.extract::<Vec<String>>() {
        let mut iter = argv.into_iter();
        let Some(first) = iter.next() else {
            return Err(PyValueError::new_err("command argv list must not be empty"));
        };
        let mut combined: Vec<String> = iter.collect();
        if let Some(extra) = args {
            combined.extend(extra);
        }
        return Ok((first, combined));
    }
    Err(PyValueError::new_err(
        "command must be a path string or a non-empty list[str] argv",
    ))
}

/// Live Linux container handle implementing `AsyncContextManager`.
#[pyclass(name = "Container")]
pub(crate) struct PyContainer {
    inner: Arc<Mutex<Option<Container>>>,
    hostname: String,
    root_path: String,
}

impl PyContainer {
    fn from_ops(container: Container) -> Self {
        let hostname = container.config().hostname.clone();
        let root_path = container.config().root.source_path.clone();
        Self {
            inner: Arc::new(Mutex::new(Some(container))),
            hostname,
            root_path,
        }
    }
}

#[pymethods]
impl PyContainer {
    #[getter]
    fn hostname(&self) -> &str {
        &self.hostname
    }

    #[getter]
    fn root_path(&self) -> &str {
        &self.root_path
    }

    fn __aenter__<'py>(slf: Py<Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(slf) })
    }

    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: Option<&Bound<'py, PyAny>>,
        _exc_val: Option<&Bound<'py, PyAny>>,
        _exc_tb: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let holder = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let ctr = holder.lock().await.take();
            if let Some(c) = ctr {
                c.close();
            }
            Ok(false)
        })
    }

    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let holder = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let ctr = holder.lock().await.take();
            if let Some(c) = ctr {
                c.close();
            }
            Ok(())
        })
    }

    #[pyo3(signature = (command, args=None, *, env=None, cwd=None, stdin=None))]
    fn exec<'py>(
        &self,
        py: Python<'py>,
        command: &Bound<'py, PyAny>,
        args: Option<Vec<String>>,
        env: Option<BTreeMap<String, String>>,
        cwd: Option<String>,
        stdin: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (path, argv) = extract_path_and_args(command, args)?;
        let extra_env: Vec<(String, String)> = env.unwrap_or_default().into_iter().collect();
        let stdin_bytes = stdin.unwrap_or_default();
        let holder = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = holder.lock().await;
            let ctr = guard
                .as_ref()
                .ok_or_else(|| HeliosError::new_err("Container has already been closed"))?;
            let res = ctr
                .exec_with_options(&path, &argv, &extra_env, cwd.as_deref(), stdin_bytes)
                .await
                .map_err(ops_err_to_py)?;
            Ok(PyExecResult { inner: res })
        })
    }

    #[pyo3(signature = (command, args=None, *, env=None, cwd=None, stdin=None))]
    fn spawn<'py>(
        &self,
        py: Python<'py>,
        command: &Bound<'py, PyAny>,
        args: Option<Vec<String>>,
        env: Option<BTreeMap<String, String>>,
        cwd: Option<String>,
        stdin: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (path, argv) = extract_path_and_args(command, args)?;
        let extra_env: Vec<(String, String)> = env.unwrap_or_default().into_iter().collect();
        let stdin_bytes = stdin.unwrap_or_default();
        let holder = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = holder.lock().await;
            let ctr = guard
                .as_ref()
                .ok_or_else(|| HeliosError::new_err("Container has already been closed"))?;
            let child = ctr
                .spawn_with_options(&path, &argv, &extra_env, cwd.as_deref(), stdin_bytes)
                .await
                .map_err(ops_err_to_py)?;
            Ok(PyChild::new(child))
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "Container(hostname={:?}, root_path={:?})",
            self.hostname, self.root_path
        )
    }
}

#[pyclass(name = "LinuxClient", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyLinuxClient {
    session: Session,
}

impl PyLinuxClient {
    pub(crate) fn new(session: Session) -> Self {
        Self { session }
    }
}

#[pymethods]
impl PyLinuxClient {
    /// Query the session's current inherited default Linux root image.
    fn default_image<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let session = self.session.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let img = session.get_default_image().await.map_err(ops_err_to_py)?;
            Ok(img.map(|inner| PyDefaultLinuxImage { inner }))
        })
    }

    /// Set or clear (`None`) the session's inherited default Linux root image.
    #[pyo3(signature = (image=None, *, env=None, uid=None, gid=None, supplementary_groups=None))]
    fn set_default_image<'py>(
        &self,
        py: Python<'py>,
        image: Option<&Bound<'py, PyAny>>,
        env: Option<BTreeMap<String, String>>,
        uid: Option<u32>,
        gid: Option<u32>,
        supplementary_groups: Option<Vec<u32>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        enum Input {
            Clear,
            Wire(DefaultLinuxImage),
            Pulled(Box<PulledImage>),
            RefOrPath(String),
        }

        let input = match image {
            None => Input::Clear,
            Some(obj) if obj.is_none() => Input::Clear,
            Some(obj) => {
                if let Ok(default_img) = obj.extract::<PyRef<'_, PyDefaultLinuxImage>>() {
                    Input::Wire(default_img.inner.clone())
                } else if let Ok(pulled) = obj.extract::<PyRef<'_, PyPulledImage>>() {
                    Input::Pulled(Box::new(pulled.inner.clone()))
                } else if let Ok(raw) = obj.extract::<String>() {
                    Input::RefOrPath(raw)
                } else {
                    return Err(PyValueError::new_err(
                        "`image` must be None, str (path or OCI ref), PulledImage, or DefaultLinuxImage",
                    ));
                }
            }
        };

        let env_pairs: Vec<(String, String)> = env.unwrap_or_default().into_iter().collect();
        let creds = match (uid, gid, supplementary_groups) {
            (None, None, None) => None,
            (u, g, supp) => Some(ContainerCredentials {
                uid: u.unwrap_or(0),
                gid: g.unwrap_or(0),
                supplementary_groups: supp.unwrap_or_default(),
            }),
        };

        let session = self.session.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match input {
                Input::Clear => session
                    .set_default_image(None)
                    .await
                    .map_err(ops_err_to_py)?,
                Input::Wire(mut img) => {
                    img.env.extend(env_pairs);
                    if creds.is_some() {
                        img.credentials = creds;
                    }
                    session
                        .set_default_image(Some(img))
                        .await
                        .map_err(ops_err_to_py)?;
                }
                Input::Pulled(pulled) => {
                    let mut img = helios_ops::linux::default_linux_image_from_oci(&pulled)
                        .map_err(|err| ops_err_to_py(OpsError::from(err)))?;
                    img.env.extend(env_pairs);
                    if creds.is_some() {
                        img.credentials = creds;
                    }
                    session
                        .set_default_image(Some(img))
                        .await
                        .map_err(ops_err_to_py)?;
                }
                Input::RefOrPath(raw) => {
                    if raw.starts_with('/') {
                        session
                            .set_default_image(Some(DefaultLinuxImage {
                                root_path: raw,
                                env: env_pairs,
                                credentials: creds,
                            }))
                            .await
                            .map_err(ops_err_to_py)?;
                    } else {
                        let pulled = session.oci().inspect(&raw).await.map_err(ops_err_to_py)?;
                        let mut img = helios_ops::linux::default_linux_image_from_oci(&pulled)
                            .map_err(|err| ops_err_to_py(OpsError::from(err)))?;
                        img.env.extend(env_pairs);
                        if creds.is_some() {
                            img.credentials = creds;
                        }
                        session
                            .set_default_image(Some(img))
                            .await
                            .map_err(ops_err_to_py)?;
                    }
                }
            }
            Ok(())
        })
    }

    /// Create an explicit multi-binary Linux [`Container`] (`async with await s.linux.container(...) as c:`).
    #[pyo3(signature = (
        image=None,
        *,
        root=None,
        hostname=None,
        domainname=None,
        mounts=None,
        grants=None,
        env=None,
        cwd=None,
        uid=None,
        gid=None,
    ))]
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the typed Python s.linux.container(...) keyword-only API"
    )]
    fn container<'py>(
        &self,
        py: Python<'py>,
        image: Option<&Bound<'py, PyAny>>,
        root: Option<String>,
        hostname: Option<String>,
        domainname: Option<String>,
        mounts: Option<&Bound<'py, PyAny>>,
        grants: Option<&Bound<'py, PyAny>>,
        env: Option<BTreeMap<String, String>>,
        cwd: Option<String>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
        enum RootSource {
            Pulled(Box<PulledImage>),
            OciRef(String),
            Path(String),
        }

        let root_source = if let Some(img_obj) = image
            && !img_obj.is_none()
        {
            if let Ok(pulled) = img_obj.extract::<PyRef<'_, PyPulledImage>>() {
                RootSource::Pulled(Box::new(pulled.inner.clone()))
            } else if let Ok(raw) = img_obj.extract::<String>() {
                if raw.starts_with('/') {
                    RootSource::Path(raw)
                } else {
                    RootSource::OciRef(raw)
                }
            } else {
                return Err(PyValueError::new_err(
                    "`image` must be a PulledImage, OCI reference string, or rootfs path",
                ));
            }
        } else if let Some(root_path) = root {
            RootSource::Path(root_path)
        } else {
            return Err(PyValueError::new_err(
                "container() requires either `image=` or `root=`",
            ));
        };

        let mut parsed_mounts = Vec::new();
        if let Some(m_obj) = mounts
            && !m_obj.is_none()
        {
            if let Ok(dict) = m_obj.cast::<PyDict>() {
                for (k, v) in dict.iter() {
                    let target: String = k.extract()?;
                    if let Ok(spec) = v.extract::<PyRef<'_, PyMountSpec>>() {
                        parsed_mounts.push(spec.to_container_mount(Some(&target))?);
                    } else if let Ok(src) = v.extract::<String>() {
                        parsed_mounts.push(ContainerMount {
                            source_path: src,
                            target_path: target,
                            rights: vec![FilesystemRight::Read],
                            sharing: ContainerMountSharing::Shared,
                        });
                    } else {
                        return Err(PyValueError::new_err(
                            "`mounts` dict values must be `MountSpec` or source path strings",
                        ));
                    }
                }
            } else if let Ok(list) = m_obj.cast::<PyList>() {
                for item in list.iter() {
                    let spec: PyRef<'_, PyMountSpec> = item.extract()?;
                    parsed_mounts.push(spec.to_container_mount(None)?);
                }
            } else {
                return Err(PyValueError::new_err(
                    "`mounts` must be a dict[target, MountSpec] or list[MountSpec]",
                ));
            }
        }

        let non_fs = if let Some(g_obj) = grants
            && !g_obj.is_none()
        {
            let typed: PyRef<'_, PyGrants> = g_obj.extract().map_err(|_| {
                PyValueError::new_err("container `grants` must be a `helios.Grants` instance")
            })?;
            typed.to_non_fs_grants()?
        } else {
            NonFsGrants::new()
        };

        let env_pairs: Vec<(String, String)> = env.unwrap_or_default().into_iter().collect();
        let session = self.session.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut builder = match root_source {
                RootSource::Pulled(img) => ContainerBuilder::from_image(&img)
                    .map_err(|err| ops_err_to_py(OpsError::from(err)))?,
                RootSource::OciRef(reference) => {
                    let img = session
                        .oci()
                        .inspect(&reference)
                        .await
                        .map_err(ops_err_to_py)?;
                    ContainerBuilder::from_image(&img)
                        .map_err(|err| ops_err_to_py(OpsError::from(err)))?
                }
                RootSource::Path(path) => ContainerBuilder::ephemeral(path),
            };
            if let Some(h) = hostname {
                builder = builder.hostname(h);
            }
            if let Some(d) = domainname {
                builder = builder.domainname(d);
            }
            if let Some(dir) = cwd {
                builder = builder.working_dir(dir);
            }
            if uid.is_some() || gid.is_some() {
                builder = builder.user(uid.unwrap_or(0), gid.unwrap_or(0));
            }
            for (k, v) in env_pairs {
                builder = builder.env(k, v);
            }
            for m in parsed_mounts {
                builder = builder.mount(m);
            }
            builder = builder.grants(non_fs);
            let container = builder.create(session).await.map_err(ops_err_to_py)?;
            Ok(PyContainer::from_ops(container))
        })
    }
}

// ---------------------------------------------------------------------------
// Storage clients (`s.mounts` and `s.btrfs`)
// ---------------------------------------------------------------------------

#[pyclass(name = "MountInfo", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyMountInfo {
    pub(crate) inner: MountInfo,
}

#[pymethods]
impl PyMountInfo {
    #[getter]
    fn path(&self) -> &str {
        &self.inner.path
    }

    #[getter]
    fn source(&self) -> &str {
        &self.inner.source
    }

    #[getter]
    fn read_only(&self) -> bool {
        self.inner.read_only
    }

    #[getter]
    fn sharing(&self) -> &str {
        &self.inner.sharing
    }

    fn __repr__(&self) -> String {
        format!(
            "MountInfo(path={:?}, source={:?}, read_only={}, sharing={:?})",
            self.inner.path, self.inner.source, self.inner.read_only, self.inner.sharing
        )
    }
}

#[pyclass(name = "MountsClient", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyMountsClient {
    inner: MountsClient,
}

impl PyMountsClient {
    pub(crate) fn new(session: Session) -> Self {
        Self {
            inner: session.mounts(),
        }
    }
}

#[pymethods]
impl PyMountsClient {
    fn list<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mounts = client.list().await.map_err(ops_err_to_py)?;
            Ok(mounts
                .into_iter()
                .map(|inner| PyMountInfo { inner })
                .collect::<Vec<_>>())
        })
    }

    #[pyo3(signature = (source, path, *, read_only=false, sharing="shared", compress=None, commit=None, max_inline=None))]
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors helios:system/mounts.mount-request fields directly"
    )]
    fn mount<'py>(
        &self,
        py: Python<'py>,
        source: &str,
        path: String,
        read_only: bool,
        sharing: &str,
        compress: Option<String>,
        commit: Option<u32>,
        max_inline: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mount_source = match source.trim() {
            "memory" => MountSource::Memory,
            "boot-image" => MountSource::BootImage,
            "host-share" => MountSource::HostShare,
            other => {
                if let Some(serial) = other.strip_prefix("disk:") {
                    MountSource::Disk(serial.to_owned())
                } else if let Some(serial) = other.strip_prefix("btrfs:") {
                    MountSource::Btrfs(serial.to_owned())
                } else {
                    return Err(PyValueError::new_err(format!(
                        "unknown mount source `{other}`; expected memory|boot-image|host-share|disk:<serial>|btrfs:<serial>"
                    )));
                }
            }
        };
        let mount_sharing = match sharing.trim().to_ascii_lowercase().as_str() {
            "shared" => MountSharing::Shared,
            "private" => MountSharing::Private,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown mount sharing `{other}`; expected shared|private"
                )));
            }
        };
        let req = MountRequest {
            source: mount_source,
            path,
            read_only,
            sharing: mount_sharing,
            compress,
            commit,
            max_inline,
        };
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client.mount(req).await.map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    fn unmount<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client.unmount(&path).await.map_err(ops_err_to_py)?;
            Ok(())
        })
    }
}

#[pyclass(name = "SubvolumeInfo", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PySubvolumeInfo {
    pub(crate) inner: SubvolumeInfo,
}

#[pymethods]
impl PySubvolumeInfo {
    #[getter]
    fn id(&self) -> u64 {
        self.inner.id
    }

    #[getter]
    fn parent_id(&self) -> Option<u64> {
        self.inner.parent_id
    }

    #[getter]
    fn path(&self) -> &str {
        &self.inner.path
    }

    #[getter]
    fn uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.uuid)
    }

    #[getter]
    fn parent_uuid<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .parent_uuid
            .as_deref()
            .map(|b| PyBytes::new(py, b))
    }

    #[getter]
    fn received_uuid<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .received_uuid
            .as_deref()
            .map(|b| PyBytes::new(py, b))
    }

    #[getter]
    fn generation(&self) -> u64 {
        self.inner.generation
    }

    #[getter]
    fn ctransid(&self) -> u64 {
        self.inner.ctransid
    }

    #[getter]
    fn otransid(&self) -> u64 {
        self.inner.otransid
    }

    #[getter]
    fn stransid(&self) -> u64 {
        self.inner.stransid
    }

    #[getter]
    fn rtransid(&self) -> u64 {
        self.inner.rtransid
    }

    #[getter]
    fn read_only(&self) -> bool {
        self.inner.read_only
    }

    fn __repr__(&self) -> String {
        format!(
            "SubvolumeInfo(id={}, path={:?}, read_only={})",
            self.inner.id, self.inner.path, self.inner.read_only
        )
    }
}

#[pyclass(name = "DedupeOutcome", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyDedupeOutcome {
    pub(crate) inner: DedupeOutcome,
}

#[pymethods]
impl PyDedupeOutcome {
    #[getter]
    fn same(&self) -> bool {
        self.inner.same
    }

    #[getter]
    fn bytes_deduped(&self) -> u64 {
        self.inner.bytes_deduped
    }
}

#[pyclass(name = "VolumeDeviceInfo", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyVolumeDeviceInfo {
    pub(crate) inner: VolumeDeviceInfo,
}

#[pymethods]
impl PyVolumeDeviceInfo {
    #[getter]
    fn devid(&self) -> u64 {
        self.inner.devid
    }

    #[getter]
    fn uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.uuid)
    }

    #[getter]
    fn total_bytes(&self) -> u64 {
        self.inner.total_bytes
    }

    #[getter]
    fn bytes_used(&self) -> u64 {
        self.inner.bytes_used
    }

    #[getter]
    fn serial(&self) -> Option<&str> {
        self.inner.serial.as_deref()
    }
}

#[pyclass(name = "BalanceReport", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyBalanceReport {
    pub(crate) inner: BalanceReport,
}

#[pymethods]
impl PyBalanceReport {
    #[getter]
    fn considered(&self) -> u64 {
        self.inner.considered
    }

    #[getter]
    fn relocated(&self) -> u64 {
        self.inner.relocated
    }
}

#[pyclass(name = "ScrubReport", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyScrubReport {
    pub(crate) inner: ScrubReport,
}

#[pymethods]
impl PyScrubReport {
    #[getter]
    fn data_extents_scrubbed(&self) -> u64 {
        self.inner.data_extents_scrubbed
    }

    #[getter]
    fn tree_extents_scrubbed(&self) -> u64 {
        self.inner.tree_extents_scrubbed
    }

    #[getter]
    fn data_bytes_scrubbed(&self) -> u64 {
        self.inner.data_bytes_scrubbed
    }

    #[getter]
    fn tree_bytes_scrubbed(&self) -> u64 {
        self.inner.tree_bytes_scrubbed
    }

    #[getter]
    fn csum_errors(&self) -> u64 {
        self.inner.csum_errors
    }

    #[getter]
    fn verify_errors(&self) -> u64 {
        self.inner.verify_errors
    }

    #[getter]
    fn uncorrectable_errors(&self) -> u64 {
        self.inner.uncorrectable_errors
    }

    #[getter]
    fn corrected_errors(&self) -> u64 {
        self.inner.corrected_errors
    }

    #[getter]
    fn no_csum_sectors(&self) -> u64 {
        self.inner.no_csum_sectors
    }
}

#[pyclass(name = "QuotaStatus", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyQuotaStatus {
    pub(crate) inner: QuotaStatus,
}

#[pymethods]
impl PyQuotaStatus {
    #[getter]
    fn enabled(&self) -> bool {
        self.inner.enabled
    }

    #[getter]
    fn rescanning(&self) -> bool {
        self.inner.rescanning
    }

    #[getter]
    fn inconsistent(&self) -> bool {
        self.inner.inconsistent
    }

    #[getter]
    fn generation(&self) -> u64 {
        self.inner.generation
    }
}

#[pyclass(name = "QgroupInfo", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyQgroupInfo {
    pub(crate) inner: QgroupInfo,
}

#[pymethods]
impl PyQgroupInfo {
    #[getter]
    fn level(&self) -> u16 {
        self.inner.id.level
    }

    #[getter]
    fn id(&self) -> u64 {
        self.inner.id.id
    }

    #[getter]
    fn referenced_bytes(&self) -> u64 {
        self.inner.referenced_bytes
    }

    #[getter]
    fn referenced_compressed_bytes(&self) -> u64 {
        self.inner.referenced_compressed_bytes
    }

    #[getter]
    fn exclusive_bytes(&self) -> u64 {
        self.inner.exclusive_bytes
    }

    #[getter]
    fn exclusive_compressed_bytes(&self) -> u64 {
        self.inner.exclusive_compressed_bytes
    }

    #[getter]
    fn max_referenced(&self) -> Option<u64> {
        self.inner.limit.max_referenced
    }

    #[getter]
    fn max_exclusive(&self) -> Option<u64> {
        self.inner.limit.max_exclusive
    }

    #[getter]
    fn parents(&self) -> Vec<(u16, u64)> {
        self.inner.parents.iter().map(|p| (p.level, p.id)).collect()
    }
}

#[pyclass(name = "BtrfsClient", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyBtrfsClient {
    inner: BtrfsClient,
}

impl PyBtrfsClient {
    pub(crate) fn new(session: Session) -> Self {
        Self {
            inner: session.btrfs(),
        }
    }
}

#[pymethods]
impl PyBtrfsClient {
    fn create_subvolume<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let info = client
                .create_subvolume(&path)
                .await
                .map_err(ops_err_to_py)?;
            Ok(PySubvolumeInfo { inner: info })
        })
    }

    fn delete_subvolume<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .delete_subvolume(&path)
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    #[pyo3(signature = (source, destination, *, read_only=false))]
    fn snapshot_subvolume<'py>(
        &self,
        py: Python<'py>,
        source: String,
        destination: String,
        read_only: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let info = client
                .snapshot_subvolume(&source, &destination, read_only)
                .await
                .map_err(ops_err_to_py)?;
            Ok(PySubvolumeInfo { inner: info })
        })
    }

    fn set_subvolume_read_only<'py>(
        &self,
        py: Python<'py>,
        path: String,
        read_only: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .set_subvolume_read_only(&path, read_only)
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    fn subvolume_info<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let info = client.subvolume_info(&path).await.map_err(ops_err_to_py)?;
            Ok(PySubvolumeInfo { inner: info })
        })
    }

    fn list_subvolumes<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let list = client
                .list_subvolumes(&mount_point)
                .await
                .map_err(ops_err_to_py)?;
            Ok(list
                .into_iter()
                .map(|inner| PySubvolumeInfo { inner })
                .collect::<Vec<_>>())
        })
    }

    #[pyo3(signature = (subvolume, *, parent=None, clone_sources=None))]
    fn send_subvolume<'py>(
        &self,
        py: Python<'py>,
        subvolume: String,
        parent: Option<String>,
        clone_sources: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        let clones = clone_sources.unwrap_or_default();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let payload = client
                .send_subvolume(&subvolume, parent.as_deref(), &clones)
                .await
                .map_err(ops_err_to_py)?;
            Python::attach(|py| Ok(PyBytes::new(py, &payload).into_any().unbind()))
        })
    }

    fn receive_subvolume<'py>(
        &self,
        py: Python<'py>,
        destination: String,
        payload: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let info = client
                .receive_subvolume(&destination, payload)
                .await
                .map_err(ops_err_to_py)?;
            Ok(PySubvolumeInfo { inner: info })
        })
    }

    fn reflink<'py>(
        &self,
        py: Python<'py>,
        source: String,
        source_offset: u64,
        destination: String,
        destination_offset: u64,
        length: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .reflink(
                    &source,
                    source_offset,
                    &destination,
                    destination_offset,
                    length,
                )
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    fn dedupe<'py>(
        &self,
        py: Python<'py>,
        source: String,
        source_offset: u64,
        destination: String,
        destination_offset: u64,
        length: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcome = client
                .dedupe(
                    &source,
                    source_offset,
                    &destination,
                    destination_offset,
                    length,
                )
                .await
                .map_err(ops_err_to_py)?;
            Ok(PyDedupeOutcome { inner: outcome })
        })
    }

    fn list_devices<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let list = client
                .list_devices(&mount_point)
                .await
                .map_err(ops_err_to_py)?;
            Ok(list
                .into_iter()
                .map(|inner| PyVolumeDeviceInfo { inner })
                .collect::<Vec<_>>())
        })
    }

    fn add_device<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
        device: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let info = client
                .add_device(&mount_point, &device)
                .await
                .map_err(ops_err_to_py)?;
            Ok(PyVolumeDeviceInfo { inner: info })
        })
    }

    fn remove_device<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
        devid: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .remove_device(&mount_point, devid)
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    fn replace_device<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
        source_devid: u64,
        target_device: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let info = client
                .replace_device(&mount_point, source_devid, &target_device)
                .await
                .map_err(ops_err_to_py)?;
            Ok(PyVolumeDeviceInfo { inner: info })
        })
    }

    #[pyo3(signature = (mount_point, *, devid=None, size_bytes=None))]
    fn resize_device<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
        devid: Option<u64>,
        size_bytes: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let target = match size_bytes {
            Some(bytes) => ResizeTarget::Bytes(bytes),
            None => ResizeTarget::Max,
        };
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let info = client
                .resize_device(&mount_point, devid, target)
                .await
                .map_err(ops_err_to_py)?;
            Ok(PyVolumeDeviceInfo { inner: info })
        })
    }

    #[pyo3(signature = (mount_point, *, data=true, metadata=true, system=false, usage_max_percent=None, limit=None))]
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the typed Python btrfs.balance(...) keyword-only filter API"
    )]
    fn balance<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
        data: bool,
        metadata: bool,
        system: bool,
        usage_max_percent: Option<u8>,
        limit: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let filter = BalanceFilter {
            data,
            metadata,
            system,
            usage_max_percent,
            limit,
        };
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let report = client
                .balance(&mount_point, filter)
                .await
                .map_err(ops_err_to_py)?;
            Ok(PyBalanceReport { inner: report })
        })
    }

    #[pyo3(signature = (mount_point, *, devid=None, read_only=true))]
    fn scrub<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
        devid: Option<u64>,
        read_only: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let report = client
                .scrub(&mount_point, devid, read_only)
                .await
                .map_err(ops_err_to_py)?;
            Ok(PyScrubReport { inner: report })
        })
    }

    fn quota_enable<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .quota_enable(&mount_point)
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    fn quota_disable<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .quota_disable(&mount_point)
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    fn quota_rescan<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .quota_rescan(&mount_point)
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    fn quota_status<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let status = client
                .quota_status(&mount_point)
                .await
                .map_err(ops_err_to_py)?;
            Ok(PyQuotaStatus { inner: status })
        })
    }

    fn qgroup_list<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let list = client
                .qgroup_list(&mount_point)
                .await
                .map_err(ops_err_to_py)?;
            Ok(list
                .into_iter()
                .map(|inner| PyQgroupInfo { inner })
                .collect::<Vec<_>>())
        })
    }

    fn qgroup_create<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
        level: u16,
        id: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .qgroup_create(&mount_point, QgroupId { level, id })
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    fn qgroup_destroy<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
        level: u16,
        id: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .qgroup_destroy(&mount_point, QgroupId { level, id })
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    fn qgroup_assign<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
        member: (u16, u64),
        parent: (u16, u64),
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .qgroup_assign(
                    &mount_point,
                    QgroupId {
                        level: member.0,
                        id: member.1,
                    },
                    QgroupId {
                        level: parent.0,
                        id: parent.1,
                    },
                )
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    fn qgroup_remove<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
        member: (u16, u64),
        parent: (u16, u64),
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .qgroup_remove(
                    &mount_point,
                    QgroupId {
                        level: member.0,
                        id: member.1,
                    },
                    QgroupId {
                        level: parent.0,
                        id: parent.1,
                    },
                )
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    #[pyo3(signature = (mount_point, level, id, *, max_referenced=None, max_exclusive=None))]
    fn set_qgroup_limit<'py>(
        &self,
        py: Python<'py>,
        mount_point: String,
        level: u16,
        id: u64,
        max_referenced: Option<u64>,
        max_exclusive: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .set_qgroup_limit(
                    &mount_point,
                    QgroupId { level, id },
                    QgroupLimit {
                        max_referenced,
                        max_exclusive,
                    },
                )
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Custom Linux VM orchestration (`s.vm`)
// ---------------------------------------------------------------------------

#[pyclass(name = "HvVm", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyHvVm {
    pub(crate) inner: HvVm,
}

#[pymethods]
impl PyHvVm {
    #[getter]
    fn id(&self) -> u64 {
        self.inner.id
    }

    #[getter]
    fn vmid(&self) -> Option<u32> {
        self.inner.vmid
    }

    #[getter]
    fn owner_instance_id(&self) -> Option<u64> {
        self.inner.owner_instance_id
    }

    #[getter]
    fn stage2_pages(&self) -> u64 {
        self.inner.stage2_pages
    }

    #[getter]
    fn stage2_bytes(&self) -> u64 {
        self.inner.stage2_bytes
    }

    #[getter]
    fn allocated_bytes(&self) -> u64 {
        self.inner.allocated_bytes
    }

    #[getter]
    fn memory_limit_bytes(&self) -> u64 {
        self.inner.memory_limit_bytes
    }

    #[getter]
    fn vcpus(&self) -> u64 {
        self.inner.vcpus
    }

    #[getter]
    fn vcpu_exits_total(&self) -> u64 {
        self.inner.vcpu_exits_total
    }

    #[getter]
    fn ioevent_registrations(&self) -> u64 {
        self.inner.ioevent_registrations
    }

    #[getter]
    fn ioevent_hits(&self) -> u64 {
        self.inner.ioevent_hits
    }

    fn __repr__(&self) -> String {
        format!(
            "HvVm(id={}, vcpus={}, allocated_bytes={})",
            self.inner.id, self.inner.vcpus, self.inner.allocated_bytes
        )
    }
}

/// Live custom Linux [`MicroVm`] handle implementing `AsyncContextManager`.
#[pyclass(name = "MicroVm")]
pub(crate) struct PyMicroVm {
    inner: Arc<Mutex<Option<MicroVm>>>,
    console: PyByteStream,
    stderr: PyByteStream,
}

impl PyMicroVm {
    fn from_ops(vm: MicroVm) -> Self {
        let console = PyByteStream::new(vm.console().clone());
        let stderr = PyByteStream::new(vm.stderr().clone());
        Self {
            inner: Arc::new(Mutex::new(Some(vm))),
            console,
            stderr,
        }
    }
}

#[pymethods]
impl PyMicroVm {
    #[getter]
    fn instance_id(&self) -> Option<u64> {
        self.inner
            .try_lock()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(MicroVm::instance_id))
    }

    #[getter]
    fn console(&self) -> PyByteStream {
        self.console.clone()
    }

    #[getter]
    fn stderr(&self) -> PyByteStream {
        self.stderr.clone()
    }

    fn __aenter__<'py>(slf: Py<Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(slf) })
    }

    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: Option<&Bound<'py, PyAny>>,
        _exc_val: Option<&Bound<'py, PyAny>>,
        _exc_tb: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let holder = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vm = holder.lock().await.take();
            if let Some(vm) = vm {
                let _ = vm.shutdown().await;
            }
            Ok(false)
        })
    }

    fn write_console<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let holder = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = holder.lock().await;
            let vm = guard
                .as_ref()
                .ok_or_else(|| HeliosError::new_err("MicroVm has already shut down"))?;
            vm.write_console(&data).await.map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    fn shutdown<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let holder = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vm = holder.lock().await.take();
            if let Some(vm) = vm {
                let res = vm.shutdown().await.map_err(ops_err_to_py)?;
                return Ok(res.map(|inner| PyExecResult { inner }));
            }
            Ok(None)
        })
    }

    fn wait<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let holder = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vm = holder
                .lock()
                .await
                .take()
                .ok_or_else(|| HeliosError::new_err("MicroVm has already exited"))?;
            let res = vm.wait().await.map_err(ops_err_to_py)?;
            Ok(PyExecResult { inner: res })
        })
    }
}

#[pyclass(name = "VmClient", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyVmClient {
    inner: VmClient,
}

impl PyVmClient {
    pub(crate) fn new(session: Session) -> Self {
        Self {
            inner: session.vm(),
        }
    }
}

#[pymethods]
impl PyVmClient {
    fn list<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vms = client.list().await.map_err(ops_err_to_py)?;
            Ok(vms
                .into_iter()
                .map(|inner| PyHvVm { inner })
                .collect::<Vec<_>>())
        })
    }

    #[pyo3(signature = (
        *,
        kernel,
        initramfs=None,
        cpus=1,
        memory_mib=128,
        cmdline=None,
        disks=None,
        shares=None,
        rootfs_dir=None,
        oci_image=None,
        vmm_binary=None,
    ))]
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the typed Python s.vm.spawn(...) keyword-only API"
    )]
    fn spawn<'py>(
        &self,
        py: Python<'py>,
        kernel: String,
        initramfs: Option<String>,
        cpus: u32,
        memory_mib: u64,
        cmdline: Option<String>,
        disks: Option<Vec<PyVmDisk>>,
        shares: Option<Vec<PyVmShare>>,
        rootfs_dir: Option<String>,
        oci_image: Option<String>,
        vmm_binary: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut builder = MicroVmBuilder::new(kernel)
            .cpus(cpus)
            .memory_mib(memory_mib);
        if let Some(bin) = vmm_binary {
            builder = builder.vmm_binary(bin);
        }
        if let Some(initrd) = initramfs {
            builder = builder.initramfs(initrd);
        }
        if let Some(cmd) = cmdline {
            builder = builder.cmdline(cmd);
        }
        if let Some(root) = rootfs_dir {
            builder = builder.rootfs_dir(root);
        }
        if let Some(oci) = oci_image {
            builder = builder.oci_image(oci);
        }
        for disk in disks.unwrap_or_default() {
            builder = builder.disk(disk.inner);
        }
        for share in shares.unwrap_or_default() {
            builder = builder.share(share.inner);
        }
        let config = builder.build();
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vm = client.spawn(config).await.map_err(ops_err_to_py)?;
            Ok(PyMicroVm::from_ops(vm))
        })
    }
}

// ---------------------------------------------------------------------------
// Profiling RAII SamplingSession & ELF/DWARF symbolization
// ---------------------------------------------------------------------------

#[pyclass(name = "InstructionProfile", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PyInstructionProfile {
    pub(crate) inner: InstructionProfile,
}

#[pymethods]
impl PyInstructionProfile {
    #[getter]
    fn period_nanos(&self) -> u64 {
        self.inner.period_nanos
    }

    #[getter]
    fn kernel_image_base(&self) -> u64 {
        self.inner.kernel_image_base
    }

    #[getter]
    fn dropped(&self) -> u64 {
        self.inner.dropped
    }

    #[getter]
    fn total_samples(&self) -> u64 {
        self.inner.samples.iter().map(|s| s.count).sum()
    }

    #[getter]
    fn unique_pcs(&self) -> usize {
        self.inner.samples.len()
    }

    /// Symbolize this raw instruction profile against a local kernel ELF/DWARF image.
    fn symbolize<'py>(&self, py: Python<'py>, kernel_image: String) -> PyResult<Bound<'py, PyAny>> {
        let profile = self.inner.clone();
        let path = PathBuf::from(kernel_image);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sym = helios_ops::symbolize_instruction_profile(profile, &path)
                .await
                .map_err(|err| ops_err_to_py(OpsError::from(err)))?;
            Ok(PySymbolizedInstructionProfile { inner: sym })
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "InstructionProfile(total_samples={}, unique_pcs={}, dropped={})",
            self.total_samples(),
            self.inner.samples.len(),
            self.inner.dropped
        )
    }
}

#[pyclass(name = "SymbolizedSample", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PySymbolizedSample {
    pub(crate) inner: SymbolizedSample,
}

#[pymethods]
impl PySymbolizedSample {
    #[getter]
    fn stack(&self) -> &str {
        &self.inner.stack
    }

    #[getter]
    fn count(&self) -> u64 {
        self.inner.count
    }

    fn __repr__(&self) -> String {
        format!(
            "SymbolizedSample(stack={:?}, count={})",
            self.inner.stack, self.inner.count
        )
    }
}

#[pyclass(name = "SymbolizedInstructionProfile", from_py_object)]
#[derive(Clone, Debug)]
pub(crate) struct PySymbolizedInstructionProfile {
    pub(crate) inner: SymbolizedInstructionProfile,
}

#[pymethods]
impl PySymbolizedInstructionProfile {
    #[getter]
    fn period_nanos(&self) -> u64 {
        self.inner.period_nanos
    }

    #[getter]
    fn kernel_image_base(&self) -> u64 {
        self.inner.kernel_image_base
    }

    #[getter]
    fn dropped(&self) -> u64 {
        self.inner.dropped
    }

    #[getter]
    fn total_samples(&self) -> u64 {
        self.inner.total_samples
    }

    #[getter]
    fn samples(&self) -> Vec<PySymbolizedSample> {
        self.inner
            .samples
            .iter()
            .cloned()
            .map(|inner| PySymbolizedSample { inner })
            .collect()
    }

    fn to_folded(&self) -> String {
        helios_ops::symbolize::render_folded_samples(&self.inner.samples)
    }
}

/// Standalone RAII instruction-sampling session implementing `AsyncContextManager`.
#[pyclass(name = "SamplingSession")]
pub(crate) struct PySamplingSession {
    inner: Arc<Mutex<Option<SamplingSession>>>,
}

impl PySamplingSession {
    pub(crate) fn new(lease: SamplingSession) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(lease))),
        }
    }
}

#[pymethods]
impl PySamplingSession {
    #[getter]
    fn is_active(&self) -> bool {
        self.inner
            .try_lock()
            .ok()
            .is_some_and(|guard| guard.as_ref().is_some_and(SamplingSession::is_active))
    }

    fn __aenter__<'py>(slf: Py<Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(slf) })
    }

    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: Option<&Bound<'py, PyAny>>,
        _exc_val: Option<&Bound<'py, PyAny>>,
        _exc_tb: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let holder = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let lease = holder.lock().await.take();
            if let Some(lease) = lease {
                let _ = lease.stop().await;
            }
            Ok(false)
        })
    }

    fn samples<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let holder = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = holder.lock().await;
            let lease = guard
                .as_ref()
                .ok_or_else(|| HeliosError::new_err("SamplingSession has already stopped"))?;
            let profile = lease.samples().await.map_err(ops_err_to_py)?;
            Ok(PyInstructionProfile { inner: profile })
        })
    }

    fn stop_and_collect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let holder = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let lease = holder
                .lock()
                .await
                .take()
                .ok_or_else(|| HeliosError::new_err("SamplingSession has already stopped"))?;
            let profile = lease.stop_and_collect().await.map_err(ops_err_to_py)?;
            Ok(PyInstructionProfile { inner: profile })
        })
    }

    fn stop<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let holder = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if let Some(lease) = holder.lock().await.take() {
                lease.stop().await.map_err(ops_err_to_py)?;
            }
            Ok(())
        })
    }
}
