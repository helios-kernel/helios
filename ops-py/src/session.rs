//! Async Python `Session` bindings over [`helios_ops::Session`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use helios_inspector_protocol::system::tracing as sys_tracing;
use helios_ops::{
    Attenuation, DiagnosticBundle, GrantRight, OpsError, Session, SpawnRequest, TargetStore,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::error::{ops_err_to_py, target_err_to_py};
use crate::types::{
    PyChild, PyDiagnosticBundle, PyExecResult, PyInspectSnapshot, PyInstance, PyRemoteEntry,
    PyRemoteStat, PyTarget, PyTraceEvent, build_session_options, extract_target_arg,
    kernel_snapshot_to_py, parse_trace_level,
};

/// Async operations session connected to a single Helios node.
#[pyclass(name = "Session", from_py_object)]
#[derive(Clone)]
pub(crate) struct PySession {
    pub(crate) inner: Session,
}

#[pymethods]
impl PySession {
    /// Connect asynchronously to a Helios node target (name, URI, `Target`, or default target).
    #[staticmethod]
    #[pyo3(signature = (target=None, *, timeout_secs=None, scope=None, only=None, identity=None, targets_path=None))]
    fn connect<'py>(
        py: Python<'py>,
        target: Option<&Bound<'py, PyAny>>,
        timeout_secs: Option<f64>,
        scope: Option<String>,
        only: Option<Vec<String>>,
        identity: Option<String>,
        targets_path: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let resolved_target = match target {
            Some(arg) => extract_target_arg(arg, targets_path.as_deref())?,
            None => {
                let store = match targets_path.as_deref() {
                    Some(path) => TargetStore::load(path).map_err(target_err_to_py)?,
                    None => TargetStore::load_default().map_err(target_err_to_py)?,
                };
                store.resolve(None).map_err(target_err_to_py)?
            }
        };
        let options = build_session_options(timeout_secs, scope, only, identity)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let session = Session::connect(&resolved_target, options)
                .await
                .map_err(ops_err_to_py)?;
            Ok(Self { inner: session })
        })
    }

    #[getter]
    fn target(&self) -> PyTarget {
        PyTarget {
            inner: self.inner.target().clone(),
        }
    }

    #[getter]
    fn scope(&self) -> &str {
        self.inner.options().attenuation.effective_scope()
    }

    #[getter]
    fn only(&self) -> Vec<&'static str> {
        self.inner
            .options()
            .attenuation
            .only
            .iter()
            .map(|r| r.as_str())
            .collect()
    }

    #[getter]
    fn whoami(&self) -> String {
        self.inner.whoami()
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
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(false) })
    }

    /// Return a new [`Session`] handle sharing this connection with monotonically narrowed attenuation.
    #[pyo3(signature = (*, scope=None, only=None))]
    fn attenuated(&self, scope: Option<String>, only: Option<Vec<String>>) -> PyResult<Self> {
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
        } else {
            rights = self.inner.options().attenuation.only.clone();
        }
        let narrowed = self
            .inner
            .attenuated(Attenuation {
                scope,
                only: rights,
            })
            .map_err(ops_err_to_py)?;
        Ok(Self { inner: narrowed })
    }

    /// Query `helios:system/inspect` across `/kernel/*` and component inspect trees.
    #[pyo3(signature = (prefixes=None, *, limit=0))]
    fn inspect<'py>(
        &self,
        py: Python<'py>,
        prefixes: Option<Vec<String>>,
        limit: u32,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        let prefixes = prefixes.unwrap_or_default();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
            let snapshot = session.inspect(&refs, limit).await.map_err(ops_err_to_py)?;
            Ok(PyInspectSnapshot { inner: snapshot })
        })
    }

    /// Fetch and decode the `/kernel/*` inspect subtree into a structured Python dictionary.
    fn kernel_snapshot<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let snapshot = session.kernel_snapshot().await.map_err(ops_err_to_py)?;
            Python::attach(|py| kernel_snapshot_to_py(py, &snapshot))
        })
    }

    /// List live instances (`ps`).
    fn ps<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let list = session.ps().await.map_err(ops_err_to_py)?;
            Ok(list
                .into_iter()
                .map(|inner| PyInstance { inner })
                .collect::<Vec<_>>())
        })
    }

    /// Alias for [`Self::ps`].
    fn instances<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.ps(py)
    }

    /// Request termination of an instance by numeric ID or instance name.
    fn kill<'py>(
        &self,
        py: Python<'py>,
        target: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        if let Ok(id) = target.extract::<u64>() {
            return pyo3_async_runtimes::tokio::future_into_py(py, async move {
                session.kill(id).await.map_err(ops_err_to_py)?;
                Ok(id)
            });
        }
        if let Ok(name) = target.extract::<String>() {
            return pyo3_async_runtimes::tokio::future_into_py(py, async move {
                let id = session.kill_by_name(&name).await.map_err(ops_err_to_py)?;
                Ok(id)
            });
        }
        Err(PyValueError::new_err(
            "kill target must be an integer instance ID or instance name string",
        ))
    }

    /// Fetch recent guest tracing events.
    #[pyo3(signature = (*, limit=64, min_level=Some("info"), target_prefixes=None))]
    fn trace_recent<'py>(
        &self,
        py: Python<'py>,
        limit: u32,
        min_level: Option<&str>,
        target_prefixes: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        let parsed_level = parse_trace_level(min_level)?;
        let filter = sys_tracing::Filter {
            min_level: parsed_level,
            target_prefixes: target_prefixes.unwrap_or_default(),
        };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let events = session
                .trace_recent(&filter, limit)
                .await
                .map_err(ops_err_to_py)?;
            Ok(events
                .into_iter()
                .map(|inner| PyTraceEvent { inner })
                .collect::<Vec<_>>())
        })
    }

    /// Enable or disable a named kernel diagnostic tracing target.
    #[pyo3(signature = (target, enabled=true))]
    fn set_trace_target_enabled<'py>(
        &self,
        py: Python<'py>,
        target: String,
        enabled: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            session
                .set_trace_target_enabled(&target, enabled)
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    /// Execute a program by path via `debugger.programs.exec-path`.
    #[pyo3(signature = (path, args=None))]
    fn exec<'py>(
        &self,
        py: Python<'py>,
        path: String,
        args: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        let args = args.unwrap_or_default();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let result = session.exec(&path, &args).await.map_err(ops_err_to_py)?;
            Ok(PyExecResult { inner: result })
        })
    }

    /// Spawn a remote program with optional env, stdin, and capability grants, returning a streaming [`PyChild`].
    #[pyo3(signature = (path, args=None, *, env=None, stdin=None, grants=None))]
    fn spawn<'py>(
        &self,
        py: Python<'py>,
        path: String,
        args: Option<Vec<String>>,
        env: Option<BTreeMap<String, String>>,
        stdin: Option<Vec<u8>>,
        grants: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut capability_grants = Vec::new();
        if let Some(specs) = grants {
            for spec in specs {
                let parsed =
                    helios_ops::session::parse_capability_grant(&spec).map_err(ops_err_to_py)?;
                capability_grants.push(parsed);
            }
        }
        let request = SpawnRequest {
            path,
            args: args.unwrap_or_default(),
            env: env.unwrap_or_default().into_iter().collect(),
            stdin: stdin.unwrap_or_default(),
            capability_grants,
        };
        let session = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let child = session.spawn(request).await.map_err(ops_err_to_py)?;
            Ok(PyChild::new(child))
        })
    }

    /// List directory entries on the remote VFS.
    #[pyo3(signature = (path="/"))]
    fn list_dir<'py>(&self, py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        let path = path.to_owned();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let entries = session.list_dir(&path).await.map_err(ops_err_to_py)?;
            Ok(entries
                .into_iter()
                .map(|inner| PyRemoteEntry { inner })
                .collect::<Vec<_>>())
        })
    }

    /// Stat a single path on the remote VFS.
    fn stat<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let stat = session.stat(&path).await.map_err(ops_err_to_py)?;
            Ok(PyRemoteStat { inner: stat })
        })
    }

    /// Read a file from the remote VFS as `bytes`.
    fn read_file<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let data = session.read_file(&path).await.map_err(ops_err_to_py)?;
            Python::attach(|py| Ok(PyBytes::new(py, &data).into_any().unbind()))
        })
    }

    /// Write or append `bytes` to a file on the remote VFS.
    #[pyo3(signature = (path, data, *, append=false))]
    fn write_file<'py>(
        &self,
        py: Python<'py>,
        path: String,
        data: Vec<u8>,
        append: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            session
                .write_file(&path, &data, append)
                .await
                .map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    /// Create a directory on the remote VFS.
    fn mkdir<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            session.mkdir(&path).await.map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    /// Remove a file or directory on the remote VFS.
    fn remove<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            session.remove(&path).await.map_err(ops_err_to_py)?;
            Ok(())
        })
    }

    /// Collect a diagnostic bundle (and optionally write `.tar.zst` to `output_path`).
    #[pyo3(signature = (output_path=None))]
    fn bundle<'py>(
        &self,
        py: Python<'py>,
        output_path: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let session = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let collected = DiagnosticBundle::collect(&session)
                .await
                .map_err(ops_err_to_py)?;
            if let Some(path) = output_path {
                collected
                    .write_tar_zst(PathBuf::from(path))
                    .await
                    .map_err(|err| ops_err_to_py(OpsError::from(err)))?;
            }
            Ok(PyDiagnosticBundle { inner: collected })
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "Session(target={:?}, uri={:?}, scope={:?})",
            self.inner.target().name,
            self.inner.target().uri,
            self.inner.options().attenuation.effective_scope()
        )
    }
}
