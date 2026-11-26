//! Async Python `Fleet` bindings over [`helios_ops::Fleet`].

use helios_ops::{DEFAULT_FLEET_CONCURRENCY, Fleet, NodeOutcome, TargetStore};
use pyo3::IntoPyObjectExt as _;
use pyo3::prelude::*;

use crate::error::target_err_to_py;
use crate::types::{
    OutcomeErrorKind, PyDiagnosticBundle, PyExecResult, PyInspectSnapshot, PyInstance,
    PyNodeOutcome, PyTarget, build_session_options, extract_target_arg,
};

fn convert_outcome<T, F>(
    py: Python<'_>,
    outcome: NodeOutcome<T>,
    convert_ok: F,
) -> PyResult<PyNodeOutcome>
where
    F: FnOnce(Python<'_>, T) -> PyResult<Py<PyAny>>,
{
    let target = PyTarget {
        inner: outcome.target,
    };
    let elapsed_ms = outcome.elapsed.as_secs_f64() * 1000.0;
    match outcome.result {
        Ok(val) => Ok(PyNodeOutcome {
            target,
            elapsed_ms,
            value: Some(convert_ok(py, val)?),
            error_message: None,
            error_kind: None,
        }),
        Err(err) => Ok(PyNodeOutcome {
            target,
            elapsed_ms,
            value: None,
            error_kind: Some(OutcomeErrorKind::from_ops_error(&err)),
            error_message: Some(err.to_string()),
        }),
    }
}

/// Multi-node fleet handle supporting bounded-concurrency async fan-out.
#[pyclass(name = "Fleet", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyFleet {
    inner: Fleet,
}

#[pymethods]
impl PyFleet {
    /// Construct a [`Fleet`] from explicit targets (`Target` or target name/URI strings).
    #[staticmethod]
    #[pyo3(signature = (targets, *, concurrency=DEFAULT_FLEET_CONCURRENCY, timeout_secs=None, scope=None, only=None, identity=None, targets_path=None))]
    fn from_targets(
        targets: Vec<Bound<'_, PyAny>>,
        concurrency: usize,
        timeout_secs: Option<f64>,
        scope: Option<String>,
        only: Option<Vec<String>>,
        identity: Option<String>,
        targets_path: Option<String>,
    ) -> PyResult<Self> {
        let mut resolved = Vec::with_capacity(targets.len());
        for item in &targets {
            resolved.push(extract_target_arg(item, targets_path.as_deref())?);
        }
        let allow_ambient_auth = resolved.iter().all(|target| {
            !matches!(
                target.parsed_uri(),
                Ok(helios_ops::TargetUri::Helios { tls: false, .. })
            )
        });
        let options =
            build_session_options(timeout_secs, scope, only, identity, allow_ambient_auth)?;
        Ok(Self {
            inner: Fleet::new(resolved, concurrency, options),
        })
    }

    /// Construct a [`Fleet`] by selecting targets matching `key=value` labels in `targets.toml`.
    #[staticmethod]
    #[pyo3(signature = (labels, *, concurrency=DEFAULT_FLEET_CONCURRENCY, timeout_secs=None, scope=None, only=None, identity=None, targets_path=None))]
    fn from_labels(
        labels: Vec<String>,
        concurrency: usize,
        timeout_secs: Option<f64>,
        scope: Option<String>,
        only: Option<Vec<String>>,
        identity: Option<String>,
        targets_path: Option<String>,
    ) -> PyResult<Self> {
        let store = match targets_path.as_deref() {
            Some(path) => TargetStore::load(path).map_err(target_err_to_py)?,
            None => TargetStore::load_default().map_err(target_err_to_py)?,
        };
        let targets = store.select_by_labels(&labels).map_err(target_err_to_py)?;
        let allow_ambient_auth = targets.iter().all(|target| {
            !matches!(
                target.parsed_uri(),
                Ok(helios_ops::TargetUri::Helios { tls: false, .. })
            )
        });
        let options =
            build_session_options(timeout_secs, scope, only, identity, allow_ambient_auth)?;
        Ok(Self {
            inner: Fleet::new(targets, concurrency, options),
        })
    }

    #[getter]
    fn targets(&self) -> Vec<PyTarget> {
        self.inner
            .targets()
            .iter()
            .cloned()
            .map(|inner| PyTarget { inner })
            .collect()
    }

    #[getter]
    fn concurrency(&self) -> usize {
        self.inner.concurrency()
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

    /// Run `inspect` across every target in the fleet.
    #[pyo3(signature = (prefixes=None, *, limit=0))]
    fn inspect<'py>(
        &self,
        py: Python<'py>,
        prefixes: Option<Vec<String>>,
        limit: u32,
    ) -> PyResult<Bound<'py, PyAny>> {
        let fleet = self.inner.clone();
        let prefixes = prefixes.unwrap_or_default();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fleet.inspect(prefixes, limit).await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| {
                        convert_outcome(py, outcome, |py, snap| {
                            PyInspectSnapshot { inner: snap }.into_py_any(py)
                        })
                    })
                    .collect::<PyResult<Vec<_>>>()
            })
        })
    }

    /// Run `ps` across every target in the fleet.
    fn ps<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let fleet = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fleet.ps().await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| {
                        convert_outcome(py, outcome, |py, list| {
                            let wrapped: Vec<PyInstance> =
                                list.into_iter().map(|inner| PyInstance { inner }).collect();
                            wrapped.into_py_any(py)
                        })
                    })
                    .collect::<PyResult<Vec<_>>>()
            })
        })
    }

    /// Execute a program across every target in the fleet.
    #[pyo3(signature = (path, args=None))]
    fn exec<'py>(
        &self,
        py: Python<'py>,
        path: String,
        args: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let fleet = self.inner.clone();
        let args = args.unwrap_or_default();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fleet.exec(path, args).await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| {
                        convert_outcome(py, outcome, |py, res| {
                            PyExecResult { inner: res }.into_py_any(py)
                        })
                    })
                    .collect::<PyResult<Vec<_>>>()
            })
        })
    }

    /// Collect diagnostic bundles across every target in the fleet.
    fn collect_bundles<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let fleet = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let outcomes = fleet.collect_bundles().await;
            Python::attach(|py| {
                outcomes
                    .into_iter()
                    .map(|outcome| {
                        convert_outcome(py, outcome, |py, bundle| {
                            PyDiagnosticBundle { inner: bundle }.into_py_any(py)
                        })
                    })
                    .collect::<PyResult<Vec<_>>>()
            })
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "Fleet(targets={}, concurrency={})",
            self.inner.targets().len(),
            self.inner.concurrency()
        )
    }
}
