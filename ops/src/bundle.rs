//! `.tar.zst` diagnostic bundle collection and export.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use helios_wit_rpc::inspector::helios::system::{
    inspect::{self, SnapshotResult},
    instances::Instance,
    profiling::{Filter as ProfileFilter, FoldedSample, MetricFilter, MetricSample},
    tracing as sys_tracing,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::{BundleError, OpsError};
use crate::session::Session;

/// Default zstd compression level for diagnostic bundles (fast, good ratio).
const DEFAULT_ZSTD_LEVEL: i32 = 3;

/// Summary metadata embedded as `manifest.json` inside every `.tar.zst` bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    pub target_name: String,
    pub target_uri: String,
    pub collected_at_rfc3339: String,
    pub entries: Vec<String>,
}

/// One file stored inside a [`DiagnosticBundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEntry {
    pub path: String,
    pub bytes: Vec<u8>,
}

/// Collected diagnostic archive ready to be written as `.tar.zst`.
#[derive(Debug, Clone)]
pub struct DiagnosticBundle {
    pub manifest: BundleManifest,
    pub entries: Vec<BundleEntry>,
}

impl DiagnosticBundle {
    /// Start an empty bundle for `target_name` / `target_uri`.
    #[must_use]
    pub fn new(target_name: impl Into<String>, target_uri: impl Into<String>) -> Self {
        let collected_at_rfc3339 = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        Self {
            manifest: BundleManifest {
                target_name: target_name.into(),
                target_uri: target_uri.into(),
                collected_at_rfc3339,
                entries: Vec::new(),
            },
            entries: Vec::new(),
        }
    }

    /// Append a named raw file entry to this bundle.
    pub fn add_entry(&mut self, path: impl Into<String>, bytes: Vec<u8>) {
        let path = path.into();
        self.manifest.entries.push(path.clone());
        self.entries.push(BundleEntry { path, bytes });
    }

    /// Append a pretty-printed JSON file entry to this bundle.
    pub fn add_json<T: Serialize>(
        &mut self,
        path: impl Into<String>,
        value: &T,
    ) -> Result<(), BundleError> {
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|source| BundleError::EncodeJson { source })?;
        self.add_entry(path, bytes);
        Ok(())
    }

    /// Collect inspect state, live instances, recent tracing events, and profiling
    /// snapshots from a live [`Session`].
    pub async fn collect(session: &Session) -> Result<Self, OpsError> {
        let mut bundle = Self::new(&session.target().name, &session.target().uri);

        let inspect_fut = session.inspect(&[], 0);
        let instances_fut = session.instances();
        let trace_filter = sys_tracing::Filter {
            min_level: Some(sys_tracing::Level::Debug),
            target_prefixes: Vec::new(),
        };
        let trace_fut = session.trace_recent(&trace_filter, 512);
        let metric_filter = MetricFilter {
            name_prefixes: Vec::new(),
        };
        let metrics_fut = session.profile_metrics(&metric_filter, 512);
        let folded_filter = ProfileFilter {
            scope: None,
            stack_prefixes: Vec::new(),
        };
        let folded_fut = session.profile_folded(&folded_filter, 512);

        let (inspect_res, instances_res, trace_res, metrics_res, folded_res) = tokio::join!(
            inspect_fut,
            instances_fut,
            trace_fut,
            metrics_fut,
            folded_fut
        );

        match inspect_res {
            Ok(snapshot) => {
                bundle.add_json("inspect.json", &encode_inspect_snapshot(&snapshot))?;
            }
            Err(err) => {
                bundle.add_entry("inspect.error.txt", err.to_string().into_bytes());
            }
        }

        match instances_res {
            Ok(list) => {
                bundle.add_json("instances.json", &encode_instances(&list))?;
            }
            Err(err) => {
                bundle.add_entry("instances.error.txt", err.to_string().into_bytes());
            }
        }

        match trace_res {
            Ok(events) => {
                bundle.add_json("tracing.json", &encode_tracing_events(&events))?;
            }
            Err(err) => {
                bundle.add_entry("tracing.error.txt", err.to_string().into_bytes());
            }
        }

        match metrics_res {
            Ok(metrics) => {
                bundle.add_json("profile-metrics.json", &encode_metrics(&metrics))?;
            }
            Err(err) => {
                bundle.add_entry("profile-metrics.error.txt", err.to_string().into_bytes());
            }
        }

        match folded_res {
            Ok(folded) => {
                bundle.add_json("profile-folded.json", &encode_folded(&folded))?;
            }
            Err(err) => {
                bundle.add_entry("profile-folded.error.txt", err.to_string().into_bytes());
            }
        }

        Ok(bundle)
    }

    /// Write this bundle to `path` as a `.tar.zst` archive off the async executor thread.
    pub async fn write_tar_zst(&self, path: impl AsRef<Path>) -> Result<PathBuf, BundleError> {
        let out_path = path.as_ref().to_path_buf();
        let manifest_bytes = serde_json::to_vec_pretty(&self.manifest)
            .map_err(|source| BundleError::EncodeJson { source })?;
        let entries = self.entries.clone();

        let write_path = out_path.clone();
        tokio::task::spawn_blocking(move || {
            if let Some(parent) = write_path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent).map_err(|source| BundleError::CreateFile {
                    path: write_path.clone(),
                    source,
                })?;
            }
            let file = File::create(&write_path).map_err(|source| BundleError::CreateFile {
                path: write_path.clone(),
                source,
            })?;
            let encoder =
                zstd::stream::write::Encoder::new(file, DEFAULT_ZSTD_LEVEL).map_err(|source| {
                    BundleError::WriteArchive {
                        path: write_path.clone(),
                        source,
                    }
                })?;
            let mut tar = tar::Builder::new(encoder);

            append_tar_bytes(&mut tar, "manifest.json", &manifest_bytes).map_err(|source| {
                BundleError::WriteArchive {
                    path: write_path.clone(),
                    source,
                }
            })?;
            for entry in &entries {
                append_tar_bytes(&mut tar, &entry.path, &entry.bytes).map_err(|source| {
                    BundleError::WriteArchive {
                        path: write_path.clone(),
                        source,
                    }
                })?;
            }

            let encoder = tar
                .into_inner()
                .map_err(|source| BundleError::WriteArchive {
                    path: write_path.clone(),
                    source,
                })?;
            encoder
                .finish()
                .map_err(|source| BundleError::WriteArchive {
                    path: write_path.clone(),
                    source,
                })?;
            Ok::<_, BundleError>(())
        })
        .await
        .map_err(|err| BundleError::TaskJoin {
            detail: err.to_string(),
        })??;

        Ok(out_path)
    }

    /// Read all entries from a `.tar.zst` bundle file asynchronously.
    pub async fn read_tar_zst(path: impl AsRef<Path>) -> Result<Vec<BundleEntry>, BundleError> {
        let in_path = path.as_ref().to_path_buf();
        tokio::task::spawn_blocking(move || {
            let file = File::open(&in_path).map_err(|source| BundleError::OpenFile {
                path: in_path.clone(),
                source,
            })?;
            let decoder = zstd::stream::read::Decoder::new(file).map_err(|source| {
                BundleError::ReadArchive {
                    path: in_path.clone(),
                    source,
                }
            })?;
            let mut archive = tar::Archive::new(decoder);
            let mut out = Vec::new();
            let entries = archive
                .entries()
                .map_err(|source| BundleError::ReadArchive {
                    path: in_path.clone(),
                    source,
                })?;
            for entry_res in entries {
                let mut entry = entry_res.map_err(|source| BundleError::ReadArchive {
                    path: in_path.clone(),
                    source,
                })?;
                let path = entry
                    .path()
                    .map_err(|source| BundleError::ReadArchive {
                        path: in_path.clone(),
                        source,
                    })?
                    .to_string_lossy()
                    .into_owned();
                let mut bytes = Vec::new();
                entry
                    .read_to_end(&mut bytes)
                    .map_err(|source| BundleError::ReadArchive {
                        path: in_path.clone(),
                        source,
                    })?;
                out.push(BundleEntry { path, bytes });
            }
            Ok::<_, BundleError>(out)
        })
        .await
        .map_err(|err| BundleError::TaskJoin {
            detail: err.to_string(),
        })?
    }
}

fn append_tar_bytes<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    path: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, bytes)
}

fn encode_inspect_snapshot(snapshot: &SnapshotResult) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = snapshot
        .entries
        .iter()
        .map(|entry| {
            serde_json::json!({
                "path": entry.path,
                "value": encode_inspect_value(&entry.value),
            })
        })
        .collect();
    serde_json::json!({
        "timestamp": snapshot.timestamp,
        "truncated": snapshot.truncated,
        "entries": entries,
    })
}

fn encode_inspect_value(value: &inspect::Value) -> serde_json::Value {
    match value {
        inspect::Value::Boolean(v) => serde_json::Value::Bool(*v),
        inspect::Value::Signed64(v) => serde_json::json!(v),
        inspect::Value::Unsigned64(v) => serde_json::json!(v),
        inspect::Value::Float64(v) => serde_json::json!(v),
        inspect::Value::Text(v) => serde_json::Value::String(v.clone()),
        inspect::Value::Blob(v) => serde_json::json!(v),
    }
}

fn encode_instances(instances: &[Instance]) -> Vec<serde_json::Value> {
    instances
        .iter()
        .map(|inst| {
            serde_json::json!({
                "id": inst.id,
                "name": inst.name,
                "uptime_nanos": inst.uptime,
                "memory_bytes": inst.memory_bytes,
                "cpu_busy_permille": inst.cpu_busy,
            })
        })
        .collect()
}

fn encode_tracing_events(events: &[sys_tracing::Event]) -> Vec<serde_json::Value> {
    events
        .iter()
        .map(|ev| {
            let fields: serde_json::Map<String, serde_json::Value> = ev
                .fields
                .iter()
                .map(|f| {
                    let val = match &f.value {
                        sys_tracing::Value::Boolean(b) => serde_json::json!(b),
                        sys_tracing::Value::Signed64(n) => serde_json::json!(n),
                        sys_tracing::Value::Unsigned64(n) => serde_json::json!(n),
                        sys_tracing::Value::Float64(n) => serde_json::json!(n),
                        sys_tracing::Value::Text(s) => serde_json::json!(s),
                        sys_tracing::Value::Blob(b) => serde_json::json!(b),
                    };
                    (f.key.clone(), val)
                })
                .collect();
            serde_json::json!({
                "timestamp": ev.timestamp,
                "level": format!("{:?}", ev.level),
                "target": ev.target,
                "fields": fields,
            })
        })
        .collect()
}

fn encode_metrics(metrics: &[MetricSample]) -> Vec<serde_json::Value> {
    metrics
        .iter()
        .map(|m| {
            serde_json::json!({
                "scope": format!("{:?}", m.scope),
                "name": m.name,
                "count": m.count,
                "total_events": m.total_events,
                "total_nanos": m.total_nanos,
                "min_nanos": m.min_nanos,
                "max_nanos": m.max_nanos,
                "total_bytes": m.total_bytes,
            })
        })
        .collect()
}

fn encode_folded(folded: &[FoldedSample]) -> Vec<serde_json::Value> {
    folded
        .iter()
        .map(|f| {
            serde_json::json!({
                "scope": format!("{:?}", f.scope),
                "stack": f.stack,
                "weight": f.weight,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn diagnostic_bundle_round_trips_tar_zst() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("diag.tar.zst");

        let mut bundle = DiagnosticBundle::new("node-1", "helios://127.0.0.1:9443");
        bundle
            .add_json("inspect.json", &serde_json::json!({ "ok": true }))
            .expect("add json");
        bundle.add_entry("notes.txt", b"helios diagnostics".to_vec());

        bundle.write_tar_zst(&path).await.expect("write tar.zst");
        let entries = DiagnosticBundle::read_tar_zst(&path)
            .await
            .expect("read tar.zst");

        assert!(entries.iter().any(|e| e.path == "manifest.json"));
        assert!(entries.iter().any(|e| e.path == "inspect.json"));
        let notes = entries
            .iter()
            .find(|e| e.path == "notes.txt")
            .expect("notes.txt");
        assert_eq!(notes.bytes, b"helios diagnostics");
    }
}
