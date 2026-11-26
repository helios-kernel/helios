//! Bounded-concurrency fleet orchestration returning typed [`NodeOutcome`] values.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use helios_oci::PulledImage;
use helios_wit_rpc::inspector::helios::system::{
    component_control::ComponentStatus, inspect::SnapshotResult, instances::Instance,
    programs::ExecResult,
};
use tokio::sync::Semaphore;

use crate::bundle::DiagnosticBundle;
use crate::error::OpsError;
use crate::oci::{DEFAULT_REMOTE_OCI_STORE, PullOptions};
use crate::session::{Session, SessionOptions};
use crate::target::Target;

/// Default maximum number of concurrent node operations in a [`Fleet`] fan-out.
pub const DEFAULT_FLEET_CONCURRENCY: usize = 16;

/// Result of running a single fleet operation against one node.
#[derive(Debug)]
pub struct NodeOutcome<T> {
    pub target: Target,
    pub elapsed: Duration,
    pub result: Result<T, OpsError>,
}

impl<T> NodeOutcome<T> {
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result.is_ok()
    }
}

/// Multi-node fleet handle supporting bounded-concurrency async fan-out.
#[derive(Clone)]
pub struct Fleet {
    targets: Vec<Target>,
    existing_sessions: Vec<Session>,
    concurrency: usize,
    options: SessionOptions,
}

impl Fleet {
    /// Construct a [`Fleet`] over `targets` with a bounded concurrency limit.
    #[must_use]
    pub fn new(targets: Vec<Target>, concurrency: usize, options: SessionOptions) -> Self {
        Self {
            targets,
            existing_sessions: Vec::new(),
            concurrency: concurrency.max(1),
            options,
        }
    }

    /// Construct a single-node [`Fleet`] backed by an already-connected [`Session`].
    #[must_use]
    pub fn from_sessions(sessions: Vec<Session>, concurrency: usize) -> Self {
        let targets = sessions.iter().map(|s| s.target().clone()).collect();
        let options = sessions
            .first()
            .map_or_else(SessionOptions::default, |s| s.options().clone());
        Self {
            targets,
            existing_sessions: sessions,
            concurrency: concurrency.max(1),
            options,
        }
    }

    /// Targets in this fleet.
    #[must_use]
    pub fn targets(&self) -> &[Target] {
        &self.targets
    }

    /// Maximum concurrent node operations permitted.
    #[must_use]
    pub const fn concurrency(&self) -> usize {
        self.concurrency
    }

    /// Fan out an async closure `op` across every node in the fleet under the
    /// configured concurrency bound, preserving input target ordering.
    pub async fn run<F, Fut, T>(&self, op: F) -> Vec<NodeOutcome<T>>
    where
        F: Fn(Session) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<T, OpsError>> + Send + 'static,
        T: Send + 'static,
    {
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let op = Arc::new(op);
        let mut handles = Vec::with_capacity(self.targets.len());

        for (idx, target) in self.targets.iter().cloned().enumerate() {
            let permit_sem = Arc::clone(&semaphore);
            let op_fn = Arc::clone(&op);
            let options = self.options.clone();
            let preconnected = self.existing_sessions.get(idx).cloned();

            handles.push(tokio::spawn(async move {
                let _permit = permit_sem
                    .acquire_owned()
                    .await
                    .expect("fleet semaphore is never closed while tasks hold Arc");
                let started = Instant::now();
                let session = match preconnected {
                    Some(session) => Ok(session),
                    None => Session::connect(&target, options).await,
                };
                let result = match session {
                    Ok(session) => op_fn(session).await,
                    Err(err) => Err(err),
                };
                NodeOutcome {
                    target,
                    elapsed: started.elapsed(),
                    result,
                }
            }));
        }

        let mut outcomes = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(outcome) => outcomes.push(outcome),
                Err(err) => {
                    tracing::error!("fleet worker task failed: {err}");
                }
            }
        }
        outcomes
    }

    /// Run `inspect` across every node in the fleet.
    pub async fn inspect(
        &self,
        prefixes: Vec<String>,
        limit: u32,
    ) -> Vec<NodeOutcome<SnapshotResult>> {
        self.run(move |session| {
            let prefixes = prefixes.clone();
            async move {
                let refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
                session.inspect(&refs, limit).await
            }
        })
        .await
    }

    /// Run `ps` / `instances` across every node in the fleet.
    pub async fn ps(&self) -> Vec<NodeOutcome<Vec<Instance>>> {
        self.run(|session| async move { session.ps().await }).await
    }

    /// Execute a program across every node in the fleet.
    pub async fn exec(&self, path: String, args: Vec<String>) -> Vec<NodeOutcome<ExecResult>> {
        self.run(move |session| {
            let path = path.clone();
            let args = args.clone();
            async move { session.exec(&path, &args).await }
        })
        .await
    }

    /// Collect diagnostic bundles from every node in the fleet.
    pub async fn collect_bundles(&self) -> Vec<NodeOutcome<DiagnosticBundle>> {
        self.run(|session| async move { DiagnosticBundle::collect(&session).await })
            .await
    }

    /// Component-control fan-out helpers (`fleet.components()`).
    #[must_use]
    pub fn components(&self) -> FleetComponents {
        FleetComponents {
            fleet: self.clone(),
        }
    }

    /// OCI image management fan-out helpers (`fleet.oci()`).
    #[must_use]
    pub fn oci(&self) -> FleetOci {
        FleetOci {
            fleet: self.clone(),
            store_root: DEFAULT_REMOTE_OCI_STORE.to_owned(),
        }
    }
}

/// Bounded-concurrency component-control fan-out over a [`Fleet`].
#[derive(Clone)]
pub struct FleetComponents {
    fleet: Fleet,
}

impl FleetComponents {
    /// List components across every node in the fleet.
    pub async fn list(&self) -> Vec<NodeOutcome<Vec<ComponentStatus>>> {
        self.fleet
            .run(|session| async move { session.components().list().await })
            .await
    }

    /// Fetch the status of `moniker` across every node in the fleet.
    pub async fn status(&self, moniker: String) -> Vec<NodeOutcome<ComponentStatus>> {
        self.fleet
            .run(move |session| {
                let moniker = moniker.clone();
                async move { session.components().status(&moniker).await }
            })
            .await
    }

    /// Start `moniker` across every node in the fleet.
    pub async fn start(&self, moniker: String) -> Vec<NodeOutcome<ComponentStatus>> {
        self.fleet
            .run(move |session| {
                let moniker = moniker.clone();
                async move { session.components().start(&moniker).await }
            })
            .await
    }

    /// Stop `moniker` across every node in the fleet.
    pub async fn stop(&self, moniker: String) -> Vec<NodeOutcome<()>> {
        self.fleet
            .run(move |session| {
                let moniker = moniker.clone();
                async move { session.components().stop(&moniker).await }
            })
            .await
    }

    /// Restart `moniker` across every node in the fleet.
    pub async fn restart(&self, moniker: String) -> Vec<NodeOutcome<ComponentStatus>> {
        self.fleet
            .run(move |session| {
                let moniker = moniker.clone();
                async move { session.components().restart(&moniker).await }
            })
            .await
    }

    /// Mount a dynamic component subtree under `parent_moniker` across every node in the fleet.
    pub async fn mount_dynamic(
        &self,
        parent_moniker: String,
        source: helios_wit_rpc::inspector::helios::system::component_control::DynamicSubtreeSource,
    ) -> Vec<NodeOutcome<String>> {
        self.fleet
            .run(move |session| {
                let parent_moniker = parent_moniker.clone();
                let source = source.clone();
                async move {
                    session
                        .components()
                        .mount_dynamic(&parent_moniker, source)
                        .await
                }
            })
            .await
    }

    /// Gracefully stop and unmount a previously mounted dynamic subtree across every node in the fleet.
    pub async fn unmount_dynamic(&self, moniker: String) -> Vec<NodeOutcome<()>> {
        self.fleet
            .run(move |session| {
                let moniker = moniker.clone();
                async move { session.components().unmount_dynamic(&moniker).await }
            })
            .await
    }
}

/// Bounded-concurrency OCI image management fan-out over a [`Fleet`].
#[derive(Clone)]
pub struct FleetOci {
    fleet: Fleet,
    store_root: String,
}

impl FleetOci {
    /// Target a custom guest OCI store root path on every node.
    #[must_use]
    pub fn with_store_root(mut self, store_root: impl Into<String>) -> Self {
        self.store_root = store_root.into();
        self
    }

    /// Pull `reference` onto every node in the fleet.
    pub async fn pull(&self, reference: String) -> Vec<NodeOutcome<PulledImage>> {
        self.pull_with_options(reference, PullOptions::default())
            .await
    }

    /// Pull `reference` with explicit [`PullOptions`] onto every node in the fleet.
    pub async fn pull_with_options(
        &self,
        reference: String,
        options: PullOptions,
    ) -> Vec<NodeOutcome<PulledImage>> {
        let store_root = self.store_root.clone();
        self.fleet
            .run(move |session| {
                let reference = reference.clone();
                let options = options.clone();
                let store_root = store_root.clone();
                async move {
                    session
                        .oci_with_store_root(&store_root)?
                        .pull_with_options(&reference, options)
                        .await
                }
            })
            .await
    }

    /// List pulled OCI images on every node in the fleet.
    pub async fn list(&self) -> Vec<NodeOutcome<Vec<PulledImage>>> {
        let store_root = self.store_root.clone();
        self.fleet
            .run(move |session| {
                let store_root = store_root.clone();
                async move { session.oci_with_store_root(&store_root)?.list().await }
            })
            .await
    }

    /// Inspect `reference` on every node in the fleet.
    pub async fn inspect(&self, reference: String) -> Vec<NodeOutcome<PulledImage>> {
        let store_root = self.store_root.clone();
        self.fleet
            .run(move |session| {
                let reference = reference.clone();
                let store_root = store_root.clone();
                async move {
                    session
                        .oci_with_store_root(&store_root)?
                        .inspect(&reference)
                        .await
                }
            })
            .await
    }

    /// Remove `reference` from every node in the fleet.
    pub async fn remove(&self, reference: String) -> Vec<NodeOutcome<PulledImage>> {
        let store_root = self.store_root.clone();
        self.fleet
            .run(move |session| {
                let reference = reference.clone();
                let store_root = store_root.clone();
                async move {
                    session
                        .oci_with_store_root(&store_root)?
                        .remove(&reference)
                        .await
                }
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::transport::RpcConnection;
    use async_io::Async;
    use std::os::unix::net::UnixStream;

    #[tokio::test]
    async fn fleet_fanout_enforces_concurrency_bound() {
        let mut sessions = Vec::new();
        for idx in 0..6 {
            let (host, _guest) = UnixStream::pair().expect("socket pair");
            host.set_nonblocking(true).expect("nonblocking");
            let read = host.try_clone().expect("clone");
            let conn = RpcConnection::from_split(
                Box::new(Async::new(read).expect("async read")),
                Box::new(Async::new(host).expect("async write")),
            );
            let target = Target::new(format!("node-{idx}"), "serial:///dev/null").expect("target");
            sessions.push(Session::from_connection(
                target,
                conn,
                SessionOptions::default(),
            ));
        }

        let fleet = Fleet::from_sessions(sessions, 2);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let in_flight_clone = Arc::clone(&in_flight);
        let max_seen_clone = Arc::clone(&max_seen);
        let outcomes = fleet
            .run(move |session| {
                let in_flight = Arc::clone(&in_flight_clone);
                let max_seen = Arc::clone(&max_seen_clone);
                async move {
                    let cur = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_seen.fetch_max(cur, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    Ok(session.target().name.clone())
                }
            })
            .await;

        assert_eq!(outcomes.len(), 6);
        assert!(outcomes.iter().all(NodeOutcome::is_ok));
        assert!(
            max_seen.load(Ordering::SeqCst) <= 2,
            "fleet exceeded concurrency bound: {}",
            max_seen.load(Ordering::SeqCst)
        );
    }
}
