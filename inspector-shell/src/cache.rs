//! 1.5s TTL / 150ms-bounded remote completion cache for interactive `<Tab>` completion.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use helios_nu::{FileMetadata, FileType};
use helios_ops::Session;
use helios_wit_rpc::inspector::helios::system::tracing as sys_tracing;
use helios_wit_rpc::inspector_fs::EntryKind;
use tokio::sync::RwLock;

/// Cache TTL for remote completion metadata (1.5 seconds).
pub const COMPLETION_CACHE_TTL: Duration = Duration::from_millis(1_500);

/// Hard per-request latency ceiling for remote completion fetches (150ms).
pub const COMPLETION_REMOTE_TIMEOUT: Duration = Duration::from_millis(150);

/// Built-in kernel diagnostic targets always available for `<Tab>` completion.
const KNOWN_DIAGNOSTIC_TARGETS: &[&str] = &[
    "helios_kernel::exec::phases",
    "helios_kernel::memory",
    "helios_kernel::scheduler",
    "helios_kernel::net",
    "helios_kernel::fs",
    "helios_kernel::linux",
    "helios_kernel::hv",
];

#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    fetched_at: Instant,
}

impl<T> CacheEntry<T> {
    fn is_fresh(&self, ttl: Duration) -> bool {
        self.fetched_at.elapsed() < ttl
    }
}

#[derive(Debug, Default)]
struct CacheState {
    inspect_keys: Option<CacheEntry<Vec<String>>>,
    monikers: Option<CacheEntry<Vec<String>>>,
    diagnostic_targets: Option<CacheEntry<Vec<String>>>,
    executables: Option<CacheEntry<Vec<String>>>,
    dirs: HashMap<String, CacheEntry<Vec<FileMetadata>>>,
}

/// Shared, cheaply cloneable 1.5s TTL / 150ms-bounded remote completion cache.
#[derive(Clone)]
pub struct RemoteCompletionCache {
    ttl: Duration,
    timeout: Duration,
    state: Arc<RwLock<CacheState>>,
}

impl Default for RemoteCompletionCache {
    fn default() -> Self {
        Self::new(COMPLETION_CACHE_TTL, COMPLETION_REMOTE_TIMEOUT)
    }
}

impl RemoteCompletionCache {
    /// Create a cache with explicit TTL and remote fetch timeout bounds.
    #[must_use]
    pub fn new(ttl: Duration, timeout: Duration) -> Self {
        Self {
            ttl,
            timeout,
            state: Arc::new(RwLock::new(CacheState::default())),
        }
    }

    /// Configured cache TTL.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Configured remote fetch timeout bound.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Invalidate all cached remote completion state (e.g. after mutating VFS or killing an instance).
    pub async fn invalidate_all(&self) {
        let mut guard = self.state.write().await;
        *guard = CacheState::default();
    }

    /// Invalidate cached listing for a single VFS directory.
    pub async fn invalidate_dir(&self, dir: &str) {
        let mut guard = self.state.write().await;
        guard.dirs.remove(dir);
    }

    async fn fetch_bounded<T, F>(&self, fut: F) -> Option<T>
    where
        F: Future<Output = Result<T, helios_ops::OpsError>>,
    {
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(Ok(val)) => Some(val),
            Ok(Err(err)) => {
                tracing::debug!("remote completion fetch failed: {err}");
                None
            }
            Err(_) => {
                tracing::debug!(
                    timeout_ms = self.timeout.as_millis(),
                    "remote completion fetch hit timeout bound"
                );
                None
            }
        }
    }

    /// Fetch live `/kernel/*` and component inspect keys, cached for `ttl` and bounded by `timeout`.
    pub async fn inspect_keys(&self, session: &Session, prefix: &str) -> Vec<String> {
        let cached = {
            let guard = self.state.read().await;
            guard.inspect_keys.clone()
        };
        let keys = if let Some(entry) = cached.as_ref()
            && entry.is_fresh(self.ttl)
        {
            entry.value.clone()
        } else if let Some(snapshot) = self.fetch_bounded(session.inspect(&[], 0)).await {
            let mut set = BTreeSet::new();
            for entry in snapshot.entries {
                // Include intermediate parent prefixes (e.g. `/kernel/memory`) so tabbing drills down cleanly.
                let parts = entry.path.split('/').filter(|p| !p.is_empty());
                let mut accum = String::new();
                for part in parts {
                    accum.push('/');
                    accum.push_str(part);
                    set.insert(accum.clone());
                }
                set.insert(entry.path);
            }
            for pub_entry in snapshot.publications {
                if !pub_entry.instance_name.is_empty() {
                    set.insert(format!("/{}", pub_entry.instance_name));
                    if !pub_entry.name.is_empty() {
                        set.insert(format!("/{}/{}", pub_entry.instance_name, pub_entry.name));
                    }
                }
            }
            let list: Vec<String> = set.into_iter().collect();
            let mut guard = self.state.write().await;
            guard.inspect_keys = Some(CacheEntry {
                value: list.clone(),
                fetched_at: Instant::now(),
            });
            list
        } else {
            cached.map_or_else(Vec::new, |c| c.value)
        };

        keys.into_iter().filter(|k| k.starts_with(prefix)).collect()
    }

    /// Fetch live component monikers / instance names, cached for `ttl` and bounded by `timeout`.
    pub async fn monikers(&self, session: &Session) -> Vec<String> {
        let cached = {
            let guard = self.state.read().await;
            guard.monikers.clone()
        };
        if let Some(entry) = cached.as_ref()
            && entry.is_fresh(self.ttl)
        {
            return entry.value.clone();
        }
        if let Some(instances) = self.fetch_bounded(session.instances()).await {
            let mut set = BTreeSet::new();
            for inst in instances {
                if !inst.name.is_empty() {
                    if inst.name.starts_with('/') {
                        set.insert(inst.name);
                    } else {
                        set.insert(format!("/{}", inst.name));
                    }
                }
            }
            let list: Vec<String> = set.into_iter().collect();
            let mut guard = self.state.write().await;
            guard.monikers = Some(CacheEntry {
                value: list.clone(),
                fetched_at: Instant::now(),
            });
            return list;
        }
        cached.map_or_else(Vec::new, |c| c.value)
    }

    /// Fetch live diagnostic targets (built-in known targets + recently observed tracing targets).
    pub async fn diagnostic_targets(&self, session: &Session) -> Vec<String> {
        let cached = {
            let guard = self.state.read().await;
            guard.diagnostic_targets.clone()
        };
        if let Some(entry) = cached.as_ref()
            && entry.is_fresh(self.ttl)
        {
            return entry.value.clone();
        }

        let mut set: BTreeSet<String> = KNOWN_DIAGNOSTIC_TARGETS
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let filter = sys_tracing::Filter {
            min_level: Some(sys_tracing::Level::Trace),
            target_prefixes: Vec::new(),
        };
        if let Some(events) = self.fetch_bounded(session.trace_recent(&filter, 64)).await {
            for ev in events {
                if !ev.target.is_empty() {
                    set.insert(ev.target);
                }
            }
        }
        let list: Vec<String> = set.into_iter().collect();
        let mut guard = self.state.write().await;
        guard.diagnostic_targets = Some(CacheEntry {
            value: list.clone(),
            fetched_at: Instant::now(),
        });
        list
    }

    /// Fetch live executables from `/bin`, cached for `ttl` and bounded by `timeout`.
    pub async fn executables(&self, session: &Session) -> Vec<String> {
        let cached = {
            let guard = self.state.read().await;
            guard.executables.clone()
        };
        if let Some(entry) = cached.as_ref()
            && entry.is_fresh(self.ttl)
        {
            return entry.value.clone();
        }
        if let Some(entries) = self.fetch_bounded(session.list_dir("/bin")).await {
            let list: Vec<String> = entries
                .into_iter()
                .filter(|e| e.kind == EntryKind::File)
                .map(|e| e.name)
                .collect();
            let mut guard = self.state.write().await;
            guard.executables = Some(CacheEntry {
                value: list.clone(),
                fetched_at: Instant::now(),
            });
            return list;
        }
        cached.map_or_else(Vec::new, |c| c.value)
    }

    /// Fetch live VFS directory entries for `dir`, cached for `ttl` and bounded by `timeout`.
    pub async fn list_dir(&self, session: &Session, dir: &str) -> Vec<FileMetadata> {
        let cached = {
            let guard = self.state.read().await;
            guard.dirs.get(dir).cloned()
        };
        if let Some(entry) = cached.as_ref()
            && entry.is_fresh(self.ttl)
        {
            return entry.value.clone();
        }
        if let Some(entries) = self.fetch_bounded(session.list_dir(dir)).await {
            let list: Vec<FileMetadata> = entries
                .into_iter()
                .map(|entry| FileMetadata {
                    path: entry.path,
                    name: entry.name,
                    file_type: match entry.kind {
                        EntryKind::Directory => FileType::Dir,
                        EntryKind::File | EntryKind::Other => FileType::File,
                    },
                    size: 0,
                    modified: None,
                    readonly: false,
                    target: None,
                })
                .collect();
            let mut guard = self.state.write().await;
            guard.dirs.insert(
                dir.to_owned(),
                CacheEntry {
                    value: list.clone(),
                    fetched_at: Instant::now(),
                },
            );
            return list;
        }
        cached.map_or_else(Vec::new, |c| c.value)
    }
}
