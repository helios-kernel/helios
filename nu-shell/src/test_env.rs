//! In-memory [`HeliosEnv`] implementation for unit and integration testing.

use core::time::Duration;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, FixedOffset, Utc};

use crate::env::{
    ExecutableMatch, ExternalProcess, ExternalSpawnRequest, FileMetadata, FileType, GrantSpec,
    HeliosEnv, InspectEntry, InspectValue, InstructionProfileSummary, ProcessInfo,
    STREAM_CHANNEL_CAPACITY, SnapshotInfo, SysCpuInfo, SysDiskInfo, SysHostInfo, SysMemInfo,
    SysNetInfo, WatchEvent, normalize_vfs_path,
};
use crate::error::EnvError;

#[derive(Debug, Clone)]
enum VfsNode {
    File {
        bytes: Vec<u8>,
        modified: DateTime<FixedOffset>,
    },
    Dir {
        modified: DateTime<FixedOffset>,
    },
}

/// Recorded external command invocation for assertions in tests.
#[derive(Debug, Clone)]
pub struct RecordedExternal {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub grants: Vec<GrantSpec>,
    pub scope: Option<String>,
    pub stdin: Vec<u8>,
}

/// Recorded kill invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedKill {
    pub pid: u64,
    pub signal: Option<String>,
    pub force: bool,
}

#[derive(Debug)]
struct TestState {
    cwd: String,
    vfs: BTreeMap<String, VfsNode>,
    executables: BTreeMap<String, String>,
    cpus: Vec<SysCpuInfo>,
    mem: SysMemInfo,
    net: Vec<SysNetInfo>,
    disks: Vec<SysDiskInfo>,
    host: SysHostInfo,
    inspect_entries: Vec<InspectEntry>,
    processes: Vec<ProcessInfo>,
    diagnostic_targets: Vec<String>,
    oci_refs: Vec<String>,
    whoami: String,
    cleared: usize,
    slept: Vec<Duration>,
    kills: Vec<RecordedKill>,
    externals: Vec<RecordedExternal>,
    scopes_entered: Vec<String>,
    scopes_left: Vec<String>,
    snapshots: Vec<SnapshotInfo>,
    released_snapshots: Vec<String>,
    stdout_log: Vec<u8>,
    stderr_log: Vec<u8>,
    profile_handles: usize,
    watch_events: BTreeMap<String, Vec<WatchEvent>>,
}

/// Rich in-memory [`HeliosEnv`] for testing every command and pipeline stage
/// without touching the host OS filesystem or processes.
#[derive(Debug, Clone)]
pub struct TestHeliosEnv {
    state: Arc<Mutex<TestState>>,
}

impl Default for TestHeliosEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl TestHeliosEnv {
    #[must_use]
    pub fn new() -> Self {
        let now: DateTime<FixedOffset> = Utc::now().into();
        let mut vfs = BTreeMap::new();
        vfs.insert(String::from("/"), VfsNode::Dir { modified: now });
        vfs.insert(String::from("/bin"), VfsNode::Dir { modified: now });
        vfs.insert(String::from("/etc"), VfsNode::Dir { modified: now });
        vfs.insert(String::from("/tmp"), VfsNode::Dir { modified: now });

        let mut executables = BTreeMap::new();
        executables.insert(String::from("echo-ext"), String::from("/bin/echo-ext"));
        executables.insert(String::from("upper-pipe"), String::from("/bin/upper-pipe"));
        executables.insert(String::from("fail-ext"), String::from("/bin/fail-ext"));

        let state = TestState {
            cwd: String::from("/"),
            vfs,
            executables,
            cpus: vec![
                SysCpuInfo {
                    name: String::from("cpu0"),
                    brand: String::from("Helios Virtual Core"),
                    vendor_id: String::from("Helios"),
                    freq_mhz: 3200,
                    cpu_usage: Some(12.5),
                    load_average: String::from("0.25, 0.20, 0.15"),
                },
                SysCpuInfo {
                    name: String::from("cpu1"),
                    brand: String::from("Helios Virtual Core"),
                    vendor_id: String::from("Helios"),
                    freq_mhz: 3200,
                    cpu_usage: Some(8.0),
                    load_average: String::from("0.25, 0.20, 0.15"),
                },
            ],
            mem: SysMemInfo {
                total: 2 * 1024 * 1024 * 1024,
                free: 1024 * 1024 * 1024,
                used: 1024 * 1024 * 1024,
                available: 1536 * 1024 * 1024,
                swap_total: 0,
                swap_free: 0,
                swap_used: 0,
            },
            net: vec![SysNetInfo {
                name: String::from("eth0"),
                mac: String::from("52:54:00:12:34:56"),
                ip: vec![String::from("10.0.2.15")],
                sent: 4096,
                recv: 8192,
            }],
            disks: vec![SysDiskInfo {
                device: String::from("virtio-blk0"),
                kind: String::from("btrfs"),
                mount: String::from("/"),
                total: 16 * 1024 * 1024 * 1024,
                free: 12 * 1024 * 1024 * 1024,
                removable: false,
            }],
            host: SysHostInfo {
                name: String::from("Helios"),
                os_version: String::from("0.1.0"),
                long_os_version: String::from("Helios 0.1.0"),
                kernel_version: String::from("0.1.0-test"),
                hostname: String::from("helios-test"),
                uptime: Duration::from_secs(42),
                boot_time: Some(now),
            },
            inspect_entries: vec![
                InspectEntry {
                    path: String::from("kernel/scheduler/tasks"),
                    moniker: String::from("/kernel"),
                    value: InspectValue::Uint(7),
                },
                InspectEntry {
                    path: String::from("net/virtio/rx_packets"),
                    moniker: String::from("/sys/net"),
                    value: InspectValue::Uint(1024),
                },
                InspectEntry {
                    path: String::from("http/pool/active"),
                    moniker: String::from("/plugins/http-client"),
                    value: InspectValue::Uint(2),
                },
            ],
            processes: vec![
                ProcessInfo {
                    pid: 1,
                    ppid: 0,
                    moniker: String::from("/init"),
                    name: String::from("init"),
                    status: String::from("running"),
                    cpu: 0.5,
                    mem: 4 * 1024 * 1024,
                    virtual_mem: 16 * 1024 * 1024,
                    command: String::from("/bin/init"),
                },
                ProcessInfo {
                    pid: 2,
                    ppid: 1,
                    moniker: String::from("/plugins/http-client"),
                    name: String::from("http-client"),
                    status: String::from("running"),
                    cpu: 1.2,
                    mem: 8 * 1024 * 1024,
                    virtual_mem: 32 * 1024 * 1024,
                    command: String::from("/bin/http-client"),
                },
            ],
            diagnostic_targets: vec![
                String::from("kernel/executor"),
                String::from("plugins/compiler"),
                String::from("plugins/http-client"),
            ],
            oci_refs: vec![
                String::from("docker.io/library/alpine:3.21"),
                String::from("ghcr.io/helios/base:latest"),
            ],
            whoami: String::from("helios-root"),
            cleared: 0,
            slept: Vec::new(),
            kills: Vec::new(),
            externals: Vec::new(),
            scopes_entered: Vec::new(),
            scopes_left: Vec::new(),
            snapshots: Vec::new(),
            released_snapshots: Vec::new(),
            stdout_log: Vec::new(),
            stderr_log: Vec::new(),
            profile_handles: 0,
            watch_events: BTreeMap::new(),
        };

        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn insert_file(&self, path: &str, bytes: impl Into<Vec<u8>>) {
        let mut st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path("/", path);
        let now: DateTime<FixedOffset> = Utc::now().into();
        ensure_parents(&mut st.vfs, &norm, now);
        st.vfs.insert(
            norm,
            VfsNode::File {
                bytes: bytes.into(),
                modified: now,
            },
        );
    }

    pub fn set_watch_events(&self, path: &str, events: Vec<WatchEvent>) {
        let mut st = self.state.lock().expect("test env lock");
        st.watch_events
            .insert(normalize_vfs_path("/", path), events);
    }

    #[must_use]
    pub fn recorded_externals(&self) -> Vec<RecordedExternal> {
        self.state.lock().expect("test env lock").externals.clone()
    }

    #[must_use]
    pub fn recorded_kills(&self) -> Vec<RecordedKill> {
        self.state.lock().expect("test env lock").kills.clone()
    }

    #[must_use]
    pub fn recorded_sleeps(&self) -> Vec<Duration> {
        self.state.lock().expect("test env lock").slept.clone()
    }

    #[must_use]
    pub fn clear_count(&self) -> usize {
        self.state.lock().expect("test env lock").cleared
    }

    #[must_use]
    pub fn recorded_scopes(&self) -> (Vec<String>, Vec<String>) {
        let st = self.state.lock().expect("test env lock");
        (st.scopes_entered.clone(), st.scopes_left.clone())
    }

    #[must_use]
    pub fn recorded_snapshots(&self) -> Vec<SnapshotInfo> {
        self.state.lock().expect("test env lock").snapshots.clone()
    }

    #[must_use]
    pub fn released_snapshots(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("test env lock")
            .released_snapshots
            .clone()
    }

    #[must_use]
    pub fn recorded_stdout(&self) -> String {
        String::from_utf8_lossy(&self.state.lock().expect("test env lock").stdout_log).into_owned()
    }

    #[must_use]
    pub fn recorded_stderr(&self) -> String {
        String::from_utf8_lossy(&self.state.lock().expect("test env lock").stderr_log).into_owned()
    }

    #[must_use]
    pub fn read_vfs_bytes(&self, path: &str) -> Option<Vec<u8>> {
        let st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path("/", path);
        match st.vfs.get(&norm) {
            Some(VfsNode::File { bytes, .. }) => Some(bytes.clone()),
            _ => None,
        }
    }
}

fn ensure_parents(vfs: &mut BTreeMap<String, VfsNode>, path: &str, now: DateTime<FixedOffset>) {
    let mut current = String::new();
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() <= 1 {
        return;
    }
    for seg in &segments[..segments.len() - 1] {
        current.push('/');
        current.push_str(seg);
        vfs.entry(current.clone())
            .or_insert(VfsNode::Dir { modified: now });
    }
}

fn node_metadata(path: &str, node: &VfsNode) -> FileMetadata {
    let name = if path == "/" {
        String::from("/")
    } else {
        path.rsplit('/').next().unwrap_or(path).to_owned()
    };
    match node {
        VfsNode::File { bytes, modified } => FileMetadata {
            path: path.to_owned(),
            name,
            file_type: FileType::File,
            size: bytes.len() as u64,
            modified: Some(*modified),
            readonly: false,
            target: None,
        },
        VfsNode::Dir { modified } => FileMetadata {
            path: path.to_owned(),
            name,
            file_type: FileType::Dir,
            size: 0,
            modified: Some(*modified),
            readonly: false,
            target: None,
        },
    }
}

impl HeliosEnv for TestHeliosEnv {
    async fn cwd(&self) -> Result<String, EnvError> {
        Ok(self.state.lock().expect("test env lock").cwd.clone())
    }

    async fn set_cwd(&self, path: &str) -> Result<String, EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path(&st.cwd, path);
        match st.vfs.get(&norm) {
            Some(VfsNode::Dir { .. }) => {
                st.cwd.clone_from(&norm);
                Ok(norm)
            }
            Some(VfsNode::File { .. }) => Err(EnvError::NotADirectory { path: norm }),
            None => Err(EnvError::NotFound { path: norm }),
        }
    }

    async fn spawn_external(
        &self,
        request: ExternalSpawnRequest,
    ) -> Result<ExternalProcess, EnvError> {
        let stdin_bytes = if let Some(rx) = request.stdin {
            let mut buf = Vec::new();
            while let Ok(chunk) = rx.recv().await {
                if let Ok(bytes) = chunk {
                    buf.extend_from_slice(&bytes);
                }
            }
            buf
        } else {
            Vec::new()
        };

        let prog_name = request
            .program
            .rsplit('/')
            .next()
            .unwrap_or(&request.program);

        {
            let mut st = self.state.lock().expect("test env lock");
            st.externals.push(RecordedExternal {
                program: request.program.clone(),
                args: request.args.clone(),
                cwd: request.cwd.clone(),
                grants: request.grants.clone(),
                scope: request.scope.clone(),
                stdin: stdin_bytes.clone(),
            });
        }

        let (out_tx, out_rx) = if request.capture_stdout {
            let (tx, rx) = async_channel::bounded(STREAM_CHANNEL_CAPACITY);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let (err_tx, err_rx) = if request.capture_stderr {
            let (tx, rx) = async_channel::bounded(STREAM_CHANNEL_CAPACITY);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let (code_tx, code_rx) = async_channel::bounded(1);

        match prog_name {
            "echo-ext" => {
                let text = format!("{}\n", request.args.join(" "));
                if let Some(tx) = out_tx {
                    // Stream in multiple chunks to verify chunked async streaming.
                    for chunk in text.as_bytes().chunks(4) {
                        let _ = tx.send(Ok(chunk.to_vec())).await;
                    }
                } else {
                    self.state
                        .lock()
                        .expect("test env lock")
                        .stdout_log
                        .extend_from_slice(text.as_bytes());
                }
                let _ = code_tx.send(Ok(0)).await;
            }
            "upper-pipe" => {
                let upper = String::from_utf8_lossy(&stdin_bytes).to_uppercase();
                if let Some(tx) = out_tx {
                    for chunk in upper.as_bytes().chunks(8) {
                        let _ = tx.send(Ok(chunk.to_vec())).await;
                    }
                } else {
                    self.state
                        .lock()
                        .expect("test env lock")
                        .stdout_log
                        .extend_from_slice(upper.as_bytes());
                }
                let _ = code_tx.send(Ok(0)).await;
            }
            "fail-ext" => {
                if let Some(tx) = out_tx {
                    let _ = tx.send(Ok(b"partial-out".to_vec())).await;
                } else {
                    self.state
                        .lock()
                        .expect("test env lock")
                        .stdout_log
                        .extend_from_slice(b"partial-out");
                }
                if let Some(tx) = err_tx {
                    let _ = tx.send(Ok(b"boom-stderr".to_vec())).await;
                } else {
                    self.state
                        .lock()
                        .expect("test env lock")
                        .stderr_log
                        .extend_from_slice(b"boom-stderr");
                }
                let _ = code_tx.send(Ok(7)).await;
            }
            "async-missing" => {
                let _ = code_tx
                    .send(Err(EnvError::NotFound {
                        path: "/bin/async-missing".to_owned(),
                    }))
                    .await;
            }
            #[cfg(not(target_arch = "wasm32"))]
            "big-out-then-err" => {
                // Simulate a real WASI child that emits more than
                // `STREAM_CHANNEL_CAPACITY` stdout chunks before writing and
                // closing stderr; sequential stderr-before-stdout draining
                // would deadlock on channel backpressure.
                let state_bg = Arc::clone(&self.state);
                let out_tx_bg = out_tx;
                let err_tx_bg = err_tx;
                let code_tx_bg = code_tx;
                std::thread::spawn(move || {
                    for _ in 0..(STREAM_CHANNEL_CAPACITY * 4) {
                        if let Some(tx) = &out_tx_bg {
                            if tx.send_blocking(Ok(b"1234".to_vec())).is_err() {
                                return;
                            }
                        } else {
                            state_bg
                                .lock()
                                .expect("test env lock")
                                .stdout_log
                                .extend_from_slice(b"1234");
                        }
                    }
                    if let Some(tx) = err_tx_bg {
                        let _ = tx.send_blocking(Ok(b"late-stderr".to_vec()));
                    } else {
                        state_bg
                            .lock()
                            .expect("test env lock")
                            .stderr_log
                            .extend_from_slice(b"late-stderr");
                    }
                    let _ = code_tx_bg.send_blocking(Ok(0));
                });
            }
            other => {
                return Err(EnvError::NotFound {
                    path: other.to_owned(),
                });
            }
        }

        Ok(ExternalProcess {
            stdout: out_rx,
            stderr: err_rx,
            exit_code: code_rx,
        })
    }

    async fn resolve_executable(
        &self,
        name: &str,
        _path_env: &[String],
    ) -> Result<Option<ExecutableMatch>, EnvError> {
        let st = self.state.lock().expect("test env lock");
        let short = name.rsplit('/').next().unwrap_or(name);
        Ok(st.executables.get(short).map(|path| ExecutableMatch {
            command: name.to_owned(),
            path: path.clone(),
        }))
    }

    async fn list_executables(&self) -> Result<Vec<String>, EnvError> {
        let st = self.state.lock().expect("test env lock");
        Ok(st.executables.keys().cloned().collect())
    }

    async fn sys_cpu(&self, _long: bool) -> Result<Vec<SysCpuInfo>, EnvError> {
        Ok(self.state.lock().expect("test env lock").cpus.clone())
    }

    async fn sys_mem(&self) -> Result<SysMemInfo, EnvError> {
        Ok(self.state.lock().expect("test env lock").mem.clone())
    }

    async fn sys_net(&self) -> Result<Vec<SysNetInfo>, EnvError> {
        Ok(self.state.lock().expect("test env lock").net.clone())
    }

    async fn sys_disks(&self) -> Result<Vec<SysDiskInfo>, EnvError> {
        Ok(self.state.lock().expect("test env lock").disks.clone())
    }

    async fn sys_host(&self) -> Result<SysHostInfo, EnvError> {
        Ok(self.state.lock().expect("test env lock").host.clone())
    }

    async fn inspect(&self, path: Option<&str>) -> Result<Vec<InspectEntry>, EnvError> {
        let st = self.state.lock().expect("test env lock");
        Ok(match path {
            None => st.inspect_entries.clone(),
            Some(prefix) => st
                .inspect_entries
                .iter()
                .filter(|e| e.path.starts_with(prefix) || e.moniker.starts_with(prefix))
                .cloned()
                .collect(),
        })
    }

    async fn list_processes(&self) -> Result<Vec<ProcessInfo>, EnvError> {
        Ok(self.state.lock().expect("test env lock").processes.clone())
    }

    async fn kill_process(
        &self,
        pid: u64,
        signal: Option<&str>,
        force: bool,
    ) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        if !st.processes.iter().any(|p| p.pid == pid) {
            return Err(EnvError::NotFound {
                path: format!("pid:{pid}"),
            });
        }
        st.kills.push(RecordedKill {
            pid,
            signal: signal.map(ToOwned::to_owned),
            force,
        });
        Ok(())
    }

    async fn whoami(&self) -> Result<String, EnvError> {
        Ok(self.state.lock().expect("test env lock").whoami.clone())
    }

    async fn sleep(&self, duration: Duration) -> Result<(), EnvError> {
        self.state
            .lock()
            .expect("test env lock")
            .slept
            .push(duration);
        futures_lite::future::yield_now().await;
        Ok(())
    }

    async fn clear(&self) -> Result<(), EnvError> {
        self.state.lock().expect("test env lock").cleared += 1;
        Ok(())
    }

    async fn write_stdout(&self, bytes: &[u8]) -> Result<(), EnvError> {
        self.state
            .lock()
            .expect("test env lock")
            .stdout_log
            .extend_from_slice(bytes);
        Ok(())
    }

    async fn write_stderr(&self, bytes: &[u8]) -> Result<(), EnvError> {
        self.state
            .lock()
            .expect("test env lock")
            .stderr_log
            .extend_from_slice(bytes);
        Ok(())
    }

    async fn enter_scope(&self, scope: &str) -> Result<String, EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        st.scopes_entered.push(scope.to_owned());
        Ok(scope.to_owned())
    }

    async fn leave_scope(&self, scope: &str) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        st.scopes_left.push(scope.to_owned());
        Ok(())
    }

    async fn take_snapshot(
        &self,
        name: &str,
        moniker: Option<&str>,
    ) -> Result<SnapshotInfo, EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let id = format!("snap-{}", st.snapshots.len() + 1);
        let info = SnapshotInfo {
            id,
            name: name.to_owned(),
            moniker: moniker.map(ToOwned::to_owned),
        };
        st.snapshots.push(info.clone());
        Ok(info)
    }

    async fn release_snapshot(&self, id: &str) -> Result<(), EnvError> {
        self.state
            .lock()
            .expect("test env lock")
            .released_snapshots
            .push(id.to_owned());
        Ok(())
    }

    async fn begin_instruction_profile(&self, target: Option<&str>) -> Result<String, EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        st.profile_handles += 1;
        let t = target.unwrap_or("self");
        Ok(format!("{t}#{}", st.profile_handles))
    }

    async fn end_instruction_profile(
        &self,
        handle: &str,
    ) -> Result<InstructionProfileSummary, EnvError> {
        let target = handle.split('#').next().unwrap_or("self").to_owned();
        Ok(InstructionProfileSummary {
            target,
            instructions: 12_345,
            cycles: 24_690,
            samples: 12,
            elapsed: Duration::from_micros(500),
        })
    }

    async fn list_dir(&self, path: &str) -> Result<Vec<FileMetadata>, EnvError> {
        let st = self.state.lock().expect("test env lock");
        let dir = normalize_vfs_path("/", path);
        match st.vfs.get(&dir) {
            Some(VfsNode::Dir { .. }) => {}
            Some(VfsNode::File { .. }) => return Err(EnvError::NotADirectory { path: dir }),
            None => return Err(EnvError::NotFound { path: dir }),
        }

        let prefix = if dir == "/" {
            String::from("/")
        } else {
            format!("{dir}/")
        };

        let mut entries = Vec::new();
        for (entry_path, node) in &st.vfs {
            if entry_path == &dir {
                continue;
            }
            if let Some(rest) = entry_path.strip_prefix(&prefix)
                && !rest.contains('/')
            {
                entries.push(node_metadata(entry_path, node));
            }
        }
        Ok(entries)
    }

    async fn stat(&self, path: &str) -> Result<FileMetadata, EnvError> {
        let st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path("/", path);
        st.vfs
            .get(&norm)
            .map(|node| node_metadata(&norm, node))
            .ok_or(EnvError::NotFound { path: norm })
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>, EnvError> {
        let st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path("/", path);
        match st.vfs.get(&norm) {
            Some(VfsNode::File { bytes, .. }) => Ok(bytes.clone()),
            Some(VfsNode::Dir { .. }) => Err(EnvError::IsADirectory { path: norm }),
            None => Err(EnvError::NotFound { path: norm }),
        }
    }

    async fn write_file(
        &self,
        path: &str,
        data: &[u8],
        append: bool,
        force: bool,
    ) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path("/", path);
        let now: DateTime<FixedOffset> = Utc::now().into();

        if let Some(existing) = st.vfs.get_mut(&norm) {
            match existing {
                VfsNode::Dir { .. } => return Err(EnvError::IsADirectory { path: norm }),
                VfsNode::File { bytes, modified } => {
                    if append {
                        bytes.extend_from_slice(data);
                        *modified = now;
                        return Ok(());
                    }
                    if !force {
                        return Err(EnvError::AlreadyExists { path: norm });
                    }
                    *bytes = data.to_vec();
                    *modified = now;
                    return Ok(());
                }
            }
        }

        ensure_parents(&mut st.vfs, &norm, now);
        st.vfs.insert(
            norm,
            VfsNode::File {
                bytes: data.to_vec(),
                modified: now,
            },
        );
        Ok(())
    }

    async fn mkdir(&self, path: &str) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path("/", path);
        let now: DateTime<FixedOffset> = Utc::now().into();
        if let Some(VfsNode::File { .. }) = st.vfs.get(&norm) {
            return Err(EnvError::AlreadyExists { path: norm });
        }
        ensure_parents(&mut st.vfs, &norm, now);
        st.vfs.entry(norm).or_insert(VfsNode::Dir { modified: now });
        Ok(())
    }

    async fn remove(&self, path: &str, recursive: bool, force: bool) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path("/", path);
        let Some(node) = st.vfs.get(&norm).cloned() else {
            return if force {
                Ok(())
            } else {
                Err(EnvError::NotFound { path: norm })
            };
        };

        match node {
            VfsNode::File { .. } => {
                st.vfs.remove(&norm);
                Ok(())
            }
            VfsNode::Dir { .. } => {
                let prefix = format!("{norm}/");
                let children: Vec<String> = st
                    .vfs
                    .keys()
                    .filter(|k| k.starts_with(&prefix))
                    .cloned()
                    .collect();
                if !children.is_empty() && !recursive {
                    return Err(EnvError::IsADirectory { path: norm });
                }
                for child in children {
                    st.vfs.remove(&child);
                }
                st.vfs.remove(&norm);
                Ok(())
            }
        }
    }

    async fn copy(
        &self,
        from: &str,
        to: &str,
        recursive: bool,
        force: bool,
    ) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let src = normalize_vfs_path("/", from);
        let dst = normalize_vfs_path("/", to);
        let now: DateTime<FixedOffset> = Utc::now().into();

        let Some(src_node) = st.vfs.get(&src).cloned() else {
            return Err(EnvError::NotFound { path: src });
        };

        if st.vfs.contains_key(&dst) && !force {
            return Err(EnvError::AlreadyExists { path: dst });
        }

        match src_node {
            VfsNode::File { bytes, .. } => {
                ensure_parents(&mut st.vfs, &dst, now);
                st.vfs.insert(
                    dst,
                    VfsNode::File {
                        bytes,
                        modified: now,
                    },
                );
                Ok(())
            }
            VfsNode::Dir { .. } => {
                if !recursive {
                    return Err(EnvError::IsADirectory { path: src });
                }
                let src_prefix = format!("{src}/");
                let sub_entries: Vec<(String, VfsNode)> = st
                    .vfs
                    .iter()
                    .filter(|(k, _)| k.starts_with(&src_prefix))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                ensure_parents(&mut st.vfs, &dst, now);
                st.vfs.insert(dst.clone(), VfsNode::Dir { modified: now });
                for (k, v) in sub_entries {
                    let rel = k.strip_prefix(&src_prefix).unwrap_or("");
                    st.vfs.insert(format!("{dst}/{rel}"), v);
                }
                Ok(())
            }
        }
    }

    async fn rename(&self, from: &str, to: &str, force: bool) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let src = normalize_vfs_path("/", from);
        let dst = normalize_vfs_path("/", to);
        let now: DateTime<FixedOffset> = Utc::now().into();

        let Some(src_node) = st.vfs.get(&src).cloned() else {
            return Err(EnvError::NotFound { path: src });
        };
        if st.vfs.contains_key(&dst) && !force {
            return Err(EnvError::AlreadyExists { path: dst });
        }

        st.vfs.remove(&src);
        ensure_parents(&mut st.vfs, &dst, now);
        st.vfs.insert(dst.clone(), src_node);

        let src_prefix = format!("{src}/");
        let moved: Vec<(String, VfsNode)> = st
            .vfs
            .iter()
            .filter(|(k, _)| k.starts_with(&src_prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, _) in &moved {
            st.vfs.remove(k);
        }
        for (k, v) in moved {
            let rel = k.strip_prefix(&src_prefix).unwrap_or("");
            st.vfs.insert(format!("{dst}/{rel}"), v);
        }
        Ok(())
    }

    async fn touch(&self, path: &str, no_create: bool) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path("/", path);
        let now: DateTime<FixedOffset> = Utc::now().into();
        if let Some(node) = st.vfs.get_mut(&norm) {
            match node {
                VfsNode::File { modified, .. } | VfsNode::Dir { modified } => *modified = now,
            }
            return Ok(());
        }
        if no_create {
            return Ok(());
        }
        ensure_parents(&mut st.vfs, &norm, now);
        st.vfs.insert(
            norm,
            VfsNode::File {
                bytes: Vec::new(),
                modified: now,
            },
        );
        Ok(())
    }

    async fn watch(&self, path: &str) -> Result<async_channel::Receiver<WatchEvent>, EnvError> {
        let norm = normalize_vfs_path("/", path);
        let events = {
            let st = self.state.lock().expect("test env lock");
            st.watch_events.get(&norm).cloned().unwrap_or_default()
        };
        let (tx, rx) = async_channel::bounded(events.len().max(1));
        for ev in events {
            let _ = tx.send(ev).await;
        }
        Ok(rx)
    }

    async fn complete_diagnostic_targets(&self) -> Result<Vec<String>, EnvError> {
        Ok(self
            .state
            .lock()
            .expect("test env lock")
            .diagnostic_targets
            .clone())
    }

    async fn complete_oci_refs(&self) -> Result<Vec<String>, EnvError> {
        Ok(self.state.lock().expect("test env lock").oci_refs.clone())
    }
}
