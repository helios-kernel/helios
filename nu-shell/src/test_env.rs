//! In-memory [`HeliosEnv`] implementation for unit and integration testing.

use core::time::Duration;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, FixedOffset, Utc};

use crate::env::{
    BtrfsSubvolumeInfo, ComponentAddRequest, ComponentInfo, ComponentSubtreeSource,
    ContainerCreateRequest, ContainerExecOutput, ContainerExecRequest, ContainerInfo,
    ContainerSpawnRequest, DEFAULT_LINUX_IMAGE_REF, ExecutableMatch, ExternalProcess,
    ExternalSpawnRequest, FileMetadata, FileType, GrantSpec, HeliosEnv, InspectEntry, InspectValue,
    InstructionProfileSummary, LinuxImageClearResult, LinuxImageInfo, MountEntryInfo,
    MountRequestSpec, OciImageInspect, OciImageSummary, ProcessInfo, STREAM_CHANNEL_CAPACITY,
    SnapshotInfo, SysCpuInfo, SysDiskInfo, SysHostInfo, SysMemInfo, SysNetInfo, VmInfo,
    VmRunRequest, WatchEvent, normalize_vfs_path,
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
    user_default_images: BTreeMap<String, LinuxImageInfo>,
    active_linux_image: Option<LinuxImageInfo>,
    components: BTreeMap<String, ComponentInfo>,
    oci_images: BTreeMap<String, OciImageInspect>,
    containers: BTreeMap<String, ContainerInfo>,
    next_container_id: u64,
    mounts: BTreeMap<String, MountEntryInfo>,
    subvolumes: BTreeMap<String, BtrfsSubvolumeInfo>,
    next_subvol_id: u64,
    vms: Vec<VmInfo>,
    next_vm_id: u64,
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
        executables.insert(String::from("ok-err-ext"), String::from("/bin/ok-err-ext"));

        let mut components = BTreeMap::new();
        components.insert(
            String::from("/init"),
            ComponentInfo {
                moniker: String::from("/init"),
                program: String::from("/bin/init"),
                state: String::from("running"),
                instance_id: Some(1),
                restarts: 0,
            },
        );
        components.insert(
            String::from("/plugins/http-client"),
            ComponentInfo {
                moniker: String::from("/plugins/http-client"),
                program: String::from("/bin/http-client"),
                state: String::from("running"),
                instance_id: Some(2),
                restarts: 0,
            },
        );

        let mut oci_images = BTreeMap::new();
        oci_images.insert(
            String::from("docker.io/library/alpine:3.21"),
            OciImageInspect {
                reference: String::from("docker.io/library/alpine:3.21"),
                digest: String::from("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
                arch: String::from("amd64"),
                os: String::from("linux"),
                layer_chain_ids: vec![String::from("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")],
                rootfs_path: String::from("/var/lib/oci/layers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                btrfs_backed: true,
                user: Some(String::from("0:0")),
                working_dir: Some(String::from("/")),
                entrypoint: Vec::new(),
                cmd: vec![String::from("/bin/sh")],
                env: vec![(String::from("PATH"), String::from("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"))],
                labels: BTreeMap::new(),
            },
        );
        oci_images.insert(
            String::from("ghcr.io/helios/base:latest"),
            OciImageInspect {
                reference: String::from("ghcr.io/helios/base:latest"),
                digest: String::from("sha256:2222222222222222222222222222222222222222222222222222222222222222"),
                arch: String::from("amd64"),
                os: String::from("linux"),
                layer_chain_ids: vec![String::from("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")],
                rootfs_path: String::from("/var/lib/oci/layers/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                btrfs_backed: true,
                user: Some(String::from("0:0")),
                working_dir: Some(String::from("/work")),
                entrypoint: Vec::new(),
                cmd: vec![String::from("/bin/sh")],
                env: vec![(String::from("PATH"), String::from("/usr/bin:/bin"))],
                labels: BTreeMap::new(),
            },
        );

        let mut mounts = BTreeMap::new();
        mounts.insert(
            String::from("/"),
            MountEntryInfo {
                path: String::from("/"),
                source: String::from("boot-image"),
                kind: String::from("boot-image"),
                read_only: true,
                sharing: String::from("shared"),
            },
        );

        let mut subvolumes = BTreeMap::new();
        subvolumes.insert(
            String::from("/data"),
            BtrfsSubvolumeInfo {
                id: 5,
                parent_id: None,
                path: String::new(),
                uuid: String::from("00000000-0000-0000-0000-000000000005"),
                parent_uuid: None,
                received_uuid: None,
                generation: 1,
                ctransid: 1,
                otransid: 1,
                stransid: 0,
                rtransid: 0,
                read_only: false,
            },
        );

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
            user_default_images: BTreeMap::new(),
            active_linux_image: None,
            components,
            oci_images,
            containers: BTreeMap::new(),
            next_container_id: 1,
            mounts,
            subvolumes,
            next_subvol_id: 256,
            vms: Vec::new(),
            next_vm_id: 1,
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
            "ok-err-ext" => {
                let stdout_text = if request.args.is_empty() {
                    String::from("ok-stdout\n")
                } else {
                    format!("{}\n", request.args.join(" "))
                };
                if let Some(tx) = out_tx {
                    let _ = tx.send(Ok(stdout_text.as_bytes().to_vec())).await;
                } else {
                    self.state
                        .lock()
                        .expect("test env lock")
                        .stdout_log
                        .extend_from_slice(stdout_text.as_bytes());
                }
                if let Some(tx) = err_tx {
                    let _ = tx.send(Ok(b"stderr-on-zero\n".to_vec())).await;
                } else {
                    self.state
                        .lock()
                        .expect("test env lock")
                        .stderr_log
                        .extend_from_slice(b"stderr-on-zero\n");
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
        let st = self.state.lock().expect("test env lock");
        let mut refs: Vec<String> = st.oci_images.keys().cloned().collect();
        for extra in &st.oci_refs {
            if !refs.contains(extra) {
                refs.push(extra.clone());
            }
        }
        Ok(refs)
    }

    async fn linux_image_get(&self) -> Result<LinuxImageInfo, EnvError> {
        let st = self.state.lock().expect("test env lock");
        if let Some(info) = st.user_default_images.get(&st.whoami) {
            return Ok(info.clone());
        }
        if let Some(active) = &st.active_linux_image {
            return Ok(active.clone());
        }
        Ok(LinuxImageInfo {
            principal: st.whoami.clone(),
            image_ref: None,
            default_ref: String::from(DEFAULT_LINUX_IMAGE_REF),
            rootfs_path: None,
            active: false,
            persisted: false,
            env: Vec::new(),
            uid: None,
            gid: None,
        })
    }

    async fn linux_image_set(
        &self,
        image_ref: &str,
        arch: Option<&str>,
    ) -> Result<LinuxImageInfo, EnvError> {
        let pulled = self.oci_pull(image_ref, arch).await?;
        let mut st = self.state.lock().expect("test env lock");
        let info = LinuxImageInfo {
            principal: st.whoami.clone(),
            image_ref: Some(pulled.reference),
            default_ref: String::from(DEFAULT_LINUX_IMAGE_REF),
            rootfs_path: Some(pulled.rootfs_path),
            active: true,
            persisted: true,
            env: vec![(
                String::from("PATH"),
                String::from("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            )],
            uid: Some(0),
            gid: Some(0),
        };
        let principal = st.whoami.clone();
        st.user_default_images.insert(principal, info.clone());
        st.active_linux_image = Some(info.clone());
        Ok(info)
    }

    async fn linux_image_clear(&self) -> Result<LinuxImageClearResult, EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let principal = st.whoami.clone();
        let removed = st.user_default_images.remove(&principal);
        let active = st.active_linux_image.take();
        let previous_ref = removed
            .and_then(|i| i.image_ref)
            .or_else(|| active.and_then(|i| i.image_ref));
        Ok(LinuxImageClearResult {
            principal,
            cleared: previous_ref.is_some(),
            previous_ref,
        })
    }

    async fn component_list(&self) -> Result<Vec<ComponentInfo>, EnvError> {
        Ok(self
            .state
            .lock()
            .expect("test env lock")
            .components
            .values()
            .cloned()
            .collect())
    }

    async fn component_status(&self, moniker: &str) -> Result<ComponentInfo, EnvError> {
        self.state
            .lock()
            .expect("test env lock")
            .components
            .get(moniker)
            .cloned()
            .ok_or_else(|| EnvError::NotFound {
                path: moniker.to_owned(),
            })
    }

    async fn component_start(&self, moniker: &str) -> Result<ComponentInfo, EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let comp = st
            .components
            .get_mut(moniker)
            .ok_or_else(|| EnvError::NotFound {
                path: moniker.to_owned(),
            })?;
        comp.state = String::from("running");
        if comp.instance_id.is_none() {
            comp.instance_id = Some(100);
        }
        Ok(comp.clone())
    }

    async fn component_stop(&self, moniker: &str) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let comp = st
            .components
            .get_mut(moniker)
            .ok_or_else(|| EnvError::NotFound {
                path: moniker.to_owned(),
            })?;
        comp.state = String::from("stopped");
        comp.instance_id = None;
        Ok(())
    }

    async fn component_restart(&self, moniker: &str) -> Result<ComponentInfo, EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let comp = st
            .components
            .get_mut(moniker)
            .ok_or_else(|| EnvError::NotFound {
                path: moniker.to_owned(),
            })?;
        comp.state = String::from("running");
        comp.restarts += 1;
        comp.instance_id = Some(comp.instance_id.unwrap_or(100) + 1);
        Ok(comp.clone())
    }

    async fn component_add(&self, request: ComponentAddRequest) -> Result<String, EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let parent = normalize_vfs_path("/", &request.parent_moniker);
        let child_name = match &request.source {
            ComponentSubtreeSource::GuestDir { subtree_name, .. } => subtree_name.clone(),
            ComponentSubtreeSource::Manifests(entries) => entries
                .first()
                .map(|(p, _)| {
                    p.split('/')
                        .next()
                        .unwrap_or("dynamic")
                        .trim_end_matches(".toml")
                        .to_owned()
                })
                .unwrap_or_else(|| String::from("dynamic")),
        };
        let moniker = normalize_vfs_path(&parent, &child_name);
        if st.components.contains_key(&moniker) {
            return Err(EnvError::AlreadyExists { path: moniker });
        }
        st.components.insert(
            moniker.clone(),
            ComponentInfo {
                moniker: moniker.clone(),
                program: String::from("dynamic"),
                state: String::from("running"),
                instance_id: Some(200),
                restarts: 0,
            },
        );
        Ok(moniker)
    }

    async fn component_remove(&self, moniker: &str) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        st.components
            .remove(moniker)
            .map(|_| ())
            .ok_or_else(|| EnvError::NotFound {
                path: moniker.to_owned(),
            })
    }

    async fn oci_pull(
        &self,
        reference: &str,
        arch: Option<&str>,
    ) -> Result<OciImageSummary, EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let canonical = canonicalize_test_oci_ref(reference);
        if let Some(existing) = st.oci_images.get(&canonical) {
            return Ok(OciImageSummary {
                reference: existing.reference.clone(),
                digest: existing.digest.clone(),
                arch: existing.arch.clone(),
                layers: existing.layer_chain_ids.len(),
                rootfs_path: existing.rootfs_path.clone(),
                btrfs_backed: existing.btrfs_backed,
            });
        }
        let arch_str = arch.unwrap_or("amd64").to_owned();
        let slug: String = canonical
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let rootfs_path = format!("/var/lib/oci/layers/{slug}");
        let inspect = OciImageInspect {
            reference: canonical.clone(),
            digest: format!("sha256:pulled-{slug}"),
            arch: arch_str.clone(),
            os: String::from("linux"),
            layer_chain_ids: vec![format!("sha256:layer-{slug}")],
            rootfs_path: rootfs_path.clone(),
            btrfs_backed: true,
            user: Some(String::from("0:0")),
            working_dir: Some(String::from("/")),
            entrypoint: Vec::new(),
            cmd: vec![String::from("/bin/sh")],
            env: vec![(String::from("PATH"), String::from("/usr/bin:/bin"))],
            labels: BTreeMap::new(),
        };
        let summary = OciImageSummary {
            reference: canonical.clone(),
            digest: inspect.digest.clone(),
            arch: arch_str,
            layers: inspect.layer_chain_ids.len(),
            rootfs_path,
            btrfs_backed: true,
        };
        st.oci_images.insert(canonical, inspect);
        Ok(summary)
    }

    async fn oci_list(&self) -> Result<Vec<OciImageSummary>, EnvError> {
        Ok(self
            .state
            .lock()
            .expect("test env lock")
            .oci_images
            .values()
            .map(|img| OciImageSummary {
                reference: img.reference.clone(),
                digest: img.digest.clone(),
                arch: img.arch.clone(),
                layers: img.layer_chain_ids.len(),
                rootfs_path: img.rootfs_path.clone(),
                btrfs_backed: img.btrfs_backed,
            })
            .collect())
    }

    async fn oci_inspect(&self, reference: &str) -> Result<OciImageInspect, EnvError> {
        let st = self.state.lock().expect("test env lock");
        let canonical = canonicalize_test_oci_ref(reference);
        st.oci_images
            .get(&canonical)
            .or_else(|| st.oci_images.get(reference))
            .cloned()
            .ok_or_else(|| EnvError::NotFound {
                path: reference.to_owned(),
            })
    }

    async fn oci_remove(&self, reference: &str) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let canonical = canonicalize_test_oci_ref(reference);
        if st.oci_images.remove(&canonical).is_some() || st.oci_images.remove(reference).is_some() {
            Ok(())
        } else {
            Err(EnvError::NotFound {
                path: reference.to_owned(),
            })
        }
    }

    async fn container_create(
        &self,
        request: ContainerCreateRequest,
    ) -> Result<ContainerInfo, EnvError> {
        let rootfs_path = if let Some(ref image) = request.image {
            let pulled = self.oci_pull(image, None).await?;
            pulled.rootfs_path
        } else if let Some(rootfs) = request.rootfs {
            rootfs
        } else {
            return Err(EnvError::InvalidArgument {
                detail: String::from("container requires image or rootfs"),
            });
        };
        let mut st = self.state.lock().expect("test env lock");
        let id = st.next_container_id;
        st.next_container_id += 1;
        let handle = format!("ctr-{id}");
        let info = ContainerInfo {
            handle: handle.clone(),
            image: request.image,
            rootfs_path,
            hostname: request.hostname.unwrap_or_else(|| String::from("helios")),
            cwd: request.cwd,
            uid: request.uid.unwrap_or(0),
            gid: request.gid.unwrap_or(0),
        };
        st.containers.insert(handle, info.clone());
        Ok(info)
    }

    async fn container_list(&self) -> Result<Vec<ContainerInfo>, EnvError> {
        Ok(self
            .state
            .lock()
            .expect("test env lock")
            .containers
            .values()
            .cloned()
            .collect())
    }

    async fn container_exec(
        &self,
        handle: &str,
        request: ContainerExecRequest,
    ) -> Result<ContainerExecOutput, EnvError> {
        let container = {
            let st = self.state.lock().expect("test env lock");
            st.containers
                .get(handle)
                .cloned()
                .ok_or_else(|| EnvError::NotFound {
                    path: handle.to_owned(),
                })?
        };
        let stdout = format!(
            "{}:{} {}",
            container.hostname,
            request.program,
            request.args.join(" ")
        )
        .trim_end()
        .as_bytes()
        .to_vec();
        Ok(ContainerExecOutput {
            instance_id: 500,
            exit_code: 0,
            stdout,
            stderr: Vec::new(),
        })
    }

    async fn container_spawn(
        &self,
        handle: &str,
        request: ContainerSpawnRequest,
    ) -> Result<ExternalProcess, EnvError> {
        let container = {
            let st = self.state.lock().expect("test env lock");
            st.containers
                .get(handle)
                .cloned()
                .ok_or_else(|| EnvError::NotFound {
                    path: handle.to_owned(),
                })?
        };
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
        let (out_tx, out_rx) = if request.capture_stdout {
            let (tx, rx) = async_channel::bounded(STREAM_CHANNEL_CAPACITY);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let (_err_tx, err_rx) = if request.capture_stderr {
            let (tx, rx) = async_channel::bounded(STREAM_CHANNEL_CAPACITY);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let (code_tx, code_rx) = async_channel::bounded(1);

        let payload = if stdin_bytes.is_empty() {
            format!(
                "[{}] {} {}\n",
                container.handle,
                request.program,
                request.args.join(" ")
            )
        } else {
            format!(
                "[{}] {}",
                container.handle,
                String::from_utf8_lossy(&stdin_bytes)
            )
        };
        if let Some(tx) = out_tx {
            let _ = tx.send(Ok(payload.into_bytes())).await;
        } else {
            self.state
                .lock()
                .expect("test env lock")
                .stdout_log
                .extend_from_slice(payload.as_bytes());
        }
        let _ = code_tx.send(Ok(0)).await;
        Ok(ExternalProcess {
            stdout: out_rx,
            stderr: err_rx,
            exit_code: code_rx,
        })
    }

    async fn container_remove(&self, handle: &str) -> Result<(), EnvError> {
        self.state
            .lock()
            .expect("test env lock")
            .containers
            .remove(handle)
            .map(|_| ())
            .ok_or_else(|| EnvError::NotFound {
                path: handle.to_owned(),
            })
    }

    async fn list_mounts(&self) -> Result<Vec<MountEntryInfo>, EnvError> {
        Ok(self
            .state
            .lock()
            .expect("test env lock")
            .mounts
            .values()
            .cloned()
            .collect())
    }

    async fn mount(&self, request: MountRequestSpec) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let path = normalize_vfs_path("/", &request.path);
        if st.mounts.contains_key(&path) {
            return Err(EnvError::AlreadyExists { path });
        }
        st.mounts.insert(
            path.clone(),
            MountEntryInfo {
                path,
                source: request.source.display_label(),
                kind: request.source.kind_name().to_owned(),
                read_only: request.read_only,
                sharing: request.sharing.as_str().to_owned(),
            },
        );
        Ok(())
    }

    async fn umount(&self, path: &str) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path("/", path);
        st.mounts
            .remove(&norm)
            .map(|_| ())
            .ok_or(EnvError::NotFound { path: norm })
    }

    async fn btrfs_subvolume_create(&self, path: &str) -> Result<BtrfsSubvolumeInfo, EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path("/", path);
        if st.subvolumes.contains_key(&norm) {
            return Err(EnvError::AlreadyExists { path: norm });
        }
        let id = st.next_subvol_id;
        st.next_subvol_id += 1;
        let info = BtrfsSubvolumeInfo {
            id,
            parent_id: Some(5),
            path: norm.clone(),
            uuid: format!("00000000-0000-0000-0000-{id:012x}"),
            parent_uuid: None,
            received_uuid: None,
            generation: 2,
            ctransid: 2,
            otransid: 2,
            stransid: 0,
            rtransid: 0,
            read_only: false,
        };
        st.subvolumes.insert(norm, info.clone());
        Ok(info)
    }

    async fn btrfs_subvolume_delete(&self, path: &str) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path("/", path);
        st.subvolumes
            .remove(&norm)
            .map(|_| ())
            .ok_or(EnvError::NotFound { path: norm })
    }

    async fn btrfs_subvolume_snapshot(
        &self,
        source: &str,
        destination: &str,
        read_only: bool,
    ) -> Result<BtrfsSubvolumeInfo, EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let src = normalize_vfs_path("/", source);
        let dst = normalize_vfs_path("/", destination);
        let src_info = st
            .subvolumes
            .get(&src)
            .cloned()
            .ok_or(EnvError::NotFound { path: src })?;
        if st.subvolumes.contains_key(&dst) {
            return Err(EnvError::AlreadyExists { path: dst });
        }
        let id = st.next_subvol_id;
        st.next_subvol_id += 1;
        let info = BtrfsSubvolumeInfo {
            id,
            parent_id: Some(src_info.id),
            path: dst.clone(),
            uuid: format!("00000000-0000-0000-0000-{id:012x}"),
            parent_uuid: Some(src_info.uuid),
            received_uuid: None,
            generation: src_info.generation + 1,
            ctransid: src_info.ctransid + 1,
            otransid: src_info.ctransid + 1,
            stransid: 0,
            rtransid: 0,
            read_only,
        };
        st.subvolumes.insert(dst, info.clone());
        Ok(info)
    }

    async fn btrfs_subvolume_list(
        &self,
        _mount_point: &str,
    ) -> Result<Vec<BtrfsSubvolumeInfo>, EnvError> {
        Ok(self
            .state
            .lock()
            .expect("test env lock")
            .subvolumes
            .values()
            .cloned()
            .collect())
    }

    async fn btrfs_subvolume_info(&self, path: &str) -> Result<BtrfsSubvolumeInfo, EnvError> {
        let norm = normalize_vfs_path("/", path);
        self.state
            .lock()
            .expect("test env lock")
            .subvolumes
            .get(&norm)
            .cloned()
            .ok_or(EnvError::NotFound { path: norm })
    }

    async fn btrfs_subvolume_set_ro(&self, path: &str, read_only: bool) -> Result<(), EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let norm = normalize_vfs_path("/", path);
        let info = st
            .subvolumes
            .get_mut(&norm)
            .ok_or(EnvError::NotFound { path: norm })?;
        info.read_only = read_only;
        Ok(())
    }

    async fn btrfs_subvolume_send(
        &self,
        subvolume: &str,
        _parent: Option<&str>,
        _clone_sources: &[String],
    ) -> Result<Vec<u8>, EnvError> {
        let norm = normalize_vfs_path("/", subvolume);
        let st = self.state.lock().expect("test env lock");
        let info = st
            .subvolumes
            .get(&norm)
            .ok_or(EnvError::NotFound { path: norm.clone() })?;
        if !info.read_only {
            return Err(EnvError::InvalidArgument {
                detail: format!("subvolume `{norm}` must be read-only for send"),
            });
        }
        Ok(format!("btrfs-stream:{}:{}", info.uuid, info.path).into_bytes())
    }

    async fn btrfs_subvolume_receive(
        &self,
        destination: &str,
        payload: Vec<u8>,
    ) -> Result<BtrfsSubvolumeInfo, EnvError> {
        if payload.is_empty() {
            return Err(EnvError::InvalidArgument {
                detail: String::from("empty btrfs send stream"),
            });
        }
        let mut st = self.state.lock().expect("test env lock");
        let dst = normalize_vfs_path("/", destination);
        let id = st.next_subvol_id;
        st.next_subvol_id += 1;
        let info = BtrfsSubvolumeInfo {
            id,
            parent_id: Some(5),
            path: dst.clone(),
            uuid: format!("00000000-0000-0000-0000-{id:012x}"),
            parent_uuid: None,
            received_uuid: Some(String::from("11111111-1111-1111-1111-111111111111")),
            generation: 3,
            ctransid: 3,
            otransid: 3,
            stransid: 0,
            rtransid: 3,
            read_only: true,
        };
        st.subvolumes.insert(dst, info.clone());
        Ok(info)
    }

    async fn vm_run(&self, request: VmRunRequest) -> Result<VmInfo, EnvError> {
        let mut st = self.state.lock().expect("test env lock");
        let id = st.next_vm_id;
        st.next_vm_id += 1;
        let vm_id = format!("vm-{id}");
        let name = request.name.unwrap_or_else(|| vm_id.clone());
        let info = VmInfo {
            id: vm_id,
            name,
            state: if request.detach {
                String::from("running")
            } else {
                String::from("stopped")
            },
            cpus: request.cpus,
            memory_mib: request.memory_mib,
            oci_ref: request.oci_ref,
            kernel: request.kernel,
            exit_reason: (!request.detach).then(|| String::from("guest-shutdown")),
        };
        st.vms.push(info.clone());
        Ok(info)
    }

    async fn vm_list(&self) -> Result<Vec<VmInfo>, EnvError> {
        Ok(self.state.lock().expect("test env lock").vms.clone())
    }
}

fn canonicalize_test_oci_ref(raw: &str) -> String {
    if raw.contains('/') {
        if raw.contains(':') || raw.contains('@') {
            raw.to_owned()
        } else {
            format!("{raw}:latest")
        }
    } else if raw.contains(':') {
        format!("docker.io/library/{raw}")
    } else {
        format!("docker.io/library/{raw}:latest")
    }
}
