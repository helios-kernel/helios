//! Container-isolated `/proc` virtual filesystem (`ProcFs`).
//!
//! Exposes strictly the processes registered inside one container's
//! [`PidNamespace`], caller-aware `/proc/self` and `/proc/thread-self`
//! symlinks, container-scoped `/proc/{meminfo,uptime,loadavg,stat,cpuinfo,
//! version,filesystems,mounts,cmdline}`, `/proc/net/*`, and
//! `/proc/sys/kernel/*` (with `CAP_SYS_ADMIN` writes to `hostname` and
//! `domainname` updating container UTS).
//!
//! # Concurrency contract
//!
//! [`ProcRegistry`] holds its process table, mount table snapshot, network
//! snapshot, and UTS state behind short synchronous `spin::Mutex` locks never
//! held across an `.await`. No dynamic dispatch (`dyn`) is used.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use bytes::Bytes;
use helios_hal::fs::{
    DeviceId, DirCookie, DirEntry, DirStream, FileSystem, FsError, FsPath, FsResult, Landed,
    Metadata, NodeId, NodeKind, OpenFlags, Opened, OwnedFsPath, PreparedWrite, RenameMode,
    WritePosition, WriteProgress,
};
use helios_linux::syscall::{Credentials, NGROUPS_MAX, RELEASE, UtsField};
use triomphe::Arc;

use super::{UnixAttributes, UnixFsError, UnixNodeMetadata, delegate_path_handles};

const PID_MAX: u32 = 0x3fff_ffff;
const PAGE_BYTES: u64 = 4096;

/// Caller identity used to resolve `/proc/self` and `/proc/thread-self`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcCaller {
    pub pid: u32,
    pub tid: u32,
}

/// Container UTS state shared between [`crate::LinuxContainer`] and [`ProcFs`].
#[derive(Clone, Debug)]
pub struct SharedUts {
    pub hostname: UtsField,
    pub domainname: UtsField,
}

/// One container mount entry rendered in `/proc/mounts` and `/proc/<pid>/mountinfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcMountEntry {
    pub mnt_id: u32,
    pub parent_id: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub options: String,
}

/// One network interface snapshot exposed via `/proc/net/dev` and `/sys/class/net/*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetIfSnapshot {
    pub name: String,
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub mtu: u32,
    pub flags: u32,
    pub operstate: String,
    pub arp_type: u16,
    pub ipv4: Vec<([u8; 4], u8)>,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

/// One IPv4 route entry rendered in `/proc/net/route`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetRouteSnapshot {
    pub iface: String,
    pub destination: [u8; 4],
    pub gateway: [u8; 4],
    pub mask: [u8; 4],
    pub flags: u16,
    pub metric: u32,
    pub mtu: u32,
}

/// Container-scoped network snapshot for `/proc/net/*` and `/sys/class/net/*`.
#[derive(Clone, Debug)]
pub struct ContainerNetSnapshot {
    pub interfaces: Vec<NetIfSnapshot>,
    pub routes: Vec<NetRouteSnapshot>,
}

impl Default for ContainerNetSnapshot {
    fn default() -> Self {
        Self {
            interfaces: alloc::vec![NetIfSnapshot {
                name: String::from("lo"),
                ifindex: 1,
                mac: [0; 6],
                mtu: 65_536,
                flags: 0x0009, // IFF_UP | IFF_LOOPBACK
                operstate: String::from("unknown"),
                arp_type: 772, // ARPHRD_LOOPBACK
                ipv4: alloc::vec![([127, 0, 0, 1], 8)],
                rx_bytes: 0,
                rx_packets: 0,
                rx_errors: 0,
                rx_dropped: 0,
                tx_bytes: 0,
                tx_packets: 0,
                tx_errors: 0,
                tx_dropped: 0,
            }],
            routes: Vec::new(),
        }
    }
}

/// One open file descriptor entry shown in `/proc/<pid>/fd/` and `fdinfo/`.
#[derive(Clone, Debug)]
pub struct ProcFdEntry {
    pub fd: i32,
    pub target: String,
    pub pos: u64,
    pub flags: u32,
    pub mnt_id: u32,
}

/// One memory mapping entry shown in `/proc/<pid>/maps`.
#[derive(Clone, Debug)]
pub struct ProcMapEntry {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub shared: bool,
    pub offset: u64,
    pub pathname: String,
}

/// One resource limit row shown in `/proc/<pid>/limits`.
#[derive(Clone, Debug)]
pub struct ProcLimitEntry {
    pub name: &'static str,
    pub soft: u64,
    pub hard: u64,
    pub units: &'static str,
}

/// Per-thread snapshot inside [`ProcProcessRecord`].
#[derive(Clone, Debug)]
pub struct ProcThreadRecord {
    pub tid: u32,
    pub comm: String,
    pub state: char,
    pub utime_ticks: u64,
    pub stime_ticks: u64,
}

/// Per-process snapshot owned by one container's [`ProcRegistry`].
#[derive(Clone)]
pub struct ProcProcessRecord {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub comm: String,
    pub exe: String,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub root: String,
    pub state: char,
    pub umask: u32,
    pub credentials: Credentials,
    pub start_time_ticks: u64,
    pub utime_ticks: u64,
    pub stime_ticks: u64,
    pub vm_size_bytes: u64,
    pub vm_rss_bytes: u64,
    pub maps: Vec<ProcMapEntry>,
    pub limits: Vec<ProcLimitEntry>,
    pub fds: Vec<ProcFdEntry>,
    pub threads: BTreeMap<u32, ProcThreadRecord>,
}

impl ProcProcessRecord {
    pub fn minimal(pid: u32, ppid: u32, comm: impl Into<String>, exe: impl Into<String>) -> Self {
        let comm = comm.into();
        let mut threads = BTreeMap::new();
        threads.insert(
            pid,
            ProcThreadRecord {
                tid: pid,
                comm: comm.clone(),
                state: 'R',
                utime_ticks: 0,
                stime_ticks: 0,
            },
        );
        Self {
            pid,
            ppid,
            pgid: pid,
            sid: pid,
            comm,
            exe: exe.into(),
            argv: Vec::new(),
            env: Vec::new(),
            cwd: String::from("/"),
            root: String::from("/"),
            state: 'R',
            umask: 0o022,
            credentials: Credentials::root(),
            start_time_ticks: 0,
            utime_ticks: 0,
            stime_ticks: 0,
            vm_size_bytes: 0,
            vm_rss_bytes: 0,
            maps: Vec::new(),
            limits: default_proc_limits(),
            fds: Vec::new(),
            threads,
        }
    }
}

/// Default Linux `/proc/<pid>/limits` rows.
pub fn default_proc_limits() -> Vec<ProcLimitEntry> {
    const INF: u64 = u64::MAX;
    alloc::vec![
        ProcLimitEntry {
            name: "Max cpu time",
            soft: INF,
            hard: INF,
            units: "seconds",
        },
        ProcLimitEntry {
            name: "Max file size",
            soft: INF,
            hard: INF,
            units: "bytes",
        },
        ProcLimitEntry {
            name: "Max data size",
            soft: INF,
            hard: INF,
            units: "bytes",
        },
        ProcLimitEntry {
            name: "Max stack size",
            soft: 8 * 1024 * 1024,
            hard: INF,
            units: "bytes",
        },
        ProcLimitEntry {
            name: "Max core file size",
            soft: 0,
            hard: INF,
            units: "bytes",
        },
        ProcLimitEntry {
            name: "Max resident set",
            soft: INF,
            hard: INF,
            units: "bytes",
        },
        ProcLimitEntry {
            name: "Max processes",
            soft: 4096,
            hard: 4096,
            units: "processes",
        },
        ProcLimitEntry {
            name: "Max open files",
            soft: 1024,
            hard: 4096,
            units: "files",
        },
        ProcLimitEntry {
            name: "Max locked memory",
            soft: 65_536,
            hard: 65_536,
            units: "bytes",
        },
        ProcLimitEntry {
            name: "Max address space",
            soft: INF,
            hard: INF,
            units: "bytes",
        },
    ]
}

struct ProcRegistryInner {
    processes: spin::Mutex<BTreeMap<u32, ProcProcessRecord>>,
    uts: Arc<spin::Mutex<SharedUts>>,
    mounts: spin::Mutex<Vec<ProcMountEntry>>,
    net: spin::Mutex<ContainerNetSnapshot>,
    cpu_count: AtomicU32,
    total_forks: AtomicU32,
    last_pid: AtomicU32,
    uptime_nanos: AtomicU64,
}

/// Container-owned live state backing [`ProcFs`] and [`super::SysFs`].
#[derive(Clone)]
pub struct ProcRegistry {
    inner: Arc<ProcRegistryInner>,
}

impl ProcRegistry {
    pub fn new(uts: Arc<spin::Mutex<SharedUts>>, cpu_count: u32) -> Self {
        Self {
            inner: Arc::new(ProcRegistryInner {
                processes: spin::Mutex::new(BTreeMap::new()),
                uts,
                mounts: spin::Mutex::new(Vec::new()),
                net: spin::Mutex::new(ContainerNetSnapshot::default()),
                cpu_count: AtomicU32::new(cpu_count.max(1)),
                total_forks: AtomicU32::new(0),
                last_pid: AtomicU32::new(0),
                uptime_nanos: AtomicU64::new(0),
            }),
        }
    }

    pub fn set_uptime_nanos(&self, nanos: u64) {
        self.inner.uptime_nanos.store(nanos, Ordering::Relaxed);
    }

    pub fn set_cpu_count(&self, count: u32) {
        self.inner.cpu_count.store(count.max(1), Ordering::Relaxed);
    }

    pub fn cpu_count(&self) -> u32 {
        self.inner.cpu_count.load(Ordering::Relaxed).max(1)
    }

    pub fn set_mounts(&self, mounts: Vec<ProcMountEntry>) {
        *self.inner.mounts.lock() = mounts;
    }

    pub fn set_net_snapshot(&self, snapshot: ContainerNetSnapshot) {
        *self.inner.net.lock() = snapshot;
    }

    pub fn net_snapshot(&self) -> ContainerNetSnapshot {
        self.inner.net.lock().clone()
    }

    pub fn uts(&self) -> &Arc<spin::Mutex<SharedUts>> {
        &self.inner.uts
    }

    pub fn register_process(&self, record: ProcProcessRecord) {
        self.inner.total_forks.fetch_add(1, Ordering::Relaxed);
        self.inner.last_pid.store(record.pid, Ordering::Relaxed);
        self.inner.processes.lock().insert(record.pid, record);
    }

    pub fn update_process(&self, pid: u32, update: impl FnOnce(&mut ProcProcessRecord)) {
        if let Some(record) = self.inner.processes.lock().get_mut(&pid) {
            update(record);
        }
    }

    pub fn unregister_process(&self, pid: u32) {
        self.inner.processes.lock().remove(&pid);
    }

    pub fn register_thread(&self, pid: u32, thread: ProcThreadRecord) {
        if let Some(record) = self.inner.processes.lock().get_mut(&pid) {
            record.threads.insert(thread.tid, thread);
        }
    }

    pub fn unregister_thread(&self, pid: u32, tid: u32) {
        if let Some(record) = self.inner.processes.lock().get_mut(&pid) {
            record.threads.remove(&tid);
        }
    }

    pub fn process(&self, pid: u32) -> Option<ProcProcessRecord> {
        self.inner.processes.lock().get(&pid).cloned()
    }

    pub fn pids(&self) -> Vec<u32> {
        self.inner.processes.lock().keys().copied().collect()
    }
}

/// Container-isolated `/proc` virtual filesystem.
#[derive(Clone)]
pub struct ProcFs {
    device: DeviceId,
    registry: ProcRegistry,
}

enum ProcNode {
    Dir {
        ino: u64,
        entries: Vec<(String, NodeKind, u64)>,
    },
    File {
        ino: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        content: Vec<u8>,
    },
    Symlink {
        ino: u64,
        uid: u32,
        gid: u32,
        target: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysctlTarget {
    Hostname,
    Domainname,
}

fn path_ino(path: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in path.as_bytes() {
        h = (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    if h <= 1 { 2 } else { h }
}

impl ProcFs {
    pub fn new(device: DeviceId, registry: ProcRegistry) -> Self {
        Self { device, registry }
    }

    pub fn registry(&self) -> &ProcRegistry {
        &self.registry
    }

    /// Returns which writable `/proc/sys/kernel/*` node `path` targets, if any.
    pub fn writable_sysctl(path: FsPath<'_>) -> Option<SysctlTarget> {
        match path.as_str() {
            "sys/kernel/hostname" => Some(SysctlTarget::Hostname),
            "sys/kernel/domainname" => Some(SysctlTarget::Domainname),
            _ => None,
        }
    }

    /// Parses a magic `/proc/<pid>/fd/<n>` path inside `ProcFs`, returning
    /// `(pid, fd)`.
    pub fn parse_proc_fd_path(path: FsPath<'_>) -> Option<(u32, i32)> {
        let mut parts = path.as_str().split('/');
        let pid: u32 = parts.next()?.parse().ok()?;
        let second = parts.next()?;
        if second == "fd" {
            let fd: i32 = parts.next()?.parse().ok()?;
            if parts.next().is_none() && fd >= 0 {
                return Some((pid, fd));
            }
        } else if second == "task" {
            let _tid: u32 = parts.next()?.parse().ok()?;
            if parts.next()? == "fd" {
                let fd: i32 = parts.next()?.parse().ok()?;
                if parts.next().is_none() && fd >= 0 {
                    return Some((pid, fd));
                }
            }
        }
        None
    }

    /// Caller-aware symlink resolution for `/proc/self` and `/proc/thread-self`.
    pub fn read_link_for(&self, path: FsPath<'_>, caller: Option<ProcCaller>) -> FsResult<String> {
        match path.as_str() {
            "self" => {
                let pid = caller.map_or(1, |c| c.pid);
                Ok(pid.to_string())
            }
            "thread-self" => {
                let (pid, tid) = caller.map_or((1, 1), |c| (c.pid, c.tid));
                Ok(format!("{pid}/task/{tid}"))
            }
            _ => match self.resolve_node(path, caller)? {
                ProcNode::Symlink { target, .. } => Ok(target),
                _ => Err(FsError::Invalid),
            },
        }
    }

    pub fn unix_node_metadata(
        &self,
        path: FsPath<'_>,
        caller: Option<ProcCaller>,
    ) -> Result<UnixNodeMetadata, UnixFsError> {
        let node = self.resolve_node(path, caller)?;
        let (kind, mode, uid, gid) = match node {
            ProcNode::Dir { .. } => (NodeKind::Directory, 0o555, 0, 0),
            ProcNode::File { mode, uid, gid, .. } => (NodeKind::File, mode, uid, gid),
            ProcNode::Symlink { uid, gid, .. } => (NodeKind::Symlink, 0o777, uid, gid),
        };
        Ok(UnixNodeMetadata {
            kind,
            attributes: UnixAttributes {
                permissions: mode,
                uid,
                gid,
            },
            rdev: 0,
        })
    }

    fn resolve_node(&self, path: FsPath<'_>, caller: Option<ProcCaller>) -> FsResult<ProcNode> {
        let s = path.as_str();
        if s.is_empty() {
            let mut entries = alloc::vec![
                (String::from("cmdline"), NodeKind::File, path_ino("cmdline")),
                (String::from("cpuinfo"), NodeKind::File, path_ino("cpuinfo")),
                (
                    String::from("filesystems"),
                    NodeKind::File,
                    path_ino("filesystems"),
                ),
                (String::from("loadavg"), NodeKind::File, path_ino("loadavg")),
                (String::from("meminfo"), NodeKind::File, path_ino("meminfo")),
                (String::from("mounts"), NodeKind::File, path_ino("mounts")),
                (String::from("net"), NodeKind::Directory, path_ino("net")),
                (String::from("self"), NodeKind::Symlink, path_ino("self")),
                (String::from("stat"), NodeKind::File, path_ino("stat")),
                (String::from("sys"), NodeKind::Directory, path_ino("sys")),
                (
                    String::from("thread-self"),
                    NodeKind::Symlink,
                    path_ino("thread-self"),
                ),
                (String::from("uptime"), NodeKind::File, path_ino("uptime")),
                (String::from("version"), NodeKind::File, path_ino("version")),
            ];
            for pid in self.registry.pids() {
                let name = pid.to_string();
                let ino = path_ino(&name);
                entries.push((name, NodeKind::Directory, ino));
            }
            return Ok(ProcNode::Dir { ino: 1, entries });
        }

        match s {
            "self" => {
                let pid = caller.map_or(1, |c| c.pid);
                return Ok(ProcNode::Symlink {
                    ino: path_ino(s),
                    uid: 0,
                    gid: 0,
                    target: pid.to_string(),
                });
            }
            "thread-self" => {
                let (pid, tid) = caller.map_or((1, 1), |c| (c.pid, c.tid));
                return Ok(ProcNode::Symlink {
                    ino: path_ino(s),
                    uid: 0,
                    gid: 0,
                    target: format!("{pid}/task/{tid}"),
                });
            }
            "meminfo" => return Ok(self.ro_file(s, self.render_meminfo().into_bytes())),
            "uptime" => return Ok(self.ro_file(s, self.render_uptime().into_bytes())),
            "loadavg" => return Ok(self.ro_file(s, self.render_loadavg().into_bytes())),
            "stat" => return Ok(self.ro_file(s, self.render_stat().into_bytes())),
            "cpuinfo" => return Ok(self.ro_file(s, self.render_cpuinfo().into_bytes())),
            "version" => return Ok(self.ro_file(s, self.render_version().into_bytes())),
            "filesystems" => return Ok(self.ro_file(s, render_filesystems().into_bytes())),
            "mounts" => return Ok(self.ro_file(s, self.render_mounts().into_bytes())),
            "cmdline" => return Ok(self.ro_file(s, b"helios\n".to_vec())),
            "net" => {
                return Ok(ProcNode::Dir {
                    ino: path_ino(s),
                    entries: alloc::vec![
                        (String::from("arp"), NodeKind::File, path_ino("net/arp")),
                        (String::from("dev"), NodeKind::File, path_ino("net/dev")),
                        (
                            String::from("if_inet6"),
                            NodeKind::File,
                            path_ino("net/if_inet6"),
                        ),
                        (String::from("route"), NodeKind::File, path_ino("net/route")),
                        (String::from("tcp"), NodeKind::File, path_ino("net/tcp")),
                        (String::from("udp"), NodeKind::File, path_ino("net/udp")),
                        (String::from("unix"), NodeKind::File, path_ino("net/unix")),
                    ],
                });
            }
            "net/dev" => return Ok(self.ro_file(s, self.render_net_dev().into_bytes())),
            "net/tcp" => return Ok(self.ro_file(s, render_net_tcp().into_bytes())),
            "net/udp" => return Ok(self.ro_file(s, render_net_udp().into_bytes())),
            "net/unix" => return Ok(self.ro_file(s, render_net_unix().into_bytes())),
            "net/route" => return Ok(self.ro_file(s, self.render_net_route().into_bytes())),
            "net/arp" => return Ok(self.ro_file(s, render_net_arp().into_bytes())),
            "net/if_inet6" => return Ok(self.ro_file(s, render_net_if_inet6().into_bytes())),
            "sys" => {
                return Ok(ProcNode::Dir {
                    ino: path_ino(s),
                    entries: alloc::vec![(
                        String::from("kernel"),
                        NodeKind::Directory,
                        path_ino("sys/kernel"),
                    )],
                });
            }
            "sys/kernel" => {
                return Ok(ProcNode::Dir {
                    ino: path_ino(s),
                    entries: alloc::vec![
                        (
                            String::from("domainname"),
                            NodeKind::File,
                            path_ino("sys/kernel/domainname"),
                        ),
                        (
                            String::from("hostname"),
                            NodeKind::File,
                            path_ino("sys/kernel/hostname"),
                        ),
                        (
                            String::from("ngroups_max"),
                            NodeKind::File,
                            path_ino("sys/kernel/ngroups_max"),
                        ),
                        (
                            String::from("osrelease"),
                            NodeKind::File,
                            path_ino("sys/kernel/osrelease"),
                        ),
                        (
                            String::from("ostype"),
                            NodeKind::File,
                            path_ino("sys/kernel/ostype"),
                        ),
                        (
                            String::from("pid_max"),
                            NodeKind::File,
                            path_ino("sys/kernel/pid_max"),
                        ),
                    ],
                });
            }
            "sys/kernel/hostname" => {
                let mut content = self.registry.inner.uts.lock().hostname.as_bytes().to_vec();
                content.push(b'\n');
                return Ok(ProcNode::File {
                    ino: path_ino(s),
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    content,
                });
            }
            "sys/kernel/domainname" => {
                let mut content = self
                    .registry
                    .inner
                    .uts
                    .lock()
                    .domainname
                    .as_bytes()
                    .to_vec();
                content.push(b'\n');
                return Ok(ProcNode::File {
                    ino: path_ino(s),
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    content,
                });
            }
            "sys/kernel/osrelease" => {
                let mut out = String::from(RELEASE);
                out.push('\n');
                return Ok(self.ro_file(s, out.into_bytes()));
            }
            "sys/kernel/ostype" => return Ok(self.ro_file(s, b"Linux\n".to_vec())),
            "sys/kernel/pid_max" => {
                return Ok(self.ro_file(s, format!("{PID_MAX}\n").into_bytes()));
            }
            "sys/kernel/ngroups_max" => {
                return Ok(self.ro_file(s, format!("{NGROUPS_MAX}\n").into_bytes()));
            }
            _ => {}
        }

        // Per-process subtree: `<pid>` or `<pid>/...`
        let (pid_str, rest) = match s.split_once('/') {
            Some((first, tail)) => (first, Some(tail)),
            None => (s, None),
        };
        let pid: u32 = pid_str.parse().map_err(|_| FsError::NoEntry)?;
        let proc_rec = self.registry.process(pid).ok_or(FsError::NoEntry)?;
        self.resolve_process_node(&proc_rec, None, s, rest)
    }

    fn resolve_process_node(
        &self,
        rec: &ProcProcessRecord,
        thread_override: Option<&ProcThreadRecord>,
        full_path: &str,
        rest: Option<&str>,
    ) -> FsResult<ProcNode> {
        let uid = rec.credentials.user.effective;
        let gid = rec.credentials.group.effective;
        let Some(sub) = rest else {
            let mut entries = alloc::vec![
                (
                    String::from("cmdline"),
                    NodeKind::File,
                    path_ino(&format!("{full_path}/cmdline")),
                ),
                (
                    String::from("comm"),
                    NodeKind::File,
                    path_ino(&format!("{full_path}/comm")),
                ),
                (
                    String::from("cwd"),
                    NodeKind::Symlink,
                    path_ino(&format!("{full_path}/cwd")),
                ),
                (
                    String::from("environ"),
                    NodeKind::File,
                    path_ino(&format!("{full_path}/environ")),
                ),
                (
                    String::from("exe"),
                    NodeKind::Symlink,
                    path_ino(&format!("{full_path}/exe")),
                ),
                (
                    String::from("fd"),
                    NodeKind::Directory,
                    path_ino(&format!("{full_path}/fd")),
                ),
                (
                    String::from("fdinfo"),
                    NodeKind::Directory,
                    path_ino(&format!("{full_path}/fdinfo")),
                ),
                (
                    String::from("limits"),
                    NodeKind::File,
                    path_ino(&format!("{full_path}/limits")),
                ),
                (
                    String::from("maps"),
                    NodeKind::File,
                    path_ino(&format!("{full_path}/maps")),
                ),
                (
                    String::from("mountinfo"),
                    NodeKind::File,
                    path_ino(&format!("{full_path}/mountinfo")),
                ),
                (
                    String::from("mounts"),
                    NodeKind::File,
                    path_ino(&format!("{full_path}/mounts")),
                ),
                (
                    String::from("root"),
                    NodeKind::Symlink,
                    path_ino(&format!("{full_path}/root")),
                ),
                (
                    String::from("stat"),
                    NodeKind::File,
                    path_ino(&format!("{full_path}/stat")),
                ),
                (
                    String::from("statm"),
                    NodeKind::File,
                    path_ino(&format!("{full_path}/statm")),
                ),
                (
                    String::from("status"),
                    NodeKind::File,
                    path_ino(&format!("{full_path}/status")),
                ),
            ];
            if thread_override.is_none() {
                entries.push((
                    String::from("task"),
                    NodeKind::Directory,
                    path_ino(&format!("{full_path}/task")),
                ));
            }
            return Ok(ProcNode::Dir {
                ino: path_ino(full_path),
                entries,
            });
        };

        match sub {
            "stat" => Ok(ProcNode::File {
                ino: path_ino(full_path),
                mode: 0o444,
                uid,
                gid,
                content: render_pid_stat(rec, thread_override).into_bytes(),
            }),
            "status" => Ok(ProcNode::File {
                ino: path_ino(full_path),
                mode: 0o444,
                uid,
                gid,
                content: render_pid_status(rec, thread_override).into_bytes(),
            }),
            "statm" => Ok(ProcNode::File {
                ino: path_ino(full_path),
                mode: 0o444,
                uid,
                gid,
                content: render_pid_statm(rec).into_bytes(),
            }),
            "cmdline" => {
                let mut buf = Vec::new();
                for arg in &rec.argv {
                    buf.extend_from_slice(arg.as_bytes());
                    buf.push(0);
                }
                Ok(ProcNode::File {
                    ino: path_ino(full_path),
                    mode: 0o444,
                    uid,
                    gid,
                    content: buf,
                })
            }
            "comm" => {
                let name = thread_override.map_or(rec.comm.as_str(), |t| t.comm.as_str());
                let mut out = String::from(name);
                out.push('\n');
                Ok(ProcNode::File {
                    ino: path_ino(full_path),
                    mode: 0o444,
                    uid,
                    gid,
                    content: out.into_bytes(),
                })
            }
            "environ" => {
                let mut buf = Vec::new();
                for var in &rec.env {
                    buf.extend_from_slice(var.as_bytes());
                    buf.push(0);
                }
                Ok(ProcNode::File {
                    ino: path_ino(full_path),
                    mode: 0o400,
                    uid,
                    gid,
                    content: buf,
                })
            }
            "exe" => Ok(ProcNode::Symlink {
                ino: path_ino(full_path),
                uid,
                gid,
                target: rec.exe.clone(),
            }),
            "cwd" => Ok(ProcNode::Symlink {
                ino: path_ino(full_path),
                uid,
                gid,
                target: rec.cwd.clone(),
            }),
            "root" => Ok(ProcNode::Symlink {
                ino: path_ino(full_path),
                uid,
                gid,
                target: rec.root.clone(),
            }),
            "maps" => Ok(ProcNode::File {
                ino: path_ino(full_path),
                mode: 0o444,
                uid,
                gid,
                content: render_pid_maps(rec).into_bytes(),
            }),
            "limits" => Ok(ProcNode::File {
                ino: path_ino(full_path),
                mode: 0o444,
                uid,
                gid,
                content: render_pid_limits(rec).into_bytes(),
            }),
            "mounts" => Ok(ProcNode::File {
                ino: path_ino(full_path),
                mode: 0o444,
                uid,
                gid,
                content: self.render_mounts().into_bytes(),
            }),
            "mountinfo" => Ok(ProcNode::File {
                ino: path_ino(full_path),
                mode: 0o444,
                uid,
                gid,
                content: self.render_mountinfo().into_bytes(),
            }),
            "fd" => {
                let entries = rec
                    .fds
                    .iter()
                    .map(|f| {
                        let name = f.fd.to_string();
                        let ino = path_ino(&format!("{full_path}/{name}"));
                        (name, NodeKind::Symlink, ino)
                    })
                    .collect();
                Ok(ProcNode::Dir {
                    ino: path_ino(full_path),
                    entries,
                })
            }
            "fdinfo" => {
                let entries = rec
                    .fds
                    .iter()
                    .map(|f| {
                        let name = f.fd.to_string();
                        let ino = path_ino(&format!("{full_path}/{name}"));
                        (name, NodeKind::File, ino)
                    })
                    .collect();
                Ok(ProcNode::Dir {
                    ino: path_ino(full_path),
                    entries,
                })
            }
            "task" if thread_override.is_none() => {
                let entries = rec
                    .threads
                    .keys()
                    .map(|tid| {
                        let name = tid.to_string();
                        let ino = path_ino(&format!("{full_path}/{name}"));
                        (name, NodeKind::Directory, ino)
                    })
                    .collect();
                Ok(ProcNode::Dir {
                    ino: path_ino(full_path),
                    entries,
                })
            }
            other => {
                if let Some(fd_str) = other.strip_prefix("fd/") {
                    let fd: i32 = fd_str.parse().map_err(|_| FsError::NoEntry)?;
                    let entry = rec
                        .fds
                        .iter()
                        .find(|f| f.fd == fd)
                        .ok_or(FsError::NoEntry)?;
                    return Ok(ProcNode::Symlink {
                        ino: path_ino(full_path),
                        uid,
                        gid,
                        target: entry.target.clone(),
                    });
                }
                if let Some(fd_str) = other.strip_prefix("fdinfo/") {
                    let fd: i32 = fd_str.parse().map_err(|_| FsError::NoEntry)?;
                    let entry = rec
                        .fds
                        .iter()
                        .find(|f| f.fd == fd)
                        .ok_or(FsError::NoEntry)?;
                    let content = format!(
                        "pos:\t{}\nflags:\t0{:o}\nmnt_id:\t{}\n",
                        entry.pos, entry.flags, entry.mnt_id
                    );
                    return Ok(ProcNode::File {
                        ino: path_ino(full_path),
                        mode: 0o444,
                        uid,
                        gid,
                        content: content.into_bytes(),
                    });
                }
                if thread_override.is_none()
                    && let Some(task_rest) = other.strip_prefix("task/")
                {
                    let (tid_str, task_sub) = match task_rest.split_once('/') {
                        Some((first, tail)) => (first, Some(tail)),
                        None => (task_rest, None),
                    };
                    let tid: u32 = tid_str.parse().map_err(|_| FsError::NoEntry)?;
                    let thread = rec.threads.get(&tid).ok_or(FsError::NoEntry)?;
                    return self.resolve_process_node(rec, Some(thread), full_path, task_sub);
                }
                Err(FsError::NoEntry)
            }
        }
    }

    fn ro_file(&self, path: &str, content: Vec<u8>) -> ProcNode {
        ProcNode::File {
            ino: path_ino(path),
            mode: 0o444,
            uid: 0,
            gid: 0,
            content,
        }
    }

    fn render_meminfo(&self) -> String {
        let machine = crate::machine_memory();
        let total_kb = (machine.usable_bytes as u64) / 1024;
        let free_kb = (machine.free_bytes as u64) / 1024;
        let avail_kb = free_kb;
        let mut out = String::new();
        let _ = writeln!(out, "MemTotal:       {total_kb:>8} kB");
        let _ = writeln!(out, "MemFree:        {free_kb:>8} kB");
        let _ = writeln!(out, "MemAvailable:   {avail_kb:>8} kB");
        let _ = writeln!(out, "Buffers:               0 kB");
        let _ = writeln!(out, "Cached:                0 kB");
        let _ = writeln!(out, "SwapCached:            0 kB");
        let _ = writeln!(out, "SwapTotal:             0 kB");
        let _ = writeln!(out, "SwapFree:              0 kB");
        out
    }

    fn render_uptime(&self) -> String {
        let elapsed_ns = self.registry.inner.uptime_nanos.load(Ordering::Relaxed);
        let secs = elapsed_ns / 1_000_000_000;
        let centis = (elapsed_ns % 1_000_000_000) / 10_000_000;
        let cpus = u64::from(self.registry.cpu_count());
        let idle_ns = elapsed_ns.saturating_mul(cpus);
        let idle_secs = idle_ns / 1_000_000_000;
        let idle_centis = (idle_ns % 1_000_000_000) / 10_000_000;
        format!("{secs}.{centis:02} {idle_secs}.{idle_centis:02}\n")
    }

    fn render_loadavg(&self) -> String {
        let procs = self.registry.inner.processes.lock();
        let total_threads: usize = procs.values().map(|p| p.threads.len().max(1)).sum();
        let running = total_threads.max(1);
        let last_pid = self.registry.inner.last_pid.load(Ordering::Relaxed);
        format!("0.00 0.00 0.00 {running}/{total_threads} {last_pid}\n")
    }

    fn render_stat(&self) -> String {
        let cpus = self.registry.cpu_count();
        let procs = self.registry.inner.processes.lock();
        let running = procs.len().max(1);
        let forks = self.registry.inner.total_forks.load(Ordering::Relaxed);
        let mut out = String::new();
        let _ = writeln!(out, "cpu  0 0 0 0 0 0 0 0 0 0");
        for idx in 0..cpus {
            let _ = writeln!(out, "cpu{idx} 0 0 0 0 0 0 0 0 0 0");
        }
        let _ = writeln!(out, "intr 0");
        let _ = writeln!(out, "ctxt 0");
        let _ = writeln!(out, "btime 0");
        let _ = writeln!(out, "processes {forks}");
        let _ = writeln!(out, "procs_running {running}");
        let _ = writeln!(out, "procs_blocked 0");
        out
    }

    fn render_cpuinfo(&self) -> String {
        let cpus = self.registry.cpu_count();
        let mut out = String::new();
        for idx in 0..cpus {
            let _ = writeln!(out, "processor\t: {idx}");
            let _ = writeln!(out, "vendor_id\t: Helios");
            let _ = writeln!(out, "model name\t: Helios Virtual CPU");
            let _ = writeln!(out, "cpu MHz\t\t: 2000.000");
            let _ = writeln!(out, "cache size\t: 4096 KB");
            let _ = writeln!(out, "cpu cores\t: {cpus}");
            let _ = writeln!(out);
        }
        out
    }

    fn render_version(&self) -> String {
        format!(
            "Linux version {RELEASE} (helios@localhost) (#1 Helios {})\n",
            env!("CARGO_PKG_VERSION")
        )
    }

    fn render_mounts(&self) -> String {
        let mounts = self.registry.inner.mounts.lock();
        let mut out = String::new();
        for m in mounts.iter() {
            let _ = writeln!(
                out,
                "{} {} {} {} 0 0",
                m.source, m.target, m.fstype, m.options
            );
        }
        out
    }

    fn render_mountinfo(&self) -> String {
        let mounts = self.registry.inner.mounts.lock();
        let mut out = String::new();
        for m in mounts.iter() {
            let _ = writeln!(
                out,
                "{} {} {}:{} / {} {} - {} {} {}",
                m.mnt_id,
                m.parent_id,
                m.dev_major,
                m.dev_minor,
                m.target,
                m.options,
                m.fstype,
                m.source,
                m.options
            );
        }
        out
    }

    fn render_net_dev(&self) -> String {
        let net = self.registry.inner.net.lock();
        let mut out = String::from(
            "Inter-|   Receive                                                |  Transmit\n\
             face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
        );
        for iface in &net.interfaces {
            let _ = writeln!(
                out,
                "{:>6}: {:>7} {:>7} {:>4} {:>4}    0     0          0         0 {:>8} {:>7} {:>4} {:>4}    0     0       0          0",
                iface.name,
                iface.rx_bytes,
                iface.rx_packets,
                iface.rx_errors,
                iface.rx_dropped,
                iface.tx_bytes,
                iface.tx_packets,
                iface.tx_errors,
                iface.tx_dropped
            );
        }
        out
    }

    fn render_net_route(&self) -> String {
        let net = self.registry.inner.net.lock();
        let mut out = String::from(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
        );
        for route in &net.routes {
            let dest = u32::from_le_bytes(route.destination);
            let gw = u32::from_le_bytes(route.gateway);
            let mask = u32::from_le_bytes(route.mask);
            let _ = writeln!(
                out,
                "{}\t{:08X}\t{:08X}\t{:04X}\t0\t0\t{}\t{:08X}\t{}\t0\t0",
                route.iface, dest, gw, route.flags, route.metric, mask, route.mtu
            );
        }
        out
    }
    fn stat_sync(&self, path: FsPath<'_>) -> FsResult<Metadata> {
        let node = self.resolve_node(path, None)?;
        let (ino, kind, size) = match node {
            ProcNode::Dir { ino, .. } => (ino, NodeKind::Directory, 0),
            ProcNode::File { ino, content, .. } => (ino, NodeKind::File, content.len() as u64),
            ProcNode::Symlink { ino, target, .. } => (ino, NodeKind::Symlink, target.len() as u64),
        };
        Ok(Metadata {
            id: NodeId::new(self.device, ino),
            kind,
            link_count: if kind == NodeKind::Directory { 2 } else { 1 },
            size,
            access_nanos: 0,
            modified_nanos: 0,
            status_nanos: 0,
        })
    }
}

fn render_filesystems() -> String {
    String::from(
        "nodev\tproc\n\
         nodev\tsysfs\n\
         nodev\tdevtmpfs\n\
         nodev\ttmpfs\n\
         nodev\tdevpts\n\
         nodev\toverlay\n\
         \tbtrfs\n\
         \terofs\n",
    )
}

fn render_net_tcp() -> String {
    String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    )
}

fn render_net_udp() -> String {
    String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
    )
}

fn render_net_unix() -> String {
    String::from("Num       RefCount Protocol Flags    Type St Inode Path\n")
}

fn render_net_arp() -> String {
    String::from("IP address       HW type     Flags       HW address            Mask     Device\n")
}

fn render_net_if_inet6() -> String {
    String::from("00000000000000000000000000000001 01 80 10 80       lo\n")
}

fn render_pid_stat(rec: &ProcProcessRecord, thread: Option<&ProcThreadRecord>) -> String {
    let tid = thread.map_or(rec.pid, |t| t.tid);
    let comm = thread.map_or(rec.comm.as_str(), |t| t.comm.as_str());
    let state = thread.map_or(rec.state, |t| t.state);
    let utime = thread.map_or(rec.utime_ticks, |t| t.utime_ticks);
    let stime = thread.map_or(rec.stime_ticks, |t| t.stime_ticks);
    let num_threads = rec.threads.len().max(1);
    let rss_pages = rec.vm_rss_bytes / PAGE_BYTES;
    format!(
        "{tid} ({comm}) {state} {} {} {} 0 -1 0 0 0 0 0 {utime} {stime} 0 0 20 0 {num_threads} 0 {} {} {rss_pages} 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        rec.ppid, rec.pgid, rec.sid, rec.start_time_ticks, rec.vm_size_bytes
    )
}

fn render_pid_status(rec: &ProcProcessRecord, thread: Option<&ProcThreadRecord>) -> String {
    let tid = thread.map_or(rec.pid, |t| t.tid);
    let comm = thread.map_or(rec.comm.as_str(), |t| t.comm.as_str());
    let state_ch = thread.map_or(rec.state, |t| t.state);
    let state_name = match state_ch {
        'R' => "running",
        'S' => "sleeping",
        'T' => "stopped",
        'Z' => "zombie",
        _ => "sleeping",
    };
    let creds = &rec.credentials;
    let vm_size_kb = rec.vm_size_bytes / 1024;
    let vm_rss_kb = rec.vm_rss_bytes / 1024;
    let mut out = String::new();
    let _ = writeln!(out, "Name:\t{comm}");
    let _ = writeln!(out, "Umask:\t{:04o}", rec.umask);
    let _ = writeln!(out, "State:\t{state_ch} ({state_name})");
    let _ = writeln!(out, "Tgid:\t{}", rec.pid);
    let _ = writeln!(out, "Ngid:\t0");
    let _ = writeln!(out, "Pid:\t{tid}");
    let _ = writeln!(out, "PPid:\t{}", rec.ppid);
    let _ = writeln!(out, "TracerPid:\t0");
    let _ = writeln!(
        out,
        "Uid:\t{}\t{}\t{}\t{}",
        creds.user.real, creds.user.effective, creds.user.saved, creds.user.effective
    );
    let _ = writeln!(
        out,
        "Gid:\t{}\t{}\t{}\t{}",
        creds.group.real, creds.group.effective, creds.group.saved, creds.group.effective
    );
    let _ = writeln!(out, "FDSize:\t{}", rec.fds.len().max(64));
    let _ = write!(out, "Groups:");
    for g in &creds.supplementary_groups {
        let _ = write!(out, " {g}");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "NStgid:\t{}", rec.pid);
    let _ = writeln!(out, "NSpid:\t{tid}");
    let _ = writeln!(out, "NSpgid:\t{}", rec.pgid);
    let _ = writeln!(out, "NSsid:\t{}", rec.sid);
    let _ = writeln!(out, "VmPeak:\t{:>8} kB", vm_size_kb);
    let _ = writeln!(out, "VmSize:\t{:>8} kB", vm_size_kb);
    let _ = writeln!(out, "VmRSS:\t{:>8} kB", vm_rss_kb);
    let _ = writeln!(out, "Threads:\t{}", rec.threads.len().max(1));
    let _ = writeln!(out, "CapInh:\t{:016x}", creds.capabilities.inheritable);
    let _ = writeln!(out, "CapPrm:\t{:016x}", creds.capabilities.permitted);
    let _ = writeln!(out, "CapEff:\t{:016x}", creds.capabilities.effective);
    let _ = writeln!(out, "CapBnd:\t{:016x}", creds.capabilities.bounding);
    let _ = writeln!(out, "CapAmb:\t{:016x}", creds.capabilities.ambient);
    let _ = writeln!(out, "NoNewPrivs:\t{}", u8::from(creds.no_new_privs));
    out
}

fn render_pid_statm(rec: &ProcProcessRecord) -> String {
    let size = rec.vm_size_bytes / PAGE_BYTES;
    let resident = rec.vm_rss_bytes / PAGE_BYTES;
    format!("{size} {resident} 0 0 0 {resident} 0\n")
}

fn render_pid_maps(rec: &ProcProcessRecord) -> String {
    let mut out = String::new();
    for m in &rec.maps {
        let r = if m.readable { 'r' } else { '-' };
        let w = if m.writable { 'w' } else { '-' };
        let x = if m.executable { 'x' } else { '-' };
        let p = if m.shared { 's' } else { 'p' };
        if m.pathname.is_empty() {
            let _ = writeln!(
                out,
                "{:08x}-{:08x} {r}{w}{x}{p} {:08x} 00:00 0",
                m.start, m.end, m.offset
            );
        } else {
            let _ = writeln!(
                out,
                "{:08x}-{:08x} {r}{w}{x}{p} {:08x} 00:00 0          {}",
                m.start, m.end, m.offset, m.pathname
            );
        }
    }
    out
}

fn render_pid_limits(rec: &ProcProcessRecord) -> String {
    let mut out = String::from(
        "Limit                     Soft Limit           Hard Limit           Units     \n",
    );
    for lim in &rec.limits {
        let soft = if lim.soft == u64::MAX {
            String::from("unlimited")
        } else {
            lim.soft.to_string()
        };
        let hard = if lim.hard == u64::MAX {
            String::from("unlimited")
        } else {
            lim.hard.to_string()
        };
        let _ = writeln!(
            out,
            "{:<26}{:<21}{:<21}{:<10}",
            lim.name, soft, hard, lim.units
        );
    }
    out
}

/// Staged write targeting a writable `/proc/sys/kernel/*` sysctl file.
pub struct ProcWrite {
    uts: Arc<spin::Mutex<SharedUts>>,
    target: SysctlTarget,
    len: usize,
}

impl PreparedWrite for ProcWrite {
    type Filled = FsResult<WriteProgress<Self>>;

    fn staged_len(&self) -> usize {
        self.len
    }

    fn fill<F>(self, mut fill: F) -> Self::Filled
    where
        F: FnMut(usize, &mut [u8]),
    {
        let mut buf = alloc::vec![0u8; self.len];
        if !buf.is_empty() {
            fill(0, &mut buf);
        }
        let trimmed = match buf.iter().position(|&b| b == b'\n' || b == 0) {
            Some(pos) => &buf[..pos],
            None => &buf[..],
        };
        let field = UtsField::from_bytes(trimmed).map_err(|_| FsError::Invalid)?;
        let mut uts = self.uts.lock();
        match self.target {
            SysctlTarget::Hostname => uts.hostname = field,
            SysctlTarget::Domainname => uts.domainname = field,
        }
        Ok(WriteProgress::Done(Landed {
            offset: 0,
            len: self.len,
        }))
    }
}

pub struct ProcDir {
    entries: Vec<(String, NodeKind, u64)>,
}

impl DirStream for ProcDir {
    async fn read(&self, cookie: DirCookie, max_entries: usize) -> FsResult<Vec<DirEntry>> {
        let start = usize::try_from(cookie.raw()).unwrap_or(self.entries.len());
        if start >= self.entries.len() || max_entries == 0 {
            return Ok(Vec::new());
        }
        let end = start.saturating_add(max_entries).min(self.entries.len());
        let mut out = Vec::with_capacity(end - start);
        for (idx, (name, kind, inode)) in self.entries[start..end].iter().enumerate() {
            out.push(DirEntry {
                name: name.clone(),
                kind: *kind,
                inode: *inode,
                next: DirCookie::new((start + idx + 1) as u64),
            });
        }
        Ok(out)
    }

    async fn rewind(&mut self) -> FsResult<()> {
        Ok(())
    }
}

impl FileSystem for ProcFs {
    type Payer = crate::StoragePayer;
    type Write = ProcWrite;
    type Dir = ProcDir;

    delegate_path_handles!();

    async fn stat(&self, path: FsPath<'_>) -> FsResult<Metadata> {
        self.stat_sync(path)
    }

    async fn open(
        &self,
        path: FsPath<'_>,
        flags: OpenFlags,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<Opened<OwnedFsPath>> {
        if flags.contains(OpenFlags::CREATE) {
            return Err(FsError::NotPermitted);
        }
        let metadata = self.stat_sync(path)?;
        if flags.contains(OpenFlags::DIRECTORY) && metadata.kind != NodeKind::Directory {
            return Err(FsError::NotDirectory);
        }
        Ok(Opened {
            metadata,
            handle: OwnedFsPath::from(path),
        })
    }

    async fn read_at(&self, path: FsPath<'_>, offset: u64, max_bytes: usize) -> FsResult<Bytes> {
        match self.resolve_node(path, None)? {
            ProcNode::File { content, .. } => {
                let start = usize::try_from(offset)
                    .unwrap_or(content.len())
                    .min(content.len());
                let end = start.saturating_add(max_bytes).min(content.len());
                Ok(Bytes::copy_from_slice(&content[start..end]))
            }
            ProcNode::Dir { .. } => Err(FsError::IsDirectory),
            ProcNode::Symlink { .. } => Err(FsError::Invalid),
        }
    }

    async fn prepare_write<'a>(
        &'a self,
        path: FsPath<'a>,
        _position: WritePosition,
        len: usize,
        _now: u64,
        _payer: &'a Self::Payer,
    ) -> FsResult<Self::Write> {
        let Some(target) = Self::writable_sysctl(path) else {
            return Err(FsError::NotPermitted);
        };
        Ok(ProcWrite {
            uts: self.registry.inner.uts.clone(),
            target,
            len,
        })
    }

    async fn set_size(
        &self,
        path: FsPath<'_>,
        _size: u64,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        if Self::writable_sysctl(path).is_some() {
            Ok(())
        } else {
            Err(FsError::NotPermitted)
        }
    }

    async fn set_times(
        &self,
        _path: FsPath<'_>,
        _access_nanos: Option<u64>,
        _modified_nanos: Option<u64>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::NotPermitted)
    }

    async fn open_dir(&self, path: FsPath<'_>) -> FsResult<Self::Dir> {
        match self.resolve_node(path, None)? {
            ProcNode::Dir { entries, .. } => Ok(ProcDir { entries }),
            _ => Err(FsError::NotDirectory),
        }
    }

    async fn create_directory(
        &self,
        _path: FsPath<'_>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::NotPermitted)
    }

    async fn remove_directory(
        &self,
        _path: FsPath<'_>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::NotPermitted)
    }

    async fn unlink(&self, _path: FsPath<'_>, _now: u64, _payer: &Self::Payer) -> FsResult<()> {
        Err(FsError::NotPermitted)
    }

    async fn rename(
        &self,
        _source: FsPath<'_>,
        _destination: FsPath<'_>,
        _mode: RenameMode,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::NotPermitted)
    }

    async fn link(
        &self,
        _existing: FsPath<'_>,
        _link: FsPath<'_>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::NotPermitted)
    }

    async fn symlink(
        &self,
        _target: &str,
        _link: FsPath<'_>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::NotPermitted)
    }

    async fn read_link(&self, path: FsPath<'_>) -> FsResult<String> {
        self.read_link_for(path, None)
    }

    async fn sync(&self, _path: FsPath<'_>) -> FsResult<()> {
        Ok(())
    }

    async fn sync_data(&self, _path: FsPath<'_>) -> FsResult<()> {
        Ok(())
    }
}
