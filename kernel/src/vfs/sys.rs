//! Container-scoped `/sys` virtual filesystem (`SysFs`).
//!
//! Exposes CPU topology (`devices/system/cpu/{online,possible,present,cpu0..N}`),
//! network interface attributes and statistics (`class/net/{lo,eth0}/*`),
//! TTY class metadata (`class/tty/*`), character device nodes (`dev/char/*`),
//! and authority-bounded PCI device visibility (`bus/pci/devices/`, strictly
//! empty when the container holds no device grants).
//!
//! # Concurrency contract
//!
//! Reads live snapshots from the container's [`ProcRegistry`] and [`PtyRegistry`]
//! under short synchronous `spin::Mutex` locks never held across an `.await`.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;

use bytes::Bytes;
use helios_hal::fs::{
    DeviceId, DirCookie, DirEntry, DirStream, FileSystem, FsError, FsPath, FsResult, Metadata,
    NodeId, NodeKind, OpenFlags, Opened, OwnedFsPath, RenameMode, WritePosition,
};
use triomphe::Arc;

use super::dev::PtyRegistry;
use super::proc::ProcRegistry;
use super::{UnixAttributes, UnixFsError, UnixNodeMetadata, delegate_path_handles};

fn sys_ino(path: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in path.as_bytes() {
        h = (h ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    if h <= 1 { 2 } else { h }
}

/// Container-scoped read-only `/sys` virtual filesystem.
#[derive(Clone)]
pub struct SysFs {
    device: DeviceId,
    proc: ProcRegistry,
    ptys: PtyRegistry,
    granted_devices: Arc<Vec<String>>,
}

enum SysNode {
    Dir(Vec<(String, NodeKind, u64)>),
    File(Vec<u8>),
}

impl SysFs {
    pub fn new(
        device: DeviceId,
        proc: ProcRegistry,
        ptys: PtyRegistry,
        granted_devices: Vec<String>,
    ) -> Self {
        Self {
            device,
            proc,
            ptys,
            granted_devices: Arc::new(granted_devices),
        }
    }

    fn cpu_range_text(&self) -> String {
        let count = self.proc.cpu_count();
        if count <= 1 {
            String::from("0\n")
        } else {
            format!("0-{}\n", count - 1)
        }
    }

    fn resolve(&self, path: FsPath<'_>) -> FsResult<SysNode> {
        let s = path.as_str();
        if s.is_empty() {
            return Ok(SysNode::Dir(alloc::vec![
                (String::from("bus"), NodeKind::Directory, sys_ino("bus")),
                (String::from("class"), NodeKind::Directory, sys_ino("class")),
                (String::from("dev"), NodeKind::Directory, sys_ino("dev")),
                (
                    String::from("devices"),
                    NodeKind::Directory,
                    sys_ino("devices"),
                ),
            ]));
        }

        match s {
            "bus" => {
                return Ok(SysNode::Dir(alloc::vec![(
                    String::from("pci"),
                    NodeKind::Directory,
                    sys_ino("bus/pci"),
                )]));
            }
            "bus/pci" => {
                return Ok(SysNode::Dir(alloc::vec![(
                    String::from("devices"),
                    NodeKind::Directory,
                    sys_ino("bus/pci/devices"),
                )]));
            }
            "bus/pci/devices" => {
                let entries = self
                    .granted_devices
                    .iter()
                    .map(|name| {
                        (
                            name.clone(),
                            NodeKind::Directory,
                            sys_ino(&format!("bus/pci/devices/{name}")),
                        )
                    })
                    .collect();
                return Ok(SysNode::Dir(entries));
            }
            "class" => {
                return Ok(SysNode::Dir(alloc::vec![
                    (
                        String::from("net"),
                        NodeKind::Directory,
                        sys_ino("class/net"),
                    ),
                    (
                        String::from("tty"),
                        NodeKind::Directory,
                        sys_ino("class/tty"),
                    ),
                ]));
            }
            "class/net" => {
                let net = self.proc.net_snapshot();
                let entries = net
                    .interfaces
                    .iter()
                    .map(|iface| {
                        (
                            iface.name.clone(),
                            NodeKind::Directory,
                            sys_ino(&format!("class/net/{}", iface.name)),
                        )
                    })
                    .collect();
                return Ok(SysNode::Dir(entries));
            }
            "class/tty" => {
                return Ok(SysNode::Dir(alloc::vec![
                    (
                        String::from("console"),
                        NodeKind::Directory,
                        sys_ino("class/tty/console"),
                    ),
                    (
                        String::from("ptmx"),
                        NodeKind::Directory,
                        sys_ino("class/tty/ptmx"),
                    ),
                    (
                        String::from("tty"),
                        NodeKind::Directory,
                        sys_ino("class/tty/tty"),
                    ),
                ]));
            }
            "class/tty/tty" => {
                return Ok(SysNode::Dir(alloc::vec![(
                    String::from("dev"),
                    NodeKind::File,
                    sys_ino("class/tty/tty/dev"),
                )]));
            }
            "class/tty/tty/dev" => return Ok(SysNode::File(b"5:0\n".to_vec())),
            "class/tty/console" => {
                return Ok(SysNode::Dir(alloc::vec![(
                    String::from("dev"),
                    NodeKind::File,
                    sys_ino("class/tty/console/dev"),
                )]));
            }
            "class/tty/console/dev" => return Ok(SysNode::File(b"5:1\n".to_vec())),
            "class/tty/ptmx" => {
                return Ok(SysNode::Dir(alloc::vec![(
                    String::from("dev"),
                    NodeKind::File,
                    sys_ino("class/tty/ptmx/dev"),
                )]));
            }
            "class/tty/ptmx/dev" => return Ok(SysNode::File(b"5:2\n".to_vec())),
            "dev" => {
                return Ok(SysNode::Dir(alloc::vec![(
                    String::from("char"),
                    NodeKind::Directory,
                    sys_ino("dev/char"),
                )]));
            }
            "dev/char" => {
                let mut entries = alloc::vec![
                    (
                        String::from("1:3"),
                        NodeKind::Directory,
                        sys_ino("dev/char/1:3")
                    ),
                    (
                        String::from("1:5"),
                        NodeKind::Directory,
                        sys_ino("dev/char/1:5")
                    ),
                    (
                        String::from("1:7"),
                        NodeKind::Directory,
                        sys_ino("dev/char/1:7")
                    ),
                    (
                        String::from("1:8"),
                        NodeKind::Directory,
                        sys_ino("dev/char/1:8")
                    ),
                    (
                        String::from("1:9"),
                        NodeKind::Directory,
                        sys_ino("dev/char/1:9")
                    ),
                    (
                        String::from("5:0"),
                        NodeKind::Directory,
                        sys_ino("dev/char/5:0")
                    ),
                    (
                        String::from("5:1"),
                        NodeKind::Directory,
                        sys_ino("dev/char/5:1")
                    ),
                    (
                        String::from("5:2"),
                        NodeKind::Directory,
                        sys_ino("dev/char/5:2")
                    ),
                ];
                for idx in self.ptys.list_indices() {
                    let name = format!("136:{idx}");
                    let ino = sys_ino(&format!("dev/char/{name}"));
                    entries.push((name, NodeKind::Directory, ino));
                }
                return Ok(SysNode::Dir(entries));
            }
            "devices" => {
                return Ok(SysNode::Dir(alloc::vec![(
                    String::from("system"),
                    NodeKind::Directory,
                    sys_ino("devices/system"),
                )]));
            }
            "devices/system" => {
                return Ok(SysNode::Dir(alloc::vec![(
                    String::from("cpu"),
                    NodeKind::Directory,
                    sys_ino("devices/system/cpu"),
                )]));
            }
            "devices/system/cpu" => {
                let mut entries = alloc::vec![
                    (
                        String::from("online"),
                        NodeKind::File,
                        sys_ino("devices/system/cpu/online"),
                    ),
                    (
                        String::from("possible"),
                        NodeKind::File,
                        sys_ino("devices/system/cpu/possible"),
                    ),
                    (
                        String::from("present"),
                        NodeKind::File,
                        sys_ino("devices/system/cpu/present"),
                    ),
                ];
                for idx in 0..self.proc.cpu_count() {
                    let name = format!("cpu{idx}");
                    let ino = sys_ino(&format!("devices/system/cpu/{name}"));
                    entries.push((name, NodeKind::Directory, ino));
                }
                return Ok(SysNode::Dir(entries));
            }
            "devices/system/cpu/online"
            | "devices/system/cpu/possible"
            | "devices/system/cpu/present" => {
                return Ok(SysNode::File(self.cpu_range_text().into_bytes()));
            }
            _ => {}
        }

        // `devices/system/cpu/cpu<N>`
        if let Some(rest) = s.strip_prefix("devices/system/cpu/cpu") {
            let (idx_str, sub) = match rest.split_once('/') {
                Some((a, b)) => (a, Some(b)),
                None => (rest, None),
            };
            let idx: u32 = idx_str.parse().map_err(|_| FsError::NoEntry)?;
            if idx >= self.proc.cpu_count() {
                return Err(FsError::NoEntry);
            }
            return match sub {
                None => Ok(SysNode::Dir(alloc::vec![(
                    String::from("online"),
                    NodeKind::File,
                    sys_ino(&format!("{s}/online")),
                )])),
                Some("online") => Ok(SysNode::File(b"1\n".to_vec())),
                _ => Err(FsError::NoEntry),
            };
        }

        // `class/net/<iface>/...`
        if let Some(rest) = s.strip_prefix("class/net/") {
            let (ifname, sub) = match rest.split_once('/') {
                Some((a, b)) => (a, Some(b)),
                None => (rest, None),
            };
            let net = self.proc.net_snapshot();
            let iface = net
                .interfaces
                .iter()
                .find(|i| i.name == ifname)
                .ok_or(FsError::NoEntry)?;
            return match sub {
                None => Ok(SysNode::Dir(alloc::vec![
                    (
                        String::from("address"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/address")),
                    ),
                    (
                        String::from("flags"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/flags")),
                    ),
                    (
                        String::from("ifindex"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/ifindex")),
                    ),
                    (
                        String::from("mtu"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/mtu")),
                    ),
                    (
                        String::from("operstate"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/operstate")),
                    ),
                    (
                        String::from("statistics"),
                        NodeKind::Directory,
                        sys_ino(&format!("{s}/statistics")),
                    ),
                    (
                        String::from("type"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/type")),
                    ),
                ])),
                Some("ifindex") => Ok(SysNode::File(format!("{}\n", iface.ifindex).into_bytes())),
                Some("address") => Ok(SysNode::File(
                    format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                        iface.mac[0],
                        iface.mac[1],
                        iface.mac[2],
                        iface.mac[3],
                        iface.mac[4],
                        iface.mac[5]
                    )
                    .into_bytes(),
                )),
                Some("mtu") => Ok(SysNode::File(format!("{}\n", iface.mtu).into_bytes())),
                Some("flags") => Ok(SysNode::File(format!("0x{:x}\n", iface.flags).into_bytes())),
                Some("operstate") => {
                    Ok(SysNode::File(format!("{}\n", iface.operstate).into_bytes()))
                }
                Some("type") => Ok(SysNode::File(format!("{}\n", iface.arp_type).into_bytes())),
                Some("statistics") => Ok(SysNode::Dir(alloc::vec![
                    (
                        String::from("rx_bytes"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/rx_bytes")),
                    ),
                    (
                        String::from("rx_dropped"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/rx_dropped")),
                    ),
                    (
                        String::from("rx_errors"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/rx_errors")),
                    ),
                    (
                        String::from("rx_packets"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/rx_packets")),
                    ),
                    (
                        String::from("tx_bytes"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/tx_bytes")),
                    ),
                    (
                        String::from("tx_dropped"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/tx_dropped")),
                    ),
                    (
                        String::from("tx_errors"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/tx_errors")),
                    ),
                    (
                        String::from("tx_packets"),
                        NodeKind::File,
                        sys_ino(&format!("{s}/tx_packets")),
                    ),
                ])),
                Some("statistics/rx_bytes") => {
                    Ok(SysNode::File(format!("{}\n", iface.rx_bytes).into_bytes()))
                }
                Some("statistics/rx_packets") => Ok(SysNode::File(
                    format!("{}\n", iface.rx_packets).into_bytes(),
                )),
                Some("statistics/rx_errors") => {
                    Ok(SysNode::File(format!("{}\n", iface.rx_errors).into_bytes()))
                }
                Some("statistics/rx_dropped") => Ok(SysNode::File(
                    format!("{}\n", iface.rx_dropped).into_bytes(),
                )),
                Some("statistics/tx_bytes") => {
                    Ok(SysNode::File(format!("{}\n", iface.tx_bytes).into_bytes()))
                }
                Some("statistics/tx_packets") => Ok(SysNode::File(
                    format!("{}\n", iface.tx_packets).into_bytes(),
                )),
                Some("statistics/tx_errors") => {
                    Ok(SysNode::File(format!("{}\n", iface.tx_errors).into_bytes()))
                }
                Some("statistics/tx_dropped") => Ok(SysNode::File(
                    format!("{}\n", iface.tx_dropped).into_bytes(),
                )),
                _ => Err(FsError::NoEntry),
            };
        }

        // `dev/char/<major>:<minor>`
        if let Some(rest) = s.strip_prefix("dev/char/") {
            let (dev_id, sub) = match rest.split_once('/') {
                Some((a, b)) => (a, Some(b)),
                None => (rest, None),
            };
            let valid = matches!(
                dev_id,
                "1:3" | "1:5" | "1:7" | "1:8" | "1:9" | "5:0" | "5:1" | "5:2"
            ) || dev_id
                .strip_prefix("136:")
                .and_then(|n| n.parse::<u32>().ok())
                .is_some_and(|n| self.ptys.get(n).is_some());
            if !valid {
                return Err(FsError::NoEntry);
            }
            return match sub {
                None => Ok(SysNode::Dir(alloc::vec![(
                    String::from("uevent"),
                    NodeKind::File,
                    sys_ino(&format!("{s}/uevent")),
                )])),
                Some("uevent") => {
                    let (maj, min) = dev_id.split_once(':').unwrap_or(("0", "0"));
                    Ok(SysNode::File(
                        format!("MAJOR={maj}\nMINOR={min}\n").into_bytes(),
                    ))
                }
                _ => Err(FsError::NoEntry),
            };
        }

        // `bus/pci/devices/<granted>`
        if let Some(rest) = s.strip_prefix("bus/pci/devices/") {
            let (dev_name, sub) = match rest.split_once('/') {
                Some((a, b)) => (a, Some(b)),
                None => (rest, None),
            };
            if !self.granted_devices.iter().any(|d| d == dev_name) {
                return Err(FsError::NoEntry);
            }
            return match sub {
                None => Ok(SysNode::Dir(alloc::vec![(
                    String::from("uevent"),
                    NodeKind::File,
                    sys_ino(&format!("{s}/uevent")),
                )])),
                Some("uevent") => Ok(SysNode::File(
                    format!("PCI_SLOT_NAME={dev_name}\n").into_bytes(),
                )),
                _ => Err(FsError::NoEntry),
            };
        }

        Err(FsError::NoEntry)
    }

    pub fn unix_node_metadata(&self, path: FsPath<'_>) -> Result<UnixNodeMetadata, UnixFsError> {
        let node = self.resolve(path)?;
        let (kind, permissions) = match node {
            SysNode::Dir(_) => (NodeKind::Directory, 0o555),
            SysNode::File(_) => (NodeKind::File, 0o444),
        };
        Ok(UnixNodeMetadata {
            kind,
            attributes: UnixAttributes {
                permissions,
                uid: 0,
                gid: 0,
            },
            rdev: 0,
        })
    }
    fn stat_sync(&self, path: FsPath<'_>) -> FsResult<Metadata> {
        let node = self.resolve(path)?;
        let (kind, size) = match node {
            SysNode::Dir(_) => (NodeKind::Directory, 0),
            SysNode::File(bytes) => (NodeKind::File, bytes.len() as u64),
        };
        let ino = if path.is_root() {
            1
        } else {
            sys_ino(path.as_str())
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

pub struct SysDir {
    entries: Vec<(String, NodeKind, u64)>,
}

impl DirStream for SysDir {
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

impl FileSystem for SysFs {
    type Payer = crate::StoragePayer;
    type Write = Infallible;
    type Dir = SysDir;

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
        if flags.contains(OpenFlags::CREATE) || flags.contains(OpenFlags::TRUNCATE) {
            return Err(FsError::ReadOnly);
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
        match self.resolve(path)? {
            SysNode::File(bytes) => {
                let start = usize::try_from(offset)
                    .unwrap_or(bytes.len())
                    .min(bytes.len());
                let end = start.saturating_add(max_bytes).min(bytes.len());
                Ok(Bytes::copy_from_slice(&bytes[start..end]))
            }
            SysNode::Dir(_) => Err(FsError::IsDirectory),
        }
    }

    async fn prepare_write<'a>(
        &'a self,
        _path: FsPath<'a>,
        _position: WritePosition,
        _len: usize,
        _now: u64,
        _payer: &'a Self::Payer,
    ) -> FsResult<Self::Write> {
        Err(FsError::ReadOnly)
    }

    async fn set_size(
        &self,
        _path: FsPath<'_>,
        _size: u64,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn set_times(
        &self,
        _path: FsPath<'_>,
        _access_nanos: Option<u64>,
        _modified_nanos: Option<u64>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn open_dir(&self, path: FsPath<'_>) -> FsResult<Self::Dir> {
        match self.resolve(path)? {
            SysNode::Dir(entries) => Ok(SysDir { entries }),
            SysNode::File(_) => Err(FsError::NotDirectory),
        }
    }

    async fn create_directory(
        &self,
        _path: FsPath<'_>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn remove_directory(
        &self,
        _path: FsPath<'_>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn unlink(&self, _path: FsPath<'_>, _now: u64, _payer: &Self::Payer) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn rename(
        &self,
        _source: FsPath<'_>,
        _destination: FsPath<'_>,
        _mode: RenameMode,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn link(
        &self,
        _existing: FsPath<'_>,
        _link: FsPath<'_>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn symlink(
        &self,
        _target: &str,
        _link: FsPath<'_>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn read_link(&self, _path: FsPath<'_>) -> FsResult<String> {
        Err(FsError::Invalid)
    }

    async fn sync(&self, _path: FsPath<'_>) -> FsResult<()> {
        Ok(())
    }

    async fn sync_data(&self, _path: FsPath<'_>) -> FsResult<()> {
        Ok(())
    }
}
