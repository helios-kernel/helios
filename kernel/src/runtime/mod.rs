//! Kernel runtime state and the type aliases shared with the
//! component host.
//!
//! `state` carries the per-instance runtime state used by the
//! component runtime backend. `types` declares the kernel-facing
//! aliases for component-host service interfaces (network, host
//! filesystem, etc.) that backends and tests share.

mod state;
mod types;

pub use state::{RuntimeState, SnapshotHold, SnapshotHoldBusy};
pub use types::{
    AuthorityDomain, ComponentHostNetwork, ComponentNetworkService, ComponentNetworkState,
    DnsError, DnsErrorKind, ExecOutput, ExecResult, HostCreation, HostDirEntry, HostDirLimit,
    HostFileSystem, HostFilledWrite, HostFsError, HostFsErrorKind, HostMetadata, HostShareRestore,
    HostWrite, HttpsRecord, Ipv4Address, NetworkErrorDetail, NetworkHandle, NetworkIpAddress,
    NetworkPacketPump, ObjectIdentity, PacketFrame, PingError, PingErrorKind, PingReply,
    RegisteredTcpReadBuffer, SocketReadiness, TcpAccepted, TcpConnectPoll, TcpError, TcpErrorKind,
    TcpListener, TcpPayloadPieces, TcpReadInto, TcpReadProgress, TcpWriteProgress, UdpBinding,
    UdpDatagram, UdpError, UdpErrorKind,
};
