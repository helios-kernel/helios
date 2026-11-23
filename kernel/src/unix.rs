//! Capability bridge for optional UNIX process bookkeeping, and the
//! machine's network as the shared UNIX socket objects see it.

use crate::settings::{Setting, SettingUnit};
use crate::{ComponentNetworkService, Ipv4Address, NetworkIpAddress};
use helios_unix::{DescriptorLimit, SocketFamily, SocketLimits, SocketNetwork};

// A limit is a `usize` and a setting's amount is a `u64`; the conversions
// below are lossless only where both have the same width, which every
// target the kernel runs on does.
const _: () = assert!(usize::BITS == u64::BITS);

/// The machine-wide setting a new process's descriptor limit starts from.
/// A running process keeps the limit it was created with.
pub struct DescriptorLimitSetting;

impl Setting for DescriptorLimitSetting {
    const NAME: &'static str = "process.descriptor-limit";
    const DESCRIPTION: &'static str =
        "Descriptor numbers a new process may hand out; one past the highest it may open.";
    const UNIT: SettingUnit = SettingUnit::Count;
    type Value = DescriptorLimit;
    const DEFAULT: DescriptorLimit = DescriptorLimit::DEFAULT;

    fn to_raw(value: DescriptorLimit) -> u64 {
        u64::try_from(value.get()).expect("usize is no wider than u64, asserted above")
    }

    fn from_raw(raw: u64) -> DescriptorLimit {
        DescriptorLimit::new(usize::try_from(raw).expect("usize is as wide as u64, asserted above"))
    }
}

/// The machine's network service as `helios-unix`'s sockets see it: the
/// network the socket descriptors of every UNIX ABI the kernel hosts live
/// on. It names the service's handle types and forwards the close calls,
/// and adds nothing of its own.
#[derive(Clone)]
pub(crate) struct UnixNetwork<Service>(Service);

impl<Service: ComponentNetworkService> UnixNetwork<Service> {
    pub(crate) const fn new(service: Service) -> Self {
        Self(service)
    }
}

impl<Service: ComponentNetworkService> SocketNetwork for UnixNetwork<Service> {
    type Address = NetworkIpAddress;
    type TcpStream = Service::TcpStream;
    type TcpListener = Service::TcpListener;
    type UdpSocket = Service::UdpSocket;
    type PacketSocket = u64;

    /// The netstack's receive window and transmit buffer, and its default
    /// hop limit.
    const LIMITS: SocketLimits = SocketLimits {
        receive_buffer_bytes: helios_netstack::TCP_RECEIVE_WINDOW_BYTES as u64,
        send_buffer_bytes: helios_netstack::TCP_TRANSMIT_BUFFER_BYTES as u64,
        default_hop_limit: helios_netstack::DEFAULT_HOP_LIMIT,
    };

    fn tcp_close(&self, stream: Self::TcpStream) {
        self.0.tcp_close(stream);
    }

    fn tcp_listener_close(&self, listener: Self::TcpListener) {
        self.0.tcp_listener_close(listener);
    }

    fn udp_close(&self, socket: Self::UdpSocket) {
        self.0.udp_close(socket);
    }

    fn packet_close(&self, socket: Self::PacketSocket) {
        self.0.packet_close(socket);
    }
}

/// The wildcard local address of `family`: `0.0.0.0` or `::`.
pub(crate) const fn unspecified_address(family: SocketFamily) -> NetworkIpAddress {
    match family {
        SocketFamily::Ipv4 => NetworkIpAddress::Ipv4(Ipv4Address::new([0, 0, 0, 0])),
        SocketFamily::Ipv6 => NetworkIpAddress::Ipv6(helios_netstack::Ipv6Address::UNSPECIFIED),
    }
}

/// Whether a socket of `family` may use `address`. There is no
/// v4-mapped-v6 path: the netstack keeps the two families in separate
/// socket address spaces, so accepting a v4 address on a v6 socket would
/// produce a socket that cannot be described back to its program.
pub(crate) const fn family_accepts(family: SocketFamily, address: NetworkIpAddress) -> bool {
    matches!(
        (family, address),
        (SocketFamily::Ipv4, NetworkIpAddress::Ipv4(_))
            | (SocketFamily::Ipv6, NetworkIpAddress::Ipv6(_))
    )
}

#[cfg(test)]
mod network_tests {
    use super::{family_accepts, unspecified_address};
    use crate::{Ipv4Address, NetworkIpAddress};
    use helios_unix::SocketFamily;

    #[test]
    fn each_family_has_its_own_wildcard_and_accepts_only_its_addresses() {
        let v4 = NetworkIpAddress::Ipv4(Ipv4Address::new([10, 0, 2, 2]));
        let v6 = NetworkIpAddress::Ipv6(helios_netstack::Ipv6Address::UNSPECIFIED);
        assert_eq!(
            unspecified_address(SocketFamily::Ipv4),
            NetworkIpAddress::Ipv4(Ipv4Address::new([0, 0, 0, 0]))
        );
        assert_eq!(unspecified_address(SocketFamily::Ipv6), v6);
        assert!(family_accepts(SocketFamily::Ipv4, v4));
        assert!(!family_accepts(SocketFamily::Ipv4, v6));
        assert!(family_accepts(SocketFamily::Ipv6, v6));
        assert!(!family_accepts(SocketFamily::Ipv6, v4));
    }
}

#[cfg(test)]
mod process_tests {
    use crate::{
        DirectoryAuthorityRights, DirectoryPreopen, ProcessAuthority, ProcessAuthorityRights,
    };
    use helios_unix::{ProcessState, ProcessTable, ProcessTableError};

    fn authority_with(rights: ProcessAuthorityRights) -> ProcessAuthority {
        let mut authority = ProcessAuthority::empty();
        authority.grant_process_rights(rights);
        authority
    }

    #[test]
    fn spawn_requires_child_authority_subset() {
        let mut table = ProcessTable::new();
        let mut parent_authority = authority_with(ProcessAuthorityRights::SPAWN);
        parent_authority.insert_directory_preopen(
            DirectoryPreopen::new("/bin", "/", DirectoryAuthorityRights::READ)
                .expect("test preopen should be valid"),
        );
        let spawn = parent_authority
            .derive_spawn_authority()
            .expect("parent should derive spawn authority");
        let parent = table
            .register_root(parent_authority)
            .expect("root registration should succeed");

        let mut child_authority = ProcessAuthority::empty();
        child_authority.insert_directory_preopen(
            DirectoryPreopen::new("/bin", "/", DirectoryAuthorityRights::READ)
                .expect("test preopen should be valid"),
        );
        let child = table
            .spawn(&spawn, parent, child_authority)
            .expect("subset child authority should spawn");
        assert_eq!(table.record(child).unwrap().parent(), Some(parent));

        let mut overgrant = ProcessAuthority::empty();
        overgrant.insert_directory_preopen(
            DirectoryPreopen::new("/bin", "/", DirectoryAuthorityRights::WRITE)
                .expect("test preopen should be valid"),
        );
        assert_eq!(
            table.spawn(&spawn, parent, overgrant),
            Err(ProcessTableError::AuthorityWidening)
        );
    }

    #[test]
    fn spawn_with_empty_child_authority_has_zero_ambient_rights() {
        let mut table = ProcessTable::new();
        let parent_authority = ProcessAuthority::root();
        let spawn = parent_authority
            .derive_spawn_authority()
            .expect("root should derive spawn authority");
        let parent = table
            .register_root(parent_authority)
            .expect("root registration should succeed");

        let child = table
            .spawn(&spawn, parent, ProcessAuthority::empty())
            .expect("empty child authority should be a valid subset");
        assert_eq!(
            table.record(child).unwrap().authority(),
            &ProcessAuthority::empty()
        );
    }

    #[test]
    fn fork_inherits_and_exec_preserves_authority() {
        let mut table = ProcessTable::new();
        let authority = authority_with(ProcessAuthorityRights::FORK | ProcessAuthorityRights::EXEC);
        let fork = authority
            .derive_fork_authority()
            .expect("parent should derive fork authority");
        let exec = authority
            .derive_exec_authority()
            .expect("parent should derive exec authority");
        let parent = table
            .register_root(authority.clone())
            .expect("root registration should succeed");
        let child = table
            .fork(&fork, parent)
            .expect("fork should inherit parent authority");

        assert_eq!(table.record(child).unwrap().authority(), &authority);
        table
            .exec(&exec, child)
            .expect("exec should preserve authority");
        assert_eq!(table.record(child).unwrap().authority(), &authority);
    }

    #[test]
    fn join_and_signal_require_typed_caps() {
        let mut table = ProcessTable::new();
        let authority =
            authority_with(ProcessAuthorityRights::JOIN | ProcessAuthorityRights::SIGNAL);
        let join = authority
            .derive_join_authority()
            .expect("join authority should derive");
        let signal = authority
            .derive_signal_authority()
            .expect("signal authority should derive");
        let process = table
            .register_root(authority)
            .expect("root registration should succeed");

        assert_eq!(table.join(&join, process).unwrap(), None);
        table.signal(&signal, process, 9).unwrap();
        assert_eq!(
            table.record(process).unwrap().state(),
            ProcessState::Signaled(9)
        );
        assert_eq!(table.join(&join, process).unwrap(), None);
        table.exit(process, 7).unwrap();
        assert_eq!(table.join(&join, process).unwrap(), Some(7));
    }
}

#[cfg(test)]
mod thread_tests {
    use crate::{ProcessAuthority, ProcessAuthorityRights};
    use helios_unix::{ProcessId, ProcessTable, ThreadState, ThreadTable};

    fn process(raw: u64) -> ProcessId {
        let mut table = ProcessTable::new();
        let mut authority = ProcessAuthority::empty();
        authority.grant_process_rights(ProcessAuthorityRights::SPAWN);
        let process = table.register_root(authority).unwrap();
        assert_eq!(process.raw(), raw);
        process
    }

    #[test]
    fn thread_lifecycle_tracks_join_state() {
        let mut table = ThreadTable::new();
        let thread = table.spawn(process(1)).unwrap();

        assert_eq!(table.join(thread), Ok(None));
        table.exit(thread, 7).unwrap();
        assert_eq!(table.join(thread), Ok(Some(7)));
    }

    #[test]
    fn sleeping_threads_wake_when_deadline_passes() {
        let mut table = ThreadTable::new();
        let thread = table.spawn(process(1)).unwrap();
        table.set_sleeping(thread, 50).unwrap();

        assert_eq!(table.wake_due(49), 0);
        assert_eq!(
            table.record(thread).unwrap().state(),
            ThreadState::Sleeping { wake_at_nanos: 50 }
        );
        assert_eq!(table.wake_due(50), 1);
        assert_eq!(table.record(thread).unwrap().state(), ThreadState::Runnable);
    }

    #[test]
    fn process_parallelism_counts_live_threads() {
        let mut table = ThreadTable::new();
        let first = table.spawn(process(1)).unwrap();
        let second = table.spawn(process(1)).unwrap();
        table.spawn(process(1)).unwrap();

        assert_eq!(table.process_parallelism(process(1)), 3);
        table.exit(first, 0).unwrap();
        assert_eq!(table.process_parallelism(process(1)), 2);
        table.signal(second, 9).unwrap();
        assert_eq!(table.process_parallelism(process(1)), 2);
    }
}

impl helios_unix::ProcessPermissions for crate::ProcessAuthority {
    type Spawn = crate::SpawnAuthority;
    type Fork = crate::ForkAuthority;
    type Exec = crate::ExecAuthority;
    type Join = crate::JoinAuthority;
    type Signal = crate::SignalAuthority;
    fn contains_authority(&self, child: &Self) -> bool {
        self.contains_authority(child)
    }
}
