mod fs;
pub(crate) use fs::*;
mod rights;
pub(crate) use rights::*;
#[cfg(test)]
mod fs_tests;
pub(in crate::wasmtime_adapter) mod net;
mod stream;
pub(crate) use stream::*;
mod host_env;
pub(crate) use host_env::*;

/// Defines `add_to_linker` and, for tests, `LINKED_INTERFACES` from one
/// table, so the list of interfaces the linker serves is the list the code
/// links and cannot drift from it.
///
/// By default each entry is linked only when `imports.has(name, "0.3")`;
/// `when <cond>` overrides that predicate (for example when `wasi:http/client`
/// also requires `wasi:http/types`).
macro_rules! linked_interfaces {
    (
        $linker:ident, $imports:ident;
        $($name:literal $(when $cond:expr)? => $link:expr;)+
    ) => {
        #[cfg(test)]
        pub(crate) const LINKED_INTERFACES: &[&str] = &[$($name),+];

        pub(crate) fn add_to_linker<CpuImpl, Net, StorageImpl>(
            $linker: &mut wasmtime::component::Linker<StoreData<CpuImpl, Net, StorageImpl>>,
            $imports: &WasiImportSet,
        ) -> Result<()>
        where
            CpuImpl: Cpu + Clone,
            Net: ComponentHostNetwork,
            StorageImpl: crate::Storage,
        {
            $(
                if linked_interfaces!(@cond $imports, $name $(, $cond)?) {
                    $link?;
                }
            )+
            Ok(())
        }
    };
    (@cond $imports:ident, $name:literal) => {
        $imports.has($name, "0.3")
    };
    (@cond $imports:ident, $name:literal, $cond:expr) => {
        $cond
    };
}

pub(crate) mod http;
pub(crate) use http::*;

// The bindgen `with:` mappings re-export these resource types with `pub use`,
// which requires a fully `pub` path; the globs above are only crate-visible.
pub use crate::FsDescriptor;
pub use host_env::{TerminalInput, TerminalOutput};
pub use http::{WasiRequest, WasiResponse};
pub use net::{TcpSocket, UdpSocket};

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::{
    ComponentOutputMode, ComponentOutputRoute, ComponentOutputStreamKind, FsDescriptorFlags,
    ObjectIdentity,
};
use bytes::Bytes;
use futures::channel::oneshot;
use helios_hal::cpu::Cpu;
use helios_netstack::Ipv6Address;
use thiserror::Error;
use triomphe::Arc;
use wasmtime::component::{
    Access, Accessor, Component, Destination, FutureConsumer, FutureProducer, FutureReader,
    HasSelf, Resource, Source, StreamConsumer, StreamProducer, StreamReader, StreamResult,
    WriteBuffer,
};
use wasmtime::{self, Result, StoreContextMut};

use crate::wasmtime_adapter::component_host::{HostRuntimeState, OutputStreamKind, StoreData};

pub(crate) type FsNodeKind = crate::ComponentFsNodeKind;
const FILE_READ_CHUNK_BYTES: usize = 1024 * 1024;
const DEFAULT_WASI_UDP_BUFFER_BYTES: u64 = 64 * 1024;
/// Receive window the netstack actually reserves per TCP socket.
///
/// `wasi:sockets` lets an implementation clamp a buffer-size hint and expects
/// the getter to report the effective value, so this is the ceiling for
/// `set-receive-buffer-size` rather than an arbitrary echo of the request.
const WASI_TCP_RECEIVE_BUFFER_BYTES: u64 = helios_netstack::TCP_RECEIVE_WINDOW_BYTES as u64;
/// Transmit buffer the netstack actually reserves per TCP socket.
const WASI_TCP_SEND_BUFFER_BYTES: u64 = helios_netstack::TCP_TRANSMIT_BUFFER_BYTES as u64;
const DEFAULT_WASI_UDP_HOP_LIMIT: u8 = helios_netstack::DEFAULT_HOP_LIMIT;
const DEFAULT_WASI_TCP_HOP_LIMIT: u8 = helios_netstack::DEFAULT_HOP_LIMIT;
const DEFAULT_WASI_TCP_LISTEN_BACKLOG: u16 = 128;
const DEFAULT_WASI_TCP_KEEP_ALIVE_IDLE_NANOS: u64 = 7_200_000_000_000;
const DEFAULT_WASI_TCP_KEEP_ALIVE_INTERVAL_NANOS: u64 = 75_000_000_000;
const DEFAULT_WASI_TCP_KEEP_ALIVE_COUNT: u32 = 9;
pub(crate) const MAX_WASI_UDP_DATAGRAM_BYTES: usize = u16::MAX as usize;
/// The most guest bytes one host call or one stream poll holds in kernel
/// memory at once when it has to copy them out of linear memory. A transfer
/// larger than this moves in successive chunks, so what is held never grows
/// with the guest's length. A stream consumer takes the chunks one after
/// another within its poll and reports the write complete only when none is
/// left, because a `stream.write` ends at that report. 64 KiB is the largest UDP payload
/// (`u16::MAX` rounded to a power of two) and the WASI UDP default buffer
/// size ([`DEFAULT_WASI_UDP_BUFFER_BYTES`]).
pub(crate) const GUEST_IO_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("guest requested wasi preview3 exit code {code}")]
struct Preview3GuestExit {
    code: u32,
}

impl Preview3GuestExit {
    const fn new(code: u32) -> Self {
        Self { code }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum WasiAdapterTrap {
    #[error("random byte length exceeds usize")]
    RandomLengthOverflow,
    #[error("random byte list of {len} bytes exceeds the {limit}-byte limit")]
    RandomBytesLimitExceeded { len: u64, limit: u64 },
    #[error("the kernel heap cannot serve a random byte list of {len} bytes")]
    RandomBytesUnavailable { len: u64 },
    #[error("file read offset overflowed u64")]
    FileReadOffsetOverflow,
    #[error("file write offset does not fit into usize")]
    FileWriteOffsetOverflow,
}

pub(crate) struct WasiImportSet {
    names: Vec<String>,
}

impl WasiImportSet {
    pub(crate) fn from_component(engine: &wasmtime::Engine, component: &Component) -> Self {
        Self {
            names: component
                .component_type()
                .imports(engine)
                .map(|(name, _)| name.to_owned())
                .collect(),
        }
    }

    pub(crate) fn has(&self, interface: &str, version_prefix: &str) -> bool {
        self.names.iter().any(|name| {
            name.strip_prefix(interface)
                .and_then(|suffix| suffix.strip_prefix('@'))
                .is_some_and(|version| version.starts_with(version_prefix))
        })
    }

    pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(String::as_str)
    }
}

/// Whether the component's standard input is attached to the interactive
/// serial console.
///
/// The serial console is the only terminal Helios attaches a component to;
/// every other stdin route is a byte channel fed by a parent process, which is
/// a pipe rather than a tty. `wasi:cli/terminal-stdin` must only produce a
/// `terminal-input` resource for the console so guests do not misdetect a tty
/// on a captured stream.
///
/// Console-attached components read keystrokes through `helios:system/serial`
/// rather than the wasi stdin stream, which stays empty; the terminal
/// resource describes the attachment, not that stream.
pub(crate) fn stdin_is_terminal(mode: &ComponentOutputMode) -> bool {
    matches!(mode.stdin_route(), crate::ComponentInputRoute::Serial)
}

/// Whether the requested output stream is attached to the interactive serial
/// console.
///
/// `Trace` and `Discard` routes are capture sinks, and `Child` routes are
/// pipes to a parent process; only the serial console is a terminal.
pub(crate) fn output_is_terminal(
    mode: &ComponentOutputMode,
    kind: ComponentOutputStreamKind,
) -> bool {
    match mode {
        ComponentOutputMode::Serial => true,
        ComponentOutputMode::Trace | ComponentOutputMode::Child { .. } => false,
        ComponentOutputMode::RoutedChild { stdout, stderr, .. } => {
            let route = match kind {
                ComponentOutputStreamKind::Stdout => stdout,
                ComponentOutputStreamKind::Stderr => stderr,
            };
            match route {
                ComponentOutputRoute::Serial => true,
                ComponentOutputRoute::Trace
                | ComponentOutputRoute::Child(_)
                | ComponentOutputRoute::Discard => false,
            }
        }
    }
}

pub(crate) mod preview1;
pub(crate) mod preview3;

pub(crate) mod bindings;
pub(crate) mod http_bindings;

use bindings as wasi;
use wasi::cli::types as cli_types;
use wasi::filesystem::types as fs_types;
use wasi::sockets::ip_name_lookup;
use wasi::sockets::types as socket_types;

type TcpReadResult = core::result::Result<Option<Bytes>, socket_types::ErrorCode>;

type TcpWriteResult = core::result::Result<(), socket_types::ErrorCode>;

#[repr(transparent)]
pub struct TrappableError<T> {
    err: wasmtime::Error,
    _marker: PhantomData<T>,
}

pub type FsError = TrappableError<fs_types::ErrorCode>;

impl<T> TrappableError<T> {
    fn trap(err: impl Into<wasmtime::Error>) -> Self {
        Self {
            err: err.into(),
            _marker: PhantomData,
        }
    }

    fn downcast(self) -> Result<T>
    where
        T: core::error::Error + Send + Sync + 'static,
    {
        self.err.downcast()
    }
}

impl<T> From<T> for TrappableError<T>
where
    T: core::error::Error + Send + Sync + 'static,
{
    fn from(error: T) -> Self {
        Self::trap(error)
    }
}

impl<T> core::fmt::Debug for TrappableError<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.err.fmt(f)
    }
}

impl<T> core::fmt::Display for TrappableError<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.err.fmt(f)
    }
}

impl<T> core::error::Error for TrappableError<T> {}

#[cfg(test)]
mod tests {
    use crate::test_support::{TestNetworkService, TestSocketRetirement};

    use alloc::collections::BTreeSet;
    use alloc::string::String;
    use alloc::vec;

    use crate::{AuthorityDomain, ObjectIdentity};
    use bytes::Bytes;
    use futures_lite::future::block_on;

    use super::net::{
        OwnedTcpListener, TcpConnection, TcpSocket, UdpSend, UdpSendBinding, UdpSocket,
        WasiTcpIpAddress, WasiTcpSocketAddress, WasiTcpSocketFamily, WasiUdpSocketAddress,
        WasiUdpSocketError, WasiUdpSocketFamily, format_p3_tcp_socket_address,
        format_p3_udp_socket_address, has_wasi_network_rights, map_p3_dns_error, map_p3_tcp_error,
        map_p3_udp_family, map_p3_udp_socket_error, parse_p3_tcp_socket_address,
        parse_p3_udp_socket_address, read_socket, send_on, wasi_tcp_bind_rights,
        wasi_udp_bind_rights, write_socket,
    };
    use super::{
        DEFAULT_WASI_TCP_HOP_LIMIT, DEFAULT_WASI_TCP_KEEP_ALIVE_COUNT,
        DEFAULT_WASI_TCP_KEEP_ALIVE_IDLE_NANOS, DEFAULT_WASI_TCP_KEEP_ALIVE_INTERVAL_NANOS,
        DEFAULT_WASI_TCP_LISTEN_BACKLOG, http, ip_name_lookup, preview3, socket_types,
        stdin_is_terminal,
    };
    use triomphe::Arc;

    /// A connection on stream `raw`, owned the way a socket owns one.
    fn connection(retire: crate::SocketRetirementSender, raw: u64) -> Arc<TcpConnection> {
        Arc::new(TcpConnection::new(retire, raw))
    }

    const fn tcp4(octets: [u8; 4], port: u16) -> WasiTcpSocketAddress {
        WasiTcpSocketAddress {
            address: WasiTcpIpAddress::Ipv4(crate::Ipv4Address::new(octets)),
            port,
        }
    }

    const fn udp4(octets: [u8; 4], port: u16) -> WasiUdpSocketAddress {
        WasiUdpSocketAddress {
            address: crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new(octets)),
            port,
        }
    }

    #[test]
    fn a_random_length_the_address_space_cannot_hold_traps_without_filling() {
        // Both exceed `isize::MAX`, the most a single allocation can span, so
        // even when an operator lifts the limit to `u64::MAX`, the reservation
        // refuses them on every host without allocating.
        for len in [u64::MAX, isize::MAX as u64 + 1] {
            let mut filled = false;
            let error = super::random_bytes(len, u64::MAX, |_| filled = true)
                .expect_err("a list larger than the address space cannot be built");
            assert_eq!(
                error.downcast_ref::<super::WasiAdapterTrap>(),
                Some(&super::WasiAdapterTrap::RandomBytesUnavailable { len })
            );
            assert!(!filled, "fill ran for an unservable length {len}");
        }
    }

    #[test]
    fn a_random_length_above_the_setting_traps_without_filling() {
        use crate::settings::Setting;

        let limit = crate::RandomBytesLimitSetting::DEFAULT;
        let len = limit + 1;
        let mut filled = false;
        let error = super::random_bytes(len, limit, |_| filled = true)
            .expect_err("a list one byte above the limit must trap");
        assert_eq!(
            error.downcast_ref::<super::WasiAdapterTrap>(),
            Some(&super::WasiAdapterTrap::RandomBytesLimitExceeded { len, limit })
        );
        assert!(!filled, "fill ran for a length above the limit");
    }

    #[test]
    fn a_small_random_length_is_filled_once_to_exactly_that_length() {
        let mut calls = 0_u32;
        let bytes = super::random_bytes(37, 37, |buffer| {
            calls += 1;
            buffer.fill(0xa5);
        })
        .expect("a list at the limit is served");
        assert_eq!(bytes, vec![0xa5_u8; 37]);
        assert_eq!(calls, 1);
    }

    #[test]
    fn preview3_linked_interfaces_exist_in_checked_in_wit() {
        let wit_interfaces = wit_interface_names(preview3::WIT_PACKAGES);
        for interface in preview3::LINKED_INTERFACES {
            assert!(
                wit_interfaces.contains(interface),
                "Preview3 adapter maps {interface}, but checked-in WIT does not declare it"
            );
        }
    }

    #[test]
    fn preview3_linked_interfaces_cover_required_subsystems() {
        assert_interface_set_eq(
            preview3::LINKED_INTERFACES,
            &[
                "wasi:clocks/monotonic-clock",
                "wasi:clocks/system-clock",
                "wasi:clocks/timezone",
                "wasi:cli/environment",
                "wasi:cli/exit",
                "wasi:cli/stdin",
                "wasi:cli/stdout",
                "wasi:cli/stderr",
                "wasi:cli/terminal-input",
                "wasi:cli/terminal-output",
                "wasi:cli/terminal-stdin",
                "wasi:cli/terminal-stdout",
                "wasi:cli/terminal-stderr",
                "wasi:random/random",
                "wasi:random/insecure",
                "wasi:random/insecure-seed",
                "wasi:filesystem/types",
                "wasi:filesystem/preopens",
                "wasi:sockets/types",
                "wasi:sockets/ip-name-lookup",
            ],
            "Preview3",
        );
    }

    #[test]
    fn http_linked_interfaces_exist_in_checked_in_wit() {
        let wit_interfaces = wit_interface_names(preview3::WIT_PACKAGES);
        for interface in http::LINKED_INTERFACES {
            assert!(
                wit_interfaces.contains(interface),
                "http adapter maps {interface}, but checked-in WIT does not declare it"
            );
        }
    }

    #[test]
    fn http_linked_interfaces_cover_the_client_surface() {
        // `handler` is deliberately absent: the kernel calls it as an export
        // on the plugin store, it never serves it as an import.
        assert_interface_set_eq(
            http::LINKED_INTERFACES,
            &["wasi:http/types", "wasi:http/client"],
            "http",
        );
    }

    #[test]
    fn http_linked_functions_cover_the_whole_types_interface() {
        assert_function_set_eq(
            &wit_function_names(preview3::WIT_PACKAGES, http::LINKED_INTERFACES),
            &HTTP_EXPECTED_FUNCTIONS,
            "http",
        );
    }

    #[test]
    fn only_serial_console_stdio_is_reported_as_a_terminal() {
        use super::{ComponentOutputMode, ComponentOutputRoute, output_is_terminal};
        use crate::ComponentOutputStreamKind::{Stderr, Stdout};

        assert!(stdin_is_terminal(&ComponentOutputMode::Serial));
        assert!(output_is_terminal(&ComponentOutputMode::Serial, Stdout));
        assert!(output_is_terminal(&ComponentOutputMode::Serial, Stderr));

        assert!(!stdin_is_terminal(&ComponentOutputMode::Trace));
        assert!(!output_is_terminal(&ComponentOutputMode::Trace, Stdout));
        assert!(!output_is_terminal(&ComponentOutputMode::Trace, Stderr));

        let (stdout_tx, _stdout_rx) = crate::byte_channel();
        let (stderr_tx, _stderr_rx) = crate::byte_channel();
        let (_stdin_tx, stdin_rx) = crate::byte_channel();
        let captured = ComponentOutputMode::Child {
            stdin_rx: stdin_rx.clone(),
            stdout_tx,
            stderr_tx,
        };
        assert!(!stdin_is_terminal(&captured));
        assert!(!output_is_terminal(&captured, Stdout));
        assert!(!output_is_terminal(&captured, Stderr));

        let (routed_stdout_tx, _routed_stdout_rx) = crate::byte_channel();
        let routed = ComponentOutputMode::RoutedChild {
            stdin: crate::ComponentInputRoute::Child(stdin_rx),
            stdout: ComponentOutputRoute::Child(routed_stdout_tx),
            stderr: ComponentOutputRoute::Serial,
        };
        assert!(!stdin_is_terminal(&routed));
        assert!(!output_is_terminal(&routed, Stdout));
        assert!(output_is_terminal(&routed, Stderr));

        let serial_stdin = ComponentOutputMode::RoutedChild {
            stdin: crate::ComponentInputRoute::Serial,
            stdout: ComponentOutputRoute::Discard,
            stderr: ComponentOutputRoute::Discard,
        };
        assert!(stdin_is_terminal(&serial_stdin));

        let closed_stdin = ComponentOutputMode::RoutedChild {
            stdin: crate::ComponentInputRoute::Closed,
            stdout: ComponentOutputRoute::Discard,
            stderr: ComponentOutputRoute::Discard,
        };
        assert!(!stdin_is_terminal(&closed_stdin));
    }

    #[test]
    fn preview3_linked_functions_cover_required_subsystems() {
        assert_function_set_eq(
            &wit_function_names(preview3::WIT_PACKAGES, preview3::LINKED_INTERFACES),
            &[
                "wasi:cli/environment.get-arguments",
                "wasi:cli/environment.get-environment",
                "wasi:cli/environment.get-initial-cwd",
                "wasi:cli/exit.exit",
                "wasi:cli/exit.exit-with-code",
                "wasi:cli/stderr.write-via-stream",
                "wasi:cli/stdin.read-via-stream",
                "wasi:cli/stdout.write-via-stream",
                "wasi:cli/terminal-stderr.get-terminal-stderr",
                "wasi:cli/terminal-stdin.get-terminal-stdin",
                "wasi:cli/terminal-stdout.get-terminal-stdout",
                "wasi:clocks/monotonic-clock.get-resolution",
                "wasi:clocks/monotonic-clock.now",
                "wasi:clocks/monotonic-clock.wait-for",
                "wasi:clocks/monotonic-clock.wait-until",
                "wasi:clocks/system-clock.get-resolution",
                "wasi:clocks/system-clock.now",
                "wasi:clocks/timezone.iana-id",
                "wasi:clocks/timezone.to-debug-string",
                "wasi:clocks/timezone.utc-offset",
                "wasi:filesystem/preopens.get-directories",
                "wasi:filesystem/types.descriptor.advise",
                "wasi:filesystem/types.descriptor.append-via-stream",
                "wasi:filesystem/types.descriptor.create-directory-at",
                "wasi:filesystem/types.descriptor.get-flags",
                "wasi:filesystem/types.descriptor.get-type",
                "wasi:filesystem/types.descriptor.is-same-object",
                "wasi:filesystem/types.descriptor.link-at",
                "wasi:filesystem/types.descriptor.metadata-hash",
                "wasi:filesystem/types.descriptor.metadata-hash-at",
                "wasi:filesystem/types.descriptor.open-at",
                "wasi:filesystem/types.descriptor.read-directory",
                "wasi:filesystem/types.descriptor.read-via-stream",
                "wasi:filesystem/types.descriptor.readlink-at",
                "wasi:filesystem/types.descriptor.remove-directory-at",
                "wasi:filesystem/types.descriptor.rename-at",
                "wasi:filesystem/types.descriptor.set-size",
                "wasi:filesystem/types.descriptor.set-times",
                "wasi:filesystem/types.descriptor.set-times-at",
                "wasi:filesystem/types.descriptor.stat",
                "wasi:filesystem/types.descriptor.stat-at",
                "wasi:filesystem/types.descriptor.symlink-at",
                "wasi:filesystem/types.descriptor.sync",
                "wasi:filesystem/types.descriptor.sync-data",
                "wasi:filesystem/types.descriptor.unlink-file-at",
                "wasi:filesystem/types.descriptor.write-via-stream",
                "wasi:random/insecure-seed.get-insecure-seed",
                "wasi:random/insecure.get-insecure-random-bytes",
                "wasi:random/insecure.get-insecure-random-u64",
                "wasi:random/random.get-random-bytes",
                "wasi:random/random.get-random-u64",
                "wasi:sockets/ip-name-lookup.resolve-addresses",
                "wasi:sockets/types.tcp-socket.bind",
                "wasi:sockets/types.tcp-socket.connect",
                "wasi:sockets/types.tcp-socket.create",
                "wasi:sockets/types.tcp-socket.get-address-family",
                "wasi:sockets/types.tcp-socket.get-hop-limit",
                "wasi:sockets/types.tcp-socket.get-is-listening",
                "wasi:sockets/types.tcp-socket.get-keep-alive-count",
                "wasi:sockets/types.tcp-socket.get-keep-alive-enabled",
                "wasi:sockets/types.tcp-socket.get-keep-alive-idle-time",
                "wasi:sockets/types.tcp-socket.get-keep-alive-interval",
                "wasi:sockets/types.tcp-socket.get-local-address",
                "wasi:sockets/types.tcp-socket.get-receive-buffer-size",
                "wasi:sockets/types.tcp-socket.get-remote-address",
                "wasi:sockets/types.tcp-socket.get-send-buffer-size",
                "wasi:sockets/types.tcp-socket.listen",
                "wasi:sockets/types.tcp-socket.receive",
                "wasi:sockets/types.tcp-socket.send",
                "wasi:sockets/types.tcp-socket.set-hop-limit",
                "wasi:sockets/types.tcp-socket.set-keep-alive-count",
                "wasi:sockets/types.tcp-socket.set-keep-alive-enabled",
                "wasi:sockets/types.tcp-socket.set-keep-alive-idle-time",
                "wasi:sockets/types.tcp-socket.set-keep-alive-interval",
                "wasi:sockets/types.tcp-socket.set-listen-backlog-size",
                "wasi:sockets/types.tcp-socket.set-receive-buffer-size",
                "wasi:sockets/types.tcp-socket.set-send-buffer-size",
                "wasi:sockets/types.udp-socket.bind",
                "wasi:sockets/types.udp-socket.connect",
                "wasi:sockets/types.udp-socket.create",
                "wasi:sockets/types.udp-socket.disconnect",
                "wasi:sockets/types.udp-socket.get-address-family",
                "wasi:sockets/types.udp-socket.get-local-address",
                "wasi:sockets/types.udp-socket.get-receive-buffer-size",
                "wasi:sockets/types.udp-socket.get-remote-address",
                "wasi:sockets/types.udp-socket.get-send-buffer-size",
                "wasi:sockets/types.udp-socket.get-unicast-hop-limit",
                "wasi:sockets/types.udp-socket.receive",
                "wasi:sockets/types.udp-socket.send",
                "wasi:sockets/types.udp-socket.set-receive-buffer-size",
                "wasi:sockets/types.udp-socket.set-send-buffer-size",
                "wasi:sockets/types.udp-socket.set-unicast-hop-limit",
            ],
            "Preview3",
        );
    }

    /// Every function the kernel must implement to serve `wasi:http` to a
    /// guest. Derived from the checked-in WIT, so adding a method upstream
    /// fails this test rather than silently going unimplemented.
    const HTTP_EXPECTED_FUNCTIONS: [&str; 34] = [
        "wasi:http/client.send",
        "wasi:http/types.fields.append",
        "wasi:http/types.fields.clone",
        "wasi:http/types.fields.copy-all",
        "wasi:http/types.fields.delete",
        "wasi:http/types.fields.from-list",
        "wasi:http/types.fields.get",
        "wasi:http/types.fields.get-and-delete",
        "wasi:http/types.fields.has",
        "wasi:http/types.fields.set",
        "wasi:http/types.request.consume-body",
        "wasi:http/types.request.get-authority",
        "wasi:http/types.request.get-headers",
        "wasi:http/types.request.get-method",
        "wasi:http/types.request.get-options",
        "wasi:http/types.request.get-path-with-query",
        "wasi:http/types.request.get-scheme",
        "wasi:http/types.request.new",
        "wasi:http/types.request.set-authority",
        "wasi:http/types.request.set-method",
        "wasi:http/types.request.set-path-with-query",
        "wasi:http/types.request.set-scheme",
        "wasi:http/types.request-options.clone",
        "wasi:http/types.request-options.get-between-bytes-timeout",
        "wasi:http/types.request-options.get-connect-timeout",
        "wasi:http/types.request-options.get-first-byte-timeout",
        "wasi:http/types.request-options.set-between-bytes-timeout",
        "wasi:http/types.request-options.set-connect-timeout",
        "wasi:http/types.request-options.set-first-byte-timeout",
        "wasi:http/types.response.consume-body",
        "wasi:http/types.response.get-headers",
        "wasi:http/types.response.get-status-code",
        "wasi:http/types.response.new",
        "wasi:http/types.response.set-status-code",
    ];

    fn assert_interface_set_eq(actual: &[&'static str], expected: &[&'static str], label: &str) {
        let actual = actual.iter().copied().collect::<BTreeSet<_>>();
        let expected = expected.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "{label} linked interface coverage changed"
        );
    }

    fn assert_function_set_eq(actual: &BTreeSet<String>, expected: &[&'static str], label: &str) {
        let expected = expected
            .iter()
            .map(|function| String::from(*function))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual, &expected,
            "{label} linked function coverage changed"
        );
    }

    fn wit_interface_names(packages: &[(&'static str, &'static str)]) -> BTreeSet<&'static str> {
        packages
            .iter()
            .flat_map(|(package, wit)| {
                wit.lines().filter_map(move |line| {
                    let trimmed = line.trim_start();
                    let rest = trimmed.strip_prefix("interface ")?;
                    let name = rest
                        .split(|byte: char| byte.is_whitespace() || byte == '{')
                        .next()?;
                    wit_interface_name(package, name)
                })
            })
            .collect()
    }

    fn wit_function_names(
        packages: &[(&'static str, &'static str)],
        linked_interfaces: &[&'static str],
    ) -> BTreeSet<String> {
        let linked_interfaces = linked_interfaces.iter().copied().collect::<BTreeSet<_>>();
        let mut functions = BTreeSet::new();
        for (package, wit) in packages {
            let mut interface = None;
            let mut interface_depth = 0_i32;
            let mut resource = None;
            let mut resource_depth = 0_i32;

            for line in wit.lines() {
                let trimmed = line.trim_start();
                if interface.is_none() {
                    if let Some(rest) = trimmed.strip_prefix("interface ") {
                        let Some(name) = rest
                            .split(|byte: char| byte.is_whitespace() || byte == '{')
                            .next()
                        else {
                            continue;
                        };
                        let Some(mapped) = wit_interface_name(package, name) else {
                            continue;
                        };
                        if !linked_interfaces.contains(mapped) {
                            continue;
                        }
                        interface = Some(mapped);
                        interface_depth = wit_brace_delta(line);
                    }
                    continue;
                }

                if resource_depth > 0 {
                    if let Some(method) = wit_func_name(trimmed) {
                        let interface = interface.expect("resource methods require an interface");
                        let resource = resource.expect("resource method requires resource context");
                        functions.insert(wit_scoped_resource_function(interface, resource, method));
                    }
                    resource_depth += wit_brace_delta(line);
                    if resource_depth <= 0 {
                        resource = None;
                        resource_depth = 0;
                    }
                } else if let Some(rest) = trimmed.strip_prefix("resource ") {
                    let Some(name) = rest
                        .split(|byte: char| byte.is_whitespace() || byte == '{' || byte == ';')
                        .next()
                    else {
                        continue;
                    };
                    resource = Some(name);
                    resource_depth = wit_brace_delta(line);
                    if resource_depth <= 0 {
                        resource = None;
                        resource_depth = 0;
                    }
                } else if let Some(function) = wit_func_name(trimmed) {
                    let interface = interface.expect("functions require an interface");
                    functions.insert(wit_scoped_function(interface, function));
                }

                interface_depth += wit_brace_delta(line);
                if interface_depth <= 0 {
                    interface = None;
                    interface_depth = 0;
                    resource = None;
                    resource_depth = 0;
                }
            }
        }
        functions
    }

    fn wit_interface_name(package: &str, name: &str) -> Option<&'static str> {
        Some(match package {
            "wasi:cli" => match name {
                "environment" => "wasi:cli/environment",
                "exit" => "wasi:cli/exit",
                "run" => "wasi:cli/run",
                "types" => "wasi:cli/types",
                "stdin" => "wasi:cli/stdin",
                "stdout" => "wasi:cli/stdout",
                "stderr" => "wasi:cli/stderr",
                "terminal-input" => "wasi:cli/terminal-input",
                "terminal-output" => "wasi:cli/terminal-output",
                "terminal-stdin" => "wasi:cli/terminal-stdin",
                "terminal-stdout" => "wasi:cli/terminal-stdout",
                "terminal-stderr" => "wasi:cli/terminal-stderr",
                _ => return None,
            },
            "wasi:clocks" => match name {
                "types" => "wasi:clocks/types",
                "monotonic-clock" => "wasi:clocks/monotonic-clock",
                "system-clock" => "wasi:clocks/system-clock",
                "wall-clock" => "wasi:clocks/wall-clock",
                "timezone" => "wasi:clocks/timezone",
                _ => return None,
            },
            "wasi:filesystem" => match name {
                "types" => "wasi:filesystem/types",
                "preopens" => "wasi:filesystem/preopens",
                _ => return None,
            },
            "wasi:http" => match name {
                "types" => "wasi:http/types",
                "client" => "wasi:http/client",
                "handler" => "wasi:http/handler",
                _ => return None,
            },
            "wasi:random" => match name {
                "random" => "wasi:random/random",
                "insecure" => "wasi:random/insecure",
                "insecure-seed" => "wasi:random/insecure-seed",
                _ => return None,
            },
            "wasi:sockets" => match name {
                "types" => "wasi:sockets/types",
                "network" => "wasi:sockets/network",
                "instance-network" => "wasi:sockets/instance-network",
                "udp" => "wasi:sockets/udp",
                "udp-create-socket" => "wasi:sockets/udp-create-socket",
                "tcp" => "wasi:sockets/tcp",
                "tcp-create-socket" => "wasi:sockets/tcp-create-socket",
                "ip-name-lookup" => "wasi:sockets/ip-name-lookup",
                _ => return None,
            },
            _ => return None,
        })
    }

    fn wit_func_name(line: &str) -> Option<&str> {
        if !line.contains("func(") && !line.contains("func()") {
            return None;
        }
        let (name, signature) = line.split_once(':')?;
        if !signature.contains("func") {
            return None;
        }
        name.strip_prefix('%').or(Some(name))
    }

    fn wit_scoped_function(interface: &str, function: &str) -> String {
        let mut scoped = String::from(interface);
        scoped.push('.');
        scoped.push_str(function);
        scoped
    }

    fn wit_scoped_resource_function(interface: &str, resource: &str, function: &str) -> String {
        let mut scoped = String::from(interface);
        scoped.push('.');
        scoped.push_str(resource);
        scoped.push('.');
        scoped.push_str(function);
        scoped
    }

    fn wit_brace_delta(line: &str) -> i32 {
        if line.trim_start().starts_with("///") {
            return 0;
        }
        let opens = line.bytes().filter(|byte| *byte == b'{').count() as i32;
        let closes = line.bytes().filter(|byte| *byte == b'}').count() as i32;
        opens - closes
    }

    /// `st_dev`/`st_ino` are derived from object identity, so neither half may
    /// be zero for a host-share file: programs de-duplicate by that pair.
    #[test]
    fn host_file_identity_yields_nonzero_device_and_inode() {
        let identity = ObjectIdentity::new(AuthorityDomain::HOST_SHARE_9P, 4242);

        assert_ne!(identity.domain().raw(), 0);
        assert_ne!(identity.local(), 0);
        assert_eq!(identity.local(), 4242);
        assert_ne!(
            identity.domain().raw(),
            AuthorityDomain::GUEST_BOOTFS.raw(),
            "the host share must not share a device id with bootfs"
        );
    }

    #[test]
    fn wasi_udp_bind_rights_require_privileged_bind_for_low_ports() {
        assert_eq!(wasi_udp_bind_rights(0), crate::NetworkAuthorityRights::UDP);
        assert_eq!(
            wasi_udp_bind_rights(1024),
            crate::NetworkAuthorityRights::UDP
        );
        assert_eq!(
            wasi_udp_bind_rights(53),
            crate::NetworkAuthorityRights::UDP | crate::NetworkAuthorityRights::PRIVILEGED_BIND
        );
    }

    #[test]
    fn wasi_tcp_bind_rights_require_privileged_bind_for_low_ports() {
        assert_eq!(wasi_tcp_bind_rights(0), crate::NetworkAuthorityRights::TCP);
        assert_eq!(
            wasi_tcp_bind_rights(1024),
            crate::NetworkAuthorityRights::TCP
        );
        assert_eq!(
            wasi_tcp_bind_rights(443),
            crate::NetworkAuthorityRights::TCP | crate::NetworkAuthorityRights::PRIVILEGED_BIND
        );
    }

    #[test]
    fn wasi_network_right_check_never_widens_authority() {
        let mut authority = crate::ProcessAuthority::empty();
        authority.grant_network_rights(crate::NetworkAuthorityRights::UDP);

        assert!(has_wasi_network_rights(
            &authority,
            crate::NetworkAuthorityRights::UDP
        ));
        assert!(!has_wasi_network_rights(
            &authority,
            crate::NetworkAuthorityRights::UDP | crate::NetworkAuthorityRights::PRIVILEGED_BIND
        ));
    }

    #[test]
    fn p3_network_error_mapping_does_not_allocate_detail_strings() {
        assert!(matches!(
            map_p3_tcp_error(crate::TcpError {
                kind: crate::TcpErrorKind::Internal,
                detail: crate::NetworkErrorDetail::InternalInvariant,
            }),
            socket_types::ErrorCode::Other(None)
        ));
        assert!(matches!(
            map_p3_udp_socket_error(WasiUdpSocketError::Backend(crate::UdpError {
                kind: crate::UdpErrorKind::Internal,
                detail: crate::NetworkErrorDetail::InternalInvariant,
            })),
            socket_types::ErrorCode::Other(None)
        ));
        assert!(matches!(
            map_p3_dns_error(crate::DnsError {
                kind: crate::DnsErrorKind::Internal,
                detail: crate::NetworkErrorDetail::InternalInvariant,
            }),
            ip_name_lookup::ErrorCode::Other(None)
        ));
    }

    #[test]
    fn p3_tcp_ipv6_addresses_roundtrip_while_family_mismatches_fail() {
        assert_eq!(
            map_p3_udp_family(socket_types::IpAddressFamily::Ipv6)
                .expect("IPv6 UDP family must be supported"),
            WasiUdpSocketFamily::Ipv6
        );
        let ipv6_socket_address =
            socket_types::IpSocketAddress::Ipv6(socket_types::Ipv6SocketAddress {
                port: 80,
                flow_info: 0,
                address: (0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                scope_id: 0,
            });
        assert!(matches!(
            parse_p3_tcp_socket_address(ipv6_socket_address, WasiTcpSocketFamily::Ipv4,),
            Err(socket_types::ErrorCode::NotSupported)
        ));
        let parsed = parse_p3_tcp_socket_address(ipv6_socket_address, WasiTcpSocketFamily::Ipv6)
            .expect("IPv6 TCP socket address must parse for IPv6 sockets");
        match format_p3_tcp_socket_address(parsed) {
            socket_types::IpSocketAddress::Ipv6(address) => {
                assert_eq!(address.port, 80);
                assert_eq!(address.address, (0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
            }
            socket_types::IpSocketAddress::Ipv4(_) => panic!("IPv6 TCP address formatted as IPv4"),
        }
        assert!(matches!(
            parse_p3_tcp_socket_address(
                socket_types::IpSocketAddress::Ipv4(socket_types::Ipv4SocketAddress {
                    port: 80,
                    address: (127, 0, 0, 1),
                }),
                WasiTcpSocketFamily::Ipv6,
            ),
            Err(socket_types::ErrorCode::NotSupported)
        ));
        let udp = parse_p3_udp_socket_address(ipv6_socket_address, WasiUdpSocketFamily::Ipv6)
            .expect("IPv6 UDP socket address must parse for IPv6 sockets");
        match format_p3_udp_socket_address(udp) {
            socket_types::IpSocketAddress::Ipv6(address) => {
                assert_eq!(address.port, 80);
                assert_eq!(address.address, (0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
            }
            socket_types::IpSocketAddress::Ipv4(_) => panic!("IPv6 UDP address formatted as IPv4"),
        }
        assert!(matches!(
            parse_p3_udp_socket_address(
                socket_types::IpSocketAddress::Ipv6(socket_types::Ipv6SocketAddress {
                    port: 53,
                    flow_info: 0,
                    address: (0, 0, 0, 0, 0, 0, 0, 1),
                    scope_id: 0,
                }),
                WasiUdpSocketFamily::Ipv4,
            ),
            Err(WasiUdpSocketError::NotSupported)
        ));
    }

    #[test]
    fn p3_ip_address_formatting_preserves_the_address_family() {
        use crate::wasmtime_adapter::wasi::net::format_p3_ip_address;

        assert!(matches!(
            format_p3_ip_address(crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([
                192, 0, 2, 1
            ]))),
            socket_types::IpAddress::Ipv4((192, 0, 2, 1))
        ));
        // Each 16-bit group is big-endian, per `wasi:sockets` ipv6-address.
        assert!(matches!(
            format_p3_ip_address(crate::NetworkIpAddress::Ipv6(
                helios_netstack::Ipv6Address::new([
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ])
            )),
            socket_types::IpAddress::Ipv6((0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        ));
    }

    #[test]
    fn udp_socket_send_uses_typed_address_path() {
        let service = TestNetworkService::new();
        let retirement = TestSocketRetirement::new(service.clone());
        let mut socket = UdpSocket::new(retirement.sender(), WasiUdpSocketFamily::Ipv4);

        let UdpSend { target, binding } = socket
            .start_send(5, Some(udp4([192, 0, 2, 4], 53)))
            .expect("an unbound socket admits a send to a valid target");
        let UdpSendBinding::Unbound(bind) = binding else {
            panic!("an unbound socket binds implicitly on its first send");
        };
        let (guard, outcome) = block_on(bind.run(&service));
        let binding = socket
            .finish_implicit_bind(guard, outcome)
            .expect("the test service binds");
        block_on(send_on(&service, &binding, target, b"hello", 0))
            .expect("UDP send should use typed backend address");
    }

    /// A `wasi:sockets` socket's kernel stream dies with the socket.
    ///
    /// A component's resource destructors run when the *guest* drops a
    /// handle and never when the store around it is torn down, so a
    /// close that only the destructor performed was lost by every
    /// program that exited with its socket still open. In #184 that
    /// left connections in their shards — eleven of them on one shard,
    /// each still advertising a receive window — after the programs
    /// that opened them had gone. Ownership lives on the connection
    /// instead, so whatever ends the resource's life ends the stream's.
    ///
    /// The socket resource holds no service (#219), so its drop queues
    /// the stream and the store closes it on its next turn. Both halves
    /// are asserted here: nothing is queued while the socket lives, the
    /// drop queues, and the drain closes.
    #[test]
    fn a_wasi_tcp_socket_retires_its_stream_when_its_resource_is_dropped() {
        let (service, closed) = crate::test_support::recording_network_service();
        let retirement = TestSocketRetirement::new(service.clone());
        let mut socket = TcpSocket::new(retirement.sender(), WasiTcpSocketFamily::Ipv4);
        block_on(socket.connect(&service, tcp4([127, 0, 0, 1], 80)))
            .expect("the test service always connects");

        assert!(
            !retirement.queued(),
            "a live socket must not have retired its stream"
        );
        drop(socket);
        assert!(
            retirement.queued(),
            "dropping the socket must queue the stream it owns"
        );
        assert_eq!(
            closed.count(),
            0,
            "nothing is closed until the store takes its turn"
        );
        assert_eq!(retirement.drain(), 1, "the drain retires the queued stream");
        assert_eq!(closed.count(), 1);
        assert_eq!(closed.last(), 7, "the retired stream is the one connected");
    }

    /// A socket that owns nothing queues nothing, so a store whose
    /// guest only ever created sockets never pays a close.
    #[test]
    fn a_wasi_tcp_socket_that_owns_nothing_queues_nothing() {
        let (service, closed) = crate::test_support::recording_network_service();
        let retirement = TestSocketRetirement::new(service.clone());
        let socket = TcpSocket::new(retirement.sender(), WasiTcpSocketFamily::Ipv4);

        drop(socket);
        assert!(
            !retirement.queued(),
            "a socket with no stream and no listener has nothing to retire"
        );
        assert_eq!(retirement.drain(), 0);
        assert_eq!(closed.count(), 0);
    }

    /// A connection handed to a stream outlives the socket resource,
    /// and the stream is retired only once the last holder is gone.
    /// Retiring on the socket's drop would close a connection the read
    /// side is still using, and the slab slot it frees is handed
    /// straight to the next connection.
    #[test]
    fn a_wasi_tcp_socket_retires_its_stream_only_once_every_holder_is_gone() {
        let (service, closed) = crate::test_support::recording_network_service();
        let retirement = TestSocketRetirement::new(service.clone());
        let mut socket = TcpSocket::new(retirement.sender(), WasiTcpSocketFamily::Ipv4);
        block_on(socket.connect(&service, tcp4([127, 0, 0, 1], 80)))
            .expect("the test service always connects");
        let borrowed = socket
            .connection()
            .expect("a connected socket has a connection");

        drop(socket);
        assert_eq!(
            retirement.drain(),
            0,
            "a stream another holder still uses must stay open"
        );
        drop(borrowed);
        assert_eq!(retirement.drain(), 1, "the last holder retires the stream");
        assert_eq!(closed.count(), 1);
    }

    /// The retirement reaches the wire: the last holder of a
    /// `wasi:sockets` socket puts its FIN on it.
    ///
    /// #184 moved the stream's ownership onto the socket, and the tests
    /// above prove the drop retires it. What retirement meant
    /// inside the stack was dropping the socket, clearing its timers
    /// and freeing its slot with nothing sent, so a component that
    /// exited holding a connection was invisible to its peer, which
    /// kept an established connection until its own timeout (#224).
    #[test]
    fn a_wasi_tcp_socket_puts_its_fin_on_the_wire_when_its_resource_is_dropped() {
        use crate::network::EstablishedTcpFixture;
        use helios_netstack::TcpFlags;

        let fixture = EstablishedTcpFixture::new();
        let retirement = crate::SocketRetirementQueue::new();
        let mut socket = TcpSocket::new(retirement.sender(), WasiTcpSocketFamily::Ipv4);
        socket.connection = Some(connection(
            retirement.sender(),
            crate::NetworkHandle::into_raw(fixture.stream()),
        ));

        assert!(
            fixture.drive().is_empty(),
            "a live socket owes its peer nothing"
        );

        drop(socket);
        assert_eq!(
            crate::retire_queued_handles(&retirement, &fixture.service()),
            1,
            "the store's drain retires the connection the socket queued"
        );
        let segments = fixture.drive();
        let fin = segments
            .iter()
            .find(|segment| segment.flags.contains(TcpFlags::FIN))
            .expect("the resource takes its connection down with a FIN");
        assert_eq!(
            fin.sequence,
            EstablishedTcpFixture::LOCAL_SEQUENCE.wrapping_add(1),
            "the FIN carries this side's send sequence"
        );
        assert!(
            !fin.flags.contains(TcpFlags::RST),
            "a connection with nothing unread is closed, not aborted"
        );
    }

    /// A `wasi:sockets` socket's kernel listener dies with the socket.
    ///
    /// Nothing retired it before: the resource destructor deleted the
    /// table entry, the socket state's `Drop` retired only the stream
    /// beside it, and the network service offered no
    /// `tcp_listener_close` at all — so every listener a component
    /// opened stayed installed on every shard with its local port bound
    /// for the rest of the boot (#191).
    #[test]
    fn a_wasi_tcp_socket_retires_its_listener_when_its_resource_is_dropped() {
        let (service, closed) = crate::test_support::recording_listener_network_service();
        let retirement = TestSocketRetirement::new(service);
        let mut socket = TcpSocket::new(retirement.sender(), WasiTcpSocketFamily::Ipv4);
        socket.listener = Some(Arc::new(OwnedTcpListener::new(
            retirement.sender(),
            crate::TcpListener {
                listener: 41,
                local_port: 8080,
            },
        )));

        assert!(
            !retirement.queued(),
            "a live socket must not have retired its listener"
        );
        drop(socket);
        assert_eq!(
            retirement.drain(),
            1,
            "dropping the socket must retire the listener it owns"
        );
        assert_eq!(closed.count(), 1);
        assert_eq!(closed.last(), 41);
    }

    /// A listener that was opened but never adopted is retired too.
    ///
    /// `tcp_listen` completes on a detached task and answers through a
    /// oneshot the socket keeps; the socket takes the answer in on its
    /// next accessor. A socket dropped before that holds a listener in
    /// the shards with nothing pointing at it, which is the same leak by
    /// a narrower door: the answer still in the channel is retired with
    /// the socket.
    #[test]
    fn a_wasi_tcp_socket_retires_a_listener_it_never_adopted() {
        let (service, closed) = crate::test_support::recording_listener_network_service();
        let retirement = TestSocketRetirement::new(service);
        let listener = |raw| {
            Arc::new(OwnedTcpListener::new(
                retirement.sender(),
                crate::TcpListener {
                    listener: raw,
                    local_port: 8080,
                },
            ))
        };

        let mut unsettled = TcpSocket::new(retirement.sender(), WasiTcpSocketFamily::Ipv4);
        let (answer, receiver) = futures::channel::oneshot::channel();
        unsettled.pending_listen = Some(receiver);
        assert!(answer.send(Ok(listener(42))).is_ok());
        drop(unsettled);
        assert_eq!(
            retirement.drain(),
            1,
            "a listener still in the listen task's answer is retired"
        );
        assert_eq!(closed.count(), 1);
        assert_eq!(closed.last(), 42);
    }

    /// A `wasi:sockets` datagram socket's kernel socket dies with the
    /// socket.
    ///
    /// Nothing retired it before: the resource destructor deleted the
    /// table entry and the socket state had no `Drop`, so every program
    /// that bound a `udp-socket` left a replica on every shard and a
    /// slot in `udp_slots` behind it (#190).
    #[test]
    fn a_wasi_udp_socket_retires_its_socket_when_its_resource_is_dropped() {
        let (service, closed) = crate::test_support::recording_udp_network_service();
        let retirement = TestSocketRetirement::new(service.clone());
        let mut socket = UdpSocket::new(retirement.sender(), WasiUdpSocketFamily::Ipv4);
        block_on(socket.bind(&service, udp4([0, 0, 0, 0], 5353)))
            .expect("the test service always binds");

        assert!(
            !retirement.queued(),
            "a live socket must not have retired its binding"
        );
        drop(socket);
        assert_eq!(
            retirement.drain(),
            1,
            "dropping the socket must retire the binding it owns"
        );
        assert_eq!(closed.count(), 1);
        assert_eq!(closed.last(), 9, "the retired socket is the one bound");
    }

    /// A binding a p3 send or receive took with the socket released
    /// outlives the socket, and the kernel socket is retired only once
    /// the last holder is gone. Retiring on the socket's drop would
    /// unbind a socket the operation is still using, and the slab slot
    /// it frees is handed straight to the next bind.
    #[test]
    fn a_wasi_udp_socket_retires_its_socket_only_once_every_holder_is_gone() {
        let (service, closed) = crate::test_support::recording_udp_network_service();
        let retirement = TestSocketRetirement::new(service.clone());
        let mut socket = UdpSocket::new(retirement.sender(), WasiUdpSocketFamily::Ipv4);
        block_on(socket.bind(&service, udp4([0, 0, 0, 0], 5353)))
            .expect("the test service always binds");
        let borrowed = socket
            .start_receive(None)
            .expect("a bound socket admits a receive");

        drop(socket);
        assert_eq!(
            retirement.drain(),
            0,
            "a binding an operation still holds must stay open"
        );
        drop(borrowed);
        assert_eq!(retirement.drain(), 1, "the last holder retires the binding");
        assert_eq!(closed.count(), 1);
    }

    #[test]
    fn p3_tcp_socket_hop_limit_is_descriptor_local_state() {
        let service = TestNetworkService::new();
        let retirement = TestSocketRetirement::new(service.clone());
        let mut socket = TcpSocket::new(retirement.sender(), WasiTcpSocketFamily::Ipv4);

        assert_eq!(socket.hop_limit().unwrap(), DEFAULT_WASI_TCP_HOP_LIMIT);
        socket
            .set_hop_limit(&service, 127)
            .expect("nonzero hop limit must be accepted");
        assert_eq!(socket.hop_limit().unwrap(), 127);
        assert!(matches!(
            socket.set_hop_limit(&service, 0),
            Err(socket_types::ErrorCode::InvalidArgument)
        ));
        assert_eq!(socket.hop_limit().unwrap(), 127);
    }

    /// Enabling keepalive must fail rather than be recorded.
    ///
    /// The netstack has no keepalive timer, so a socket that accepted
    /// `set-keep-alive-enabled(true)` would leave a guest believing dead peers
    /// get detected. The timing knobs stay settable — `wasi:sockets` allows
    /// them to be configured while keepalive is off — and reading them back
    /// still reports what was stored.
    #[test]
    fn tcp_socket_rejects_enabling_unsupported_keep_alive() {
        let retirement = TestSocketRetirement::new(TestNetworkService::new());
        let mut socket = TcpSocket::new(retirement.sender(), WasiTcpSocketFamily::Ipv4);

        assert!(!socket.keep_alive_enabled().unwrap());
        assert_eq!(
            socket.keep_alive_idle_time().unwrap(),
            DEFAULT_WASI_TCP_KEEP_ALIVE_IDLE_NANOS
        );
        assert_eq!(
            socket.keep_alive_interval().unwrap(),
            DEFAULT_WASI_TCP_KEEP_ALIVE_INTERVAL_NANOS
        );
        assert_eq!(
            socket.keep_alive_count().unwrap(),
            DEFAULT_WASI_TCP_KEEP_ALIVE_COUNT
        );

        assert!(matches!(
            socket.set_keep_alive_enabled(true),
            Err(socket_types::ErrorCode::NotSupported)
        ));
        assert!(!socket.keep_alive_enabled().unwrap());
        socket
            .set_keep_alive_enabled(false)
            .expect("disabling keepalive matches what the stack already does");
        socket
            .set_keep_alive_idle_time(11)
            .expect("nonzero idle time must be accepted");
        socket
            .set_keep_alive_interval(13)
            .expect("nonzero interval must be accepted");
        socket
            .set_keep_alive_count(3)
            .expect("nonzero count must be accepted");

        assert!(!socket.keep_alive_enabled().unwrap());
        assert_eq!(socket.keep_alive_idle_time().unwrap(), 11);
        assert_eq!(socket.keep_alive_interval().unwrap(), 13);
        assert_eq!(socket.keep_alive_count().unwrap(), 3);
        assert!(matches!(
            socket.set_keep_alive_idle_time(0),
            Err(socket_types::ErrorCode::InvalidArgument)
        ));
        assert!(matches!(
            socket.set_keep_alive_interval(0),
            Err(socket_types::ErrorCode::InvalidArgument)
        ));
        assert!(matches!(
            socket.set_keep_alive_count(0),
            Err(socket_types::ErrorCode::InvalidArgument)
        ));
        assert_eq!(socket.keep_alive_idle_time().unwrap(), 11);
        assert_eq!(socket.keep_alive_interval().unwrap(), 13);
        assert_eq!(socket.keep_alive_count().unwrap(), 3);
    }

    /// A second p3 `connect` while one is running answers
    /// `invalid-state`, the code `wasi:sockets` documents for "The
    /// socket is already in the `connecting` state. (EALREADY)".
    ///
    /// The connect runs with the socket released, so the second call
    /// used to find nothing marking the first: both connected, and the
    /// later to finish overwrote the earlier's stream. A cancelled
    /// connect leaves no mark behind, and a connected socket refuses
    /// another connect as it always has.
    #[test]
    fn p3_tcp_connect_refuses_a_second_connect_while_one_runs() {
        let (service, closed) = crate::test_support::recording_network_service();
        let retirement = TestSocketRetirement::new(service.clone());
        let mut socket = TcpSocket::new(retirement.sender(), WasiTcpSocketFamily::Ipv4);
        let remote = tcp4([127, 0, 0, 1], 80);

        let first = socket
            .start_p3_connect()
            .expect("an unconnected socket admits a connect");
        assert!(matches!(
            socket.start_p3_connect(),
            Err(socket_types::ErrorCode::InvalidState)
        ));

        drop(first);
        let again = socket
            .start_p3_connect()
            .expect("a cancelled connect leaves the socket free");
        let (guard, outcome) = block_on(again.run(&service, remote));
        socket
            .finish_p3_connect(guard, remote, outcome)
            .expect("the test service always connects");
        assert_eq!(socket.remote_address().unwrap(), remote);
        assert!(matches!(
            socket.start_p3_connect(),
            Err(socket_types::ErrorCode::InvalidState)
        ));

        drop(socket);
        assert_eq!(retirement.drain(), 1, "one connect made one stream");
        assert_eq!(closed.count(), 1);
    }

    /// A bind while a p3 `send`'s implicit bind is running answers
    /// `invalid-state`, the code `wasi:sockets` documents for "The
    /// socket is already bound. (EINVAL)".
    ///
    /// The send binds with the socket released. Before the socket kept
    /// a mark of it, a second send, a `bind` or a `connect` bound the
    /// socket again meanwhile, and the later of the two to finish failed
    /// the assertion "udp bind raced with a concurrent state
    /// transition". A cancelled implicit bind leaves no mark behind.
    #[test]
    fn a_udp_bind_while_an_implicit_bind_runs_is_invalid_state() {
        let (service, closed) = crate::test_support::recording_udp_network_service();
        let retirement = TestSocketRetirement::new(service.clone());
        let mut socket = UdpSocket::new(retirement.sender(), WasiUdpSocketFamily::Ipv4);
        let peer = Some(udp4([192, 0, 2, 4], 53));

        let Ok(UdpSend {
            binding: UdpSendBinding::Unbound(first),
            ..
        }) = socket.start_send(5, peer)
        else {
            panic!("a send on an unbound socket binds it first");
        };
        assert!(matches!(
            socket.start_send(5, peer),
            Err(WasiUdpSocketError::InvalidState)
        ));
        assert!(matches!(
            block_on(socket.bind(&service, udp4([0, 0, 0, 0], 5353))),
            Err(WasiUdpSocketError::InvalidState)
        ));
        assert!(matches!(
            block_on(socket.connect(&service, udp4([192, 0, 2, 4], 53))),
            Err(WasiUdpSocketError::InvalidState)
        ));

        drop(first);
        let Ok(UdpSend {
            binding: UdpSendBinding::Unbound(bind),
            ..
        }) = socket.start_send(5, peer)
        else {
            panic!("a cancelled implicit bind leaves the socket unbound");
        };
        let (guard, outcome) = block_on(bind.run(&service));
        socket
            .finish_implicit_bind(guard, outcome)
            .expect("the test service always binds");
        assert!(matches!(
            socket.start_send(5, peer),
            Ok(UdpSend {
                binding: UdpSendBinding::Bound(_),
                ..
            })
        ));

        drop(socket);
        assert_eq!(retirement.drain(), 1, "one implicit bind made one socket");
        assert_eq!(closed.count(), 1);
    }

    #[test]
    fn tcp_socket_bind_local_tracks_authorized_local_address() {
        let retirement = TestSocketRetirement::new(TestNetworkService::new());
        let mut socket = TcpSocket::new(retirement.sender(), WasiTcpSocketFamily::Ipv4);
        let local = tcp4([127, 0, 0, 1], 8080);

        socket
            .bind_local(local)
            .expect("unconnected socket must accept a local bind");
        assert_eq!(socket.local_address().unwrap(), local);
        assert!(!socket.is_listening());
    }

    #[test]
    fn tcp_socket_listen_backlog_is_descriptor_local_state() {
        let retirement = TestSocketRetirement::new(TestNetworkService::new());
        let mut socket = TcpSocket::new(retirement.sender(), WasiTcpSocketFamily::Ipv4);

        assert_eq!(socket.listen_backlog(), DEFAULT_WASI_TCP_LISTEN_BACKLOG);
        socket
            .set_listen_backlog_size(64)
            .expect("positive u16 backlog must be accepted");
        assert_eq!(socket.listen_backlog(), 64);
        assert!(matches!(
            socket.set_listen_backlog_size(0),
            Err(socket_types::ErrorCode::InvalidArgument)
        ));
        assert!(matches!(
            socket.set_listen_backlog_size(u64::from(u16::MAX) + 1),
            Err(socket_types::ErrorCode::InvalidArgument)
        ));
        assert_eq!(socket.listen_backlog(), 64);
    }

    #[test]
    fn p3_tcp_socket_uses_network_backend_without_widening_rights() {
        let service = TestNetworkService::new();
        let retirement = TestSocketRetirement::new(service.clone());
        let mut socket = TcpSocket::new(retirement.sender(), WasiTcpSocketFamily::Ipv4);
        let remote = tcp4([203, 0, 113, 10], 443);

        block_on(socket.connect(&service, remote)).expect("test TCP backend should connect");
        assert_eq!(socket.remote_address().unwrap(), remote);
        block_on(write_socket(
            socket.connection(),
            service.clone(),
            Bytes::from_static(b"hello"),
        ))
        .expect("test TCP backend should write");
        let bytes = block_on(read_socket(socket.connection(), service.clone(), 16))
            .unwrap()
            .expect("test TCP backend should read bytes");
        assert_eq!(bytes.as_ref(), [4, 2]);
    }
}
