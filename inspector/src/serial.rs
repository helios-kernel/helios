use async_io::Async;
use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{ChildStdin, ChildStdout};
use std::time::{Duration, Instant};

/// Which half of a transport a failure concerns.
///
/// A transport is opened as a pair, and the two halves fail for
/// different reasons — a reader that cannot be cloned and a writer that
/// cannot be registered are different defects — so the half is part of
/// what the message names.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TransportHalf {
    Reader,
    Writer,
}

impl std::fmt::Display for TransportHalf {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Reader => "reader",
            Self::Writer => "writer",
        })
    }
}

/// Why the inspector could not open the transport its RPC runs over.
///
/// Each variant names the device or pipe it was working on and the step
/// that failed, because the caller's next move differs by step: a device
/// that cannot be opened is a wrong path or a permission, a device that
/// opens and cannot be registered is a host that will not poll it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SerialError {
    #[error("failed to inspect serial device {device}: {source}")]
    InspectDevice {
        device: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to open serial device {device} with serialport: {source}")]
    OpenTty {
        device: String,
        #[source]
        source: serialport::Error,
    },
    #[error("failed to clone serial device {device}: {source}")]
    CloneTty {
        device: String,
        #[source]
        source: serialport::Error,
    },
    #[error("failed to register serial device {device}: {source}")]
    RegisterTty {
        device: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to connect to serial socket {device}: {source}")]
    ConnectSocket {
        device: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to configure serial socket {device} nonblocking: {source}")]
    ConfigureSocket {
        device: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to clone serial socket {device} reader: {source}")]
    CloneSocket {
        device: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to register serial socket {device} {half}: {source}")]
    RegisterSocket {
        device: String,
        half: TransportHalf,
        #[source]
        source: io::Error,
    },
    #[error("failed to register QEMU {pipe} serial pipe: {source}")]
    RegisterChildPipe {
        pipe: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to create serial PTY: {source}")]
    CreatePty {
        #[source]
        source: io::Error,
    },
    #[error("failed to {step}: {source}")]
    ConfigurePty {
        /// The PTY attribute that was being read or written, spelled the
        /// way the message reads it.
        step: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("serial PTY path was not valid UTF-8: {source}")]
    PtyPathNotUtf8 {
        #[source]
        source: core::str::Utf8Error,
    },
    #[error("failed to clone serial PTY master: {source}")]
    ClonePty {
        #[source]
        source: io::Error,
    },
    #[error("failed to register serial PTY {half}: {source}")]
    RegisterPty {
        half: TransportHalf,
        #[source]
        source: io::Error,
    },
}

/// The read half of a transport the inspector RPC can run over.
///
/// Reuses `helios-ops`'s transport trait aliases so a booted VM's [`RpcClient`]
/// hands directly into [`helios_ops::Session`] with zero adapter overhead.
pub(crate) use helios_ops::transport::{RpcReader, RpcWriter};

#[derive(Clone)]
pub(crate) struct RpcClient {
    client: helios_wit_rpc::PeerHandle,
    driver: std::sync::Arc<crate::frame_reader::FrameReader>,
}

impl RpcClient {
    pub(crate) fn new(read: RpcReader, write: RpcWriter) -> io::Result<Self> {
        let (client, driver) = crate::frame_reader::FrameReader::start(read, write)?;
        Ok(Self {
            client,
            driver: std::sync::Arc::new(driver),
        })
    }

    /// Runs the unified Ed25519 + `postcard` authentication handshake over
    /// `(read, write)` and starts the WIT-RPC frame driver once accepted.
    pub(crate) async fn connect_authenticated(
        mut read: RpcReader,
        mut write: RpcWriter,
        transport: helios_inspector_protocol::auth::TransportKind,
        identity: &helios_inspector_protocol::auth::ClientIdentity,
        expected_machine_public_key: Option<[u8; 32]>,
    ) -> Result<Self, AuthConnectError> {
        let _accepted = helios_inspector_protocol::auth::client_handshake(
            &mut read,
            &mut write,
            transport,
            identity,
            expected_machine_public_key,
            None,
            None,
        )
        .await?;
        Ok(Self::new(read, write)?)
    }

    /// Cheaply clone the underlying `helios-wit-rpc` peer handle.
    pub(crate) fn peer(&self) -> helios_wit_rpc::PeerHandle {
        self.client.clone()
    }

    /// Wrap this already-connected client into a [`helios_ops::RpcConnection`]
    /// sharing the same frame reader guard.
    pub(crate) fn to_ops_connection(&self) -> helios_ops::RpcConnection {
        helios_ops::RpcConnection::from_external(
            self.client.clone(),
            std::sync::Arc::clone(&self.driver) as std::sync::Arc<dyn Send + Sync>,
        )
    }
}

/// Why an authenticated inspector connection could not be established.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AuthConnectError {
    #[error("inspector authentication handshake failed: {0}")]
    Auth(#[from] helios_inspector_protocol::auth::AuthError),
    #[error("failed to start RPC frame driver: {0}")]
    Driver(#[from] io::Error),
}

impl std::ops::Deref for RpcClient {
    type Target = helios_wit_rpc::PeerHandle;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

const SOCKET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKET_CONNECT_POLL: Duration = Duration::from_millis(50);

pub(crate) struct SerialIo {
    read: RpcReader,
    write: RpcWriter,
}

pub(crate) struct PtyTransport {
    pub(crate) io: SerialIo,
    pub(crate) slave_path: PathBuf,
    pub(crate) slave: File,
}

pub(crate) async fn open(device: &str, baud: u32) -> Result<SerialIo, SerialError> {
    let (read, write) = if is_unix_socket(device)? {
        open_socket_transport(device).await?
    } else {
        open_tty_transport(device, baud)?
    };
    Ok(SerialIo { read, write })
}

pub(crate) fn open_child_stdio(
    stdout: ChildStdout,
    stdin: ChildStdin,
) -> Result<SerialIo, SerialError> {
    Ok(SerialIo {
        read: Box::new(Async::new(AsyncChildStdout::new(stdout)).map_err(|source| {
            SerialError::RegisterChildPipe {
                pipe: "stdout",
                source,
            }
        })?),
        write: Box::new(Async::new(AsyncChildStdin::new(stdin)).map_err(|source| {
            SerialError::RegisterChildPipe {
                pipe: "stdin",
                source,
            }
        })?),
    })
}

pub(crate) fn open_pty_transport() -> Result<PtyTransport, SerialError> {
    let mut master_fd = 0;
    let mut slave_fd = 0;
    // `c_char` is i8 on x86-64 Linux but u8 on aarch64 Linux; spell the
    // libc type so the buffer matches on both.
    let mut name = [0 as libc::c_char; 128];
    // SAFETY: `master_fd` and `slave_fd` point to writable stack `c_int` locals,
    // `name` provides 128 bytes for the `/dev/pts/...` or `/dev/ttys...` slave
    // PTY pathname, and `termp`/`winp` may be null per `openpty(3)`.
    let status = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            name.as_mut_ptr(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(SerialError::CreatePty {
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: `openpty` succeeded (`status == 0`), returning a newly opened,
    // exclusively owned master PTY descriptor in `master_fd`.
    let master = unsafe { File::from_raw_fd(master_fd) };
    // SAFETY: `openpty` succeeded (`status == 0`), returning a newly opened,
    // exclusively owned slave PTY descriptor in `slave_fd` distinct from `master_fd`.
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    configure_raw_pty(slave.as_fd())?;
    // SAFETY: `openpty` succeeded (`status == 0`), writing a NUL-terminated
    // slave PTY pathname into `name`.
    let path = unsafe { CStr::from_ptr(name.as_ptr()) }
        .to_str()
        .map_err(|source| SerialError::PtyPathNotUtf8 { source })?;
    configure_nonblocking(master.as_fd())?;
    let read = master
        .try_clone()
        .map_err(|source| SerialError::ClonePty { source })?;
    Ok(PtyTransport {
        io: SerialIo {
            read: Box::new(Async::new(PtyFile::new(read)).map_err(|source| {
                SerialError::RegisterPty {
                    half: TransportHalf::Reader,
                    source,
                }
            })?),
            write: Box::new(Async::new(PtyFile::new(master)).map_err(|source| {
                SerialError::RegisterPty {
                    half: TransportHalf::Writer,
                    source,
                }
            })?),
        },
        slave_path: PathBuf::from(path),
        slave,
    })
}

fn configure_raw_pty(fd: BorrowedFd<'_>) -> Result<(), SerialError> {
    let mut termios = core::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: `fd` is a valid open PTY descriptor (`BorrowedFd`) and
    // `termios` is writable stack storage for `libc::termios`.
    if unsafe { libc::tcgetattr(fd.as_raw_fd(), termios.as_mut_ptr()) } != 0 {
        return Err(SerialError::ConfigurePty {
            step: "inspect serial PTY termios",
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: `tcgetattr` returned 0, so `termios` is fully initialized.
    let mut termios = unsafe { termios.assume_init() };
    // SAFETY: `termios` is an initialized `libc::termios` passed by unique
    // mutable reference.
    unsafe {
        libc::cfmakeraw(&mut termios);
    }
    // SAFETY: `fd` is a valid open PTY descriptor and `&termios` points to an
    // initialized `libc::termios`.
    if unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSANOW, &termios) } != 0 {
        return Err(SerialError::ConfigurePty {
            step: "configure serial PTY raw mode",
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

fn configure_nonblocking(fd: BorrowedFd<'_>) -> Result<(), SerialError> {
    // SAFETY: `fd` is a valid open file descriptor (`BorrowedFd`) and `F_GETFL`
    // takes no extra arguments.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(SerialError::ConfigurePty {
            step: "inspect serial PTY flags",
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: `fd` is a valid open file descriptor (`BorrowedFd`) and `F_SETFL`
    // takes a single `c_int` flags argument.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(SerialError::ConfigurePty {
            step: "configure serial PTY nonblocking",
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

struct PtyFile {
    file: File,
}

impl PtyFile {
    fn new(file: File) -> Self {
        Self { file }
    }
}

// SAFETY: `PtyFile`'s `Read` and `Write` implementations only forward to
// `self.file` and never move out or drop the underlying `File`.
unsafe impl async_io::IoSafe for PtyFile {}

impl AsFd for PtyFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl io::Read for PtyFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.file, buf)
    }
}

impl io::Write for PtyFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.file, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.file)
    }
}

fn is_unix_socket(device: &str) -> Result<bool, SerialError> {
    match std::fs::metadata(device) {
        Ok(metadata) => Ok(metadata.file_type().is_socket()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(device.ends_with(".sock")),
        Err(source) => Err(SerialError::InspectDevice {
            device: device.to_owned(),
            source,
        }),
    }
}

impl SerialIo {
    pub(crate) fn into_split(self) -> (RpcReader, RpcWriter) {
        (self.read, self.write)
    }
}

struct AsyncSerialPort {
    port: serialport::TTYPort,
}

impl AsyncSerialPort {
    fn new(port: serialport::TTYPort) -> Self {
        Self { port }
    }
}

// SAFETY: `AsyncSerialPort`'s `Read` and `Write` implementations only forward
// to `self.port` and never move out or drop the underlying `TTYPort`.
unsafe impl async_io::IoSafe for AsyncSerialPort {}

impl AsFd for AsyncSerialPort {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: `self.port` owns its underlying TTY file descriptor and
        // closes it only on drop, so the raw descriptor stays open and valid
        // for the lifetime of `&self`.
        unsafe { BorrowedFd::borrow_raw(self.port.as_raw_fd()) }
    }
}

impl io::Read for AsyncSerialPort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.port, buf)
    }
}

impl io::Write for AsyncSerialPort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.port, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.port)
    }
}

struct AsyncChildStdout {
    stdout: ChildStdout,
}

impl AsyncChildStdout {
    fn new(stdout: ChildStdout) -> Self {
        Self { stdout }
    }
}

// SAFETY: `AsyncChildStdout`'s `Read` implementation only forwards to
// `self.stdout` and never moves out or drops the underlying `ChildStdout`.
unsafe impl async_io::IoSafe for AsyncChildStdout {}

impl AsFd for AsyncChildStdout {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stdout.as_fd()
    }
}

impl io::Read for AsyncChildStdout {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.stdout, buf)
    }
}

struct AsyncChildStdin {
    stdin: ChildStdin,
}

impl AsyncChildStdin {
    fn new(stdin: ChildStdin) -> Self {
        Self { stdin }
    }
}

// SAFETY: `AsyncChildStdin`'s `Write` implementation only forwards to
// `self.stdin` and never moves out or drops the underlying `ChildStdin`.
unsafe impl async_io::IoSafe for AsyncChildStdin {}

impl AsFd for AsyncChildStdin {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stdin.as_fd()
    }
}

impl io::Write for AsyncChildStdin {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.stdin, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.stdin)
    }
}

fn open_tty_transport(device: &str, baud: u32) -> Result<(RpcReader, RpcWriter), SerialError> {
    let register = |source| SerialError::RegisterTty {
        device: device.to_owned(),
        source,
    };
    let port = serialport::new(device, baud)
        .open_native()
        .map_err(|source| SerialError::OpenTty {
            device: device.to_owned(),
            source,
        })?;
    let read_port = port
        .try_clone_native()
        .map_err(|source| SerialError::CloneTty {
            device: device.to_owned(),
            source,
        })?;
    Ok((
        Box::new(Async::new(AsyncSerialPort::new(read_port)).map_err(register)?) as RpcReader,
        Box::new(Async::new(AsyncSerialPort::new(port)).map_err(register)?) as RpcWriter,
    ))
}

async fn open_socket_transport(device: &str) -> Result<(RpcReader, RpcWriter), SerialError> {
    let deadline = Instant::now() + SOCKET_CONNECT_TIMEOUT;
    let socket = loop {
        match UnixStream::connect(device) {
            Ok(socket) => break socket,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::NotFound
                        | io::ErrorKind::AddrNotAvailable
                ) && Instant::now() < deadline =>
            {
                async_io::Timer::after(SOCKET_CONNECT_POLL).await;
            }
            Err(source) => {
                return Err(SerialError::ConnectSocket {
                    device: device.to_owned(),
                    source,
                });
            }
        }
    };
    socket
        .set_nonblocking(true)
        .map_err(|source| SerialError::ConfigureSocket {
            device: device.to_owned(),
            source,
        })?;
    let read = socket
        .try_clone()
        .map_err(|source| SerialError::CloneSocket {
            device: device.to_owned(),
            source,
        })?;
    let register = |half| {
        move |source| SerialError::RegisterSocket {
            device: device.to_owned(),
            half,
            source,
        }
    };
    Ok((
        Box::new(Async::new(AsyncUnixSocket::new(read)).map_err(register(TransportHalf::Reader))?)
            as RpcReader,
        Box::new(Async::new(AsyncUnixSocket::new(socket)).map_err(register(TransportHalf::Writer))?)
            as RpcWriter,
    ))
}

struct AsyncUnixSocket {
    socket: UnixStream,
}

impl AsyncUnixSocket {
    fn new(socket: UnixStream) -> Self {
        Self { socket }
    }
}

// SAFETY: `AsyncUnixSocket`'s `Read` and `Write` implementations only forward
// to `self.socket` and never move out or drop the underlying `UnixStream`.
unsafe impl async_io::IoSafe for AsyncUnixSocket {}

impl AsFd for AsyncUnixSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl io::Read for AsyncUnixSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.socket, buf)
    }
}

impl io::Write for AsyncUnixSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.socket, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.socket)
    }
}
