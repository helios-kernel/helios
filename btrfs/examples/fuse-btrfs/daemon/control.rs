//! Per-mount control Unix socket served by the running `fuse-btrfs` daemon.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fuser::Errno;
use futures_lite::future::block_on;
use tracing::warn;

use crate::protocol::{self, ControlRequest, ControlResponse};

use super::state::SharedState;

/// Timeout for reading a request or writing a response on the control socket.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time `remount,ro` waits for an already-closed file's asynchronous
/// `FUSE_RELEASE` to be processed by the FUSE event loop after `mount -i` has
/// set `SB_RDONLY`.
const RELEASE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs a dedicated listener thread serving control requests for one mount.
///
/// Dropping or calling [`Self::shutdown`] stops the listener thread (releasing
/// its [`Arc<SharedState>`]) and removes the socket file.
pub struct ControlServer {
    socket_path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlServer {
    pub fn start(mountpoint: &Path, device: &Path, shared: Arc<SharedState>) -> io::Result<Self> {
        let dir = protocol::run_dir();
        let socket_path = protocol::socket_path(&dir, mountpoint);
        Self::bind_at(socket_path, device.display().to_string(), shared)
    }

    fn bind_at(socket_path: PathBuf, device: String, shared: Arc<SharedState>) -> io::Result<Self> {
        if let Some(parent) = socket_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                // Safe to unlink a leftover socket from a crashed daemon: we
                // bind only after `Session::new` has mounted this mountpoint.
                let _ = std::fs::remove_file(&socket_path);
                UnixListener::bind(&socket_path)?
            }
            Err(error) => return Err(error),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("fuse-btrfs-control".to_owned())
            .spawn(move || serve(listener, thread_stop, device, shared))?;
        Ok(Self {
            socket_path,
            stop,
            thread: Some(thread),
        })
    }

    pub fn shutdown(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            // Wake the blocking `accept()` call without polling.
            let _ = UnixStream::connect(&self.socket_path);
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

fn serve(listener: UnixListener, stop: Arc<AtomicBool>, device: String, shared: Arc<SharedState>) {
    for incoming in listener.incoming() {
        if stop.load(Ordering::Acquire) {
            break;
        }
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                warn!(%error, "control socket accept failed");
                continue;
            }
        };
        if let Err(error) = handle_connection(stream, &device, &shared) {
            warn!(%error, "control socket request failed");
        }
    }
}

fn handle_connection(mut stream: UnixStream, device: &str, shared: &SharedState) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&stream);
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
    }
    let response = match ControlRequest::decode(&line) {
        Some(request) => dispatch(request, device, shared),
        None => ControlResponse::Error {
            errno: libc::EINVAL,
            message: format!("unknown control request: {}", line.trim()),
        },
    };
    stream.write_all(response.encode().as_bytes())?;
    stream.flush()
}

fn dispatch(request: ControlRequest, device: &str, shared: &SharedState) -> ControlResponse {
    match request {
        ControlRequest::Status => {
            let state = shared
                .state
                .lock()
                .expect("an earlier request panicked while holding the filesystem");
            if state.is_destroyed() {
                return errno_response(Errno::ENODEV, "filesystem is unmounted");
            }
            ControlResponse::Status {
                read_only: state.is_read_only(),
                device: device.to_owned(),
            }
        }
        ControlRequest::RemountReadOnly => {
            let mut state = shared
                .state
                .lock()
                .expect("an earlier request panicked while holding the filesystem");
            let deadline = Instant::now() + RELEASE_DRAIN_TIMEOUT;
            while !state.is_destroyed() && state.blocks_read_only_remount() {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                let (guard, waited) = shared
                    .writable_released
                    .wait_timeout(state, remaining)
                    .expect("an earlier request panicked while holding the filesystem");
                state = guard;
                if waited.timed_out() {
                    break;
                }
            }
            match block_on(state.remount_read_only()) {
                Ok(()) => ControlResponse::Ok,
                Err(errno) => errno_response(errno, "remount read-only failed"),
            }
        }
        ControlRequest::RemountReadWrite => {
            let mut state = shared
                .state
                .lock()
                .expect("an earlier request panicked while holding the filesystem");
            match block_on(state.remount_read_write()) {
                Ok(()) => ControlResponse::Ok,
                Err(errno) => errno_response(errno, "remount read-write failed"),
            }
        }
        ControlRequest::RollbackReadOnly => {
            let mut state = shared
                .state
                .lock()
                .expect("an earlier request panicked while holding the filesystem");
            match state.rollback_read_only() {
                Ok(()) => ControlResponse::Ok,
                Err(errno) => errno_response(errno, "rollback to read-only failed"),
            }
        }
    }
}

fn errno_response(errno: Errno, context: &str) -> ControlResponse {
    let code = i32::from(errno);
    let message = format!("{context}: {}", io::Error::from_raw_os_error(code));
    ControlResponse::Error {
        errno: code,
        message,
    }
}

/// Sends one control request to the daemon listening at `socket_path`.
pub fn send(socket_path: &Path, request: ControlRequest) -> io::Result<ControlResponse> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(request.encode().as_bytes())?;
    stream.flush()?;
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line)?;
    ControlResponse::decode(&line).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid response from fuse-btrfs daemon: {:?}", line.trim()),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs::{File, Permissions};
    use std::num::NonZeroUsize;
    use std::os::unix::fs::PermissionsExt;

    use ferrosys::btrfs::{FormatOptions, format_to};
    use ferrosys::{Metadata, Timestamp as FerrosysTimestamp, TreeBuilder};
    use fuser::{FileHandle, INodeNo, OpenFlags};
    use helios_btrfs::Timestamp;

    use super::*;
    use crate::daemon::device::Claim;
    use crate::daemon::state::{Node, Owner, State};

    const VOLUME_BYTES: u64 = 128 << 20;

    fn make_image(dir: &Path) -> PathBuf {
        let path = dir.join("btrfs.img");
        let mut file = File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(VOLUME_BYTES).unwrap();
        let when = FerrosysTimestamp::from_secs(1_700_000_000);
        let tree = TreeBuilder::new()
            .root(Metadata::new(0o755, when).owned_by(0, 0))
            .directory("/existing", Metadata::new(0o755, when).owned_by(0, 0))
            .file(
                "/existing/pre.txt",
                b"before".to_vec(),
                Metadata::new(0o644, when).owned_by(0, 0),
            );
        let options = FormatOptions::new([0x5a; 16], when)
            .chunk_tree_uuid([0x22; 16])
            .device_uuid([0x33; 16])
            .subvolume_uuid([0x44; 16]);
        format_to(&mut file, tree, VOLUME_BYTES, options).expect("ferrosys formats image");
        file.sync_all().unwrap();
        path
    }

    #[test]
    fn remount_ro_and_rw_over_control_socket_tracks_writers_and_commits() {
        let dir = tempfile::tempdir().unwrap();
        let image = make_image(dir.path());
        let socket_path = dir.path().join("mount.sock");

        let claim = Claim::open(&image, false).unwrap();
        let concurrency = NonZeroUsize::new(1).unwrap();
        let state = State::open_for_test(claim, image.clone(), concurrency, false).unwrap();
        let shared = Arc::new(SharedState::new(state));
        let server = ControlServer::bind_at(
            socket_path.clone(),
            image.display().to_string(),
            Arc::clone(&shared),
        )
        .unwrap();

        let status = send(&socket_path, ControlRequest::Status).unwrap();
        assert_eq!(
            status,
            ControlResponse::Status {
                read_only: false,
                device: image.display().to_string(),
            }
        );

        let now = Timestamp {
            seconds: 1_700_000_001,
            nanoseconds: 0,
        };
        let (file_ino, fh) = {
            let mut state = shared.state.lock().unwrap();
            let (attr, _) = block_on(state.create(
                INodeNo::ROOT,
                OsStr::new("note.txt"),
                Node::File,
                0o644,
                Owner {
                    uid: 0,
                    gid: 0,
                    umask: 0,
                },
                now,
            ))
            .unwrap();
            let fh = block_on(state.open_file(attr.ino, OpenFlags(libc::O_WRONLY))).unwrap();
            assert_ne!(fh, FileHandle(0));
            let written = block_on(state.write(attr.ino, 0, b"durable", now)).unwrap();
            assert_eq!(written, 7);
            // Direct remount_read_only rejects open writable handles with EBUSY.
            assert_eq!(block_on(state.remount_read_only()), Err(Errno::EBUSY));
            (attr.ino, fh)
        };

        // Release the writable handle from another thread while `RemountReadOnly`
        // waits on `writable_released`, mirroring an in-flight async FUSE_RELEASE.
        let releaser_shared = Arc::clone(&shared);
        let releaser = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            let mut state = releaser_shared.state.lock().unwrap();
            assert!(block_on(state.release_file(fh)));
            releaser_shared.writable_released.notify_all();
        });

        assert_eq!(
            send(&socket_path, ControlRequest::RemountReadOnly).unwrap(),
            ControlResponse::Ok
        );
        releaser.join().unwrap();

        // Verify the transaction was committed durably on disk before
        // `RemountReadOnly` returned by reading the image independently.
        {
            let ro_claim = Claim::open(&image, true).unwrap();
            let ro_device =
                crate::daemon::device::Device::open_read_only(&image, ro_claim).unwrap();
            let fs = block_on(helios_btrfs::Filesystem::mount(Arc::new(ro_device))).unwrap();
            let root = block_on(fs.root()).unwrap();
            let note = block_on(fs.lookup(&root, b"note.txt"))
                .unwrap()
                .expect("note.txt was committed durably on remount,ro");
            let mut buf = [0_u8; 16];
            let len = block_on(fs.read(&note, 0, &mut buf)).unwrap();
            assert_eq!(&buf[..len], b"durable");
        }

        assert_eq!(
            send(&socket_path, ControlRequest::Status).unwrap(),
            ControlResponse::Status {
                read_only: true,
                device: image.display().to_string(),
            }
        );
        {
            let mut state = shared.state.lock().unwrap();
            assert_eq!(
                block_on(state.open_file(file_ino, OpenFlags(libc::O_WRONLY))),
                Err(Errno::EROFS)
            );
            let ro_fh = block_on(state.open_file(file_ino, OpenFlags(libc::O_RDONLY))).unwrap();
            assert_ne!(ro_fh, FileHandle(0));
            assert!(!block_on(state.release_file(ro_fh)));
        }

        // Transition back to rw, then test rollback_ro.
        assert_eq!(
            send(&socket_path, ControlRequest::RemountReadWrite).unwrap(),
            ControlResponse::Ok
        );
        assert_eq!(
            send(&socket_path, ControlRequest::Status).unwrap(),
            ControlResponse::Status {
                read_only: false,
                device: image.display().to_string(),
            }
        );
        assert_eq!(
            send(&socket_path, ControlRequest::RollbackReadOnly).unwrap(),
            ControlResponse::Ok
        );
        assert_eq!(
            send(&socket_path, ControlRequest::Status).unwrap(),
            ControlResponse::Status {
                read_only: true,
                device: image.display().to_string(),
            }
        );

        server.shutdown();
        assert!(!socket_path.exists());
    }

    #[test]
    fn read_only_image_upgrades_to_writable_after_permissions_allow_write() {
        let dir = tempfile::tempdir().unwrap();
        let image = make_image(dir.path());
        // Make the image read-only so initial open uses `Storage::ReadOnly`.
        // Skip only when running as root (UID 0 bypasses DAC read-only mode
        // bits on regular files, whereas block devices use `BLKROGET`).
        // SAFETY: `geteuid` takes no pointers, reads the calling process's
        // effective user ID, and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        std::fs::set_permissions(&image, Permissions::from_mode(0o444)).unwrap();

        let claim = Claim::open(&image, true).unwrap();
        assert!(!claim.is_writable());
        let concurrency = NonZeroUsize::new(1).unwrap();
        let mut state = State::open_for_test(claim, image.clone(), concurrency, true).unwrap();
        assert!(state.is_read_only());

        // Look up a pre-existing directory and file while under
        // `Storage::ReadOnly` so their FUSE inodes are cached without writer
        // handles before `remount,rw`, including via export-handle `.` lookup.
        let (dir_attr, _) = block_on(state.lookup(INodeNo::ROOT, OsStr::new("existing"))).unwrap();
        let (file_attr, _) = block_on(state.lookup(dir_attr.ino, OsStr::new("pre.txt"))).unwrap();
        block_on(state.forget(file_attr.ino, 1));
        let (reopened_attr, _) = block_on(state.lookup(file_attr.ino, OsStr::new("."))).unwrap();
        assert_eq!(reopened_attr.ino, file_attr.ino);
        assert_eq!(
            block_on(state.read(file_attr.ino, 0, 16)).unwrap(),
            b"before"
        );

        // Still read-only -> remount_read_write fails with EACCES.
        assert_eq!(block_on(state.remount_read_write()), Err(Errno::EACCES));
        assert!(state.is_read_only());

        // Restore write permission -> upgrades to `Storage::Writable` and
        // attaches live handles to cached non-root inodes.
        std::fs::set_permissions(&image, Permissions::from_mode(0o644)).unwrap();
        block_on(state.remount_read_write()).unwrap();
        assert!(!state.is_read_only());

        let now = Timestamp {
            seconds: 1_700_000_002,
            nanoseconds: 0,
        };
        // Mutate the pre-cached non-root file directly (no re-lookup).
        assert_eq!(
            block_on(state.write(file_attr.ino, 0, b"after!", now)).unwrap(),
            6
        );
        assert_eq!(
            block_on(state.read(file_attr.ino, 0, 16)).unwrap(),
            b"after!"
        );
        // Create a new file inside the pre-cached non-root directory directly.
        let (attr, _) = block_on(state.create(
            dir_attr.ino,
            OsStr::new("after-upgrade.txt"),
            Node::File,
            0o644,
            Owner {
                uid: 0,
                gid: 0,
                umask: 0,
            },
            now,
        ))
        .unwrap();
        assert_eq!(block_on(state.write(attr.ino, 0, b"ok", now)).unwrap(), 2);
        block_on(state.remount_read_only()).unwrap();
        assert!(state.is_read_only());
    }
}
