//! The Linux process host: a static or dynamic Linux executable (`ET_EXEC` or
//! `ET_DYN`, with optional `PT_INTERP` dynamic linker) launched through the
//! program service, as a wasm program is, run natively through the
//! platform's [`helios_hal::native`] capability.
//!
//! Each thread of a Linux process runs on its own executor task with its own
//! [`UserContext`] and [`Process`] handle, sharing one [`UserSpace`] and one
//! underlying process state (descriptor table, futex queues, program break
//! and process attributes). Tasks spawned by `clone` / `clone3` enter the
//! instance's global home-node queue (`InstanceSpawner::try_spawn_detached`),
//! so online processors steal and execute threads of one process concurrently
//! across SMP. Its exit status, or the signal that ended it, reaches the
//! parent through the child's exit channel once every thread of the group has
//! exited and dropped its handles.
//!
//! # Concurrency
//!
//! - User slices and address-space mutations synchronize inside [`UserSpace`],
//!   which shoots down stale translations across active processors before
//!   reclaiming physical frames; multi-step VM compositions serialize on the
//!   process's shared address-space lock in `helios-linux`.
//! - Process-wide state in [`LinuxShared`] uses lock-free atomics for summed
//!   processor ticks, fatal-error latch and live spawned-task count, plus a
//!   bounded non-awaiting `spin::Mutex` for wall-clock offset updates.
//! - Each thread task checks instance condemnation, thread-group exit and
//!   process signals before every user slice and again after arming its
//!   `NotifyWaiter`s around every suspended system call, so `exit_group`, a
//!   fatal fault, OOM, a signal or a kill wakes every parked sibling at once
//!   and stops running slices at the next timer preemption.

use super::*;
use crate::{
    ComponentFsNodeKind, DiagnosticsControlCap, Ipv4Cidr as KernelIpv4Cidr,
    Ipv4Route as KernelIpv4Route, LinkSourceCap, MulticastCap, NetworkAdminCap,
    NetworkControlError, NetworkPortId, PrivilegedBindCap, SetWallClockCap, SymlinkCreateCap,
    SymlinkReadCap, TcpCap, TerminalAuthorityRights, TerminalInputCap, TerminalOutputCap,
    TraceReadCap, TtyControlCap, UdpCap,
};
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use helios_hal::fs::{FileSystem, FsError, Landed, NodeKind, RenameMode, WritePosition};
use helios_hal::native::{
    FaultKind, NativeError, NativeExecution, NativeUnavailable, RegionKind, Stop, UserContext,
    UserFault, UserSpace,
};
use helios_hal::pmm::PhysFrame;
use helios_hal::vmm::{PageFlags, VirtAddr, VirtRange};
use helios_linux::abi::{self, Abi};
use helios_linux::elf::{self, Image};
use helios_linux::syscall::{
    self, AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW, AccessCheck, Call, Denied, Descriptors, DirListEntry,
    EpollData, ExecError, ExecSpec, Exit, FileAccess, FileStat, Filesystem, LinkOptions, MapError,
    MemoryFault, MemoryTotals, OpenOutcome, OpenRequest, Process, ProcessSignals, READY_ERR,
    READY_HUP, READY_IN, READY_OUT, Region, Resource, Resources, SignalDelivery, SpawnError,
    SpawnedProcess, SpawnedThread, Start, StdinTryRead, Stdio, Stream, SyscallOutcome,
    SyscallRestart, System, Termios, TermiosAction, Thread, TimeUpdate, Tty, TtyError, TtyStream,
    UserMemory, VirtualMemory, Winsize, WriteError,
};
use helios_sync::{TryRead, TryWrite};

/// The ELF identification bytes every ELF file starts with (System V gABI,
/// `e_ident[EI_MAG0..EI_MAG3]`).
const ELF_MAGIC: &[u8] = b"\x7fELF";

/// Whether `bytes` are an ELF file, which only the Linux host runs.
pub(super) fn is_linux_elf(bytes: &[u8]) -> bool {
    bytes.starts_with(ELF_MAGIC)
}

/// A validated Linux executable (`ET_EXEC` or `ET_DYN`), optionally paired
/// with its resolved `PT_INTERP` dynamic linker image, ready to map into a new
/// process.
pub(super) struct LinuxExecutable {
    image: Bytes,
    interpreter: Option<Bytes>,
    path: Option<String>,
    abi: Abi,
    secure: bool,
}

impl LinuxExecutable {
    pub(super) fn set_secure(&mut self, secure: bool) {
        self.secure = secure;
    }

    #[cfg(test)]
    pub(super) fn is_secure(&self) -> bool {
        self.secure
    }

    /// Validates `image` for this platform. Refused when the platform has
    /// no native execution or its processor lacks a protection the
    /// isolation contract requires, when no Linux ABI is decoded for its
    /// instruction set, or when the image is not one the loader maps.
    pub(super) fn load<CpuImpl: Cpu>(
        cpu: &CpuImpl,
        image: Bytes,
    ) -> Result<Self, ProgramExecError> {
        let native = cpu.native().map_err(native_unavailable)?;
        let abi = Abi::for_instruction_set(native.instruction_set()).ok_or(ProgramExecError {
            kind: ProgramExecErrorKind::Unavailable,
            detail: ProgramExecErrorDetail::LinuxAbiUnsupported,
        })?;
        Image::parse(&image, abi, user_end(native)).map_err(image_error)?;
        Ok(Self {
            image,
            interpreter: None,
            path: None,
            abi,
            secure: false,
        })
    }

    /// Validates `image` and, when it declares `PT_INTERP`, resolves and
    /// validates the interpreter strictly inside `container`'s filesystem
    /// under `READ | EXECUTE` authority and `creds`.
    pub(super) async fn load_in_container<CpuImpl: Cpu, StorageImpl: crate::Storage>(
        cpu: &CpuImpl,
        container: &crate::LinuxContainer<StorageImpl>,
        base_dir: &str,
        image: Bytes,
        exec_path: Option<String>,
        creds: &syscall::Credentials,
    ) -> Result<Self, ProgramExecError> {
        let mut loaded = Self::load(cpu, image)?;
        loaded.path = exec_path;
        let native = cpu.native().map_err(native_unavailable)?;
        let limit = user_end(native);
        let interp_path = {
            let parsed = Image::parse(&loaded.image, loaded.abi, limit).map_err(image_error)?;
            parsed.interpreter().map(str::to_owned)
        };
        if let Some(interp_path) = interp_path {
            let interp_bytes = read_interpreter_in_container(
                container.filesystem(),
                base_dir,
                &interp_path,
                creds,
            )
            .await
            .map_err(map_fs_op_error_to_program)?;
            if !is_linux_elf(&interp_bytes) {
                return Err(ProgramExecError {
                    kind: ProgramExecErrorKind::InvalidBinary,
                    detail: ProgramExecErrorDetail::LinuxImageInvalid(
                        crate::LinuxImageRefusal::Malformed,
                    ),
                });
            }
            Image::parse_interpreter(&interp_bytes, loaded.abi, limit).map_err(image_error)?;
            loaded.interpreter = Some(interp_bytes);
        }
        Ok(loaded)
    }

    /// Validates `image` with an already-loaded optional interpreter image
    /// (used by `prepare_exec_in_container` so filesystem errors preserve
    /// exact Linux `execve` errnos).
    fn load_with_interpreter<CpuImpl: Cpu>(
        cpu: &CpuImpl,
        image: Bytes,
        interpreter: Option<Bytes>,
        exec_path: Option<String>,
    ) -> Result<Self, ProgramExecError> {
        let mut loaded = Self::load(cpu, image)?;
        loaded.path = exec_path;
        if let Some(interp_bytes) = interpreter {
            let native = cpu.native().map_err(native_unavailable)?;
            if !is_linux_elf(&interp_bytes) {
                return Err(ProgramExecError {
                    kind: ProgramExecErrorKind::InvalidBinary,
                    detail: ProgramExecErrorDetail::LinuxImageInvalid(
                        crate::LinuxImageRefusal::Malformed,
                    ),
                });
            }
            Image::parse_interpreter(&interp_bytes, loaded.abi, user_end(native))
                .map_err(image_error)?;
            loaded.interpreter = Some(interp_bytes);
        }
        Ok(loaded)
    }

    fn interpreter_path<CpuImpl: Cpu>(
        &self,
        cpu: &CpuImpl,
    ) -> Result<Option<String>, ProgramExecError> {
        let native = cpu.native().map_err(native_unavailable)?;
        let parsed = Image::parse(&self.image, self.abi, user_end(native)).map_err(image_error)?;
        Ok(parsed.interpreter().map(str::to_owned))
    }
}

/// Resolves and reads an ELF `PT_INTERP` dynamic linker strictly inside
/// `container_fs` under `READ | EXECUTE` mount authority and `creds`
/// (enforcing private-mount `MAY_EXEC` DAC/ACL checks and clamping symlinks
/// and `..` to the container root).
async fn read_interpreter_in_container<StorageImpl: crate::Storage>(
    container_fs: &crate::ContainerFilesystem<StorageImpl>,
    base_dir: &str,
    interp_path: &str,
    creds: &syscall::Credentials,
) -> Result<Bytes, syscall::FsOpError> {
    let (resolved, trailing_slash) = container_fs
        .walk_path_for(base_dir, interp_path, true, creds)
        .await?;
    let meta = resolved.fs().stat(resolved.fs_path()).await?;
    if meta.kind == NodeKind::Symlink {
        return Err(FsError::Loop.into());
    }
    if meta.kind == NodeKind::Directory {
        return Err(FsError::NotPermitted.into());
    }
    if trailing_slash {
        return Err(FsError::NotDirectory.into());
    }
    if meta.kind != NodeKind::File {
        return Err(FsError::NotPermitted.into());
    }
    let contents = resolved.check_exec_and_read(creds).await?;
    Ok(match contents {
        FileContents::Boot(boot) => Bytes::copy_from_slice(boot.as_slice()),
        FileContents::Written(written) => written,
    })
}

pub(super) fn map_fs_op_error_to_program(error: syscall::FsOpError) -> ProgramExecError {
    let fs_err = match error {
        syscall::FsOpError::Fs(err) => err,
        syscall::FsOpError::PermissionDenied => FsError::NotPermitted,
        syscall::FsOpError::NoDevice
        | syscall::FsOpError::NoData
        | syscall::FsOpError::Range
        | syscall::FsOpError::ArgTooBig => FsError::Io,
    };
    ProgramExecError::from_source_read_error(fs_err)
}

fn native_unavailable(reason: NativeUnavailable) -> ProgramExecError {
    ProgramExecError {
        kind: ProgramExecErrorKind::Unavailable,
        detail: ProgramExecErrorDetail::NativeExecutionUnavailable(reason),
    }
}

fn user_end<Native: NativeExecution>(native: &Native) -> u64 {
    native.user_range().end().raw() as u64
}

/// What a Linux process's [`ProcessAuthority`] lets its system calls
/// reach, derived once from the authority its parent granted. Each
/// resource a later system call reaches (files, sockets, clocks,
/// processes, devices) derives its capability here the way the matching
/// WASIX import does, and a missing one is refused with Linux's errno.
/// User and group IDs are values a process reports and take no part here.
struct LinuxGrants {
    terminal_input: Option<TerminalInputCap>,
    terminal_output: Option<TerminalOutputCap>,
    tty_control: Option<TtyControlCap>,
    /// What WASIX's `clock_time_set` derives, for `clock_settime`.
    set_wall_clock: Option<SetWallClockCap>,
    link_source: Option<LinkSourceCap>,
    symlink_create: Option<SymlinkCreateCap>,
    symlink_read: Option<SymlinkReadCap>,
    tcp: Option<TcpCap>,
    udp: Option<UdpCap>,
    privileged_bind: Option<PrivilegedBindCap>,
    multicast: Option<MulticastCap>,
    network_admin: Option<NetworkAdminCap>,
    trace_read: Option<TraceReadCap>,
    diagnostics_control: Option<DiagnosticsControlCap>,
}

impl LinuxGrants {
    fn derive(authority: &ProcessAuthority) -> Self {
        Self {
            terminal_input: authority.derive_terminal_input_cap().ok(),
            terminal_output: authority.derive_terminal_output_cap().ok(),
            tty_control: authority.derive_tty_control_cap().ok(),
            set_wall_clock: authority.derive_set_wall_clock_cap().ok(),
            link_source: authority.derive_link_source_cap().ok(),
            symlink_create: authority.derive_symlink_create_cap().ok(),
            symlink_read: authority.derive_symlink_read_cap().ok(),
            tcp: authority.derive_tcp_cap().ok(),
            udp: authority.derive_udp_cap().ok(),
            privileged_bind: authority.derive_privileged_bind_cap().ok(),
            multicast: authority.derive_multicast_cap().ok(),
            network_admin: authority.derive_network_admin_cap().ok(),
            trace_read: authority.derive_trace_read_cap().ok(),
            diagnostics_control: authority.derive_diagnostics_control_cap().ok(),
        }
    }
}

/// Process-wide terminal state aligned with [`WasixTtyState`]: whether each
/// standard stream is attached to a terminal, plus the active `termios` and
/// window size.
#[derive(Clone)]
struct LinuxTtyState {
    stdin_tty: bool,
    stdout_tty: bool,
    stderr_tty: bool,
    termios: Termios,
    winsize: Winsize,
    controlling_pty: Option<helios_unix::PtySlave>,
}

impl LinuxTtyState {
    fn new(
        authority: &ProcessAuthority,
        output_mode: &OutputMode,
        instance_id: crate::InstanceId,
    ) -> Self {
        let rights = authority.terminal_rights();
        let stdin_tty = matches!(
            output_mode.stdin_route(),
            crate::ComponentInputRoute::Serial
        ) && rights.contains(TerminalAuthorityRights::INPUT);
        let stdout_tty = matches!(
            output_mode.sink(crate::ComponentOutputStreamKind::Stdout, instance_id),
            crate::ComponentOutputSink::Local(crate::LocalOutputSink::Serial)
        ) && rights.contains(TerminalAuthorityRights::OUTPUT);
        let stderr_tty = matches!(
            output_mode.sink(crate::ComponentOutputStreamKind::Stderr, instance_id),
            crate::ComponentOutputSink::Local(crate::LocalOutputSink::Serial)
        ) && rights.contains(TerminalAuthorityRights::OUTPUT);
        Self {
            stdin_tty,
            stdout_tty,
            stderr_tty,
            termios: Termios::from_flags(stdin_tty, stdin_tty, true),
            winsize: Winsize::DEFAULT,
            controlling_pty: None,
        }
    }

    fn is_tty(&self, stream: TtyStream) -> bool {
        match stream {
            TtyStream::Stdin => self.stdin_tty,
            TtyStream::Stdout => self.stdout_tty,
            TtyStream::Stderr => self.stderr_tty,
        }
    }
}

fn image_error(error: elf::Error) -> ProgramExecError {
    let refusal = match error {
        elf::Error::Parse(_) => crate::LinuxImageRefusal::Malformed,
        elf::Error::UnsupportedImage => crate::LinuxImageRefusal::Unsupported,
        elf::Error::InvalidInterpreter => crate::LinuxImageRefusal::Interpreter,
        elf::Error::InvalidSegment | elf::Error::Overlap => crate::LinuxImageRefusal::Segment,
        elf::Error::InvalidEntry => crate::LinuxImageRefusal::Entry,
    };
    ProgramExecError {
        kind: ProgramExecErrorKind::InvalidBinary,
        detail: ProgramExecErrorDetail::LinuxImageInvalid(refusal),
    }
}

fn native_error(error: NativeError) -> ProgramExecError {
    match error {
        NativeError::OutOfMemory => ProgramExecError {
            kind: ProgramExecErrorKind::OutOfMemory,
            detail: ProgramExecErrorDetail::NativeMemoryExhausted,
        },
        // The image was validated and the stack built inside the user
        // range, so any other refusal is a kernel defect.
        error => panic!("mapping a validated Linux image was refused: {error}"),
    }
}

/// The objects a Linux process's descriptors share with WASIX programs.
pub(super) struct LinuxResources<Net>(core::marker::PhantomData<fn() -> Net>);

impl<Net: ComponentHostNetwork> Resources for LinuxResources<Net> {
    type File = FsDescriptor;
    type Network = crate::UnixNetwork<Net>;
    type Data = EpollUserData;
}

/// A Linux interest's 64-bit `epoll_data` rides in the WASIX record's
/// 64-bit field; the rest of the record is a WASIX program's own.
impl EpollData for EpollUserData {
    fn from_linux(data: u64) -> Self {
        Self {
            ptr: 0,
            fd: 0,
            data1: 0,
            data2: data,
        }
    }
    fn to_linux(&self) -> u64 {
        self.data2
    }
}

/// One active `MAP_SHARED` mapping bound to a [`crate::SharedPageObject`] inside
/// a Linux process, cloned across `fork(2)` so parent and child share the exact
/// same underlying physical frames even for lazily committed pages.
#[derive(Clone)]
struct SharedVma {
    start: u64,
    len: u64,
    object_id: u64,
    object: crate::SharedPageObject,
    object_offset: u64,
    file_key: Option<(u64, u64)>,
}

impl SharedVma {
    fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }
}

/// Process-local table of [`crate::SharedPageObject`]s and active shared VMAs.
#[derive(Clone)]
struct SharedMemoryTable {
    next_id: u64,
    objects: alloc::collections::BTreeMap<u64, (crate::SharedPageObject, Option<(u64, u64)>)>,
    vmas: Vec<SharedVma>,
}

impl SharedMemoryTable {
    fn new() -> Self {
        Self {
            next_id: 1,
            objects: alloc::collections::BTreeMap::new(),
            vmas: Vec::new(),
        }
    }

    fn insert_object(
        &mut self,
        object: crate::SharedPageObject,
        file_key: Option<(u64, u64)>,
    ) -> u64 {
        if let Some(key) = file_key {
            for (&id, (_, existing_key)) in &self.objects {
                if *existing_key == Some(key) {
                    return id;
                }
            }
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.objects.insert(id, (object, file_key));
        id
    }

    fn get_object(&self, id: u64) -> Option<crate::SharedPageObject> {
        self.objects.get(&id).map(|(obj, _)| obj.clone())
    }

    fn get_entry(&self, id: u64) -> Option<(crate::SharedPageObject, Option<(u64, u64)>)> {
        self.objects.get(&id).map(|(obj, key)| (obj.clone(), *key))
    }

    fn remove_vma_range(&mut self, start: u64, end: u64) {
        let mut next = Vec::with_capacity(self.vmas.len());
        for vma in self.vmas.drain(..) {
            let v_end = vma.end();
            if v_end <= start || vma.start >= end {
                next.push(vma);
                continue;
            }
            if vma.start < start {
                next.push(SharedVma {
                    start: vma.start,
                    len: start - vma.start,
                    object_id: vma.object_id,
                    object: vma.object.clone(),
                    object_offset: vma.object_offset,
                    file_key: vma.file_key,
                });
            }
            if v_end > end {
                let delta = end - vma.start;
                next.push(SharedVma {
                    start: end,
                    len: v_end - end,
                    object_id: vma.object_id,
                    object: vma.object,
                    object_offset: vma.object_offset.saturating_add(delta),
                    file_key: vma.file_key,
                });
            }
        }
        self.vmas = next;
    }

    fn remap_vma_range(&mut self, from: u64, old_len: u64, to: u64, new_len: u64) {
        let from_end = from.saturating_add(old_len);
        let mut next = Vec::with_capacity(self.vmas.len() + 2);
        for vma in self.vmas.drain(..) {
            let v_end = vma.end();
            if v_end <= from || vma.start >= from_end {
                next.push(vma);
                continue;
            }
            if vma.start < from {
                next.push(SharedVma {
                    start: vma.start,
                    len: from - vma.start,
                    object_id: vma.object_id,
                    object: vma.object.clone(),
                    object_offset: vma.object_offset,
                    file_key: vma.file_key,
                });
            }
            let ov_start = vma.start.max(from);
            let ov_end = v_end.min(from_end);
            let mut moved_len = ov_end - ov_start;
            if ov_end == from_end && new_len > old_len {
                moved_len = moved_len.saturating_add(new_len - old_len);
            }
            next.push(SharedVma {
                start: to + (ov_start - from),
                len: moved_len,
                object_id: vma.object_id,
                object: vma.object.clone(),
                object_offset: vma.object_offset.saturating_add(ov_start - vma.start),
                file_key: vma.file_key,
            });
            if v_end > from_end {
                next.push(SharedVma {
                    start: from_end,
                    len: v_end - from_end,
                    object_id: vma.object_id,
                    object: vma.object,
                    object_offset: vma.object_offset.saturating_add(from_end - vma.start),
                    file_key: vma.file_key,
                });
            }
        }
        self.vmas = next;
    }

    /// Returns `(vma_page_start, vma_page_end)` ranges belonging to `file_key`
    /// whose file offset lies at or beyond `eof_page` so the caller can discard
    /// their hardware PTEs after `ftruncate`.
    fn pages_beyond_eof(&self, file_key: (u64, u64), eof_page: u64) -> Vec<(u64, u64)> {
        let mut ranges = Vec::new();
        for vma in &self.vmas {
            if vma.file_key != Some(file_key) {
                continue;
            }
            let map_file_end = vma.object_offset.saturating_add(vma.len);
            if map_file_end <= eof_page {
                continue;
            }
            let trim_start_off = eof_page.max(vma.object_offset);
            let addr_start = vma.start + (trim_start_off - vma.object_offset);
            let addr_end = vma.end();
            if addr_start < addr_end {
                ranges.push((addr_start, addr_end));
            }
        }
        ranges
    }
}

/// A process's address space as the system-call decoder sees it.
struct LinuxMemory<'a, Space> {
    space: &'a Space,
    /// The platform's user range, whose start is the lowest mappable
    /// address.
    user: VirtRange,
    /// Initial-stack growth region (`VM_GROWSDOWN`, bounded by `RLIMIT_STACK`
    /// and the highest ELF segment), so kernel writes such as signal frames
    /// (`setup_signal_frame`) or syscall outputs into a fresh stack page
    /// expand the initial stack on demand just as Linux `copy_to_user` does.
    stack_growth: Option<VirtRange>,
    /// Process-wide table of shared memory objects and `MAP_SHARED` VMAs.
    shared_mem: Option<&'a spin::Mutex<SharedMemoryTable>>,
    /// Container-wide cache of file-backed `SharedPageObject`s.
    shared_files: Option<&'a crate::linux_container::SharedFileCache>,
}

impl<Space: UserSpace> LinuxMemory<'_, Space> {
    /// Ensures any `MAP_SHARED` page overlapping `[address, address + length)`
    /// has its [`crate::SharedPageObject`] frame attached in `self.space`
    /// before a kernel read, write, or atomic operation touches it.
    fn ensure_shared_attached(&self, address: u64, length: usize, allocate: bool) {
        let Some(shared_mem) = self.shared_mem else {
            return;
        };
        if length == 0 {
            return;
        }
        let Some(end) = address.checked_add(length as u64) else {
            return;
        };
        let page_size = PhysFrame::SIZE as u64;
        let first_page = address & !(page_size - 1);
        let last_page = end.next_multiple_of(page_size);
        let hits: Vec<(u64, u64, crate::SharedPageObject, u64)> = {
            let guard = shared_mem.lock();
            guard
                .vmas
                .iter()
                .filter_map(|vma| {
                    let ov_start = vma.start.max(first_page);
                    let ov_end = vma.end().min(last_page);
                    (ov_start < ov_end).then(|| {
                        (
                            ov_start,
                            ov_end,
                            vma.object.clone(),
                            vma.object_offset.saturating_add(ov_start - vma.start),
                        )
                    })
                })
                .collect()
        };
        for (ov_start, ov_end, object, mut obj_off) in hits {
            let mut base = ov_start;
            while base < ov_end {
                let page_idx = obj_off / page_size;
                let frame = if allocate {
                    object.get_or_alloc_frame(page_idx).ok()
                } else {
                    object.get_frame(page_idx)
                };
                if let Some(frame) = frame {
                    let _ = self
                        .space
                        .attach_shared_frame(VirtAddr::new(base as usize), frame);
                }
                base += page_size;
                obj_off += page_size;
            }
        }
    }

    fn expand_stack_for(&self, address: u64, length: usize) -> bool {
        let Some(growth) = self.stack_growth else {
            return false;
        };
        if length == 0 {
            return false;
        }
        let Ok(start_raw) = usize::try_from(address) else {
            return false;
        };
        let Some(end_raw) = start_raw.checked_add(length) else {
            return false;
        };
        let mut page = VirtAddr::new(start_raw).page_floor().raw();
        let end_page = end_raw.next_multiple_of(PhysFrame::SIZE);
        let mut expanded = false;
        while page < end_page {
            let page_addr = VirtAddr::new(page);
            if growth.contains(page_addr) {
                let range = VirtRange::new(page_addr, PhysFrame::SIZE);
                match self
                    .space
                    .map(range, &[], PageFlags::READ | PageFlags::WRITE)
                {
                    Ok(()) => expanded = true,
                    Err(NativeError::Overlap) => {}
                    Err(_) => return false,
                }
            }
            page += PhysFrame::SIZE;
        }
        expanded
    }
}

impl<Space: UserSpace> UserMemory for LinuxMemory<'_, Space> {
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        self.ensure_shared_attached(address, output.len(), false);
        self.space
            .read(VirtAddr::new(address as usize), output)
            .map_err(|_| MemoryFault)
    }

    fn read_unrestricted(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        self.ensure_shared_attached(address, output.len(), false);
        self.space
            .read_unrestricted(VirtAddr::new(address as usize), output)
            .map_err(|_| MemoryFault)
    }

    fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
        match self
            .space
            .check_writable(VirtAddr::new(address as usize), length)
        {
            Ok(()) => Ok(()),
            Err(NativeError::NotMapped) if self.expand_stack_for(address, length) => self
                .space
                .check_writable(VirtAddr::new(address as usize), length)
                .map_err(|_| MemoryFault),
            Err(_) => Err(MemoryFault),
        }
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
        self.ensure_shared_attached(address, bytes.len(), true);
        match self.space.write(VirtAddr::new(address as usize), bytes) {
            Ok(()) => Ok(()),
            Err(NativeError::NotMapped) if self.expand_stack_for(address, bytes.len()) => self
                .space
                .write(VirtAddr::new(address as usize), bytes)
                .map_err(|_| MemoryFault),
            Err(_) => Err(MemoryFault),
        }
    }

    fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
        self.ensure_shared_attached(address, 4, false);
        self.space
            .atomic_load_u32(VirtAddr::new(address as usize))
            .map_err(|_| MemoryFault)
    }

    fn atomic_store_u32(&mut self, address: u64, value: u32) -> Result<(), MemoryFault> {
        self.ensure_shared_attached(address, 4, true);
        self.space
            .atomic_store_u32(VirtAddr::new(address as usize), value)
            .map_err(|_| MemoryFault)
    }

    fn atomic_compare_exchange_u32(
        &mut self,
        address: u64,
        expected: u32,
        desired: u32,
    ) -> Result<Result<u32, u32>, MemoryFault> {
        self.ensure_shared_attached(address, 4, true);
        self.space
            .atomic_compare_exchange_u32(VirtAddr::new(address as usize), expected, desired)
            .map_err(|_| MemoryFault)
    }

    fn is_page_shared(&self, address: u64) -> bool {
        self.space.is_page_shared(VirtAddr::new(address as usize))
    }

    fn collect_shared_dirty(
        &self,
        object_id: u64,
        file_offset: u64,
        valid_len: u64,
    ) -> Option<Vec<(u64, Vec<u8>)>> {
        let object = self.shared_mem?.lock().get_object(object_id)?;
        Some(object.collect_dirty_runs(file_offset, valid_len))
    }

    fn mark_shared_clean(&self, object_id: u64, file_offset: u64, bytes: &[u8]) {
        if let Some(shared_mem) = self.shared_mem
            && let Some(object) = shared_mem.lock().get_object(object_id)
        {
            object.mark_clean(file_offset, bytes);
        }
    }
}

fn page_range(address: u64, length: u64) -> VirtRange {
    VirtRange::new(VirtAddr::new(address as usize), length as usize)
}

/// A refusal of a memory-map call the decoder already validated. Only the
/// address space's own limits reach the process; anything else means the
/// decoder and the space disagree on a range, a kernel defect.
fn map_error(error: NativeError) -> MapError {
    match error {
        NativeError::OutOfMemory => MapError::OutOfMemory,
        NativeError::Address => MapError::Address,
        NativeError::Overlap => MapError::Occupied,
        error @ (NativeError::NotMapped | NativeError::BackingFault | NativeError::Register) => {
            panic!("a validated Linux memory-map call was refused: {error}")
        }
    }
}

impl<Space: UserSpace> VirtualMemory for LinuxMemory<'_, Space> {
    fn lowest_address(&self) -> u64 {
        self.user.start.raw() as u64
    }

    fn map_anywhere(&mut self, hint: u64, length: u64, access: PageFlags) -> Result<u64, MapError> {
        self.space
            .map_anywhere(VirtAddr::new(hint as usize), length as usize, access)
            .map(|range| range.start.raw() as u64)
            .map_err(map_error)
    }

    fn map_at(&mut self, address: u64, length: u64, access: PageFlags) -> Result<(), MapError> {
        self.space
            .map(page_range(address, length), &[], access)
            .map_err(map_error)
    }

    fn unmap(&mut self, address: u64, length: u64) {
        self.space
            .unmap(page_range(address, length))
            .unwrap_or_else(|error| panic!("unmapping a validated Linux range: {error}"));
    }

    fn protect(&mut self, address: u64, length: u64, access: PageFlags) -> Result<(), MapError> {
        self.space
            .protect(page_range(address, length), access)
            .map_err(map_error)
    }

    fn discard(&mut self, address: u64, length: u64) {
        self.space
            .discard(page_range(address, length))
            .unwrap_or_else(|error| panic!("discarding a validated Linux range: {error}"));
    }

    fn remap(&mut self, from: u64, length: u64, to: u64, new_length: u64) -> Result<(), MapError> {
        self.space
            .remap(page_range(from, length), page_range(to, new_length))
            .map_err(map_error)
    }

    fn region(&self, start: u64, end: u64) -> Option<Region> {
        if start >= end {
            return None;
        }
        self.space
            .mapping(page_range(start, end - start))
            .map(|mapping| Region {
                start: mapping.range.start.raw() as u64,
                end: mapping.range.end().raw() as u64,
                access: mapping.flags,
            })
    }

    fn free_range(&self, hint: u64, length: u64) -> Option<u64> {
        self.space
            .free_range(VirtAddr::new(hint as usize), length as usize)
            .map(|start| start.raw() as u64)
    }

    fn populate(&mut self, address: u64, bytes: &[u8]) -> Result<(), MapError> {
        self.ensure_shared_attached(address, bytes.len(), true);
        match self.space.populate(VirtAddr::new(address as usize), bytes) {
            Ok(()) => Ok(()),
            Err(NativeError::OutOfMemory) => Err(MapError::OutOfMemory),
            Err(NativeError::Address | NativeError::NotMapped | NativeError::BackingFault) => {
                Err(MapError::Address)
            }
            Err(error @ (NativeError::Overlap | NativeError::Register)) => {
                panic!("populating a validated Linux mapping was refused: {error}")
            }
        }
    }

    fn create_shared_anonymous(&mut self) -> u64 {
        let Some(shared_mem) = self.shared_mem else {
            return 0;
        };
        shared_mem
            .lock()
            .insert_object(crate::SharedPageObject::new_anonymous(), None)
    }

    fn acquire_shared_file(&mut self, dev: u64, ino: u64) -> u64 {
        let Some(shared_mem) = self.shared_mem else {
            return 0;
        };
        let object = match self.shared_files {
            Some(cache) => cache.get_or_create(dev, ino),
            None => crate::SharedPageObject::new_file_backed(),
        };
        shared_mem.lock().insert_object(object, Some((dev, ino)))
    }

    fn load_shared_page(
        &mut self,
        object_id: u64,
        page_index: u64,
        bytes: &[u8],
    ) -> Result<(), MapError> {
        let Some(shared_mem) = self.shared_mem else {
            return Ok(());
        };
        let Some(object) = shared_mem.lock().get_object(object_id) else {
            return Err(MapError::Address);
        };
        object
            .load_file_page(page_index, bytes)
            .map(|_| ())
            .map_err(map_error)
    }

    fn release_shared_object(&mut self, object_id: u64) {
        if let Some(shared_mem) = self.shared_mem {
            shared_mem.lock().objects.remove(&object_id);
        }
    }

    fn map_shared_at(
        &mut self,
        address: u64,
        length: u64,
        access: PageFlags,
        object_id: u64,
        object_offset: u64,
        attach_len: u64,
    ) -> Result<(), MapError> {
        let Some(shared_mem) = self.shared_mem else {
            return self.map_at(address, length, access);
        };
        self.space
            .map_region(page_range(address, length), access, RegionKind::Shared)
            .map_err(map_error)?;
        let entry = shared_mem.lock().get_entry(object_id);
        if let Some((object, file_key)) = entry {
            if let Err(err) =
                self.attach_object_range(address, &object, object_offset, attach_len.min(length))
            {
                let _ = self.space.unmap(page_range(address, length));
                return Err(err);
            }
            shared_mem.lock().vmas.push(SharedVma {
                start: address,
                len: length,
                object_id,
                object,
                object_offset,
                file_key,
            });
        }
        Ok(())
    }

    fn map_shared_anywhere(
        &mut self,
        hint: u64,
        length: u64,
        access: PageFlags,
        object_id: u64,
        object_offset: u64,
        attach_len: u64,
    ) -> Result<u64, MapError> {
        let Some(shared_mem) = self.shared_mem else {
            return self.map_anywhere(hint, length, access);
        };
        let range = self
            .space
            .map_region_anywhere(
                VirtAddr::new(hint as usize),
                length as usize,
                access,
                RegionKind::Shared,
            )
            .map_err(map_error)?;
        let address = range.start.raw() as u64;
        let entry = shared_mem.lock().get_entry(object_id);
        if let Some((object, file_key)) = entry {
            if let Err(err) =
                self.attach_object_range(address, &object, object_offset, attach_len.min(length))
            {
                let _ = self.space.unmap(range);
                return Err(err);
            }
            shared_mem.lock().vmas.push(SharedVma {
                start: address,
                len: length,
                object_id,
                object,
                object_offset,
                file_key,
            });
        }
        Ok(address)
    }

    fn map_private_file_at(
        &mut self,
        address: u64,
        length: u64,
        access: PageFlags,
        stage_id: u64,
        staged_len: u64,
    ) -> Result<(), MapError> {
        self.space
            .map_region(page_range(address, length), access, RegionKind::PrivateFile)
            .map_err(map_error)?;
        if stage_id != 0
            && staged_len > 0
            && let Err(err) = self.install_staged_private(address, stage_id)
        {
            let _ = self.space.unmap(page_range(address, length));
            return Err(err);
        }
        Ok(())
    }

    fn map_private_file_anywhere(
        &mut self,
        hint: u64,
        length: u64,
        access: PageFlags,
        stage_id: u64,
        staged_len: u64,
    ) -> Result<u64, MapError> {
        let range = self
            .space
            .map_region_anywhere(
                VirtAddr::new(hint as usize),
                length as usize,
                access,
                RegionKind::PrivateFile,
            )
            .map_err(map_error)?;
        let address = range.start.raw() as u64;
        if stage_id != 0
            && staged_len > 0
            && let Err(err) = self.install_staged_private(address, stage_id)
        {
            let _ = self.space.unmap(range);
            return Err(err);
        }
        Ok(address)
    }

    fn apply_shared_file_write(&mut self, object_id: u64, file_offset: u64, bytes: &[u8]) -> bool {
        let Some(shared_mem) = self.shared_mem else {
            return false;
        };
        let Some(object) = shared_mem.lock().get_object(object_id) else {
            return false;
        };
        object.apply_file_write(file_offset, bytes);
        true
    }

    fn unmap_shared_vma(&mut self, start: u64, end: u64) {
        if let Some(shared_mem) = self.shared_mem {
            shared_mem.lock().remove_vma_range(start, end);
        }
    }

    fn remap_shared_vma(&mut self, from: u64, old_len: u64, to: u64, new_len: u64) {
        if let Some(shared_mem) = self.shared_mem {
            shared_mem
                .lock()
                .remap_vma_range(from, old_len, to, new_len);
        }
    }

    fn attach_shared_tail(
        &mut self,
        address: u64,
        object_id: u64,
        object_offset: u64,
        attach_len: u64,
    ) -> Result<(), MapError> {
        let Some(shared_mem) = self.shared_mem else {
            return Ok(());
        };
        let Some(object) = shared_mem.lock().get_object(object_id) else {
            return Ok(());
        };
        self.attach_object_range(address, &object, object_offset, attach_len)
    }
}

impl<Space: UserSpace> LinuxMemory<'_, Space> {
    fn attach_object_range(
        &self,
        address: u64,
        object: &crate::SharedPageObject,
        object_offset: u64,
        attach_len: u64,
    ) -> Result<(), MapError> {
        let page_size = PhysFrame::SIZE as u64;
        let pages = attach_len.div_ceil(page_size);
        for index in 0..pages {
            let page_idx = (object_offset / page_size) + index;
            if let Some(frame) = object.get_frame(page_idx) {
                let va = VirtAddr::new((address + index * page_size) as usize);
                self.space
                    .attach_shared_frame(va, frame)
                    .map_err(map_error)?;
            }
        }
        Ok(())
    }

    fn install_staged_private(&self, address: u64, stage_id: u64) -> Result<(), MapError> {
        let Some(shared_mem) = self.shared_mem else {
            return Ok(());
        };
        let Some((stage_obj, _)) = shared_mem.lock().objects.remove(&stage_id) else {
            return Ok(());
        };
        let page_size = PhysFrame::SIZE as u64;
        for (rel_idx, frame) in stage_obj.drain_unique_frames() {
            let va = VirtAddr::new((address + rel_idx * page_size) as usize);
            self.space
                .install_private_frame(va, frame)
                .map_err(map_error)?;
        }
        Ok(())
    }
}

/// Wasm/WASIX execution handles forwarded from the program service so a Linux
/// process can `execve`/`execveat` into a Wasm module or component.
pub(super) struct LinuxWasmRuntime<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    pub(super) filesystem: Option<Namespace<StorageImpl>>,
    pub(super) progress: helios_hal::watchdog::ProgressCounter,
    pub(super) engine: crate::wasmtime_adapter::WasmtimeEngine,
    pub(super) runtime: crate::wasmtime_adapter::WasmtimeComponentRuntime<CpuImpl>,
    pub(super) preview1_core_linker: CoreLinker<Preview1ProgramStore<CpuImpl, Net, StorageImpl>>,
    pub(super) shared_memory_pool: Arc<Mutex<SharedMemoryPool>>,
    pub(super) core_module_instance_pre_cache:
        CoreModuleInstancePreCache<CpuImpl, Net, StorageImpl>,
}

impl<CpuImpl, Net, StorageImpl> Clone for LinuxWasmRuntime<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn clone(&self) -> Self {
        Self {
            filesystem: self.filesystem.clone(),
            progress: self.progress.clone(),
            engine: self.engine.clone(),
            runtime: self.runtime.clone(),
            preview1_core_linker: self.preview1_core_linker.clone(),
            shared_memory_pool: self.shared_memory_pool.clone(),
            core_module_instance_pre_cache: self.core_module_instance_pre_cache.clone(),
        }
    }
}

/// Runtime handles forwarded from the program service into a Linux process so
/// `fork` can register child instances and `execve`/`execveat` can replace the
/// image with either a Linux ELF or a Wasm/WASIX program.
pub(super) struct LinuxExecRuntime<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    pub(super) exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
    pub(super) wasm: Option<LinuxWasmRuntime<CpuImpl, Net, StorageImpl>>,
}

impl<CpuImpl, Net, StorageImpl> Clone for LinuxExecRuntime<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn clone(&self) -> Self {
        Self {
            exec_context: self.exec_context.clone(),
            wasm: self.wasm.clone(),
        }
    }
}

/// Validated replacement image prepared by `ContextThread::prepare_exec`
/// before committing the point-of-no-return `execve`/`execveat` transition.
enum PreparedExec<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    Linux {
        executable: LinuxExecutable,
        exe_path: String,
        argv: Vec<String>,
        env: Vec<String>,
        credentials: syscall::Credentials,
        secure: bool,
    },
    Wasm {
        executable: ProgramExecutable<CpuImpl, Net, StorageImpl>,
        argv: ProgramArgv,
        env: Vec<(String, String)>,
    },
}

/// A prepared `execve`/`execveat` payload handed from the calling thread to
/// the process lifecycle driver.
type ExecHandoff<CpuImpl, Net, StorageImpl> = (
    Box<PreparedExec<CpuImpl, Net, StorageImpl>>,
    Process<LinuxResources<Net>>,
);

/// Process-wide host state shared across every thread task of one Linux
/// process.
struct LinuxShared<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    cpu: CpuImpl,
    timer: crate::Timer<CpuImpl>,
    spawner: crate::InstanceSpawner<CpuImpl>,
    runtime_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    exec_runtime: LinuxExecRuntime<CpuImpl, Net, StorageImpl>,
    read_serial: crate::SerialReader,
    write_serial: crate::DebugSerialWriter,
    output_mode: OutputMode,
    launched_instance: crate::RegisteredInstance,
    signal_state: WasixSignalState,
    container: Arc<crate::LinuxContainer<StorageImpl>>,
    grants: LinuxGrants,
    pid: NonZeroU32,
    ppid: u32,
    exe_path: String,
    argv: Vec<String>,
    env: Vec<String>,
    cwd_handle: Arc<spin::Mutex<String>>,
    descriptors_handle: Arc<spin::Mutex<Descriptors<LinuxResources<Net>>>>,
    credentials_handle: Arc<spin::Mutex<syscall::Credentials>>,
    proc_signals: Arc<ProcessSignals>,
    /// Process-wide terminal state (`termios`, window size, stream TTY flags).
    /// Never held across `.await`.
    tty: spin::Mutex<LinuxTtyState>,
    /// Bytes drained from the debug serial ring during non-blocking reads or
    /// readiness checks so `poll`/`epoll`/`read(O_NONBLOCK)` never drop input.
    /// Never held across `.await`.
    serial_peek: spin::Mutex<Vec<u8>>,
    /// The process's view of wall time, which `clock_settime` moves as
    /// WASIX's `clock_time_set` moves a program's. Never held across `.await`.
    clock: spin::Mutex<crate::KernelClock<CpuImpl, HostRuntimeState<CpuImpl, Net, StorageImpl>>>,
    abi: Abi,
    registers: abi::SystemCallRegisters,
    user: VirtRange,
    stack_top: u64,
    stack_base: usize,
    image_end: usize,
    /// User-executable `rt_sigreturn` trampoline page on ABIs that supply one
    /// (AArch64), or `0` on ABIs that require `SA_RESTORER` (x86-64).
    sigreturn_trampoline: u64,
    space: Arc<Space>,
    /// Shared memory objects and active `MAP_SHARED` VMA bindings for this
    /// address space (shared on `CLONE_VM`, cloned on `fork` so parent and
    /// child share the underlying `SharedPageObject`s).
    shared_mem: Arc<spin::Mutex<SharedMemoryTable>>,
    /// Summed user-slice ticks across every thread of the process
    /// (`CLOCK_PROCESS_CPUTIME_ID`).
    process_cpu_ticks: AtomicU64,
    /// Summed kernel syscall ticks across every thread of the process
    /// (`times(2)` `tms_stime` and `getrusage(2)` `ru_stime`).
    process_sys_ticks: AtomicU64,
    /// High-water mark of mapped user address space in KiB (`ru_maxrss`).
    peak_rss_kib: AtomicU64,
    /// Cursor of the last syslog trace event consumed by `SYSLOG_ACTION_READ`.
    syslog_cursor: spin::Mutex<u64>,
    /// Minimum trace timestamp admitted after `SYSLOG_ACTION_CLEAR` /
    /// `SYSLOG_ACTION_READ_CLEAR`.
    syslog_clear_after: AtomicU64,
    /// First host-level failure (user memory exhaustion or instance kill)
    /// observed on any thread of the process.
    fatal_error: spin::Mutex<Option<ProgramExecError>>,
    /// Prepared `execve`/`execveat` handoff submitted by any thread of the
    /// process; first caller wins, condemns sibling threads, and the process
    /// driver commits the replacement once every thread task has drained.
    exec_handoff: spin::Mutex<Option<ExecHandoff<CpuImpl, Net, StorageImpl>>>,
    /// Detached thread tasks still executing or dropping their process/space
    /// handles.
    running_tasks: AtomicUsize,
    tasks_drained: helios_sync::Notify,
}

impl<CpuImpl, Net, StorageImpl, Space> LinuxShared<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    /// Where the initial stack may grow down into: from its initial pages
    /// down as far as the process's current `RLIMIT_STACK` allows, stopping
    /// above the highest ELF segment.
    fn stack_growth(&self, limit: u64) -> VirtRange {
        let lowest = (self.stack_top.saturating_sub(limit) as usize).max(self.image_end);
        VirtRange::new(
            VirtAddr::new(lowest),
            self.stack_base.saturating_sub(lowest),
        )
    }

    fn record_fatal(&self, error: ProgramExecError) {
        let mut slot = self.fatal_error.lock();
        if slot.is_none() {
            *slot = Some(error);
        }
    }

    fn take_fatal(&self) -> Option<ProgramExecError> {
        self.fatal_error.lock().take()
    }

    fn pull_serial_into_peek(&self, max_bytes: usize) -> bool {
        let mut peek = self.serial_peek.lock();
        if !peek.is_empty() {
            return true;
        }
        let mut scratch = Vec::new();
        (self.read_serial)(
            &mut scratch,
            u32::try_from(max_bytes.max(1)).unwrap_or(u32::MAX),
        );
        if scratch.is_empty() {
            return false;
        }
        peek.extend_from_slice(&scratch);
        true
    }

    fn take_serial_peek(&self, limit: usize) -> Option<Bytes> {
        let mut peek = self.serial_peek.lock();
        if peek.is_empty() {
            let mut scratch = Vec::new();
            (self.read_serial)(&mut scratch, u32::try_from(limit).unwrap_or(u32::MAX));
            if scratch.is_empty() {
                return None;
            }
            peek.extend_from_slice(&scratch);
        }
        let take = peek.len().min(limit);
        let bytes = Bytes::copy_from_slice(&peek[..take]);
        peek.drain(..take);
        Some(bytes)
    }

    async fn wait_tasks_drained(&self) {
        loop {
            let mut waiter = self.tasks_drained.waiter();
            if self.running_tasks.load(Ordering::SeqCst) == 0 {
                return;
            }
            core::future::poll_fn(|cx| self.tasks_drained.poll_notified(cx, &mut waiter)).await;
        }
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> LinuxShared<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn current_rss_kib(&self) -> u64 {
        let mut cursor = self.user.start.raw() as u64;
        let end = self.user.end().raw() as u64;
        let mut bytes = 0u64;
        while cursor < end {
            let range = page_range(cursor, end - cursor);
            let Some(mapping) = self.space.mapping(range) else {
                break;
            };
            bytes = bytes.saturating_add(mapping.range.byte_len as u64);
            let next = mapping.range.end().raw() as u64;
            if next <= cursor {
                break;
            }
            cursor = next;
        }
        let kib = bytes.div_ceil(1024);
        self.peak_rss_kib.fetch_max(kib, Ordering::Relaxed).max(kib)
    }

    fn snapshot_usage(&self) -> syscall::CpuUsage {
        let tb = self.cpu.timebase();
        syscall::CpuUsage {
            user_nanos: tb.ticks_to_nanos(self.process_cpu_ticks.load(Ordering::Relaxed)),
            sys_nanos: tb.ticks_to_nanos(self.process_sys_ticks.load(Ordering::Relaxed)),
            max_rss_kib: self.current_rss_kib(),
        }
    }
}

/// Decrements [`LinuxShared::running_tasks`] after a spawned thread task has
/// finished [`drive_linux_thread`] and dropped its `Process`, `UserContext`
/// and `LinuxThreadPlatform`.
struct TaskDrainGuard<CpuImpl, Net, StorageImpl, Space>(
    Arc<LinuxShared<CpuImpl, Net, StorageImpl, Space>>,
)
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage;

impl<CpuImpl, Net, StorageImpl, Space> Drop for TaskDrainGuard<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn drop(&mut self) {
        if self.0.running_tasks.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.tasks_drained.notify_all();
        }
    }
}

/// Per-thread host state: per-thread DRBG stream and per-thread slice tick
/// counter (`CLOCK_THREAD_CPUTIME_ID`).
struct LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    shared: Arc<LinuxShared<CpuImpl, Net, StorageImpl, Space>>,
    tid: NonZeroU32,
    entropy: crate::EntropyPool,
    thread_cpu_ticks: u64,
    thread_sys_ticks: u64,
}

impl<CpuImpl, Net, StorageImpl, Space> LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn new(shared: Arc<LinuxShared<CpuImpl, Net, StorageImpl, Space>>, tid: NonZeroU32) -> Self {
        let personalization = shared.launched_instance.id().raw() ^ (u64::from(tid.get()) << 32);
        let entropy =
            crate::EntropyPool::derive(shared.runtime_state.root_entropy(), personalization);
        Self {
            shared,
            tid,
            entropy,
            thread_cpu_ticks: 0,
            thread_sys_ticks: 0,
        }
    }

    fn caller(&self) -> crate::ProcCaller {
        crate::ProcCaller {
            pid: self.shared.pid.get(),
            tid: self.tid.get(),
        }
    }

    async fn refresh_proc_if_needed(&self, base_dir: &str, path: &str) {
        let touches_pseudo = path.starts_with("/proc")
            || path.starts_with("/sys")
            || path.starts_with("/dev")
            || base_dir.starts_with("/proc")
            || base_dir.starts_with("/sys");
        if !touches_pseudo {
            return;
        }
        let registry = self.shared.container.proc_registry();
        registry.set_cpu_count(crate::online_processor_count().max(1) as u32);
        registry.set_uptime_nanos(
            self.shared
                .runtime_state
                .uptime_nanos(self.shared.cpu.now().ticks()),
        );

        let pid = self.shared.pid.get();
        let cwd = self.shared.cwd_handle.lock().clone();
        let creds = self.shared.credentials_handle.lock().clone();
        let pgid = self.shared.proc_signals.pgid();
        let fds = snapshot_process_fds(&self.shared.descriptors_handle.lock());
        let ticks_ns = self
            .shared
            .cpu
            .timebase()
            .ticks_to_nanos(self.shared.process_cpu_ticks.load(Ordering::Relaxed));
        let utime_ticks = ticks_ns / 10_000_000;
        registry.update_process(pid, |record| {
            record.cwd = cwd;
            record.credentials = creds;
            record.pgid = pgid;
            record.fds = fds;
            record.utime_ticks = utime_ticks;
        });

        if let Some(service) = self.shared.runtime_state.network_service() {
            let mut snapshot = crate::ContainerNetSnapshot::default();
            if let Ok(mac) = service.mac_address(NetworkPortId::new(0)).await {
                let ipv4 = service
                    .list_addresses(NetworkPortId::new(0))
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|cidr| (cidr.address().octets(), cidr.prefix_len()))
                    .collect();
                snapshot.interfaces.push(crate::NetIfSnapshot {
                    name: String::from("eth0"),
                    ifindex: 2,
                    mac: mac.octets(),
                    mtu: 1500,
                    flags: 0x1043, // IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST
                    operstate: String::from("up"),
                    arp_type: 1, // ARPHRD_ETHER
                    ipv4,
                    rx_bytes: 0,
                    rx_packets: 0,
                    rx_errors: 0,
                    rx_dropped: 0,
                    tx_bytes: 0,
                    tx_packets: 0,
                    tx_errors: 0,
                    tx_dropped: 0,
                });
                if let Ok(routes) = service.list_routes(NetworkPortId::new(0)).await {
                    for route in routes {
                        let prefix = route.destination().prefix_len();
                        let mask = if prefix == 0 {
                            [0; 4]
                        } else {
                            (!0u32 << (32 - prefix.min(32))).to_be_bytes()
                        };
                        let gw = route.gateway().octets();
                        let mut flags = 0x0001u16; // RTF_UP
                        if gw != [0, 0, 0, 0] {
                            flags |= 0x0002; // RTF_GATEWAY
                        }
                        snapshot.routes.push(crate::NetRouteSnapshot {
                            iface: String::from("eth0"),
                            destination: route.destination().address().octets(),
                            gateway: gw,
                            mask,
                            flags,
                            metric: 0,
                            mtu: 1500,
                        });
                    }
                }
            }
            registry.set_net_snapshot(snapshot);
        }
    }

    fn recent_syslog_events(&self) -> Vec<triomphe::Arc<crate::TraceEvent>> {
        let filter = crate::TraceFilter {
            min_level: None,
            target_prefixes: crate::PrefixSet::from_prefixes(core::iter::empty())
                .expect("empty prefix set fits"),
        };
        if self.shared.grants.diagnostics_control.is_some() {
            return self
                .shared
                .runtime_state
                .recent(&crate::MachineObservation, &filter, 256);
        }
        let Some(cap) = self.shared.grants.trace_read.as_ref() else {
            return Vec::new();
        };
        match cap.scope() {
            crate::AuthorityScope::Own => self.shared.runtime_state.recent(
                &crate::OwnInstance::new(self.shared.launched_instance.id()),
                &filter,
                256,
            ),
            crate::AuthorityScope::Subtree(root) => self.shared.runtime_state.recent(
                &crate::SubtreeObservation::new(
                    root,
                    self.shared
                        .exec_runtime
                        .exec_context
                        .instance_registry
                        .clone(),
                ),
                &filter,
                256,
            ),
            crate::AuthorityScope::Machine => {
                self.shared
                    .runtime_state
                    .recent(&crate::MachineObservation, &filter, 256)
            }
        }
    }

    fn format_syslog_events(&self, min_ts: u64, max_len: usize) -> (Vec<u8>, Option<u64>) {
        use core::fmt::Write as _;
        let events = self.recent_syslog_events();
        let mut out = String::new();
        let mut last_ts = None;
        for event in events {
            if event.timestamp <= min_ts {
                continue;
            }
            let level = match event.level {
                crate::TraceLevel::Error => 3,
                crate::TraceLevel::Warn => 4,
                crate::TraceLevel::Info => 6,
                crate::TraceLevel::Debug | crate::TraceLevel::Trace => 7,
            };
            let secs = event.timestamp / 1_000_000_000;
            let usecs = (event.timestamp % 1_000_000_000) / 1_000;
            let mut line = String::new();
            let _ = write!(line, "<{level}>[{secs:5}.{usecs:06}] {}:", event.target);
            for field in &event.fields {
                let _ = match &field.value {
                    crate::TraceValue::Boolean(v) => write!(line, " {}={v}", field.key),
                    crate::TraceValue::Signed64(v) => write!(line, " {}={v}", field.key),
                    crate::TraceValue::Unsigned64(v) => write!(line, " {}={v}", field.key),
                    crate::TraceValue::Float64(v) => write!(line, " {}={v}", field.key),
                    crate::TraceValue::Text(v) => write!(line, " {}={v}", field.key),
                    crate::TraceValue::Blob(v) => write!(line, " {}=<{}B>", field.key, v.len()),
                };
            }
            line.push('\n');
            if out.len().saturating_add(line.len()) > max_len {
                if out.is_empty() && max_len > 0 {
                    let cut = line.floor_char_boundary(max_len);
                    out.push_str(&line[..cut]);
                    last_ts = Some(event.timestamp);
                }
                break;
            }
            out.push_str(&line);
            last_ts = Some(event.timestamp);
        }
        (out.into_bytes(), last_ts)
    }
}

fn process_comm_from_exe(exe: &str) -> String {
    let base = exe.rsplit('/').next().unwrap_or(exe);
    let base = if base.is_empty() { "linux" } else { base };
    base.chars().take(15).collect()
}

fn snapshot_process_fds<Net: ComponentHostNetwork>(
    descriptors: &Descriptors<LinuxResources<Net>>,
) -> Vec<crate::ProcFdEntry> {
    let mut out = Vec::new();
    for (idx, slot) in descriptors.entries.iter().enumerate() {
        let Some(entry) = slot else {
            continue;
        };
        let target = match &entry.descriptor {
            helios_unix::FileDescriptor::Stdin { .. }
            | helios_unix::FileDescriptor::Stdout
            | helios_unix::FileDescriptor::Stderr => String::from("/dev/console"),
            helios_unix::FileDescriptor::File(open) => open.node().path.clone(),
            helios_unix::FileDescriptor::Preopen { descriptor, .. } => descriptor.path.clone(),
            helios_unix::FileDescriptor::PipeRead { inode, .. } => {
                alloc::format!("pipe:[{}]", inode.attrs().ino)
            }
            helios_unix::FileDescriptor::PipeWrite { inode, .. } => {
                alloc::format!("pipe:[{}]", inode.attrs().ino)
            }
            helios_unix::FileDescriptor::FifoRead(r) => {
                alloc::format!("pipe:[{}]", r.inode().attrs().ino)
            }
            helios_unix::FileDescriptor::FifoWrite(w) => {
                alloc::format!("pipe:[{}]", w.inode().attrs().ino)
            }
            helios_unix::FileDescriptor::FifoReadWrite(rw) => {
                alloc::format!("pipe:[{}]", rw.inode().attrs().ino)
            }
            helios_unix::FileDescriptor::PseudoDevice(dev) => String::from(dev.kind.default_path()),
            helios_unix::FileDescriptor::NullDevice => String::from("/dev/null"),
            helios_unix::FileDescriptor::PtyMaster(_) => String::from("/dev/ptmx"),
            helios_unix::FileDescriptor::PtySlave(s) => alloc::format!("/dev/pts/{}", s.index()),
            helios_unix::FileDescriptor::Socket(_) => alloc::format!("socket:[{idx}]"),
            helios_unix::FileDescriptor::Event(_) => String::from("anon_inode:[eventfd]"),
            helios_unix::FileDescriptor::Epoll(_) => String::from("anon_inode:[eventpoll]"),
        };
        let pos = match &entry.descriptor {
            helios_unix::FileDescriptor::File(open) => {
                open.try_lock_position().map_or(0, |p| p.get())
            }
            _ => 0,
        };
        out.push(crate::ProcFdEntry {
            fd: idx as i32,
            target,
            pos,
            flags: u32::from(entry.fdflags()),
            mnt_id: 1,
        });
    }
    out
}

struct ProcProcessGuard {
    registry: crate::ProcRegistry,
    pid: u32,
}

impl Drop for ProcProcessGuard {
    fn drop(&mut self) {
        self.registry.unregister_process(self.pid);
    }
}

struct ProcThreadGuard {
    registry: crate::ProcRegistry,
    pid: u32,
    tid: u32,
}

impl Drop for ProcThreadGuard {
    fn drop(&mut self) {
        self.registry.unregister_thread(self.pid, self.tid);
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> Stdio
    for LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn write(&mut self, stream: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        let kind = match stream {
            Stream::Stdout => crate::ComponentOutputStreamKind::Stdout,
            Stream::Stderr => crate::ComponentOutputStreamKind::Stderr,
        };
        let writer = match self
            .shared
            .output_mode
            .sink(kind, self.shared.launched_instance.id())
        {
            // The terminal is the one destination the stream reaches on
            // the process's own authority; a channel or a log belongs to
            // whoever routed the stream there.
            crate::ComponentOutputSink::Local(crate::LocalOutputSink::Serial)
                if self.shared.grants.terminal_output.is_none() =>
            {
                return Err(WriteError::Denied);
            }
            crate::ComponentOutputSink::Local(local) => loop {
                // Zero means another processor owns the debug UART now:
                // offer the same bytes again after a yield.
                let taken = local.write(
                    &self.shared.cpu,
                    &self.shared.runtime_state,
                    self.shared.write_serial,
                    bytes,
                );
                if taken != 0 || bytes.is_empty() {
                    return Ok(taken);
                }
                crate::yield_now().await;
            },
            crate::ComponentOutputSink::Child(writer) => writer.clone(),
        };
        match writer.write(Bytes::copy_from_slice(bytes)).await {
            Ok(()) => Ok(bytes.len()),
            Err(crate::ClosedPeer) => Err(WriteError::Io),
        }
    }

    fn try_write(&mut self, stream: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        let kind = match stream {
            Stream::Stdout => crate::ComponentOutputStreamKind::Stdout,
            Stream::Stderr => crate::ComponentOutputStreamKind::Stderr,
        };
        match self
            .shared
            .output_mode
            .sink(kind, self.shared.launched_instance.id())
        {
            crate::ComponentOutputSink::Local(crate::LocalOutputSink::Serial)
                if self.shared.grants.terminal_output.is_none() =>
            {
                Err(WriteError::Denied)
            }
            crate::ComponentOutputSink::Local(local) => {
                let taken = local.write(
                    &self.shared.cpu,
                    &self.shared.runtime_state,
                    self.shared.write_serial,
                    bytes,
                );
                if taken == 0 && !bytes.is_empty() {
                    Err(WriteError::WouldBlock)
                } else {
                    Ok(taken)
                }
            }
            crate::ComponentOutputSink::Child(writer) => {
                match writer.try_write(Bytes::copy_from_slice(bytes)) {
                    TryWrite::Written => Ok(bytes.len()),
                    TryWrite::Closed => Err(WriteError::Io),
                    TryWrite::Full(_) => Err(WriteError::WouldBlock),
                }
            }
        }
    }

    async fn read_input(&mut self, limit: usize) -> Result<Bytes, Denied> {
        Ok(match self.shared.output_mode.stdin_route() {
            crate::ComponentInputRoute::Serial if self.shared.grants.terminal_input.is_none() => {
                return Err(Denied);
            }
            crate::ComponentInputRoute::Serial => loop {
                let wait = self.shared.write_serial.wait_for_debug_serial_input();
                if let Some(bytes) = self.shared.take_serial_peek(limit) {
                    break bytes;
                }
                wait.await;
            },
            crate::ComponentInputRoute::Closed => Bytes::new(),
            crate::ComponentInputRoute::Child(stdin_rx) => {
                stdin_rx.read_limit(limit).await.unwrap_or_default()
            }
        })
    }

    fn try_read_input(&mut self, limit: usize) -> StdinTryRead {
        match self.shared.output_mode.stdin_route() {
            crate::ComponentInputRoute::Serial if self.shared.grants.terminal_input.is_none() => {
                StdinTryRead::Denied
            }
            crate::ComponentInputRoute::Serial => match self.shared.take_serial_peek(limit) {
                Some(bytes) => StdinTryRead::Ready(bytes),
                None => StdinTryRead::WouldBlock,
            },
            crate::ComponentInputRoute::Closed => StdinTryRead::Eof,
            crate::ComponentInputRoute::Child(stdin_rx) => match stdin_rx.try_read_limit(limit) {
                TryRead::Ready(bytes) => StdinTryRead::Ready(bytes),
                TryRead::Eof => StdinTryRead::Eof,
                TryRead::Pending => StdinTryRead::WouldBlock,
            },
        }
    }

    fn stdin_ready_mask(&self) -> u32 {
        match self.shared.output_mode.stdin_route() {
            crate::ComponentInputRoute::Serial if self.shared.grants.terminal_input.is_none() => {
                READY_ERR
            }
            crate::ComponentInputRoute::Serial => {
                if self.shared.pull_serial_into_peek(4096) {
                    READY_IN
                } else {
                    0
                }
            }
            crate::ComponentInputRoute::Closed => READY_IN | READY_HUP,
            crate::ComponentInputRoute::Child(stdin_rx) => {
                (if stdin_rx.has_buffered_data() {
                    READY_IN
                } else {
                    0
                }) | (if stdin_rx.is_writer_closed() {
                    READY_HUP
                } else {
                    0
                })
            }
        }
    }

    async fn wait_stdin_ready(&self) {
        match self.shared.output_mode.stdin_route() {
            crate::ComponentInputRoute::Serial if self.shared.grants.terminal_input.is_none() => {}
            crate::ComponentInputRoute::Serial => loop {
                let wait = self.shared.write_serial.wait_for_debug_serial_input();
                if self.shared.pull_serial_into_peek(4096) {
                    return;
                }
                wait.await;
            },
            crate::ComponentInputRoute::Closed => {}
            crate::ComponentInputRoute::Child(stdin_rx) => {
                let mut wait = stdin_rx.wait_state();
                core::future::poll_fn(|cx| stdin_rx.poll_readable(cx, &mut wait)).await;
            }
        }
    }

    fn stdout_ready_mask(&self, stream: Stream) -> u32 {
        let kind = match stream {
            Stream::Stdout => crate::ComponentOutputStreamKind::Stdout,
            Stream::Stderr => crate::ComponentOutputStreamKind::Stderr,
        };
        match self
            .shared
            .output_mode
            .sink(kind, self.shared.launched_instance.id())
        {
            crate::ComponentOutputSink::Local(crate::LocalOutputSink::Serial)
                if self.shared.grants.terminal_output.is_none() =>
            {
                READY_ERR
            }
            crate::ComponentOutputSink::Local(_) => READY_OUT,
            crate::ComponentOutputSink::Child(writer) => {
                if writer.is_reader_closed() {
                    READY_ERR
                } else if writer.is_writable() {
                    READY_OUT
                } else {
                    0
                }
            }
        }
    }
}

fn node_kind_to_component(kind: NodeKind) -> ComponentFsNodeKind {
    match kind {
        NodeKind::Directory => ComponentFsNodeKind::Directory,
        NodeKind::File => ComponentFsNodeKind::File,
        NodeKind::Symlink => ComponentFsNodeKind::Symlink,
        NodeKind::CharacterDevice => ComponentFsNodeKind::CharacterDevice,
        NodeKind::BlockDevice => ComponentFsNodeKind::BlockDevice,
        NodeKind::Fifo => ComponentFsNodeKind::Fifo,
        NodeKind::Socket => ComponentFsNodeKind::Socket,
    }
}

fn join_synthetic_etc_path(base_dir: &str, path: &str) -> Option<(String, bool)> {
    // Reject `..` components so `/nonexistent/../etc/hosts` cannot lexically
    // collapse onto a synthetic `/etc` entry.
    if path.split('/').any(|seg| seg == "..") {
        return None;
    }
    let trailing_slash = path.ends_with('/');
    let combined = if path.starts_with('/') {
        String::from(path)
    } else if base_dir.ends_with('/') {
        alloc::format!("{base_dir}{path}")
    } else {
        alloc::format!("{base_dir}/{path}")
    };
    Some((combined, trailing_slash))
}

fn synthetic_etc_open<StorageImpl: crate::Storage>(
    container: &crate::LinuxContainer<StorageImpl>,
    base_dir: &str,
    path: &str,
    servers: &[crate::NetworkIpAddress],
    request: OpenRequest,
) -> Result<FsDescriptor, FsError> {
    let Some((combined, trailing_slash)) = join_synthetic_etc_path(base_dir, path) else {
        return Err(FsError::NoEntry);
    };
    if container.synthetic_etc_file(&combined, servers).is_none() {
        return Err(FsError::NoEntry);
    }
    if trailing_slash || request.directory {
        return Err(FsError::NotDirectory);
    }
    if request.create && request.exclusive {
        return Err(FsError::Exists);
    }
    if request.write || request.truncate {
        return Err(FsError::ReadOnly);
    }
    let mut flags = FsDescriptorFlags::empty();
    if request.read {
        flags |= FsDescriptorFlags::READ;
    }
    Ok(FsDescriptor {
        path: combined,
        kind: ComponentFsNodeKind::File,
        flags,
        identity: None,
        mount: None,
        open: None,
    })
}

fn synthetic_etc_stat_lookup<StorageImpl: crate::Storage>(
    container: &crate::LinuxContainer<StorageImpl>,
    base_dir: &str,
    path: &str,
    servers: &[crate::NetworkIpAddress],
) -> Result<(FileStat, String), FsError> {
    let Some((combined, trailing_slash)) = join_synthetic_etc_path(base_dir, path) else {
        return Err(FsError::NoEntry);
    };
    let Some(bytes) = container.synthetic_etc_file(&combined, servers) else {
        return Err(FsError::NoEntry);
    };
    if trailing_slash {
        return Err(FsError::NotDirectory);
    }
    Ok((synthetic_etc_stat(&combined, bytes.len() as u64), combined))
}

fn synthetic_etc_access_lookup<StorageImpl: crate::Storage>(
    container: &crate::LinuxContainer<StorageImpl>,
    base_dir: &str,
    path: &str,
    servers: &[crate::NetworkIpAddress],
    check: AccessCheck,
) -> Result<(), FsError> {
    let Some((combined, trailing_slash)) = join_synthetic_etc_path(base_dir, path) else {
        return Err(FsError::NoEntry);
    };
    if container.synthetic_etc_file(&combined, servers).is_none() {
        return Err(FsError::NoEntry);
    }
    if trailing_slash {
        return Err(FsError::NotDirectory);
    }
    if check.write {
        return Err(FsError::ReadOnly);
    }
    if check.exec {
        return Err(FsError::NotPermitted);
    }
    Ok(())
}

fn synthetic_etc_stat(path: &str, size: u64) -> FileStat {
    let ino = if path.ends_with("/resolv.conf") { 1 } else { 2 };
    FileStat {
        dev: u64::MAX,
        ino,
        kind: NodeKind::File,
        permissions: 0o444,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        size,
        access_nanos: 0,
        modified_nanos: 0,
        status_nanos: 0,
    }
}

fn container_info_to_stat(info: &crate::ContainerNodeInfo) -> FileStat {
    FileStat {
        dev: info.metadata.id.device.raw(),
        ino: info.metadata.id.inode,
        kind: info.metadata.kind,
        permissions: info.unix.permissions,
        nlink: info.metadata.link_count,
        uid: info.unix.uid,
        gid: info.unix.gid,
        rdev: info.rdev,
        size: info.metadata.size,
        access_nanos: info.metadata.access_nanos,
        modified_nanos: info.metadata.modified_nanos,
        status_nanos: info.metadata.status_nanos,
    }
}

fn synthetic_tmpfs_stat(read_only: bool) -> syscall::FsStat {
    let machine = crate::machine_memory();
    let total_blocks = (machine.usable_bytes as u64) / 4096;
    let free_blocks = if read_only {
        0
    } else {
        (machine.free_bytes as u64) / 4096
    };
    let mut flags = syscall::ST_VALID | syscall::ST_NOSUID | syscall::ST_NODEV;
    if read_only {
        flags |= syscall::ST_RDONLY;
    }
    syscall::FsStat {
        f_type: syscall::TMPFS_MAGIC,
        f_bsize: 4096,
        f_blocks: total_blocks.max(1),
        f_bfree: free_blocks,
        f_bavail: free_blocks,
        f_files: 65_536,
        f_ffree: if read_only { 0 } else { 65_500 },
        f_fsid: [0x4845_4c49, 0x4f53_544d],
        f_namelen: 255,
        f_frsize: 4096,
        f_flags: flags,
    }
}

fn container_resolved_fs_stat<S: crate::Storage>(
    resolved: &crate::ContainerResolved<'_, S>,
) -> syscall::FsStat {
    let f_type = match resolved.fs().kind_name() {
        "btrfs" => syscall::BTRFS_SUPER_MAGIC,
        "memory" => syscall::TMPFS_MAGIC,
        "erofs" | "boot" => syscall::EROFS_SUPER_MAGIC_V1,
        "host" => syscall::V9FS_MAGIC,
        "overlay" | "root" => syscall::OVERLAYFS_SUPER_MAGIC,
        "proc" => syscall::PROC_SUPER_MAGIC,
        "sysfs" => syscall::SYSFS_MAGIC,
        _ => syscall::TMPFS_MAGIC,
    };
    let read_only = !resolved
        .authority_rights()
        .contains(crate::DirectoryAuthorityRights::WRITE)
        || resolved.flags().contains(crate::MountFlags::READ_ONLY);
    let mut flags = syscall::ST_VALID;
    if read_only {
        flags |= syscall::ST_RDONLY;
    }
    if resolved.flags().contains(crate::MountFlags::NO_SUID) {
        flags |= syscall::ST_NOSUID;
    }
    if resolved.flags().contains(crate::MountFlags::NO_DEV) {
        flags |= syscall::ST_NODEV;
    }
    if !resolved
        .authority_rights()
        .contains(crate::DirectoryAuthorityRights::EXECUTE)
    {
        flags |= syscall::ST_NOEXEC;
    }
    let machine = crate::machine_memory();
    let total_blocks = ((machine.usable_bytes as u64) / 4096).max(1);
    let free_blocks = if read_only {
        0
    } else {
        (machine.free_bytes as u64) / 4096
    };
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in resolved.mount_point().as_bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    syscall::FsStat {
        f_type,
        f_bsize: 4096,
        f_blocks: total_blocks,
        f_bfree: free_blocks,
        f_bavail: free_blocks,
        f_files: 65_536,
        f_ffree: if read_only { 0 } else { 65_500 },
        f_fsid: [hash as i32, (hash >> 32) as i32],
        f_namelen: 255,
        f_frsize: 4096,
        f_flags: flags,
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> Tty
    for LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn is_tty(&self, stream: TtyStream) -> bool {
        self.shared.tty.lock().is_tty(stream)
    }

    fn get_termios(&self, stream: TtyStream) -> Result<Termios, TtyError> {
        let state = self.shared.tty.lock();
        if !state.is_tty(stream) {
            return Err(TtyError::NotTty);
        }
        Ok(state.termios)
    }

    fn set_termios(
        &mut self,
        stream: TtyStream,
        termios: Termios,
        action: TermiosAction,
    ) -> Result<(), TtyError> {
        let mut state = self.shared.tty.lock();
        if !state.is_tty(stream) {
            return Err(TtyError::NotTty);
        }
        if self.shared.grants.tty_control.is_none() {
            return Err(TtyError::Denied);
        }
        state.termios = termios;
        drop(state);
        if action == TermiosAction::Flush {
            self.shared.serial_peek.lock().clear();
        }
        Ok(())
    }

    fn get_winsize(&self, stream: TtyStream) -> Result<Winsize, TtyError> {
        let state = self.shared.tty.lock();
        if !state.is_tty(stream) {
            return Err(TtyError::NotTty);
        }
        Ok(state.winsize)
    }

    fn set_winsize(&mut self, stream: TtyStream, winsize: Winsize) -> Result<(), TtyError> {
        let mut state = self.shared.tty.lock();
        if !state.is_tty(stream) {
            return Err(TtyError::NotTty);
        }
        if self.shared.grants.tty_control.is_none() {
            return Err(TtyError::Denied);
        }
        state.winsize = winsize;
        Ok(())
    }

    fn controlling_pty(&self) -> Option<helios_unix::PtySlave> {
        self.shared.tty.lock().controlling_pty.clone()
    }

    fn set_controlling_pty(&mut self, pty: Option<helios_unix::PtySlave>) {
        self.shared.tty.lock().controlling_pty = pty;
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> Filesystem<LinuxResources<Net>>
    for LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn file_access(&self, file: &FsDescriptor) -> FileAccess {
        let read = file.flags.contains(FsDescriptorFlags::READ);
        let write = file.flags.contains(FsDescriptorFlags::WRITE);
        match (read, write) {
            (true, true) => FileAccess::ReadWrite,
            (true, false) => FileAccess::ReadOnly,
            (false, true) => FileAccess::WriteOnly,
            (false, false) => FileAccess::PathOnly,
        }
    }

    fn file_is_directory(&self, file: &FsDescriptor) -> bool {
        file.kind == ComponentFsNodeKind::Directory
    }

    fn file_path<'a>(&self, file: &'a FsDescriptor) -> Option<&'a str> {
        Some(&file.path)
    }

    fn can_exec_file(&self, file: &FsDescriptor) -> bool {
        self.shared.container.filesystem().can_exec(&file.path)
    }

    fn same_file(&self, a: &FsDescriptor, b: &FsDescriptor) -> bool {
        match (a.identity, b.identity) {
            (Some(ia), Some(ib)) => ia == ib,
            _ => a.path == b.path,
        }
    }

    fn has_synthetic_dev_fallback(&self) -> bool {
        false
    }

    async fn open_descriptor(
        &mut self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        request: OpenRequest,
        creds: &syscall::Credentials,
    ) -> Result<Option<OpenOutcome<LinuxResources<Net>>>, syscall::FsOpError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        self.refresh_proc_if_needed(base_dir, path).await;
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        let opened = alloc::boxed::Box::pin(self.shared.container.filesystem().open_descriptor_at(
            base_dir,
            path,
            request,
            creds,
            Some(self.caller()),
            now,
            &payer,
        ))
        .await;
        match opened {
            Ok(crate::ContainerOpenOutcome::Node {
                info,
                container_path,
                mount_hold,
            }) => {
                let mut flags = FsDescriptorFlags::empty();
                if request.read {
                    flags |= FsDescriptorFlags::READ;
                }
                if request.write {
                    flags |= FsDescriptorFlags::WRITE;
                }
                if request.sync {
                    flags |= FsDescriptorFlags::FILE_INTEGRITY_SYNC;
                }
                if request.dsync {
                    flags |= FsDescriptorFlags::DATA_INTEGRITY_SYNC;
                }
                if info.metadata.kind == NodeKind::Directory {
                    flags |= FsDescriptorFlags::MUTATE_DIRECTORY;
                }
                let desc = FsDescriptor {
                    path: container_path,
                    kind: node_kind_to_component(info.metadata.kind),
                    flags,
                    identity: Some(crate::vfs::object_identity(&info.metadata)),
                    mount: mount_hold,
                    open: None,
                };
                Ok(Some(OpenOutcome::Descriptor(
                    helios_unix::FileDescriptor::File(helios_unix::OpenFile::new(desc)),
                )))
            }
            Ok(crate::ContainerOpenOutcome::PseudoDevice(dev)) => Ok(Some(
                OpenOutcome::Descriptor(helios_unix::FileDescriptor::PseudoDevice(dev)),
            )),
            Ok(crate::ContainerOpenOutcome::ControllingTty {
                is_console,
                dev,
                ino,
                uid,
                gid,
                mode,
            }) => {
                let has_rights = self.shared.grants.terminal_input.is_some()
                    || self.shared.grants.terminal_output.is_some();
                let tty = self.shared.tty.lock();
                let has_stdio_tty = has_rights
                    && (tty.stdin_tty || (is_console && (tty.stdout_tty || tty.stderr_tty)));
                drop(tty);
                let fallback = if has_stdio_tty {
                    let kind = if is_console {
                        helios_unix::PseudoDeviceKind::Console
                    } else {
                        helios_unix::PseudoDeviceKind::Tty
                    };
                    let mut p = helios_unix::PseudoDevice::new(kind, request.read, request.write);
                    p.dev = dev;
                    p.ino = ino;
                    p.uid = uid;
                    p.gid = gid;
                    p.mode = mode;
                    Some(helios_unix::FileDescriptor::PseudoDevice(p))
                } else {
                    None
                };
                Ok(Some(OpenOutcome::ControllingTty { fallback }))
            }
            Ok(crate::ContainerOpenOutcome::PtyMaster(master)) => Ok(Some(
                OpenOutcome::Descriptor(helios_unix::FileDescriptor::PtyMaster(master)),
            )),
            Ok(crate::ContainerOpenOutcome::PtySlave { slave, noctty }) => {
                Ok(Some(OpenOutcome::PtySlave { slave, noctty }))
            }
            Ok(crate::ContainerOpenOutcome::FifoRead(reader)) => Ok(Some(OpenOutcome::Descriptor(
                helios_unix::FileDescriptor::FifoRead(reader),
            ))),
            Ok(crate::ContainerOpenOutcome::FifoWrite(writer)) => Ok(Some(
                OpenOutcome::Descriptor(helios_unix::FileDescriptor::FifoWrite(writer)),
            )),
            Ok(crate::ContainerOpenOutcome::FifoReadWrite(rw)) => Ok(Some(
                OpenOutcome::Descriptor(helios_unix::FileDescriptor::FifoReadWrite(rw)),
            )),
            Ok(crate::ContainerOpenOutcome::ProcFd { pid, fd, .. }) => {
                if pid == self.shared.pid.get() {
                    Ok(Some(OpenOutcome::ReopenFd { fd }))
                } else {
                    Err(syscall::FsOpError::PermissionDenied)
                }
            }
            Err(syscall::FsOpError::Fs(FsError::NoEntry)) => {
                let servers = self
                    .shared
                    .runtime_state
                    .network_service()
                    .map(|service| service.dns_servers())
                    .unwrap_or_default();
                let desc =
                    synthetic_etc_open(&self.shared.container, base_dir, path, &servers, request)?;
                Ok(Some(OpenOutcome::Descriptor(
                    helios_unix::FileDescriptor::File(helios_unix::OpenFile::new(desc)),
                )))
            }
            Err(error) => Err(error),
        }
    }

    fn file_lock_key(&self, file: &FsDescriptor) -> Option<helios_unix::FileLockKey> {
        if let Some(id) = file.identity {
            Some(helios_unix::FileLockKey {
                dev: id.domain().raw(),
                ino: id.local(),
            })
        } else {
            let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
            for &b in file.path.as_bytes() {
                hash ^= u64::from(b);
                hash = hash.wrapping_mul(0x0100_0000_01b3);
            }
            Some(helios_unix::FileLockKey {
                dev: u64::MAX,
                ino: hash,
            })
        }
    }

    async fn statfs_path(
        &self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        creds: &syscall::Credentials,
    ) -> Result<syscall::FsStat, syscall::FsOpError> {
        let effective_cwd = match base {
            Some(dir) => dir.path.as_str(),
            None => cwd,
        };
        let fs = self.shared.container.filesystem();
        match fs
            .walk_path_for_caller(effective_cwd, path, true, creds, Some(self.caller()))
            .await
        {
            Ok((resolved, _)) => Ok(container_resolved_fs_stat(&resolved)),
            Err(syscall::FsOpError::Fs(FsError::NoEntry)) => {
                let servers = self
                    .shared
                    .runtime_state
                    .network_service()
                    .map(|service| service.dns_servers())
                    .unwrap_or_default();
                if synthetic_etc_stat_lookup(&self.shared.container, effective_cwd, path, &servers)
                    .is_ok()
                {
                    Ok(synthetic_tmpfs_stat(true))
                } else {
                    Err(syscall::FsOpError::Fs(FsError::NoEntry))
                }
            }
            Err(err) => Err(err),
        }
    }

    async fn statfs_file(
        &self,
        file: &FsDescriptor,
    ) -> Result<syscall::FsStat, syscall::FsOpError> {
        let fs = self.shared.container.filesystem();
        match fs.resolve(&file.path) {
            Ok(resolved) => Ok(container_resolved_fs_stat(&resolved)),
            Err(_) => Ok(synthetic_tmpfs_stat(
                !file.flags.contains(FsDescriptorFlags::WRITE),
            )),
        }
    }

    async fn sync_all(&self) -> Result<(), syscall::FsOpError> {
        let fs = self.shared.container.filesystem();
        for mount in fs.mounts() {
            if mount
                .authority_rights()
                .contains(crate::DirectoryAuthorityRights::WRITE)
                && !mount.flags().contains(crate::MountFlags::READ_ONLY)
            {
                let _ = fs.sync(mount.target(), false).await;
            }
        }
        Ok(())
    }

    async fn sync_fs(&self, file: &FsDescriptor) -> Result<(), syscall::FsOpError> {
        let fs = self.shared.container.filesystem();
        match fs.sync(&file.path, false).await {
            Ok(()) | Err(syscall::FsOpError::Fs(FsError::ReadOnly | FsError::Unsupported)) => {
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    async fn open(
        &mut self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        request: OpenRequest,
        creds: &syscall::Credentials,
    ) -> Result<FsDescriptor, syscall::FsOpError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        self.refresh_proc_if_needed(base_dir, path).await;
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        let opened = self
            .shared
            .container
            .filesystem()
            .open_at(base_dir, path, request, creds, now, &payer)
            .await;
        let (info, container_path, mount_hold) = match opened {
            Ok(ok) => ok,
            Err(syscall::FsOpError::Fs(FsError::NoEntry)) => {
                let servers = self
                    .shared
                    .runtime_state
                    .network_service()
                    .map(|service| service.dns_servers())
                    .unwrap_or_default();
                return synthetic_etc_open(
                    &self.shared.container,
                    base_dir,
                    path,
                    &servers,
                    request,
                )
                .map_err(Into::into);
            }
            Err(error) => return Err(error),
        };
        let mut flags = FsDescriptorFlags::empty();
        if request.read {
            flags |= FsDescriptorFlags::READ;
        }
        if request.write {
            flags |= FsDescriptorFlags::WRITE;
        }
        if request.sync {
            flags |= FsDescriptorFlags::FILE_INTEGRITY_SYNC;
        }
        if request.dsync {
            flags |= FsDescriptorFlags::DATA_INTEGRITY_SYNC;
        }
        if info.metadata.kind == NodeKind::Directory {
            flags |= FsDescriptorFlags::MUTATE_DIRECTORY;
        }
        Ok(FsDescriptor {
            path: container_path,
            kind: node_kind_to_component(info.metadata.kind),
            flags,
            identity: Some(crate::vfs::object_identity(&info.metadata)),
            mount: mount_hold,
            open: None,
        })
    }

    async fn stat_path(
        &self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        follow: bool,
        creds: &syscall::Credentials,
    ) -> Result<(FileStat, String), syscall::FsOpError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        self.refresh_proc_if_needed(base_dir, path).await;
        match self
            .shared
            .container
            .filesystem()
            .stat_at_for(base_dir, path, follow, creds, Some(self.caller()))
            .await
        {
            Ok((info, resolved_path)) => Ok((container_info_to_stat(&info), resolved_path)),
            Err(syscall::FsOpError::Fs(FsError::NoEntry)) => {
                let servers = self
                    .shared
                    .runtime_state
                    .network_service()
                    .map(|service| service.dns_servers())
                    .unwrap_or_default();
                synthetic_etc_stat_lookup(&self.shared.container, base_dir, path, &servers)
                    .map_err(Into::into)
            }
            Err(error) => Err(error),
        }
    }

    async fn stat_file(&self, file: &FsDescriptor) -> Result<FileStat, syscall::FsOpError> {
        match self
            .shared
            .container
            .filesystem()
            .stat_resolved(&file.path)
            .await
        {
            Ok(info) => Ok(container_info_to_stat(&info)),
            Err(syscall::FsOpError::Fs(FsError::NoEntry)) => {
                let servers = self
                    .shared
                    .runtime_state
                    .network_service()
                    .map(|service| service.dns_servers())
                    .unwrap_or_default();
                if let Some(bytes) = self
                    .shared
                    .container
                    .synthetic_etc_file(&file.path, &servers)
                {
                    return Ok(synthetic_etc_stat(&file.path, bytes.len() as u64));
                }
                Err(FsError::NoEntry.into())
            }
            Err(error) => Err(error),
        }
    }

    async fn access_path(
        &self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        check: AccessCheck,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        self.refresh_proc_if_needed(base_dir, path).await;
        match self
            .shared
            .container
            .filesystem()
            .access_at_for(base_dir, path, check, creds, Some(self.caller()))
            .await
        {
            Ok(()) => Ok(()),
            Err(syscall::FsOpError::Fs(FsError::NoEntry)) => {
                let servers = self
                    .shared
                    .runtime_state
                    .network_service()
                    .map(|service| service.dns_servers())
                    .unwrap_or_default();
                synthetic_etc_access_lookup(&self.shared.container, base_dir, path, &servers, check)
                    .map_err(Into::into)
            }
            Err(error) => Err(error),
        }
    }

    async fn can_chdir_file(
        &self,
        file: &FsDescriptor,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        self.shared
            .container
            .filesystem()
            .can_chdir(&file.path, creds)
            .await
    }

    async fn read_at(
        &self,
        file: &FsDescriptor,
        offset: u64,
        max_bytes: usize,
    ) -> Result<Bytes, syscall::FsOpError> {
        self.refresh_proc_if_needed(&file.path, "").await;
        match self
            .shared
            .container
            .filesystem()
            .read_at(&file.path, offset, max_bytes)
            .await
        {
            Ok(bytes) => {
                if !bytes.is_empty()
                    && let Some(id) = file.identity
                    && self
                        .shared
                        .container
                        .shared_files()
                        .get(id.domain().raw(), id.local())
                        .is_some()
                {
                    let mut buf = bytes.to_vec();
                    self.shared.container.shared_files().overlay_file_read(
                        id.domain().raw(),
                        id.local(),
                        offset,
                        &mut buf,
                    );
                    return Ok(Bytes::from(buf));
                }
                Ok(bytes)
            }
            Err(syscall::FsOpError::Fs(FsError::NoEntry)) => {
                let servers = self
                    .shared
                    .runtime_state
                    .network_service()
                    .map(|service| service.dns_servers())
                    .unwrap_or_default();
                if let Some(bytes) = self
                    .shared
                    .container
                    .synthetic_etc_file(&file.path, &servers)
                {
                    let start = usize::try_from(offset)
                        .unwrap_or(bytes.len())
                        .min(bytes.len());
                    let end = start.saturating_add(max_bytes).min(bytes.len());
                    return Ok(Bytes::copy_from_slice(&bytes[start..end]));
                }
                Err(FsError::NoEntry.into())
            }
            Err(error) => Err(error),
        }
    }

    async fn write_at(
        &mut self,
        file: &FsDescriptor,
        position: WritePosition,
        bytes: &[u8],
        creds: &syscall::Credentials,
    ) -> Result<Landed, syscall::FsOpError> {
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        let result = self
            .shared
            .container
            .filesystem()
            .write_at(&file.path, position, bytes, creds, now, &payer)
            .await;
        if let Ok(landed) = &result
            && landed.len > 0
            && let Some(id) = file.identity
        {
            self.shared.container.shared_files().apply_file_write(
                id.domain().raw(),
                id.local(),
                landed.offset,
                &bytes[..landed.len],
            );
        }
        if matches!(result, Err(syscall::FsOpError::Fs(FsError::OutOfMemory))) {
            crate::wasmtime_adapter::store::request_oom_kill(
                &self.shared.runtime_state,
                &self.shared.runtime_state.instance_registry(),
                &self.shared.cpu,
                self.shared.launched_instance.id(),
                crate::MemoryPool::User,
                bytes.len().max(helios_hal::pmm::PhysFrame::SIZE),
            );
        }
        result
    }

    async fn list_dir(
        &self,
        file: &FsDescriptor,
    ) -> Result<(u64, u64, Vec<DirListEntry>), syscall::FsOpError> {
        self.refresh_proc_if_needed(&file.path, "").await;
        let (self_ino, parent_ino, entries) = self
            .shared
            .container
            .filesystem()
            .list_with_inodes(&file.path)
            .await?;
        let out = entries
            .into_iter()
            .map(|entry| DirListEntry {
                name: entry.name,
                kind: entry.kind,
                inode: entry.inode,
            })
            .collect();
        Ok((self_ino, parent_ino, out))
    }

    async fn set_size_file(
        &mut self,
        file: &FsDescriptor,
        size: u64,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .set_size(&file.path, size, creds, now, &payer)
            .await?;
        if let Some(id) = file.identity {
            let key = (id.domain().raw(), id.local());
            self.shared
                .container
                .shared_files()
                .truncate(key.0, key.1, size);
            let eof_page = size.div_ceil(PhysFrame::SIZE as u64) * PhysFrame::SIZE as u64;
            let discard_ranges = self
                .shared
                .shared_mem
                .lock()
                .pages_beyond_eof(key, eof_page);
            for (start, end) in discard_ranges {
                let _ = self.shared.space.discard(page_range(start, end - start));
            }
        }
        Ok(())
    }

    async fn set_size_path(
        &mut self,
        cwd: &str,
        path: &str,
        size: u64,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        let file_key = self
            .shared
            .container
            .filesystem()
            .stat_at(cwd, path, true, creds)
            .await
            .ok()
            .map(|(info, _)| (info.metadata.id.device.raw(), info.metadata.id.inode));
        self.shared
            .container
            .filesystem()
            .set_size_at(cwd, path, size, creds, now, &payer)
            .await?;
        if let Some(key) = file_key {
            self.shared
                .container
                .shared_files()
                .truncate(key.0, key.1, size);
            let eof_page = size.div_ceil(PhysFrame::SIZE as u64) * PhysFrame::SIZE as u64;
            let discard_ranges = self
                .shared
                .shared_mem
                .lock()
                .pages_beyond_eof(key, eof_page);
            for (start, end) in discard_ranges {
                let _ = self.shared.space.discard(page_range(start, end - start));
            }
        }
        Ok(())
    }

    async fn sync(&self, file: &FsDescriptor, data_only: bool) -> Result<(), syscall::FsOpError> {
        self.shared
            .container
            .filesystem()
            .sync(&file.path, data_only)
            .await
    }

    async fn read_link(
        &self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        creds: &syscall::Credentials,
    ) -> Result<String, syscall::FsOpError> {
        if self.shared.grants.symlink_read.is_none() {
            return Err(FsError::NotPermitted.into());
        }
        if path.is_empty() {
            let Some(file) = base else {
                return Err(FsError::NoEntry.into());
            };
            self.refresh_proc_if_needed(&file.path, "").await;
            return self
                .shared
                .container
                .filesystem()
                .read_link_resolved_for(&file.path, Some(self.caller()))
                .await;
        }
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        self.refresh_proc_if_needed(base_dir, path).await;
        self.shared
            .container
            .filesystem()
            .read_link_at_for(base_dir, path, creds, Some(self.caller()))
            .await
    }

    async fn mkdir(
        &mut self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        mode: u32,
        umask: u32,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .mkdir_at(base_dir, path, mode, umask, creds, now, &payer)
            .await
    }

    async fn mknod(
        &mut self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        kind: NodeKind,
        mode: u32,
        umask: u32,
        rdev: u64,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .mknod_at(base_dir, path, kind, mode, umask, rdev, creds, now, &payer)
            .await
    }

    async fn unlink(
        &mut self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        remove_dir: bool,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .unlink_at(base_dir, path, remove_dir, creds, now, &payer)
            .await
    }

    async fn rename(
        &mut self,
        old_base: Option<&FsDescriptor>,
        old_path: &str,
        new_base: Option<&FsDescriptor>,
        new_path: &str,
        cwd: &str,
        mode: RenameMode,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let old_dir = old_base.map_or(cwd, |f| f.path.as_str());
        let new_dir = new_base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .rename_at(
                old_dir, old_path, new_dir, new_path, mode, creds, now, &payer,
            )
            .await
    }

    async fn link(
        &mut self,
        old_base: Option<&FsDescriptor>,
        old_path: &str,
        new_base: Option<&FsDescriptor>,
        new_path: &str,
        cwd: &str,
        options: LinkOptions,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        if self.shared.grants.link_source.is_none() {
            return Err(FsError::NotPermitted.into());
        }
        let old_dir = old_base.map_or(cwd, |f| f.path.as_str());
        let new_dir = new_base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .link_at(
                old_dir,
                old_path,
                new_dir,
                new_path,
                options.follow,
                options.empty_path,
                creds,
                now,
                &payer,
            )
            .await
    }

    async fn symlink(
        &mut self,
        target: &str,
        base: Option<&FsDescriptor>,
        cwd: &str,
        link_path: &str,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        if self.shared.grants.symlink_create.is_none() {
            return Err(FsError::NotPermitted.into());
        }
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .symlink_at(target, base_dir, link_path, creds, now, &payer)
            .await
    }

    async fn set_times_path(
        &mut self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        follow: bool,
        access: TimeUpdate,
        modified: TimeUpdate,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .set_times_at(base_dir, path, follow, access, modified, creds, now, &payer)
            .await
    }

    async fn set_times_file(
        &mut self,
        file: &FsDescriptor,
        access: TimeUpdate,
        modified: TimeUpdate,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .set_times_resolved(&file.path, access, modified, creds, now, &payer)
            .await
    }

    async fn chmod_path(
        &mut self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        follow: bool,
        mode: u32,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .chmod_at(base_dir, path, follow, mode, creds, now, &payer)
            .await
    }

    async fn chmod_file(
        &mut self,
        file: &FsDescriptor,
        mode: u32,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .chmod_resolved(&file.path, mode, creds, now, &payer)
            .await
    }

    async fn chown_path(
        &mut self,
        base: Option<&FsDescriptor>,
        cwd: &str,
        path: &str,
        follow: bool,
        uid: Option<u32>,
        gid: Option<u32>,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let base_dir = base.map_or(cwd, |f| f.path.as_str());
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .chown_at(base_dir, path, follow, uid, gid, creds, now, &payer)
            .await
    }

    async fn chown_file(
        &mut self,
        file: &FsDescriptor,
        uid: Option<u32>,
        gid: Option<u32>,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .chown_resolved(&file.path, uid, gid, creds, now, &payer)
            .await
    }

    async fn get_xattr_path(
        &self,
        cwd: &str,
        path: &str,
        follow: bool,
        name: &str,
        creds: &syscall::Credentials,
    ) -> Result<Vec<u8>, syscall::FsOpError> {
        self.shared
            .container
            .filesystem()
            .get_xattr_at(cwd, path, follow, name, creds)
            .await
    }

    async fn get_xattr_file(
        &self,
        file: &FsDescriptor,
        name: &str,
        creds: &syscall::Credentials,
    ) -> Result<Vec<u8>, syscall::FsOpError> {
        self.shared
            .container
            .filesystem()
            .get_xattr_resolved(&file.path, name, creds)
            .await
    }

    async fn set_xattr_path(
        &mut self,
        cwd: &str,
        path: &str,
        follow: bool,
        name: &str,
        value: &[u8],
        mode: syscall::XattrSetMode,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .set_xattr_at(cwd, path, follow, name, value, mode, creds, now, &payer)
            .await
    }

    async fn set_xattr_file(
        &mut self,
        file: &FsDescriptor,
        name: &str,
        value: &[u8],
        mode: syscall::XattrSetMode,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .set_xattr_resolved(&file.path, name, value, mode, creds, now, &payer)
            .await
    }

    async fn list_xattrs_path(
        &self,
        cwd: &str,
        path: &str,
        follow: bool,
        creds: &syscall::Credentials,
    ) -> Result<Vec<String>, syscall::FsOpError> {
        self.shared
            .container
            .filesystem()
            .list_xattrs_at(cwd, path, follow, creds)
            .await
    }

    async fn list_xattrs_file(
        &self,
        file: &FsDescriptor,
        creds: &syscall::Credentials,
    ) -> Result<Vec<String>, syscall::FsOpError> {
        self.shared
            .container
            .filesystem()
            .list_xattrs_resolved(&file.path, creds)
            .await
    }

    async fn remove_xattr_path(
        &mut self,
        cwd: &str,
        path: &str,
        follow: bool,
        name: &str,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .remove_xattr_at(cwd, path, follow, name, creds, now, &payer)
            .await
    }

    async fn remove_xattr_file(
        &mut self,
        file: &FsDescriptor,
        name: &str,
        creds: &syscall::Credentials,
    ) -> Result<(), syscall::FsOpError> {
        let now = self.shared.clock.lock().system_time_nanos();
        let payer = self.shared.launched_instance.storage_payer();
        self.shared
            .container
            .filesystem()
            .remove_xattr_resolved(&file.path, name, creds, now, &payer)
            .await
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> syscall::Clock
    for LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    /// The uptime clock, the one WASIX's `clock_time_get` reads.
    fn now_nanos(&self) -> u64 {
        self.shared
            .runtime_state
            .uptime_nanos(self.shared.cpu.now().ticks())
    }

    async fn sleep_until(&self, deadline: u64) {
        let remaining = deadline.saturating_sub(self.now_nanos());
        self.shared
            .timer
            .sleep_for(Duration::from_nanos(remaining))
            .await;
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> System
    for LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn realtime_nanos(&self) -> u64 {
        self.shared.clock.lock().system_time_nanos()
    }

    fn set_realtime_nanos(&mut self, nanos: u64) -> Result<(), Denied> {
        // The right WASIX's `clock_time_set` derives.
        let cap = self.shared.grants.set_wall_clock.as_ref().ok_or(Denied)?;
        self.shared.clock.lock().set_system_time_nanos(cap, nanos);
        Ok(())
    }

    fn cpu_nanos(&self) -> u64 {
        self.shared
            .cpu
            .timebase()
            .ticks_to_nanos(self.thread_cpu_ticks)
    }

    fn process_cpu_nanos(&self) -> u64 {
        self.shared
            .cpu
            .timebase()
            .ticks_to_nanos(self.shared.process_cpu_ticks.load(Ordering::Relaxed))
    }

    fn thread_sys_nanos(&self) -> u64 {
        self.shared
            .cpu
            .timebase()
            .ticks_to_nanos(self.thread_sys_ticks)
    }

    fn process_sys_nanos(&self) -> u64 {
        self.shared
            .cpu
            .timebase()
            .ticks_to_nanos(self.shared.process_sys_ticks.load(Ordering::Relaxed))
    }

    fn max_rss_kib(&self) -> u64 {
        self.shared.current_rss_kib()
    }

    fn syslog_check_authority(&self) -> Result<(), Denied> {
        if self.shared.grants.trace_read.is_some()
            || self.shared.grants.diagnostics_control.is_some()
        {
            Ok(())
        } else {
            Err(Denied)
        }
    }

    fn syslog_buffer_size(&self) -> usize {
        65_536
    }

    fn syslog_unread_size(&self) -> usize {
        let min_ts = self
            .shared
            .syslog_clear_after
            .load(Ordering::Relaxed)
            .max(*self.shared.syslog_cursor.lock());
        self.format_syslog_events(min_ts, usize::MAX).0.len()
    }

    fn syslog_read(&mut self, all: bool, clear: bool, max_bytes: usize) -> Result<Vec<u8>, Denied> {
        if clear {
            if self.shared.grants.diagnostics_control.is_none() {
                return Err(Denied);
            }
        } else {
            self.syslog_check_authority()?;
        }
        let clear_after = self.shared.syslog_clear_after.load(Ordering::Relaxed);
        let min_ts = if all {
            clear_after
        } else {
            clear_after.max(*self.shared.syslog_cursor.lock())
        };
        let (bytes, last_ts) = self.format_syslog_events(min_ts, max_bytes);
        if let Some(ts) = last_ts {
            if !all {
                let mut cursor = self.shared.syslog_cursor.lock();
                if ts > *cursor {
                    *cursor = ts;
                }
            }
            if clear {
                self.shared
                    .syslog_clear_after
                    .fetch_max(ts, Ordering::Relaxed);
            }
        }
        Ok(bytes)
    }

    fn syslog_clear(&mut self) -> Result<(), Denied> {
        if self.shared.grants.diagnostics_control.is_none() {
            return Err(Denied);
        }
        let (_, last_ts) = self.format_syslog_events(0, usize::MAX);
        if let Some(ts) = last_ts {
            self.shared
                .syslog_clear_after
                .fetch_max(ts, Ordering::Relaxed);
            let mut cursor = self.shared.syslog_cursor.lock();
            if ts > *cursor {
                *cursor = ts;
            }
        }
        Ok(())
    }

    fn processor_count(&self) -> u32 {
        u32::try_from(self.shared.cpu.processor_count().max(1)).unwrap_or(u32::MAX)
    }

    fn fill_random(&mut self, output: &mut [u8]) {
        self.entropy
            .fill_secure(self.shared.runtime_state.root_entropy(), output);
    }

    fn memory(&self) -> MemoryTotals {
        let machine = crate::machine_memory();
        MemoryTotals {
            total_bytes: machine.usable_bytes as u64,
            free_bytes: machine.free_bytes as u64,
        }
    }

    fn process_count(&self) -> u32 {
        self.shared.container.process_count()
    }

    fn kernel_version(&self) -> &str {
        concat!("#1 Helios ", env!("CARGO_PKG_VERSION"))
    }

    fn hostname(&self) -> syscall::UtsField {
        self.shared.container.hostname()
    }

    fn domainname(&self) -> syscall::UtsField {
        self.shared.container.domainname()
    }

    fn set_hostname(&mut self, name: syscall::UtsField) -> Result<(), Denied> {
        self.shared.container.set_hostname(name);
        Ok(())
    }

    fn set_domainname(&mut self, name: syscall::UtsField) -> Result<(), Denied> {
        self.shared.container.set_domainname(name);
        Ok(())
    }
}

fn linux_to_network_ip(ip: syscall::IpAddr) -> crate::NetworkIpAddress {
    match ip {
        syscall::IpAddr::V4(octets) => {
            crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new(octets))
        }
        syscall::IpAddr::V6(octets) => {
            crate::NetworkIpAddress::Ipv6(helios_netstack::Ipv6Address::new(octets))
        }
    }
}

fn network_to_linux_ip(address: crate::NetworkIpAddress) -> syscall::IpAddr {
    match address {
        crate::NetworkIpAddress::Ipv4(addr) => syscall::IpAddr::V4(addr.octets()),
        crate::NetworkIpAddress::Ipv6(addr) => syscall::IpAddr::V6(addr.octets()),
    }
}

fn linux_errno_from_tcp_error(error: crate::TcpError) -> u64 {
    const EACCES: u64 = 13;
    const EIO: u64 = 5;
    match error.detail {
        crate::NetworkErrorDetail::AddressNotAvailable => return syscall::EADDRNOTAVAIL,
        crate::NetworkErrorDetail::TcpRemotePortUnreachable => return syscall::ECONNREFUSED,
        crate::NetworkErrorDetail::TcpRemoteNetworkUnreachable => return syscall::ENETUNREACH,
        crate::NetworkErrorDetail::TcpRemoteHostUnreachable => return syscall::EHOSTUNREACH,
        crate::NetworkErrorDetail::TcpRemoteCommunicationProhibited => return EACCES,
        crate::NetworkErrorDetail::TcpClosedDuringConnect => return syscall::ECONNREFUSED,
        crate::NetworkErrorDetail::TcpListenStartFailed => return syscall::EADDRINUSE,
        crate::NetworkErrorDetail::TcpNoLongerWritable => return syscall::EPIPE,
        _ => {}
    }
    match error.kind {
        crate::TcpErrorKind::UnresolvedHost => syscall::EHOSTUNREACH,
        crate::TcpErrorKind::Timeout => syscall::ETIMEDOUT,
        crate::TcpErrorKind::ConnectionReset => syscall::ECONNRESET,
        crate::TcpErrorKind::ConnectionAborted => syscall::ECONNABORTED,
        crate::TcpErrorKind::PermissionDenied => EACCES,
        crate::TcpErrorKind::Unavailable => syscall::ENETDOWN,
        crate::TcpErrorKind::Internal => EIO,
    }
}

fn linux_errno_from_udp_error(error: crate::UdpError) -> u64 {
    const EACCES: u64 = 13;
    const EIO: u64 = 5;
    const EINVAL: u64 = 22;
    const EOPNOTSUPP: u64 = 95;
    match error.detail {
        crate::NetworkErrorDetail::AddressNotAvailable
        | crate::NetworkErrorDetail::UdpMulticastInterfaceUnavailable => {
            return syscall::EADDRNOTAVAIL;
        }
        crate::NetworkErrorDetail::UdpPortInUse => return syscall::EADDRINUSE,
        crate::NetworkErrorDetail::UdpDatagramTooLarge => return syscall::EMSGSIZE,
        crate::NetworkErrorDetail::UdpRemotePortUnreachable => return syscall::ECONNREFUSED,
        crate::NetworkErrorDetail::UdpRemoteNetworkUnreachable => return syscall::ENETUNREACH,
        crate::NetworkErrorDetail::UdpRemoteHostUnreachable => return syscall::EHOSTUNREACH,
        crate::NetworkErrorDetail::UdpRemoteCommunicationProhibited => return EACCES,
        crate::NetworkErrorDetail::UnsupportedAddressFamily => return syscall::EAFNOSUPPORT,
        crate::NetworkErrorDetail::UdpMulticastJoinFailed
        | crate::NetworkErrorDetail::UdpMulticastLeaveFailed => return EINVAL,
        _ => {}
    }
    match error.kind {
        crate::UdpErrorKind::UnresolvedHost => syscall::EHOSTUNREACH,
        crate::UdpErrorKind::Unsupported => EOPNOTSUPP,
        crate::UdpErrorKind::Timeout => syscall::ETIMEDOUT,
        crate::UdpErrorKind::PermissionDenied => EACCES,
        crate::UdpErrorKind::Unavailable => syscall::ENETDOWN,
        crate::UdpErrorKind::Internal => EIO,
    }
}

impl<CpuImpl, Net, StorageImpl, Space: UserSpace> syscall::Network<crate::UnixNetwork<Net>>
    for LinuxThreadPlatform<CpuImpl, Net, StorageImpl, Space>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn to_ip(&self, address: crate::NetworkIpAddress) -> syscall::IpAddr {
        network_to_linux_ip(address)
    }

    fn encode_ip(&self, ip: syscall::IpAddr) -> crate::NetworkIpAddress {
        linux_to_network_ip(ip)
    }

    fn check_tcp_open(&self) -> Result<(), u64> {
        const EACCES: u64 = 13;
        if self.shared.grants.tcp.is_none() {
            return Err(EACCES);
        }
        if self.shared.runtime_state.network_service().is_none() {
            return Err(syscall::ENETDOWN);
        }
        Ok(())
    }

    fn check_udp_open(&self) -> Result<(), u64> {
        const EACCES: u64 = 13;
        if self.shared.grants.udp.is_none() {
            return Err(EACCES);
        }
        if self.shared.runtime_state.network_service().is_none() {
            return Err(syscall::ENETDOWN);
        }
        Ok(())
    }

    fn check_tcp_bind(&self, local_port: u16) -> Result<(), u64> {
        const EACCES: u64 = 13;
        self.check_tcp_open()?;
        if local_port != 0 && local_port < 1024 && self.shared.grants.privileged_bind.is_none() {
            return Err(EACCES);
        }
        Ok(())
    }

    fn check_udp_bind(&self, local_port: u16) -> Result<(), u64> {
        const EACCES: u64 = 13;
        self.check_udp_open()?;
        if local_port != 0 && local_port < 1024 && self.shared.grants.privileged_bind.is_none() {
            return Err(EACCES);
        }
        Ok(())
    }

    async fn tcp_listen(
        &self,
        local: syscall::SocketAddr,
        backlog: u16,
        hop_limit: u8,
    ) -> Result<(Arc<OwnedTcpListener<crate::UnixNetwork<Net>>>, u16), u64> {
        self.check_tcp_bind(local.port)?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let bound = service
            .tcp_listen(
                linux_to_network_ip(local.ip),
                local.port,
                backlog,
                hop_limit,
            )
            .await
            .map_err(linux_errno_from_tcp_error)?;
        let owned = OwnedTcpListener::new(crate::UnixNetwork::new(service), bound.listener);
        Ok((owned, bound.local_port))
    }

    async fn tcp_accept(
        &self,
        listener: Net::TcpListener,
        timeout_nanos: u64,
    ) -> Result<
        (
            Arc<OwnedTcpStream<crate::UnixNetwork<Net>>>,
            syscall::SocketAddr,
        ),
        u64,
    > {
        // Possessing a pre-bound TCP listener descriptor (e.g. inherited at
        // `fd = 3+`) is itself the capability to accept connections on it.
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let accepted = service
            .tcp_accept(listener, timeout_nanos)
            .await
            .map_err(linux_errno_from_tcp_error)?;
        let owned = OwnedTcpStream::new(crate::UnixNetwork::new(service), accepted.stream);
        Ok((
            owned,
            syscall::SocketAddr {
                ip: network_to_linux_ip(accepted.address),
                port: accepted.port,
            },
        ))
    }

    async fn tcp_connect(
        &self,
        remote: syscall::SocketAddr,
        local_port: u16,
        hop_limit: u8,
        timeout_nanos: u64,
    ) -> Result<Arc<OwnedTcpStream<crate::UnixNetwork<Net>>>, u64> {
        self.check_tcp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let stream = service
            .tcp_connect_address(
                linux_to_network_ip(remote.ip),
                remote.port,
                local_port,
                hop_limit,
                timeout_nanos,
            )
            .await
            .map_err(linux_errno_from_tcp_error)?;
        Ok(OwnedTcpStream::new(
            crate::UnixNetwork::new(service),
            stream,
        ))
    }

    async fn tcp_connect_start(
        &self,
        remote: syscall::SocketAddr,
        local_port: u16,
        hop_limit: u8,
    ) -> Result<
        (
            Arc<OwnedTcpStream<crate::UnixNetwork<Net>>>,
            syscall::ConnectProgress,
        ),
        u64,
    > {
        self.check_tcp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let (stream, progress) = service
            .tcp_connect_start(
                linux_to_network_ip(remote.ip),
                remote.port,
                local_port,
                hop_limit,
            )
            .await
            .map_err(linux_errno_from_tcp_error)?;
        let owned = OwnedTcpStream::new(crate::UnixNetwork::new(service), stream);
        let progress = match progress {
            crate::TcpConnectPoll::Pending => syscall::ConnectProgress::Pending,
            crate::TcpConnectPoll::Connected => syscall::ConnectProgress::Connected,
        };
        Ok((owned, progress))
    }

    async fn tcp_connect_poll(
        &self,
        stream: Net::TcpStream,
    ) -> Result<syscall::ConnectProgress, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        match service
            .tcp_connect_poll(stream)
            .await
            .map_err(linux_errno_from_tcp_error)?
        {
            crate::TcpConnectPoll::Pending => Ok(syscall::ConnectProgress::Pending),
            crate::TcpConnectPoll::Connected => Ok(syscall::ConnectProgress::Connected),
        }
    }

    fn tcp_local_endpoint(
        &self,
        stream: Net::TcpStream,
    ) -> Result<Option<syscall::SocketAddr>, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        Ok(service
            .tcp_local_endpoint(stream)
            .map_err(linux_errno_from_tcp_error)?
            .map(|(ip, port)| syscall::SocketAddr {
                ip: network_to_linux_ip(ip),
                port,
            }))
    }

    fn tcp_set_hop_limit(&self, stream: Net::TcpStream, hop_limit: u8) -> Result<(), u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .tcp_set_hop_limit(stream, hop_limit)
            .map_err(linux_errno_from_tcp_error)
    }

    fn tcp_listener_set_hop_limit(
        &self,
        listener: Net::TcpListener,
        hop_limit: u8,
    ) -> Result<(), u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .tcp_listener_set_hop_limit(listener, hop_limit)
            .map_err(linux_errno_from_tcp_error)
    }

    async fn tcp_read(
        &self,
        stream: Net::TcpStream,
        max_bytes: u32,
        timeout_nanos: u64,
        peek: bool,
    ) -> Result<Option<Bytes>, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        if !peek {
            return service
                .tcp_read(stream, max_bytes, timeout_nanos)
                .await
                .map_err(linux_errno_from_tcp_error);
        }
        let cap = (max_bytes as usize).min(65_536);
        let mut storage = alloc::vec![0u8; cap];
        let ranges = [(0usize, storage.len())];
        // SAFETY: `storage` is a live, exclusively owned heap buffer that stays
        // in place for the duration of `tcp_peek_into`, and no page of it can
        // be swapped out (`residency = None`).
        let mut buffer = unsafe {
            crate::RegisteredTcpReadBuffer::new(storage.as_mut_ptr() as usize, &ranges, None)
        };
        match service
            .tcp_peek_into(stream, &mut buffer, timeout_nanos)
            .await
            .map_err(linux_errno_from_tcp_error)?
        {
            crate::TcpReadInto::Data(n) => {
                storage.truncate(n);
                Ok(Some(Bytes::from(storage)))
            }
            crate::TcpReadInto::Eof => Ok(None),
            crate::TcpReadInto::PageLost(_) => Err(5),
        }
    }

    async fn tcp_write(
        &self,
        stream: Net::TcpStream,
        bytes: Bytes,
        timeout_nanos: u64,
    ) -> Result<usize, u64> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let len = bytes.len().min(helios_netstack::TCP_TRANSMIT_BUFFER_BYTES);
        match service.tcp_payload(len, |piece| piece.copy_from_slice(&bytes[..len])) {
            Ok(payload) => service
                .tcp_write_some_bytes(stream, payload, timeout_nanos)
                .await
                .map_err(linux_errno_from_tcp_error),
            Err(error)
                if matches!(
                    error.detail,
                    crate::NetworkErrorDetail::TransmitMemoryReplenishing
                        | crate::NetworkErrorDetail::TransmitMemoryExhausted
                ) =>
            {
                if timeout_nanos == 0 {
                    return Err(syscall::ETIMEDOUT);
                }
                let pieces = service.tcp_payload_pieces(len, |offset, piece| {
                    piece.copy_from_slice(&bytes[offset..][..piece.len()]);
                });
                service
                    .tcp_write_all(stream, pieces, timeout_nanos)
                    .await
                    .map(|()| len)
                    .map_err(linux_errno_from_tcp_error)
            }
            Err(error) => Err(linux_errno_from_tcp_error(error)),
        }
    }

    async fn tcp_shutdown_send(&self, stream: Net::TcpStream) -> Result<(), u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .tcp_shutdown_send(stream)
            .await
            .map_err(linux_errno_from_tcp_error)
    }

    async fn tcp_readiness(&self, stream: Net::TcpStream) -> Result<syscall::SocketReady, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let r = service
            .tcp_readiness(stream)
            .await
            .map_err(linux_errno_from_tcp_error)?;
        Ok(syscall::SocketReady {
            readable: r.readable,
            writable: r.writable,
            hangup: r.hangup,
        })
    }

    async fn tcp_listener_readiness(
        &self,
        listener: Net::TcpListener,
    ) -> Result<syscall::SocketReady, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let r = service
            .tcp_listener_readiness(listener)
            .await
            .map_err(linux_errno_from_tcp_error)?;
        Ok(syscall::SocketReady {
            readable: r.readable,
            writable: r.writable,
            hangup: r.hangup,
        })
    }

    async fn udp_bind(
        &self,
        local: syscall::SocketAddr,
        hop_limit: u8,
    ) -> Result<(Arc<OwnedUdpSocket<crate::UnixNetwork<Net>>>, u16), u64> {
        self.check_udp_bind(local.port)?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let bound = service
            .udp_bind(linux_to_network_ip(local.ip), local.port)
            .await
            .map_err(linux_errno_from_udp_error)?;
        let owned = OwnedUdpSocket::new(crate::UnixNetwork::new(service.clone()), bound.socket);
        service
            .udp_set_hop_limit(bound.socket, hop_limit)
            .map_err(linux_errno_from_udp_error)?;
        Ok((owned, bound.local_port))
    }

    fn udp_connect(&self, socket: Net::UdpSocket, remote: syscall::SocketAddr) -> Result<(), u64> {
        self.check_udp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .udp_connect(socket, linux_to_network_ip(remote.ip), remote.port)
            .map_err(linux_errno_from_udp_error)
    }

    fn udp_disconnect(&self, socket: Net::UdpSocket) -> Result<(), u64> {
        self.check_udp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .udp_disconnect(socket)
            .map_err(linux_errno_from_udp_error)
    }

    fn udp_set_hop_limit(&self, socket: Net::UdpSocket, hop_limit: u8) -> Result<(), u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .udp_set_hop_limit(socket, hop_limit)
            .map_err(linux_errno_from_udp_error)
    }

    async fn udp_send<'a>(
        &'a self,
        socket: Net::UdpSocket,
        remote: syscall::SocketAddr,
        bytes: &'a [u8],
        timeout_nanos: u64,
    ) -> Result<usize, u64> {
        self.check_udp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let sent = service
            .udp_send_address(
                socket,
                linux_to_network_ip(remote.ip),
                remote.port,
                bytes,
                timeout_nanos,
            )
            .await
            .map_err(linux_errno_from_udp_error)?;
        Ok(sent as usize)
    }

    async fn udp_receive(
        &self,
        socket: Net::UdpSocket,
        max_bytes: u32,
        timeout_nanos: u64,
        peek: bool,
    ) -> Result<Option<(Bytes, syscall::SocketAddr, usize)>, u64> {
        self.check_udp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let datagram = if peek {
            service
                .udp_peek(socket, max_bytes, timeout_nanos)
                .await
                .map_err(linux_errno_from_udp_error)?
        } else {
            service
                .udp_receive(socket, max_bytes, timeout_nanos)
                .await
                .map_err(linux_errno_from_udp_error)?
        };
        Ok(datagram.map(|d| {
            (
                d.bytes,
                syscall::SocketAddr {
                    ip: network_to_linux_ip(d.address),
                    port: d.port,
                },
                d.original_len,
            )
        }))
    }

    async fn udp_readiness(&self, socket: Net::UdpSocket) -> Result<syscall::SocketReady, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let r = service
            .udp_readiness(socket)
            .await
            .map_err(linux_errno_from_udp_error)?;
        Ok(syscall::SocketReady {
            readable: r.readable,
            writable: r.writable,
            hangup: r.hangup,
        })
    }

    async fn udp_join_multicast_v4(&self, group: [u8; 4], interface: [u8; 4]) -> Result<(), u64> {
        const EACCES: u64 = 13;
        if self.shared.grants.multicast.is_none() {
            return Err(EACCES);
        }
        self.check_udp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .udp_join_multicast_v4(
                crate::Ipv4Address::new(group),
                crate::Ipv4Address::new(interface),
            )
            .await
            .map_err(linux_errno_from_udp_error)
    }

    async fn udp_leave_multicast_v4(&self, group: [u8; 4], interface: [u8; 4]) -> Result<(), u64> {
        const EACCES: u64 = 13;
        if self.shared.grants.multicast.is_none() {
            return Err(EACCES);
        }
        self.check_udp_open()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .udp_leave_multicast_v4(
                crate::Ipv4Address::new(group),
                crate::Ipv4Address::new(interface),
            )
            .await
            .map_err(linux_errno_from_udp_error)
    }

    fn check_multicast_v6(&self) -> Result<(), u64> {
        const EACCES: u64 = 13;
        if self.shared.grants.multicast.is_none() {
            return Err(EACCES);
        }
        self.check_udp_open()
    }

    async fn interface_mac(&self) -> Result<[u8; 6], u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .mac_address(NetworkPortId::new(0))
            .await
            .map(crate::MacAddress::octets)
            .map_err(linux_errno_from_control_error)
    }

    async fn list_ipv4_addresses(&self) -> Result<Vec<syscall::Ipv4InterfaceAddress>, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let addrs = service
            .list_addresses(NetworkPortId::new(0))
            .await
            .map_err(linux_errno_from_control_error)?;
        Ok(addrs
            .into_iter()
            .map(|cidr| syscall::Ipv4InterfaceAddress {
                address: cidr.address().octets(),
                prefix: cidr.prefix_len(),
            })
            .collect())
    }

    async fn add_ipv4_address(&self, address: syscall::Ipv4InterfaceAddress) -> Result<(), u64> {
        self.check_net_admin()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let cidr = KernelIpv4Cidr::new(crate::Ipv4Address::new(address.address), address.prefix);
        service
            .add_address(NetworkPortId::new(0), cidr)
            .await
            .map_err(linux_errno_from_control_error)
    }

    async fn remove_ipv4_address(&self, address: syscall::Ipv4InterfaceAddress) -> Result<(), u64> {
        self.check_net_admin()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let cidr = KernelIpv4Cidr::new(crate::Ipv4Address::new(address.address), address.prefix);
        service
            .remove_address(NetworkPortId::new(0), cidr)
            .await
            .map_err(linux_errno_from_control_error)
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<syscall::Ipv4RouteEntry>, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let routes = service
            .list_routes(NetworkPortId::new(0))
            .await
            .map_err(linux_errno_from_control_error)?;
        Ok(routes
            .into_iter()
            .map(|route| {
                let gw = route.gateway().octets();
                syscall::Ipv4RouteEntry {
                    destination: route.destination().address().octets(),
                    prefix: route.destination().prefix_len(),
                    gateway: if gw == [0, 0, 0, 0] { None } else { Some(gw) },
                }
            })
            .collect())
    }

    async fn add_ipv4_route(&self, route: syscall::Ipv4RouteEntry) -> Result<(), u64> {
        self.check_net_admin()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let cidr = KernelIpv4Cidr::new(crate::Ipv4Address::new(route.destination), route.prefix);
        let gw = crate::Ipv4Address::new(route.gateway.unwrap_or([0, 0, 0, 0]));
        service
            .add_route(NetworkPortId::new(0), KernelIpv4Route::new(cidr, gw))
            .await
            .map_err(linux_errno_from_control_error)
    }

    async fn remove_ipv4_route(&self, route: syscall::Ipv4RouteEntry) -> Result<(), u64> {
        self.check_net_admin()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let cidr = KernelIpv4Cidr::new(crate::Ipv4Address::new(route.destination), route.prefix);
        let gw = crate::Ipv4Address::new(route.gateway.unwrap_or([0, 0, 0, 0]));
        service
            .remove_route(NetworkPortId::new(0), KernelIpv4Route::new(cidr, gw))
            .await
            .map_err(linux_errno_from_control_error)
    }

    fn check_net_admin(&self) -> Result<(), u64> {
        const EPERM: u64 = 1;
        if self.shared.grants.network_admin.is_none() {
            return Err(EPERM);
        }
        Ok(())
    }

    fn packet_open(
        &self,
        protocol: u16,
    ) -> Result<Arc<helios_unix::OwnedPacketSocket<crate::UnixNetwork<Net>>>, u64> {
        self.check_net_admin()?;
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let id = service
            .packet_open(protocol)
            .map_err(linux_errno_from_udp_error)?;
        Ok(helios_unix::OwnedPacketSocket::new(
            crate::UnixNetwork::new(service),
            id,
        ))
    }

    fn packet_bind(&self, socket: u64, protocol: u16, ifindex: u32) -> Result<(), u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .packet_bind(socket, protocol, ifindex)
            .map_err(linux_errno_from_udp_error)
    }

    async fn packet_send<'a>(
        &'a self,
        socket: u64,
        ifindex: u32,
        frame: &'a [u8],
    ) -> Result<usize, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .packet_send(socket, ifindex, frame)
            .await
            .map_err(linux_errno_from_udp_error)
    }

    async fn packet_receive(
        &self,
        socket: u64,
        max_bytes: u32,
        timeout_nanos: u64,
        peek: bool,
    ) -> Result<Option<syscall::PacketFrameData>, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let frame = service
            .packet_receive(socket, max_bytes, timeout_nanos, peek)
            .await
            .map_err(linux_errno_from_udp_error)?;
        Ok(frame.map(|f| syscall::PacketFrameData {
            ifindex: f.ifindex,
            protocol: f.protocol,
            bytes: f.bytes,
            original_len: f.original_len,
        }))
    }

    async fn packet_readiness(&self, socket: u64) -> Result<syscall::SocketReady, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let ready = service
            .packet_readiness(socket)
            .await
            .map_err(linux_errno_from_udp_error)?;
        Ok(syscall::SocketReady {
            readable: ready.readable,
            writable: ready.writable,
            hangup: ready.hangup,
        })
    }

    fn check_icmp_open(&self, is_raw: bool) -> Result<(), u64> {
        const EPERM: u64 = 1;
        const EACCES: u64 = 13;
        if is_raw {
            if self.shared.grants.network_admin.is_none() {
                return Err(EPERM);
            }
        } else if self.shared.grants.udp.is_none() {
            return Err(EACCES);
        }
        if self.shared.runtime_state.network_service().is_none() {
            return Err(syscall::ENETDOWN);
        }
        Ok(())
    }

    fn icmp_open(
        &self,
        family: helios_unix::SocketFamily,
        is_raw: bool,
    ) -> Result<
        (
            Arc<helios_unix::OwnedIcmpSocket<crate::UnixNetwork<Net>>>,
            u16,
        ),
        u64,
    > {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let ipv6 = family == helios_unix::SocketFamily::Ipv6;
        let (id, local_id) = service
            .icmp_open(ipv6, is_raw)
            .map_err(linux_errno_from_udp_error)?;
        Ok((
            helios_unix::OwnedIcmpSocket::new(crate::UnixNetwork::new(service), id),
            local_id,
        ))
    }

    fn icmp_bind(&self, socket: u64, requested_id: u16) -> Result<u16, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .icmp_bind(socket, requested_id)
            .map_err(linux_errno_from_udp_error)
    }

    async fn icmp_send<'a>(
        &'a self,
        socket: u64,
        destination: syscall::IpAddr,
        identifier: u16,
        sequence: u16,
        payload: &'a [u8],
        hop_limit: u8,
    ) -> Result<(), u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        service
            .icmp_send(
                socket,
                linux_to_network_ip(destination),
                identifier,
                sequence,
                payload,
                hop_limit,
            )
            .await
            .map_err(linux_errno_from_udp_error)
    }

    async fn icmp_receive(
        &self,
        socket: u64,
        timeout_nanos: u64,
        peek: bool,
    ) -> Result<Option<syscall::IcmpDatagram>, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let datagram = service
            .icmp_receive(socket, timeout_nanos, peek)
            .await
            .map_err(linux_errno_from_udp_error)?;
        Ok(datagram.map(|d| syscall::IcmpDatagram {
            source: network_to_linux_ip(d.source),
            destination: network_to_linux_ip(d.destination),
            ttl: d.ttl,
            payload: d.payload,
        }))
    }

    async fn icmp_readiness(&self, socket: u64) -> Result<syscall::SocketReady, u64> {
        let service = self
            .shared
            .runtime_state
            .network_service()
            .ok_or(syscall::ENETDOWN)?;
        let ready = service
            .icmp_readiness(socket)
            .await
            .map_err(linux_errno_from_udp_error)?;
        Ok(syscall::SocketReady {
            readable: ready.readable,
            writable: ready.writable,
            hangup: ready.hangup,
        })
    }

    async fn vsock_accept(
        &self,
        listener: u64,
        timeout_nanos: u64,
    ) -> Result<syscall::AcceptedVsockStream<crate::UnixNetwork<Net>>, u64> {
        let vsock = self
            .shared
            .runtime_state
            .vsock_service()
            .ok_or(syscall::ENETDOWN)?;
        let listener_id = crate::VsockListenerId::from_u64(listener);
        let stream_id = if timeout_nanos == 0 {
            vsock
                .try_accept(listener_id)
                .map_err(linux_errno_from_vsock_error)?
                .ok_or(syscall::EAGAIN)?
        } else {
            vsock
                .accept(listener_id, timeout_nanos)
                .await
                .map_err(linux_errno_from_vsock_error)?
        };
        let local = vsock
            .local(stream_id)
            .map_err(linux_errno_from_vsock_error)?;
        let peer = vsock
            .peer(stream_id)
            .map_err(linux_errno_from_vsock_error)?;
        let net = crate::UnixNetwork::with_vsock(
            self.shared.runtime_state.network_service(),
            Some(vsock),
        );
        let owned = OwnedVsockStream::new(net, stream_id.as_u64());
        Ok(syscall::AcceptedVsockStream {
            stream: owned,
            local_cid: local.cid as u32,
            local_port: local.port,
            peer_cid: peer.cid as u32,
            peer_port: peer.port,
        })
    }

    async fn vsock_read(
        &self,
        stream: u64,
        max_bytes: usize,
        timeout_nanos: u64,
    ) -> Result<Option<Bytes>, u64> {
        let vsock = self
            .shared
            .runtime_state
            .vsock_service()
            .ok_or(syscall::ENETDOWN)?;
        let bytes = vsock
            .read(
                crate::VsockStreamId::from_u64(stream),
                max_bytes,
                timeout_nanos,
            )
            .await
            .map_err(linux_errno_from_vsock_error)?;
        Ok(bytes.map(Bytes::from))
    }

    async fn vsock_write(
        &self,
        stream: u64,
        bytes: Bytes,
        timeout_nanos: u64,
    ) -> Result<usize, u64> {
        let vsock = self
            .shared
            .runtime_state
            .vsock_service()
            .ok_or(syscall::ENETDOWN)?;
        vsock
            .write(
                crate::VsockStreamId::from_u64(stream),
                &bytes,
                timeout_nanos,
            )
            .await
            .map_err(linux_errno_from_vsock_error)
    }

    async fn vsock_shutdown(&self, stream: u64, read: bool, write: bool) -> Result<(), u64> {
        let vsock = self
            .shared
            .runtime_state
            .vsock_service()
            .ok_or(syscall::ENETDOWN)?;
        vsock
            .shutdown(
                crate::VsockStreamId::from_u64(stream),
                helios_hal::vsock::VsockShutdown {
                    receive: read,
                    send: write,
                },
            )
            .await
            .map_err(linux_errno_from_vsock_error)
    }

    async fn vsock_listener_readiness(&self, listener: u64) -> Result<syscall::SocketReady, u64> {
        let vsock = self
            .shared
            .runtime_state
            .vsock_service()
            .ok_or(syscall::ENETDOWN)?;
        let readable = vsock
            .listener_readable(crate::VsockListenerId::from_u64(listener))
            .map_err(linux_errno_from_vsock_error)?;
        Ok(syscall::SocketReady {
            readable,
            writable: false,
            hangup: false,
        })
    }

    async fn vsock_stream_readiness(&self, stream: u64) -> Result<syscall::SocketReady, u64> {
        let vsock = self
            .shared
            .runtime_state
            .vsock_service()
            .ok_or(syscall::ENETDOWN)?;
        let ready = vsock
            .stream_readiness(crate::VsockStreamId::from_u64(stream))
            .map_err(linux_errno_from_vsock_error)?;
        Ok(syscall::SocketReady {
            readable: ready.readable,
            writable: ready.writable,
            hangup: ready.hangup,
        })
    }
}

fn linux_errno_from_vsock_error(error: crate::VsockError) -> u64 {
    match error {
        crate::VsockError::Timeout => syscall::ETIMEDOUT,
        crate::VsockError::ConnectionRefused => syscall::ECONNREFUSED,
        crate::VsockError::ConnectionReset => syscall::ECONNRESET,
        crate::VsockError::Closed | crate::VsockError::UnknownHandle => syscall::EPIPE,
        crate::VsockError::PortInUse { .. }
        | crate::VsockError::NoEphemeralPort
        | crate::VsockError::ListenerTableFull
        | crate::VsockError::ConnectionTableFull => syscall::EADDRINUSE,
        crate::VsockError::Unavailable => syscall::ENETDOWN,
        crate::VsockError::Device(_) => 5, // EIO
    }
}

fn linux_errno_from_control_error(error: NetworkControlError) -> u64 {
    const EINVAL: u64 = 22;
    const EIO: u64 = 5;
    const EOPNOTSUPP: u64 = 95;
    match error {
        NetworkControlError::PortUnavailable => syscall::ENODEV,
        NetworkControlError::BridgeUnavailable => EOPNOTSUPP,
        NetworkControlError::InvalidBridgeRequest
        | NetworkControlError::InvalidAddress
        | NetworkControlError::InvalidRoute
        | NetworkControlError::RouteTimestampOutOfRange => EINVAL,
        NetworkControlError::BackendFault => EIO,
    }
}

use super::parse_shebang;

fn map_fs_error_to_exec(error: helios_hal::fs::FsError) -> ExecError {
    use helios_hal::fs::FsError;
    match error {
        FsError::NoEntry => ExecError::NoEntry,
        FsError::NotPermitted => ExecError::Access,
        FsError::NotDirectory => ExecError::NotDir,
        FsError::IsDirectory => ExecError::IsDir,
        FsError::Loop => ExecError::Loop,
        FsError::NameTooLong => ExecError::NameTooLong,
        FsError::NoSpace => ExecError::OutOfMemory,
        _ => ExecError::Io,
    }
}

fn map_program_error_to_exec(error: &ProgramExecError) -> ExecError {
    match error.kind {
        ProgramExecErrorKind::NotFound => ExecError::NoEntry,
        ProgramExecErrorKind::PermissionDenied => ExecError::Access,
        ProgramExecErrorKind::InvalidPath => ExecError::NoEntry,
        ProgramExecErrorKind::InvalidBinary | ProgramExecErrorKind::InvalidHint => {
            ExecError::InvalidFormat
        }
        ProgramExecErrorKind::OutOfMemory => ExecError::OutOfMemory,
        _ => ExecError::Io,
    }
}

enum ExecTarget {
    Path { base_dir: String, raw_path: String },
    Resolved(String),
}

fn map_fs_op_error_to_exec(error: syscall::FsOpError) -> ExecError {
    match error {
        syscall::FsOpError::Fs(error) => map_fs_error_to_exec(error),
        syscall::FsOpError::PermissionDenied | syscall::FsOpError::NoDevice => ExecError::Access,
        syscall::FsOpError::NoData | syscall::FsOpError::Range | syscall::FsOpError::ArgTooBig => {
            ExecError::Io
        }
    }
}

fn apply_chroot_to_exec_path(root: &str, raw_path: &str) -> String {
    if root == "/" || !raw_path.starts_with('/') {
        return String::from(raw_path);
    }
    let mut rel: Vec<&str> = Vec::new();
    for seg in raw_path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                let _ = rel.pop();
            }
            part => rel.push(part),
        }
    }
    let trimmed = root.trim_end_matches('/');
    if rel.is_empty() {
        String::from(trimmed)
    } else {
        alloc::format!("{trimmed}/{}", rel.join("/"))
    }
}

fn resolve_exec_spec_base<Net: ComponentHostNetwork>(
    spec: &ExecSpec,
    cwd: &Arc<spin::Mutex<String>>,
    root: &Arc<spin::Mutex<String>>,
    descriptors: &Arc<spin::Mutex<Descriptors<LinuxResources<Net>>>>,
) -> Result<ExecTarget, ExecError> {
    const AT_FDCWD: i32 = -100;
    if spec.path.starts_with('/') {
        let root_dir = root.lock().clone();
        return Ok(ExecTarget::Path {
            base_dir: String::from("/"),
            raw_path: apply_chroot_to_exec_path(&root_dir, &spec.path),
        });
    }
    if spec.dirfd == AT_FDCWD {
        if spec.path.is_empty() {
            return Err(ExecError::NoEntry);
        }
        return Ok(ExecTarget::Path {
            base_dir: cwd.lock().clone(),
            raw_path: spec.path.clone(),
        });
    }
    let entry = descriptors
        .lock()
        .get_entry(spec.dirfd)
        .cloned()
        .ok_or(ExecError::BadFd)?;
    let desc = match &entry.descriptor {
        helios_unix::FileDescriptor::File(open) => open.node(),
        helios_unix::FileDescriptor::Preopen { descriptor, .. } => descriptor,
        _ => {
            return Err(if spec.path.is_empty() && spec.flags & AT_EMPTY_PATH != 0 {
                ExecError::Access
            } else {
                ExecError::NotDir
            });
        }
    };
    if spec.path.is_empty() {
        if spec.flags & AT_EMPTY_PATH == 0 {
            return Err(ExecError::NoEntry);
        }
        if desc.kind == crate::ComponentFsNodeKind::Directory {
            return Err(ExecError::Access);
        }
        return Ok(ExecTarget::Resolved(desc.path.clone()));
    }
    if desc.kind != crate::ComponentFsNodeKind::Directory {
        return Err(ExecError::NotDir);
    }
    Ok(ExecTarget::Path {
        base_dir: desc.path.clone(),
        raw_path: spec.path.clone(),
    })
}

async fn prepare_exec_in_container<CpuImpl, Net, StorageImpl>(
    shared: &LinuxShared<CpuImpl, Net, StorageImpl, <CpuImpl::Native as NativeExecution>::Space>,
    cwd: &Arc<spin::Mutex<String>>,
    root: &Arc<spin::Mutex<String>>,
    descriptors: &Arc<spin::Mutex<Descriptors<LinuxResources<Net>>>>,
    credentials: &Arc<spin::Mutex<syscall::Credentials>>,
    spec: ExecSpec,
) -> Result<PreparedExec<CpuImpl, Net, StorageImpl>, ExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    const MAX_SHEBANG_DEPTH: usize = 4;
    let current_creds = credentials.lock().clone();
    let root_dir = root.lock().clone();
    let mut target = resolve_exec_spec_base(&spec, cwd, root, descriptors)?;
    let mut argv = spec.argv;
    let envp = spec.envp;
    let mut nofollow = spec.flags & AT_SYMLINK_NOFOLLOW != 0;

    for depth in 0..=MAX_SHEBANG_DEPTH {
        let fs = shared.container.filesystem();
        let (resolved, trailing_slash) = match &target {
            ExecTarget::Resolved(path) => (fs.resolve(path).map_err(map_fs_error_to_exec)?, false),
            ExecTarget::Path { base_dir, raw_path } => fs
                .walk_path_for_caller(
                    base_dir,
                    raw_path,
                    !nofollow,
                    &current_creds,
                    Some(crate::ProcCaller {
                        pid: shared.pid.get(),
                        tid: shared.pid.get(),
                    }),
                )
                .await
                .map_err(map_fs_op_error_to_exec)?,
        };
        let meta = resolved
            .fs()
            .stat(resolved.fs_path())
            .await
            .map_err(map_fs_error_to_exec)?;
        if meta.kind == NodeKind::Symlink {
            return Err(ExecError::Loop);
        }
        nofollow = false;
        if meta.kind == NodeKind::Directory {
            return Err(ExecError::Access);
        }
        if trailing_slash {
            return Err(ExecError::NotDir);
        }
        if meta.kind != NodeKind::File {
            return Err(ExecError::Access);
        }
        let current_path = resolved.container_path().to_owned();

        let contents = resolved
            .check_exec_and_read(&current_creds)
            .await
            .map_err(map_fs_op_error_to_exec)?;

        let raw_slice = match &contents {
            FileContents::Boot(boot) => boot.as_slice(),
            FileContents::Written(written) => written.as_ref(),
        };
        if let Some((interp, opt_arg)) = parse_shebang(raw_slice) {
            if depth == MAX_SHEBANG_DEPTH {
                return Err(ExecError::Loop);
            }
            let mut next_argv = Vec::with_capacity(argv.len() + 2);
            next_argv.push(interp.clone());
            if let Some(arg) = opt_arg {
                next_argv.push(arg);
            }
            next_argv.push(current_path);
            if argv.len() > 1 {
                next_argv.extend(argv.into_iter().skip(1));
            }
            argv = next_argv;
            target = ExecTarget::Path {
                base_dir: cwd.lock().clone(),
                raw_path: apply_chroot_to_exec_path(&root_dir, &interp),
            };
            continue;
        }

        let source = ProgramSource::from_file(contents);
        match source {
            ProgramSource::LinuxElf(bytes) => {
                let parsed_main = LinuxExecutable::load(&shared.cpu, bytes.clone())
                    .map_err(|error| map_program_error_to_exec(&error))?;
                let interp_path = parsed_main
                    .interpreter_path(&shared.cpu)
                    .map_err(|error| map_program_error_to_exec(&error))?;
                let interpreter = if let Some(interp_path) = interp_path {
                    let interp_base_dir = cwd.lock().clone();
                    let chroot_interp = apply_chroot_to_exec_path(&root_dir, &interp_path);
                    Some(
                        Box::pin(read_interpreter_in_container(
                            fs,
                            &interp_base_dir,
                            &chroot_interp,
                            &current_creds,
                        ))
                        .await
                        .map_err(map_fs_op_error_to_exec)?,
                    )
                } else {
                    None
                };
                let execfn = if spec.path.is_empty() {
                    current_path.clone()
                } else {
                    spec.path.clone()
                };
                let executable = LinuxExecutable::load_with_interpreter(
                    &shared.cpu,
                    bytes,
                    interpreter,
                    Some(execfn),
                )
                .map_err(|error| map_program_error_to_exec(&error))?;
                // Compute post-execve credentials strictly for the final binary
                // (never an intermediate `#!` script, `fs/binfmt_script.c`),
                // respecting `NO_SUID`, `PR_SET_NO_NEW_PRIVS`, and the
                // container's `ProcessAuthority` capability ceiling.
                let next_creds = resolved
                    .exec_credentials(&current_creds, shared.container.authority_cap_ceiling())
                    .await
                    .map_err(map_fs_op_error_to_exec)?;
                let secure = syscall::permissions::exec_is_secure(&current_creds, &next_creds);
                let exe_path = current_path.clone();
                if argv.is_empty() {
                    argv.push(current_path);
                }
                return Ok(PreparedExec::Linux {
                    executable,
                    exe_path,
                    argv,
                    env: envp,
                    credentials: next_creds,
                    secure,
                });
            }
            other => {
                if shared.exec_runtime.wasm.is_none() {
                    return Err(ExecError::InvalidFormat);
                }
                let Some(program_service) = shared.runtime_state.program_service() else {
                    return Err(ExecError::InvalidFormat);
                };
                let exec_auth = shared
                    .container
                    .authority()
                    .derive_exec_authority()
                    .map_err(|_| ExecError::Access)?;
                let compile = CompileAuthority::from(&exec_auth);
                let program_argv = ProgramArgv::from_caller(&current_path, argv);
                let timeline = phases::Timeline::disabled();
                let executable = program_service
                    .load_executable(
                        &compile,
                        &shared.exec_runtime.exec_context,
                        program_argv.program_name(),
                        &other,
                        None,
                        &timeline,
                    )
                    .await
                    .map_err(|error| map_program_error_to_exec(&error))?;
                let parsed_env: Vec<(String, String)> = envp
                    .into_iter()
                    .filter_map(|entry| {
                        entry
                            .split_once('=')
                            .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    })
                    .collect();
                return Ok(PreparedExec::Wasm {
                    executable,
                    argv: program_argv,
                    env: parsed_env,
                });
            }
        }
    }
    Err(ExecError::Loop)
}

/// Calling thread's context view for `arch_prctl`, `clone` / `clone3`, `fork`,
/// `vfork`, `execve`, and `execveat`.
struct ContextThread<'a, CpuImpl, Net, StorageImpl, Context: UserContext>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    context: &'a mut Context,
    shared: &'a Arc<LinuxShared<CpuImpl, Net, StorageImpl, Context::Space>>,
    cwd: Arc<spin::Mutex<String>>,
    root: Arc<spin::Mutex<String>>,
    descriptors: Arc<spin::Mutex<Descriptors<LinuxResources<Net>>>>,
    credentials: Arc<spin::Mutex<syscall::Credentials>>,
    prepared_exec: &'a mut Option<Box<PreparedExec<CpuImpl, Net, StorageImpl>>>,
}

impl<CpuImpl, Net, StorageImpl> Thread<LinuxResources<Net>>
    for ContextThread<'_, CpuImpl, Net, StorageImpl, <CpuImpl::Native as NativeExecution>::Context>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn thread_pointer(&self) -> u64 {
        self.context.thread_pointer().raw() as u64
    }

    fn set_thread_pointer(&mut self, address: u64) -> Result<(), Denied> {
        self.context
            .set_thread_pointer(VirtAddr::new(address as usize))
            .map_err(|_| Denied)
    }

    fn stack_pointer(&self) -> u64 {
        self.context
            .register(self.shared.abi.stack_pointer_register())
            .expect("the ABI names registers of this instruction set")
    }

    fn spawn_thread(
        &mut self,
        child: Process<LinuxResources<Net>>,
        state: SpawnedThread,
    ) -> Result<(), SpawnError> {
        let mut child_context = self
            .context
            .try_clone()
            .map_err(|_| SpawnError::OutOfMemory)?;
        if let Some(tls) = state.tls {
            child_context
                .set_thread_pointer(VirtAddr::new(tls as usize))
                .map_err(|_| SpawnError::InvalidTls)?;
        }
        if let Some(stack) = state.stack {
            child_context
                .set_register(self.shared.abi.stack_pointer_register(), stack)
                .expect("the ABI names registers of this instruction set");
        }
        child_context
            .set_register(self.shared.registers.result, 0)
            .expect("the ABI names registers of this instruction set");
        let child_tid = child.tid().get();
        let child_pid = self.shared.pid.get();
        let comm = process_comm_from_exe(&self.shared.exe_path);
        self.shared.container.proc_registry().register_thread(
            child_pid,
            crate::ProcThreadRecord {
                tid: child_tid,
                comm,
                state: 'R',
                utime_ticks: 0,
                stime_ticks: 0,
            },
        );
        let thread_proc_guard = ProcThreadGuard {
            registry: self.shared.container.proc_registry().clone(),
            pid: child_pid,
            tid: child_tid,
        };
        let child_platform = LinuxThreadPlatform::new(self.shared.clone(), child.tid());
        let shared = self.shared.clone();
        let spawner = shared.spawner.clone();
        shared.running_tasks.fetch_add(1, Ordering::SeqCst);
        let guard = TaskDrainGuard(shared.clone());
        spawner
            .try_spawn_detached(async move {
                let _thread_proc_guard = thread_proc_guard;
                if let ThreadRunEnd::Exec(prepared, exec_proc) =
                    drive_linux_thread(child_context, child, child_platform).await
                {
                    let observer = exec_proc.observer();
                    let mut slot = shared.exec_handoff.lock();
                    if slot.is_none() {
                        *slot = Some((prepared, exec_proc));
                        drop(slot);
                        observer.terminate_group(helios_unix::ChildTermination::Exited(0));
                    }
                }
                drop(guard);
            })
            .map_err(|error| {
                tracing::warn!(
                    target: "helios_kernel::linux",
                    instance = ?self.shared.launched_instance.id(),
                    %error,
                    "refused a Linux thread: the executor's instance share is full"
                );
                SpawnError::Busy
            })
    }

    fn spawn_process(
        &mut self,
        spawned: SpawnedProcess<LinuxResources<Net>>,
    ) -> Result<(), SpawnError> {
        let mut child_context = self
            .context
            .try_clone()
            .map_err(|_| SpawnError::OutOfMemory)?;
        if let Some(tls) = spawned.tls {
            child_context
                .set_thread_pointer(VirtAddr::new(tls as usize))
                .map_err(|_| SpawnError::InvalidTls)?;
        }
        if let Some(stack) = spawned.stack {
            child_context
                .set_register(self.shared.abi.stack_pointer_register(), stack)
                .expect("the ABI names registers of this instruction set");
        }
        child_context
            .set_register(self.shared.registers.result, 0)
            .expect("the ABI names registers of this instruction set");

        let child_space = if spawned.share_vm {
            self.shared.space.clone()
        } else {
            Arc::new(
                self.shared
                    .space
                    .clone_cow()
                    .map_err(|_| SpawnError::OutOfMemory)?,
            )
        };
        if let Some(addr) = spawned.child_tid_addr {
            let pid_val = spawned.child.pid().get();
            if addr & 3 == 0 {
                let _ = child_space.atomic_store_u32(VirtAddr::new(addr as usize), pid_val);
            } else {
                let _ = child_space.write(VirtAddr::new(addr as usize), &pid_val.to_le_bytes());
            }
        }

        let exec_context = &self.shared.exec_runtime.exec_context;
        let started_at = exec_context
            .runtime_state
            .uptime_nanos(exec_context.cpu.now().ticks());
        let child_name = alloc::format!("linux-pid-{}", spawned.child.pid().get());
        let child_instance = exec_context.instance_registry.register_child(
            Some(self.shared.launched_instance.id()),
            child_name,
            started_at,
        );
        let child_spawner = exec_context
            .spawner
            .instance_spawner(crate::TaskFunding::Instance, &child_instance);
        let child_shared_mem = if spawned.share_vm {
            self.shared.shared_mem.clone()
        } else {
            Arc::new(spin::Mutex::new(self.shared.shared_mem.lock().clone()))
        };
        let child_signal_state = WasixSignalState::new();
        let child_shared = Arc::new(LinuxShared {
            cpu: self.shared.cpu.clone(),
            timer: self.shared.timer.clone(),
            spawner: child_spawner.clone(),
            runtime_state: self.shared.runtime_state.clone(),
            exec_runtime: self.shared.exec_runtime.clone(),
            read_serial: self.shared.read_serial,
            write_serial: self.shared.write_serial,
            output_mode: self.shared.output_mode.clone(),
            launched_instance: child_instance,
            signal_state: child_signal_state,
            container: self.shared.container.clone(),
            grants: LinuxGrants::derive(self.shared.container.authority()),
            pid: spawned.child.pid(),
            ppid: self.shared.pid.get(),
            exe_path: self.shared.exe_path.clone(),
            argv: self.shared.argv.clone(),
            env: self.shared.env.clone(),
            cwd_handle: spawned.child.cwd_handle(),
            descriptors_handle: spawned.child.descriptors_handle(),
            credentials_handle: spawned.child.credentials_handle(),
            proc_signals: spawned.child.process_signals(),
            tty: spin::Mutex::new(self.shared.tty.lock().clone()),
            serial_peek: spin::Mutex::new(Vec::new()),
            clock: spin::Mutex::new(crate::KernelClock::new(
                self.shared.cpu.clone(),
                self.shared.runtime_state.clone(),
            )),
            abi: self.shared.abi,
            registers: self.shared.registers,
            user: self.shared.user,
            stack_top: self.shared.stack_top,
            stack_base: self.shared.stack_base,
            image_end: self.shared.image_end,
            sigreturn_trampoline: self.shared.sigreturn_trampoline,
            space: child_space,
            shared_mem: child_shared_mem,
            process_cpu_ticks: AtomicU64::new(0),
            process_sys_ticks: AtomicU64::new(0),
            peak_rss_kib: AtomicU64::new(0),
            syslog_cursor: spin::Mutex::new(0),
            syslog_clear_after: AtomicU64::new(0),
            fatal_error: spin::Mutex::new(None),
            exec_handoff: spin::Mutex::new(None),
            running_tasks: AtomicUsize::new(0),
            tasks_drained: helios_sync::Notify::new(),
        });

        let child_proc = spawned.child;
        let child_pid = child_proc.pid();
        let container = self.shared.container.clone();
        child_spawner
            .try_spawn_detached(async move {
                let mut guard = ChildExitSafetyGuard {
                    pids: container.pid_namespace().clone(),
                    pid: child_pid,
                    completed: false,
                };
                let outcome = Box::pin(drive_linux_process_lifecycle(
                    child_context,
                    child_proc,
                    child_shared,
                    None,
                    phases::Timeline::disabled(),
                ))
                .await;
                let termination = match outcome {
                    Ok(exit) => exit.termination,
                    Err(_) => helios_unix::ChildTermination::Killed,
                };
                guard.completed = true;
                container
                    .pid_namespace()
                    .mark_exited(child_pid, termination);
            })
            .map_err(|error| {
                tracing::warn!(
                    target: "helios_kernel::linux",
                    instance = ?self.shared.launched_instance.id(),
                    %error,
                    "refused a forked Linux child: the executor's instance share is full"
                );
                SpawnError::Busy
            })
    }

    async fn prepare_exec(&mut self, spec: ExecSpec) -> Result<(), ExecError> {
        let prepared = Box::pin(prepare_exec_in_container(
            self.shared,
            &self.cwd,
            &self.root,
            &self.descriptors,
            &self.credentials,
            spec,
        ))
        .await?;
        *self.prepared_exec = Some(Box::new(prepared));
        Ok(())
    }
}

/// Safety net ensuring a forked child process transitions to exited state even
/// if its executor task is cancelled before normal completion.
struct ChildExitSafetyGuard {
    pids: syscall::PidNamespace,
    pid: NonZeroU32,
    completed: bool,
}

impl Drop for ChildExitSafetyGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.pids
                .mark_exited(self.pid, helios_unix::ChildTermination::Killed);
        }
    }
}

/// What ended a thread's execution loop.
enum ThreadRunEnd<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    Exited,
    Exec(
        Box<PreparedExec<CpuImpl, Net, StorageImpl>>,
        Process<LinuxResources<Net>>,
    ),
}

/// What ended a system call a thread was suspended in.
enum CallEnd {
    Done(ControlFlow<Exit, SyscallOutcome>),
    /// Thread-group exit or instance kill arrived; the loop's next check acts
    /// on it.
    Stopped,
}

fn forward_external_signals(process_signals: &ProcessSignals, external_signals: &WasixSignalState) {
    while let Some(signal) = external_signals.take_pending() {
        process_signals.raise_external(signal);
    }
}

fn check_thread_stop<CpuImpl, Net, StorageImpl, Space>(
    process: &mut Process<LinuxResources<Net>>,
    shared: &LinuxShared<CpuImpl, Net, StorageImpl, Space>,
) -> bool
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if let Some(reason) = shared.launched_instance.pending_kill() {
        match reason {
            crate::KillReason::Operator | crate::KillReason::RequesterGone => {
                process.terminate_group(helios_unix::ChildTermination::Killed);
            }
            crate::KillReason::OutOfMemory
            | crate::KillReason::SupervisorRestart
            | crate::KillReason::StoreFailed => {
                shared.record_fatal(map_program_runtime_error(wasmtime::Error::from(
                    crate::InstanceKilled { reason },
                )));
                process.terminate_group(helios_unix::ChildTermination::Killed);
            }
        }
        return true;
    }
    if process.group_ended() {
        return true;
    }
    forward_external_signals(&process.process_signals(), &shared.signal_state);
    false
}

/// Parks the thread while its process is stopped (`SIGSTOP`/`SIGTSTP`/etc.)
/// until `SIGCONT`, `SIGKILL`, group termination, or an instance kill arrives.
async fn wait_while_stopped<CpuImpl, Net, StorageImpl, Space>(
    process: &mut Process<LinuxResources<Net>>,
    shared: &LinuxShared<CpuImpl, Net, StorageImpl, Space>,
    observer: &syscall::ProcessObserver,
) -> bool
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let proc_signals = process.process_signals();
    loop {
        if check_thread_stop(process, shared) {
            return true;
        }
        let mut stop_wait = proc_signals.stop_waiter();
        let mut group_wait = observer.waiter();
        let mut signal_wait = shared.signal_state.wait_state();
        let mut kill_wait = shared.launched_instance.arm_kill_wait();
        forward_external_signals(&proc_signals, &shared.signal_state);
        if !proc_signals.is_stopped() {
            return false;
        }
        if check_thread_stop(process, shared) {
            return true;
        }
        core::future::poll_fn(|cx| {
            let resumed = proc_signals
                .poll_stop_changed(cx, &mut stop_wait)
                .is_ready();
            let group_stopped = observer.poll_changed(cx, &mut group_wait).is_ready();
            let signalled = shared
                .signal_state
                .poll_changed(cx, &mut signal_wait)
                .is_ready();
            let killed = shared
                .launched_instance
                .poll_kill_wait(cx, &mut kill_wait)
                .is_ready();
            if resumed || group_stopped || signalled || killed {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

/// Applies signal delivery on return to user mode. Returns `true` when the
/// thread group was terminated and the driving loop should exit.
fn deliver_and_apply<CpuImpl, Net, StorageImpl, Context>(
    process: &mut Process<LinuxResources<Net>>,
    context: &mut Context,
    shared: &LinuxShared<CpuImpl, Net, StorageImpl, Context::Space>,
    restart: Option<SyscallRestart>,
) -> bool
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    Context: UserContext,
{
    let mut memory = LinuxMemory {
        space: &*shared.space,
        user: shared.user,
        stack_growth: Some(shared.stack_growth(process.limit(Resource::Stack).current)),
        shared_mem: Some(&shared.shared_mem),
        shared_files: Some(shared.container.shared_files()),
    };
    match process.deliver_pending_signals(
        context,
        &mut memory,
        restart,
        shared.sigreturn_trampoline,
    ) {
        SignalDelivery::None | SignalDelivery::Delivered => false,
        SignalDelivery::Stopped(signal) => {
            process.mark_stopped(signal);
            false
        }
        SignalDelivery::Terminated { signal, .. } => {
            // No core dump file is produced (`RLIMIT_CORE` default is 0), so
            // `WCOREDUMP` stays false as on Linux.
            process.terminate_group(helios_unix::ChildTermination::Signaled(
                helios_unix::SignalTermination {
                    signal: signal.raw(),
                    core_dumped: false,
                },
            ));
            true
        }
    }
}

/// Delivers an unresolvable hardware fault as a Linux signal (`force_sig_fault`
/// semantics). Returns `true` when the thread group terminated.
fn handle_unresolvable_fault<CpuImpl, Net, StorageImpl, Context>(
    process: &mut Process<LinuxResources<Net>>,
    context: &mut Context,
    shared: &LinuxShared<CpuImpl, Net, StorageImpl, Context::Space>,
    instance_id: crate::InstanceId,
    mut fault: UserFault,
) -> bool
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    Context: UserContext,
{
    // Linux decides `SEGV_MAPERR` vs `SEGV_ACCERR` from VMA presence rather
    // than hardware PTE residency: a first write to a lazy-committed `PROT_READ`
    // or `PROT_NONE` mapping faults with `present == false` in hardware yet
    // delivers `SEGV_ACCERR` because the mapping exists.
    if let FaultKind::Page {
        address,
        present: ref mut present @ false,
        ..
    } = fault.kind
        && shared.user.contains(address)
        && shared
            .space
            .mapping(VirtRange::new(address.page_floor(), PhysFrame::SIZE))
            .is_some()
    {
        *present = true;
    }
    let mut memory = LinuxMemory {
        space: &*shared.space,
        user: shared.user,
        stack_growth: Some(shared.stack_growth(process.limit(Resource::Stack).current)),
        shared_mem: Some(&shared.shared_mem),
        shared_files: Some(shared.container.shared_files()),
    };
    match process.deliver_fault_signal(fault, context, &mut memory, shared.sigreturn_trampoline) {
        SignalDelivery::Delivered => false,
        SignalDelivery::Terminated { signal, .. } => {
            tracing::debug!(
                target: "helios_kernel::linux",
                instance = ?instance_id,
                tid = process.tid().get(),
                ?fault,
                signal = signal.raw(),
                "Linux thread faulted"
            );
            process.terminate_group(helios_unix::ChildTermination::Signaled(
                helios_unix::SignalTermination {
                    signal: signal.raw(),
                    core_dumped: false,
                },
            ));
            true
        }
        SignalDelivery::None | SignalDelivery::Stopped(_) => false,
    }
}

/// Delivers `SIGBUS` (`BUS_ADRERR`) for an access beyond the backing file's end.
/// Returns `true` when the thread group terminated.
fn handle_bus_fault<CpuImpl, Net, StorageImpl, Context>(
    process: &mut Process<LinuxResources<Net>>,
    context: &mut Context,
    shared: &LinuxShared<CpuImpl, Net, StorageImpl, Context::Space>,
    instance_id: crate::InstanceId,
    address: VirtAddr,
) -> bool
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
    Context: UserContext,
{
    let mut memory = LinuxMemory {
        space: &*shared.space,
        user: shared.user,
        stack_growth: Some(shared.stack_growth(process.limit(Resource::Stack).current)),
        shared_mem: Some(&shared.shared_mem),
        shared_files: Some(shared.container.shared_files()),
    };
    match process.deliver_bus_fault(
        address.raw() as u64,
        context,
        &mut memory,
        shared.sigreturn_trampoline,
    ) {
        SignalDelivery::Delivered => false,
        SignalDelivery::Terminated { signal, .. } => {
            tracing::debug!(
                target: "helios_kernel::linux",
                instance = ?instance_id,
                tid = process.tid().get(),
                ?address,
                signal = signal.raw(),
                "Linux thread received SIGBUS"
            );
            process.terminate_group(helios_unix::ChildTermination::Signaled(
                helios_unix::SignalTermination {
                    signal: signal.raw(),
                    core_dumped: false,
                },
            ));
            true
        }
        SignalDelivery::None | SignalDelivery::Stopped(_) => false,
    }
}

/// Drives one Linux thread (`main` or a `clone`-spawned worker) until that
/// thread exits (`exit`), condemns the group (`exit_group`, unhandled fault,
/// OOM), commits an `execve`/`execveat` replacement, or observes condemnation
/// from a sibling, signal or kill.
async fn drive_linux_thread<CpuImpl, Net, StorageImpl>(
    mut context: <CpuImpl::Native as NativeExecution>::Context,
    mut process: Process<LinuxResources<Net>>,
    mut platform: LinuxThreadPlatform<
        CpuImpl,
        Net,
        StorageImpl,
        <CpuImpl::Native as NativeExecution>::Space,
    >,
) -> ThreadRunEnd<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let shared = platform.shared.clone();
    let observer = process.observer();
    let proc_signals = process.process_signals();
    let instance_id = shared.launched_instance.id();
    let registers = shared.registers;
    loop {
        if check_thread_stop(&mut process, &shared) {
            break;
        }
        if process.is_stopped() && wait_while_stopped(&mut process, &shared, &observer).await {
            break;
        }
        if deliver_and_apply(&mut process, &mut context, &shared, None) {
            break;
        }
        if process.is_stopped() {
            continue;
        }
        let slice_began = shared.cpu.now().ticks();
        let stop = context.resume(&shared.space);
        let elapsed = shared.cpu.now().ticks().saturating_sub(slice_began);
        platform.thread_cpu_ticks += elapsed;
        shared
            .process_cpu_ticks
            .fetch_add(elapsed, Ordering::Relaxed);
        let user_ns = shared.cpu.timebase().ticks_to_nanos(elapsed);
        process.account_cpu_timers(user_ns, user_ns);
        match stop {
            Stop::SystemCall => {
                let (call, orig_reg) = {
                    let read = |register| {
                        context
                            .register(register)
                            .expect("the ABI names registers of this instruction set")
                    };
                    (
                        Call {
                            number: read(registers.number),
                            arguments: registers.arguments.map(read),
                        },
                        read(registers.result),
                    )
                };
                // Arm every stop source before testing them so an `exit_group`,
                // signal or kill raised during the user slice cannot be missed
                // before `dispatch` suspends.
                let mut group_wait = observer.waiter();
                let mut signal_wait = shared.signal_state.wait_state();
                let mut kill_wait = shared.launched_instance.arm_kill_wait();
                if check_thread_stop(&mut process, &shared) {
                    break;
                }
                let syscall_began = shared.cpu.now().ticks();
                let mut prepared_exec = None;
                let ended = {
                    let mut memory = LinuxMemory {
                        space: &*shared.space,
                        user: shared.user,
                        stack_growth: Some(
                            shared.stack_growth(process.limit(Resource::Stack).current),
                        ),
                        shared_mem: Some(&shared.shared_mem),
                        shared_files: Some(shared.container.shared_files()),
                    };
                    let mut thread = ContextThread {
                        context: &mut context,
                        shared: &shared,
                        cwd: process.cwd_handle(),
                        root: process.root_handle(),
                        descriptors: process.descriptors_handle(),
                        credentials: process.credentials_handle(),
                        prepared_exec: &mut prepared_exec,
                    };
                    let mut call = core::pin::pin!(syscall::dispatch(
                        &mut process,
                        call,
                        &mut memory,
                        &mut thread,
                        &mut platform,
                    ));
                    core::future::poll_fn(|cx| {
                        // Forward any externally raised signals into Linux's
                        // signal mailbox so blocking syscalls observe them via
                        // their own `ThreadSignalSlot` and handle masks/EINTR.
                        if shared
                            .signal_state
                            .poll_changed(cx, &mut signal_wait)
                            .is_ready()
                        {
                            forward_external_signals(&proc_signals, &shared.signal_state);
                            signal_wait = shared.signal_state.wait_state();
                            let _ = shared.signal_state.poll_changed(cx, &mut signal_wait);
                        }
                        if let Poll::Ready(flow) = call.as_mut().poll(cx) {
                            return Poll::Ready(CallEnd::Done(flow));
                        }
                        let group_stopped = observer.poll_changed(cx, &mut group_wait).is_ready();
                        let killed = shared
                            .launched_instance
                            .poll_kill_wait(cx, &mut kill_wait)
                            .is_ready();
                        if group_stopped || killed {
                            Poll::Ready(CallEnd::Stopped)
                        } else {
                            Poll::Pending
                        }
                    })
                    .await
                };
                let sys_elapsed = shared.cpu.now().ticks().saturating_sub(syscall_began);
                platform.thread_sys_ticks += sys_elapsed;
                shared
                    .process_sys_ticks
                    .fetch_add(sys_elapsed, Ordering::Relaxed);
                let sys_ns = shared.cpu.timebase().ticks_to_nanos(sys_elapsed);
                process.account_cpu_timers(0, sys_ns);
                match ended {
                    CallEnd::Done(ControlFlow::Continue(SyscallOutcome::Return(result))) => {
                        context
                            .set_register(registers.result, result)
                            .expect("the ABI names registers of this instruction set");
                    }
                    CallEnd::Done(ControlFlow::Continue(SyscallOutcome::RestartSys)) => {
                        if deliver_and_apply(
                            &mut process,
                            &mut context,
                            &shared,
                            Some(SyscallRestart::RestartSys { orig_reg }),
                        ) {
                            break;
                        }
                    }
                    CallEnd::Done(ControlFlow::Continue(SyscallOutcome::RestartNoHand)) => {
                        if deliver_and_apply(
                            &mut process,
                            &mut context,
                            &shared,
                            Some(SyscallRestart::RestartNoHand { orig_reg }),
                        ) {
                            break;
                        }
                    }
                    CallEnd::Done(ControlFlow::Continue(SyscallOutcome::SigReturn)) => {
                        let memory = LinuxMemory {
                            space: &*shared.space,
                            user: shared.user,
                            stack_growth: None,
                            shared_mem: Some(&shared.shared_mem),
                            shared_files: Some(shared.container.shared_files()),
                        };
                        if process.restore_signal_frame(&mut context, &memory).is_err() {
                            process.terminate_group(helios_unix::ChildTermination::Signaled(
                                helios_unix::SignalTermination {
                                    signal: helios_unix::Signal::SIGSEGV.raw(),
                                    core_dumped: false,
                                },
                            ));
                            break;
                        }
                    }
                    CallEnd::Done(ControlFlow::Continue(SyscallOutcome::Exec)) => {
                        let memory = LinuxMemory {
                            space: &*shared.space,
                            user: shared.user,
                            stack_growth: None,
                            shared_mem: Some(&shared.shared_mem),
                            shared_files: Some(shared.container.shared_files()),
                        };
                        process.flush_shared_mappings(&memory, &mut platform).await;
                        let prepared = prepared_exec
                            .expect("SyscallOutcome::Exec follows Thread::prepare_exec");
                        return ThreadRunEnd::Exec(prepared, process);
                    }
                    CallEnd::Done(ControlFlow::Break(_)) => break,
                    CallEnd::Stopped => {}
                }
            }
            Stop::Preempted | Stop::Interrupted => crate::yield_now().await,
            Stop::Fault(fault) => match fault.kind {
                // An uncommitted page's first touch, a translation older than
                // the page's current access, or growth of the initial stack:
                // resolved atomically against concurrent sibling VM ops.
                FaultKind::Page {
                    address,
                    access,
                    present,
                } if shared.user.contains(address) => {
                    match shared.space.resolve_fault(address, access) {
                        Ok(()) => {}
                        Err(NativeError::OutOfMemory) => {
                            shared.record_fatal(native_error(NativeError::OutOfMemory));
                            process.terminate_group(helios_unix::ChildTermination::Killed);
                            break;
                        }
                        Err(NativeError::NotMapped)
                            if !present
                                && !access.contains(PageFlags::EXECUTE)
                                && shared
                                    .stack_growth(process.limit(Resource::Stack).current)
                                    .contains(address) =>
                        {
                            let page = VirtRange::new(address.page_floor(), PhysFrame::SIZE);
                            match shared
                                .space
                                .map(page, &[], PageFlags::READ | PageFlags::WRITE)
                            {
                                // Commit the new stack page in the same fault
                                // rather than taking a second fault on resume;
                                // `Overlap` means a sibling thread already
                                // mapped or grew this page concurrently.
                                Ok(()) | Err(NativeError::Overlap) => {
                                    match shared.space.resolve_fault(address, access) {
                                        Ok(()) => {}
                                        Err(NativeError::OutOfMemory) => {
                                            shared.record_fatal(native_error(
                                                NativeError::OutOfMemory,
                                            ));
                                            process.terminate_group(
                                                helios_unix::ChildTermination::Killed,
                                            );
                                            break;
                                        }
                                        Err(NativeError::NotMapped) => {
                                            if handle_unresolvable_fault(
                                                &mut process,
                                                &mut context,
                                                &shared,
                                                instance_id,
                                                fault,
                                            ) {
                                                break;
                                            }
                                        }
                                        Err(error) => panic!(
                                            "resolving a stack-growth fault on {page:?}: {error}"
                                        ),
                                    }
                                }
                                Err(NativeError::OutOfMemory) => {
                                    shared.record_fatal(native_error(NativeError::OutOfMemory));
                                    process.terminate_group(helios_unix::ChildTermination::Killed);
                                    break;
                                }
                                Err(error) => {
                                    panic!("growing a Linux stack into {page:?}: {error}")
                                }
                            }
                        }
                        Err(NativeError::BackingFault) => {
                            let page_va = address.page_floor();
                            match process.lookup_vma(address.raw() as u64) {
                                Some(syscall::VmaBacking::SharedAnon {
                                    start,
                                    object_id,
                                    object_offset,
                                }) => {
                                    let obj = shared.shared_mem.lock().get_object(object_id);
                                    let Some(obj) = obj else {
                                        if handle_unresolvable_fault(
                                            &mut process,
                                            &mut context,
                                            &shared,
                                            instance_id,
                                            fault,
                                        ) {
                                            break;
                                        }
                                        continue;
                                    };
                                    let page_idx = object_offset
                                        .saturating_add(page_va.raw() as u64 - start)
                                        / PhysFrame::SIZE as u64;
                                    match obj.get_or_alloc_frame(page_idx) {
                                        Ok(frame) => {
                                            match shared.space.attach_shared_frame(page_va, frame) {
                                                Ok(()) => {}
                                                Err(NativeError::OutOfMemory) => {
                                                    shared.record_fatal(native_error(
                                                        NativeError::OutOfMemory,
                                                    ));
                                                    process.terminate_group(
                                                        helios_unix::ChildTermination::Killed,
                                                    );
                                                    break;
                                                }
                                                Err(NativeError::NotMapped) => {
                                                    if handle_unresolvable_fault(
                                                        &mut process,
                                                        &mut context,
                                                        &shared,
                                                        instance_id,
                                                        fault,
                                                    ) {
                                                        break;
                                                    }
                                                }
                                                Err(error) => panic!(
                                                    "attaching shared anonymous frame at {page_va:?}: {error}"
                                                ),
                                            }
                                        }
                                        Err(NativeError::OutOfMemory) => {
                                            shared.record_fatal(native_error(
                                                NativeError::OutOfMemory,
                                            ));
                                            process.terminate_group(
                                                helios_unix::ChildTermination::Killed,
                                            );
                                            break;
                                        }
                                        Err(error) => panic!(
                                            "allocating shared anonymous frame at {page_va:?}: {error}"
                                        ),
                                    }
                                }
                                Some(syscall::VmaBacking::File(vma)) => {
                                    let page_file_off = vma
                                        .file_offset
                                        .saturating_add(page_va.raw() as u64 - vma.start);
                                    match syscall::Filesystem::stat_file(&platform, &vma.file).await
                                    {
                                        Ok(meta) => {
                                            let eof_page = meta
                                                .size
                                                .checked_add(PhysFrame::SIZE as u64 - 1)
                                                .map_or(u64::MAX, |n| {
                                                    n & !(PhysFrame::SIZE as u64 - 1)
                                                });
                                            if meta.size == 0 || page_file_off >= eof_page {
                                                if handle_bus_fault(
                                                    &mut process,
                                                    &mut context,
                                                    &shared,
                                                    instance_id,
                                                    address,
                                                ) {
                                                    break;
                                                }
                                            } else if vma.is_shared {
                                                let obj = shared
                                                    .shared_mem
                                                    .lock()
                                                    .get_object(vma.shared_object);
                                                let Some(obj) = obj else {
                                                    if handle_bus_fault(
                                                        &mut process,
                                                        &mut context,
                                                        &shared,
                                                        instance_id,
                                                        address,
                                                    ) {
                                                        break;
                                                    }
                                                    continue;
                                                };
                                                let page_idx =
                                                    page_file_off / PhysFrame::SIZE as u64;
                                                let frame_res =
                                                    if let Some(frame) = obj.get_frame(page_idx) {
                                                        Ok(frame)
                                                    } else {
                                                        match syscall::Filesystem::read_at(
                                                            &platform,
                                                            &vma.file,
                                                            page_file_off,
                                                            PhysFrame::SIZE,
                                                        )
                                                        .await
                                                        {
                                                            Ok(bytes) => {
                                                                obj.load_file_page(page_idx, &bytes)
                                                            }
                                                            Err(_) => {
                                                                if handle_bus_fault(
                                                                    &mut process,
                                                                    &mut context,
                                                                    &shared,
                                                                    instance_id,
                                                                    address,
                                                                ) {
                                                                    break;
                                                                }
                                                                continue;
                                                            }
                                                        }
                                                    };
                                                match frame_res {
                                                    Ok(frame) => match shared
                                                        .space
                                                        .attach_shared_frame(page_va, frame)
                                                    {
                                                        Ok(()) => {}
                                                        Err(NativeError::OutOfMemory) => {
                                                            shared.record_fatal(native_error(
                                                                NativeError::OutOfMemory,
                                                            ));
                                                            process.terminate_group(
                                                                helios_unix::ChildTermination::Killed,
                                                            );
                                                            break;
                                                        }
                                                        Err(NativeError::NotMapped) => {
                                                            if handle_unresolvable_fault(
                                                                &mut process,
                                                                &mut context,
                                                                &shared,
                                                                instance_id,
                                                                fault,
                                                            ) {
                                                                break;
                                                            }
                                                        }
                                                        Err(error) => panic!(
                                                            "attaching shared file frame at {page_va:?}: {error}"
                                                        ),
                                                    },
                                                    Err(NativeError::OutOfMemory) => {
                                                        shared.record_fatal(native_error(
                                                            NativeError::OutOfMemory,
                                                        ));
                                                        process.terminate_group(
                                                            helios_unix::ChildTermination::Killed,
                                                        );
                                                        break;
                                                    }
                                                    Err(error) => panic!(
                                                        "loading shared file frame at {page_va:?}: {error}"
                                                    ),
                                                }
                                            } else {
                                                match syscall::Filesystem::read_at(
                                                    &platform,
                                                    &vma.file,
                                                    page_file_off,
                                                    PhysFrame::SIZE,
                                                )
                                                .await
                                                {
                                                    Ok(bytes) => {
                                                        match crate::SharedPageObject::allocate_frame_from_bytes(&bytes)
                                                            .and_then(|frame| {
                                                                shared
                                                                    .space
                                                                    .install_private_frame(page_va, frame)
                                                            }) {
                                                            Ok(()) => {}
                                                            Err(NativeError::OutOfMemory) => {
                                                                shared.record_fatal(native_error(
                                                                    NativeError::OutOfMemory,
                                                                ));
                                                                process.terminate_group(
                                                                    helios_unix::ChildTermination::Killed,
                                                                );
                                                                break;
                                                            }
                                                            Err(NativeError::NotMapped) => {
                                                                if handle_unresolvable_fault(
                                                                    &mut process,
                                                                    &mut context,
                                                                    &shared,
                                                                    instance_id,
                                                                    fault,
                                                                ) {
                                                                    break;
                                                                }
                                                            }
                                                            Err(error) => panic!(
                                                                "installing private file frame at {page_va:?}: {error}"
                                                            ),
                                                        }
                                                    }
                                                    Err(_) => {
                                                        if handle_bus_fault(
                                                            &mut process,
                                                            &mut context,
                                                            &shared,
                                                            instance_id,
                                                            address,
                                                        ) {
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            if handle_bus_fault(
                                                &mut process,
                                                &mut context,
                                                &shared,
                                                instance_id,
                                                address,
                                            ) {
                                                break;
                                            }
                                        }
                                    }
                                }
                                None => {
                                    if handle_unresolvable_fault(
                                        &mut process,
                                        &mut context,
                                        &shared,
                                        instance_id,
                                        fault,
                                    ) {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(NativeError::NotMapped) => {
                            if handle_unresolvable_fault(
                                &mut process,
                                &mut context,
                                &shared,
                                instance_id,
                                fault,
                            ) {
                                break;
                            }
                        }
                        Err(error) => panic!("resolving a page fault at {address:?}: {error}"),
                    }
                }
                _ => {
                    if handle_unresolvable_fault(
                        &mut process,
                        &mut context,
                        &shared,
                        instance_id,
                        fault,
                    ) {
                        break;
                    }
                }
            },
        }
    }
    let memory = LinuxMemory {
        space: &*shared.space,
        user: shared.user,
        stack_growth: None,
        shared_mem: Some(&shared.shared_mem),
        shared_files: Some(shared.container.shared_files()),
    };
    process.flush_shared_mappings(&memory, &mut platform).await;
    ThreadRunEnd::Exited
}

/// Drives a process's `ITIMER_REAL` (`alarm` / `setitimer`) asynchronously
/// until every thread of the process has exited, without holding any spin lock
/// across `.await`.
async fn drive_real_timer<CpuImpl, Net, StorageImpl>(
    cpu: CpuImpl,
    timer: crate::Timer<CpuImpl>,
    runtime_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    proc_signals: Arc<ProcessSignals>,
    observer: syscall::ProcessObserver,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    loop {
        let mut group_wait = observer.waiter();
        let mut timer_wait = proc_signals.real_timer_waiter();
        if observer.all_threads_exited() || observer.group_ended() {
            return;
        }
        let now = runtime_state.uptime_nanos(cpu.now().ticks());
        if proc_signals.fire_real_timer_if_due(now) {
            continue;
        }
        let deadline = proc_signals.next_real_timer_deadline();
        match deadline {
            None => {
                core::future::poll_fn(|cx| {
                    if observer.poll_changed(cx, &mut group_wait).is_ready()
                        || proc_signals
                            .poll_real_timer_changed(cx, &mut timer_wait)
                            .is_ready()
                    {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            }
            Some((target_ns, _generation)) => {
                let remaining = target_ns.saturating_sub(now);
                let sleep = timer.sleep_for(Duration::from_nanos(remaining));
                let mut sleep = core::pin::pin!(sleep);
                core::future::poll_fn(|cx| {
                    if observer.poll_changed(cx, &mut group_wait).is_ready()
                        || proc_signals
                            .poll_real_timer_changed(cx, &mut timer_wait)
                            .is_ready()
                        || sleep.as_mut().poll(cx).is_ready()
                    {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            }
        }
    }
}

/// Computes the initial stack top and, when `abi` supplies a sigreturn
/// trampoline (AArch64), maps it at the top of `user` above an unmapped guard
/// page so it never collides with `brk` growth at `image_end`.
fn map_sigreturn_trampoline<Space: UserSpace>(
    space: &Space,
    user: VirtRange,
    abi: Abi,
) -> Result<(u64, u64), NativeError> {
    if let Some(code) = abi.sigreturn_trampoline_code() {
        let trampoline = VirtAddr::new(user.end().raw() - PhysFrame::SIZE);
        space.map(
            VirtRange::new(trampoline, PhysFrame::SIZE),
            code,
            PageFlags::READ | PageFlags::EXECUTE,
        )?;
        Ok((
            (user.end().raw() - 2 * PhysFrame::SIZE) as u64,
            trampoline.raw() as u64,
        ))
    } else {
        Ok(((user.end().raw() - PhysFrame::SIZE) as u64, 0))
    }
}

struct MappedLinuxImage<Native: NativeExecution> {
    space: Arc<Native::Space>,
    context: Native::Context,
    user: VirtRange,
    stack_top: u64,
    stack_base: usize,
    image_end: usize,
    sigreturn_trampoline: u64,
    program_break: u64,
}

fn map_elf_segments<Space: UserSpace>(
    space: &Space,
    image: &Image<'_>,
    load_bias: u64,
) -> Result<(), ProgramExecError> {
    for segment in image.segments_at(load_bias) {
        let mut flags = PageFlags::READ;
        flags.set(PageFlags::WRITE, segment.writable);
        flags.set(PageFlags::EXECUTE, segment.executable);
        let range = VirtRange::new(
            VirtAddr::new(segment.address as usize),
            segment.memory_size as usize,
        );
        space
            .map(range, segment.bytes, flags)
            .map_err(native_error)?;
    }
    Ok(())
}

fn map_linux_image<Native: NativeExecution>(
    native: &Native,
    entropy: &crate::RootEntropy,
    executable: &LinuxExecutable,
    argv: &[String],
    environment: &[String],
    credentials: &syscall::Credentials,
    secure: bool,
) -> Result<MappedLinuxImage<Native>, ProgramExecError> {
    let limit = user_end(native);
    let image = Image::parse(&executable.image, executable.abi, limit).map_err(image_error)?;
    let interp_image = match &executable.interpreter {
        Some(bytes) => {
            Some(Image::parse_interpreter(bytes, executable.abi, limit).map_err(image_error)?)
        }
        None => {
            if image.interpreter().is_some() {
                return Err(image_error(elf::Error::InvalidInterpreter));
            }
            None
        }
    };

    let space = Arc::new(native.create_space().map_err(native_error)?);
    let user = native.user_range();
    let (top, sigreturn_trampoline) =
        map_sigreturn_trampoline(&*space, user, executable.abi).map_err(native_error)?;

    let page_size = PhysFrame::SIZE as u64;
    let placement = elf::plan_placement(
        &image,
        interp_image.as_ref(),
        user.start.raw() as u64,
        top,
        page_size,
    )
    .map_err(image_error)?;

    map_elf_segments(&*space, &image, placement.main_bias)?;
    if let (Some(interp), Some(interp_bias)) = (&interp_image, placement.interpreter_bias) {
        map_elf_segments(&*space, interp, interp_bias)?;
    }

    let arguments: Vec<&[u8]> = argv.iter().map(String::as_bytes).collect();
    let variables: Vec<&[u8]> = environment.iter().map(String::as_bytes).collect();
    let mut random = [0; 16];
    entropy.fill(&mut random);
    let executable_name = executable
        .path
        .as_deref()
        .map(str::as_bytes)
        .or_else(|| arguments.first().copied())
        .unwrap_or(b"");
    let stack = helios_linux::stack::build(
        &helios_linux::stack::Startup {
            entry: placement.main_entry,
            page_size,
            headers: placement.program_headers,
            interpreter_base: placement.at_base,
            flags: 0,
            random,
            arguments: &arguments,
            environment: &variables,
            executable: executable_name,
            uid: credentials.user.real,
            euid: credentials.user.effective,
            gid: credentials.group.real,
            egid: credentials.group.effective,
            secure,
        },
        top,
    )
    .map_err(|_| ProgramExecError {
        kind: ProgramExecErrorKind::InvalidPath,
        detail: ProgramExecErrorDetail::InvalidProgramPath,
    })?;
    if stack.base <= placement.image_end {
        return Err(ProgramExecError {
            kind: ProgramExecErrorKind::OutOfMemory,
            detail: ProgramExecErrorDetail::NativeMemoryExhausted,
        });
    }
    space
        .map(
            VirtRange::new(VirtAddr::new(stack.base as usize), stack.bytes.len()),
            &stack.bytes,
            PageFlags::READ | PageFlags::WRITE,
        )
        .map_err(native_error)?;
    let context = native
        .create_context(
            VirtAddr::new(placement.initial_pc as usize),
            VirtAddr::new(stack.pointer as usize),
        )
        .map_err(native_error)?;
    Ok(MappedLinuxImage {
        space,
        context,
        user,
        stack_top: top,
        stack_base: stack.base as usize,
        image_end: placement.image_end as usize,
        sigreturn_trampoline,
        program_break: placement.program_break,
    })
}

/// Drives a Linux process (either a root launch or a forked child) across its
/// initial image and any subsequent `execve`/`execveat` replacements — whether
/// Linux ELF or Wasm/WASIX — until the process terminates.
async fn drive_linux_process_lifecycle<CpuImpl, Net, StorageImpl>(
    mut context: <CpuImpl::Native as NativeExecution>::Context,
    mut process: Process<LinuxResources<Net>>,
    mut shared: Arc<
        LinuxShared<CpuImpl, Net, StorageImpl, <CpuImpl::Native as NativeExecution>::Space>,
    >,
    root_guard: Option<crate::ContainerProcessGuard>,
    timeline: phases::Timeline,
) -> Result<ChildExit, ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let _root_guard = root_guard;
    let _proc_guard = ProcProcessGuard {
        registry: shared.container.proc_registry().clone(),
        pid: process.pid().get(),
    };
    loop {
        let cpu = shared.cpu.clone();
        let pid = process.pid();
        {
            let comm = process_comm_from_exe(&shared.exe_path);
            let mut rec = crate::ProcProcessRecord::minimal(
                pid.get(),
                shared.ppid,
                comm,
                shared.exe_path.clone(),
            );
            rec.pgid = shared.proc_signals.pgid();
            rec.sid = pid.get();
            rec.argv = shared.argv.clone();
            rec.env = shared.env.clone();
            rec.cwd = shared.cwd_handle.lock().clone();
            rec.credentials = shared.credentials_handle.lock().clone();
            rec.fds = snapshot_process_fds(&shared.descriptors_handle.lock());
            shared.container.proc_registry().register_process(rec);
        }
        let observer = process.observer();
        let proc_signals = process.process_signals();
        let main_platform = LinuxThreadPlatform::new(shared.clone(), pid);
        let real_timer_driver = drive_real_timer(
            cpu.clone(),
            shared.timer.clone(),
            shared.runtime_state.clone(),
            proc_signals.clone(),
            observer.clone(),
        );
        let mut main_exec: Option<ExecHandoff<CpuImpl, Net, StorageImpl>> = None;
        let main_and_siblings = async {
            match Box::pin(drive_linux_thread(context, process, main_platform)).await {
                ThreadRunEnd::Exec(prepared, exec_proc) => {
                    // Condemn any sibling threads so they drain before the
                    // address space is replaced.
                    observer.terminate_group(helios_unix::ChildTermination::Exited(0));
                    main_exec = Some((prepared, exec_proc));
                    return;
                }
                ThreadRunEnd::Exited => {}
            }

            // Wait for every live sibling thread to exit, still honouring
            // external signals and instance kills while `main` is already gone.
            loop {
                let mut group_wait = observer.waiter();
                let mut signal_wait = shared.signal_state.wait_state();
                let mut kill_wait = shared.launched_instance.arm_kill_wait();
                if let Some(reason) = shared.launched_instance.pending_kill() {
                    match reason {
                        crate::KillReason::Operator | crate::KillReason::RequesterGone => {
                            observer.terminate_group(helios_unix::ChildTermination::Killed);
                        }
                        crate::KillReason::OutOfMemory
                        | crate::KillReason::SupervisorRestart
                        | crate::KillReason::StoreFailed => {
                            shared.record_fatal(map_program_runtime_error(wasmtime::Error::from(
                                crate::InstanceKilled { reason },
                            )));
                            observer.terminate_group(helios_unix::ChildTermination::Killed);
                        }
                    }
                } else if !observer.group_ended() {
                    forward_external_signals(&proc_signals, &shared.signal_state);
                }
                if observer.all_threads_exited() {
                    break;
                }
                core::future::poll_fn(|cx| {
                    let group_changed = observer.poll_changed(cx, &mut group_wait).is_ready();
                    let signalled = shared
                        .signal_state
                        .poll_changed(cx, &mut signal_wait)
                        .is_ready();
                    let killed = shared
                        .launched_instance
                        .poll_kill_wait(cx, &mut kill_wait)
                        .is_ready();
                    if group_changed || signalled || killed {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            }
        };
        futures::future::join(main_and_siblings, real_timer_driver).await;

        // Wait for every detached thread task to drop its `Process` and
        // `Arc<Space>` before committing exec or reporting `ChildExit`.
        shared.wait_tasks_drained().await;

        let exec_request = main_exec.or_else(|| shared.exec_handoff.lock().take());
        if let Some((prepared, mut exec_proc)) = exec_request {
            match *prepared {
                PreparedExec::Linux {
                    executable,
                    exe_path,
                    argv,
                    env,
                    credentials,
                    secure,
                } => {
                    let native = cpu.native().map_err(native_unavailable)?;
                    let mapped = map_linux_image(
                        native,
                        shared.runtime_state.root_entropy(),
                        &executable,
                        &argv,
                        &env,
                        &credentials,
                        secure,
                    )?;
                    exec_proc.commit_linux_exec(mapped.program_break, credentials);
                    let next_shared = Arc::new(LinuxShared {
                        cpu: shared.cpu.clone(),
                        timer: shared.timer.clone(),
                        spawner: shared.spawner.clone(),
                        runtime_state: shared.runtime_state.clone(),
                        exec_runtime: shared.exec_runtime.clone(),
                        read_serial: shared.read_serial,
                        write_serial: shared.write_serial,
                        output_mode: shared.output_mode.clone(),
                        launched_instance: shared.launched_instance.clone(),
                        signal_state: shared.signal_state.clone(),
                        container: shared.container.clone(),
                        grants: LinuxGrants::derive(shared.container.authority()),
                        pid: exec_proc.pid(),
                        ppid: shared.ppid,
                        exe_path,
                        argv,
                        env,
                        cwd_handle: exec_proc.cwd_handle(),
                        descriptors_handle: exec_proc.descriptors_handle(),
                        credentials_handle: exec_proc.credentials_handle(),
                        proc_signals: exec_proc.process_signals(),
                        tty: spin::Mutex::new(shared.tty.lock().clone()),
                        serial_peek: spin::Mutex::new(core::mem::take(
                            &mut *shared.serial_peek.lock(),
                        )),
                        clock: spin::Mutex::new(crate::KernelClock::new(
                            shared.cpu.clone(),
                            shared.runtime_state.clone(),
                        )),
                        abi: executable.abi,
                        registers: executable.abi.system_call_registers(),
                        user: mapped.user,
                        stack_top: mapped.stack_top,
                        stack_base: mapped.stack_base,
                        image_end: mapped.image_end,
                        sigreturn_trampoline: mapped.sigreturn_trampoline,
                        space: mapped.space,
                        shared_mem: Arc::new(spin::Mutex::new(SharedMemoryTable::new())),
                        process_cpu_ticks: AtomicU64::new(
                            shared.process_cpu_ticks.load(Ordering::Relaxed),
                        ),
                        process_sys_ticks: AtomicU64::new(
                            shared.process_sys_ticks.load(Ordering::Relaxed),
                        ),
                        peak_rss_kib: AtomicU64::new(shared.current_rss_kib()),
                        syslog_cursor: spin::Mutex::new(*shared.syslog_cursor.lock()),
                        syslog_clear_after: AtomicU64::new(
                            shared.syslog_clear_after.load(Ordering::Relaxed),
                        ),
                        fatal_error: spin::Mutex::new(None),
                        exec_handoff: spin::Mutex::new(None),
                        running_tasks: AtomicUsize::new(0),
                        tasks_drained: helios_sync::Notify::new(),
                    });
                    // Drop the old `LinuxShared` and old address space before
                    // starting the replacement image.
                    drop(observer);
                    drop(proc_signals);
                    shared = next_shared;
                    context = mapped.context;
                    process = exec_proc;
                    continue;
                }
                PreparedExec::Wasm {
                    executable,
                    argv,
                    env,
                } => {
                    let (surviving_slots, ignored) = exec_proc.commit_wasm_exec();
                    let thread_signals = exec_proc.thread_signals().clone();
                    let descriptors = Preview1DescriptorTable::from_slots(surviving_slots);
                    let signal_dispositions: Vec<WasixSignalDisposition> = ignored
                        .into_iter()
                        .map(|sig| WasixSignalDisposition {
                            signal: sig.raw(),
                            action: WasixSignalDispositionAction::Ignore,
                        })
                        .collect();
                    let exec_runtime = shared.exec_runtime.clone();
                    let spawner = shared.spawner.clone();
                    let launched_instance = shared.launched_instance.clone();
                    let output_mode = shared.output_mode.clone();
                    let external_signal_state = shared.signal_state.clone();
                    let authority = shared.container.authority().clone();
                    // Reclaim the entire old Linux address space before
                    // instantiating the replacement Wasm image.
                    drop(observer);
                    drop(proc_signals);
                    drop(exec_proc);
                    drop(shared);

                    let wasm_runtime = exec_runtime
                        .wasm
                        .expect("PreparedExec::Wasm requires a Wasm runtime");
                    let wasm_signal_state = WasixSignalState::new();
                    let wasm_run = Box::pin(run_program_executable(
                        exec_runtime.exec_context,
                        argv,
                        env,
                        authority,
                        crate::IpcEndpointGrants::new(),
                        None,
                        crate::InheritedSockets::new(),
                        None,
                        wasm_runtime.filesystem,
                        // Exec keeps the process, so it keeps the process's limit.
                        DescriptorOrigin::SameProcess(descriptors),
                        wasm_signal_state.clone(),
                        signal_dispositions,
                        None,
                        spawner,
                        wasm_runtime.progress,
                        executable,
                        &wasm_runtime.engine,
                        &wasm_runtime.runtime,
                        wasm_runtime.preview1_core_linker,
                        wasm_runtime.shared_memory_pool,
                        wasm_runtime.core_module_instance_pre_cache,
                        launched_instance,
                        output_mode,
                        timeline,
                    ));
                    // Bridge container Linux signals (`kill(pid, sig)` /
                    // `kill(-pgid, sig)`) and parent external signals into the
                    // replacement Wasm/WASIX process while it runs.
                    let mut wasm_run = wasm_run;
                    let mut linux_sig_wait = thread_signals.signal_waiter();
                    let mut ext_sig_wait = external_signal_state.wait_state();
                    let outcome = core::future::poll_fn(|cx| {
                        while let Some(sig) = thread_signals.take_pending_signal() {
                            wasm_signal_state.raise(sig);
                        }
                        while let Some(sig) = external_signal_state.take_pending() {
                            wasm_signal_state.raise(sig);
                        }
                        if let Poll::Ready(result) = wasm_run.as_mut().poll(cx) {
                            return Poll::Ready(result);
                        }
                        if thread_signals
                            .poll_signal_waiter(cx, &mut linux_sig_wait)
                            .is_ready()
                        {
                            while let Some(sig) = thread_signals.take_pending_signal() {
                                wasm_signal_state.raise(sig);
                            }
                            linux_sig_wait = thread_signals.signal_waiter();
                            let _ = thread_signals.poll_signal_waiter(cx, &mut linux_sig_wait);
                        }
                        if external_signal_state
                            .poll_changed(cx, &mut ext_sig_wait)
                            .is_ready()
                        {
                            while let Some(sig) = external_signal_state.take_pending() {
                                wasm_signal_state.raise(sig);
                            }
                            ext_sig_wait = external_signal_state.wait_state();
                            let _ = external_signal_state.poll_changed(cx, &mut ext_sig_wait);
                        }
                        Poll::Pending
                    })
                    .await;
                    return outcome;
                }
            }
        }

        timeline.record(&cpu, LaunchPhase::GuestEnd);
        shared
            .container
            .pid_namespace()
            .record_usage(pid, shared.snapshot_usage());
        let instance_id = shared.launched_instance.id();
        let fatal = shared.take_fatal();
        let termination = observer.termination();
        drop(observer);
        drop(proc_signals);
        drop(shared);

        return match fatal {
            Some(error) => Err(error),
            None => Ok(ChildExit {
                instance_id,
                termination,
                filesystem: None,
            }),
        };
    }
}

/// Runs a Linux process inside `container` to its end: maps `executable`,
/// builds its initial stack from `argv` and `env`, allocates its container-local
/// PID (starting at 1), drives `main`, every thread spawned via `clone`/`clone3`,
/// forked children, and `execve`/`execveat` replacements (Linux ELF or Wasm),
/// and returns once the process has exited and released its resources.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_linux_process<CpuImpl, Net, StorageImpl>(
    exec_runtime: LinuxExecRuntime<CpuImpl, Net, StorageImpl>,
    argv: ProgramArgv,
    env: Vec<(String, String)>,
    container: Arc<crate::LinuxContainer<StorageImpl>>,
    credentials: Option<syscall::Credentials>,
    cwd: Option<String>,
    inherited_sockets: crate::InheritedSockets,
    descriptors: DescriptorOrigin<Net>,
    signal_state: WasixSignalState,
    spawner: crate::InstanceSpawner<CpuImpl>,
    launched_instance: crate::RegisteredInstance,
    output_mode: OutputMode,
    executable: LinuxExecutable,
    timeline: &phases::Timeline,
) -> Result<ChildExit, ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let exec_context = exec_runtime.exec_context.clone();
    let instance_id = launched_instance.id();
    timeline.set_instance(instance_id);
    timeline.record(&exec_context.cpu, LaunchPhase::TaskBegin);
    let cpu = exec_context.cpu.clone();
    let native = cpu.native().map_err(native_unavailable)?;

    let argv = argv.into_vec();
    let environment: Vec<String> = env
        .into_iter()
        .map(|(name, value)| {
            let mut variable = String::with_capacity(name.len() + 1 + value.len());
            variable.push_str(&name);
            variable.push('=');
            variable.push_str(&value);
            variable
        })
        .collect();
    let mut credentials = credentials.unwrap_or_else(|| container.default_credentials().clone());
    container.clamp_credentials(&mut credentials);
    let executable =
        if executable.interpreter.is_none() && executable.interpreter_path(&cpu)?.is_some() {
            let base_dir = cwd
                .as_deref()
                .or_else(|| {
                    container
                        .authority()
                        .cwd()
                        .map(|preopen| preopen.guest_name())
                })
                .unwrap_or("/");
            Box::pin(LinuxExecutable::load_in_container(
                &cpu,
                &container,
                base_dir,
                executable.image,
                executable.path,
                &credentials,
            ))
            .await?
        } else {
            executable
        };
    let initial_secure = executable.secure
        || credentials.user.effective != credentials.user.real
        || credentials.group.effective != credentials.group.real;
    let mapped = map_linux_image(
        native,
        exec_context.runtime_state.root_entropy(),
        &executable,
        &argv,
        &environment,
        &credentials,
        initial_secure,
    )?;

    let process_guard = container.allocate_process().map_err(|_| ProgramExecError {
        kind: ProgramExecErrorKind::OutOfMemory,
        detail: ProgramExecErrorDetail::ContainerRefused(crate::RuntimeMessage::of(
            "container PID namespace exhausted",
        )),
    })?;
    let pid = process_guard.pid();
    let mut table = match descriptors {
        DescriptorOrigin::Fresh => {
            let mut table = syscall::standard_streams::<LinuxResources<Net>>();
            table.limit = exec_context
                .runtime_state
                .settings()
                .get::<DescriptorLimitSetting>();
            table
        }
        DescriptorOrigin::NewProcess(table) => table
            .for_new_process(
                exec_context
                    .runtime_state
                    .settings()
                    .get::<DescriptorLimitSetting>(),
            )
            .into_slots(),
        DescriptorOrigin::SameProcess(table) => table.into_slots(),
    };
    let unix_sockets =
        inherited_sockets_to_unix_sockets(&exec_context.runtime_state, inherited_sockets)?;
    for (index, socket) in unix_sockets.into_iter().enumerate() {
        let fd = 3 + index;
        if table.entries.len() <= fd {
            table.entries.resize(fd + 1, None);
        }
        table.entries[fd] = Some(helios_unix::FileDescriptorEntry::new(
            helios_unix::FileDescriptor::Socket(socket),
            false,
        ));
    }
    let initial_cwd = cwd.or_else(|| {
        container
            .authority()
            .cwd()
            .map(|preopen| String::from(preopen.guest_name()))
    });
    let process = Process::<LinuxResources<Net>>::with_descriptors(
        executable.abi,
        pid,
        mapped.program_break,
        table,
        Start {
            credentials,
            memory_bytes: crate::machine_memory().usable_bytes as u64,
            futex: container.futex_table().clone(),
            pids: Some(container.pid_namespace().clone()),
            memory_id: Some(instance_id.raw()),
            cwd: initial_cwd,
            ..Start::default()
        },
    );
    let exe_path = executable
        .path
        .clone()
        .or_else(|| argv.first().cloned())
        .unwrap_or_else(|| String::from("/"));
    let grants = LinuxGrants::derive(container.authority());
    let tty = LinuxTtyState::new(container.authority(), &output_mode, instance_id);
    let shared = Arc::new(LinuxShared {
        cpu: cpu.clone(),
        timer: exec_context.timer.clone(),
        spawner,
        runtime_state: exec_context.runtime_state.clone(),
        read_serial: exec_context.read_serial,
        write_serial: exec_context.write_serial,
        exec_runtime,
        output_mode,
        launched_instance,
        signal_state,
        container,
        grants,
        pid,
        ppid: 0,
        exe_path,
        argv,
        env: environment,
        cwd_handle: process.cwd_handle(),
        descriptors_handle: process.descriptors_handle(),
        credentials_handle: process.credentials_handle(),
        proc_signals: process.process_signals(),
        tty: spin::Mutex::new(tty),
        serial_peek: spin::Mutex::new(Vec::new()),
        clock: spin::Mutex::new(crate::KernelClock::new(
            cpu.clone(),
            exec_context.runtime_state.clone(),
        )),
        abi: executable.abi,
        registers: executable.abi.system_call_registers(),
        user: mapped.user,
        stack_top: mapped.stack_top,
        stack_base: mapped.stack_base,
        image_end: mapped.image_end,
        sigreturn_trampoline: mapped.sigreturn_trampoline,
        space: mapped.space,
        shared_mem: Arc::new(spin::Mutex::new(SharedMemoryTable::new())),
        process_cpu_ticks: AtomicU64::new(0),
        process_sys_ticks: AtomicU64::new(0),
        peak_rss_kib: AtomicU64::new(0),
        syslog_cursor: spin::Mutex::new(0),
        syslog_clear_after: AtomicU64::new(0),
        fatal_error: spin::Mutex::new(None),
        exec_handoff: spin::Mutex::new(None),
        running_tasks: AtomicUsize::new(0),
        tasks_drained: helios_sync::Notify::new(),
    });

    timeline.record(&cpu, LaunchPhase::GuestBegin);
    Box::pin(drive_linux_process_lifecycle(
        mapped.context,
        process,
        shared,
        Some(process_guard),
        timeline.clone(),
    ))
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{
        NativeSpace, UserMemoryPool, UserTranslation, install_user_memory_pool,
        installed_user_memory_pool,
    };
    use core::alloc::Layout;
    use core::ptr::NonNull;

    fn ensure_pool() {
        const POOL_BYTES: usize = 4 * 1024 * 1024;
        if installed_user_memory_pool().is_some() {
            return;
        }
        let layout = Layout::from_size_align(POOL_BYTES, PhysFrame::SIZE).expect("pool layout");
        // SAFETY: nonzero size, leaked for the lifetime of the test process.
        let base = unsafe { alloc::alloc::alloc_zeroed(layout) } as usize;
        assert!(base != 0, "pool backing");
        install_user_memory_pool(UserMemoryPool::single_node(1, &[(base, base + POOL_BYTES)]));
    }

    struct DummyTables;

    // SAFETY: host unit test uses `NativeSpace`'s direct-map operations only
    // and never enters hardware user mode.
    unsafe impl UserTranslation for DummyTables {
        fn install(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), NativeError> {
            Ok(())
        }
        fn uninstall(&mut self, _: u64) {}
        fn protect(&mut self, _: u64, _: PageFlags) {}
        fn invalidate(&self, _: u64, _: u64) {}
        fn physical(&self, frame: NonNull<u8>) -> u64 {
            frame.as_ptr() as u64
        }
        fn new_empty(&self) -> Result<Self, NativeError> {
            Ok(DummyTables)
        }
    }

    #[test]
    fn linux_memory_atomic_u32_ops_commit_discarded_pages_and_enforce_permissions() {
        ensure_pool();
        let start = PhysFrame::SIZE;
        let end = 1 << 32;
        let space = NativeSpace::new(DummyTables, start as u64, end as u64);
        let user = VirtRange::new(VirtAddr::new(start), end - start);
        let mut memory = LinuxMemory {
            space: &space,
            user,
            stack_growth: None,
            shared_mem: None,
            shared_files: None,
        };

        let rw_addr = 0x10_000u64;
        memory
            .map_at(
                rw_addr,
                PhysFrame::SIZE as u64,
                PageFlags::READ | PageFlags::WRITE,
            )
            .unwrap();
        assert_eq!(memory.atomic_load_u32(rw_addr + 2), Err(MemoryFault));
        assert_eq!(memory.atomic_load_u32(0x20_000), Err(MemoryFault));
        assert_eq!(memory.atomic_load_u32(rw_addr), Ok(0));

        // Discard leaves a zero-fill-on-demand page; atomic store commits a
        // fresh frame and writes the word.
        memory.discard(rw_addr, PhysFrame::SIZE as u64);
        assert_eq!(memory.atomic_load_u32(rw_addr), Ok(0));
        memory.atomic_store_u32(rw_addr, 0x1234_5678).unwrap();
        assert_eq!(memory.atomic_load_u32(rw_addr), Ok(0x1234_5678));
        assert_eq!(
            memory.atomic_compare_exchange_u32(rw_addr, 9, 10),
            Ok(Err(0x1234_5678))
        );
        assert_eq!(
            memory.atomic_compare_exchange_u32(rw_addr, 0x1234_5678, 0xdead_beef),
            Ok(Ok(0x1234_5678))
        );
        assert_eq!(memory.atomic_load_u32(rw_addr), Ok(0xdead_beef));

        // Narrowing to read-only keeps atomic loads working and refuses atomic
        // stores and CAS.
        memory
            .protect(rw_addr, PhysFrame::SIZE as u64, PageFlags::READ)
            .unwrap();
        assert_eq!(memory.atomic_load_u32(rw_addr), Ok(0xdead_beef));
        assert_eq!(memory.atomic_store_u32(rw_addr, 1), Err(MemoryFault));
        assert_eq!(
            memory.atomic_compare_exchange_u32(rw_addr, 0xdead_beef, 1),
            Err(MemoryFault)
        );
    }

    struct DummyThread;

    impl Thread for DummyThread {
        fn thread_pointer(&self) -> u64 {
            0
        }
        fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
            Err(Denied)
        }
        fn spawn_thread(
            &mut self,
            _: Process<helios_linux::syscall::NoBacking>,
            _: SpawnedThread,
        ) -> Result<(), SpawnError> {
            unreachable!("no thread spawned")
        }
    }

    struct DummyOutput;

    impl syscall::Network<helios_unix::NoNetwork> for DummyOutput {
        fn to_ip(&self, address: core::convert::Infallible) -> syscall::IpAddr {
            match address {}
        }
        fn encode_ip(&self, _: syscall::IpAddr) -> core::convert::Infallible {
            unreachable!()
        }
    }

    impl Stdio for DummyOutput {
        async fn write(&mut self, _: Stream, _: &[u8]) -> Result<usize, WriteError> {
            Err(WriteError::Io)
        }
        async fn read_input(&mut self, _: usize) -> Result<Bytes, Denied> {
            Err(Denied)
        }
    }

    impl syscall::Clock for DummyOutput {
        fn now_nanos(&self) -> u64 {
            0
        }
        async fn sleep_until(&self, _: u64) {}
    }

    impl System for DummyOutput {
        fn realtime_nanos(&self) -> u64 {
            0
        }
        fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
            Err(Denied)
        }
        fn cpu_nanos(&self) -> u64 {
            0
        }
        fn fill_random(&mut self, _: &mut [u8]) {}
        fn memory(&self) -> MemoryTotals {
            MemoryTotals {
                total_bytes: 0,
                free_bytes: 0,
            }
        }
        fn process_count(&self) -> u32 {
            1
        }
        fn kernel_version(&self) -> &str {
            "test"
        }
    }

    impl Filesystem<syscall::NoBacking> for DummyOutput {}
    impl Tty for DummyOutput {}

    #[test]
    fn linux_mmap_brk_and_mremap_commit_only_touched_pages() {
        use core::future::Future;
        use core::task::{Context, Poll, Waker};
        use helios_linux::syscall::dispatch;

        const MMAP: u64 = 9;
        const MUNMAP: u64 = 11;
        const BRK: u64 = 12;
        const MREMAP: u64 = 25;
        const PROT_RW: u64 = 0x3;
        const MAP_PRIVATE_ANON: u64 = 0x22;
        const MREMAP_MAYMOVE: u64 = 1;

        ensure_pool();
        let page = PhysFrame::SIZE as u64;
        let start = PhysFrame::SIZE;
        let end = 1usize << 32;
        let space = NativeSpace::new(DummyTables, start as u64, end as u64);
        let user = VirtRange::new(VirtAddr::new(start), end - start);
        let mut memory = LinuxMemory {
            space: &space,
            user,
            stack_growth: None,
            shared_mem: None,
            shared_files: None,
        };
        let mut process = Process::new(Abi::X86_64, NonZeroU32::new(1).unwrap(), 0x50_0000);
        let mut call = |number: u64, arguments: [u64; 6]| -> u64 {
            let (mut thread, mut output) = (DummyThread, DummyOutput);
            let mut fut = core::pin::pin!(dispatch(
                &mut process,
                Call { number, arguments },
                &mut memory,
                &mut thread,
                &mut output,
            ));
            match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(ControlFlow::Continue(SyscallOutcome::Return(result))) => result,
                other => panic!("unexpected syscall state: {other:?}"),
            }
        };

        let baseline = crate::memory::user_heap_stats().allocated_bytes;

        // An anonymous mapping larger than the entire 4 MiB test pool succeeds
        // and takes zero frames until touched.
        let large_len = 16 * 1024 * 1024;
        let mapped = call(
            MMAP,
            [
                0x1000_0000,
                large_len,
                PROT_RW,
                MAP_PRIVATE_ANON,
                u64::MAX,
                0,
            ],
        );
        assert_eq!(mapped, 0x1000_0000);
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);

        // Touching the first and last pages commits exactly two frames.
        space
            .resolve_fault(VirtAddr::new(mapped as usize), PageFlags::WRITE)
            .unwrap();
        space
            .resolve_fault(
                VirtAddr::new((mapped + large_len - page) as usize),
                PageFlags::READ,
            )
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 2 * PhysFrame::SIZE
        );

        // `brk` growth takes zero frames until touched, then commits per touched page.
        let brk_start = call(BRK, [0; 6]);
        let brk_end = brk_start + 8 * page;
        assert_eq!(call(BRK, [brk_end, 0, 0, 0, 0, 0]), brk_end);
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 2 * PhysFrame::SIZE
        );
        space
            .resolve_fault(
                VirtAddr::new((brk_start + 5 * page) as usize),
                PageFlags::WRITE,
            )
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 3 * PhysFrame::SIZE
        );

        // `mremap` growth (beyond the entire 4 MiB pool!) keeps existing frames
        // and commits no frames for the new tail until touched.
        let small = call(MMAP, [0, 2 * page, PROT_RW, MAP_PRIVATE_ANON, u64::MAX, 0]);
        space.write(VirtAddr::new(small as usize), b"kept").unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 4 * PhysFrame::SIZE
        );
        let grown_len = 8 * 1024 * 1024;
        let moved = call(MREMAP, [small, 2 * page, grown_len, MREMAP_MAYMOVE, 0, 0]);
        assert!(moved >= start as u64);
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 4 * PhysFrame::SIZE
        );
        let mut head = [0u8; 4];
        space
            .read(VirtAddr::new(moved as usize), &mut head)
            .unwrap();
        assert_eq!(&head, b"kept");
        space
            .resolve_fault(
                VirtAddr::new((moved + grown_len - page) as usize),
                PageFlags::WRITE,
            )
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 5 * PhysFrame::SIZE
        );

        // Unmapping and shrinking the break release every committed frame.
        assert_eq!(call(MUNMAP, [mapped, large_len, 0, 0, 0, 0]), 0);
        assert_eq!(call(MUNMAP, [moved, grown_len, 0, 0, 0, 0]), 0);
        assert_eq!(call(BRK, [brk_start, 0, 0, 0, 0, 0]), brk_start);
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);
    }

    #[test]
    fn aarch64_sigreturn_trampoline_sits_above_stack_guard_and_leaves_brk_free() {
        use core::future::Future;
        use core::task::{Context, Poll, Waker};
        use helios_linux::syscall::dispatch;

        ensure_pool();
        let page = PhysFrame::SIZE;
        let start = page;
        let end = 1usize << 32;
        let user = VirtRange::new(VirtAddr::new(start), end - start);

        // x86-64 needs no kernel trampoline and keeps one guard page above the stack.
        let x86_space = NativeSpace::new(DummyTables, start as u64, end as u64);
        let (x86_top, x86_tramp) = map_sigreturn_trampoline(&x86_space, user, Abi::X86_64).unwrap();
        assert_eq!(x86_tramp, 0);
        assert_eq!(x86_top, (end - page) as u64);
        assert_eq!(
            x86_space.mapping(VirtRange::new(VirtAddr::new(end - page), page)),
            None
        );

        // AArch64 maps the RX trampoline at the very top page, keeps an unmapped
        // guard page between the stack and the trampoline, and leaves `brk`
        // growth right at `image_end` unblocked.
        let arm_space = NativeSpace::new(DummyTables, start as u64, end as u64);
        let image_end = 0x41_0000usize;
        arm_space
            .map(
                VirtRange::new(VirtAddr::new(0x40_0000), image_end - 0x40_0000),
                &[],
                PageFlags::READ | PageFlags::EXECUTE,
            )
            .unwrap();
        let (arm_top, arm_tramp) =
            map_sigreturn_trampoline(&arm_space, user, Abi::Aarch64).unwrap();
        assert_eq!(arm_tramp, (end - page) as u64);
        assert_eq!(arm_top, (end - 2 * page) as u64);
        assert_eq!(
            arm_space
                .mapping(VirtRange::new(VirtAddr::new(end - page), page))
                .map(|m| m.flags),
            Some(PageFlags::READ | PageFlags::EXECUTE)
        );
        assert_eq!(
            arm_space.mapping(VirtRange::new(VirtAddr::new(end - 2 * page), page)),
            None
        );

        let expected_code = Abi::Aarch64.sigreturn_trampoline_code().unwrap();
        let mut actual_code = vec![0u8; expected_code.len()];
        arm_space
            .read(VirtAddr::new(arm_tramp as usize), &mut actual_code)
            .unwrap();
        assert_eq!(actual_code.as_slice(), expected_code);

        // Growing `brk` directly above `image_end` must succeed without colliding.
        const AARCH64_BRK: u64 = 214;
        let mut memory = LinuxMemory {
            space: &arm_space,
            user,
            stack_growth: None,
            shared_mem: None,
            shared_files: None,
        };
        let mut process = Process::new(Abi::Aarch64, NonZeroU32::new(1).unwrap(), image_end as u64);
        let (mut thread, mut output) = (DummyThread, DummyOutput);
        let grown = image_end as u64 + 4 * page as u64;
        let mut fut = core::pin::pin!(dispatch(
            &mut process,
            Call {
                number: AARCH64_BRK,
                arguments: [grown, 0, 0, 0, 0, 0],
            },
            &mut memory,
            &mut thread,
            &mut output,
        ));
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(ControlFlow::Continue(SyscallOutcome::Return(result))) => {
                assert_eq!(result, grown);
            }
            other => panic!("unexpected aarch64 brk outcome: {other:?}"),
        }
    }

    #[test]
    fn synthetic_etc_lookup_enforces_trailing_slash_and_open_flags() {
        use crate::test_support::UnsupportedStorage;
        use crate::vfs::BOOT_DEVICE;
        use crate::{
            BootFs, ContainerConfig, ContainerId, ContainerMountSpec, DirectoryAuthorityRights,
            EmbeddedBootDirectory, EmbeddedBootFs, LinuxContainer, ProcessAuthority, SharedOwner,
        };
        use core::task::{Context, Poll, Waker};
        use helios_linux::syscall::{Credentials, UtsField};

        const BOOT_IMAGE: EmbeddedBootFs =
            EmbeddedBootFs::new(&[EmbeddedBootDirectory::new("root", 0)], &[]);
        let host_ns = crate::Namespace::<UnsupportedStorage>::new(crate::MountTable::new(
            BootFs::new(BOOT_IMAGE, BOOT_DEVICE),
            4,
        ));
        let root_auth = ProcessAuthority::root();
        let container = {
            let mut fut = core::pin::pin!(LinuxContainer::create(
                ContainerId::new(core::num::NonZeroU64::new(1).unwrap()),
                &root_auth,
                &host_ns,
                ProcessAuthority::root(),
                ContainerConfig {
                    root: ContainerMountSpec {
                        source_path: String::from("/root"),
                        target_path: String::from("/"),
                        rights: DirectoryAuthorityRights::READ | DirectoryAuthorityRights::EXECUTE,
                        sharing: crate::ContainerMountSharing::Shared,
                    },
                    mounts: Vec::new(),
                    shared_owner: SharedOwner { uid: 0, gid: 0 },
                    credentials: Credentials::root(),
                    hostname: UtsField::from_bytes(b"helios-test").unwrap(),
                    domainname: UtsField::from_bytes(b"").unwrap(),
                },
            ));
            match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(Ok(container)) => container,
                Poll::Ready(Err(err)) => panic!("container create failed: {err:?}"),
                Poll::Pending => panic!("container create unexpectedly pending"),
            }
        };

        let servers = [crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([
            10, 0, 2, 3,
        ]))];
        let base_req = OpenRequest {
            read: true,
            write: false,
            create: false,
            exclusive: false,
            truncate: false,
            directory: false,
            nofollow: false,
            path_only: false,
            append: false,
            sync: false,
            dsync: false,
            nonblock: false,
            noctty: false,
            mode: 0o644,
            umask: 0,
        };

        // Trailing slash on a synthetic regular file must fail with NotDirectory.
        assert_eq!(
            synthetic_etc_open(&container, "/", "/etc/hosts/", &servers, base_req).err(),
            Some(FsError::NotDirectory)
        );
        assert_eq!(
            synthetic_etc_stat_lookup(&container, "/", "/etc/hosts/", &servers).err(),
            Some(FsError::NotDirectory)
        );
        assert_eq!(
            synthetic_etc_stat_lookup(&container, "/", "/etc/resolv.conf/", &servers).err(),
            Some(FsError::NotDirectory)
        );
        assert_eq!(
            synthetic_etc_access_lookup(
                &container,
                "/",
                "/etc/hosts/",
                &servers,
                AccessCheck {
                    read: false,
                    write: false,
                    exec: false,
                    follow: true,
                    use_effective: false,
                },
            )
            .err(),
            Some(FsError::NotDirectory)
        );

        // O_CREAT | O_EXCL on an existing synthetic file must return Exists (EEXIST).
        assert_eq!(
            synthetic_etc_open(
                &container,
                "/",
                "/etc/hosts",
                &servers,
                OpenRequest {
                    create: true,
                    exclusive: true,
                    ..base_req
                },
            )
            .err(),
            Some(FsError::Exists)
        );

        // O_CREAT | O_RDONLY (without exclusive/write/truncate) opens the existing file read-only.
        let desc = synthetic_etc_open(
            &container,
            "/",
            "/etc/hosts",
            &servers,
            OpenRequest {
                create: true,
                ..base_req
            },
        )
        .expect("O_CREAT | O_RDONLY on existing synthetic /etc/hosts must succeed");
        assert_eq!(desc.path, "/etc/hosts");
        assert!(desc.flags.contains(FsDescriptorFlags::READ));

        // O_WRONLY / O_TRUNC still return ReadOnly (EROFS).
        assert_eq!(
            synthetic_etc_open(
                &container,
                "/",
                "/etc/hosts",
                &servers,
                OpenRequest {
                    write: true,
                    ..base_req
                },
            )
            .err(),
            Some(FsError::ReadOnly)
        );

        // `..` path traversal must not resolve to synthetic /etc files.
        assert_eq!(
            synthetic_etc_open(
                &container,
                "/",
                "/nonexistent/../etc/hosts",
                &servers,
                base_req,
            )
            .err(),
            Some(FsError::NoEntry)
        );
    }

    fn build_test_elf(abi: Abi, e_type: u16, base: u64, interp: Option<&[u8]>) -> Vec<u8> {
        let mut bytes = alloc::vec![0u8; 2 * PhysFrame::SIZE];
        bytes[0x1000..0x1008].copy_from_slice(b"ELF_CODE");
        let mut phdrs: Vec<[u8; 56]> = Vec::new();
        let push = |phdrs: &mut Vec<[u8; 56]>,
                    p_type: u32,
                    p_flags: u32,
                    p_offset: u64,
                    p_vaddr: u64,
                    p_filesz: u64,
                    p_memsz: u64,
                    p_align: u64| {
            let mut h = [0u8; 56];
            h[0..4].copy_from_slice(&p_type.to_le_bytes());
            h[4..8].copy_from_slice(&p_flags.to_le_bytes());
            h[8..16].copy_from_slice(&p_offset.to_le_bytes());
            h[16..24].copy_from_slice(&p_vaddr.to_le_bytes());
            h[24..32].copy_from_slice(&p_vaddr.to_le_bytes());
            h[32..40].copy_from_slice(&p_filesz.to_le_bytes());
            h[40..48].copy_from_slice(&p_memsz.to_le_bytes());
            h[48..56].copy_from_slice(&p_align.to_le_bytes());
            phdrs.push(h);
        };
        if let Some(path) = interp {
            let off = 0x300u64;
            bytes[off as usize..off as usize + path.len()].copy_from_slice(path);
            push(
                &mut phdrs,
                3, /* PT_INTERP */
                4,
                off,
                base + off,
                path.len() as u64,
                path.len() as u64,
                1,
            );
        }
        push(&mut phdrs, 1, 4, 0, base, 0x500, 0x500, 4096);
        push(&mut phdrs, 1, 5, 0x1000, base + 0x1000, 0x200, 0x200, 4096);
        push(
            &mut phdrs,
            2, /* PT_DYNAMIC */
            4,
            0x400,
            base + 0x400,
            0x40,
            0x40,
            8,
        );

        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&e_type.to_le_bytes());
        bytes[18..20].copy_from_slice(&abi.elf_machine().to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&(base + 0x1000).to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
        for (i, h) in phdrs.iter().enumerate() {
            let off = 64 + i * 56;
            bytes[off..off + 56].copy_from_slice(h);
        }
        bytes
    }

    struct NativeTestContext {
        entry: VirtAddr,
        stack: VirtAddr,
    }

    // SAFETY: host unit test context never enters hardware user mode.
    unsafe impl UserContext for NativeTestContext {
        type Space = NativeSpace<DummyTables>;
        fn register(&self, _: helios_hal::hv::RegisterId) -> Result<u64, NativeError> {
            Ok(0)
        }
        fn set_register(
            &mut self,
            _: helios_hal::hv::RegisterId,
            _: u64,
        ) -> Result<(), NativeError> {
            Ok(())
        }
        fn thread_pointer(&self) -> VirtAddr {
            VirtAddr::new(PhysFrame::SIZE)
        }
        fn set_thread_pointer(&mut self, _: VirtAddr) -> Result<(), NativeError> {
            Ok(())
        }
        fn extended_state(&self) -> helios_hal::native::ExtendedState {
            helios_hal::native::ExtendedState::X86Xsave(alloc::vec![0; 576])
        }
        fn set_extended_state(
            &mut self,
            _: &helios_hal::native::ExtendedState,
        ) -> Result<(), NativeError> {
            Ok(())
        }
        fn try_clone(&self) -> Result<Self, NativeError> {
            Ok(Self {
                entry: self.entry,
                stack: self.stack,
            })
        }
        fn resume(&mut self, _: &Self::Space) -> Stop {
            Stop::Interrupted
        }
    }

    #[derive(Clone)]
    struct NativeTestCpu {
        isa: helios_hal::native::InstructionSet,
        user_end: usize,
    }

    impl NativeExecution for NativeTestCpu {
        type Space = NativeSpace<DummyTables>;
        type Context = NativeTestContext;
        fn instruction_set(&self) -> helios_hal::native::InstructionSet {
            self.isa
        }
        fn user_range(&self) -> VirtRange {
            VirtRange::new(
                VirtAddr::new(PhysFrame::SIZE),
                self.user_end - PhysFrame::SIZE,
            )
        }
        fn create_space(&self) -> Result<Self::Space, NativeError> {
            Ok(NativeSpace::new(
                DummyTables,
                PhysFrame::SIZE as u64,
                self.user_end as u64,
            ))
        }
        fn create_context(
            &self,
            entry: VirtAddr,
            stack: VirtAddr,
        ) -> Result<Self::Context, NativeError> {
            Ok(NativeTestContext { entry, stack })
        }
    }

    impl Cpu for NativeTestCpu {
        type Hypervisor = core::convert::Infallible;
        type Native = Self;
        const TIMER_INTERRUPT: helios_hal::cpu::TimerInterrupt =
            helios_hal::cpu::TimerInterrupt::Deadline;
        fn native(&self) -> Result<&Self::Native, NativeUnavailable> {
            Ok(self)
        }
        fn has_lazy_commit_virtual_memory(&self) -> bool {
            true
        }
        fn processor_count(&self) -> usize {
            1
        }
        fn bootstrap_processor(&self) -> helios_hal::cpu::ProcessorId {
            helios_hal::cpu::ProcessorId::new(0)
        }
        fn park_current(&self) {}
        type WakeOnlyMask = ();
        fn mask_to_wake_only(&self) {}
        fn park_wake_only(&self, _: &core::sync::atomic::AtomicU8, _: u8) {}
        fn start_processor(&self, _: helios_hal::cpu::ProcessorId) {}
        fn wake_processor(&self, _: helios_hal::cpu::ProcessorId) {}
        fn stop_current(&self) {}
        fn restart_processor(&self, _: helios_hal::cpu::ProcessorId) {}
        fn now(&self) -> helios_hal::cpu::Instant {
            helios_hal::cpu::Instant::new(0)
        }
        fn timebase(&self) -> helios_hal::cpu::Timebase {
            helios_hal::cpu::Timebase::new(1_000_000_000)
        }
        fn set_deadline(&self, _: helios_hal::cpu::Instant) {}
        fn publish_executable(&self, _: *const u8, _: usize) {}
        fn unpublish_executable(&self, _: *const u8, _: usize) {}
        fn native_feature_probe(&self) -> Option<fn(&str) -> Option<bool>> {
            None
        }
        fn fill_entropy(
            &self,
            buffer: &mut [u8],
        ) -> Result<helios_hal::entropy::EntropyQuality, helios_hal::entropy::EntropyUnavailable>
        {
            buffer.fill(0x42);
            Ok(helios_hal::entropy::EntropyQuality::Cryptographic)
        }
        fn shutdown(&self) -> ! {
            unreachable!()
        }
        fn reboot(&self) -> ! {
            unreachable!()
        }
    }

    fn poll_ready<T>(fut: impl core::future::Future<Output = T>) -> T {
        use core::task::{Context, Poll, Waker};
        let mut fut = core::pin::pin!(fut);
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    #[test]
    fn file_backed_mmap_cow_across_fork_and_user_memory_pool_accounting() {
        use helios_linux::syscall::dispatch;

        #[derive(Clone)]
        struct TestFile {
            bytes: Bytes,
            access: FileAccess,
        }
        struct TestRes;
        impl Resources for TestRes {
            type File = TestFile;
            type Network = helios_unix::NoNetwork;
            type Data = u64;
        }
        struct TestThread;
        impl Thread<TestRes> for TestThread {
            fn thread_pointer(&self) -> u64 {
                0
            }
            fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
                Err(Denied)
            }
            fn spawn_thread(
                &mut self,
                _: Process<TestRes>,
                _: SpawnedThread,
            ) -> Result<(), SpawnError> {
                unreachable!()
            }
        }
        struct TestHost {
            file: TestFile,
        }
        impl syscall::Network<helios_unix::NoNetwork> for TestHost {
            fn to_ip(&self, a: core::convert::Infallible) -> syscall::IpAddr {
                match a {}
            }
            fn encode_ip(&self, _: syscall::IpAddr) -> core::convert::Infallible {
                unreachable!()
            }
        }
        impl Stdio for TestHost {
            async fn write(&mut self, _: Stream, _: &[u8]) -> Result<usize, WriteError> {
                Err(WriteError::Io)
            }
            async fn read_input(&mut self, _: usize) -> Result<Bytes, Denied> {
                Err(Denied)
            }
        }
        impl syscall::Clock for TestHost {
            fn now_nanos(&self) -> u64 {
                0
            }
            async fn sleep_until(&self, _: u64) {}
        }
        impl System for TestHost {
            fn realtime_nanos(&self) -> u64 {
                0
            }
            fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
                Err(Denied)
            }
            fn cpu_nanos(&self) -> u64 {
                0
            }
            fn fill_random(&mut self, _: &mut [u8]) {}
            fn memory(&self) -> MemoryTotals {
                MemoryTotals {
                    total_bytes: 0,
                    free_bytes: 0,
                }
            }
            fn process_count(&self) -> u32 {
                1
            }
            fn kernel_version(&self) -> &str {
                "test"
            }
        }
        impl Tty for TestHost {}
        impl Filesystem<TestRes> for TestHost {
            fn file_access(&self, file: &TestFile) -> FileAccess {
                file.access
            }
            fn can_exec_file(&self, _: &TestFile) -> bool {
                true
            }
            fn same_file(&self, _: &TestFile, _: &TestFile) -> bool {
                true
            }
            async fn open(
                &mut self,
                _: Option<&TestFile>,
                _: &str,
                _: &str,
                _: OpenRequest,
                _: &syscall::Credentials,
            ) -> Result<TestFile, syscall::FsOpError> {
                Ok(self.file.clone())
            }
            async fn stat_file(&self, file: &TestFile) -> Result<FileStat, syscall::FsOpError> {
                Ok(FileStat {
                    dev: 1,
                    ino: 1,
                    kind: NodeKind::File,
                    permissions: 0o644,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    size: file.bytes.len() as u64,
                    access_nanos: 0,
                    modified_nanos: 0,
                    status_nanos: 0,
                })
            }
            async fn read_at(
                &self,
                file: &TestFile,
                offset: u64,
                max_bytes: usize,
            ) -> Result<Bytes, syscall::FsOpError> {
                let start = (offset as usize).min(file.bytes.len());
                let end = start.saturating_add(max_bytes).min(file.bytes.len());
                Ok(file.bytes.slice(start..end))
            }
        }

        ensure_pool();
        let page = PhysFrame::SIZE as u64;
        let start = PhysFrame::SIZE;
        let end = 1usize << 32;
        let space = NativeSpace::new(DummyTables, start as u64, end as u64);
        let user = VirtRange::new(VirtAddr::new(start), end - start);
        let baseline = crate::memory::user_heap_stats().allocated_bytes;

        // Open a 500-byte regular file via descriptors slot 3.
        let mut payload = alloc::vec![0u8; 500];
        payload[..16].copy_from_slice(b"FILE-MMAP-COW!!!");
        let file = TestFile {
            bytes: Bytes::from(payload),
            access: FileAccess::ReadOnly,
        };
        let mut descs = syscall::standard_streams::<TestRes>();
        let fd = descs
            .insert_entry(helios_unix::FileDescriptorEntry::new(
                helios_unix::FileDescriptor::File(helios_unix::OpenFile::new(file.clone())),
                false,
            ))
            .expect("insert fd") as u64;

        let mut process = Process::with_descriptors(
            Abi::X86_64,
            NonZeroU32::new(1).unwrap(),
            0x50_0000,
            descs,
            Start::default(),
        );
        let mut host = TestHost { file };
        let mut memory = LinuxMemory {
            space: &space,
            user,
            stack_growth: None,
            shared_mem: None,
            shared_files: None,
        };
        let mut call = |number: u64,
                        arguments: [u64; 6],
                        memory: &mut LinuxMemory<'_, NativeSpace<DummyTables>>|
         -> u64 {
            let mut thread = TestThread;
            match poll_ready(dispatch(
                &mut process,
                Call { number, arguments },
                memory,
                &mut thread,
                &mut host,
            )) {
                ControlFlow::Continue(SyscallOutcome::Return(v)) => v,
                other => panic!("unexpected syscall outcome: {other:?}"),
            }
        };

        const SYS_MMAP: u64 = 9;
        const PROT_READ: u64 = 1;
        const PROT_RW: u64 = 3;
        const MAP_SHARED: u64 = 0x01;
        const MAP_PRIVATE: u64 = 0x02;
        const MAP_FIXED: u64 = 0x10;
        const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;

        // Map 3 pages of a 500-byte file MAP_PRIVATE | PROT_RW:
        // only page 0 commits a frame from UserMemoryPool; pages 1..2 stay uncommitted zero-tail!
        let priv_addr = call(
            SYS_MMAP,
            [0x100_0000, 3 * page, PROT_RW, MAP_PRIVATE, fd, 0],
            &mut memory,
        );
        assert_eq!(priv_addr, 0x100_0000);
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + PhysFrame::SIZE
        );

        // Read-only MAP_SHARED commits 1 frame and enforces read-only permissions.
        let ro_shared = call(
            SYS_MMAP,
            [
                0x200_0000,
                2 * page,
                PROT_READ,
                MAP_SHARED | MAP_FIXED_NOREPLACE,
                fd,
                0,
            ],
            &mut memory,
        );
        assert_eq!(ro_shared, 0x200_0000);
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 2 * PhysFrame::SIZE
        );
        assert!(
            space
                .check_writable(VirtAddr::new(ro_shared as usize), 1)
                .is_err()
        );

        // MAP_FIXED_NOREPLACE collides -> -EEXIST (17), MAP_FIXED replaces cleanly.
        assert_eq!(
            call(
                SYS_MMAP,
                [
                    ro_shared,
                    page,
                    PROT_READ,
                    MAP_PRIVATE | MAP_FIXED_NOREPLACE,
                    fd,
                    0
                ],
                &mut memory,
            ),
            17u64.wrapping_neg()
        );
        assert_eq!(
            call(
                SYS_MMAP,
                [ro_shared, page, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0],
                &mut memory,
            ),
            ro_shared
        );

        // Fork (`clone_cow`): 0 additional frames in UserMemoryPool; both spaces share page 0.
        let child_space = space.clone_cow().unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 2 * PhysFrame::SIZE
        );
        assert!(space.is_page_shared(VirtAddr::new(priv_addr as usize)));
        assert!(child_space.is_page_shared(VirtAddr::new(priv_addr as usize)));

        // Child write breaks CoW (+1 frame in UserMemoryPool); parent retains original bytes & zero-tail.
        child_space
            .write(VirtAddr::new(priv_addr as usize), b"CHILD-MUTATED!!!")
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 3 * PhysFrame::SIZE
        );
        let mut parent_buf = [0xffu8; 32];
        let mut child_buf = [0xffu8; 32];
        let mut eof_tail = [0xffu8; 32];
        space
            .read(VirtAddr::new(priv_addr as usize), &mut parent_buf)
            .unwrap();
        child_space
            .read(VirtAddr::new(priv_addr as usize), &mut child_buf)
            .unwrap();
        space
            .read(VirtAddr::new((priv_addr + 500) as usize), &mut eof_tail)
            .unwrap();
        assert_eq!(&parent_buf[..16], b"FILE-MMAP-COW!!!");
        assert_eq!(&child_buf[..16], b"CHILD-MUTATED!!!");
        assert!(eof_tail.iter().all(|&b| b == 0));

        drop(child_space);
        drop(space);
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);
    }

    #[test]
    fn dynamic_elf_loading_and_interpreter_confinement_for_x86_64_and_aarch64() {
        use crate::test_support::UnsupportedStorage;
        use crate::vfs::BOOT_DEVICE;
        use crate::{
            BootFs, ContainerConfig, ContainerId, ContainerMountSharing, ContainerMountSpec,
            DirectoryAuthorityRights, EmbeddedBootDirectory, EmbeddedBootFile, EmbeddedBootFs,
            LinuxContainer, ProcessAuthority, SharedOwner,
        };
        use helios_linux::syscall::{Credentials, UtsField};

        ensure_pool();
        let entropy = crate::RootEntropy::from_platform(
            &crate::test_support::TestCpu::with_entropy(0x42),
            None,
            None,
            crate::MachineGeneration::new(None),
        )
        .expect("root entropy");

        for (abi, isa, user_end) in [
            (
                Abi::X86_64,
                helios_hal::native::InstructionSet::X86_64,
                1usize << 32,
            ),
            (
                Abi::Aarch64,
                helios_hal::native::InstructionSet::Aarch64,
                1usize << 32,
            ),
        ] {
            let cpu = NativeTestCpu { isa, user_end };
            let interp_elf: &'static [u8] =
                Box::leak(build_test_elf(abi, 3, 0, None).into_boxed_slice());
            let bad_recursive: &'static [u8] =
                Box::leak(build_test_elf(abi, 3, 0, Some(b"/lib/ld.so\0")).into_boxed_slice());
            let pie_main: &'static [u8] =
                Box::leak(build_test_elf(abi, 3, 0, Some(b"/lib/ld.so\0")).into_boxed_slice());
            let pie_escape: &'static [u8] = Box::leak(
                build_test_elf(abi, 3, 0, Some(b"/../../../lib/ld.so\0")).into_boxed_slice(),
            );
            let pie_missing: &'static [u8] =
                Box::leak(build_test_elf(abi, 3, 0, Some(b"/lib/missing.so\0")).into_boxed_slice());
            let pie_recursive: &'static [u8] = Box::leak(
                build_test_elf(abi, 3, 0, Some(b"/lib/bad_interp.so\0")).into_boxed_slice(),
            );
            let pie_noexec: &'static [u8] =
                Box::leak(build_test_elf(abi, 3, 0, Some(b"/noexec/ld.so\0")).into_boxed_slice());
            let pie_noread: &'static [u8] =
                Box::leak(build_test_elf(abi, 3, 0, Some(b"/noread/ld.so\0")).into_boxed_slice());

            let dirs: &'static [EmbeddedBootDirectory] = Box::leak(
                alloc::vec![
                    EmbeddedBootDirectory::new("root", 0),
                    EmbeddedBootDirectory::new("root/bin", 0),
                    EmbeddedBootDirectory::new("root/lib", 0),
                    EmbeddedBootDirectory::new("root/noexec", 0),
                    EmbeddedBootDirectory::new("root/noread", 0),
                    EmbeddedBootDirectory::new("noexec_src", 0),
                    EmbeddedBootDirectory::new("noread_src", 0),
                ]
                .into_boxed_slice(),
            );
            let entries: &'static [EmbeddedBootFile] = Box::leak(
                alloc::vec![
                    EmbeddedBootFile::new("root/lib/ld.so", interp_elf, 0),
                    EmbeddedBootFile::new("root/lib/bad_interp.so", bad_recursive, 0),
                    EmbeddedBootFile::new("root/bin/pie", pie_main, 0),
                    EmbeddedBootFile::new("noexec_src/ld.so", interp_elf, 0),
                    EmbeddedBootFile::new("noread_src/ld.so", interp_elf, 0),
                ]
                .into_boxed_slice(),
            );
            let boot_fs = BootFs::new(EmbeddedBootFs::new(dirs, entries), BOOT_DEVICE);
            let host_ns =
                crate::Namespace::<UnsupportedStorage>::new(crate::MountTable::new(boot_fs, 8));
            let root_auth = ProcessAuthority::root();
            let container = poll_ready(LinuxContainer::create(
                ContainerId::new(core::num::NonZeroU64::new(1).unwrap()),
                &root_auth,
                &host_ns,
                ProcessAuthority::root(),
                ContainerConfig {
                    root: ContainerMountSpec {
                        source_path: String::from("/root"),
                        target_path: String::from("/"),
                        rights: DirectoryAuthorityRights::READ | DirectoryAuthorityRights::EXECUTE,
                        sharing: ContainerMountSharing::Shared,
                    },
                    mounts: alloc::vec![
                        ContainerMountSpec {
                            source_path: String::from("/noexec_src"),
                            target_path: String::from("/noexec"),
                            rights: DirectoryAuthorityRights::READ,
                            sharing: ContainerMountSharing::Shared,
                        },
                        ContainerMountSpec {
                            source_path: String::from("/noread_src"),
                            target_path: String::from("/noread"),
                            rights: DirectoryAuthorityRights::EXECUTE,
                            sharing: ContainerMountSharing::Shared,
                        },
                    ],
                    shared_owner: SharedOwner { uid: 0, gid: 0 },
                    credentials: Credentials::root(),
                    hostname: UtsField::from_bytes(b"helios-elf").unwrap(),
                    domainname: UtsField::from_bytes(b"").unwrap(),
                },
            ))
            .expect("create container");

            let creds = Credentials::root();

            // 1. Valid ET_DYN + PT_INTERP loads and maps at non-overlapping bases with complete auxv.
            let loaded = poll_ready(LinuxExecutable::load_in_container(
                &cpu,
                &container,
                "/",
                Bytes::from_static(pie_main),
                Some(String::from("/bin/pie")),
                &creds,
            ))
            .expect("load dynamic PIE");
            let mapped = map_linux_image(
                &cpu,
                &entropy,
                &loaded,
                &[String::from("custom-argv0")],
                &[String::from("PATH=/bin")],
                &creds,
                false,
            )
            .expect("map dynamic PIE");

            // Parse auxv directly out of the mapped NativeSpace stack.
            let read_u64 = |addr: u64| {
                let mut raw = [0u8; 8];
                mapped
                    .space
                    .read(VirtAddr::new(addr as usize), &mut raw)
                    .unwrap();
                u64::from_le_bytes(raw)
            };
            let mut cursor = mapped.context.stack.raw() as u64;
            let argc = read_u64(cursor);
            assert_eq!(argc, 1);
            cursor += 8 + (argc + 1) * 8;
            while read_u64(cursor) != 0 {
                cursor += 8;
            }
            cursor += 8;
            let mut auxv = alloc::collections::BTreeMap::new();
            loop {
                let tag = read_u64(cursor);
                let val = read_u64(cursor + 8);
                cursor += 16;
                if tag == 0 {
                    break;
                }
                auxv.insert(tag, val);
            }
            let at_phdr = *auxv.get(&3).expect("AT_PHDR");
            let at_phent = *auxv.get(&4).expect("AT_PHENT");
            let at_phnum = *auxv.get(&5).expect("AT_PHNUM");
            let at_base = *auxv.get(&7).expect("AT_BASE");
            let at_flags = *auxv.get(&8).expect("AT_FLAGS");
            let at_entry = *auxv.get(&9).expect("AT_ENTRY");
            let at_execfn = *auxv.get(&31).expect("AT_EXECFN");

            assert_eq!(at_phent, 56);
            assert_eq!(at_phnum, 4);
            assert_eq!(at_flags, 0);
            assert_ne!(at_base, 0);
            assert_ne!(at_entry, mapped.context.entry.raw() as u64);
            // Context entry is the interpreter's entry (at_base + 0x1000).
            assert_eq!(mapped.context.entry.raw() as u64, at_base + 0x1000);
            // Program headers at AT_PHDR match the main ELF's program headers.
            let mut phdr_bytes = [0u8; 56];
            mapped
                .space
                .read(VirtAddr::new(at_phdr as usize), &mut phdr_bytes)
                .unwrap();
            assert_eq!(&phdr_bytes, &pie_main[64..120]);
            // Interpreter bytes at AT_BASE match the interpreter ELF magic.
            let mut interp_magic = [0u8; 4];
            mapped
                .space
                .read(VirtAddr::new(at_base as usize), &mut interp_magic)
                .unwrap();
            assert_eq!(&interp_magic, b"\x7fELF");
            // AT_EXECFN carries the executed binary path (not argv[0]).
            let mut execfn_bytes = [0u8; 8];
            mapped
                .space
                .read(VirtAddr::new(at_execfn as usize), &mut execfn_bytes)
                .unwrap();
            assert_eq!(&execfn_bytes, b"/bin/pie");
            // program_break sits below interpreter so brk growth succeeds.
            assert!(mapped.program_break < at_base);

            // 2. `..` traversal in PT_INTERP stays confined to container root.
            poll_ready(LinuxExecutable::load_in_container(
                &cpu,
                &container,
                "/",
                Bytes::from_static(pie_escape),
                Some(String::from("/bin/pie_escape")),
                &creds,
            ))
            .expect("clamped container-relative PT_INTERP resolves inside root");

            // 3. Missing interpreter -> NotFound.
            let missing_err = poll_ready(LinuxExecutable::load_in_container(
                &cpu,
                &container,
                "/",
                Bytes::from_static(pie_missing),
                None,
                &creds,
            ))
            .err()
            .expect("missing interpreter fails");
            assert_eq!(missing_err.kind, ProgramExecErrorKind::NotFound);

            // 4. Interpreter on READ-only (no EXECUTE) mount -> PermissionDenied.
            let noexec_err = poll_ready(LinuxExecutable::load_in_container(
                &cpu,
                &container,
                "/",
                Bytes::from_static(pie_noexec),
                None,
                &creds,
            ))
            .err()
            .expect("noexec interpreter fails");
            assert_eq!(noexec_err.kind, ProgramExecErrorKind::PermissionDenied);

            // 5. Interpreter on EXECUTE-only (no READ) mount -> PermissionDenied.
            let noread_err = poll_ready(LinuxExecutable::load_in_container(
                &cpu,
                &container,
                "/",
                Bytes::from_static(pie_noread),
                None,
                &creds,
            ))
            .err()
            .expect("noread interpreter fails");
            assert_eq!(noread_err.kind, ProgramExecErrorKind::PermissionDenied);

            // 6. Recursive PT_INTERP inside interpreter -> InvalidBinary(Interpreter).
            let rec_err = poll_ready(LinuxExecutable::load_in_container(
                &cpu,
                &container,
                "/",
                Bytes::from_static(pie_recursive),
                None,
                &creds,
            ))
            .err()
            .expect("recursive interpreter fails");
            assert_eq!(rec_err.kind, ProgramExecErrorKind::InvalidBinary);
            assert_eq!(
                rec_err.detail,
                ProgramExecErrorDetail::LinuxImageInvalid(crate::LinuxImageRefusal::Interpreter)
            );
        }
    }

    #[test]
    fn map_shared_coherence_vm_mayexec_madvise_and_sigbus_beyond_eof() {
        use core::future::Future;
        use core::task::{Context, Poll, Waker};
        use helios_linux::syscall::{
            Clock, Denied, FileAccess, FileStat, Filesystem, MemoryTotals, OpenRequest, Process,
            Resources, Start, Stdio, Stream, SyscallOutcome, System, Thread, Tty, WriteError,
            dispatch,
        };

        fn poll_ready<F: Future>(future: F) -> F::Output {
            let mut fut = core::pin::pin!(future);
            match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(v) => v,
                Poll::Pending => panic!("in-memory test future unexpectedly yielded"),
            }
        }

        #[derive(Clone)]
        struct SharedTestFile {
            ino: u64,
            data: Arc<spin::Mutex<Vec<u8>>>,
            access: FileAccess,
            exec_allowed: bool,
            shared_files: Arc<crate::linux_container::SharedFileCache>,
        }
        struct SharedTestRes;
        impl Resources for SharedTestRes {
            type File = SharedTestFile;
            type Network = helios_unix::NoNetwork;
            type Data = u64;
        }
        struct SharedTestThread;
        impl Thread<SharedTestRes> for SharedTestThread {
            fn thread_pointer(&self) -> u64 {
                0
            }
            fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
                Err(Denied)
            }
            fn spawn_thread(
                &mut self,
                _: Process<SharedTestRes>,
                _: syscall::SpawnedThread,
            ) -> Result<(), syscall::SpawnError> {
                unreachable!()
            }
        }
        struct SharedTestHost;
        impl syscall::Network<helios_unix::NoNetwork> for SharedTestHost {
            fn to_ip(&self, a: core::convert::Infallible) -> syscall::IpAddr {
                match a {}
            }
            fn encode_ip(&self, _: syscall::IpAddr) -> core::convert::Infallible {
                unreachable!()
            }
        }
        impl Stdio for SharedTestHost {
            async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
                Ok(bytes.len())
            }
            async fn read_input(&mut self, _: usize) -> Result<Bytes, Denied> {
                Err(Denied)
            }
        }
        impl Clock for SharedTestHost {
            fn now_nanos(&self) -> u64 {
                0
            }
            async fn sleep_until(&self, _: u64) {}
        }
        impl System for SharedTestHost {
            fn realtime_nanos(&self) -> u64 {
                0
            }
            fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
                Err(Denied)
            }
            fn cpu_nanos(&self) -> u64 {
                0
            }
            fn fill_random(&mut self, _: &mut [u8]) {}
            fn memory(&self) -> MemoryTotals {
                MemoryTotals {
                    total_bytes: 0,
                    free_bytes: 0,
                }
            }
            fn process_count(&self) -> u32 {
                1
            }
            fn kernel_version(&self) -> &str {
                "test"
            }
        }
        impl Tty for SharedTestHost {}
        impl Filesystem<SharedTestRes> for SharedTestHost {
            fn file_access(&self, file: &SharedTestFile) -> FileAccess {
                file.access
            }
            fn can_exec_file(&self, file: &SharedTestFile) -> bool {
                file.exec_allowed
            }
            fn same_file(&self, a: &SharedTestFile, b: &SharedTestFile) -> bool {
                a.ino == b.ino
            }
            async fn stat_file(
                &self,
                file: &SharedTestFile,
            ) -> Result<FileStat, syscall::FsOpError> {
                Ok(FileStat {
                    dev: 7,
                    ino: file.ino,
                    kind: NodeKind::File,
                    permissions: if file.exec_allowed { 0o755 } else { 0o644 },
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    size: file.data.lock().len() as u64,
                    access_nanos: 0,
                    modified_nanos: 0,
                    status_nanos: 0,
                })
            }
            async fn read_at(
                &self,
                file: &SharedTestFile,
                offset: u64,
                max_bytes: usize,
            ) -> Result<Bytes, syscall::FsOpError> {
                let guard = file.data.lock();
                let start = (offset as usize).min(guard.len());
                let end = start.saturating_add(max_bytes).min(guard.len());
                let mut out = guard[start..end].to_vec();
                drop(guard);
                file.shared_files
                    .overlay_file_read(7, file.ino, offset, &mut out);
                Ok(Bytes::from(out))
            }
            async fn write_at(
                &mut self,
                file: &SharedTestFile,
                position: helios_hal::fs::WritePosition,
                bytes: &[u8],
                _: &syscall::Credentials,
            ) -> Result<helios_hal::fs::Landed, syscall::FsOpError> {
                let mut guard = file.data.lock();
                let at = match position {
                    helios_hal::fs::WritePosition::At(off) => off as usize,
                    helios_hal::fs::WritePosition::End => guard.len(),
                };
                if at + bytes.len() > guard.len() {
                    guard.resize(at + bytes.len(), 0);
                }
                guard[at..at + bytes.len()].copy_from_slice(bytes);
                drop(guard);
                file.shared_files
                    .apply_file_write(7, file.ino, at as u64, bytes);
                Ok(helios_hal::fs::Landed {
                    offset: at as u64,
                    len: bytes.len(),
                })
            }
            async fn sync(&self, _: &SharedTestFile, _: bool) -> Result<(), syscall::FsOpError> {
                Ok(())
            }
            async fn open(
                &mut self,
                _: Option<&SharedTestFile>,
                _: &str,
                _: &str,
                _: OpenRequest,
                _: &syscall::Credentials,
            ) -> Result<SharedTestFile, syscall::FsOpError> {
                Err(syscall::FsOpError::Fs(helios_hal::fs::FsError::NoEntry))
            }
        }

        ensure_pool();
        let page = PhysFrame::SIZE as u64;
        let start = PhysFrame::SIZE;
        let end = 1usize << 32;
        let space = NativeSpace::new(DummyTables, start as u64, end as u64);
        let user = VirtRange::new(VirtAddr::new(start), end - start);
        let shared_mem = spin::Mutex::new(SharedMemoryTable::new());
        let shared_files = Arc::new(crate::linux_container::SharedFileCache::new());

        let backing = Arc::new(spin::Mutex::new(b"AAAA----BBBB----CCCC".to_vec()));
        let rw_file = SharedTestFile {
            ino: 101,
            data: backing.clone(),
            access: FileAccess::ReadWrite,
            exec_allowed: false,
            shared_files: shared_files.clone(),
        };
        let mut descs = syscall::standard_streams::<SharedTestRes>();
        let fd = descs
            .insert_entry(helios_unix::FileDescriptorEntry::new(
                helios_unix::FileDescriptor::File(helios_unix::OpenFile::new(rw_file.clone())),
                false,
            ))
            .expect("insert fd") as u64;

        let mut process = Process::with_descriptors(
            Abi::X86_64,
            NonZeroU32::new(1).unwrap(),
            0x50_0000,
            descs,
            Start::default(),
        );
        let mut host = SharedTestHost;
        let mut memory = LinuxMemory {
            space: &space,
            user,
            stack_growth: None,
            shared_mem: Some(&shared_mem),
            shared_files: Some(&shared_files),
        };
        let mut call = |number: u64,
                        arguments: [u64; 6],
                        memory: &mut LinuxMemory<'_, NativeSpace<DummyTables>>|
         -> u64 {
            let mut thread = SharedTestThread;
            match poll_ready(dispatch(
                &mut process,
                Call { number, arguments },
                memory,
                &mut thread,
                &mut host,
            )) {
                ControlFlow::Continue(SyscallOutcome::Return(v)) => v,
                other => panic!("unexpected syscall outcome: {other:?}"),
            }
        };

        const SYS_MMAP: u64 = 9;
        const SYS_MPROTECT: u64 = 10;
        const SYS_MSYNC: u64 = 26;
        const SYS_MADVISE: u64 = 28;
        const PROT_NONE: u64 = 0;
        const PROT_READ: u64 = 1;
        const PROT_RW: u64 = 3;
        const PROT_RX: u64 = 5;
        const MAP_SHARED: u64 = 0x01;
        const MAP_PRIVATE: u64 = 0x02;
        const MS_SYNC: u64 = 4;
        const MADV_DONTNEED: u64 = 4;
        const MADV_FREE: u64 = 8;
        const EACCES_NEG: u64 = (-13i64) as u64;
        const EINVAL_NEG: u64 = (-22i64) as u64;

        // 1. Two MAP_SHARED mappings of the same file share the exact underlying frame,
        //    and a 2-page mapping leaves page 1 beyond EOF (BackingFault -> SIGBUS).
        let map_a = call(
            SYS_MMAP,
            [0x100_0000, 2 * page, PROT_RW, MAP_SHARED, fd, 0],
            &mut memory,
        );
        let map_b = call(
            SYS_MMAP,
            [0x200_0000, page, PROT_RW, MAP_SHARED, fd, 0],
            &mut memory,
        );
        assert_eq!(map_a, 0x100_0000);
        assert_eq!(map_b, 0x200_0000);
        space.write(VirtAddr::new(map_a as usize), b"1111").unwrap();
        let mut seen = [0u8; 20];
        space
            .read(VirtAddr::new(map_b as usize), &mut seen)
            .unwrap();
        assert_eq!(&seen, b"1111----BBBB----CCCC");

        // 2. Concurrent write(2) updates bytes 8..12 without clobbering mmap's dirty 0..4;
        //    mprotect(PROT_NONE) preserves dirty bytes for msync!
        poll_ready(SharedTestHost.write_at(
            &rw_file,
            helios_hal::fs::WritePosition::At(8),
            b"2222",
            &syscall::Credentials::root(),
        ))
        .expect("write(2) succeeds");
        assert_eq!(
            call(SYS_MPROTECT, [map_a, page, PROT_NONE, 0, 0, 0], &mut memory),
            0
        );
        assert_eq!(
            call(SYS_MSYNC, [map_a, page, MS_SYNC, 0, 0, 0], &mut memory),
            0
        );
        assert_eq!(
            backing.lock().as_slice(),
            b"1111----2222----CCCC",
            "msync after PROT_NONE writes only dirty mmap bytes without clobbering write(2)"
        );

        // 3. VM_MAYEXEC: mmap(PROT_READ) on a non-executable file + mprotect(PROT_EXEC) -> EACCES.
        let ro_noexec = call(
            SYS_MMAP,
            [0x300_0000, 2 * page, PROT_READ, MAP_PRIVATE, fd, 0],
            &mut memory,
        );
        assert_eq!(ro_noexec, 0x300_0000);
        assert_eq!(
            call(
                SYS_MPROTECT,
                [ro_noexec, page, PROT_RX, 0, 0, 0],
                &mut memory
            ),
            EACCES_NEG,
            "mprotect(PROT_EXEC) must fail with EACCES when VM_MAYEXEC is false"
        );

        // 4. madvise(MADV_DONTNEED) on file-backed MAP_PRIVATE reloads file bytes,
        //    on MAP_SHARED preserves shared bytes, and MADV_FREE returns EINVAL.
        let priv_rw = call(
            SYS_MMAP,
            [0x400_0000, page, PROT_RW, MAP_PRIVATE, fd, 0],
            &mut memory,
        );
        assert_eq!(priv_rw, 0x400_0000);
        space
            .write(VirtAddr::new(priv_rw as usize), b"DIRTY-PRIV")
            .unwrap();
        assert_eq!(
            call(
                SYS_MADVISE,
                [priv_rw, page, MADV_FREE, 0, 0, 0],
                &mut memory
            ),
            EINVAL_NEG
        );
        assert_eq!(
            call(
                SYS_MADVISE,
                [priv_rw, page, MADV_DONTNEED, 0, 0, 0],
                &mut memory
            ),
            0
        );
        space
            .read(VirtAddr::new(priv_rw as usize), &mut seen)
            .unwrap();
        assert_eq!(
            &seen, b"1111----2222----CCCC",
            "MADV_DONTNEED on file-backed MAP_PRIVATE reloads from file instead of zeroing"
        );
        assert_eq!(
            call(
                SYS_MADVISE,
                [map_b, page, MADV_DONTNEED, 0, 0, 0],
                &mut memory
            ),
            0
        );
        space
            .read(VirtAddr::new(map_b as usize), &mut seen)
            .unwrap();
        assert_eq!(
            &seen, b"1111----2222----CCCC",
            "MADV_DONTNEED on MAP_SHARED preserves shared contents"
        );

        // 5. Beyond-EOF page (map_a + page) triggers BackingFault and delivers SIGBUS.
        assert_eq!(
            space.resolve_fault(VirtAddr::new((map_a + page) as usize), PageFlags::READ),
            Err(NativeError::BackingFault)
        );
        let mut ctx = NativeTestContext {
            entry: VirtAddr::new(0x40_0000),
            stack: VirtAddr::new(0x50_0000),
        };
        assert_eq!(
            process.deliver_bus_fault(map_a + page, &mut ctx, &mut memory, 0),
            SignalDelivery::Terminated {
                signal: helios_unix::Signal::SIGBUS,
                core_dumped: true,
            }
        );
    }
}
