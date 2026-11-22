//! ABI tests for `capget`/`capset`, `chmod`/`chown`/`mknod` and extended
//! attribute system call decoding across x86-64 and AArch64.

use core::future::Future;
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use core::task::{Context, Poll, Waker};
use helios_hal::fs::NodeKind;
use helios_hal::vmm::PageFlags;
use helios_linux::abi::{Abi, Operation};
use helios_linux::syscall::{
    CAP_DAC_OVERRIDE, CAP_MKNOD, CAP_SETFCAP, CAP_SYS_ADMIN, Call, Clock, Credentials, Denied,
    FileAccess, Filesystem, FsOpError, MapError, MemoryFault, MemoryTotals, Process, Region,
    Resources, SpawnError, SpawnedThread, Stdio, Stream, SyscallOutcome, System, Thread, Tty,
    UserMemory, VirtualMemory, WriteError, XattrSetMode, dispatch,
};
use helios_unix::NoNetwork;
use std::collections::BTreeMap;

const EPERM: u64 = 1;
const E2BIG: u64 = 7;
const EFAULT: u64 = 14;
const EINVAL: u64 = 22;
const ERANGE: u64 = 34;

fn err(code: u64) -> u64 {
    code.wrapping_neg()
}

fn syscall_num(abi: Abi, op: Operation) -> u64 {
    (0..500)
        .find(|&n| abi.operation(n) == op)
        .unwrap_or_else(|| panic!("operation {op:?} not present on {abi:?}"))
}

#[derive(Default)]
struct FlatMem(BTreeMap<u64, u8>);

impl FlatMem {
    fn write_bytes(&mut self, addr: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.0.insert(addr + i as u64, b);
        }
    }
    fn write_cstr(&mut self, addr: u64, s: &str) {
        self.write_bytes(addr, s.as_bytes());
        self.0.insert(addr + s.len() as u64, 0);
    }
    fn read_bytes(&self, addr: u64, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| *self.0.get(&(addr + i as u64)).unwrap_or(&0))
            .collect()
    }
}

impl UserMemory for FlatMem {
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        for (i, slot) in output.iter_mut().enumerate() {
            *slot = *self.0.get(&(address + i as u64)).ok_or(MemoryFault)?;
        }
        Ok(())
    }
    fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
        if address == 0 && length > 0 {
            return Err(MemoryFault);
        }
        Ok(())
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
        if address == 0 {
            return Err(MemoryFault);
        }
        self.write_bytes(address, bytes);
        Ok(())
    }
    fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
        let mut raw = [0u8; 4];
        self.read(address, &mut raw)?;
        Ok(u32::from_le_bytes(raw))
    }
    fn atomic_store_u32(&mut self, address: u64, value: u32) -> Result<(), MemoryFault> {
        self.write(address, &value.to_le_bytes())
    }
    fn atomic_compare_exchange_u32(
        &mut self,
        address: u64,
        expected: u32,
        desired: u32,
    ) -> Result<Result<u32, u32>, MemoryFault> {
        let cur = self.atomic_load_u32(address)?;
        if cur == expected {
            self.atomic_store_u32(address, desired)?;
            Ok(Ok(cur))
        } else {
            Ok(Err(cur))
        }
    }
}

impl VirtualMemory for FlatMem {
    fn lowest_address(&self) -> u64 {
        0x1000
    }
    fn map_anywhere(&mut self, _: u64, _: u64, _: PageFlags) -> Result<u64, MapError> {
        Err(MapError::OutOfMemory)
    }
    fn map_at(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), MapError> {
        Err(MapError::OutOfMemory)
    }
    fn unmap(&mut self, _: u64, _: u64) {}
    fn protect(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), MapError> {
        Ok(())
    }
    fn discard(&mut self, _: u64, _: u64) {}
    fn remap(&mut self, _: u64, _: u64, _: u64, _: u64) -> Result<(), MapError> {
        Err(MapError::OutOfMemory)
    }
    fn region(&self, _: u64, _: u64) -> Option<Region> {
        None
    }
    fn free_range(&self, _: u64, _: u64) -> Option<u64> {
        None
    }
}

struct DummyRes;
impl Resources for DummyRes {
    type File = ();
    type Network = NoNetwork;
    type Data = u64;
}

struct DummyThread;
impl Thread<DummyRes> for DummyThread {
    fn thread_pointer(&self) -> u64 {
        0
    }
    fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
        Ok(())
    }
    fn spawn_thread(&mut self, _: Process<DummyRes>, _: SpawnedThread) -> Result<(), SpawnError> {
        Err(SpawnError::Busy)
    }
}

#[derive(Default)]
struct RecordingHost {
    last_chmod: Option<(String, bool, u32)>,
    last_chown: Option<(String, bool, Option<u32>, Option<u32>)>,
    last_mknod: Option<(String, NodeKind, u32, u32, u64)>,
    xattrs: BTreeMap<String, Vec<u8>>,
}

impl Stdio for RecordingHost {
    async fn read_input(&mut self, _: usize) -> Result<bytes::Bytes, Denied> {
        Ok(bytes::Bytes::new())
    }
    async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        Ok(bytes.len())
    }
}
impl Clock for RecordingHost {
    fn now_nanos(&self) -> u64 {
        0
    }
    async fn sleep_until(&self, _: u64) {}
}
impl System for RecordingHost {
    fn realtime_nanos(&self) -> u64 {
        0
    }
    fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
        Err(Denied)
    }
    fn cpu_nanos(&self) -> u64 {
        0
    }
    fn fill_random(&mut self, out: &mut [u8]) {
        out.fill(0);
    }
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
impl Tty for RecordingHost {}
impl helios_linux::syscall::Network<NoNetwork> for RecordingHost {
    fn to_ip(&self, address: core::convert::Infallible) -> helios_linux::syscall::IpAddr {
        match address {}
    }
    fn encode_ip(&self, _: helios_linux::syscall::IpAddr) -> core::convert::Infallible {
        unreachable!()
    }
}
impl Filesystem<DummyRes> for RecordingHost {
    fn file_access(&self, _: &()) -> FileAccess {
        FileAccess::ReadWrite
    }
    async fn chmod_path(
        &mut self,
        _: Option<&()>,
        _: &str,
        path: &str,
        follow: bool,
        mode: u32,
        _: &Credentials,
    ) -> Result<(), FsOpError> {
        self.last_chmod = Some((String::from(path), follow, mode));
        Ok(())
    }
    async fn chown_path(
        &mut self,
        _: Option<&()>,
        _: &str,
        path: &str,
        follow: bool,
        uid: Option<u32>,
        gid: Option<u32>,
        _: &Credentials,
    ) -> Result<(), FsOpError> {
        self.last_chown = Some((String::from(path), follow, uid, gid));
        Ok(())
    }
    async fn mknod(
        &mut self,
        _: Option<&()>,
        _: &str,
        path: &str,
        kind: NodeKind,
        mode: u32,
        umask: u32,
        rdev: u64,
        _: &Credentials,
    ) -> Result<(), FsOpError> {
        self.last_mknod = Some((String::from(path), kind, mode, umask, rdev));
        Ok(())
    }
    async fn set_xattr_path(
        &mut self,
        _: &str,
        _: &str,
        _: bool,
        name: &str,
        value: &[u8],
        _: XattrSetMode,
        _: &Credentials,
    ) -> Result<(), FsOpError> {
        self.xattrs.insert(String::from(name), value.to_vec());
        Ok(())
    }
    async fn get_xattr_path(
        &self,
        _: &str,
        _: &str,
        _: bool,
        name: &str,
        _: &Credentials,
    ) -> Result<Vec<u8>, FsOpError> {
        self.xattrs.get(name).cloned().ok_or(FsOpError::NoData)
    }
    async fn list_xattrs_path(
        &self,
        _: &str,
        _: &str,
        _: bool,
        _: &Credentials,
    ) -> Result<Vec<String>, FsOpError> {
        Ok(self.xattrs.keys().cloned().collect())
    }
    async fn remove_xattr_path(
        &mut self,
        _: &str,
        _: &str,
        _: bool,
        name: &str,
        _: &Credentials,
    ) -> Result<(), FsOpError> {
        self.xattrs
            .remove(name)
            .map(|_| ())
            .ok_or(FsOpError::NoData)
    }
}

fn run_call(
    process: &mut Process<DummyRes>,
    abi: Abi,
    op: Operation,
    args: [u64; 6],
    mem: &mut FlatMem,
    host: &mut RecordingHost,
) -> u64 {
    let mut thread = DummyThread;
    let call = Call {
        number: syscall_num(abi, op),
        arguments: args,
    };
    let mut fut = core::pin::pin!(dispatch(process, call, mem, &mut thread, host));
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(ControlFlow::Continue(SyscallOutcome::Return(res))) => res,
        other => panic!("unexpected outcome for {op:?}: {other:?}"),
    }
}

#[test]
fn capget_and_capset_work_across_both_abis() {
    const V3: u32 = 0x2008_0522;
    for abi in [Abi::X86_64, Abi::Aarch64] {
        let mut proc = Process::<DummyRes>::new(abi, NonZeroU32::new(1).unwrap(), 0x40_0000);
        let mut mem = FlatMem::default();
        let mut host = RecordingHost::default();

        // Version probe with datap == NULL writes V3 and returns 0.
        let hdr = 0x1000;
        mem.write_bytes(hdr, &0u32.to_le_bytes());
        mem.write_bytes(hdr + 4, &0i32.to_le_bytes());
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Capget,
                [hdr, 0, 0, 0, 0, 0],
                &mut mem,
                &mut host
            ),
            0
        );
        assert_eq!(
            u32::from_le_bytes(mem.read_bytes(hdr, 4).try_into().unwrap()),
            V3
        );

        // Invalid version with non-null datap returns EINVAL and overwrites version with V3.
        mem.write_bytes(hdr, &0x1234_5678u32.to_le_bytes());
        let data = 0x2000;
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Capget,
                [hdr, data, 0, 0, 0, 0],
                &mut mem,
                &mut host
            ),
            err(EINVAL)
        );
        assert_eq!(
            u32::from_le_bytes(mem.read_bytes(hdr, 4).try_into().unwrap()),
            V3
        );

        // Read full root caps.
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Capget,
                [hdr, data, 0, 0, 0, 0],
                &mut mem,
                &mut host
            ),
            0
        );
        let eff0 = u32::from_le_bytes(mem.read_bytes(data, 4).try_into().unwrap());
        assert_ne!(eff0 & (1 << CAP_MKNOD), 0);
        assert_ne!(eff0 & (1 << CAP_SETFCAP), 0);
        assert_ne!(eff0 & (1 << CAP_SYS_ADMIN), 0);

        // Drop CAP_MKNOD and CAP_DAC_OVERRIDE from effective + permitted.
        let keep_lo = eff0 & !((1 << CAP_MKNOD) | (1 << CAP_DAC_OVERRIDE));
        let mut next = [0u8; 24];
        next[0..4].copy_from_slice(&keep_lo.to_le_bytes());
        next[4..8].copy_from_slice(&keep_lo.to_le_bytes());
        mem.write_bytes(data, &next);
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Capset,
                [hdr, data, 0, 0, 0, 0],
                &mut mem,
                &mut host
            ),
            0
        );

        // Attempting to re-add CAP_MKNOD fails with EPERM.
        next[0..4].copy_from_slice(&eff0.to_le_bytes());
        next[4..8].copy_from_slice(&eff0.to_le_bytes());
        mem.write_bytes(data, &next);
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Capset,
                [hdr, data, 0, 0, 0, 0],
                &mut mem,
                &mut host
            ),
            err(EPERM)
        );

        // mknodat for char device now fails with EPERM because CAP_MKNOD was dropped.
        let path_addr = 0x3000;
        mem.write_cstr(path_addr, "/devnode");
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Mknodat,
                [(-100i32) as u32 as u64, path_addr, 0o020_666, 0x0103, 0, 0],
                &mut mem,
                &mut host
            ),
            err(EPERM)
        );
    }
}

#[test]
fn chmod_chown_mknod_and_xattr_syscalls_decode_on_both_abis() {
    for abi in [Abi::X86_64, Abi::Aarch64] {
        let mut proc = Process::<DummyRes>::new(abi, NonZeroU32::new(1).unwrap(), 0x40_0000);
        let mut mem = FlatMem::default();
        let mut host = RecordingHost::default();

        let path_addr = 0x1000;
        let name_addr = 0x2000;
        let val_addr = 0x3000;
        let out_addr = 0x4000;
        mem.write_cstr(path_addr, "/f");
        mem.write_cstr(name_addr, "user.tag");
        mem.write_bytes(val_addr, b"hello");

        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Fchmodat2,
                [(-100i32) as u32 as u64, path_addr, 0o4755, 0x100, 0, 0],
                &mut mem,
                &mut host
            ),
            0
        );
        assert_eq!(host.last_chmod, Some((String::from("/f"), false, 0o4755)));

        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Fchownat,
                [
                    (-100i32) as u32 as u64,
                    path_addr,
                    1000,
                    u32::MAX as u64,
                    0x100,
                    0
                ],
                &mut mem,
                &mut host
            ),
            0
        );
        assert_eq!(
            host.last_chown,
            Some((String::from("/f"), false, Some(1000), None))
        );

        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Mknodat,
                [(-100i32) as u32 as u64, path_addr, 0o020_640, 0x0103, 0, 0],
                &mut mem,
                &mut host
            ),
            0
        );
        assert_eq!(
            host.last_mknod,
            Some((
                String::from("/f"),
                NodeKind::CharacterDevice,
                0o640,
                0o022,
                0x0103
            ))
        );

        // Invalid xattr flags -> EINVAL; oversized value -> E2BIG; null name -> EFAULT.
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Setxattr,
                [path_addr, name_addr, val_addr, 5, 3, 0],
                &mut mem,
                &mut host
            ),
            err(EINVAL)
        );
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Setxattr,
                [path_addr, name_addr, val_addr, 65_537, 0, 0],
                &mut mem,
                &mut host
            ),
            err(E2BIG)
        );
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Setxattr,
                [path_addr, 0, val_addr, 5, 0, 0],
                &mut mem,
                &mut host
            ),
            err(EFAULT)
        );

        // Set, query size, ERANGE on too-small buffer, read, list, remove.
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Setxattr,
                [path_addr, name_addr, val_addr, 5, 0, 0],
                &mut mem,
                &mut host
            ),
            0
        );
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Getxattr,
                [path_addr, name_addr, 0, 0, 0, 0],
                &mut mem,
                &mut host
            ),
            5
        );
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Getxattr,
                [path_addr, name_addr, out_addr, 3, 0, 0],
                &mut mem,
                &mut host
            ),
            err(ERANGE)
        );
        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Getxattr,
                [path_addr, name_addr, out_addr, 16, 0, 0],
                &mut mem,
                &mut host
            ),
            5
        );
        assert_eq!(mem.read_bytes(out_addr, 5), b"hello");

        let list_len = run_call(
            &mut proc,
            abi,
            Operation::Listxattr,
            [path_addr, out_addr, 32, 0, 0, 0],
            &mut mem,
            &mut host,
        );
        assert_eq!(list_len, b"user.tag\0".len() as u64);
        assert_eq!(mem.read_bytes(out_addr, list_len as usize), b"user.tag\0");

        assert_eq!(
            run_call(
                &mut proc,
                abi,
                Operation::Removexattr,
                [path_addr, name_addr, 0, 0, 0, 0],
                &mut mem,
                &mut host
            ),
            0
        );
    }
}
