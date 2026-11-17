//! The system-information calls, run on both ABIs. Every expected value is
//! Linux v6.12's behaviour, named where the check is made.

use super::*;
use helios_unix::DescriptorLimit;

/// Polls to completion, since `getrandom` yields between pages.
fn drive<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(value) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return value;
        }
    }
}

const ABIS: [Abi; 2] = [Abi::X86_64, Abi::Aarch64];

fn number(abi: Abi, operation: Operation) -> u64 {
    (0..512)
        .find(|number| abi.operation(*number) == operation)
        .unwrap_or_else(|| panic!("{abi:?} has no number for {operation:?}"))
}

/// A process, its memory and its platform, called by operation.
struct World {
    abi: Abi,
    process: Process<NoBacking>,
    memory: Memory,
    sink: Sink,
}

impl World {
    fn new(abi: Abi) -> Self {
        Self::with_start(abi, Start::default())
    }

    fn with_start(abi: Abi, start: Start) -> Self {
        Self {
            abi,
            process: Process::with_descriptors(
                abi,
                core::num::NonZeroU32::new(77).unwrap(),
                PROGRAM_BREAK,
                helios_linux::syscall::standard_streams::<NoBacking>(),
                start,
            ),
            memory: Memory(vec![0xaa; 1 << 16]),
            sink: Sink::default(),
        }
    }

    fn call(&mut self, operation: Operation, arguments: [u64; 6]) -> i64 {
        let call = Call {
            number: number(self.abi, operation),
            arguments,
        };
        match drive(process_dispatch(
            &mut self.process,
            call,
            &mut self.memory,
            &mut self.sink,
        )) {
            ControlFlow::Continue(result) => result as i64,
            ControlFlow::Break(_) => panic!("{operation:?} ended the process"),
        }
    }

    fn u64_at(&self, address: usize) -> u64 {
        u64::from_le_bytes(self.memory.0[address..address + 8].try_into().unwrap())
    }

    fn u32_at(&self, address: usize) -> u32 {
        u32::from_le_bytes(self.memory.0[address..address + 4].try_into().unwrap())
    }

    fn put(&mut self, address: usize, values: &[u64]) {
        for (index, value) in values.iter().enumerate() {
            let at = address + index * 8;
            self.memory.0[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
    }

    fn set_uptime(&self, nanos: u64) {
        self.sink
            .time
            .store(nanos, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Beyond the 64 KiB of test memory.
const FAULT: u64 = 0xffff_ffff;
const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;

#[test]
fn system_information_calls_have_each_abis_own_numbers() {
    // arch/x86/entry/syscalls/syscall_64.tbl and
    // include/uapi/asm-generic/unistd.h, Linux v6.12. `time` is x86-64's
    // alone, and aarch64 numbers setpriority 140 and getpriority 141, the
    // reverse of x86-64.
    let table = [
        (Operation::ClockSettime, 227, Some(112)),
        (Operation::ClockGettime, 228, Some(113)),
        (Operation::ClockGetres, 229, Some(114)),
        (Operation::Gettimeofday, 96, Some(169)),
        (Operation::Time, 201, None),
        (Operation::Getrandom, 318, Some(278)),
        (Operation::Uname, 63, Some(160)),
        (Operation::Sysinfo, 99, Some(179)),
        (Operation::Getuid, 102, Some(174)),
        (Operation::Geteuid, 107, Some(175)),
        (Operation::Getgid, 104, Some(176)),
        (Operation::Getegid, 108, Some(177)),
        (Operation::Getgroups, 115, Some(158)),
        (Operation::Getresuid, 118, Some(148)),
        (Operation::Getresgid, 120, Some(150)),
        (Operation::Prlimit64, 302, Some(261)),
        (Operation::Getrlimit, 97, Some(163)),
        (Operation::Setrlimit, 160, Some(164)),
        (Operation::Umask, 95, Some(166)),
        (Operation::Getpriority, 140, Some(141)),
        (Operation::Setpriority, 141, Some(140)),
    ];
    for (operation, x86_64, aarch64) in table {
        assert_eq!(Abi::X86_64.operation(x86_64), operation);
        match aarch64 {
            Some(aarch64) => assert_eq!(Abi::Aarch64.operation(aarch64), operation),
            None => assert_eq!(Abi::Aarch64.operation(201), Operation::Unknown),
        }
    }
}

#[test]
fn clock_gettime_reads_each_clock_the_kernel_keeps() {
    for abi in ABIS {
        let mut world = World::new(abi);
        world.sink.wall_nanos = 1_700_000_000 * 1_000_000_000 + 123_456_789;
        world.set_uptime(5_000_000_042);
        world.sink.cpu_nanos = 2_000_000_007;
        // uapi/linux/time.h: REALTIME 0, MONOTONIC 1, PROCESS_CPUTIME_ID 2,
        // THREAD_CPUTIME_ID 3, MONOTONIC_RAW 4, REALTIME_COARSE 5,
        // MONOTONIC_COARSE 6, BOOTTIME 7, TAI 11.
        for (clock, seconds, nanoseconds) in [
            (0, 1_700_000_000, 123_456_789),
            (1, 5, 42),
            (2, 2, 7),
            (3, 2, 7),
            (4, 5, 42),
            (5, 1_700_000_000, 123_456_789),
            (6, 5, 42),
            (7, 5, 42),
            (11, 1_700_000_000, 123_456_789),
        ] {
            assert_eq!(
                world.call(Operation::ClockGettime, [clock, 64, 0, 0, 0, 0]),
                0
            );
            assert_eq!((world.u64_at(64), world.u64_at(72)), (seconds, nanoseconds));
        }
        // kernel/time/posix-timers.c `posix_clocks`: no clock numbered
        // so (8 and 9 are the alarm clocks, which answer EINVAL without a
        // wake-capable RTC), and a negative ID is a CPU-time clock of a
        // process or a dynamic clock, neither of which exists here.
        for clock in [8, 9, 10, 12, 15, 16, u64::MAX] {
            assert_eq!(
                world.call(Operation::ClockGettime, [clock, 64, 0, 0, 0, 0]),
                EINVAL,
                "clock {clock:#x}"
            );
        }
        // `clockid_t` is an `int`: the register's upper half is ignored.
        assert_eq!(
            world.call(Operation::ClockGettime, [(1 << 32) | 7, 64, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            world.call(Operation::ClockGettime, [0, FAULT, 0, 0, 0, 0]),
            EFAULT
        );
        assert_eq!(
            world.call(Operation::ClockGettime, [0, 1 << 16, 0, 0, 0, 0]),
            EFAULT
        );
    }
}

#[test]
fn clock_getres_answers_one_nanosecond_and_accepts_a_null_pointer() {
    for abi in ABIS {
        let mut world = World::new(abi);
        for clock in [0, 1, 2, 3, 4, 5, 6, 7, 11] {
            world.put(64, &[9, 9]);
            assert_eq!(
                world.call(Operation::ClockGetres, [clock, 64, 0, 0, 0, 0]),
                0
            );
            assert_eq!((world.u64_at(64), world.u64_at(72)), (0, 1));
            // clock_getres(2): a null `res` only asks whether the clock
            // exists.
            assert_eq!(
                world.call(Operation::ClockGetres, [clock, 0, 0, 0, 0, 0]),
                0
            );
        }
        assert_eq!(
            world.call(Operation::ClockGetres, [16, 64, 0, 0, 0, 0]),
            EINVAL
        );
        assert_eq!(
            world.call(Operation::ClockGetres, [16, 0, 0, 0, 0, 0]),
            EINVAL
        );
        assert_eq!(
            world.call(Operation::ClockGetres, [0, FAULT, 0, 0, 0, 0]),
            EFAULT
        );
    }
}

#[test]
fn clock_settime_needs_the_authority_to_set_the_wall_clock() {
    for abi in ABIS {
        let mut world = World::new(abi);
        world.sink.wall_nanos = 1_000;
        let set = |world: &mut World, clock: u64, seconds: i64, nanoseconds: u64| {
            world.put(64, &[seconds as u64, nanoseconds]);
            world.call(Operation::ClockSettime, [clock, 64, 0, 0, 0, 0])
        };
        // kernel/time/posix-timers.c: only CLOCK_REALTIME has `clock_set`;
        // the monotonic, CPU-time and unknown clocks answer EINVAL whether
        // or not the caller may set the time.
        world.sink.may_set_wall_clock = true;
        for clock in [1, 2, 3, 4, 5, 6, 7, 11, 16] {
            assert_eq!(set(&mut world, clock, 5, 0), EINVAL, "clock {clock}");
        }
        assert_eq!(world.sink.wall_nanos, 1_000);
        // kernel/time/time.c `do_sys_settimeofday64` validates the value
        // before it asks `cap_settime`, so a bad one is EINVAL even for a
        // caller without the right: before the epoch, a nanosecond count
        // of a whole second, and the first second `TIME_SETTOD_SEC_MAX`
        // refuses.
        world.sink.may_set_wall_clock = false;
        let limit = i64::MAX / 1_000_000_000 - 30 * 365 * 24 * 3600;
        for (seconds, nanoseconds) in [(-1, 0), (0, 1_000_000_000), (0, u64::MAX), (limit, 0)] {
            assert_eq!(set(&mut world, 0, seconds, nanoseconds), EINVAL);
        }
        // A valid time without the right is `CAP_SYS_TIME`'s EPERM.
        assert_eq!(set(&mut world, 0, 5, 6), EPERM);
        assert_eq!(world.sink.wall_nanos, 1_000);
        // The pointer is read before either check.
        assert_eq!(
            world.call(Operation::ClockSettime, [0, FAULT, 0, 0, 0, 0]),
            EFAULT
        );
        world.sink.may_set_wall_clock = true;
        assert_eq!(set(&mut world, 0, 5, 6), 0);
        assert_eq!(world.sink.wall_nanos, 5_000_000_006);
        assert_eq!(set(&mut world, 0, limit - 1, 999_999_999), 0);
        assert_eq!(
            world.call(Operation::ClockSettime, [0, FAULT, 0, 0, 0, 0]),
            EFAULT
        );
    }
}

#[test]
fn gettimeofday_and_time_report_the_wall_clock() {
    for abi in ABIS {
        let mut world = World::new(abi);
        world.sink.wall_nanos = 1_700_000_000 * 1_000_000_000 + 123_456_789;
        // `tv` is seconds and microseconds (truncated); `tz` is `sys_tz`,
        // zero until set.
        assert_eq!(world.call(Operation::Gettimeofday, [64, 96, 0, 0, 0, 0]), 0);
        assert_eq!(
            (world.u64_at(64), world.u64_at(72)),
            (1_700_000_000, 123_456)
        );
        assert_eq!((world.u32_at(96), world.u32_at(100)), (0, 0));
        // Either pointer may be null.
        world.memory.0[64..80].fill(0xaa);
        assert_eq!(world.call(Operation::Gettimeofday, [0, 96, 0, 0, 0, 0]), 0);
        assert_eq!(world.u64_at(64), 0xaaaa_aaaa_aaaa_aaaa);
        assert_eq!(world.call(Operation::Gettimeofday, [0, 0, 0, 0, 0, 0]), 0);
        assert_eq!(
            world.call(Operation::Gettimeofday, [FAULT, 0, 0, 0, 0, 0]),
            EFAULT
        );
        assert_eq!(
            world.call(Operation::Gettimeofday, [64, FAULT, 0, 0, 0, 0]),
            EFAULT
        );
    }
    // kernel/time/time.c `time`: x86-64 only; the seconds are the result and
    // are stored through a non-null pointer.
    let mut world = World::new(Abi::X86_64);
    world.sink.wall_nanos = 1_700_000_000 * 1_000_000_000 + 999_999_999;
    assert_eq!(
        world.call(Operation::Time, [64, 0, 0, 0, 0, 0]),
        1_700_000_000
    );
    assert_eq!(world.u64_at(64), 1_700_000_000);
    assert_eq!(
        world.call(Operation::Time, [0, 0, 0, 0, 0, 0]),
        1_700_000_000
    );
    assert_eq!(world.call(Operation::Time, [FAULT, 0, 0, 0, 0, 0]), EFAULT);
    // aarch64's asm-generic table has no `time`.
    let mut world = World::new(Abi::Aarch64);
    let result = drive(process_dispatch(
        &mut world.process,
        call(201, [64, 0, 0, 0, 0, 0]),
        &mut world.memory,
        &mut world.sink,
    ));
    assert_eq!(result, ControlFlow::Continue(38_u64.wrapping_neg()));
}

#[test]
fn getrandom_fills_the_buffer_and_validates_flags_like_the_kernel() {
    for abi in ABIS {
        let mut world = World::new(abi);
        // drivers/char/random.c: a request is served whole up to
        // MAX_RW_COUNT, a page at a time.
        assert_eq!(
            world.call(Operation::Getrandom, [100, 300, 0, 0, 0, 0]),
            300
        );
        let expected: Vec<u8> = (0..300).map(|n| n as u8).collect();
        assert_eq!(&world.memory.0[100..400], &expected[..]);
        assert_eq!(world.memory.0[400], 0xaa);
        // Longer than a yielding turn, across pages and an unaligned start.
        assert_eq!(
            world.call(Operation::Getrandom, [3, 60_000, 0, 0, 0, 0]),
            60_000
        );
        // GRND_NONBLOCK, GRND_RANDOM and GRND_INSECURE alone are valid; the
        // pool is always ready, so none changes the result.
        for flags in [0, 1, 2, 4, 3, 5] {
            assert_eq!(
                world.call(Operation::Getrandom, [100, 8, flags, 0, 0, 0]),
                8
            );
        }
        // An unknown bit, and GRND_RANDOM with GRND_INSECURE, are EINVAL.
        for flags in [8, 0x100, 6, 7, (1 << 32) | 8] {
            assert_eq!(
                world.call(Operation::Getrandom, [100, 8, flags, 0, 0, 0]),
                EINVAL
            );
        }
        // `flags` is an `unsigned int`: bits above 32 are dropped.
        assert_eq!(
            world.call(Operation::Getrandom, [100, 8, 1 << 32, 0, 0, 0]),
            8
        );
        assert_eq!(world.call(Operation::Getrandom, [100, 0, 0, 0, 0, 0]), 0);
        // A fault before any byte is EFAULT; one after a page stands as
        // the short count, as `get_random_bytes_user` returns it.
        assert_eq!(
            world.call(Operation::Getrandom, [FAULT, 8, 0, 0, 0, 0]),
            EFAULT
        );
        assert_eq!(
            world.call(Operation::Getrandom, [u64::MAX, 8, 0, 0, 0, 0]),
            EFAULT
        );
        assert_eq!(
            world.call(Operation::Getrandom, [(1 << 16) - 100, 5000, 0, 0, 0, 0]),
            100
        );
    }
}

#[test]
fn getrandom_draws_fresh_bytes_on_every_call() {
    let mut world = World::new(Abi::X86_64);
    assert_eq!(world.call(Operation::Getrandom, [0, 32, 0, 0, 0, 0]), 32);
    let first = world.memory.0[..32].to_vec();
    assert_eq!(world.call(Operation::Getrandom, [0, 32, 0, 0, 0, 0]), 32);
    assert_ne!(world.memory.0[..32], first[..]);
}

#[test]
fn uname_writes_the_six_utsname_fields() {
    for (abi, machine) in [(Abi::X86_64, "x86_64"), (Abi::Aarch64, "aarch64")] {
        let mut world = World::new(abi);
        assert_eq!(world.call(Operation::Uname, [64, 0, 0, 0, 0, 0]), 0);
        // uapi/linux/utsname.h `struct new_utsname`: six 65-byte fields.
        let field = |index: usize| {
            let start = 64 + index * 65;
            let bytes = &world.memory.0[start..start + 65];
            let end = bytes.iter().position(|byte| *byte == 0).unwrap();
            assert!(bytes[end..].iter().all(|byte| *byte == 0), "zero padded");
            String::from_utf8(bytes[..end].to_vec()).unwrap()
        };
        assert_eq!(field(0), "Linux");
        // CONFIG_DEFAULT_HOSTNAME and UTS_DOMAINNAME before either is set.
        assert_eq!(field(1), "(none)");
        assert_eq!(field(2), helios_linux::syscall::RELEASE);
        assert_eq!(field(3), "Helios test build");
        assert_eq!(field(4), machine);
        assert_eq!(field(5), "(none)");
        assert_eq!(world.memory.0[64 + 390], 0xaa, "exactly 390 bytes");
        assert_eq!(world.call(Operation::Uname, [FAULT, 0, 0, 0, 0, 0]), EFAULT);
        assert_eq!(
            world.call(Operation::Uname, [(1 << 16) - 389, 0, 0, 0, 0, 0]),
            EFAULT
        );
    }
}

#[test]
fn sysinfo_reports_uptime_memory_and_processes_in_the_lp64_layout() {
    for abi in ABIS {
        let mut world = World::new(abi);
        // Uptime rounds up to a whole second (`do_sysinfo`).
        world.set_uptime(90_000_000_001);
        world.sink.processes = 7;
        assert_eq!(world.call(Operation::Sysinfo, [64, 0, 0, 0, 0, 0]), 0);
        // uapi/linux/sysinfo.h `struct sysinfo`: 112 bytes on LP64.
        assert_eq!(world.u64_at(64), 91);
        for offset in [8, 16, 24] {
            assert_eq!(world.u64_at(64 + offset), 0, "loads");
        }
        assert_eq!(world.u64_at(64 + 32), 8 << 30);
        assert_eq!(world.u64_at(64 + 40), 3 << 30);
        for offset in [48, 56, 64, 72, 88, 96] {
            assert_eq!(world.u64_at(64 + offset), 0, "offset {offset}");
        }
        assert_eq!(
            u16::from_le_bytes(world.memory.0[64 + 80..64 + 82].try_into().unwrap()),
            7
        );
        assert_eq!(world.u32_at(64 + 104), 1, "mem_unit");
        assert_eq!(world.memory.0[64 + 112], 0xaa, "exactly 112 bytes");
        assert_eq!(
            world.call(Operation::Sysinfo, [FAULT, 0, 0, 0, 0, 0]),
            EFAULT
        );
        // Whole seconds are not rounded up.
        world.set_uptime(90_000_000_000);
        world.call(Operation::Sysinfo, [64, 0, 0, 0, 0, 0]);
        assert_eq!(world.u64_at(64), 90);
    }
}

fn credentials() -> Credentials {
    Credentials {
        user: Ids {
            real: 1000,
            effective: 1001,
            saved: 1002,
        },
        group: Ids {
            real: 2000,
            effective: 2001,
            saved: 2002,
        },
        supplementary_groups: vec![10, 20, 30],
    }
}

#[test]
fn identity_calls_report_the_launch_credentials() {
    for abi in ABIS {
        // Without credentials from the launcher every id is zero and there
        // are no supplementary groups.
        let mut world = World::new(abi);
        for operation in [
            Operation::Getuid,
            Operation::Geteuid,
            Operation::Getgid,
            Operation::Getegid,
        ] {
            assert_eq!(world.call(operation, [0; 6]), 0);
        }
        assert_eq!(world.call(Operation::Getgroups, [0, 0, 0, 0, 0, 0]), 0);

        let mut world = World::with_start(
            abi,
            Start {
                credentials: credentials(),
                ..Start::default()
            },
        );
        assert_eq!(world.call(Operation::Getuid, [0; 6]), 1000);
        assert_eq!(world.call(Operation::Geteuid, [0; 6]), 1001);
        assert_eq!(world.call(Operation::Getgid, [0; 6]), 2000);
        assert_eq!(world.call(Operation::Getegid, [0; 6]), 2001);
        // The arguments are ignored.
        assert_eq!(world.call(Operation::Getuid, [u64::MAX; 6]), 1000);

        assert_eq!(world.call(Operation::Getresuid, [64, 68, 72, 0, 0, 0]), 0);
        assert_eq!(
            [world.u32_at(64), world.u32_at(68), world.u32_at(72)],
            [1000, 1001, 1002]
        );
        assert_eq!(world.call(Operation::Getresgid, [80, 84, 88, 0, 0, 0]), 0);
        assert_eq!(
            [world.u32_at(80), world.u32_at(84), world.u32_at(88)],
            [2000, 2001, 2002]
        );
        // kernel/sys.c: three `put_user`s that stop at the first fault.
        world.memory.0[100..108].fill(0xaa);
        assert_eq!(
            world.call(Operation::Getresuid, [100, FAULT, 104, 0, 0, 0]),
            EFAULT
        );
        assert_eq!(world.u32_at(100), 1000);
        assert_eq!(world.u32_at(104), 0xaaaa_aaaa);

        // kernel/groups.c `getgroups`: a zero size counts; a list too short
        // is EINVAL; a negative size is EINVAL; a fault is EFAULT.
        assert_eq!(world.call(Operation::Getgroups, [0, FAULT, 0, 0, 0, 0]), 3);
        assert_eq!(world.call(Operation::Getgroups, [3, 128, 0, 0, 0, 0]), 3);
        assert_eq!(
            [world.u32_at(128), world.u32_at(132), world.u32_at(136)],
            [10, 20, 30]
        );
        assert_eq!(
            world.call(Operation::Getgroups, [2, 128, 0, 0, 0, 0]),
            EINVAL
        );
        assert_eq!(
            world.call(Operation::Getgroups, [u64::from(u32::MAX), 128, 0, 0, 0, 0]),
            EINVAL
        );
        assert_eq!(
            world.call(Operation::Getgroups, [3, FAULT, 0, 0, 0, 0]),
            EFAULT
        );
        assert_eq!(world.call(Operation::Getgroups, [100, 128, 0, 0, 0, 0]), 3);
    }
}

fn rlimit_of(world: &mut World, resource: u64) -> (u64, u64) {
    assert_eq!(
        world.call(Operation::Prlimit64, [0, resource, 0, 64, 0, 0]),
        0
    );
    (world.u64_at(64), world.u64_at(72))
}

#[test]
fn prlimit64_starts_from_linuxs_init_limits() {
    const INFINITY: u64 = u64::MAX;
    for abi in ABIS {
        // 8 GiB: max_threads = 8 GiB / (16 KiB * 8) = 65536, so
        // RLIMIT_NPROC and RLIMIT_SIGPENDING are 32768 (kernel/fork.c
        // `fork_init`).
        let mut world = World::with_start(
            abi,
            Start {
                memory_bytes: 8 << 30,
                ..Start::default()
            },
        );
        // asm-generic/resource.h INIT_RLIMITS, in resource-number order.
        let expected = [
            (INFINITY, INFINITY), // CPU
            (INFINITY, INFINITY), // FSIZE
            (INFINITY, INFINITY), // DATA
            (8 << 20, INFINITY),  // STACK
            (0, INFINITY),        // CORE
            (INFINITY, INFINITY), // RSS
            (32768, 32768),       // NPROC
            (1024, 4096),         // NOFILE: INR_OPEN_CUR, INR_OPEN_MAX
            (8 << 20, 8 << 20),   // MEMLOCK
            (INFINITY, INFINITY), // AS
            (INFINITY, INFINITY), // LOCKS
            (32768, 32768),       // SIGPENDING
            (819_200, 819_200),   // MSGQUEUE
            (0, 0),               // NICE
            (0, 0),               // RTPRIO
            (INFINITY, INFINITY), // RTTIME
        ];
        for (resource, limit) in expected.into_iter().enumerate() {
            assert_eq!(
                rlimit_of(&mut world, resource as u64),
                limit,
                "resource {resource}"
            );
        }
        // Memory for fewer than MIN_THREADS still allows MIN_THREADS.
        let mut small = World::new(abi);
        assert_eq!(rlimit_of(&mut small, 6), (10, 10));
        // `getrlimit` reads the same limits.
        assert_eq!(world.call(Operation::Getrlimit, [7, 64, 0, 0, 0, 0]), 0);
        assert_eq!((world.u64_at(64), world.u64_at(72)), (1024, 4096));
        // RLIM_NLIMITS and above are EINVAL.
        for resource in [16, 17, u64::from(u32::MAX)] {
            assert_eq!(
                world.call(Operation::Prlimit64, [0, resource, 0, 64, 0, 0]),
                EINVAL
            );
            assert_eq!(
                world.call(Operation::Getrlimit, [resource, 64, 0, 0, 0, 0]),
                EINVAL
            );
        }
        // The resource is an `unsigned int`.
        assert_eq!(
            world.call(Operation::Getrlimit, [(1 << 32) | 7, 64, 0, 0, 0, 0]),
            0
        );
        assert_eq!(world.u64_at(72), 4096);
    }
}

#[test]
fn rlimit_nofile_is_the_descriptor_tables_limit() {
    for abi in ABIS {
        let mut world = World::new(abi);
        // Lowering the soft limit to 5 leaves descriptors 0 to 4 and bounds
        // the numbers a new one may take: EMFILE for dup, EBADF for dup2.
        world.put(128, &[5, 4096]);
        assert_eq!(world.call(Operation::Setrlimit, [7, 128, 0, 0, 0, 0]), 0);
        assert_eq!(rlimit_of(&mut world, 7), (5, 4096));
        let renumber = |world: &mut World, to: u64| {
            let operation = match world.abi {
                Abi::X86_64 => Operation::Dup2,
                Abi::Aarch64 => Operation::Dup3,
            };
            world.call(operation, [0, to, 0, 0, 0, 0])
        };
        assert_eq!(world.call(Operation::Dup, [0; 6]), 3);
        assert_eq!(world.call(Operation::Dup, [0; 6]), 4);
        assert_eq!(world.call(Operation::Dup, [0; 6]), EMFILE);
        assert_eq!(renumber(&mut world, 5), EBADF);
        assert_eq!(renumber(&mut world, 4), 4);
        // Raising it again within the hard limit admits more.
        world.put(128, &[4096, 4096]);
        assert_eq!(world.call(Operation::Prlimit64, [0, 7, 128, 0, 0, 0]), 0);
        assert_eq!(world.call(Operation::Dup, [0; 6]), 5);
        assert_eq!(renumber(&mut world, 4095), 4095);
        assert_eq!(renumber(&mut world, 4096), EBADF);
        // Lowering the limit below descriptors in use keeps them open.
        world.put(128, &[2, 4096]);
        assert_eq!(world.call(Operation::Prlimit64, [0, 7, 128, 0, 0, 0]), 0);
        assert_eq!(world.call(Operation::Dup, [0; 6]), EMFILE);
        assert_eq!(world.call(Operation::Close, [4095, 0, 0, 0, 0, 0]), 0);
    }
}

#[test]
fn prlimit64_checks_in_kernel_order() {
    for abi in ABIS {
        let mut world = World::new(abi);
        // `soft > hard` is EINVAL.
        world.put(128, &[10, 5]);
        assert_eq!(
            world.call(Operation::Prlimit64, [0, 4, 128, 0, 0, 0]),
            EINVAL
        );
        // Raising a hard limit is `CAP_SYS_RESOURCE`'s: EPERM, with nothing
        // changed.
        world.put(128, &[1 << 20, 1 << 24]);
        assert_eq!(
            world.call(Operation::Prlimit64, [0, 8, 128, 0, 0, 0]),
            EPERM
        );
        assert_eq!(rlimit_of(&mut world, 8), (8 << 20, 8 << 20));
        // Lowering one is allowed, and the previous value comes back.
        world.put(128, &[1 << 20, 1 << 20]);
        assert_eq!(world.call(Operation::Prlimit64, [0, 8, 128, 64, 0, 0]), 0);
        assert_eq!((world.u64_at(64), world.u64_at(72)), (8 << 20, 8 << 20));
        assert_eq!(rlimit_of(&mut world, 8), (1 << 20, 1 << 20));
        // RLIMIT_NOFILE's hard limit is bounded by `fs.nr_open`.
        world.put(128, &[1, (1 << 20) + 1]);
        assert_eq!(
            world.call(Operation::Prlimit64, [0, 7, 128, 0, 0, 0]),
            EPERM
        );
        // An unreadable new limit is EFAULT before the process is named.
        assert_eq!(
            world.call(Operation::Prlimit64, [999, 7, FAULT, 0, 0, 0]),
            EFAULT
        );
        // No other process is visible, after the new limit was read.
        assert_eq!(
            world.call(Operation::Prlimit64, [999, 7, 0, 64, 0, 0]),
            ESRCH
        );
        assert_eq!(
            world.call(Operation::Prlimit64, [u64::from(u32::MAX), 7, 0, 64, 0, 0]),
            ESRCH
        );
        // The process's own pid names it.
        assert_eq!(world.call(Operation::Prlimit64, [77, 7, 0, 64, 0, 0]), 0);
        // The old limit's store failing is EFAULT after the new limit was
        // applied (kernel/sys.c `prlimit64`).
        world.put(128, &[7, 4096]);
        assert_eq!(
            world.call(Operation::Prlimit64, [0, 7, 128, FAULT, 0, 0]),
            EFAULT
        );
        assert_eq!(rlimit_of(&mut world, 7), (7, 4096));
        // `setrlimit` reads its argument first, then checks the resource.
        assert_eq!(
            world.call(Operation::Setrlimit, [99, FAULT, 0, 0, 0, 0]),
            EFAULT
        );
        world.put(128, &[1, 2]);
        assert_eq!(
            world.call(Operation::Setrlimit, [99, 128, 0, 0, 0, 0]),
            EINVAL
        );
        assert_eq!(
            world.call(Operation::Getrlimit, [7, FAULT, 0, 0, 0, 0]),
            EFAULT
        );
    }
}

#[test]
fn the_launchers_open_file_ceiling_bounds_the_hard_limit() {
    for abi in ABIS {
        // The hard limit is 4096 and the ceiling 2048: only the ceiling
        // refuses a hard limit that is not above the current one.
        let mut world = World::with_start(
            abi,
            Start {
                open_files_ceiling: 2048,
                ..Start::default()
            },
        );
        world.put(128, &[1, 4096]);
        assert_eq!(
            world.call(Operation::Prlimit64, [0, 7, 128, 0, 0, 0]),
            EPERM
        );
        world.put(128, &[1, 2048]);
        assert_eq!(world.call(Operation::Prlimit64, [0, 7, 128, 0, 0, 0]), 0);
    }
}

#[test]
fn a_launcher_that_raised_the_descriptor_limit_raises_the_hard_limit_with_it() {
    let mut table = helios_linux::syscall::standard_streams::<NoBacking>();
    table.limit = DescriptorLimit::new(1 << 16);
    let process = Process::<NoBacking>::with_descriptors(
        Abi::X86_64,
        core::num::NonZeroU32::new(9).unwrap(),
        PROGRAM_BREAK,
        table,
        Start::default(),
    );
    let limit = process.limit(helios_linux::syscall::Resource::Nofile);
    assert_eq!((limit.current, limit.maximum), (1 << 16, 1 << 16));
}

#[test]
fn umask_swaps_the_mask_and_keeps_only_permission_bits() {
    for abi in ABIS {
        let mut world = World::new(abi);
        // fs/fs_struct.c `init_fs`: 022.
        assert_eq!(world.call(Operation::Umask, [0o077, 0, 0, 0, 0, 0]), 0o022);
        assert_eq!(
            world.call(Operation::Umask, [0o7777_0027, 0, 0, 0, 0, 0]),
            0o077
        );
        assert_eq!(world.call(Operation::Umask, [0, 0, 0, 0, 0, 0]), 0o027);
        assert_eq!(world.call(Operation::Umask, [0o022, 0, 0, 0, 0, 0]), 0);
    }
}

#[test]
fn priorities_follow_nice_and_refuse_a_raise_without_rlimit_nice() {
    for abi in ABIS {
        let mut world = World::new(abi);
        // `getpriority` returns 20 - nice, so 20 for the default nice 0.
        assert_eq!(world.call(Operation::Getpriority, [0, 0, 0, 0, 0, 0]), 20);
        assert_eq!(world.call(Operation::Getpriority, [0, 77, 0, 0, 0, 0]), 20);
        assert_eq!(world.call(Operation::Getpriority, [1, 0, 0, 0, 0, 0]), 20);
        assert_eq!(world.call(Operation::Getpriority, [2, 0, 0, 0, 0, 0]), 20);
        // Raising the nice value is always allowed, and clamps to 19.
        assert_eq!(world.call(Operation::Setpriority, [0, 0, 5, 0, 0, 0]), 0);
        assert_eq!(world.call(Operation::Getpriority, [0, 0, 0, 0, 0, 0]), 15);
        assert_eq!(world.call(Operation::Setpriority, [0, 0, 100, 0, 0, 0]), 0);
        assert_eq!(world.call(Operation::Getpriority, [0, 0, 0, 0, 0, 0]), 1);
        // Lowering needs `RLIMIT_NICE` or `CAP_SYS_NICE`; RLIMIT_NICE is 0
        // and no right of the process's authority stands for the
        // capability: EACCES, nothing changed.
        assert_eq!(
            world.call(Operation::Setpriority, [0, 0, 18, 0, 0, 0]),
            EACCES
        );
        assert_eq!(
            world.call(
                Operation::Setpriority,
                [0, 0, u64::from(-5_i32 as u32), 0, 0, 0]
            ),
            EACCES
        );
        assert_eq!(world.call(Operation::Getpriority, [0, 0, 0, 0, 0, 0]), 1);
        // Raising RLIMIT_NICE needs `CAP_SYS_RESOURCE`: EPERM.
        world.put(128, &[40, 40]);
        assert_eq!(
            world.call(Operation::Prlimit64, [0, 13, 128, 0, 0, 0]),
            EPERM
        );
        // An unknown `which` is EINVAL, and a process that is not this one
        // ESRCH.
        for which in [3, u64::MAX, (1 << 32) | 5] {
            assert_eq!(
                world.call(Operation::Getpriority, [which, 0, 0, 0, 0, 0]),
                EINVAL
            );
            assert_eq!(
                world.call(Operation::Setpriority, [which, 0, 0, 0, 0, 0]),
                EINVAL
            );
        }
        assert_eq!(
            world.call(Operation::Getpriority, [0, 78, 0, 0, 0, 0]),
            ESRCH
        );
        assert_eq!(
            world.call(Operation::Setpriority, [0, 78, 0, 0, 0, 0]),
            ESRCH
        );
        assert_eq!(
            world.call(Operation::Getpriority, [1, 5, 0, 0, 0, 0]),
            ESRCH
        );
        assert_eq!(
            world.call(Operation::Getpriority, [2, 5, 0, 0, 0, 0]),
            ESRCH
        );
        // PRIO_USER names the real user.
        let mut world = World::with_start(
            abi,
            Start {
                credentials: credentials(),
                ..Start::default()
            },
        );
        assert_eq!(
            world.call(Operation::Getpriority, [2, 1000, 0, 0, 0, 0]),
            20
        );
        assert_eq!(
            world.call(Operation::Getpriority, [2, 1001, 0, 0, 0, 0]),
            ESRCH
        );
    }
}
