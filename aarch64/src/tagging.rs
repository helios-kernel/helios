//! Memory tagging on AArch64 (Armv8.5-A FEAT_MTE2): feature probing,
//! per-processor enablement, [`Aarch64AllocationTags`], synchronous tag check
//! fault decoding and fatal reporting, and the per-processor self-check.
//!
//! # Concurrency contract
//!
//! * [`init_bootstrap`] probes `ID_AA64PFR1_EL1.MTE`, builds the tagged direct
//!   map view and enables checking on the bootstrap processor before any
//!   secondary starts or `Cpu` reaches the kernel. `CHECKING` and
//!   `TAGGED_VIEW` are written once there and only read afterwards.
//! * [`enable_on_secondary`] verifies that every secondary processor matches
//!   the bootstrap processor's `FEAT_MTE2` capability and enables its own
//!   registers (`GCR_EL1`, `RGSR_EL1`, `TCR_EL1.{TBI1,TCMA1}`,
//!   `SCTLR_EL1.{TCF,ATA}`) before it publishes `started` or runs any
//!   signed return address.
//! * [`Aarch64AllocationTags`] operations are lock-free, allocate nothing and
//!   may run in fault or interrupt context. Tag stores finish with `DSB ISH`
//!   before returning.
//! * [`TagCheckProbe`] lives in each processor's own `ProcessorRuntime` and is
//!   only touched by that processor during its bring-up self-check.

use core::alloc::Layout;
use core::arch::asm;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use helios_hal::tagging::{AllocationTags, MemoryTagging, Tag, TagChecking, TagSet, TaggedView};
use helios_virtio::{DmaBuffer, DmaPool, OffsetDmaPool};
use spin::Once;

use crate::cfi::{ESR_EC_MASK, ESR_EC_SHIFT};

/// `ESR_ELx.EC` of a data abort taken from a lower and from the same
/// exception level.
const ESR_EC_DATA_ABORT_LOWER: usize = 0x24;
const ESR_EC_DATA_ABORT_SAME: usize = 0x25;
/// `ESR_ELx.ISS[5:0]`, the data fault status code (DFSC).
const ESR_DFSC_MASK: usize = 0x3f;
/// The DFSC of a synchronous tag check fault.
const DFSC_TAG_CHECK_FAULT: usize = 0b010001;
/// `ESR_ELx.ISS.WnR`: the abort was caused by a write.
const ESR_WNR: usize = 1 << 6;

/// The lowest bit of the logical tag in a pointer (and in FAR), and the tag's
/// width. The architecture places the logical tag in bits `[59:56]`.
const LOGICAL_TAG_SHIFT: usize = 56;
const LOGICAL_TAG_MASK: usize = 0xf;
/// Bit that selects the translation table, and so the value every bit of a
/// canonical address's top byte copies.
const ADDRESS_SPACE_SELECT_BIT: u32 = 55;
/// Bits of the pointer's top byte, which a processor with top-byte-ignore
/// does not use to translate.
const TOP_BYTE_BITS: usize = 8;

/// `TCR_EL1.TBI0` and `TCR_EL1.TBI1`: the top byte of an address translated
/// through `TTBR0_EL1` or `TTBR1_EL1` is ignored.
const TCR_TBI0: u64 = 1 << 37;
const TCR_TBI1: u64 = 1 << 38;
/// `TCR_EL1.TCMA1`: accesses through `TTBR1_EL1` whose bits `[59:55]` are all
/// ones (logical tag `0xf`, [`Tag::UNCHECKED`]) generate unchecked accesses
/// (Arm ARM D19.2 `TCR_EL1`).
const TCR_TCMA1: u64 = 1 << 58;

/// `ID_AA64PFR1_EL1.MTE` sits in bits `[11:8]`; `0b0010` (`2`) is FEAT_MTE2,
/// the earliest level that provides allocation-tag storage and synchronous
/// tag checking (Arm ARM D19.2 `ID_AA64PFR1_EL1`).
const ID_AA64PFR1_MTE_SHIFT: u64 = 8;
const ID_AA64PFR1_MTE_MASK: u64 = 0xf;
const ID_AA64PFR1_MTE2: u64 = 2;

/// `SCTLR_EL1.TCF` occupies bits `[41:40]`; `0b01` selects synchronous tag
/// check faults at EL1 (Arm ARM D19.2 `SCTLR_EL1`).
const SCTLR_TCF_MASK: u64 = 0b11 << 40;
const SCTLR_TCF_SYNC: u64 = 0b01 << 40;
/// `SCTLR_EL1.ATA` (bit 43): enables allocation-tag access and checking at EL1.
const SCTLR_ATA: u64 = 1 << 43;

/// `GCR_EL1.RRND` (bit 16): `IRG` draws pseudo-random tags from `RGSR_EL1`
/// rather than incrementing sequentially (Arm ARM D19.2 `GCR_EL1`).
const GCR_RRND: u64 = 1 << 16;
/// `GCR_EL1.Exclude[15:0]`: always exclude [`Tag::FREE`] (0) and
/// [`Tag::UNCHECKED`] (15) from `IRG` output.
const GCR_EXCLUDE_BASE: u64 = (1 << Tag::FREE.raw()) | (1 << Tag::UNCHECKED.raw());

/// `RGSR_EL1.SEED` occupies bits `[23:8]` (Arm ARM D19.2 `RGSR_EL1`).
const RGSR_SEED_SHIFT: u64 = 8;

/// The MAIR index programmed with [`MAIR_NORMAL_TAGGED`] when FEAT_MTE2 is
/// implemented.
pub(crate) const PAGE_ATTR_NORMAL_TAGGED_INDEX: u64 = 5;
/// `0b1111_0000`: Tagged Normal memory, inner and outer write-back
/// non-transient, read-allocate, write-allocate (Arm ARM D19.2 `MAIR_EL1`).
pub(crate) const MAIR_NORMAL_TAGGED: u64 = 0xf0;

/// Bytes one allocation tag covers (architecturally fixed to 16).
const GRANULE_BYTES: usize = 16;

/// Set once on the bootstrap processor when every processor will check tags.
static CHECKING: AtomicBool = AtomicBool::new(false);
/// The direct-map/tagged-view descriptor built on the bootstrap processor.
static TAGGED_VIEW: Once<TaggedView> = Once::new();

/// Whether the executing processor implements FEAT_MTE2 or later.
pub(crate) fn supported_on_current_processor() -> bool {
    let pfr1: u64;
    // SAFETY: reading `ID_AA64PFR1_EL1` at EL1 has no side effects.
    unsafe {
        asm!(
            "mrs {pfr1}, id_aa64pfr1_el1",
            pfr1 = out(reg) pfr1,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((pfr1 >> ID_AA64PFR1_MTE_SHIFT) & ID_AA64PFR1_MTE_MASK) >= ID_AA64PFR1_MTE2
}

/// Ensures `RGSR_EL1.SEED` is non-zero: the architecture treats a zero seed as
/// selecting an unknown value.
const fn normalize_seed(seed: u16) -> u16 {
    if seed == 0 { 1 } else { seed }
}

/// Writes `RGSR_EL1.SEED` on the executing processor when memory tagging is
/// enabled. Safe to call after `RootEntropy` is seeded to replace the early
/// boot seed; only future `IRG` outputs change.
pub(crate) fn seed_random_tag_generator(seed: u16) {
    if !Aarch64AllocationTags::checking() {
        return;
    }
    let rgsr = u64::from(normalize_seed(seed)) << RGSR_SEED_SHIFT;
    // SAFETY: `CHECKING` is only true on a processor implementing FEAT_MTE2
    // with `SCTLR_EL1.ATA` set.
    unsafe {
        asm!(
            ".arch_extension memtag",
            "msr rgsr_el1, {rgsr}",
            "isb",
            rgsr = in(reg) rgsr,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Enables synchronous EL1 tag checking and `TCMA1` match-all untagged
/// pointers on the executing processor.
///
/// # Safety
///
/// The executing processor implements FEAT_MTE2, `MAIR_EL1` index
/// [`PAGE_ATTR_NORMAL_TAGGED_INDEX`] holds [`MAIR_NORMAL_TAGGED`], and
/// `SCTLR_EL1.EnIA` is still clear (setting `TBI1` narrows the PAC bit field,
/// so no signed return address may be live across this write).
unsafe fn enable_registers(seed: u16) {
    let gcr = GCR_RRND | GCR_EXCLUDE_BASE;
    let rgsr = u64::from(normalize_seed(seed)) << RGSR_SEED_SHIFT;
    // SAFETY: caller guarantees FEAT_MTE2 is implemented and `EnIA` is clear.
    unsafe {
        asm!(
            ".arch_extension memtag",
            "msr gcr_el1, {gcr}",
            "msr rgsr_el1, {rgsr}",
            "mrs {tcr}, tcr_el1",
            "orr {tcr}, {tcr}, {tcr_bits}",
            "msr tcr_el1, {tcr}",
            "mrs {sctlr}, sctlr_el1",
            "bic {sctlr}, {sctlr}, {tcf_mask}",
            "orr {sctlr}, {sctlr}, {sctlr_bits}",
            "msr sctlr_el1, {sctlr}",
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            gcr = in(reg) gcr,
            rgsr = in(reg) rgsr,
            tcr = out(reg) _,
            tcr_bits = in(reg) TCR_TBI1 | TCR_TCMA1,
            sctlr = out(reg) _,
            tcf_mask = in(reg) SCTLR_TCF_MASK,
            sctlr_bits = in(reg) SCTLR_TCF_SYNC | SCTLR_ATA,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads `(GCR_EL1, RGSR_EL1)` for PSCI CPU suspend/resume when checking is
/// enabled, or `(0, 0)` otherwise.
pub(crate) fn save_registers() -> (bool, u64, u64) {
    if !Aarch64AllocationTags::checking() {
        return (false, 0, 0);
    }
    let gcr: u64;
    let rgsr: u64;
    // SAFETY: `CHECKING` is true only on FEAT_MTE2 processors with `ATA` set.
    unsafe {
        asm!(
            ".arch_extension memtag",
            "mrs {gcr}, gcr_el1",
            "mrs {rgsr}, rgsr_el1",
            gcr = out(reg) gcr,
            rgsr = out(reg) rgsr,
            options(nomem, nostack, preserves_flags),
        );
    }
    (true, gcr, rgsr)
}

/// Probes `FEAT_MTE2` on the bootstrap processor, builds the tagged direct-map
/// view and enables synchronous checking when supported.
///
/// # Safety
///
/// Called once on the bootstrap processor after `install_memory_attributes`
/// and `vmm::install_user_address_space`, before any secondary starts, before
/// `cfi::enable_instruction_key_a`, and before any `OffsetDmaPool` or fiber
/// stack arena is built.
pub(crate) unsafe fn init_bootstrap(
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
) -> MemoryTagging {
    if !supported_on_current_processor() {
        TAGGED_VIEW.call_once(|| TaggedView::direct_map(physical_memory_offset));
        return MemoryTagging::NONE;
    }
    let view = crate::vmm::build_tagged_view(physical_memory_offset, handoff);
    TAGGED_VIEW.call_once(|| view);
    // An initial non-zero seed so early boot allocations (virtio-rng rings)
    // draw randomized tags; replaced from `RootEntropy` as soon as the DRBG is
    // seeded.
    let initial_seed = crate::read_counter() as u16;
    // SAFETY: `supported_on_current_processor()` is true, `MAIR_EL1` was
    // programmed by `install_memory_attributes`, and `EnIA` is still clear.
    unsafe { enable_registers(initial_seed) };
    CHECKING.store(true, Ordering::Release);
    MemoryTagging {
        checking: Some(TagChecking {
            granule_bytes: GRANULE_BYTES,
        }),
    }
}

/// Verifies that a secondary processor matches the bootstrap processor's MTE
/// capability and enables its registers when checking is active.
///
/// # Safety
///
/// Called once on each secondary processor after `prepare_current_processor`
/// and before `cfi::enable_instruction_key_a`.
pub(crate) unsafe fn enable_on_secondary(expected: MemoryTagging, seed: u16, mpidr: u64) {
    let supported = supported_on_current_processor();
    let required = expected.checking.is_some();
    assert_eq!(
        supported, required,
        "AArch64 processor MPIDR {mpidr:#x} FEAT_MTE2 support ({supported}) disagrees with the \
         bootstrap processor ({required}); Helios requires uniform memory tagging across every \
         processor"
    );
    if required {
        // SAFETY: verified FEAT_MTE2 above, `MAIR_EL1` is programmed, and
        // `EnIA` is still clear.
        unsafe { enable_registers(seed) };
    }
}

/// The platform's virtio DMA pool, allocating rings through [`TaggedView`]
/// when memory tagging is enabled or directly through HHDM otherwise.
pub(crate) fn dma_pool() -> OffsetDmaPool<Aarch64AllocationTags> {
    let view = *TAGGED_VIEW
        .get()
        .expect("AArch64 DMA pool requested before memory tagging was initialized");
    // SAFETY: when `Aarch64AllocationTags::checking()` is true, `view` was
    // mapped with `MAIR_NORMAL_TAGGED` across every usable RAM region with
    // `line_bytes` equal to the cache writeback granule (a power of two).
    unsafe { OffsetDmaPool::tagged(view) }
}

/// AArch64 FEAT_MTE2 implementation of [`AllocationTags`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Aarch64AllocationTags;

impl AllocationTags for Aarch64AllocationTags {
    const GRANULE_BYTES: usize = GRANULE_BYTES;

    fn checking() -> bool {
        CHECKING.load(Ordering::Acquire)
    }

    unsafe fn assign(range: NonNull<[u8]>, avoid: TagSet) -> Tag {
        if !Self::checking() {
            return Tag::UNCHECKED;
        }
        let base = range.as_ptr() as *mut u8 as usize;
        let avoid_mask = u64::from(avoid.raw());
        debug_assert!(
            avoid_mask | GCR_EXCLUDE_BASE != 0xffff,
            "cannot exclude every allocation tag"
        );
        let tagged: usize;
        // SAFETY: `CHECKING` is true only on FEAT_MTE2 processors with `ATA`
        // set; `IRG` touches only the executing processor's `GCR_EL1`/`RGSR_EL1`.
        unsafe {
            asm!(
                ".arch_extension memtag",
                "irg {tagged}, {base}, {avoid}",
                tagged = out(reg) tagged,
                base = in(reg) base,
                avoid = in(reg) avoid_mask,
                options(nomem, nostack, preserves_flags),
            );
        }
        let tag = logical_tag(tagged);
        debug_assert!(tag != Tag::FREE && tag != Tag::UNCHECKED && !avoid.contains(tag));
        // SAFETY: caller's contract for `assign` matches `store`.
        unsafe { Self::store(range, tag) };
        tag
    }

    unsafe fn store(range: NonNull<[u8]>, tag: Tag) {
        if !Self::checking() {
            return;
        }
        let base = range.as_ptr() as *mut u8 as usize;
        let len = range.len();
        debug_assert!(base.is_multiple_of(GRANULE_BYTES));
        debug_assert!(len.is_multiple_of(GRANULE_BYTES));
        let mut ptr = Self::apply(base, tag);
        let end = ptr + len;
        // SAFETY: caller guarantees `range` is granule-aligned, canonical,
        // tag-capable and exclusively owned; `CHECKING` guarantees FEAT_MTE2
        // with `ATA` set. `DSB ISH` publishes the tag stores to the
        // inner-shareable domain before returning.
        unsafe {
            while end - ptr >= 2 * GRANULE_BYTES {
                asm!(
                    ".arch_extension memtag",
                    "st2g {ptr}, [{ptr}], #32",
                    ptr = inout(reg) ptr,
                    options(nostack, preserves_flags),
                );
            }
            if ptr < end {
                asm!(
                    ".arch_extension memtag",
                    "stg {ptr}, [{ptr}]",
                    ptr = in(reg) ptr,
                    options(nostack, preserves_flags),
                );
            }
            asm!("dsb ish", options(nostack, preserves_flags));
        }
    }

    fn apply(addr: usize, tag: Tag) -> usize {
        if !Self::checking() {
            return addr;
        }
        (addr & !(LOGICAL_TAG_MASK << LOGICAL_TAG_SHIFT))
            | (usize::from(tag.raw()) << LOGICAL_TAG_SHIFT)
    }

    fn strip(addr: usize) -> usize {
        if !Self::checking() {
            return addr;
        }
        strip(addr)
    }
}

/// Whether `esr` describes a synchronous tag check fault: a data abort whose
/// fault status is the tag check fault code.
pub(crate) fn is_tag_check_fault(esr: usize) -> bool {
    matches!(
        (esr >> ESR_EC_SHIFT) & ESR_EC_MASK,
        ESR_EC_DATA_ABORT_LOWER | ESR_EC_DATA_ABORT_SAME
    ) && esr & ESR_DFSC_MASK == DFSC_TAG_CHECK_FAULT
}

/// `addr` with its logical tag removed: the top byte, which an address with
/// top-byte-ignore enabled does not translate by, takes the value of bit 55
/// again. This is what `hal::tagging::AllocationTags::strip` is on AArch64.
pub(crate) fn strip(addr: usize) -> usize {
    (((addr << TOP_BYTE_BITS) as isize) >> TOP_BYTE_BITS) as usize
}

/// The address the processor translated when it reported `far` for a data
/// abort: `far` without its top byte where `tcr` (`TCR_EL1`) ignores the top
/// byte of that half of the address space, and `far` itself where it does
/// not, because there a top byte that differs from bit 55 is why the access
/// faulted and no mapping answers for it.
pub(crate) fn translated_address(far: usize, tcr: u64) -> usize {
    let top_byte_ignored = if far & (1 << ADDRESS_SPACE_SELECT_BIT) == 0 {
        TCR_TBI0
    } else {
        TCR_TBI1
    };
    if tcr & top_byte_ignored == 0 {
        far
    } else {
        strip(far)
    }
}

/// The logical tag a faulting pointer carried: FAR bits `[59:56]`, which are
/// valid for a tag check fault whether or not FEAT_MTE_TAGGED_FAR is
/// implemented.
pub(crate) fn logical_tag(far: usize) -> Tag {
    Tag::new(((far >> LOGICAL_TAG_SHIFT) & LOGICAL_TAG_MASK) as u8)
}

/// The start of the granule that holds `canonical`.
pub(crate) fn granule_start(canonical: usize) -> usize {
    canonical & !(GRANULE_BYTES - 1)
}

/// Whether the abort was caused by a write.
fn is_write(esr: usize) -> bool {
    esr & ESR_WNR != 0
}

/// The allocation tag stored with the granule at `granule`, from `LDG`.
///
/// # Safety
///
/// The executing processor implements FEAT_MTE2, so `LDG` is defined, and
/// `granule` is the 16-byte aligned canonical address of memory mapped with a
/// tag-capable attribute, which makes the instruction read tag storage and
/// never fault.
unsafe fn load_allocation_tag(granule: usize) -> Tag {
    let mut tagged = granule;
    // SAFETY: `LDG` replaces `tagged[59:56]` with the allocation tag of the
    // granule and reads no data; the caller guarantees it is defined.
    unsafe {
        asm!(
            ".arch_extension memtag",
            "ldg {tagged}, [{tagged}]",
            tagged = inout(reg) tagged,
            options(nostack, preserves_flags),
        );
    }
    logical_tag(tagged)
}

/// Per-processor record used by [`verify_on_current_processor`] to catch one
/// deliberate tag mismatch in the synchronous handler without panicking.
pub(crate) struct TagCheckProbe {
    expected_canonical: AtomicUsize,
    expected_logical: AtomicU8,
    observed_allocation: AtomicU8,
    faulted: AtomicBool,
}

impl TagCheckProbe {
    pub(crate) const fn new() -> Self {
        Self {
            expected_canonical: AtomicUsize::new(0),
            expected_logical: AtomicU8::new(0),
            observed_allocation: AtomicU8::new(0),
            faulted: AtomicBool::new(false),
        }
    }

    fn arm(&self, canonical: usize, logical: Tag) {
        self.faulted.store(false, Ordering::Relaxed);
        self.observed_allocation.store(0, Ordering::Relaxed);
        self.expected_logical
            .store(logical.raw(), Ordering::Relaxed);
        self.expected_canonical.store(canonical, Ordering::Release);
    }

    fn disarm(&self) -> (bool, u8) {
        self.expected_canonical.store(0, Ordering::Release);
        (
            self.faulted.load(Ordering::Acquire),
            self.observed_allocation.load(Ordering::Acquire),
        )
    }

    /// Claims a synchronous tag check fault that matches the active probe.
    ///
    /// # Safety
    ///
    /// Called only from the synchronous handler when `is_tag_check_fault(esr)`
    /// is true, so `FEAT_MTE2` is implemented and `far` names a tag-capable
    /// granule.
    pub(crate) unsafe fn claim(&self, esr: usize, far: usize) -> bool {
        let expected = self.expected_canonical.load(Ordering::Acquire);
        if expected == 0 || !is_tag_check_fault(esr) {
            return false;
        }
        let canonical = strip(far);
        let logical = logical_tag(far);
        if canonical != expected || logical.raw() != self.expected_logical.load(Ordering::Acquire) {
            return false;
        }
        // SAFETY: `far` faulted with a tag check fault, so its granule is
        // mapped tag-capable and `FEAT_MTE2` is active.
        let allocation = unsafe { load_allocation_tag(granule_start(canonical)) };
        self.observed_allocation
            .store(allocation.raw(), Ordering::Relaxed);
        self.faulted.store(true, Ordering::Release);
        self.expected_canonical.store(0, Ordering::Release);
        true
    }
}

/// Reads one byte from `ptr`; naked so no signed return address is pushed and
/// the synchronous probe handler can resume directly at `x30`.
#[unsafe(naked)]
unsafe extern "C" fn probe_load(_ptr: *const u8) -> u8 {
    core::arch::naked_asm!("ldrb w0, [x0]", "ret")
}

/// Verifies on the executing processor that synchronous tag checking,
/// `TCMA1` match-all untagged accesses, and redzone tagging all behave as
/// configured. Runs on every processor during bring-up when MTE is enabled.
pub(crate) fn verify_on_current_processor(mpidr: u64) {
    if !Aarch64AllocationTags::checking() {
        return;
    }
    let pool = dma_pool();
    let layout = Layout::from_size_align(64, 64).expect("probe buffer layout");
    let buffer = pool.allocate_zeroed(layout).unwrap_or_else(|error| {
        panic!("AArch64 MTE self-check on MPIDR {mpidr:#x} could not allocate buffer: {error}")
    });
    let tagged_ptr = buffer.as_ptr();
    let live_tag = logical_tag(tagged_ptr as usize);
    let canonical = strip(tagged_ptr as usize);
    assert!(
        live_tag != Tag::FREE && live_tag != Tag::UNCHECKED,
        "AArch64 MTE self-check on MPIDR {mpidr:#x} received reserved tag {:#x}",
        live_tag.raw()
    );
    // SAFETY: `buffer` lives in `TaggedView` and is granule-aligned.
    let stored_tag = unsafe { load_allocation_tag(canonical) };
    assert_eq!(
        stored_tag, live_tag,
        "AArch64 MTE self-check on MPIDR {mpidr:#x} read back tag {stored_tag:?}, expected {live_tag:?}"
    );
    // SAFETY: `tagged_ptr` carries the matching live tag; `canonical` carries
    // `Tag::UNCHECKED` (`0xf`) which `TCMA1` accepts.
    let tagged_byte = unsafe { tagged_ptr.read_volatile() };
    let unchecked_byte = unsafe { (canonical as *const u8).read_volatile() };
    assert_eq!(tagged_byte, 0);
    assert_eq!(unchecked_byte, 0);

    let probe = &crate::current_processor_runtime().tag_check_probe;
    // 1. Mismatched live tag on the object itself must fault synchronously.
    let wrong_tag = Tag::new(if live_tag.raw() == 1 { 2 } else { 1 });
    let wrong_ptr = Aarch64AllocationTags::apply(canonical, wrong_tag) as *const u8;
    probe.arm(canonical, wrong_tag);
    // SAFETY: `probe` catches the expected synchronous tag check fault and
    // resumes at `probe_load`'s return address.
    let _ = unsafe { probe_load(wrong_ptr) };
    let (faulted, observed_allocation) = probe.disarm();
    assert!(
        faulted && observed_allocation == live_tag.raw(),
        "AArch64 MTE self-check on MPIDR {mpidr:#x}: mismatched tag read was not refused \
         (faulted={faulted}, observed_allocation={observed_allocation:#x}, expected={:#x})",
        live_tag.raw()
    );

    // 2. Reading into the leading `Tag::FREE` redzone through the live tag
    // must fault synchronously and report `Tag::FREE`.
    let redzone_canonical = canonical - GRANULE_BYTES;
    let redzone_ptr = Aarch64AllocationTags::apply(redzone_canonical, live_tag) as *const u8;
    probe.arm(redzone_canonical, live_tag);
    // SAFETY: as above; `OffsetDmaPool` guarantees at least one `GRANULE_BYTES`
    // redzone before the object.
    let _ = unsafe { probe_load(redzone_ptr) };
    let (redzone_faulted, redzone_allocation) = probe.disarm();
    assert!(
        redzone_faulted && redzone_allocation == Tag::FREE.raw(),
        "AArch64 MTE self-check on MPIDR {mpidr:#x}: redzone read was not refused \
         (faulted={redzone_faulted}, observed_allocation={redzone_allocation:#x})"
    );
}

/// Proves at run time that a deliberate tag mismatch panics through
/// [`report_tag_check_fault`], for the image built with
/// `HELIOS_MTE_SELF_TEST`.
#[cfg(helios_mte_self_test)]
pub(crate) fn self_test() {
    assert!(
        Aarch64AllocationTags::checking(),
        "memory tagging self-test requires a machine with FEAT_MTE2 enabled"
    );
    let pool = dma_pool();
    let layout = Layout::from_size_align(64, 64).expect("self-test buffer layout");
    let buffer = pool
        .allocate_zeroed(layout)
        .expect("memory tagging self-test buffer allocation");
    // Step into the leading `Tag::FREE` redzone using the object's live tag:
    // the synchronous tag check fault must fire and panic naming the granule
    // and its `0x0` allocation tag.
    // SAFETY: `OffsetDmaPool` allocates a mapped `Tag::FREE` redzone ahead of
    // the object; the access is meant to trap synchronously on the tag mismatch.
    let _ = unsafe { buffer.as_ptr().sub(GRANULE_BYTES).read_volatile() };
    panic!("memory tagging self-test: a redzone read with a mismatched tag was accepted")
}

/// Panics with the report of a synchronous tag check fault: the access that
/// failed, the tag its pointer carried, and the tag the granule holds.
///
/// A guest's linear memory is reached through untagged pointers, so no guest
/// access raises a tag check fault; one is a defect in the kernel or the
/// runtime, and nothing is handed to the runtime.
///
/// # Safety
///
/// The executing processor implements FEAT_MTE2, as a processor that took a
/// tag check fault does, and the faulting address is mapped with a tag-capable
/// attribute, as a tag mismatch implies.
pub(crate) unsafe fn report_tag_check_fault(esr: usize, far: usize, elr: u64) -> ! {
    let canonical = strip(far);
    let logical = logical_tag(far);
    let granule = granule_start(canonical);
    // SAFETY: both are the caller's contract, and `granule` is aligned by
    // construction.
    let allocation = unsafe { load_allocation_tag(granule) };
    let access = if is_write(esr) { "write" } else { "read" };
    panic!(
        "AArch64 synchronous tag check fault: {access} at {canonical:#x} through a pointer \
         tagged {logical:#x}; a faulting granule {granule:#x}..{end:#x} holds tag \
         {allocation:#x}; esr={esr:#x} elr={elr:#x} far={far:#x}",
        logical = logical.raw(),
        end = granule + GRANULE_BYTES,
        allocation = allocation.raw(),
    )
}
