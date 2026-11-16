//! Stage-2 page tables. Mutations hold a processor-local interrupt mask and
//! one table lock; walkers on other processors remain live. Broadcast TLBI
//! completion is the hardware acknowledgement before any table is freed.

use aarch64_paging::Mapping;
use aarch64_paging::descriptor::{PhysicalAddress, Stage2Attributes, VirtualAddress};
use aarch64_paging::linearmap::LinearTranslation;
use aarch64_paging::paging::{Constraints, MemoryRegion, TranslationRegime, VaRange};
use core::arch::asm;
use helios_hal::critical_section::with_local_interrupts_masked;
use helios_hal::hv::{GuestAddress, GuestRange, HvError};
use helios_hal::pmm::PhysFrame;
use helios_hal::vmm::PageFlags;
use spin::Mutex;

type PageTables = Mapping<LinearTranslation<Stage2Attributes>, BroadcastStage2>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BroadcastStage2;

impl TranslationRegime for BroadcastStage2 {
    type Attributes = Stage2Attributes;
    type Asid = usize;
    type VaRange = VaRange;

    fn invalidate_va(_: VirtualAddress) {
        // VTTBR selects the VMID, including cached guest Stage-1 translations.
        // The caller/library supplies the surrounding publication barriers.
        unsafe { asm!("tlbi vmalls12e1is", options(nostack, preserves_flags)) };
    }

    unsafe fn activate(root: PhysicalAddress, vmid: usize, _: VaRange) -> usize {
        let previous;
        unsafe {
            asm!(
                "mrs {previous}, vttbr_el2",
                "msr vttbr_el2, {root}",
                "isb",
                previous = out(reg) previous,
                root = in(reg) root.0 | (vmid << 48),
                options(nostack, preserves_flags),
            );
        }
        previous
    }

    unsafe fn deactivate(previous: usize, _: usize, _: VaRange) {
        flush();
        unsafe {
            asm!("msr vttbr_el2, {previous}", "isb", previous = in(reg) previous,
                options(nostack, preserves_flags));
        }
    }
}

pub(super) struct Tables {
    pages: Mutex<PageTables>,
    vttbr: usize,
    offset: usize,
    address_bits: u8,
}

impl Tables {
    pub(super) fn new(vmid: u16, offset: usize, address_bits: u8) -> Self {
        // Match VTCR.SL0: level one covers up to 39 IPA bits, level zero
        // covers the remaining supported widths through 48 bits.
        let pages = Mapping::with_asid_and_va_range(
            LinearTranslation::new((offset as isize).wrapping_neg()),
            usize::from(vmid),
            if address_bits > 39 { 0 } else { 1 },
            BroadcastStage2,
            VaRange::Lower,
        );
        let vttbr = pages.root_address().0 | (usize::from(vmid) << 48);
        // These tables may acquire hardware walkers as soon as they are
        // published. Retain live-table checking for their entire lifetime.
        pages.mark_active();
        Self {
            pages: Mutex::new(pages),
            vttbr,
            offset,
            address_bits,
        }
    }

    pub(super) fn vttbr(&self) -> usize {
        self.vttbr
    }

    fn region(&self, range: GuestRange) -> Result<MemoryRegion, HvError> {
        if range.end().0 > 1u64 << self.address_bits {
            return Err(HvError::AddressWidth);
        }
        Ok(MemoryRegion::new(
            range.start().0 as usize,
            range.end().0 as usize,
        ))
    }

    fn with<R>(&self, op: impl FnOnce(&mut PageTables) -> R) -> R {
        with_local_interrupts_masked(|| {
            let mut pages = self.pages.lock();
            // No guest can execute on this processor during a mutation.
            // Selecting the root only selects the broadcast's VMID; it
            // does not enable Stage-2 for the VHE host's own accesses.
            let previous = unsafe {
                BroadcastStage2::activate(pages.root_address(), pages.asid(), VaRange::Lower)
            };
            let result = op(&mut pages);
            unsafe { BroadcastStage2::deactivate(previous, pages.asid(), VaRange::Lower) };
            result
        })
    }

    pub(super) fn contains(&self, address: GuestAddress) -> bool {
        let mut present = false;
        with_local_interrupts_masked(|| {
            self.pages
                .lock()
                .walk_range(
                    &MemoryRegion::new(address.0 as usize, address.0 as usize + 1),
                    &mut |_, descriptor, _| {
                        present = descriptor.flags().contains(Stage2Attributes::VALID);
                        Ok(())
                    },
                )
                .is_ok()
        }) && present
    }

    pub(super) unsafe fn map(
        &self,
        range: GuestRange,
        frames: &[PhysFrame],
        flags: PageFlags,
    ) -> Result<(), HvError> {
        if frames.len() != range.page_count() {
            return Err(HvError::InvalidRange);
        }
        let region = self.region(range)?;
        let attributes = attributes(flags)?;
        self.with(|pages| {
            let mut overlap = false;
            pages
                .walk_range(&region, &mut |_, descriptor, _| {
                    overlap |= descriptor.flags().contains(Stage2Attributes::VALID);
                    Ok(())
                })
                .expect("validated Stage-2 range");
            if overlap {
                return Err(HvError::Overlap);
            }
            for (index, frame) in frames.iter().enumerate() {
                let start = range.start().0 as usize + index * PhysFrame::SIZE;
                pages
                    .map_range(
                        &MemoryRegion::new(start, start + PhysFrame::SIZE),
                        PhysicalAddress(frame.phys_addr() - self.offset),
                        attributes,
                        Constraints::NO_BLOCK_MAPPINGS,
                    )
                    .expect("validated Stage-2 mapping and attributes");
            }
            Ok(())
        })
    }

    pub(super) fn unmap(&self, range: GuestRange) -> Result<(), HvError> {
        let region = self.region(range)?;
        self.with(|pages| {
            pages
                .map_range(
                    &region,
                    PhysicalAddress(0),
                    Stage2Attributes::empty(),
                    Constraints::NO_BLOCK_MAPPINGS,
                )
                .expect("validated Stage-2 unmap range");
        });
        Ok(())
    }

    pub(super) fn protect(&self, range: GuestRange, flags: PageFlags) -> Result<(), HvError> {
        let region = self.region(range)?;
        let attributes = attributes(flags)?;
        self.with(|pages| {
            let mut missing = false;
            pages
                .walk_range(&region, &mut |_, descriptor, _| {
                    missing |= !descriptor.flags().contains(Stage2Attributes::VALID);
                    Ok(())
                })
                .expect("validated Stage-2 permission range");
            if missing {
                return Err(HvError::NotMapped);
            }
            let permissions = Stage2Attributes::S2AP_ACCESS_RW | Stage2Attributes::XN;
            pages
                .modify_range(&region, &|_, descriptor| {
                    descriptor.modify_flags(attributes & permissions, !attributes & permissions)
                })
                .expect("Stage-2 permission changes preserve physical addresses and memory types");
            Ok(())
        })
    }
}

impl Drop for Tables {
    fn drop(&mut self) {
        // Every vCPU retains its space, so the final owner has no hardware
        // walker left. Flush remote cached translations before dropping pages
        // or allowing the owning space to return its VMID to the allocator.
        self.with(|pages| pages.mark_inactive());
    }
}

fn attributes(flags: PageFlags) -> Result<Stage2Attributes, HvError> {
    if flags.is_empty()
        || !(flags - (PageFlags::READ | PageFlags::WRITE | PageFlags::EXECUTE)).is_empty()
    {
        return Err(HvError::InvalidPermissions);
    }
    let mut attributes = Stage2Attributes::VALID
        | Stage2Attributes::ACCESS_FLAG
        | Stage2Attributes::SH_INNER
        | Stage2Attributes::MEMATTR_NORMAL_INNER_WB
        | Stage2Attributes::MEMATTR_NORMAL_OUTER_WB;
    if flags.contains(PageFlags::READ) {
        attributes |= Stage2Attributes::S2AP_ACCESS_RO;
    }
    if flags.contains(PageFlags::WRITE) {
        attributes |= Stage2Attributes::S2AP_ACCESS_WO;
    }
    if !flags.contains(PageFlags::EXECUTE) {
        attributes |= Stage2Attributes::XN;
    }
    Ok(attributes)
}

pub(super) fn flush() {
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vmalls12e1is",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }
}
