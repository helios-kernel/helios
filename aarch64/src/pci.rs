//! AArch64 PCIe ECAM configuration access, bus enumeration, BAR management,
//! and INTx routing.
//!
//! Works identically over either Devicetree or ACPI descriptions through
//! [`PciHostDescription`]. ECAM and BAR MMIO apertures are mapped on demand
//! as Device-nGnRnE 2 MiB blocks via [`crate::vmm::map_device_mmio`].

use alloc::vec::Vec;
use core::cell::Cell;
use core::ops::RangeInclusive;
use core::ptr::NonNull;

use arm_gic::{IntId, Trigger};
use helios_hal::align_up;
use helios_virtio::{DeviceType, PciMmioMapper};
use pci_types::{
    Bar, CommandRegister, ConfigRegionAccess, EndpointHeader, MAX_BARS, PciAddress, PciHeader,
    PciPciBridgeHeader,
};

use crate::platform::{PciHostDescription, SpiInterrupt};

const PCI_ECAM_BUS_SHIFT: usize = 20;
const PCI_ECAM_BUS_BYTES: usize = 1 << PCI_ECAM_BUS_SHIFT;
const PCI_ECAM_DEVICE_SHIFT: usize = 15;
const PCI_ECAM_FUNCTION_SHIFT: usize = 12;
const PCI_CONFIG_SPACE_BYTES: u16 = 4096;
const PCI_INVALID_VENDOR_ID: u16 = 0xffff;
const PCI_MAX_DEVICES: u8 = 32;
const PCI_MAX_FUNCTIONS: u8 = 8;

#[derive(Clone, Copy)]
pub(crate) struct EcamPciConfigAccess {
    segment: u16,
    bus_start: u8,
    bus_end: u8,
    ecam_virtual_base: usize,
}

/// One discovered modern or transitional virtio-PCI function together with
/// the GICv3 SPI its INTx pin routes to.
#[derive(Clone, Copy)]
pub(crate) struct VirtioPciFunction {
    pub(crate) address: PciAddress,
    pub(crate) device_type: DeviceType,
    pub(crate) interrupt: IntId,
    pub(crate) trigger: Trigger,
}

/// Every virtio-PCI function discovered in one walk of the PCI hierarchy,
/// excluding any `virtio-iommu-pci` translation unit.
pub(crate) struct VirtioFunctions {
    functions: Vec<VirtioPciFunction>,
}

impl VirtioFunctions {
    pub(crate) fn first(&self, device_type: DeviceType) -> Option<VirtioPciFunction> {
        self.functions
            .iter()
            .copied()
            .find(|function| function.device_type == device_type)
    }

    pub(crate) fn of_type(
        &self,
        device_type: DeviceType,
    ) -> impl Iterator<Item = VirtioPciFunction> + '_ {
        self.functions
            .iter()
            .copied()
            .filter(move |function| function.device_type == device_type)
    }

    pub(crate) fn count(&self, device_type: DeviceType) -> usize {
        self.of_type(device_type).count()
    }

    pub(crate) fn addresses(&self) -> Vec<PciAddress> {
        self.functions
            .iter()
            .map(|function| function.address)
            .collect()
    }
}

struct PciMemoryWindow {
    pci_base: u64,
    cpu_base: u64,
    size: u64,
    next_free: Cell<u64>,
}

pub(crate) struct PciRoot {
    access: EcamPciConfigAccess,
    ecam_physical_base: usize,
    bus_range: RangeInclusive<u8>,
    memory_windows: Vec<PciMemoryWindow>,
    intx: [[Option<SpiInterrupt>; 4]; 32],
}

impl PciRoot {
    pub(crate) fn new(description: PciHostDescription) -> Self {
        let bus_range = description.bus_start..=description.bus_end;
        // Map the root bus's 1 MiB ECAM window immediately; secondary buses
        // are mapped on demand when `walk_functions` descends a bridge.
        let ecam_virtual_base =
            crate::vmm::map_device_mmio(description.ecam_base, PCI_ECAM_BUS_BYTES);
        let memory_windows = description
            .memory_windows
            .iter()
            .map(|window| PciMemoryWindow {
                pci_base: window.pci_base,
                cpu_base: window.cpu_base,
                size: window.size,
                next_free: Cell::new(window.pci_base),
            })
            .collect();

        let root = Self {
            access: EcamPciConfigAccess {
                segment: description.segment,
                bus_start: description.bus_start,
                bus_end: description.bus_end,
                ecam_virtual_base,
            },
            ecam_physical_base: description.ecam_base,
            bus_range,
            memory_windows,
            intx: description.intx,
        };
        root.reserve_assigned_memory_bars();
        root
    }

    pub(crate) fn access(&self) -> EcamPciConfigAccess {
        self.access
    }

    fn map_bus_ecam(&self, bus: u8) {
        let bus_index = usize::from(bus - *self.bus_range.start());
        let bus_offset = bus_index
            .checked_shl(PCI_ECAM_BUS_SHIFT as u32)
            .unwrap_or_else(|| panic!("AArch64 PCI bus {bus} overflowed ECAM offset"));
        let bus_phys = self
            .ecam_physical_base
            .checked_add(bus_offset)
            .unwrap_or_else(|| panic!("AArch64 PCI bus {bus} overflowed ECAM physical base"));
        let _ = crate::vmm::map_device_mmio(bus_phys, PCI_ECAM_BUS_BYTES);
    }

    fn reserve_assigned_memory_bars(&self) {
        for (address, _) in self.walk_functions() {
            let header = PciHeader::new(address);
            let Some(mut endpoint) = EndpointHeader::from_header(header, self.access) else {
                continue;
            };
            let saved_command = endpoint.header().command(self.access);
            endpoint.update_command(self.access, |command| {
                command - (CommandRegister::MEMORY_ENABLE | CommandRegister::IO_ENABLE)
            });
            let mut slot = 0_u8;
            while usize::from(slot) < MAX_BARS {
                let Some(bar) = endpoint.bar(slot, self.access) else {
                    slot += 1;
                    continue;
                };
                match bar {
                    Bar::Memory32 { address, size, .. } if address != 0 && size != 0 => {
                        self.reserve_window_range(u64::from(address), u64::from(size));
                    }
                    Bar::Memory64 { address, size, .. } => {
                        if address != 0 && size != 0 {
                            self.reserve_window_range(address, size);
                        }
                        slot += 1;
                    }
                    Bar::Memory32 { .. } | Bar::Io { .. } => {}
                }
                slot += 1;
            }
            endpoint.update_command(self.access, |_| saved_command);
        }
    }

    fn reserve_window_range(&self, pci_address: u64, size: u64) {
        if let Some(window) = self
            .memory_windows
            .iter()
            .find(|window| window.contains(pci_address))
        {
            window.reserve(pci_address, size);
        }
    }

    pub(crate) fn assign_unassigned_memory_bars(&self, address: PciAddress) {
        let header = PciHeader::new(address);
        let mut endpoint = EndpointHeader::from_header(header, self.access)
            .unwrap_or_else(|| panic!("PCI function {address} was not an endpoint"));
        let saved_command = endpoint.header().command(self.access);
        endpoint.update_command(self.access, |command| {
            command - (CommandRegister::MEMORY_ENABLE | CommandRegister::IO_ENABLE)
        });
        let mut slot = 0_u8;
        while usize::from(slot) < MAX_BARS {
            let Some(bar) = endpoint.bar(slot, self.access) else {
                slot += 1;
                continue;
            };
            match bar {
                Bar::Memory32 {
                    address: 0, size, ..
                } if size != 0 => {
                    let assigned = self.allocate_memory_bar(u64::from(size), false);
                    // SAFETY: `slot` is an unassigned 32-bit memory BAR on
                    // `endpoint`, and `assigned` is a size-aligned address
                    // allocated from a non-overlapping 32-bit PCI memory window.
                    unsafe {
                        endpoint
                            .write_bar(slot, self.access, assigned as usize)
                            .unwrap_or_else(|error| {
                                panic!("failed to assign PCI BAR{slot} for {address}: {error:?}")
                            });
                    }
                }
                Bar::Memory64 {
                    address: 0, size, ..
                } if size != 0 => {
                    let assigned = self.allocate_memory_bar(size, true);
                    // SAFETY: `slot` is an unassigned 64-bit memory BAR on
                    // `endpoint`, and `assigned` is a size-aligned address
                    // allocated from a non-overlapping PCI memory window.
                    unsafe {
                        endpoint
                            .write_bar(slot, self.access, assigned as usize)
                            .unwrap_or_else(|error| {
                                panic!("failed to assign PCI BAR{slot} for {address}: {error:?}")
                            });
                    }
                    slot += 1;
                }
                Bar::Memory64 { .. } => slot += 1,
                Bar::Memory32 { .. } | Bar::Io { .. } => {}
            }
            slot += 1;
        }
        endpoint.update_command(self.access, |_| saved_command);
    }

    /// Masks legacy INTx assertion on `address`.
    ///
    /// `virtio-iommu-pci` is driven synchronously on its request queue and
    /// polled on a timer for fault reports; leaving INTx unmasked on a
    /// platform that routes PCI INTx to the GIC would assert an unserviced
    /// level-triggered SPI.
    pub(crate) fn disable_intx(&self, address: PciAddress) {
        let header = PciHeader::new(address);
        let mut endpoint = EndpointHeader::from_header(header, self.access)
            .unwrap_or_else(|| panic!("PCI function {address} was not an endpoint"));
        endpoint.update_command(self.access, |command| {
            command | CommandRegister::INTERRUPT_DISABLE
        });
    }

    /// Discovers every virtio-PCI function (excluding `virtio-iommu-pci`)
    /// in one walk of the PCI hierarchy.
    pub(crate) fn virtio_functions(&self) -> VirtioFunctions {
        let mut functions = Vec::new();
        for (address, route) in self.walk_functions() {
            let Some(device_type) = helios_virtio::virtio_pci_device_type(&self.access, address)
            else {
                continue;
            };
            if device_type == DeviceType::Iommu {
                continue;
            }
            let header = PciHeader::new(address);
            let endpoint = EndpointHeader::from_header(header, self.access)
                .unwrap_or_else(|| panic!("virtio-PCI function {address} is not an endpoint"));
            let (pin, _) = endpoint.interrupt(self.access);
            let spi = self.resolve_intx(address, route, pin).unwrap_or_else(|| {
                panic!(
                    "virtio-PCI function {address} (pin {pin}) has no routed GICv3 INTx interrupt"
                )
            });
            functions.push(VirtioPciFunction {
                address,
                device_type,
                interrupt: spi.intid(),
                trigger: spi.trigger,
            });
        }
        VirtioFunctions { functions }
    }

    fn resolve_intx(
        &self,
        address: PciAddress,
        route: Option<BridgeIntxRoute>,
        pin: u8,
    ) -> Option<SpiInterrupt> {
        if !(1..=4).contains(&pin) {
            return None;
        }
        let (root_dev, root_pin) = match route {
            None => (address.device(), pin),
            Some(bridge) => {
                let swizzled = usize::from((pin - 1 + address.device()) % 4);
                (bridge.root_device, bridge.pin_map[swizzled])
            }
        };
        self.intx
            .get(usize::from(root_dev))
            .and_then(|pins| pins.get(usize::from(root_pin - 1)))
            .copied()
            .flatten()
    }

    fn walk_functions(&self) -> Vec<(PciAddress, Option<BridgeIntxRoute>)> {
        let mut visited = [0_u64; 4];
        let mut pending: Vec<(u8, Option<BridgeIntxRoute>)> = Vec::new();
        let mark_bus = |bus: u8,
                        route: Option<BridgeIntxRoute>,
                        visited: &mut [u64; 4],
                        pending: &mut Vec<(u8, Option<BridgeIntxRoute>)>| {
            if !self.bus_range.contains(&bus) {
                return;
            }
            let word = &mut visited[usize::from(bus / 64)];
            let bit = 1_u64 << (bus % 64);
            if *word & bit == 0 {
                *word |= bit;
                self.map_bus_ecam(bus);
                pending.push((bus, route));
            }
        };

        mark_bus(*self.bus_range.start(), None, &mut visited, &mut pending);

        let mut found = Vec::new();
        let mut cursor = 0;
        while cursor < pending.len() {
            let (bus, route) = pending[cursor];
            cursor += 1;
            for device in 0..PCI_MAX_DEVICES {
                let first = PciAddress::new(self.access.segment, bus, device, 0);
                let header = PciHeader::new(first);
                let (vendor_id, _) = header.id(self.access);
                if vendor_id == PCI_INVALID_VENDOR_ID {
                    continue;
                }
                let function_count = if header.has_multiple_functions(self.access) {
                    PCI_MAX_FUNCTIONS
                } else {
                    1
                };
                for function in 0..function_count {
                    let address = PciAddress::new(self.access.segment, bus, device, function);
                    let header = PciHeader::new(address);
                    if function != 0 && header.id(self.access).0 == PCI_INVALID_VENDOR_ID {
                        continue;
                    }
                    found.push((address, route));
                    if let Some(bridge) = PciPciBridgeHeader::from_header(header, self.access) {
                        let secondary = bridge.secondary_bus_number(self.access);
                        if secondary != 0 {
                            let child_route = match route {
                                None => BridgeIntxRoute {
                                    root_device: device,
                                    pin_map: [
                                        (device % 4) + 1,
                                        ((1 + device) % 4) + 1,
                                        ((2 + device) % 4) + 1,
                                        ((3 + device) % 4) + 1,
                                    ],
                                },
                                Some(parent) => BridgeIntxRoute {
                                    root_device: parent.root_device,
                                    pin_map: [
                                        parent.pin_map[usize::from(device % 4)],
                                        parent.pin_map[usize::from((1 + device) % 4)],
                                        parent.pin_map[usize::from((2 + device) % 4)],
                                        parent.pin_map[usize::from((3 + device) % 4)],
                                    ],
                                },
                            };
                            mark_bus(secondary, Some(child_route), &mut visited, &mut pending);
                        }
                    }
                }
            }
        }
        found
    }

    fn translate_mmio_address(&self, bus_address: u64) -> usize {
        let window = self
            .memory_windows
            .iter()
            .find(|window| window.contains(bus_address))
            .unwrap_or_else(|| {
                panic!(
                    "AArch64 PCI MMIO address {bus_address:#x} did not match any CPU memory window"
                )
            });
        window.translate(bus_address)
    }

    fn allocate_memory_bar(&self, size: u64, allow_above_4g: bool) -> u64 {
        assert!(
            size.is_power_of_two(),
            "PCI BAR size {size:#x} was not a power of two"
        );
        self.memory_windows
            .iter()
            .find_map(|window| window.allocate(size, allow_above_4g))
            .unwrap_or_else(|| {
                panic!(
                    "failed to allocate a PCI memory BAR of size {size:#x} on aarch64 \
                     (64-bit allowed: {allow_above_4g})"
                )
            })
    }
}

#[derive(Clone, Copy)]
struct BridgeIntxRoute {
    root_device: u8,
    pin_map: [u8; 4],
}

impl PciMmioMapper for PciRoot {
    fn map_region(
        &self,
        physical_address: u64,
        size: usize,
    ) -> helios_hal::io::IoResult<NonNull<u8>> {
        let cpu_physical = self.translate_mmio_address(physical_address);
        let virtual_address = crate::vmm::map_device_mmio(cpu_physical, size.max(1));
        NonNull::new(virtual_address as *mut u8).ok_or(helios_hal::io::IoError::DeviceFault)
    }
}

impl ConfigRegionAccess for EcamPciConfigAccess {
    unsafe fn read(&self, address: PciAddress, offset: u16) -> u32 {
        let config_address = self.config_address(address, offset);
        // SAFETY: `config_address` validates segment, bus range, 4-byte
        // alignment, and `< 4096` offset within the Device-nGnRnE mapped ECAM
        // region.
        unsafe { (config_address as *const u32).read_volatile() }
    }

    unsafe fn write(&self, address: PciAddress, offset: u16, value: u32) {
        let config_address = self.config_address(address, offset);
        // SAFETY: `config_address` validates segment, bus range, 4-byte
        // alignment, and `< 4096` offset within the Device-nGnRnE mapped ECAM
        // region.
        unsafe { (config_address as *mut u32).write_volatile(value) };
    }
}

impl EcamPciConfigAccess {
    fn config_address(&self, address: PciAddress, offset: u16) -> usize {
        assert!(
            address.segment() == self.segment,
            "PCI segment mismatch: expected {}, got {}",
            self.segment,
            address.segment()
        );
        assert!(
            (self.bus_start..=self.bus_end).contains(&address.bus()),
            "PCI bus {} is outside ECAM bus range {}..={}",
            address.bus(),
            self.bus_start,
            self.bus_end
        );
        assert!(
            offset & 0b11 == 0,
            "PCI ECAM access requires aligned offsets, got {offset:#x}"
        );
        assert!(
            offset < PCI_CONFIG_SPACE_BYTES,
            "PCI ECAM offset {offset:#x} exceeds config space"
        );

        let bus_index = usize::from(address.bus() - self.bus_start);
        let bus_offset = bus_index
            .checked_shl(PCI_ECAM_BUS_SHIFT as u32)
            .unwrap_or_else(|| panic!("PCI bus index {bus_index} overflowed ECAM addressing"));
        let device_offset = usize::from(address.device()) << PCI_ECAM_DEVICE_SHIFT;
        let function_offset = usize::from(address.function()) << PCI_ECAM_FUNCTION_SHIFT;

        self.ecam_virtual_base
            .checked_add(bus_offset)
            .and_then(|base| base.checked_add(device_offset))
            .and_then(|base| base.checked_add(function_offset))
            .and_then(|base| base.checked_add(usize::from(offset)))
            .unwrap_or_else(|| {
                panic!("PCI ECAM address overflowed for {address} offset {offset:#x}")
            })
    }
}

impl PciMemoryWindow {
    fn contains(&self, bus_address: u64) -> bool {
        let end = self
            .pci_base
            .checked_add(self.size)
            .unwrap_or_else(|| panic!("PCI MMIO window overflowed while checking membership"));
        self.pci_base <= bus_address && bus_address < end
    }

    fn translate(&self, bus_address: u64) -> usize {
        let offset = bus_address
            .checked_sub(self.pci_base)
            .unwrap_or_else(|| panic!("PCI MMIO translation underflowed"));
        let cpu_address = self
            .cpu_base
            .checked_add(offset)
            .unwrap_or_else(|| panic!("PCI MMIO CPU address overflowed"));
        usize::try_from(cpu_address).unwrap_or_else(|_| {
            panic!("PCI MMIO CPU address {cpu_address:#x} does not fit in usize")
        })
    }

    fn reserve(&self, bus_address: u64, size: u64) {
        if let Some(end) = bus_address.checked_add(size)
            && end > self.next_free.get()
        {
            self.next_free.set(end);
        }
    }

    fn allocate(&self, size: u64, allow_above_4g: bool) -> Option<u64> {
        let current = self.next_free.get();
        let aligned = align_up(
            usize::try_from(current).unwrap_or_else(|_| {
                panic!("PCI BAR allocator cursor {current:#x} does not fit in usize")
            }),
            usize::try_from(size)
                .unwrap_or_else(|_| panic!("PCI BAR size {size:#x} does not fit in usize")),
        ) as u64;
        let end = aligned.checked_add(size)?;
        let window_end = self.pci_base.checked_add(self.size)?;
        if end > window_end {
            return None;
        }
        if !allow_above_4g && end > (u64::from(u32::MAX) + 1) {
            return None;
        }
        self.next_free.set(end);
        Some(aligned)
    }
}
