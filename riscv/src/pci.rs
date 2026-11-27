use alloc::vec::Vec;
use arrayvec::ArrayVec;
use core::cell::Cell;
use core::num::NonZeroU32;
use core::ops::RangeInclusive;
use core::ptr::NonNull;

use fdt::Fdt;
use helios_firmware::VirtioIommuTopology;
use helios_hal::align_up;
use helios_virtio::{DeviceType, InterruptController, PciMmioMapper};
use pci_types::{
    Bar, CommandRegister, ConfigRegionAccess, EndpointHeader, MAX_BARS, PciAddress, PciHeader,
    PciPciBridgeHeader,
};

use crate::net::{InterruptSourceId, PlicInterrupt};

const PCI_ECAM_BUS_SHIFT: usize = 20;
const PCI_ECAM_DEVICE_SHIFT: usize = 15;
const PCI_ECAM_FUNCTION_SHIFT: usize = 12;
const PCI_CONFIG_SPACE_BYTES: u16 = 4096;
const PCI_INVALID_VENDOR_ID: u16 = 0xffff;
const PCI_MAX_DEVICES: u8 = 32;
const PCI_MAX_FUNCTIONS: u8 = 8;
const PCI_RANGE_IO_SPACE: u8 = 0x01;
const PCI_RANGE_MEMORY32_SPACE: u8 = 0x02;
const PCI_RANGE_MEMORY64_SPACE: u8 = 0x03;
const MAX_PCI_MEMORY_WINDOWS: usize = 4;
const MAX_INTX_MAP_ENTRIES: usize = 64;

#[derive(Clone, Copy)]
pub(crate) struct EcamPciConfigAccess {
    segment: u16,
    bus_start: u8,
    bus_end: u8,
    ecam_base: usize,
}

#[derive(Clone, Copy)]
struct IntxMapMask {
    child_hi: u32,
    child_pin: u32,
}

#[derive(Clone, Copy)]
struct IntxMapEntry {
    child_hi: u32,
    child_pin: u32,
    line: PlicInterrupt,
}

/// One discovered modern or transitional virtio-PCI function together with
/// the PLIC INTx line the device tree routes it to.
#[derive(Clone, Copy)]
pub(crate) struct VirtioPciFunction {
    pub(crate) address: PciAddress,
    pub(crate) device_type: DeviceType,
    pub(crate) line: PlicInterrupt,
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

pub(crate) struct PciHostController {
    access: EcamPciConfigAccess,
    bus_range: RangeInclusive<u8>,
    memory_windows: ArrayVec<PciMemoryWindow, MAX_PCI_MEMORY_WINDOWS>,
    intx_mask: Option<IntxMapMask>,
    intx_map: ArrayVec<IntxMapEntry, MAX_INTX_MAP_ENTRIES>,
    iommu: Option<VirtioIommuTopology>,
}

struct PciMemoryWindow {
    pci_base: u64,
    cpu_base: u64,
    size: u64,
    next_free: Cell<u64>,
}

impl PciHostController {
    pub(crate) fn discover(fdt: &Fdt<'_>) -> Option<Self> {
        let node = fdt.find_compatible(&["pci-host-ecam-generic"])?;
        let ecam_region = node
            .reg()
            .and_then(|mut reg| reg.next())
            .unwrap_or_else(|| panic!("PCI ECAM host node is missing a CPU-addressable reg"));
        let ecam_size = ecam_region
            .size
            .filter(|&size| size != 0)
            .unwrap_or_else(|| panic!("PCI ECAM host node has zero-sized reg"));
        let ecam_base =
            crate::vmm::map_mmio_range(ecam_region.starting_address as usize, ecam_size);
        let domain = node.property("linux,pci-domain").map_or(0, |property| {
            let domain = read_be_u32(property.value);
            u16::try_from(domain)
                .unwrap_or_else(|_| panic!("PCI domain {domain} does not fit in u16"))
        });
        let bus_range = parse_bus_range(node);
        let parent_address_cells = infer_parent_address_cells(node);
        let memory_windows = parse_memory_windows(node, parent_address_cells);
        let (intx_mask, intx_map) = parse_interrupt_map(fdt, node);
        let iommu = helios_firmware::parse_devicetree_pci_iommu(fdt, &node, domain)
            .unwrap_or_else(|error| panic!("PCI host node has an invalid `iommu-map`: {error}"));

        Some(Self {
            access: EcamPciConfigAccess {
                segment: domain,
                bus_start: *bus_range.start(),
                bus_end: *bus_range.end(),
                ecam_base,
            },
            bus_range,
            memory_windows,
            intx_mask,
            intx_map,
            iommu,
        })
    }

    pub(crate) fn config_access(&self) -> EcamPciConfigAccess {
        self.access
    }

    pub(crate) fn bus_range(&self) -> RangeInclusive<u8> {
        self.bus_range.clone()
    }

    pub(crate) fn iommu(&self) -> Option<VirtioIommuTopology> {
        self.iommu
    }

    pub(crate) fn translate_mmio_address(&self, bus_address: usize) -> usize {
        let bus_address = u64::try_from(bus_address)
            .unwrap_or_else(|_| panic!("PCI MMIO address {bus_address:#x} does not fit in u64"));
        let window = self
            .memory_windows
            .iter()
            .find(|window| window.contains(bus_address))
            .unwrap_or_else(|| {
                panic!("PCI MMIO address {bus_address:#x} did not match any CPU memory window")
            });
        window.translate(bus_address)
    }

    /// Walks all existing endpoints once and advances each memory window's
    /// free cursor past any BAR already assigned by firmware or earlier
    /// bring-up (such as the PCI watchdog).
    pub(crate) fn reserve_assigned_memory_bars(&self) {
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
    /// platform that routes PCI INTx to the PLIC would assert an unserviced
    /// level-triggered interrupt line.
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
            let line = self.resolve_intx(address, route, pin).unwrap_or_else(|| {
                panic!(
                    "virtio-PCI function {address} (pin {pin}) did not match any PCI \
                     `interrupt-map` entry"
                )
            });
            functions.push(VirtioPciFunction {
                address,
                device_type,
                line,
            });
        }
        VirtioFunctions { functions }
    }

    fn resolve_intx(
        &self,
        address: PciAddress,
        route: Option<BridgeIntxRoute>,
        pin: u8,
    ) -> Option<PlicInterrupt> {
        if !(1..=4).contains(&pin) {
            return None;
        }
        let mask = self.intx_mask?;
        let (root_bus, root_dev, root_fn, root_pin) = match route {
            None => (address.bus(), address.device(), address.function(), pin),
            Some(bridge) => {
                let swizzled = usize::from((pin - 1 + address.device()) % 4);
                (
                    bridge.root_bus,
                    bridge.root_device,
                    0,
                    bridge.pin_map[swizzled],
                )
            }
        };
        let child_hi =
            (u32::from(root_bus) << 16) | (u32::from(root_dev) << 11) | (u32::from(root_fn) << 8);
        let child_pin = u32::from(root_pin);
        self.intx_map.iter().find_map(|entry| {
            let addr_matches = (child_hi & mask.child_hi) == (entry.child_hi & mask.child_hi);
            let pin_matches = (child_pin & mask.child_pin) == (entry.child_pin & mask.child_pin);
            (addr_matches && pin_matches).then_some(entry.line)
        })
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
                                    root_bus: bus,
                                    root_device: device,
                                    pin_map: [
                                        (device % 4) + 1,
                                        ((1 + device) % 4) + 1,
                                        ((2 + device) % 4) + 1,
                                        ((3 + device) % 4) + 1,
                                    ],
                                },
                                Some(parent) => BridgeIntxRoute {
                                    root_bus: parent.root_bus,
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
                    "failed to allocate a PCI memory BAR of size {size:#x} on riscv (64-bit allowed: {allow_above_4g})"
                )
            })
    }
}

#[derive(Clone, Copy)]
struct BridgeIntxRoute {
    root_bus: u8,
    root_device: u8,
    pin_map: [u8; 4],
}

impl PciMmioMapper for PciHostController {
    fn map_region(
        &self,
        physical_address: u64,
        size: usize,
    ) -> helios_hal::io::IoResult<NonNull<u8>> {
        let bus_address = usize::try_from(physical_address).unwrap_or_else(|_| {
            panic!("PCI MMIO address {physical_address:#x} does not fit in usize")
        });
        let cpu_phys = self.translate_mmio_address(bus_address);
        let virt = crate::vmm::map_mmio_range(cpu_phys, size.max(1));
        NonNull::new(virt as *mut u8).ok_or(helios_hal::io::IoError::DeviceFault)
    }
}

impl ConfigRegionAccess for EcamPciConfigAccess {
    unsafe fn read(&self, address: PciAddress, offset: u16) -> u32 {
        let config_address = self.config_address(address, offset);
        // SAFETY: `config_address` validates segment, bus range, 4-byte alignment,
        // and `< 4096` offset within the identity-mapped ECAM region.
        unsafe { (config_address as *const u32).read_volatile() }
    }

    unsafe fn write(&self, address: PciAddress, offset: u16, value: u32) {
        let config_address = self.config_address(address, offset);
        // SAFETY: `config_address` validates segment, bus range, 4-byte alignment,
        // and `< 4096` offset within the identity-mapped ECAM region.
        unsafe { (config_address as *mut u32).write_volatile(value) };
    }
}

impl i6300esb::PciConfigIo for EcamPciConfigAccess {
    fn read_u8(&self, address: PciAddress, offset: u16) -> u8 {
        let config_address = self.byte_address(address, offset);
        // SAFETY: `byte_address` validates segment, bus range, and `< 4096`
        // offset within the identity-mapped ECAM region.
        unsafe { (config_address as *const u8).read_volatile() }
    }

    fn read_u16(&self, address: PciAddress, offset: u16) -> u16 {
        assert!(
            offset & 0b1 == 0,
            "PCI ECAM u16 access requires aligned offsets, got {offset:#x}"
        );
        let config_address = self.byte_address(address, offset);
        // SAFETY: `byte_address` validates segment, bus range, and `< 4096`
        // offset, and the assert above guarantees 2-byte alignment.
        unsafe { (config_address as *const u16).read_volatile() }
    }

    fn write_u8(&self, address: PciAddress, offset: u16, value: u8) {
        let config_address = self.byte_address(address, offset);
        // SAFETY: `byte_address` validates segment, bus range, and `< 4096`
        // offset within the identity-mapped ECAM region.
        unsafe { (config_address as *mut u8).write_volatile(value) };
    }

    fn write_u16(&self, address: PciAddress, offset: u16, value: u16) {
        assert!(
            offset & 0b1 == 0,
            "PCI ECAM u16 access requires aligned offsets, got {offset:#x}"
        );
        let config_address = self.byte_address(address, offset);
        // SAFETY: `byte_address` validates segment, bus range, and `< 4096`
        // offset, and the assert above guarantees 2-byte alignment.
        unsafe { (config_address as *mut u16).write_volatile(value) };
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

        self.ecam_base
            .checked_add(bus_offset)
            .and_then(|base| base.checked_add(device_offset))
            .and_then(|base| base.checked_add(function_offset))
            .and_then(|base| base.checked_add(usize::from(offset)))
            .unwrap_or_else(|| {
                panic!("PCI ECAM address overflowed for {address} offset {offset:#x}")
            })
    }

    fn byte_address(&self, address: PciAddress, offset: u16) -> usize {
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
            offset < PCI_CONFIG_SPACE_BYTES,
            "PCI ECAM offset {offset:#x} exceeds config space"
        );

        let bus_index = usize::from(address.bus() - self.bus_start);
        let bus_offset = bus_index
            .checked_shl(PCI_ECAM_BUS_SHIFT as u32)
            .unwrap_or_else(|| panic!("PCI bus index {bus_index} overflowed ECAM addressing"));
        let device_offset = usize::from(address.device()) << PCI_ECAM_DEVICE_SHIFT;
        let function_offset = usize::from(address.function()) << PCI_ECAM_FUNCTION_SHIFT;

        self.ecam_base
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

fn parse_interrupt_map(
    fdt: &Fdt<'_>,
    node: fdt::node::FdtNode<'_, '_>,
) -> (
    Option<IntxMapMask>,
    ArrayVec<IntxMapEntry, MAX_INTX_MAP_ENTRIES>,
) {
    let mut entries = ArrayVec::new();
    let (Some(map_prop), Some(mask_prop)) = (
        node.property("interrupt-map"),
        node.property("interrupt-map-mask"),
    ) else {
        return (None, entries);
    };

    assert!(
        mask_prop.value.len() == 16,
        "PCI `interrupt-map-mask` must be 4 cells (16 bytes), got {} bytes",
        mask_prop.value.len()
    );
    let mask = IntxMapMask {
        child_hi: read_be_u32(&mask_prop.value[0..4]),
        child_pin: read_be_u32(&mask_prop.value[12..16]),
    };

    let bytes = map_prop.value;
    assert!(
        bytes.len().is_multiple_of(4),
        "PCI `interrupt-map` byte length {} is not a multiple of 4",
        bytes.len()
    );
    let mut offset = 0;
    while offset < bytes.len() {
        assert!(
            offset + 20 <= bytes.len(),
            "PCI `interrupt-map` entry at byte offset {offset} is truncated"
        );
        let child_hi = read_be_u32(&bytes[offset..offset + 4]);
        let child_pin = read_be_u32(&bytes[offset + 12..offset + 16]);
        let parent_phandle = read_be_u32(&bytes[offset + 16..offset + 20]);
        offset += 20;

        let parent = fdt.find_phandle(parent_phandle).unwrap_or_else(|| {
            panic!("PCI `interrupt-map` references unknown phandle {parent_phandle:#x}")
        });
        // Per DTSpec §2.4.3.1, the interrupt-parent's `#address-cells`
        // defaults to 0 when omitted.
        let parent_address_cells = parent
            .property("#address-cells")
            .map_or(0, |prop| read_be_u32(prop.value) as usize);
        let parent_irq_cells = parent
            .property("#interrupt-cells")
            .map(|prop| read_be_u32(prop.value) as usize)
            .unwrap_or_else(|| {
                panic!(
                    "PCI interrupt parent `{}` is missing `#interrupt-cells`",
                    parent.name
                )
            });
        let tail_bytes = (parent_address_cells + parent_irq_cells) * 4;
        assert!(
            offset + tail_bytes <= bytes.len(),
            "PCI `interrupt-map` parent specifier at byte offset {offset} runs past the property"
        );
        offset += parent_address_cells * 4;
        assert!(
            parent_irq_cells == 1,
            "RISC-V PCI interrupt parent `{}` uses {parent_irq_cells} `#interrupt-cells`; \
             expected 1 for PLIC",
            parent.name
        );
        let source = read_be_u32(&bytes[offset..offset + 4]);
        offset += 4;
        let controller = InterruptController::of_node(&parent).unwrap_or_else(|| {
            panic!(
                "RISC-V PCI interrupt parent `{}` is missing a `reg` window",
                parent.name
            )
        });
        let source = NonZeroU32::new(source).unwrap_or_else(|| {
            panic!("RISC-V PCI `interrupt-map` maps to PLIC source 0 (no interrupt)")
        });
        entries
            .try_push(IntxMapEntry {
                child_hi,
                child_pin,
                line: PlicInterrupt {
                    controller,
                    source: InterruptSourceId(source),
                },
            })
            .unwrap_or_else(|_| {
                panic!("PCI `interrupt-map` has more than {MAX_INTX_MAP_ENTRIES} entries")
            });
    }

    (Some(mask), entries)
}

fn parse_bus_range(node: fdt::node::FdtNode<'_, '_>) -> RangeInclusive<u8> {
    let property = node
        .property("bus-range")
        .unwrap_or_else(|| panic!("PCI host node is missing bus-range"));
    let start = read_be_u32(
        property
            .value
            .get(..4)
            .unwrap_or_else(|| panic!("PCI bus-range is missing the start cell")),
    );
    let end = read_be_u32(
        property
            .value
            .get(4..8)
            .unwrap_or_else(|| panic!("PCI bus-range is missing the end cell")),
    );
    let start = u8::try_from(start)
        .unwrap_or_else(|_| panic!("PCI bus-range start {start} does not fit in u8"));
    let end =
        u8::try_from(end).unwrap_or_else(|_| panic!("PCI bus-range end {end} does not fit in u8"));
    assert!(
        start <= end,
        "PCI bus-range start {start} exceeds end {end}"
    );
    start..=end
}

fn infer_parent_address_cells(node: fdt::node::FdtNode<'_, '_>) -> usize {
    let property = node
        .property("ranges")
        .unwrap_or_else(|| panic!("PCI host node is missing ranges"));
    assert!(
        property.value.len().is_multiple_of(4),
        "PCI ranges byte length {} is not a multiple of 4",
        property.value.len()
    );

    let child_sizes = node.cell_sizes();
    assert!(
        child_sizes.address_cells == 3,
        "PCI host #address-cells must be 3, got {}",
        child_sizes.address_cells
    );
    let total_cells = property.value.len() / 4;
    let entry_tail_cells = child_sizes.address_cells + child_sizes.size_cells;
    let mut parent_cells = None;

    for candidate in [1_usize, 2] {
        let entry_cells = entry_tail_cells + candidate;
        if total_cells.is_multiple_of(entry_cells) {
            assert!(
                parent_cells.is_none(),
                "PCI ranges matched multiple parent #address-cells candidates"
            );
            parent_cells = Some(candidate);
        }
    }

    parent_cells.unwrap_or_else(|| {
        panic!(
            "failed to infer PCI parent #address-cells from {} total range cells",
            total_cells
        )
    })
}

fn parse_memory_windows(
    node: fdt::node::FdtNode<'_, '_>,
    parent_address_cells: usize,
) -> ArrayVec<PciMemoryWindow, MAX_PCI_MEMORY_WINDOWS> {
    let property = node
        .property("ranges")
        .unwrap_or_else(|| panic!("PCI host node is missing ranges"));
    let child_sizes = node.cell_sizes();
    let entry_cells = child_sizes.address_cells + parent_address_cells + child_sizes.size_cells;
    let entry_bytes = entry_cells * 4;
    assert!(
        property.value.len().is_multiple_of(entry_bytes),
        "PCI ranges byte length {} is not divisible by entry size {}",
        property.value.len(),
        entry_bytes
    );

    let mut windows = ArrayVec::new();
    for entry in property.value.chunks_exact(entry_bytes) {
        let child_hi = read_be_u32(&entry[..4]);
        let space = (child_hi >> 24) as u8;
        if space == PCI_RANGE_IO_SPACE {
            continue;
        }
        let extra_address_bits = child_hi & 0x00ff_ffff;
        assert!(
            space == PCI_RANGE_MEMORY32_SPACE || space == PCI_RANGE_MEMORY64_SPACE,
            "unsupported PCI ranges space code {space:#x}"
        );
        assert!(
            extra_address_bits == 0,
            "unsupported PCI range encoded high address bits {extra_address_bits:#x}"
        );
        let child_base =
            (u64::from(read_be_u32(&entry[4..8])) << 32) | u64::from(read_be_u32(&entry[8..12]));
        let parent_offset = child_sizes.address_cells * 4;
        let parent_base =
            parse_cells_as_u64(&entry[parent_offset..parent_offset + parent_address_cells * 4]);
        let size_offset = parent_offset + parent_address_cells * 4;
        let size =
            parse_cells_as_u64(&entry[size_offset..size_offset + child_sizes.size_cells * 4]);
        assert!(size != 0, "PCI memory window size must be non-zero");

        windows
            .try_push(PciMemoryWindow {
                pci_base: child_base,
                cpu_base: parent_base,
                size,
                next_free: Cell::new(child_base),
            })
            .unwrap_or_else(|_| panic!("PCI host exposed too many memory windows"));
    }

    assert!(
        !windows.is_empty(),
        "PCI host did not expose any memory-mapped ranges"
    );
    windows
}

fn parse_cells_as_u64(bytes: &[u8]) -> u64 {
    assert!(
        bytes.len().is_multiple_of(4),
        "device-tree cell slice length {} is not a multiple of 4",
        bytes.len()
    );
    match bytes.len() / 4 {
        1 => u64::from(read_be_u32(bytes)),
        2 => (u64::from(read_be_u32(&bytes[..4])) << 32) | u64::from(read_be_u32(&bytes[4..8])),
        cells => panic!("unsupported device-tree cell count {cells}"),
    }
}

fn read_be_u32(bytes: &[u8]) -> u32 {
    let bytes: [u8; 4] = bytes
        .get(..4)
        .unwrap_or_else(|| panic!("expected a 4-byte device-tree cell"))
        .try_into()
        .unwrap_or_else(|_| panic!("expected a 4-byte device-tree cell"));
    u32::from_be_bytes(bytes)
}
