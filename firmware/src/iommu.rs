//! Platform IOMMU topology readers for ACPI `VIOT` and Devicetree `iommu-map`.
//!
//! Concurrency contract: every parser here reads an immutable firmware
//! table once during single-processor bring-up and returns a plain value
//! holding the discovered PCI translation unit and its endpoint ranges.
//! Nothing is allocated and nothing is shared mutably.

use helios_hal::iommu::EndpointId;
use pci_types::PciAddress;
use thiserror::Error;

#[cfg(feature = "acpi")]
use acpi::sdt::SdtHeader;
#[cfg(feature = "devicetree")]
use fdt::{Fdt, node::FdtNode};

#[cfg(feature = "devicetree")]
use crate::error::NodeName;

/// Maximum PCI requester-id ranges one firmware description may declare.
///
/// QEMU's `virt` machines split `iommu-map` into two ranges around the
/// `virtio-iommu-pci` function's own BDF; eight leaves room for machines
/// with multiple buses or bridges.
pub const MAX_PCI_IOMMU_RANGES: usize = 8;

/// The ACPI `VIOT` table signature.
///
/// The vendored `acpi` crate has no constant for `VIOT` and no public
/// constructor on `Signature`, so callers locate the table by walking
/// `AcpiTables::table_headers()` and comparing `header.signature.as_str()`.
#[cfg(feature = "acpi")]
pub const VIOT_SIGNATURE: &str = "VIOT";

/// `struct acpi_table_viot` field offsets after the common SDT header.
#[cfg(feature = "acpi")]
const VIOT_NODE_COUNT: usize = 0x00;
#[cfg(feature = "acpi")]
const VIOT_NODE_OFFSET: usize = 0x02;
#[cfg(feature = "acpi")]
const VIOT_FIXED_BODY_BYTES: usize = 12;

/// ACPI VIOT node types (ACPI 6.5 §5.2.32 / VIOT specification §3).
#[cfg(feature = "acpi")]
const VIOT_NODE_PCI_RANGE: u8 = 1;
#[cfg(feature = "acpi")]
const VIOT_NODE_VIRTIO_IOMMU_PCI: u8 = 3;

/// `struct acpi_viot_header` field offsets from the start of a node.
#[cfg(feature = "acpi")]
const VIOT_NODE_TYPE: usize = 0x00;
#[cfg(feature = "acpi")]
const VIOT_NODE_LENGTH: usize = 0x02;
#[cfg(feature = "acpi")]
const VIOT_NODE_HEADER_BYTES: usize = 4;

/// `struct acpi_viot_pci_range` field offsets.
#[cfg(feature = "acpi")]
const VIOT_PCI_RANGE_ENDPOINT_START: usize = 0x04;
#[cfg(feature = "acpi")]
const VIOT_PCI_RANGE_SEGMENT_START: usize = 0x08;
#[cfg(feature = "acpi")]
const VIOT_PCI_RANGE_SEGMENT_END: usize = 0x0a;
#[cfg(feature = "acpi")]
const VIOT_PCI_RANGE_BDF_START: usize = 0x0c;
#[cfg(feature = "acpi")]
const VIOT_PCI_RANGE_BDF_END: usize = 0x0e;
#[cfg(feature = "acpi")]
const VIOT_PCI_RANGE_OUTPUT_NODE: usize = 0x10;
#[cfg(feature = "acpi")]
const VIOT_PCI_RANGE_BYTES: usize = 24;

/// `struct acpi_viot_virtio_iommu_pci` field offsets.
#[cfg(feature = "acpi")]
const VIOT_VIRTIO_IOMMU_SEGMENT: usize = 0x04;
#[cfg(feature = "acpi")]
const VIOT_VIRTIO_IOMMU_BDF: usize = 0x06;
#[cfg(feature = "acpi")]
const VIOT_VIRTIO_IOMMU_BYTES: usize = 16;

/// Devicetree compatible string for `virtio-iommu-pci`.
#[cfg(feature = "devicetree")]
const VIRTIO_PCI_IOMMU_COMPATIBLE: &str = "virtio,pci-iommu";

/// Number of 32-bit cells per `iommu-map` entry when `#iommu-cells = <1>`:
/// `(rid-base, iommu-phandle, iommu-base, length)`.
#[cfg(feature = "devicetree")]
const IOMMU_MAP_ENTRY_CELLS: usize = 4;

/// Errors returned when a firmware IOMMU description is malformed or
/// describes a topology Helios does not drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FirmwareIommuError {
    #[error("ACPI VIOT is shorter than its fixed header ({length} bytes)")]
    ViotTruncated { length: usize },
    #[error("ACPI VIOT node array offset {offset:#x} falls outside the {length}-byte table")]
    ViotNodeOffsetOutOfBounds { offset: usize, length: usize },
    #[error("ACPI VIOT node at {offset:#x} runs past the {length}-byte table")]
    ViotNodeOutOfBounds { offset: usize, length: usize },
    #[error("ACPI VIOT node at {offset:#x} declares an unusable length {node_length}")]
    ViotNodeLengthInvalid { offset: usize, node_length: usize },
    #[error("ACPI VIOT virtio-pci node at {offset:#x} is shorter than {expected} bytes ({length})")]
    ViotUnitTooShort {
        offset: usize,
        length: usize,
        expected: usize,
    },
    #[error("ACPI VIOT PCI range node at {offset:#x} is shorter than {expected} bytes ({length})")]
    ViotPciRangeTooShort {
        offset: usize,
        length: usize,
        expected: usize,
    },
    #[error("ACPI VIOT declares more than one virtio-iommu unit")]
    MultipleIommuUnits,
    #[error("ACPI VIOT declares no virtio-iommu unit")]
    MissingIommuUnit,
    #[error("firmware IOMMU topology declares more than {limit} PCI ranges")]
    TooManyPciRanges { limit: usize },
    #[error(
        "ACPI VIOT PCI range points at node offset {output_node:#x}, which is not a valid node"
    )]
    ViotInvalidOutputNode { output_node: usize },
    #[error("ACPI VIOT PCI range translates through unsupported node type {node_type}")]
    ViotUnsupportedOutputNode { node_type: u8 },
    #[error(
        "firmware IOMMU PCI range has inverted bounds (segments {segment_start:#x}..={segment_end:#x}, \
         BDFs {bdf_start:#x}..={bdf_end:#x})"
    )]
    InvalidPciRangeBounds {
        segment_start: u16,
        segment_end: u16,
        bdf_start: u16,
        bdf_end: u16,
    },
    #[error(
        "firmware IOMMU PCI range starting at endpoint {endpoint_start:#x} with {span} functions \
         overflows 32-bit endpoint identifiers"
    )]
    EndpointIdOverflow { endpoint_start: u32, span: u32 },
    #[cfg(feature = "devicetree")]
    #[error("node `{node}`: `iommu-map-mask` is not a single 32-bit cell")]
    IommuMapMaskMalformed { node: NodeName },
    #[cfg(feature = "devicetree")]
    #[error("node `{node}`: `iommu-map` is empty or not a whole number of 4-cell entries")]
    IommuMapMalformed { node: NodeName },
    #[cfg(feature = "devicetree")]
    #[error("node `{node}`: `iommu-map` references unknown phandle {phandle:#x}")]
    IommuPhandleMissing { node: NodeName, phandle: u32 },
    #[cfg(feature = "devicetree")]
    #[error("node `{node}`: `iommu-map` target is not a `virtio,pci-iommu` node")]
    UnsupportedIommuNode { node: NodeName },
    #[cfg(feature = "devicetree")]
    #[error("node `{node}`: `#iommu-cells` must be 1 for `virtio,pci-iommu` (got {cells:?})")]
    UnsupportedIommuCells { node: NodeName, cells: Option<u32> },
    #[cfg(feature = "devicetree")]
    #[error("node `{node}`: `virtio,pci-iommu` `reg` property is missing or shorter than 4 bytes")]
    IommuRegMalformed { node: NodeName },
    #[cfg(feature = "devicetree")]
    #[error(
        "node `{node}`: `iommu-map` entry with rid_base {rid_base:#x} and length {length:#x} \
         is empty or exceeds the 16-bit PCI requester-id space"
    )]
    IommuMapRangeInvalid {
        node: NodeName,
        rid_base: u32,
        length: u32,
    },
}

/// One span of PCI functions and the endpoint identities a translation unit
/// knows them by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciIommuRange {
    endpoint_start: u32,
    segment_start: u16,
    segment_end: u16,
    bdf_start: u16,
    bdf_end: u16,
    rid_mask: u16,
}

impl PciIommuRange {
    /// Returns the endpoint identity for `address` when this range covers it.
    pub fn endpoint_of(&self, address: PciAddress) -> Option<EndpointId> {
        let segment = address.segment();
        let rid = bus_device_function(address) & self.rid_mask;
        if segment < self.segment_start
            || segment > self.segment_end
            || rid < self.bdf_start
            || rid > self.bdf_end
        {
            return None;
        }
        Some(EndpointId::new(
            self.endpoint_start + u32::from(rid - self.bdf_start),
        ))
    }

    pub const fn endpoint_start(&self) -> u32 {
        self.endpoint_start
    }

    pub const fn segment_start(&self) -> u16 {
        self.segment_start
    }

    pub const fn segment_end(&self) -> u16 {
        self.segment_end
    }

    pub const fn bdf_start(&self) -> u16 {
        self.bdf_start
    }

    pub const fn bdf_end(&self) -> u16 {
        self.bdf_end
    }

    pub const fn rid_mask(&self) -> u16 {
        self.rid_mask
    }
}

/// A platform's `virtio-iommu-pci` translation topology as described by
/// ACPI `VIOT` or Devicetree `iommu-map`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioIommuTopology {
    unit: PciAddress,
    ranges: [Option<PciIommuRange>; MAX_PCI_IOMMU_RANGES],
}

impl VirtioIommuTopology {
    /// The PCI function the `virtio-iommu-pci` unit itself sits on.
    pub const fn unit(&self) -> PciAddress {
        self.unit
    }

    /// The endpoint identity the unit knows `address` by, or `None` when
    /// the topology puts that function outside its reach.
    ///
    /// The unit's own function is deliberately excluded: a translation unit
    /// publishes its request and event rings at physical addresses and must
    /// never be attached to one of its own domains.
    pub fn endpoint_of(&self, address: PciAddress) -> Option<EndpointId> {
        if address == self.unit {
            return None;
        }
        self.ranges
            .iter()
            .flatten()
            .find_map(|range| range.endpoint_of(address))
    }

    /// Every PCI requester-id range covered by this topology.
    pub fn ranges(&self) -> impl Iterator<Item = PciIommuRange> + '_ {
        self.ranges.iter().flatten().copied()
    }
}

/// Parses an ACPI `VIOT` table (header included) into a
/// [`VirtioIommuTopology`].
#[cfg(feature = "acpi")]
pub fn parse_viot(table: &[u8]) -> Result<VirtioIommuTopology, FirmwareIommuError> {
    let header_bytes = core::mem::size_of::<SdtHeader>();
    if table.len() < header_bytes + VIOT_FIXED_BODY_BYTES {
        return Err(FirmwareIommuError::ViotTruncated {
            length: table.len(),
        });
    }
    let body = &table[header_bytes..];
    let node_count = usize::from(read_le_u16(body, VIOT_NODE_COUNT));
    let node_offset = usize::from(read_le_u16(body, VIOT_NODE_OFFSET));
    if node_offset < header_bytes || node_offset > table.len() {
        return Err(FirmwareIommuError::ViotNodeOffsetOutOfBounds {
            offset: node_offset,
            length: table.len(),
        });
    }

    let mut unit = None;
    let mut ranges = [const { None }; MAX_PCI_IOMMU_RANGES];
    let mut found_ranges = 0;
    let mut offset = node_offset;

    for _ in 0..node_count {
        if offset + VIOT_NODE_HEADER_BYTES > table.len() {
            return Err(FirmwareIommuError::ViotNodeOutOfBounds {
                offset,
                length: table.len(),
            });
        }
        let node_type = table[offset + VIOT_NODE_TYPE];
        let length = usize::from(read_le_u16(table, offset + VIOT_NODE_LENGTH));
        if length < VIOT_NODE_HEADER_BYTES || offset + length > table.len() {
            return Err(FirmwareIommuError::ViotNodeLengthInvalid {
                offset,
                node_length: length,
            });
        }
        let node = &table[offset..offset + length];
        match node_type {
            VIOT_NODE_VIRTIO_IOMMU_PCI => {
                if length < VIOT_VIRTIO_IOMMU_BYTES {
                    return Err(FirmwareIommuError::ViotUnitTooShort {
                        offset,
                        length,
                        expected: VIOT_VIRTIO_IOMMU_BYTES,
                    });
                }
                let segment = read_le_u16(node, VIOT_VIRTIO_IOMMU_SEGMENT);
                let bdf = read_le_u16(node, VIOT_VIRTIO_IOMMU_BDF);
                if unit.replace(pci_address(segment, bdf)).is_some() {
                    return Err(FirmwareIommuError::MultipleIommuUnits);
                }
            }
            VIOT_NODE_PCI_RANGE => {
                if length < VIOT_PCI_RANGE_BYTES {
                    return Err(FirmwareIommuError::ViotPciRangeTooShort {
                        offset,
                        length,
                        expected: VIOT_PCI_RANGE_BYTES,
                    });
                }
                if found_ranges >= MAX_PCI_IOMMU_RANGES {
                    return Err(FirmwareIommuError::TooManyPciRanges {
                        limit: MAX_PCI_IOMMU_RANGES,
                    });
                }
                let output_node = usize::from(read_le_u16(node, VIOT_PCI_RANGE_OUTPUT_NODE));
                if output_node < node_offset || output_node + VIOT_NODE_HEADER_BYTES > table.len() {
                    return Err(FirmwareIommuError::ViotInvalidOutputNode { output_node });
                }
                let target_type = table[output_node + VIOT_NODE_TYPE];
                if target_type != VIOT_NODE_VIRTIO_IOMMU_PCI {
                    return Err(FirmwareIommuError::ViotUnsupportedOutputNode {
                        node_type: target_type,
                    });
                }
                let endpoint_start = read_le_u32(node, VIOT_PCI_RANGE_ENDPOINT_START);
                let segment_start = read_le_u16(node, VIOT_PCI_RANGE_SEGMENT_START);
                let segment_end = read_le_u16(node, VIOT_PCI_RANGE_SEGMENT_END);
                let bdf_start = read_le_u16(node, VIOT_PCI_RANGE_BDF_START);
                let bdf_end = read_le_u16(node, VIOT_PCI_RANGE_BDF_END);
                if segment_start > segment_end || bdf_start > bdf_end {
                    return Err(FirmwareIommuError::InvalidPciRangeBounds {
                        segment_start,
                        segment_end,
                        bdf_start,
                        bdf_end,
                    });
                }
                let span = u32::from(bdf_end - bdf_start);
                if endpoint_start.checked_add(span).is_none() {
                    return Err(FirmwareIommuError::EndpointIdOverflow {
                        endpoint_start,
                        span,
                    });
                }
                ranges[found_ranges] = Some(PciIommuRange {
                    endpoint_start,
                    segment_start,
                    segment_end,
                    bdf_start,
                    bdf_end,
                    rid_mask: u16::MAX,
                });
                found_ranges += 1;
            }
            _ => {}
        }
        offset += length;
    }

    Ok(VirtioIommuTopology {
        unit: unit.ok_or(FirmwareIommuError::MissingIommuUnit)?,
        ranges,
    })
}

/// Parses a PCI host bridge's Devicetree `iommu-map` (and optional
/// `iommu-map-mask`) property into a [`VirtioIommuTopology`].
///
/// Returns `Ok(None)` when the PCI host node carries no `iommu-map`
/// property.
#[cfg(feature = "devicetree")]
pub fn parse_devicetree_pci_iommu(
    fdt: &Fdt<'_>,
    pci_node: &FdtNode<'_, '_>,
    segment: u16,
) -> Result<Option<VirtioIommuTopology>, FirmwareIommuError> {
    let Some(map_prop) = pci_node.property("iommu-map") else {
        return Ok(None);
    };
    let node_name = NodeName::new(pci_node.name);

    let rid_mask = match pci_node.property("iommu-map-mask") {
        None => u16::MAX,
        Some(mask_prop) => {
            let bytes = mask_prop.value;
            if bytes.len() != 4 {
                return Err(FirmwareIommuError::IommuMapMaskMalformed { node: node_name });
            }
            (u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & 0xffff) as u16
        }
    };

    let bytes = map_prop.value;
    let entry_bytes = IOMMU_MAP_ENTRY_CELLS * 4;
    if bytes.is_empty() || !bytes.len().is_multiple_of(entry_bytes) {
        return Err(FirmwareIommuError::IommuMapMalformed { node: node_name });
    }

    let mut unit: Option<PciAddress> = None;
    let mut ranges = [const { None }; MAX_PCI_IOMMU_RANGES];

    for (found_ranges, chunk) in bytes.chunks_exact(entry_bytes).enumerate() {
        if found_ranges >= MAX_PCI_IOMMU_RANGES {
            return Err(FirmwareIommuError::TooManyPciRanges {
                limit: MAX_PCI_IOMMU_RANGES,
            });
        }
        let rid_base = read_be_u32(chunk, 0);
        let phandle = read_be_u32(chunk, 4);
        let iommu_base = read_be_u32(chunk, 8);
        let length = read_be_u32(chunk, 12);

        let target = fdt
            .find_phandle(phandle)
            .ok_or(FirmwareIommuError::IommuPhandleMissing {
                node: node_name,
                phandle,
            })?;
        let target_name = NodeName::new(target.name);
        let is_virtio_iommu = target
            .compatible()
            .is_some_and(|compat| compat.all().any(|item| item == VIRTIO_PCI_IOMMU_COMPATIBLE));
        if !is_virtio_iommu {
            return Err(FirmwareIommuError::UnsupportedIommuNode { node: target_name });
        }

        let iommu_cells = target.property("#iommu-cells").and_then(|prop| {
            let value = prop.value;
            (value.len() == 4).then(|| read_be_u32(value, 0))
        });
        if iommu_cells != Some(1) {
            return Err(FirmwareIommuError::UnsupportedIommuCells {
                node: target_name,
                cells: iommu_cells,
            });
        }

        // A PCI child node's `reg` starts with `phys.hi`, whose bits [23:8]
        // carry the 16-bit bus/device/function address (IEEE 1275 PCI binding).
        let Some(reg_bytes) = target.property("reg").map(|prop| prop.value) else {
            return Err(FirmwareIommuError::IommuRegMalformed { node: target_name });
        };
        if reg_bytes.len() < 4 {
            return Err(FirmwareIommuError::IommuRegMalformed { node: target_name });
        }
        let phys_hi = read_be_u32(reg_bytes, 0);
        let unit_bdf = ((phys_hi >> 8) & 0xffff) as u16;
        let unit_address = pci_address(segment, unit_bdf);
        match unit {
            None => unit = Some(unit_address),
            Some(existing) if existing == unit_address => {}
            Some(_) => return Err(FirmwareIommuError::MultipleIommuUnits),
        }

        let Some(last_rid) = length
            .checked_sub(1)
            .and_then(|delta| rid_base.checked_add(delta))
        else {
            return Err(FirmwareIommuError::IommuMapRangeInvalid {
                node: node_name,
                rid_base,
                length,
            });
        };
        let (Ok(bdf_start), Ok(bdf_end)) = (u16::try_from(rid_base), u16::try_from(last_rid))
        else {
            return Err(FirmwareIommuError::IommuMapRangeInvalid {
                node: node_name,
                rid_base,
                length,
            });
        };
        let span = u32::from(bdf_end - bdf_start);
        if iommu_base.checked_add(span).is_none() {
            return Err(FirmwareIommuError::EndpointIdOverflow {
                endpoint_start: iommu_base,
                span,
            });
        }

        ranges[found_ranges] = Some(PciIommuRange {
            endpoint_start: iommu_base,
            segment_start: segment,
            segment_end: segment,
            bdf_start,
            bdf_end,
            rid_mask,
        });
    }

    Ok(Some(VirtioIommuTopology {
        unit: unit.ok_or(FirmwareIommuError::MissingIommuUnit)?,
        ranges,
    }))
}

fn bus_device_function(address: PciAddress) -> u16 {
    (u16::from(address.bus()) << 8)
        | (u16::from(address.device()) << 3)
        | u16::from(address.function())
}

#[cfg(any(feature = "acpi", feature = "devicetree"))]
fn pci_address(segment: u16, bdf: u16) -> PciAddress {
    PciAddress::new(
        segment,
        (bdf >> 8) as u8,
        ((bdf >> 3) & 0x1f) as u8,
        (bdf & 0x7) as u8,
    )
}

#[cfg(feature = "acpi")]
fn read_le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

#[cfg(feature = "acpi")]
fn read_le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(feature = "devicetree")]
fn read_be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
