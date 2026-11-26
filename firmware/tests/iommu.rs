//! Unit tests for ACPI `VIOT` and Devicetree `iommu-map` topology parsing.

use helios_hal::iommu::EndpointId;
use pci_types::PciAddress;

#[cfg(feature = "acpi")]
mod acpi_viot {
    use super::{EndpointId, PciAddress};
    use helios_firmware::{FirmwareIommuError, MAX_PCI_IOMMU_RANGES, parse_viot};

    const SDT_HEADER_BYTES: usize = 36;
    const VIOT_BODY_BYTES: usize = 12;
    const NODE_PCI_RANGE: u8 = 1;
    const NODE_VIRTIO_IOMMU_PCI: u8 = 3;

    fn viot_header(node_count: u16, node_offset: u16, total_length: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; SDT_HEADER_BYTES + VIOT_BODY_BYTES];
        bytes[0..4].copy_from_slice(b"VIOT");
        bytes[4..8].copy_from_slice(&total_length.to_le_bytes());
        bytes[SDT_HEADER_BYTES..SDT_HEADER_BYTES + 2].copy_from_slice(&node_count.to_le_bytes());
        bytes[SDT_HEADER_BYTES + 2..SDT_HEADER_BYTES + 4]
            .copy_from_slice(&node_offset.to_le_bytes());
        bytes
    }

    fn virtio_iommu_pci_node(segment: u16, bdf: u16) -> Vec<u8> {
        let mut node = vec![0u8; 16];
        node[0] = NODE_VIRTIO_IOMMU_PCI;
        node[2..4].copy_from_slice(&16u16.to_le_bytes());
        node[4..6].copy_from_slice(&segment.to_le_bytes());
        node[6..8].copy_from_slice(&bdf.to_le_bytes());
        node
    }

    fn pci_range_node(
        endpoint_start: u32,
        segment_start: u16,
        segment_end: u16,
        bdf_start: u16,
        bdf_end: u16,
        output_node: u16,
    ) -> Vec<u8> {
        let mut node = vec![0u8; 24];
        node[0] = NODE_PCI_RANGE;
        node[2..4].copy_from_slice(&24u16.to_le_bytes());
        node[4..8].copy_from_slice(&endpoint_start.to_le_bytes());
        node[8..10].copy_from_slice(&segment_start.to_le_bytes());
        node[10..12].copy_from_slice(&segment_end.to_le_bytes());
        node[12..14].copy_from_slice(&bdf_start.to_le_bytes());
        node[14..16].copy_from_slice(&bdf_end.to_le_bytes());
        node[16..18].copy_from_slice(&output_node.to_le_bytes());
        node
    }

    fn build_viot(nodes: &[Vec<u8>]) -> Vec<u8> {
        let node_offset = (SDT_HEADER_BYTES + VIOT_BODY_BYTES) as u16;
        let payload_len: usize = nodes.iter().map(Vec::len).sum();
        let total_len = usize::from(node_offset) + payload_len;
        let mut table = viot_header(nodes.len() as u16, node_offset, total_len as u32);
        for node in nodes {
            table.extend_from_slice(node);
        }
        table
    }

    #[test]
    fn parses_single_range_viot_and_excludes_unit_itself() {
        let unit_offset = (SDT_HEADER_BYTES + VIOT_BODY_BYTES) as u16;
        // Unit at 0000:00:01.0 (BDF 0x0008), range covers 0x0000..=0xffff.
        let table = build_viot(&[
            virtio_iommu_pci_node(0, 0x0008),
            pci_range_node(0, 0, 0, 0x0000, 0xffff, unit_offset),
        ]);

        let topology = parse_viot(&table).expect("valid VIOT");
        assert_eq!(topology.unit(), PciAddress::new(0, 0, 1, 0));
        assert_eq!(
            topology.endpoint_of(PciAddress::new(0, 0, 1, 0)),
            None,
            "the translation unit itself must never be confined"
        );
        assert_eq!(
            topology.endpoint_of(PciAddress::new(0, 0, 2, 0)),
            Some(EndpointId::new(0x0010))
        );
        assert_eq!(
            topology.endpoint_of(PciAddress::new(0, 1, 3, 2)),
            Some(EndpointId::new((1 << 8) | (3 << 3) | 2))
        );
        assert_eq!(topology.endpoint_of(PciAddress::new(1, 0, 2, 0)), None);
    }

    #[test]
    fn parses_multi_range_viot_with_nonzero_endpoint_base_and_segment() {
        let unit_offset = (SDT_HEADER_BYTES + VIOT_BODY_BYTES) as u16;
        let table = build_viot(&[
            virtio_iommu_pci_node(2, 0x0010),
            pci_range_node(0x100, 2, 2, 0x0000, 0x000f, unit_offset),
            pci_range_node(0x200, 2, 2, 0x0011, 0x00ff, unit_offset),
        ]);

        let topology = parse_viot(&table).expect("valid multi-range VIOT");
        assert_eq!(topology.unit(), PciAddress::new(2, 0, 2, 0));
        assert_eq!(
            topology.endpoint_of(PciAddress::new(2, 0, 1, 0)),
            Some(EndpointId::new(0x108))
        );
        assert_eq!(topology.endpoint_of(PciAddress::new(2, 0, 2, 0)), None);
        assert_eq!(
            topology.endpoint_of(PciAddress::new(2, 0, 3, 0)),
            Some(EndpointId::new(0x200 + (0x18 - 0x11)))
        );
        assert_eq!(topology.ranges().count(), 2);
    }

    #[test]
    fn rejects_malformed_viot_tables() {
        assert_eq!(
            parse_viot(&[0u8; 16]),
            Err(FirmwareIommuError::ViotTruncated { length: 16 })
        );

        let missing_unit = build_viot(&[]);
        assert_eq!(
            parse_viot(&missing_unit),
            Err(FirmwareIommuError::MissingIommuUnit)
        );

        let two_units = build_viot(&[
            virtio_iommu_pci_node(0, 0x0008),
            virtio_iommu_pci_node(0, 0x0010),
        ]);
        assert_eq!(
            parse_viot(&two_units),
            Err(FirmwareIommuError::MultipleIommuUnits)
        );

        let unit_offset = (SDT_HEADER_BYTES + VIOT_BODY_BYTES) as u16;
        let bad_bounds = build_viot(&[
            virtio_iommu_pci_node(0, 0x0008),
            pci_range_node(0, 0, 0, 0x0020, 0x0010, unit_offset),
        ]);
        assert_eq!(
            parse_viot(&bad_bounds),
            Err(FirmwareIommuError::InvalidPciRangeBounds {
                segment_start: 0,
                segment_end: 0,
                bdf_start: 0x0020,
                bdf_end: 0x0010,
            })
        );

        let bad_output = build_viot(&[
            virtio_iommu_pci_node(0, 0x0008),
            pci_range_node(0, 0, 0, 0, 0xff, 0x0004),
        ]);
        assert_eq!(
            parse_viot(&bad_output),
            Err(FirmwareIommuError::ViotInvalidOutputNode {
                output_node: 0x0004
            })
        );

        let mut too_many = vec![virtio_iommu_pci_node(0, 0x0008)];
        for index in 0..=MAX_PCI_IOMMU_RANGES {
            let start = (index as u16) * 0x10;
            too_many.push(pci_range_node(
                u32::from(start),
                0,
                0,
                start,
                start + 0x07,
                unit_offset,
            ));
        }
        assert_eq!(
            parse_viot(&build_viot(&too_many)),
            Err(FirmwareIommuError::TooManyPciRanges {
                limit: MAX_PCI_IOMMU_RANGES,
            })
        );
    }
}

#[cfg(feature = "devicetree")]
mod devicetree_iommu {
    use super::{EndpointId, PciAddress};
    use fdt::Fdt;
    use helios_firmware::{FirmwareIommuError, parse_devicetree_pci_iommu};

    const FDT_BEGIN_NODE: u32 = 1;
    const FDT_END_NODE: u32 = 2;
    const FDT_PROP: u32 = 3;
    const FDT_END: u32 = 9;

    struct Node {
        name: String,
        props: Vec<(String, Vec<u8>)>,
        children: Vec<Node>,
    }

    fn node(name: &str) -> Node {
        Node {
            name: name.to_owned(),
            props: Vec::new(),
            children: Vec::new(),
        }
    }

    impl Node {
        fn prop(mut self, name: &str, value: Vec<u8>) -> Self {
            self.props.push((name.to_owned(), value));
            self
        }

        fn cells(self, name: &str, cells: &[u32]) -> Self {
            let bytes = cells.iter().flat_map(|cell| cell.to_be_bytes()).collect();
            self.prop(name, bytes)
        }

        fn string(self, name: &str, value: &str) -> Self {
            let mut bytes = value.as_bytes().to_vec();
            bytes.push(0);
            self.prop(name, bytes)
        }

        fn child(mut self, child: Node) -> Self {
            self.children.push(child);
            self
        }
    }

    fn pad4(bytes: &mut Vec<u8>) {
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn emit(node: &Node, structure: &mut Vec<u8>, strings: &mut Vec<u8>) {
        push_u32(structure, FDT_BEGIN_NODE);
        structure.extend_from_slice(node.name.as_bytes());
        structure.push(0);
        pad4(structure);
        for (name, value) in &node.props {
            let needle = [name.as_bytes(), &[0]].concat();
            let offset = strings
                .windows(needle.len())
                .position(|window| window == needle)
                .filter(|&at| at == 0 || strings[at - 1] == 0)
                .unwrap_or_else(|| {
                    let at = strings.len();
                    strings.extend_from_slice(&needle);
                    at
                });
            push_u32(structure, FDT_PROP);
            push_u32(structure, value.len() as u32);
            push_u32(structure, offset as u32);
            structure.extend_from_slice(value);
            pad4(structure);
        }
        for child in &node.children {
            emit(child, structure, strings);
        }
        push_u32(structure, FDT_END_NODE);
    }

    fn blob(root: &Node) -> Vec<u8> {
        const HEADER: u32 = 40;
        const RESERVATIONS: u32 = 16;
        let mut structure = Vec::new();
        let mut strings = Vec::new();
        emit(root, &mut structure, &mut strings);
        push_u32(&mut structure, FDT_END);
        let off_struct = HEADER + RESERVATIONS;
        let off_strings = off_struct + structure.len() as u32;
        let total = off_strings + strings.len() as u32;
        let mut out = Vec::new();
        for word in [
            0xd00d_feed,
            total,
            off_struct,
            off_strings,
            HEADER,
            17,
            16,
            0,
            strings.len() as u32,
            structure.len() as u32,
        ] {
            push_u32(&mut out, word);
        }
        out.extend_from_slice(&[0; RESERVATIONS as usize]);
        out.extend_from_slice(&structure);
        out.extend_from_slice(&strings);
        out
    }

    #[test]
    fn absent_iommu_map_returns_none() {
        let dtb = blob(
            &node("").child(node("pcie@10000000").string("compatible", "pci-host-ecam-generic")),
        );
        let fdt = Fdt::new(&dtb).expect("valid FDT");
        let pci = fdt.find_node("/pcie@10000000").expect("pci node");

        assert_eq!(parse_devicetree_pci_iommu(&fdt, &pci, 0), Ok(None));
    }

    #[test]
    fn parses_qemu_split_iommu_map_around_virtio_iommu_bdf() {
        // QEMU places virtio-iommu-pci at 00:01.0 (BDF 0x0008, phys.hi = 0x0800)
        // and splits iommu-map into [0x0..0x8) and [0x9..0x10000).
        let iommu_child = node("virtio_iommu@8")
            .string("compatible", "virtio,pci-iommu")
            .cells("reg", &[0x0000_0800, 0, 0, 0, 0])
            .cells("#iommu-cells", &[1])
            .cells("phandle", &[0x8002]);
        let pci_node = node("pcie@10000000")
            .string("compatible", "pci-host-ecam-generic")
            .cells(
                "iommu-map",
                &[
                    0x0000, 0x8002, 0x0000, 0x0008, // BDFs 0x0000..=0x0007
                    0x0009, 0x8002, 0x0009, 0xfff7, // BDFs 0x0009..=0xffff
                ],
            )
            .child(iommu_child);
        let dtb = blob(&node("").child(pci_node));
        let fdt = Fdt::new(&dtb).expect("valid FDT");
        let pci = fdt.find_node("/pcie@10000000").expect("pci node");

        let topology = parse_devicetree_pci_iommu(&fdt, &pci, 0)
            .expect("valid iommu-map")
            .expect("topology present");

        assert_eq!(topology.unit(), PciAddress::new(0, 0, 1, 0));
        assert_eq!(
            topology.endpoint_of(PciAddress::new(0, 0, 1, 0)),
            None,
            "the IOMMU's own BDF is excluded"
        );
        assert_eq!(
            topology.endpoint_of(PciAddress::new(0, 0, 0, 0)),
            Some(EndpointId::new(0x0000))
        );
        assert_eq!(
            topology.endpoint_of(PciAddress::new(0, 0, 2, 0)),
            Some(EndpointId::new(0x0010))
        );
        assert_eq!(
            topology.endpoint_of(PciAddress::new(0, 0xff, 31, 7)),
            Some(EndpointId::new(0xffff))
        );
    }

    #[test]
    fn honors_iommu_map_mask_and_full_64k_length() {
        let iommu_child = node("virtio_iommu@8")
            .string("compatible", "virtio,pci-iommu")
            .cells("reg", &[0x0000_0800, 0, 0, 0, 0])
            .cells("#iommu-cells", &[1])
            .cells("phandle", &[7]);
        // Mask off the function bits (0xfff8) so every function of a device shares
        // the device's base requester ID.
        let pci_node = node("pcie@10000000")
            .string("compatible", "pci-host-ecam-generic")
            .cells("iommu-map", &[0x0000, 7, 0x0000, 0x1_0000])
            .cells("iommu-map-mask", &[0xfff8])
            .child(iommu_child);
        let dtb = blob(&node("").child(pci_node));
        let fdt = Fdt::new(&dtb).expect("valid FDT");
        let pci = fdt.find_node("/pcie@10000000").expect("pci node");

        let topology = parse_devicetree_pci_iommu(&fdt, &pci, 0)
            .expect("valid masked iommu-map")
            .expect("topology present");

        assert_eq!(topology.endpoint_of(PciAddress::new(0, 0, 1, 0)), None);
        assert_eq!(
            topology.endpoint_of(PciAddress::new(0, 0, 2, 3)),
            Some(EndpointId::new(0x0010))
        );
    }

    #[test]
    fn rejects_malformed_devicetree_iommu_maps() {
        let bad_stride = blob(
            &node("").child(
                node("pcie@10000000")
                    .string("compatible", "pci-host-ecam-generic")
                    .cells("iommu-map", &[0, 1, 0]),
            ),
        );
        let fdt = Fdt::new(&bad_stride).expect("valid FDT");
        let pci = fdt.find_node("/pcie@10000000").expect("pci node");
        assert!(matches!(
            parse_devicetree_pci_iommu(&fdt, &pci, 0),
            Err(FirmwareIommuError::IommuMapMalformed { .. })
        ));

        let missing_phandle = blob(
            &node("").child(
                node("pcie@10000000")
                    .string("compatible", "pci-host-ecam-generic")
                    .cells("iommu-map", &[0, 0x9999, 0, 0x10]),
            ),
        );
        let fdt = Fdt::new(&missing_phandle).expect("valid FDT");
        let pci = fdt.find_node("/pcie@10000000").expect("pci node");
        assert!(matches!(
            parse_devicetree_pci_iommu(&fdt, &pci, 0),
            Err(FirmwareIommuError::IommuPhandleMissing {
                phandle: 0x9999,
                ..
            })
        ));

        let wrong_compat = blob(
            &node("").child(
                node("pcie@10000000")
                    .string("compatible", "pci-host-ecam-generic")
                    .cells("iommu-map", &[0, 1, 0, 0x10])
                    .child(
                        node("smmu@9050000")
                            .string("compatible", "arm,smmu-v3")
                            .cells("#iommu-cells", &[1])
                            .cells("phandle", &[1]),
                    ),
            ),
        );
        let fdt = Fdt::new(&wrong_compat).expect("valid FDT");
        let pci = fdt.find_node("/pcie@10000000").expect("pci node");
        assert!(matches!(
            parse_devicetree_pci_iommu(&fdt, &pci, 0),
            Err(FirmwareIommuError::UnsupportedIommuNode { .. })
        ));

        let bad_cells = blob(
            &node("").child(
                node("pcie@10000000")
                    .string("compatible", "pci-host-ecam-generic")
                    .cells("iommu-map", &[0, 1, 0, 0x10])
                    .child(
                        node("virtio_iommu@8")
                            .string("compatible", "virtio,pci-iommu")
                            .cells("reg", &[0x0800, 0, 0, 0, 0])
                            .cells("#iommu-cells", &[2])
                            .cells("phandle", &[1]),
                    ),
            ),
        );
        let fdt = Fdt::new(&bad_cells).expect("valid FDT");
        let pci = fdt.find_node("/pcie@10000000").expect("pci node");
        assert!(matches!(
            parse_devicetree_pci_iommu(&fdt, &pci, 0),
            Err(FirmwareIommuError::UnsupportedIommuCells { cells: Some(2), .. })
        ));
    }
}
