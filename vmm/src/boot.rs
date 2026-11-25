//! ARM64 Linux boot protocol loader and Flattened Device Tree generator.

use helios_api::hv::{GuestMemory, GuestPhysAddr, GuestRegion, MemoryBackend};
use tracing::info;
use vm_fdt::FdtWriter;

use crate::error::{Error, Result};
use crate::file::WasiFile;

/// Start of guest physical RAM (1 GiB).
pub const RAM_BASE: GuestPhysAddr = GuestPhysAddr::new(0x4000_0000);
/// GICv3 distributor base and size (64 KiB).
pub const GICD: GuestPhysAddr = GuestPhysAddr::new(0x0800_0000);
pub const GICD_SIZE: u64 = 0x1_0000;
/// GICv3 redistributor base and per-CPU stride (128 KiB per vCPU).
pub const GICR: GuestPhysAddr = GuestPhysAddr::new(0x080a_0000);
pub const GICR_STRIDE: u64 = 0x2_0000;
/// PL011 early-console UART base and size (4 KiB).
pub const UART: GuestPhysAddr = GuestPhysAddr::new(0x0900_0000);
pub const UART_SIZE: u64 = 0x1000;
/// First virtio-mmio transport slot base, stride, and INTID.
pub const VIRTIO_MMIO_BASE: GuestPhysAddr = GuestPhysAddr::new(0x0a00_0000);
pub const VIRTIO_MMIO_STRIDE: u64 = 0x1000;
/// First SPI INTID reserved for virtio-mmio devices (SPI 16 = INTID 48).
pub const VIRTIO_FIRST_IRQ: u32 = 48;
/// Maximum virtio-mmio slots fitting GICv3 SPIs 48..=63.
pub const MAX_VIRTIO_SLOTS: usize = 16;

/// Size reserved at the top of RAM for the Linux ARM64 DTB (2 MiB).
pub const DTB_RESERVATION_BYTES: u64 = 2 * 1024 * 1024;

/// Allocated MMIO base and GICv3 INTID for one virtio-mmio transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioSlot {
    pub base: GuestPhysAddr,
    pub irq: u32,
}

impl VirtioSlot {
    pub fn at(index: usize) -> Result<Self> {
        if index >= MAX_VIRTIO_SLOTS {
            return Err(Error::Config(
                "too many virtio-mmio devices for GICv3 SPI table (max 16)",
            ));
        }
        let base = VIRTIO_MMIO_BASE
            .checked_add((index as u64) * VIRTIO_MMIO_STRIDE)
            .ok_or(Error::Config("virtio MMIO address overflow"))?;
        Ok(Self {
            base,
            irq: VIRTIO_FIRST_IRQ + index as u32,
        })
    }
}

/// Parsed ARM64 Linux `Image` header fields (Documentation/arch/arm64/booting.rst).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arm64ImageHeader {
    pub text_offset: u64,
    pub image_size: u64,
    pub flags: u64,
}

impl Arm64ImageHeader {
    pub fn parse(header: &[u8]) -> Result<Self> {
        if header.len() < 64 {
            return Err(Error::Image("ARM64 Image shorter than 64-byte header"));
        }
        if &header[56..60] != b"ARM\x64" {
            return Err(Error::Image("ARM64 Image magic"));
        }
        let field = |offset| u64::from_le_bytes(header[offset..offset + 8].try_into().unwrap());
        let text_offset = field(8);
        let image_size = field(16);
        let flags = field(24);
        if image_size == 0 || flags & 1 != 0 {
            return Err(Error::Image(
                "nonzero image size and little-endian kernel required",
            ));
        }
        Ok(Self {
            text_offset,
            image_size,
            flags,
        })
    }
}

/// Guest physical addresses produced after loading kernel, initramfs, and DTB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootLayout {
    pub entry: GuestPhysAddr,
    pub dtb: GuestPhysAddr,
    pub initrd: Option<(GuestPhysAddr, u64)>,
}

/// Computes non-overlapping placement for kernel, optional initramfs, and DTB.
pub fn plan_layout(
    ram_size: u64,
    header: Arm64ImageHeader,
    kernel_file_size: u64,
    initramfs_size: Option<u64>,
) -> Result<BootLayout> {
    if ram_size < DTB_RESERVATION_BYTES {
        return Err(Error::Config(
            "RAM must contain the 2 MiB DTB placement region",
        ));
    }
    let entry = RAM_BASE
        .checked_add(header.text_offset)
        .ok_or(Error::Image("text offset overflow"))?;
    let kernel_span = header.image_size.max(kernel_file_size);
    let kernel_end = entry
        .checked_add(kernel_span)
        .ok_or(Error::Image("kernel span overflow"))?;
    // The DTB is 8-byte aligned and must not cross a 2 MiB block containing
    // firmware/device attributes (Linux arm64 boot protocol).
    let dtb = RAM_BASE
        .checked_add(ram_size - DTB_RESERVATION_BYTES)
        .ok_or(Error::Image("DTB address overflow"))?;
    let initrd = match initramfs_size {
        Some(size) => {
            let start = dtb
                .raw()
                .checked_sub(size)
                .ok_or(Error::Image("initramfs size exceeds RAM"))?
                & !4095;
            let start = GuestPhysAddr::new(start);
            if start < RAM_BASE || kernel_end > start {
                return Err(Error::Image("kernel/initramfs overlap"));
            }
            Some((start, size))
        }
        None => {
            if kernel_end > dtb {
                return Err(Error::Image("kernel/DTB overlap"));
            }
            None
        }
    };
    Ok(BootLayout { entry, dtb, initrd })
}

/// Loads the ARM64 kernel, optional initramfs, and generated DTB into guest RAM,
/// explicitly publishing every written range for guest instruction/data fetch.
pub async fn load<B: MemoryBackend>(
    kernel_path: &str,
    initramfs_path: Option<&str>,
    cmdline: &str,
    cpus: u32,
    virtio_slots: &[VirtioSlot],
    memory: &GuestRegion<B>,
) -> Result<BootLayout> {
    let kernel = WasiFile::open(kernel_path, false).await?;
    let header_bytes = kernel.read_range(0, 64).await?;
    let header = Arm64ImageHeader::parse(&header_bytes)?;
    let initramfs = match initramfs_path {
        Some(path) => Some(WasiFile::open(path, false).await?),
        None => None,
    };
    let layout = plan_layout(
        memory.size(),
        header,
        kernel.size(),
        initramfs.as_ref().map(WasiFile::size),
    )?;
    memory.validate_range(layout.entry, header.image_size.max(kernel.size()))?;
    let blob = device_tree(cpus, memory.size(), cmdline, layout.initrd, virtio_slots)?;
    if blob.len() as u64 > DTB_RESERVATION_BYTES {
        return Err(Error::Image("DTB exceeds 2 MiB"));
    }
    info!(
        kernel_bytes = kernel.size(),
        initramfs_bytes = initramfs.as_ref().map_or(0, WasiFile::size),
        cpus,
        virtio_devices = virtio_slots.len(),
        "loading guest kernel and device tree"
    );
    kernel.load_into(memory, layout.entry).await?;
    if let (Some(file), Some((addr, _))) = (initramfs, layout.initrd) {
        file.load_into(memory, addr).await?;
    }
    memory.write_slice(layout.dtb, &blob)?;
    memory.publish(layout.dtb, blob.len() as u64)?;
    info!(
        entry = %layout.entry,
        dtb = %layout.dtb,
        cpus,
        "guest boot images loaded and published"
    );
    Ok(layout)
}

/// Serializes an ARM64 Flattened Device Tree describing RAM, CPUs, PSCI 1.0,
/// GICv3, architected timer, PL011 UART, and every configured virtio-mmio slot.
pub fn device_tree(
    cpus: u32,
    ram_size: u64,
    cmdline: &str,
    initrd: Option<(GuestPhysAddr, u64)>,
    virtio_slots: &[VirtioSlot],
) -> Result<Vec<u8>> {
    let mut fdt = FdtWriter::new()?;
    let root = fdt.begin_node("")?;
    fdt.property_string("compatible", "helios,virtual-machine")?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_u32("interrupt-parent", 1)?;

    let chosen = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", cmdline)?;
    fdt.property_string("stdout-path", "/pl011@9000000")?;
    if let Some((start, size)) = initrd {
        fdt.property_u64("linux,initrd-start", start.raw())?;
        fdt.property_u64("linux,initrd-end", start.raw() + size)?;
    }
    fdt.end_node(chosen)?;

    let mem = fdt.begin_node("memory@40000000")?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &[RAM_BASE.raw(), ram_size])?;
    fdt.end_node(mem)?;

    let cpus_node = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", 1)?;
    fdt.property_u32("#size-cells", 0)?;
    for id in 0..cpus {
        let node = fdt.begin_node(&format!("cpu@{id:x}"))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        fdt.property_string("enable-method", "psci")?;
        fdt.property_u32("reg", id)?;
        fdt.end_node(node)?;
    }
    fdt.end_node(cpus_node)?;

    let psci = fdt.begin_node("psci")?;
    fdt.property_string("compatible", "arm,psci-1.0")?;
    fdt.property_string("method", "hvc")?;
    fdt.end_node(psci)?;

    let gic = fdt.begin_node("interrupt-controller@8000000")?;
    fdt.property_string("compatible", "arm,gic-v3")?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_u32("#interrupt-cells", 3)?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_null("ranges")?;
    fdt.property_u32("phandle", 1)?;
    fdt.property_array_u64(
        "reg",
        &[
            GICD.raw(),
            GICD_SIZE,
            GICR.raw(),
            u64::from(cpus) * GICR_STRIDE,
        ],
    )?;
    fdt.end_node(gic)?;

    let timer = fdt.begin_node("timer")?;
    fdt.property_string("compatible", "arm,armv8-timer")?;
    fdt.property_null("always-on")?;
    fdt.property_array_u32("interrupts", &[1, 13, 4, 1, 14, 4, 1, 11, 4, 1, 10, 4])?;
    fdt.end_node(timer)?;

    let clock = fdt.begin_node("clock")?;
    fdt.property_string("compatible", "fixed-clock")?;
    fdt.property_u32("#clock-cells", 0)?;
    // QEMU virt PL011's architectural platform clock, in Hz.
    fdt.property_u32("clock-frequency", 24_000_000)?;
    fdt.property_u32("phandle", 2)?;
    fdt.end_node(clock)?;

    let uart = fdt.begin_node("pl011@9000000")?;
    fdt.property_string("compatible", "arm,pl011")?;
    fdt.property_array_u64("reg", &[UART.raw(), UART_SIZE])?;
    fdt.property_array_u32("interrupts", &[0, 1, 4])?;
    fdt.property_array_u32("clocks", &[2, 2])?;
    fdt.property_string_list("clock-names", vec!["uartclk".into(), "apb_pclk".into()])?;
    fdt.end_node(uart)?;

    for slot in virtio_slots {
        let node = fdt.begin_node(&format!("virtio_mmio@{:x}", slot.base.raw()))?;
        fdt.property_string("compatible", "virtio,mmio")?;
        fdt.property_array_u64("reg", &[slot.base.raw(), VIRTIO_MMIO_STRIDE])?;
        fdt.property_array_u32("interrupts", &[0, slot.irq - 32, 4])?;
        fdt.property_null("dma-coherent")?;
        fdt.end_node(node)?;
    }

    fdt.end_node(root)?;
    Ok(fdt.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_arm64_header(text_offset: u64, image_size: u64, flags: u64) -> [u8; 64] {
        let mut h = [0u8; 64];
        h[8..16].copy_from_slice(&text_offset.to_le_bytes());
        h[16..24].copy_from_slice(&image_size.to_le_bytes());
        h[24..32].copy_from_slice(&flags.to_le_bytes());
        h[56..60].copy_from_slice(b"ARM\x64");
        h
    }

    #[test]
    fn arm64_header_and_layout_support_optional_initramfs_and_multi_virtio_dtb() {
        let header = Arm64ImageHeader::parse(&fake_arm64_header(0x8_0000, 0x40_0000, 0)).unwrap();
        assert_eq!(header.text_offset, 0x8_0000);

        // Reject bad magic or big-endian flags.
        assert!(Arm64ImageHeader::parse(&[0u8; 64]).is_err());
        assert!(Arm64ImageHeader::parse(&fake_arm64_header(0, 0x1000, 1)).is_err());

        // Layout without initramfs (for direct --rootfs-dir boot).
        let layout = plan_layout(64 * 1024 * 1024, header, 0x30_0000, None).unwrap();
        assert_eq!(layout.entry, GuestPhysAddr::new(0x4008_0000));
        assert_eq!(layout.dtb, GuestPhysAddr::new(0x43e0_0000));
        assert!(layout.initrd.is_none());

        // Layout with initramfs.
        let with_rd = plan_layout(64 * 1024 * 1024, header, 0x30_0000, Some(0x12_3456)).unwrap();
        let (rd_addr, rd_size) = with_rd.initrd.unwrap();
        assert!(rd_addr.is_page_aligned());
        assert_eq!(rd_size, 0x12_3456);
        assert!(rd_addr.raw() + rd_size <= with_rd.dtb.raw());

        // DTB emits all virtio slots cleanly.
        let slots: Vec<VirtioSlot> = (0..5).map(|i| VirtioSlot::at(i).unwrap()).collect();
        let dtb = device_tree(
            2,
            64 * 1024 * 1024,
            "root=rootfs rootfstype=virtiofs",
            None,
            &slots,
        )
        .unwrap();
        assert_eq!(&dtb[..4], &[0xd0, 0x0d, 0xfe, 0xed]);
        assert!(VirtioSlot::at(MAX_VIRTIO_SLOTS).is_err());
    }
}
