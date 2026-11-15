use crate::memory::GuestMemory;
use crate::{
    Config, Error, Result,
    file::File,
    memory::{Memory, RAM_BASE},
};
use vm_fdt::FdtWriter;

pub const GICD: u64 = 0x0800_0000;
pub const GICR: u64 = 0x080a_0000;
pub const UART: u64 = 0x0900_0000;
pub const CONSOLE: u64 = 0x0a00_0000;
pub const BLOCK: u64 = 0x0a00_1000;
pub const CONSOLE_IRQ: u32 = 48;
pub const BLOCK_IRQ: u32 = 49;

pub struct Boot {
    pub entry: u64,
    pub dtb: u64,
}

pub async fn load(config: &Config, memory: &Memory) -> Result<Boot> {
    let kernel = File::open(&config.kernel, false).await?;
    let header = kernel.read(0, 64).await?;
    if &header[56..60] != b"ARM\x64" {
        return Err(Error::Image("ARM64 Image magic"));
    }
    let field = |offset| u64::from_le_bytes(header[offset..offset + 8].try_into().unwrap());
    let text_offset = field(8);
    let image_size = field(16);
    if image_size == 0 || field(24) & 1 != 0 {
        return Err(Error::Image(
            "nonzero image size and little-endian kernel required",
        ));
    }
    let entry = RAM_BASE
        .checked_add(text_offset)
        .ok_or(Error::Image("text offset overflow"))?;
    memory.offset(entry, image_size.max(kernel.size))?;
    let initramfs = File::open(&config.initramfs, false).await?;
    // The DTB is 8-byte aligned and must not cross a 2 MiB block containing
    // firmware/device attributes (Linux arm64 boot protocol).
    let dtb = RAM_BASE + memory.size - 2 * 1024 * 1024;
    let initrd = dtb
        .checked_sub(initramfs.size)
        .ok_or(Error::Image("initramfs size"))?
        & !4095;
    if entry + image_size.max(kernel.size) > initrd {
        return Err(Error::Image("kernel/initramfs overlap"));
    }
    let blob = device_tree(config, memory.size, initrd, initramfs.size)?;
    if blob.len() > 2 * 1024 * 1024 {
        return Err(Error::Image("DTB exceeds 2 MiB"));
    }
    println!(
        "vmm: loading kernel {} bytes and initramfs {} bytes",
        kernel.size, initramfs.size
    );
    kernel.load(memory, entry).await?;
    initramfs.load(memory, initrd).await?;
    memory.write(dtb, &blob)?;
    memory.publish(dtb, blob.len() as u64)?;
    println!(
        "vmm: kernel={entry:#x} initrd={initrd:#x}+{:#x} dtb={dtb:#x} cpus={}",
        initramfs.size, config.cpus
    );
    Ok(Boot { entry, dtb })
}

fn device_tree(config: &Config, size: u64, initrd: u64, initrd_size: u64) -> Result<Vec<u8>> {
    let mut fdt = FdtWriter::new()?;
    let root = fdt.begin_node("")?;
    fdt.property_string("compatible", "helios,virtual-machine")?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_u32("interrupt-parent", 1)?;
    let chosen = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", &config.cmdline)?;
    fdt.property_string("stdout-path", "/pl011@9000000")?;
    fdt.property_u64("linux,initrd-start", initrd)?;
    fdt.property_u64("linux,initrd-end", initrd + initrd_size)?;
    fdt.end_node(chosen)?;
    let mem = fdt.begin_node("memory@40000000")?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &[RAM_BASE, size])?;
    fdt.end_node(mem)?;
    let cpus = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", 1)?;
    fdt.property_u32("#size-cells", 0)?;
    for id in 0..config.cpus {
        let node = fdt.begin_node(&format!("cpu@{id:x}"))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        fdt.property_string("enable-method", "psci")?;
        fdt.property_u32("reg", id)?;
        fdt.end_node(node)?;
    }
    fdt.end_node(cpus)?;
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
        &[GICD, 0x10000, GICR, u64::from(config.cpus) * 0x20000],
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
    fdt.property_array_u64("reg", &[UART, 0x1000])?;
    fdt.property_array_u32("interrupts", &[0, 1, 4])?;
    fdt.property_array_u32("clocks", &[2, 2])?;
    fdt.property_string_list("clock-names", vec!["uartclk".into(), "apb_pclk".into()])?;
    fdt.end_node(uart)?;
    for (address, irq) in [(CONSOLE, CONSOLE_IRQ), (BLOCK, BLOCK_IRQ)]
        .into_iter()
        .take(if config.disk.is_some() { 2 } else { 1 })
    {
        let node = fdt.begin_node(&format!("virtio_mmio@{address:x}"))?;
        fdt.property_string("compatible", "virtio,mmio")?;
        fdt.property_array_u64("reg", &[address, 0x1000])?;
        fdt.property_array_u32("interrupts", &[0, irq - 32, 4])?;
        fdt.property_null("dma-coherent")?;
        fdt.end_node(node)?;
    }
    fdt.end_node(root)?;
    Ok(fdt.finish()?)
}
