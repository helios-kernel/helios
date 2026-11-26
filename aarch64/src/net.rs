use arm_gic::{IntId, Trigger};
use helios_hal::cpu::Cpu;
use helios_hal::dma::DmaSpaceMark;
use helios_hal::io::IoError;
use helios_hal::watchdog::Watchdog;
use helios_kernel::{
    ExternalInterruptHandler, InterfaceCapabilities, InterfaceEventMark, Kernel, LinkState,
    NetworkDevice,
};
use helios_virtio::{DeviceType, VirtioBusTransport, VirtioNetDevice};
use triomphe::Arc;

use crate::iommu::{self, Aarch64DmaArenas, Aarch64VirtioTransport, Confinement};
use crate::pci::{PciRoot, VirtioFunctions};
use crate::platform::PlatformDescription;

pub(crate) type Aarch64VirtioNetTransport = Aarch64VirtioTransport;
pub(crate) type Aarch64VirtioNetDevice = VirtioNetDevice<Aarch64VirtioNetTransport>;

#[derive(Clone)]
pub(crate) struct VirtioNetworkDevice {
    inner: Arc<Aarch64VirtioNetDevice>,
    /// Held so the interrupt handler can steer by IPI.
    ///
    /// The firmware routes this device's single SPI to one processor, so
    /// every queue pair's completions are noticed there whichever processor
    /// owns them. Waking the owners is the only steering a single-line
    /// transport can do.
    cpu: crate::Aarch64Cpu,
}

impl VirtioNetworkDevice {
    pub(crate) fn device(&self) -> &Arc<Aarch64VirtioNetDevice> {
        &self.inner
    }
}

impl ExternalInterruptHandler for VirtioNetworkDevice {
    fn handle_interrupt(&self) {
        let progress = self.inner.handle_interrupt();
        helios_kernel::wake_queue_owners(
            &self.cpu,
            progress
                .iter()
                .map(|pair| self.inner.queue_pair_owner(pair)),
        );
    }
}

/// The network device the bootstrap processor brought up, together with
/// the interrupt the firmware routes it to.
pub(crate) struct NetworkInterrupt {
    pub(crate) interrupt: IntId,
    pub(crate) trigger: Trigger,
    pub(crate) device: VirtioNetworkDevice,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn install<WatchdogImpl, MeasuredBootImpl>(
    cpu: &crate::Aarch64Cpu,
    kernel: &Kernel<crate::Aarch64Cpu, WatchdogImpl, MeasuredBootImpl>,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
    debug_state: &crate::debug_state::RuntimeState,
) -> Option<NetworkInterrupt>
where
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    let pair_budget = helios_virtio::QueuePairBudget::new(cpu.processor_count());
    let Some(network) = discover_network_device(
        cpu,
        platform,
        pci,
        pci_virtio,
        arenas,
        confinement,
        physical_memory_offset,
        handoff,
        pair_budget,
    ) else {
        tracing::warn!("virtio network device was not discovered on the platform bus");
        return None;
    };
    kernel.install_network_interface(debug_state, network.device.clone());
    tracing::info!(
        pair_budget = pair_budget.get(),
        queue_pairs = network.device.queue_pair_count(),
        "virtio network online interrupt={:?}",
        network.interrupt
    );
    Some(network)
}

pub(crate) fn has_network_device(
    platform: &PlatformDescription,
    pci_virtio: Option<&VirtioFunctions>,
) -> bool {
    pci_virtio.is_some_and(|v| v.count(DeviceType::Network) != 0)
        || crate::count_virtio_mmio_devices(platform, DeviceType::Network) != 0
}

impl NetworkDevice for VirtioNetworkDevice {
    type TxPayload = helios_virtio::TransportBuffer<Aarch64VirtioNetTransport>;

    fn transmit_payload(&self, bytes: usize) -> Result<Self::TxPayload, IoError> {
        self.inner.transmit_payload(bytes)
    }

    fn want_transmit_space(&self) -> DmaSpaceMark {
        self.inner.want_transmit_space()
    }

    fn transmit_space_mark(&self) -> DmaSpaceMark {
        self.inner.transmit_space_mark()
    }

    fn transmit_space_changed(
        &self,
        mark: DmaSpaceMark,
    ) -> impl core::future::Future<Output = ()> + Send + '_ {
        self.inner.transmit_space_changed(mark)
    }

    fn transmit_short_of_space(&self) -> bool {
        self.inner.transmit_short_of_space()
    }

    fn mac_address(&self) -> [u8; 6] {
        self.inner.mac_address()
    }

    fn max_frame_len(&self) -> usize {
        self.inner.max_frame_len()
    }

    fn queue_pair_count(&self) -> usize {
        self.inner.queue_pair_count()
    }

    fn set_active_queue_pairs(&self, pairs: usize) -> helios_hal::io::IoResult<()> {
        self.inner.set_active_queue_pairs(pairs)
    }

    fn steer_queue_pair(&self, pair: usize, processor: helios_hal::cpu::ProcessorId) {
        self.inner.steer_pair(pair, processor);
    }

    fn capabilities(&self) -> InterfaceCapabilities {
        self.inner.interface_capabilities()
    }

    fn link_state(&self) -> LinkState {
        self.inner.link_state()
    }

    fn try_receive_frames_immediate_on<Sink>(
        &self,
        queue_idx: usize,
        budget: usize,
        sink: Sink,
    ) -> Option<helios_virtio::RxDrain>
    where
        Sink: FnMut(&helios_virtio::RxFrame),
    {
        self.inner
            .try_receive_frames_immediate_on_pair(queue_idx, budget, sink)
    }

    fn try_transmit_scatter_immediate_on(
        &self,
        queue_idx: usize,
        frames: &[helios_kernel::TxFrameRef<'_>],
    ) -> Result<Option<usize>, IoError> {
        self.inner
            .try_transmit_scatter_immediate_on_pair(queue_idx, frames)
    }

    fn reclaim_transmit_completions_immediate_on(
        &self,
        queue_idx: usize,
        budget: usize,
    ) -> Result<Option<usize>, IoError> {
        self.inner
            .reclaim_transmit_completions_immediate_on_pair(queue_idx, budget)
    }

    fn event_mark(&self, queue_idx: usize) -> InterfaceEventMark {
        self.inner.interrupt_mark(queue_idx)
    }

    fn wait_for_event_since(
        &self,
        queue_idx: usize,
        mark: InterfaceEventMark,
    ) -> impl core::future::Future<Output = ()> + Send + '_ {
        self.inner.wait_for_interrupt_since(queue_idx, mark)
    }

    fn queue_interrupts(&self, queue_idx: usize) -> u64 {
        self.inner.queue_interrupts(queue_idx)
    }

    fn rx_pool_stalls(&self, queue_idx: usize) -> u64 {
        self.inner.rx_pool_stalls(queue_idx)
    }

    fn rx_pool_free(&self, queue_idx: usize) -> u32 {
        self.inner.rx_pool_free(queue_idx)
    }
}

#[allow(clippy::too_many_arguments)]
fn discover_network_device(
    cpu: &crate::Aarch64Cpu,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
    pair_budget: helios_virtio::QueuePairBudget,
) -> Option<NetworkInterrupt> {
    if let (Some(pci), Some(function)) =
        (pci, pci_virtio.and_then(|v| v.first(DeviceType::Network)))
    {
        pci.assign_unassigned_memory_bars(function.address);
        let dma = iommu::dma_pool(
            arenas,
            confinement,
            Some(function.address),
            physical_memory_offset,
            iommu::LARGE_DMA_CHUNK_BYTES,
            cpu.processor_count(),
        );
        let transport = VirtioBusTransport::pci(&pci.access(), function.address, pci, dma, None)
            .unwrap_or_else(|error| {
                panic!(
                    "failed to initialize virtio-net PCI transport at {}: {error}",
                    function.address
                )
            });
        let device = VirtioNetDevice::new(transport, pair_budget).unwrap_or_else(|error| {
            panic!(
                "failed to initialize virtio-net PCI device at {}: {error}",
                function.address
            )
        });
        return Some(NetworkInterrupt {
            interrupt: function.interrupt,
            trigger: function.trigger,
            device: VirtioNetworkDevice {
                inner: Arc::new(device),
                cpu: *cpu,
            },
        });
    }

    let candidate = crate::virtio_slots(
        platform,
        physical_memory_offset,
        handoff,
        DeviceType::Network,
    )
    .next()?;
    let (interrupt, trigger) = (candidate.interrupt.intid(), candidate.interrupt.trigger);
    let physical_base = candidate.region.base;
    let size = candidate.region.size;
    assert!(size != 0, "AArch64 virtio-net node has zero MMIO size");
    crate::map_mmio_page(physical_base, physical_memory_offset, handoff);
    let virtual_base = crate::mmio_virtual_base(physical_base, physical_memory_offset);
    let header = core::ptr::NonNull::new(virtual_base as *mut u8)
        .unwrap_or_else(|| panic!("virtio MMIO base {virtual_base:#x} was unexpectedly null"));
    let dma = iommu::dma_pool(
        arenas,
        None,
        None,
        physical_memory_offset,
        iommu::LARGE_DMA_CHUNK_BYTES,
        cpu.processor_count(),
    );
    // SAFETY: `header` points to the permanently mapped `size`-byte virtio-net
    // MMIO register block from the platform description, and no other driver
    // accesses this device's registers.
    let transport =
        unsafe { VirtioBusTransport::mmio(header, size, dma) }.unwrap_or_else(|error| {
            panic!("failed to initialize virtio-net MMIO transport at {physical_base:#x}: {error}")
        });
    let device = VirtioNetDevice::new(transport, pair_budget).unwrap_or_else(|error| {
        panic!("failed to initialize virtio-net device at {physical_base:#x}: {error}")
    });
    Some(NetworkInterrupt {
        interrupt,
        trigger,
        device: VirtioNetworkDevice {
            inner: Arc::new(device),
            cpu: *cpu,
        },
    })
}
