//! Kernel subsystem telemetry published under `/kernel/*`.
//!
//! Each subsystem subtree is pruned against the caller's [`PrefixSet`] before
//! allocating paths so targeted queries such as `["/kernel/memory"]` or
//! `["/kernel/hv"]` touch only the requested subsystem.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::PrefixSet;

use super::{InspectEntry, InspectValue};

/// Raw kernel telemetry collected across all kernel subsystems for `/kernel/*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelTelemetrySnapshot {
    pub timestamp: u64,
    pub uptime: u64,
    pub wall_clock: u64,
    pub configured_processors: u32,
    pub online_processors: u32,
    pub guest_isa_level: &'static str,
    pub guest_isa_extras: Vec<&'static str>,
    pub memory_total_bytes: u64,
    pub memory_available_bytes: u64,
    pub memory_nodes: Vec<crate::MemoryNodeStats>,
    pub block: Option<crate::BlockStats>,
    pub iommu: Option<crate::IommuStats>,
    pub balloon: Option<crate::memory::BalloonStats>,
    pub swap: Option<crate::memory::SwapStats>,
    pub host_share: Option<crate::HostFsCacheStats>,
    pub network: Option<crate::NetworkStats>,
    pub devices: Vec<crate::GrantedDeviceSnapshot>,
    pub inputs: Vec<crate::InputDeviceSnapshot>,
    pub audio: Vec<crate::AudioStreamSnapshot>,
    #[cfg(feature = "linux")]
    pub containers: Vec<crate::LinuxContainerSnapshot>,
    pub hv_vms: Vec<crate::hv::HvVmSnapshot>,
}

fn memory_pressure_label(total_bytes: u64, available_bytes: u64) -> &'static str {
    if total_bytes == 0 {
        return "nominal";
    }
    let used_permille =
        ((total_bytes.saturating_sub(available_bytes.min(total_bytes))) * 1_000) / total_bytes;
    match used_permille {
        0..=699 => "nominal",
        700..=849 => "elevated",
        850..=949 => "high",
        _ => "critical",
    }
}

fn push_if_admitted(
    prefixes: &PrefixSet,
    out: &mut Vec<InspectEntry>,
    path: String,
    value: InspectValue,
) {
    if prefixes.admits(&path) {
        out.push(InspectEntry { path, value });
    }
}

/// Emits every `/kernel/*` entry in `snapshot` matching `prefixes`.
pub fn emit_kernel_entries(
    snapshot: &KernelTelemetrySnapshot,
    prefixes: &PrefixSet,
    out: &mut Vec<InspectEntry>,
) {
    if !prefixes.may_match_subtree("/kernel") {
        return;
    }

    if prefixes.may_match_subtree("/kernel/clock") {
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/clock/timestamp-nanos"),
            InspectValue::Unsigned64(snapshot.timestamp),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/clock/uptime-nanos"),
            InspectValue::Unsigned64(snapshot.uptime),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/clock/wall-clock-nanos"),
            InspectValue::Unsigned64(snapshot.wall_clock),
        );
    }

    if prefixes.may_match_subtree("/kernel/processors") {
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/processors/configured"),
            InspectValue::Unsigned64(u64::from(snapshot.configured_processors)),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/processors/online"),
            InspectValue::Unsigned64(u64::from(snapshot.online_processors)),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/processors/guest-isa-level"),
            InspectValue::Text(String::from(snapshot.guest_isa_level)),
        );
        for (index, extra) in snapshot.guest_isa_extras.iter().enumerate() {
            push_if_admitted(
                prefixes,
                out,
                format!("/kernel/processors/guest-isa-extras/{index}"),
                InspectValue::Text(String::from(*extra)),
            );
        }
        for id in 0..snapshot.configured_processors {
            push_if_admitted(
                prefixes,
                out,
                format!("/kernel/processors/{id}/busy-permille"),
                InspectValue::Unsigned64(0),
            );
        }
    }

    if prefixes.may_match_subtree("/kernel/memory") {
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/memory/total-bytes"),
            InspectValue::Unsigned64(snapshot.memory_total_bytes),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/memory/available-bytes"),
            InspectValue::Unsigned64(snapshot.memory_available_bytes),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/memory/pressure"),
            InspectValue::Text(String::from(memory_pressure_label(
                snapshot.memory_total_bytes,
                snapshot.memory_available_bytes,
            ))),
        );
        for node in &snapshot.memory_nodes {
            let id = node.node.index();
            push_if_admitted(
                prefixes,
                out,
                format!("/kernel/memory/nodes/{id}/total-bytes"),
                InspectValue::Unsigned64(node.total_bytes as u64),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("/kernel/memory/nodes/{id}/available-bytes"),
                InspectValue::Unsigned64(node.available_bytes as u64),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("/kernel/memory/nodes/{id}/off-node-allocations"),
                InspectValue::Unsigned64(node.off_node_allocations),
            );
        }
    }

    if let Some(block) = &snapshot.block
        && prefixes.may_match_subtree("/kernel/block")
    {
        let capabilities =
            helios_hal::fs::BlockDeviceCapabilities::from_bits_truncate(block.capabilities);
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/capacity-bytes"),
            InspectValue::Unsigned64(block.capacity_bytes),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/block-bytes"),
            InspectValue::Unsigned64(u64::from(block.block_bytes)),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/physical-block-bytes"),
            InspectValue::Unsigned64(u64::from(block.physical_block_bytes)),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/flush"),
            InspectValue::Boolean(
                capabilities.contains(helios_hal::fs::BlockDeviceCapabilities::FLUSH),
            ),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/discard"),
            InspectValue::Boolean(
                capabilities.contains(helios_hal::fs::BlockDeviceCapabilities::DISCARD),
            ),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/write-zeroes"),
            InspectValue::Boolean(
                capabilities.contains(helios_hal::fs::BlockDeviceCapabilities::WRITE_ZEROES),
            ),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/queues"),
            InspectValue::Unsigned64(u64::from(block.queues)),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/queue-depth"),
            InspectValue::Unsigned64(u64::from(block.queue_depth)),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/reads"),
            InspectValue::Unsigned64(block.reads),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/writes"),
            InspectValue::Unsigned64(block.writes),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/flushes"),
            InspectValue::Unsigned64(block.flushes),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/discards"),
            InspectValue::Unsigned64(block.discards),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/block/write-zeroes-requests"),
            InspectValue::Unsigned64(block.write_zeroes),
        );
    }

    if let Some(iommu) = &snapshot.iommu
        && prefixes.may_match_subtree("/kernel/iommu")
    {
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/iommu/granule-bytes"),
            InspectValue::Unsigned64(iommu.granule_bytes),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/iommu/global-bypass"),
            InspectValue::Boolean(iommu.global_bypass),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/iommu/faults"),
            InspectValue::Unsigned64(iommu.faults),
        );
        for (index, endpoint) in iommu.endpoints().iter().enumerate() {
            push_if_admitted(
                prefixes,
                out,
                format!("/kernel/iommu/endpoints/{index}/endpoint"),
                InspectValue::Unsigned64(u64::from(endpoint.endpoint)),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("/kernel/iommu/endpoints/{index}/domain"),
                InspectValue::Unsigned64(u64::from(endpoint.domain)),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("/kernel/iommu/endpoints/{index}/mapped-bytes"),
                InspectValue::Unsigned64(endpoint.mapped_bytes),
            );
        }
    }

    if let Some(balloon) = &snapshot.balloon
        && prefixes.may_match_subtree("/kernel/balloon")
    {
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/balloon/target-bytes"),
            InspectValue::Unsigned64(balloon.target_bytes),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/balloon/actual-bytes"),
            InspectValue::Unsigned64(balloon.actual_bytes),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/balloon/reported-bytes"),
            InspectValue::Unsigned64(balloon.reported_bytes),
        );
    }

    if let Some(swap) = &snapshot.swap
        && prefixes.may_match_subtree("/kernel/swap")
    {
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/swap/backend"),
            InspectValue::Text(String::from(swap.backend)),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/swap/capacity-bytes"),
            InspectValue::Unsigned64(swap.capacity_bytes),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/swap/used-bytes"),
            InspectValue::Unsigned64(swap.used_bytes),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/swap/pages-out"),
            InspectValue::Unsigned64(swap.pages_out),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/swap/pages-in"),
            InspectValue::Unsigned64(swap.pages_in),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/swap/faults-served"),
            InspectValue::Unsigned64(swap.faults_served),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/swap/mean-fault-latency-nanos"),
            InspectValue::Unsigned64(swap.mean_fault_latency_nanos),
        );
    }

    if let Some(cache) = &snapshot.host_share
        && prefixes.may_match_subtree("/kernel/host-share")
    {
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/host-share/attribute-hits"),
            InspectValue::Unsigned64(cache.attribute_hits),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/host-share/attribute-misses"),
            InspectValue::Unsigned64(cache.attribute_misses),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/host-share/negative-hits"),
            InspectValue::Unsigned64(cache.negative_hits),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/host-share/directory-hits"),
            InspectValue::Unsigned64(cache.directory_hits),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/host-share/directory-misses"),
            InspectValue::Unsigned64(cache.directory_misses),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/host-share/fid-hits"),
            InspectValue::Unsigned64(cache.fid_hits),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/host-share/fid-misses"),
            InspectValue::Unsigned64(cache.fid_misses),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/host-share/evictions"),
            InspectValue::Unsigned64(cache.evictions),
        );
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/host-share/invalidations"),
            InspectValue::Unsigned64(cache.invalidations),
        );
    }

    if let Some(network) = &snapshot.network
        && prefixes.may_match_subtree("/kernel/network")
    {
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/network/queue-count"),
            InspectValue::Unsigned64(network.queues.len() as u64),
        );
        for queue in &network.queues {
            let id = queue.id;
            let base = format!("/kernel/network/queues/{id}");
            if !prefixes.may_match_subtree(&base) {
                continue;
            }
            let pairs: [(&str, u64); 26] = [
                ("rx-frames", queue.rx_frames),
                ("tx-frames", queue.tx_frames),
                ("interrupts", queue.interrupts),
                ("rx-refused-frames", queue.rx_refused_frames),
                ("rx-device-refusals", queue.rx_device_refusals),
                ("tcp-acks-sent", queue.tcp_acks_sent),
                ("tcp-window-updates-sent", queue.tcp_window_updates_sent),
                ("tcp-retransmits-sent", queue.tcp_retransmits_sent),
                ("tcp-sockets", u64::from(queue.tcp_sockets)),
                ("tcp-orphan-sockets", u64::from(queue.tcp_orphan_sockets)),
                (
                    "tcp-orphan-send-queued-bytes",
                    queue.tcp_orphan_send_queued_bytes,
                ),
                (
                    "tcp-orphan-fin-wait-1",
                    u64::from(queue.tcp_orphan_fin_wait_1),
                ),
                (
                    "tcp-orphan-fin-wait-2",
                    u64::from(queue.tcp_orphan_fin_wait_2),
                ),
                ("tcp-orphan-closing", u64::from(queue.tcp_orphan_closing)),
                ("tcp-orphan-last-ack", u64::from(queue.tcp_orphan_last_ack)),
                (
                    "tcp-orphan-time-wait",
                    u64::from(queue.tcp_orphan_time_wait),
                ),
                (
                    "tcp-orphan-other-state",
                    u64::from(queue.tcp_orphan_other_state),
                ),
                (
                    "tcp-orphan-retransmit-armed",
                    u64::from(queue.tcp_orphan_retransmit_armed),
                ),
                (
                    "tcp-receive-backpressured-sockets",
                    u64::from(queue.tcp_receive_backpressured_sockets),
                ),
                ("tcp-receive-window-bytes", queue.tcp_receive_window_bytes),
                ("receive-queued-bytes", queue.receive_queued_bytes),
                ("out-of-order-queued-bytes", queue.out_of_order_queued_bytes),
                ("peer-retransmits-received", queue.peer_retransmits_received),
                ("duplicate-acks-requested", queue.duplicate_acks_requested),
                ("rx-pool-stalls", queue.rx_pool_stalls),
                ("rx-pool-free", u64::from(queue.rx_pool_free)),
            ];
            for (field, value) in pairs {
                push_if_admitted(
                    prefixes,
                    out,
                    format!("{base}/{field}"),
                    InspectValue::Unsigned64(value),
                );
            }
        }
    }

    if !snapshot.devices.is_empty() && prefixes.may_match_subtree("/kernel/devices") {
        for (index, device) in snapshot.devices.iter().enumerate() {
            let base = format!("/kernel/devices/{index}");
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/name"),
                InspectValue::Text(String::from(device.name.as_str())),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/region-bytes"),
                InspectValue::Unsigned64(device.region_bytes),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/regions"),
                InspectValue::Unsigned64(u64::from(device.regions)),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/interrupts"),
                InspectValue::Unsigned64(u64::from(device.interrupt_count)),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/dma-budget-bytes"),
                InspectValue::Unsigned64(device.dma_budget_bytes),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/confined"),
                InspectValue::Boolean(device.confined),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/claimed"),
                InspectValue::Boolean(device.claimed),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/interrupts-forwarded"),
                InspectValue::Unsigned64(device.interrupts_forwarded),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/interrupts-coalesced"),
                InspectValue::Unsigned64(device.interrupts_coalesced),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/masked-sources"),
                InspectValue::Unsigned64(u64::from(device.masked_sources)),
            );
        }
    }

    if !snapshot.inputs.is_empty() && prefixes.may_match_subtree("/kernel/input") {
        for (index, device) in snapshot.inputs.iter().enumerate() {
            let base = format!("/kernel/input/{index}");
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/name"),
                InspectValue::Text(device.name.clone()),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/claimed"),
                InspectValue::Boolean(device.claimed),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/events-delivered"),
                InspectValue::Unsigned64(device.events_delivered),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/lost-reports"),
                InspectValue::Unsigned64(device.lost_reports),
            );
        }
    }

    if !snapshot.audio.is_empty() && prefixes.may_match_subtree("/kernel/audio") {
        for stream in &snapshot.audio {
            let base = format!("/kernel/audio/{}", stream.id);
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/id"),
                InspectValue::Unsigned64(u64::from(stream.id)),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/claimed"),
                InspectValue::Boolean(stream.claimed),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/played-bytes"),
                InspectValue::Unsigned64(stream.played_bytes),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/xruns"),
                InspectValue::Unsigned64(stream.xruns),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/lost-feedback"),
                InspectValue::Unsigned64(stream.lost_feedback),
            );
        }
    }

    #[cfg(feature = "linux")]
    if prefixes.may_match_subtree("/kernel/containers") {
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/containers/count"),
            InspectValue::Unsigned64(snapshot.containers.len() as u64),
        );
        for container in &snapshot.containers {
            let base = format!("/kernel/containers/{}", container.id);
            if !prefixes.may_match_subtree(&base) {
                continue;
            }
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/uts/hostname"),
                InspectValue::Text(container.hostname.clone()),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/uts/domainname"),
                InspectValue::Text(container.domainname.clone()),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/pids/live"),
                InspectValue::Unsigned64(u64::from(container.live_processes)),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/pids/allocated"),
                InspectValue::Unsigned64(u64::from(container.allocated_pids)),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/pids/threads"),
                InspectValue::Unsigned64(u64::from(container.live_threads)),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/overlay-pages"),
                InspectValue::Unsigned64(container.overlay_pages),
            );
            push_if_admitted(
                prefixes,
                out,
                format!("{base}/mounts/count"),
                InspectValue::Unsigned64(container.mounts.len() as u64),
            );
            for (index, mount) in container.mounts.iter().enumerate() {
                let mbase = format!("{base}/mounts/{index}");
                push_if_admitted(
                    prefixes,
                    out,
                    format!("{mbase}/target"),
                    InspectValue::Text(mount.target.clone()),
                );
                push_if_admitted(
                    prefixes,
                    out,
                    format!("{mbase}/kind"),
                    InspectValue::Text(String::from(mount.kind)),
                );
                push_if_admitted(
                    prefixes,
                    out,
                    format!("{mbase}/sharing"),
                    InspectValue::Text(String::from(mount.sharing)),
                );
                push_if_admitted(
                    prefixes,
                    out,
                    format!("{mbase}/read-only"),
                    InspectValue::Boolean(mount.read_only),
                );
                push_if_admitted(
                    prefixes,
                    out,
                    format!("{mbase}/overlay-pages"),
                    InspectValue::Unsigned64(mount.overlay_pages),
                );
            }
        }
    }

    if prefixes.may_match_subtree("/kernel/hv") {
        push_if_admitted(
            prefixes,
            out,
            String::from("/kernel/hv/vm-count"),
            InspectValue::Unsigned64(snapshot.hv_vms.len() as u64),
        );
        for vm in &snapshot.hv_vms {
            let base = format!("/kernel/hv/{}", vm.id);
            if !prefixes.may_match_subtree(&base) {
                continue;
            }
            if let Some(vmid) = vm.vmid {
                push_if_admitted(
                    prefixes,
                    out,
                    format!("{base}/vmid"),
                    InspectValue::Unsigned64(u64::from(vmid)),
                );
            }
            if let Some(owner) = vm.owner_instance {
                push_if_admitted(
                    prefixes,
                    out,
                    format!("{base}/owner-instance-id"),
                    InspectValue::Unsigned64(owner.raw()),
                );
            }
            let counters: [(&str, u64); 18] = [
                ("stage2-pages", vm.stage2_pages),
                ("stage2-bytes", vm.stage2_bytes),
                ("allocated-bytes", vm.allocated_bytes),
                ("memory-limit-bytes", vm.memory_limit_bytes),
                ("vcpus", vm.vcpus),
                ("vcpu-exits/total", vm.vcpu_exits_total),
                ("vcpu-exits/preempted", vm.vcpu_exits_preempted),
                ("vcpu-exits/halt", vm.vcpu_exits_halt),
                ("vcpu-exits/irq-window", vm.vcpu_exits_irq_window),
                ("vcpu-exits/mmio", vm.vcpu_exits_mmio),
                ("vcpu-exits/io-port", vm.vcpu_exits_io_port),
                ("vcpu-exits/stage2-fault", vm.vcpu_exits_stage2_fault),
                ("vcpu-exits/sysreg", vm.vcpu_exits_sysreg),
                ("vcpu-exits/msr", vm.vcpu_exits_msr),
                ("vcpu-exits/hypercall", vm.vcpu_exits_hypercall),
                ("vcpu-exits/shutdown", vm.vcpu_exits_shutdown),
                ("ioevent-registrations", vm.ioevent_registrations),
                ("ioevent-hits", vm.ioevent_hits),
            ];
            for (field, value) in counters {
                push_if_admitted(
                    prefixes,
                    out,
                    format!("{base}/{field}"),
                    InspectValue::Unsigned64(value),
                );
            }
        }
    }
}
