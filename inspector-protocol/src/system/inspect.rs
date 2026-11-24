use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use super::bindings::helios::system::filters::FilterError;
pub use super::bindings::helios::system::inspect::{
    ComponentPublication, Entry, MonoNanos, PublicationStatus, Query, SnapshotResult, Value,
};

/// Wire payload for `helios:system/inspect.snapshot`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotRequest {
    pub query: Query,
    pub limit: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryPressure {
    Nominal,
    Elevated,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Processor {
    pub id: u32,
    pub busy: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Processors {
    pub configured: u32,
    pub online: u32,
    pub utilization: Vec<Processor>,
    pub guest_isa_level: String,
    pub guest_isa_extras: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryNode {
    pub id: u32,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub off_node_allocations: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Memory {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub pressure: MemoryPressure,
    pub nodes: Vec<MemoryNode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDevice {
    pub capacity_bytes: u64,
    pub block_bytes: u32,
    pub physical_block_bytes: u32,
    pub flush: bool,
    pub discard: bool,
    pub write_zeroes: bool,
    pub queues: u32,
    pub queue_depth: u32,
    pub reads: u64,
    pub writes: u64,
    pub flushes: u64,
    pub discards: u64,
    pub write_zeroes_requests: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IommuEndpoint {
    pub endpoint: u32,
    pub domain: u32,
    pub mapped_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Iommu {
    pub granule_bytes: u64,
    pub global_bypass: bool,
    pub faults: u64,
    pub endpoints: Vec<IommuEndpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryBalloon {
    pub target_bytes: u64,
    pub actual_bytes: u64,
    pub reported_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Swap {
    pub backend: String,
    pub capacity_bytes: u64,
    pub used_bytes: u64,
    pub pages_out: u64,
    pub pages_in: u64,
    pub faults_served: u64,
    pub mean_fault_latency: MonoNanos,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostShareCache {
    pub attribute_hits: u64,
    pub attribute_misses: u64,
    pub negative_hits: u64,
    pub directory_hits: u64,
    pub directory_misses: u64,
    pub fid_hits: u64,
    pub fid_misses: u64,
    pub evictions: u64,
    pub invalidations: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkQueue {
    pub id: u32,
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub interrupts: u64,
    pub rx_refused_frames: u64,
    pub rx_device_refusals: u64,
    pub tcp_acks_sent: u64,
    pub tcp_window_updates_sent: u64,
    pub tcp_retransmits_sent: u64,
    pub tcp_sockets: u32,
    pub tcp_orphan_sockets: u32,
    pub tcp_orphan_send_queued_bytes: u64,
    pub tcp_orphan_fin_wait_1: u32,
    pub tcp_orphan_fin_wait_2: u32,
    pub tcp_orphan_closing: u32,
    pub tcp_orphan_last_ack: u32,
    pub tcp_orphan_time_wait: u32,
    pub tcp_orphan_other_state: u32,
    pub tcp_orphan_retransmit_armed: u32,
    pub tcp_receive_backpressured_sockets: u32,
    pub tcp_receive_window_bytes: u64,
    pub receive_queued_bytes: u64,
    pub out_of_order_queued_bytes: u64,
    pub peer_retransmits_received: u64,
    pub duplicate_acks_requested: u64,
    pub rx_pool_stalls: u64,
    pub rx_pool_free: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub queues: Vec<NetworkQueue>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantedDevice {
    pub name: String,
    pub region_bytes: u64,
    pub regions: u32,
    pub interrupts: u32,
    pub dma_budget_bytes: u64,
    pub confined: bool,
    pub claimed: bool,
    pub interrupts_forwarded: u64,
    pub interrupts_coalesced: u64,
    pub masked_sources: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputDevice {
    pub name: String,
    pub claimed: bool,
    pub events_delivered: u64,
    pub lost_reports: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AudioStream {
    pub id: u32,
    pub claimed: bool,
    pub played_bytes: u64,
    pub xruns: u64,
    pub lost_feedback: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerMount {
    pub target: String,
    pub kind: String,
    pub sharing: String,
    pub read_only: bool,
    pub overlay_pages: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxContainer {
    pub id: u64,
    pub hostname: String,
    pub domainname: String,
    pub live_processes: u32,
    pub allocated_pids: u32,
    pub live_threads: u32,
    pub overlay_pages: u64,
    pub mounts: Vec<ContainerMount>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HvVm {
    pub id: u64,
    pub vmid: Option<u32>,
    pub owner_instance_id: Option<u64>,
    pub stage2_pages: u64,
    pub stage2_bytes: u64,
    pub allocated_bytes: u64,
    pub memory_limit_bytes: u64,
    pub vcpus: u64,
    pub vcpu_exits_total: u64,
    pub ioevent_registrations: u64,
    pub ioevent_hits: u64,
}

/// Typed projection of the `/kernel/*` subtree returned by `inspect.snapshot`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelSnapshot {
    pub timestamp: MonoNanos,
    pub uptime: MonoNanos,
    pub wall_clock: u64,
    pub processors: Processors,
    pub memory: Memory,
    pub block: Option<BlockDevice>,
    pub iommu: Option<Iommu>,
    pub balloon: Option<MemoryBalloon>,
    pub swap: Option<Swap>,
    pub host_share: Option<HostShareCache>,
    pub network: Option<Network>,
    pub devices: Vec<GrantedDevice>,
    pub inputs: Vec<InputDevice>,
    pub audio: Vec<AudioStream>,
    pub containers: Vec<LinuxContainer>,
    pub hv_vms: Vec<HvVm>,
}

impl KernelSnapshot {
    /// Decodes `/kernel/*` inspect entries into a typed [`KernelSnapshot`].
    pub fn from_snapshot(snapshot: &SnapshotResult) -> Self {
        let map: BTreeMap<&str, &Value> = snapshot
            .entries
            .iter()
            .map(|entry| (entry.path.as_str(), &entry.value))
            .collect();

        let u64_at = |path: &str| match map.get(path) {
            Some(Value::Unsigned64(v)) => Some(*v),
            _ => None,
        };
        let bool_at = |path: &str| match map.get(path) {
            Some(Value::Boolean(v)) => Some(*v),
            _ => None,
        };
        let text_at = |path: &str| match map.get(path) {
            Some(Value::Text(v)) => Some(v.as_str()),
            _ => None,
        };

        let timestamp = u64_at("/kernel/clock/timestamp-nanos").unwrap_or(snapshot.timestamp);
        let uptime = u64_at("/kernel/clock/uptime-nanos").unwrap_or(timestamp);
        let wall_clock = u64_at("/kernel/clock/wall-clock-nanos").unwrap_or(0);

        let configured = u64_at("/kernel/processors/configured").unwrap_or(0) as u32;
        let online = u64_at("/kernel/processors/online").unwrap_or(0) as u32;
        let guest_isa_level = text_at("/kernel/processors/guest-isa-level")
            .unwrap_or_default()
            .to_owned();
        let mut extras: BTreeMap<usize, String> = BTreeMap::new();
        let mut utilization_map: BTreeMap<u32, u16> = BTreeMap::new();
        for (&path, &value) in &map {
            if let Some(rest) = path.strip_prefix("/kernel/processors/guest-isa-extras/") {
                if let (Ok(idx), Value::Text(text)) = (rest.parse::<usize>(), value) {
                    extras.insert(idx, text.clone());
                }
            } else if let Some(rest) = path.strip_prefix("/kernel/processors/")
                && let Some((id_str, field)) = rest.split_once('/')
                && field == "busy-permille"
                && let (Ok(id), Value::Unsigned64(busy)) = (id_str.parse::<u32>(), value)
            {
                utilization_map.insert(id, *busy as u16);
            }
        }
        let processors = Processors {
            configured,
            online,
            utilization: utilization_map
                .into_iter()
                .map(|(id, busy)| Processor { id, busy })
                .collect(),
            guest_isa_level,
            guest_isa_extras: extras.into_values().collect(),
        };

        let memory_pressure = match text_at("/kernel/memory/pressure") {
            Some("elevated") => MemoryPressure::Elevated,
            Some("high") => MemoryPressure::High,
            Some("critical") => MemoryPressure::Critical,
            _ => MemoryPressure::Nominal,
        };
        let mut node_ids: BTreeMap<u32, ()> = BTreeMap::new();
        for &path in map.keys() {
            if let Some(rest) = path.strip_prefix("/kernel/memory/nodes/")
                && let Some((id_str, _)) = rest.split_once('/')
                && let Ok(id) = id_str.parse::<u32>()
            {
                node_ids.insert(id, ());
            }
        }
        let nodes = node_ids
            .into_keys()
            .map(|id| MemoryNode {
                id,
                total_bytes: u64_at(&format!("/kernel/memory/nodes/{id}/total-bytes")).unwrap_or(0),
                available_bytes: u64_at(&format!("/kernel/memory/nodes/{id}/available-bytes"))
                    .unwrap_or(0),
                off_node_allocations: u64_at(&format!(
                    "/kernel/memory/nodes/{id}/off-node-allocations"
                ))
                .unwrap_or(0),
            })
            .collect();
        let memory = Memory {
            total_bytes: u64_at("/kernel/memory/total-bytes").unwrap_or(0),
            available_bytes: u64_at("/kernel/memory/available-bytes").unwrap_or(0),
            pressure: memory_pressure,
            nodes,
        };

        let block = u64_at("/kernel/block/capacity-bytes").map(|capacity_bytes| BlockDevice {
            capacity_bytes,
            block_bytes: u64_at("/kernel/block/block-bytes").unwrap_or(0) as u32,
            physical_block_bytes: u64_at("/kernel/block/physical-block-bytes").unwrap_or(0) as u32,
            flush: bool_at("/kernel/block/flush").unwrap_or(false),
            discard: bool_at("/kernel/block/discard").unwrap_or(false),
            write_zeroes: bool_at("/kernel/block/write-zeroes").unwrap_or(false),
            queues: u64_at("/kernel/block/queues").unwrap_or(0) as u32,
            queue_depth: u64_at("/kernel/block/queue-depth").unwrap_or(0) as u32,
            reads: u64_at("/kernel/block/reads").unwrap_or(0),
            writes: u64_at("/kernel/block/writes").unwrap_or(0),
            flushes: u64_at("/kernel/block/flushes").unwrap_or(0),
            discards: u64_at("/kernel/block/discards").unwrap_or(0),
            write_zeroes_requests: u64_at("/kernel/block/write-zeroes-requests").unwrap_or(0),
        });

        let iommu = u64_at("/kernel/iommu/granule-bytes").map(|granule_bytes| {
            let mut ep_indices: BTreeMap<usize, ()> = BTreeMap::new();
            for &path in map.keys() {
                if let Some(rest) = path.strip_prefix("/kernel/iommu/endpoints/")
                    && let Some((idx_str, _)) = rest.split_once('/')
                    && let Ok(idx) = idx_str.parse::<usize>()
                {
                    ep_indices.insert(idx, ());
                }
            }
            let endpoints = ep_indices
                .into_keys()
                .map(|idx| IommuEndpoint {
                    endpoint: u64_at(&format!("/kernel/iommu/endpoints/{idx}/endpoint"))
                        .unwrap_or(0) as u32,
                    domain: u64_at(&format!("/kernel/iommu/endpoints/{idx}/domain")).unwrap_or(0)
                        as u32,
                    mapped_bytes: u64_at(&format!("/kernel/iommu/endpoints/{idx}/mapped-bytes"))
                        .unwrap_or(0),
                })
                .collect();
            Iommu {
                granule_bytes,
                global_bypass: bool_at("/kernel/iommu/global-bypass").unwrap_or(false),
                faults: u64_at("/kernel/iommu/faults").unwrap_or(0),
                endpoints,
            }
        });

        let balloon = u64_at("/kernel/balloon/target-bytes").map(|target_bytes| MemoryBalloon {
            target_bytes,
            actual_bytes: u64_at("/kernel/balloon/actual-bytes").unwrap_or(0),
            reported_bytes: u64_at("/kernel/balloon/reported-bytes").unwrap_or(0),
        });

        let swap = text_at("/kernel/swap/backend").map(|backend| Swap {
            backend: backend.to_owned(),
            capacity_bytes: u64_at("/kernel/swap/capacity-bytes").unwrap_or(0),
            used_bytes: u64_at("/kernel/swap/used-bytes").unwrap_or(0),
            pages_out: u64_at("/kernel/swap/pages-out").unwrap_or(0),
            pages_in: u64_at("/kernel/swap/pages-in").unwrap_or(0),
            faults_served: u64_at("/kernel/swap/faults-served").unwrap_or(0),
            mean_fault_latency: u64_at("/kernel/swap/mean-fault-latency-nanos").unwrap_or(0),
        });

        let host_share =
            u64_at("/kernel/host-share/attribute-hits").map(|attribute_hits| HostShareCache {
                attribute_hits,
                attribute_misses: u64_at("/kernel/host-share/attribute-misses").unwrap_or(0),
                negative_hits: u64_at("/kernel/host-share/negative-hits").unwrap_or(0),
                directory_hits: u64_at("/kernel/host-share/directory-hits").unwrap_or(0),
                directory_misses: u64_at("/kernel/host-share/directory-misses").unwrap_or(0),
                fid_hits: u64_at("/kernel/host-share/fid-hits").unwrap_or(0),
                fid_misses: u64_at("/kernel/host-share/fid-misses").unwrap_or(0),
                evictions: u64_at("/kernel/host-share/evictions").unwrap_or(0),
                invalidations: u64_at("/kernel/host-share/invalidations").unwrap_or(0),
            });

        let network = u64_at("/kernel/network/queue-count").map(|_| {
            let mut queue_ids: BTreeMap<u32, ()> = BTreeMap::new();
            for &path in map.keys() {
                if let Some(rest) = path.strip_prefix("/kernel/network/queues/")
                    && let Some((id_str, _)) = rest.split_once('/')
                    && let Ok(id) = id_str.parse::<u32>()
                {
                    queue_ids.insert(id, ());
                }
            }
            let queues = queue_ids
                .into_keys()
                .map(|id| {
                    let q = |field: &str| {
                        u64_at(&format!("/kernel/network/queues/{id}/{field}")).unwrap_or(0)
                    };
                    NetworkQueue {
                        id,
                        rx_frames: q("rx-frames"),
                        tx_frames: q("tx-frames"),
                        interrupts: q("interrupts"),
                        rx_refused_frames: q("rx-refused-frames"),
                        rx_device_refusals: q("rx-device-refusals"),
                        tcp_acks_sent: q("tcp-acks-sent"),
                        tcp_window_updates_sent: q("tcp-window-updates-sent"),
                        tcp_retransmits_sent: q("tcp-retransmits-sent"),
                        tcp_sockets: q("tcp-sockets") as u32,
                        tcp_orphan_sockets: q("tcp-orphan-sockets") as u32,
                        tcp_orphan_send_queued_bytes: q("tcp-orphan-send-queued-bytes"),
                        tcp_orphan_fin_wait_1: q("tcp-orphan-fin-wait-1") as u32,
                        tcp_orphan_fin_wait_2: q("tcp-orphan-fin-wait-2") as u32,
                        tcp_orphan_closing: q("tcp-orphan-closing") as u32,
                        tcp_orphan_last_ack: q("tcp-orphan-last-ack") as u32,
                        tcp_orphan_time_wait: q("tcp-orphan-time-wait") as u32,
                        tcp_orphan_other_state: q("tcp-orphan-other-state") as u32,
                        tcp_orphan_retransmit_armed: q("tcp-orphan-retransmit-armed") as u32,
                        tcp_receive_backpressured_sockets: q("tcp-receive-backpressured-sockets")
                            as u32,
                        tcp_receive_window_bytes: q("tcp-receive-window-bytes"),
                        receive_queued_bytes: q("receive-queued-bytes"),
                        out_of_order_queued_bytes: q("out-of-order-queued-bytes"),
                        peer_retransmits_received: q("peer-retransmits-received"),
                        duplicate_acks_requested: q("duplicate-acks-requested"),
                        rx_pool_stalls: q("rx-pool-stalls"),
                        rx_pool_free: q("rx-pool-free") as u32,
                    }
                })
                .collect();
            Network { queues }
        });

        let mut device_indices: BTreeMap<usize, ()> = BTreeMap::new();
        let mut input_indices: BTreeMap<usize, ()> = BTreeMap::new();
        let mut audio_ids: BTreeMap<u32, ()> = BTreeMap::new();
        let mut container_ids: BTreeMap<u64, ()> = BTreeMap::new();
        let mut vm_ids: BTreeMap<u64, ()> = BTreeMap::new();

        for &path in map.keys() {
            if let Some(rest) = path.strip_prefix("/kernel/devices/")
                && let Some((idx_str, _)) = rest.split_once('/')
                && let Ok(idx) = idx_str.parse::<usize>()
            {
                device_indices.insert(idx, ());
            } else if let Some(rest) = path.strip_prefix("/kernel/input/")
                && let Some((idx_str, _)) = rest.split_once('/')
                && let Ok(idx) = idx_str.parse::<usize>()
            {
                input_indices.insert(idx, ());
            } else if let Some(rest) = path.strip_prefix("/kernel/audio/")
                && let Some((id_str, _)) = rest.split_once('/')
                && let Ok(id) = id_str.parse::<u32>()
            {
                audio_ids.insert(id, ());
            } else if let Some(rest) = path.strip_prefix("/kernel/containers/")
                && let Some((id_str, _)) = rest.split_once('/')
                && let Ok(id) = id_str.parse::<u64>()
            {
                container_ids.insert(id, ());
            } else if let Some(rest) = path.strip_prefix("/kernel/hv/")
                && let Some((id_str, _)) = rest.split_once('/')
                && let Ok(id) = id_str.parse::<u64>()
            {
                vm_ids.insert(id, ());
            }
        }

        let devices = device_indices
            .into_keys()
            .map(|idx| GrantedDevice {
                name: text_at(&format!("/kernel/devices/{idx}/name"))
                    .unwrap_or_default()
                    .to_owned(),
                region_bytes: u64_at(&format!("/kernel/devices/{idx}/region-bytes")).unwrap_or(0),
                regions: u64_at(&format!("/kernel/devices/{idx}/regions")).unwrap_or(0) as u32,
                interrupts: u64_at(&format!("/kernel/devices/{idx}/interrupts")).unwrap_or(0)
                    as u32,
                dma_budget_bytes: u64_at(&format!("/kernel/devices/{idx}/dma-budget-bytes"))
                    .unwrap_or(0),
                confined: bool_at(&format!("/kernel/devices/{idx}/confined")).unwrap_or(false),
                claimed: bool_at(&format!("/kernel/devices/{idx}/claimed")).unwrap_or(false),
                interrupts_forwarded: u64_at(&format!(
                    "/kernel/devices/{idx}/interrupts-forwarded"
                ))
                .unwrap_or(0),
                interrupts_coalesced: u64_at(&format!(
                    "/kernel/devices/{idx}/interrupts-coalesced"
                ))
                .unwrap_or(0),
                masked_sources: u64_at(&format!("/kernel/devices/{idx}/masked-sources"))
                    .unwrap_or(0) as u32,
            })
            .collect();

        let inputs = input_indices
            .into_keys()
            .map(|idx| InputDevice {
                name: text_at(&format!("/kernel/input/{idx}/name"))
                    .unwrap_or_default()
                    .to_owned(),
                claimed: bool_at(&format!("/kernel/input/{idx}/claimed")).unwrap_or(false),
                events_delivered: u64_at(&format!("/kernel/input/{idx}/events-delivered"))
                    .unwrap_or(0),
                lost_reports: u64_at(&format!("/kernel/input/{idx}/lost-reports")).unwrap_or(0),
            })
            .collect();

        let audio = audio_ids
            .into_keys()
            .map(|id| AudioStream {
                id,
                claimed: bool_at(&format!("/kernel/audio/{id}/claimed")).unwrap_or(false),
                played_bytes: u64_at(&format!("/kernel/audio/{id}/played-bytes")).unwrap_or(0),
                xruns: u64_at(&format!("/kernel/audio/{id}/xruns")).unwrap_or(0),
                lost_feedback: u64_at(&format!("/kernel/audio/{id}/lost-feedback")).unwrap_or(0),
            })
            .collect();

        let containers = container_ids
            .into_keys()
            .map(|id| {
                let mount_count =
                    u64_at(&format!("/kernel/containers/{id}/mounts/count")).unwrap_or(0) as usize;
                let mounts = (0..mount_count)
                    .map(|m| ContainerMount {
                        target: text_at(&format!("/kernel/containers/{id}/mounts/{m}/target"))
                            .unwrap_or_default()
                            .to_owned(),
                        kind: text_at(&format!("/kernel/containers/{id}/mounts/{m}/kind"))
                            .unwrap_or_default()
                            .to_owned(),
                        sharing: text_at(&format!("/kernel/containers/{id}/mounts/{m}/sharing"))
                            .unwrap_or_default()
                            .to_owned(),
                        read_only: bool_at(&format!(
                            "/kernel/containers/{id}/mounts/{m}/read-only"
                        ))
                        .unwrap_or(false),
                        overlay_pages: u64_at(&format!(
                            "/kernel/containers/{id}/mounts/{m}/overlay-pages"
                        ))
                        .unwrap_or(0),
                    })
                    .collect();
                LinuxContainer {
                    id,
                    hostname: text_at(&format!("/kernel/containers/{id}/uts/hostname"))
                        .unwrap_or_default()
                        .to_owned(),
                    domainname: text_at(&format!("/kernel/containers/{id}/uts/domainname"))
                        .unwrap_or_default()
                        .to_owned(),
                    live_processes: u64_at(&format!("/kernel/containers/{id}/pids/live"))
                        .unwrap_or(0) as u32,
                    allocated_pids: u64_at(&format!("/kernel/containers/{id}/pids/allocated"))
                        .unwrap_or(0) as u32,
                    live_threads: u64_at(&format!("/kernel/containers/{id}/pids/threads"))
                        .unwrap_or(0) as u32,
                    overlay_pages: u64_at(&format!("/kernel/containers/{id}/overlay-pages"))
                        .unwrap_or(0),
                    mounts,
                }
            })
            .collect();

        let hv_vms = vm_ids
            .into_keys()
            .map(|id| HvVm {
                id,
                vmid: u64_at(&format!("/kernel/hv/{id}/vmid")).map(|v| v as u32),
                owner_instance_id: u64_at(&format!("/kernel/hv/{id}/owner-instance-id")),
                stage2_pages: u64_at(&format!("/kernel/hv/{id}/stage2-pages")).unwrap_or(0),
                stage2_bytes: u64_at(&format!("/kernel/hv/{id}/stage2-bytes")).unwrap_or(0),
                allocated_bytes: u64_at(&format!("/kernel/hv/{id}/allocated-bytes")).unwrap_or(0),
                memory_limit_bytes: u64_at(&format!("/kernel/hv/{id}/memory-limit-bytes"))
                    .unwrap_or(0),
                vcpus: u64_at(&format!("/kernel/hv/{id}/vcpus")).unwrap_or(0),
                vcpu_exits_total: u64_at(&format!("/kernel/hv/{id}/vcpu-exits/total")).unwrap_or(0),
                ioevent_registrations: u64_at(&format!("/kernel/hv/{id}/ioevent-registrations"))
                    .unwrap_or(0),
                ioevent_hits: u64_at(&format!("/kernel/hv/{id}/ioevent-hits")).unwrap_or(0),
            })
            .collect();

        Self {
            timestamp,
            uptime,
            wall_clock,
            processors,
            memory,
            block,
            iommu,
            balloon,
            swap,
            host_share,
            network,
            devices,
            inputs,
            audio,
            containers,
            hv_vms,
        }
    }
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::error::{RpcError, TransportError};
    use crate::system::methods::{INSPECT_INSTANCE, INSPECT_SNAPSHOT};
    use crate::transport::Client;
    use futures_io::{AsyncRead, AsyncWrite};

    pub async fn snapshot<R, W>(
        client: &Client<R, W>,
        query: &Query,
        limit: u32,
    ) -> Result<Result<SnapshotResult, FilterError>, RpcError>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let payload = postcard::to_allocvec(&SnapshotRequest {
            query: query.clone(),
            limit,
        })
        .map_err(|source| RpcError::Encode {
            instance: INSPECT_INSTANCE,
            func: INSPECT_SNAPSHOT,
            source,
        })?;
        let bytes = client
            .invoke_raw(INSPECT_INSTANCE, INSPECT_SNAPSHOT, payload)
            .await
            .map_err(|source: TransportError| RpcError::Invoke {
                instance: INSPECT_INSTANCE,
                func: INSPECT_SNAPSHOT,
                source,
            })?;
        postcard::from_bytes(&bytes).map_err(|source| RpcError::Decode {
            instance: INSPECT_INSTANCE,
            func: INSPECT_SNAPSHOT,
            source,
        })
    }

    pub async fn snapshot_prefixes<R, W>(
        client: &Client<R, W>,
        prefixes: &[&str],
        limit: u32,
    ) -> Result<Result<SnapshotResult, FilterError>, RpcError>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let query = Query {
            prefixes: prefixes.iter().map(|prefix| (*prefix).to_owned()).collect(),
        };
        snapshot(client, &query, limit).await
    }
}

#[cfg(feature = "host")]
pub use host::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_snapshot_decodes_core_container_and_hv_subtrees() {
        let raw = SnapshotResult {
            timestamp: 99,
            truncated: false,
            publications: Vec::new(),
            entries: vec![
                Entry {
                    path: "/kernel/clock/uptime-nanos".into(),
                    value: Value::Unsigned64(500),
                },
                Entry {
                    path: "/kernel/processors/configured".into(),
                    value: Value::Unsigned64(2),
                },
                Entry {
                    path: "/kernel/processors/online".into(),
                    value: Value::Unsigned64(2),
                },
                Entry {
                    path: "/kernel/processors/guest-isa-level".into(),
                    value: Value::Text("x86-64-v4".into()),
                },
                Entry {
                    path: "/kernel/processors/guest-isa-extras/0".into(),
                    value: Value::Text("vbmi".into()),
                },
                Entry {
                    path: "/kernel/memory/total-bytes".into(),
                    value: Value::Unsigned64(1 << 30),
                },
                Entry {
                    path: "/kernel/memory/available-bytes".into(),
                    value: Value::Unsigned64(512 << 20),
                },
                Entry {
                    path: "/kernel/memory/pressure".into(),
                    value: Value::Text("elevated".into()),
                },
                Entry {
                    path: "/kernel/containers/3/uts/hostname".into(),
                    value: Value::Text("box".into()),
                },
                Entry {
                    path: "/kernel/containers/3/pids/live".into(),
                    value: Value::Unsigned64(4),
                },
                Entry {
                    path: "/kernel/containers/3/overlay-pages".into(),
                    value: Value::Unsigned64(12),
                },
                Entry {
                    path: "/kernel/hv/1/vmid".into(),
                    value: Value::Unsigned64(7),
                },
                Entry {
                    path: "/kernel/hv/1/stage2-pages".into(),
                    value: Value::Unsigned64(64),
                },
                Entry {
                    path: "/kernel/hv/1/vcpu-exits/total".into(),
                    value: Value::Unsigned64(128),
                },
                Entry {
                    path: "/kernel/hv/1/ioevent-hits".into(),
                    value: Value::Unsigned64(5),
                },
            ],
        };
        let parsed = KernelSnapshot::from_snapshot(&raw);
        assert_eq!(parsed.uptime, 500);
        assert_eq!(parsed.processors.guest_isa_level, "x86-64-v4");
        assert_eq!(parsed.processors.guest_isa_extras, vec!["vbmi"]);
        assert_eq!(parsed.memory.pressure, MemoryPressure::Elevated);
        assert_eq!(parsed.containers.len(), 1);
        assert_eq!(parsed.containers[0].hostname, "box");
        assert_eq!(parsed.containers[0].live_processes, 4);
        assert_eq!(parsed.containers[0].overlay_pages, 12);
        assert_eq!(parsed.hv_vms.len(), 1);
        assert_eq!(parsed.hv_vms[0].vmid, Some(7));
        assert_eq!(parsed.hv_vms[0].stage2_pages, 64);
        assert_eq!(parsed.hv_vms[0].vcpu_exits_total, 128);
        assert_eq!(parsed.hv_vms[0].ioevent_hits, 5);
    }
}
