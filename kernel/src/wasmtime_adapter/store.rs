//! Wasmtime trait implementations for `ComponentStoreData`.
//!
//! These trait impls bridge kernel-owned store state to Wasmtime's runtime
//! requirements. They live in the adapter module so that `component_runtime.rs`
//! stays free of Wasmtime imports.

extern crate alloc;

use helios_hal::cpu::Cpu;
use wasmtime::ResourceLimiter;
use wasmtime::component::ResourceTableLimiter;

use crate::process::ComponentHandleLimitSetting;
use crate::wasmtime_adapter::component_host::{HostRuntimeState, StoreData, deliver_kill};
use crate::{
    ComponentHostNetwork, InstanceRegistry, KernelHeapHeadroom, MemoryPool, OomKillOutcome,
    ProgramOutOfMemory, RegisteredInstance, Storage, UserResidency, allow_instance_resource_growth,
    heap_stats, monotonic_nanos, user_heap_stats,
};

impl<CpuImpl, Net, StorageImpl> ResourceLimiter for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: Storage,
{
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if maximum.is_some_and(|maximum| desired > maximum) {
            return Err(ProgramOutOfMemory {
                requested_bytes: desired,
                available_bytes: 0,
                pool_bytes: 0,
                reserved_bytes: 0,
            }
            .into());
        }

        let growth = desired.saturating_sub(current);

        if let Some(error) = self.try_satisfy_or_kill(desired, growth) {
            return Err(error);
        }

        Ok(allow_instance_resource_growth(
            self.instance(),
            desired,
            maximum,
        ))
    }

    fn memory_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        Err(error)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(maximum.is_none_or(|maximum| desired <= maximum))
    }
}

impl<CpuImpl, Net, StorageImpl> StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: Storage,
{
    /// Decide whether `growth` extra bytes of user memory can be granted.
    ///
    /// Two pools have to answer, and they are asked for different
    /// amounts. The user pool is asked for the growth itself: that is
    /// where the guest's pages come from. The kernel heap is asked only
    /// for what the growth costs *it* — the page tables and reservation
    /// records that address the new pages
    /// ([`crate::user_mapping_kernel_heap_bytes`]), around a
    /// five-hundredth of the growth. Charging the growth itself against
    /// the kernel heap, as this did, refused grows the kernel heap was
    /// never asked to fund.
    ///
    /// On insufficient user heap or kernel reserve breach, the OOM
    /// killer is asked to mark the largest non-self victim *of the pool
    /// that ran out* for termination, and its stores are interrupted, so
    /// that instance traps with [`crate::InstanceKilled`] at its next
    /// interrupt check and frees its memory. The growing request itself still returns
    /// `ProgramOutOfMemory` — reclamation happens asynchronously and the
    /// requester retries on the next allocation attempt or surfaces the
    /// error to its caller.
    fn try_satisfy_or_kill(&self, desired: usize, growth: usize) -> Option<wasmtime::Error> {
        let user_heap = user_heap_stats();
        let user_available = user_heap.available_bytes();
        if user_available < growth {
            self.request_oom_kill_for_growth(MemoryPool::User, growth);
            return Some(
                ProgramOutOfMemory {
                    requested_bytes: desired,
                    available_bytes: user_available,
                    pool_bytes: user_heap.total_bytes,
                    reserved_bytes: 0,
                }
                .into(),
            );
        }

        let heap = heap_stats();
        let headroom = KernelHeapHeadroom::of(heap, user_available);
        if let Some(shortfall) = headroom.growth_shortfall_bytes(growth) {
            self.request_oom_kill_for_growth(MemoryPool::Kernel, shortfall);
            // Every number in this refusal describes the kernel side
            // of the grow, including the request: reporting the guest's
            // `desired` here alongside kernel-heap availability is what
            // made a refusal on this branch read as a user-pool
            // refusal. Availability spans both domains because the
            // kernel heap funds itself out of the user pool, so this
            // branch fires only when the machine itself is out.
            return Some(
                ProgramOutOfMemory {
                    requested_bytes: shortfall,
                    available_bytes: headroom.available_bytes,
                    pool_bytes: heap.total_bytes.saturating_add(user_heap.total_bytes),
                    reserved_bytes: headroom.reserve_bytes,
                }
                .into(),
            );
        }

        None
    }

    /// Configures this store's component [`wasmtime::component::ResourceTable`]
    /// with the operator handle limit (`process.max-component-handles`) and a
    /// per-store [`ResourceTableLimiter`] that attributes table backing storage
    /// and boxed entries to this instance's kernel-heap footprint and refuses
    /// allocations that would breach [`KernelHeapHeadroom`].
    pub(crate) fn configure_resource_table(&mut self) {
        let max_handles = self
            .runtime_state
            .settings()
            .get::<ComponentHandleLimitSetting>();
        self.table.set_max_capacity(max_handles);
        let limiter = StoreResourceTableLimiter {
            runtime_state: self.runtime_state.clone(),
            instance_registry: self.instance_registry.clone(),
            instance: self.instance().clone(),
            cpu: self.cpu.clone(),
        };
        self.table.set_limiter(limiter);
    }

    /// Ask the OOM killer to cover `requested_bytes` of `pool`.
    ///
    /// The killer answers against its condemned-memory ledger, so a
    /// shortfall that an in-flight kill already covers condemns nothing
    /// further: `memory_growing` is a synchronous Wasmtime callback and
    /// cannot wait for the reclaim, so the requester takes its typed
    /// `ProgramOutOfMemory` failure either way and retries when the
    /// guest next asks for the memory. Logged at warn level so
    /// post-mortem analysis can trace which instance was sacrificed for
    /// which grow request, and which requests were absorbed by a kill
    /// that had already happened.
    fn request_oom_kill_for_growth(&self, pool: MemoryPool, requested_bytes: usize) {
        request_oom_kill_for_pool(
            &self.runtime_state,
            &self.instance_registry,
            self.instance(),
            &self.cpu,
            pool,
            requested_bytes,
        );
    }
}

/// Charges every byte owned by a store's [`wasmtime::component::ResourceTable`]
/// (slot array and boxed entries) to the owning [`RegisteredInstance`] and
/// refuses allocations that would breach the kernel-heap reserve.
struct StoreResourceTableLimiter<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: Storage,
{
    runtime_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    instance_registry: InstanceRegistry,
    instance: RegisteredInstance,
    cpu: CpuImpl,
}

impl<CpuImpl, Net, StorageImpl> StoreResourceTableLimiter<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: Storage,
{
    fn try_charge_with_headroom(&mut self, bytes: usize, headroom: KernelHeapHeadroom) -> bool {
        if let Some(shortfall) = headroom.allocation_shortfall_bytes(bytes) {
            request_oom_kill_for_pool(
                &self.runtime_state,
                &self.instance_registry,
                &self.instance,
                &self.cpu,
                MemoryPool::Kernel,
                shortfall,
            );
            return false;
        }
        self.instance.add_kernel_heap_bytes(bytes as u64);
        true
    }
}

impl<CpuImpl, Net, StorageImpl> ResourceTableLimiter
    for StoreResourceTableLimiter<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone + Send + 'static,
    Net: ComponentHostNetwork + 'static,
    StorageImpl: Storage + 'static,
{
    fn try_charge(&mut self, bytes: usize) -> bool {
        let heap = heap_stats();
        let user_available = crate::memory::user_pool_available_bytes();
        if heap.total_bytes > 0 || user_available > 0 {
            let headroom = KernelHeapHeadroom::of(heap, user_available);
            return self.try_charge_with_headroom(bytes, headroom);
        }
        self.instance.add_kernel_heap_bytes(bytes as u64);
        true
    }

    fn release(&mut self, bytes: usize) {
        self.instance.sub_kernel_heap_bytes(bytes as u64);
    }
}

fn request_oom_kill_for_pool<CpuImpl, Net, StorageImpl>(
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    instance_registry: &InstanceRegistry,
    requester_instance: &RegisteredInstance,
    cpu: &CpuImpl,
    pool: MemoryPool,
    requested_bytes: usize,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: Storage,
{
    // VIRTIO_BALLOON_F_DEFLATE_ON_OOM: memory the host is holding is
    // reclaimed before memory a program is using. The balloon task
    // does the deflating, so this only asks; the requester still
    // takes this refusal and retries.
    if let Some(balloon) = runtime_state.memory_balloon() {
        balloon.request_deflate();
    }
    let requester = requester_instance.id();
    // Before the registry's lock, never under it: see `UserResidency`.
    let residency = user_residency();
    let decision = instance_registry.condemn_for_oom(
        requester,
        pool,
        requested_bytes as u64,
        monotonic_nanos(cpu),
        &residency,
    );
    let condemned = decision.condemned;
    match decision.outcome {
        OomKillOutcome::Condemned(victim) => {
            deliver_kill(runtime_state, victim.id);
            tracing::warn!(
                target: "helios_kernel::oom",
                requester = ?requester,
                pool = ?pool,
                requested_bytes,
                victim_id = ?victim.id,
                victim_name = %victim.name,
                victim_memory_bytes = victim.memory_bytes,
                victim_user_bytes = victim.user_bytes,
                victim_kernel_bytes = victim.kernel_bytes,
                victim_policy = ?victim.policy,
                score = victim.score,
                condemned_pending_bytes = condemned.pending_bytes,
                condemned_stale_bytes = condemned.stale_bytes,
                "OOM killer condemned victim to free memory"
            );
        }
        OomKillOutcome::AwaitingReclaim => tracing::debug!(
            target: "helios_kernel::oom",
            requester = ?requester,
            pool = ?pool,
            requested_bytes,
            condemned_pending_bytes = condemned.pending_bytes,
            condemned_stale_bytes = condemned.stale_bytes,
            "memory already condemned covers this allocation — requester retries instead of \
             condemning another instance"
        ),
        OomKillOutcome::NoVictim => tracing::warn!(
            target: "helios_kernel::oom",
            requester = ?requester,
            pool = ?pool,
            requested_bytes,
            condemned_pending_bytes = condemned.pending_bytes,
            condemned_stale_bytes = condemned.stale_bytes,
            "OOM killer found no eligible victim — requester takes the allocation failure"
        ),
    }
}

/// What each instance holds of the user pool, for an OOM or kill
/// decision about to be made against the instance registry.
///
/// On bare metal every page the runtime commits for an instance comes
/// out of the installed address space, so that is what answers. Under
/// `wasmtime-host` the runtime's memories are host allocations the user
/// pool never served: no instance holds any of the pool, and no kill
/// gives any of it back.
pub(crate) fn user_residency() -> UserResidency {
    #[cfg(all(target_os = "none", feature = "wasmtime-bare-metal"))]
    {
        UserResidency::of_installed_address_space()
    }
    #[cfg(not(all(target_os = "none", feature = "wasmtime-bare-metal")))]
    {
        UserResidency::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasmtime_adapter::component_host::service::test_store;
    use crate::{KillReason, ProcessAuthority, SettingsAuthorityRights};
    use wasmtime::component::ResourceTableError;

    #[test]
    fn resource_table_limiter_charges_and_releases_instance_kernel_heap() {
        let mut data = test_store::store_data_authorized(ProcessAuthority::empty(), |_| {});
        data.configure_resource_table();
        let instance = data.instance().clone();
        let baseline = instance.kernel_heap_bytes();

        let first = data.table.push([1u8; 256]).expect("first entry fits");
        let after_first = instance.kernel_heap_bytes();
        assert!(
            after_first >= baseline + 256,
            "boxed entry and backing slots must raise attributed kernel heap: baseline={baseline} after={after_first}"
        );

        let second = data.table.push([2u8; 256]).expect("second entry fits");
        assert_eq!(instance.kernel_heap_bytes(), after_first + 256);

        data.table.delete(second).expect("second entry deletes");
        assert_eq!(instance.kernel_heap_bytes(), after_first);
        data.table.delete(first).expect("first entry deletes");
        assert_eq!(instance.kernel_heap_bytes(), after_first - 256);

        drop(data);
        // The store charge and backing table slots both release on drop.
        assert_eq!(instance.kernel_heap_bytes(), 0);
    }

    #[test]
    fn resource_table_enforces_component_handle_limit_setting() {
        let mut authority = ProcessAuthority::empty();
        authority.grant_settings_rights(SettingsAuthorityRights::WRITE);
        let proof = authority
            .derive_write_settings_cap()
            .expect("settings write cap");

        let mut data = test_store::store_data_authorized(ProcessAuthority::empty(), |state| {
            state
                .settings()
                .set::<ComponentHandleLimitSetting>(&proof, 8);
        });
        data.configure_resource_table();

        let mut handles = alloc::vec::Vec::new();
        for i in 0..8usize {
            handles.push(data.table.push([i as u8; 64]).expect("within handle limit"));
        }
        assert!(matches!(
            data.table.push([0xffu8; 64]),
            Err(ResourceTableError::Full)
        ));
        assert_eq!(data.table.len(), 8);
    }

    #[test]
    fn resource_table_headroom_breach_refuses_and_condemns_heaviest_kernel_heap_victim() {
        let data = test_store::store_data_authorized(ProcessAuthority::empty(), |_| {});
        let victim = data.instance_registry.register("handle-hoarder", 1);
        victim.add_kernel_heap_bytes(16 * 1024 * 1024);

        let mut limiter = StoreResourceTableLimiter {
            runtime_state: data.runtime_state.clone(),
            instance_registry: data.instance_registry.clone(),
            instance: data.instance().clone(),
            cpu: data.cpu,
        };

        let exhausted = KernelHeapHeadroom {
            available_bytes: 4096,
            reserve_bytes: 8192,
        };
        assert!(!limiter.try_charge_with_headroom(1024, exhausted));
        assert_eq!(victim.pending_kill(), Some(KillReason::OutOfMemory));
    }
}
