//! Wasmtime trait implementations for `ComponentStoreData`.
//!
//! These trait impls bridge kernel-owned store state to Wasmtime's runtime
//! requirements. They live in the adapter module so that `component_runtime.rs`
//! stays free of Wasmtime imports.

extern crate alloc;

use helios_hal::cpu::Cpu;
use wasmtime::ResourceLimiter;

use crate::wasmtime_adapter::component_host::{StoreData, deliver_kill};
use crate::{
    ComponentHostNetwork, KernelHeapHeadroom, MemoryPool, OomKillOutcome, ProgramOutOfMemory,
    Storage, UserResidency, allow_instance_resource_growth, heap_stats, monotonic_nanos,
    user_heap_stats,
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
            request_oom_kill(
                &self.runtime_state,
                &self.instance_registry,
                &self.cpu,
                self.instance().id(),
                MemoryPool::User,
                growth,
            );
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
            request_oom_kill(
                &self.runtime_state,
                &self.instance_registry,
                &self.cpu,
                self.instance().id(),
                MemoryPool::Kernel,
                shortfall,
            );
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
}

/// Ask the OOM killer to cover `requested_bytes` of `pool` for
/// `requester`.
///
/// The one OOM request: a refused linear-memory grow, a refused kernel
/// heap grow and any later refusal of user-pool frames (a store-held
/// buffer, a file page) all come through here, so the balloon, the
/// condemned-memory ledger and the log line behave the same for every
/// one. It takes the pieces of a store rather than the store, because a
/// stream that outlives the call that made it holds exactly these.
///
/// The killer answers against its condemned-memory ledger, so a
/// shortfall that an in-flight kill already covers condemns nothing
/// further: the requester cannot wait for the reclaim, so it takes its
/// typed failure either way and retries when it next asks for the
/// memory. Logged at warn level so post-mortem analysis can trace which
/// instance was sacrificed for which request, and which requests were
/// absorbed by a kill that had already happened.
pub(crate) fn request_oom_kill<CpuImpl, Net, StorageImpl>(
    runtime_state: &crate::wasmtime_adapter::component_host::HostRuntimeState<
        CpuImpl,
        Net,
        StorageImpl,
    >,
    instance_registry: &crate::InstanceRegistry,
    cpu: &CpuImpl,
    requester: crate::InstanceId,
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
    // takes its failure and retries.
    if let Some(balloon) = runtime_state.memory_balloon() {
        balloon.request_deflate();
    }
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
            "memory already condemned covers this request — requester retries instead of \
             condemning another instance"
        ),
        OomKillOutcome::NoVictim => tracing::warn!(
            target: "helios_kernel::oom",
            requester = ?requester,
            pool = ?pool,
            requested_bytes,
            condemned_pending_bytes = condemned.pending_bytes,
            condemned_stale_bytes = condemned.stale_bytes,
            "OOM killer found no eligible victim — requester takes its failure"
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
