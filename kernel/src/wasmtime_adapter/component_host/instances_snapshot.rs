//! `helios:system/instances` and `helios:system/snapshot` for the component
//! host.
//!
//! Both interfaces are registered identically in every component world (`init`
//! and `debugger`) and gated solely by the caller's [`crate::ProcessAuthority`]:
//! - `instances.snapshot` answers with the live instances inside the caller's
//!   [`crate::InspectReadCap`] scope (empty when absent), computing CPU-busy
//!   against per-instance windows so concurrent readers at distinct scopes
//!   never perturb each other's counters.
//! - `instances.kill` requires [`crate::InstanceControlCap`] whose scope admits
//!   the target instance, answering `KillError::Denied` otherwise and emitting
//!   a non-suppressible `helios_kernel::audit` record on every call.
//! - `snapshot.prepare` requires [`crate::MachineControlCap`] and returns an
//!   exclusive RAII `snapshot-hold` resource whose drop (either explicit or
//!   on store teardown via [`crate::StoreSocketRetirement`]) reopens the 9p
//!   host-share gate.

use alloc::vec::Vec;

use helios_hal::cpu::Cpu;
use wasmtime::component::{Accessor, HasSelf, Linker, Resource};

use crate::wasmtime_adapter::bindings::instances::bindings::helios::system::instances as instances_wit;
use crate::wasmtime_adapter::bindings::snapshot::bindings::helios::system::snapshot as snapshot_wit;
use crate::{ComponentHostNetwork, InstanceId, InstanceSnapshot, KillOutcome, KillReason};

use super::StoreData;

pub(super) fn add_instances_to_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    instances_wit::add_to_linker::<_, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>(
        linker,
        |state| state,
    )
}

pub(super) fn add_snapshot_to_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    snapshot_wit::add_to_linker::<_, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>(
        linker,
        |state| state,
    )
}

fn convert_instance(instance: InstanceSnapshot) -> instances_wit::Instance {
    instances_wit::Instance {
        id: instance.id.raw(),
        name: instance.name,
        started_at: instance.started_at,
        uptime: instance.uptime,
        memory_bytes: instance.memory_bytes,
        storage_bytes: instance.storage_bytes,
        cpu_busy: instance.cpu_busy,
    }
}

impl<CpuImpl, Net, StorageImpl> instances_wit::Host for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn snapshot(&mut self) -> wasmtime::Result<Vec<instances_wit::Instance>> {
        let Ok(cap) = self.process_authority().derive_inspect_read_cap() else {
            return Ok(Vec::new());
        };
        let caller_id = self.instance().id();
        Ok(self
            .instance_registry
            .snapshot_scoped(self.now_nanos(), caller_id, cap.scope())
            .into_iter()
            .map(convert_instance)
            .collect())
    }

    fn kill(
        &mut self,
        id: instances_wit::InstanceId,
    ) -> wasmtime::Result<Result<(), instances_wit::KillError>> {
        let caller_id = self.instance().id();
        let victim = InstanceId::from_raw(id);
        let Ok(cap) = self.process_authority().derive_instance_control_cap() else {
            crate::audit::instance_kill_denied(caller_id, victim);
            return Ok(Err(instances_wit::KillError::Denied));
        };
        if !cap
            .scope()
            .admits_instance(caller_id, victim, &self.instance_registry)
        {
            crate::audit::instance_kill_denied(caller_id, victim);
            return Ok(Err(instances_wit::KillError::Denied));
        }
        let now = self.now_nanos();
        // Sampled before acquiring the registry lock: see `UserResidency`.
        let residency = crate::wasmtime_adapter::store::user_residency();
        let outcome =
            self.instance_registry
                .request_kill(victim, KillReason::Operator, now, &residency);
        crate::audit::instance_kill(Some(caller_id), victim, KillReason::Operator, outcome);
        Ok(match outcome {
            KillOutcome::Requested => {
                super::deliver_kill(&self.runtime_state, victim);
                Ok(())
            }
            KillOutcome::AlreadyStopping => Err(instances_wit::KillError::AlreadyStopping),
            KillOutcome::NoSuchInstance => Err(instances_wit::KillError::NoSuchInstance),
        })
    }
}

impl<CpuImpl, Net, StorageImpl> snapshot_wit::Host for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl, U> snapshot_wit::HostWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    U: 'static,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn prepare(
        accessor: &Accessor<U, Self>,
    ) -> wasmtime::Result<Result<Resource<crate::ComponentSnapshotHold>, snapshot_wit::SnapshotError>>
    {
        let snapshot = accessor.with(|mut access| {
            let data = access.get();
            let caller_id = data.instance().id();
            if data
                .process_authority()
                .derive_machine_control_cap()
                .is_err()
            {
                return Err(caller_id);
            }
            Ok((
                caller_id,
                data.runtime_state.clone(),
                data.retirement.snapshot_sender(),
            ))
        });
        let (caller_id, state, retirement) = match snapshot {
            Ok(values) => values,
            Err(caller_id) => {
                crate::audit::diagnostic_gate_change(
                    caller_id,
                    "snapshot.prepare",
                    "denied",
                    false,
                );
                return Ok(Err(snapshot_wit::SnapshotError::Denied));
            }
        };
        let hold = match state.prepare_snapshot_hold().await {
            Ok(hold) => hold,
            Err(crate::SnapshotHoldBusy) => {
                crate::audit::diagnostic_gate_change(caller_id, "snapshot.prepare", "busy", false);
                return Ok(Err(snapshot_wit::SnapshotError::Busy));
            }
        };
        let token = hold.token();
        let has_generation_id = hold.has_generation_id();
        let handle = accessor.with(|mut access| {
            access
                .get()
                .table
                .push(crate::ComponentSnapshotHold::new(
                    token,
                    has_generation_id,
                    retirement,
                ))
                .map_err(wasmtime::Error::from)
        })?;
        hold.disarm();
        crate::audit::diagnostic_gate_change(caller_id, "snapshot.prepare", "held", true);
        Ok(Ok(handle))
    }
}

impl<CpuImpl, Net, StorageImpl> snapshot_wit::HostSnapshotHold
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn has_generation_id(
        &mut self,
        hold: Resource<crate::ComponentSnapshotHold>,
    ) -> wasmtime::Result<bool> {
        Ok(self.table.get(&hold)?.has_generation_id())
    }

    fn drop(&mut self, hold: Resource<crate::ComponentSnapshotHold>) -> wasmtime::Result<()> {
        let mut removed = self.table.delete(hold)?;
        if let Some(token) = removed.release_now() {
            self.runtime_state.finish_snapshot_hold(token);
            crate::audit::diagnostic_gate_change(
                self.instance().id(),
                "snapshot.hold",
                "released",
                true,
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use futures_lite::future::block_on;
    use wasmtime::Store;
    use wasmtime::component::{HasSelf, Resource};

    use super::instances_wit::{self, Host as _};
    use super::snapshot_wit::{self, HostSnapshotHold as _};
    use crate::test_support::TestCpu;
    use crate::wasmtime_adapter::component_host::service::test_store::{
        TestStoreData, store_data_authorized,
    };
    use crate::wasmtime_adapter::engine::build_component_engine_for_platform;
    use crate::{AuthorityScope, InstanceId, MachineAuthorityRights, ProcessAuthority};

    #[test]
    fn instances_snapshot_and_kill_enforce_own_subtree_and_machine_scopes() {
        let mut unprivileged = store_data_authorized(ProcessAuthority::empty(), |_| {});
        assert!(unprivileged.snapshot().unwrap().is_empty());
        assert_eq!(
            unprivileged
                .kill(unprivileged.instance().id().raw())
                .unwrap(),
            Err(instances_wit::KillError::Denied)
        );

        // Verify `Own` sees only its own instance and cannot kill even its own child.
        let mut own_only = ProcessAuthority::empty();
        own_only.grant_inspect_read(AuthorityScope::Own);
        own_only.grant_instance_control(AuthorityScope::Own);
        let mut own_store = store_data_authorized(own_only, |_| {});
        let own_caller = own_store.instance().id();
        let own_child =
            own_store
                .instance_registry
                .register_child(Some(own_caller), "own-child", 2);
        let own_snap: Vec<u64> = own_store
            .snapshot()
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .collect();
        assert_eq!(own_snap, [own_caller.raw()]);
        assert_eq!(
            own_store.kill(own_child.id().raw()).unwrap(),
            Err(instances_wit::KillError::Denied)
        );
        assert_eq!(own_store.kill(own_caller.raw()).unwrap(), Ok(()));
        drop(own_child);

        // Verify `Subtree(sub_caller)` sees `[sub_caller, sub_child, sub_grandchild]`
        // (never `outside`), denies killing `outside`, and permits killing `sub_grandchild`.
        let root_id = InstanceId::from_raw(1);
        let mut subtree_auth = ProcessAuthority::empty();
        subtree_auth.grant_inspect_read(AuthorityScope::Subtree(root_id));
        subtree_auth.grant_instance_control(AuthorityScope::Subtree(root_id));
        let mut subtree_store = store_data_authorized(subtree_auth, |_| {});
        let sub_caller = subtree_store.instance().id();
        assert_eq!(sub_caller, root_id);
        let outside = subtree_store
            .instance_registry
            .register("outside-sibling", 1);
        let sub_child =
            subtree_store
                .instance_registry
                .register_child(Some(sub_caller), "sub-child", 2);
        let sub_grandchild = subtree_store.instance_registry.register_child(
            Some(sub_child.id()),
            "sub-grandchild",
            3,
        );
        let mut sub_snap: Vec<u64> = subtree_store
            .snapshot()
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .collect();
        sub_snap.sort_unstable();
        let mut expected = alloc::vec![
            sub_caller.raw(),
            sub_child.id().raw(),
            sub_grandchild.id().raw(),
        ];
        expected.sort_unstable();
        assert_eq!(sub_snap, expected);
        assert_eq!(
            subtree_store.kill(outside.id().raw()).unwrap(),
            Err(instances_wit::KillError::Denied)
        );
        assert_eq!(
            subtree_store.kill(sub_grandchild.id().raw()).unwrap(),
            Ok(())
        );
        drop((outside, sub_child, sub_grandchild));

        // Verify `Machine` sees every instance and distinguishes missing vs already-stopping.
        let mut machine_auth = ProcessAuthority::empty();
        machine_auth.grant_inspect_read(AuthorityScope::Machine);
        machine_auth.grant_instance_control(AuthorityScope::Machine);
        let mut machine_store = store_data_authorized(machine_auth, |_| {});
        let m_other = machine_store.instance_registry.register("m-other", 1);
        assert_eq!(machine_store.snapshot().unwrap().len(), 2);
        assert_eq!(
            machine_store.kill(999_999).unwrap(),
            Err(instances_wit::KillError::NoSuchInstance)
        );
        assert_eq!(machine_store.kill(m_other.id().raw()).unwrap(), Ok(()));
        assert_eq!(
            machine_store.kill(m_other.id().raw()).unwrap(),
            Err(instances_wit::KillError::AlreadyStopping)
        );
        drop(m_other);
    }

    #[test]
    fn snapshot_prepare_requires_machine_control_enforces_exclusivity_and_releases_on_drop_or_store_teardown()
     {
        let engine = build_component_engine_for_platform(&TestCpu::with_entropy(0x33)).unwrap();

        // 1. Denied without `MachineControlCap`.
        let denied_data = store_data_authorized(ProcessAuthority::empty(), |_| {});
        let mut denied_store = Store::new(&engine, denied_data);
        let denied = block_on(denied_store.run_concurrent(async |accessor| {
            <HasSelf<TestStoreData> as snapshot_wit::HostWithStore<_>>::prepare(accessor)
                .await
                .unwrap()
        }))
        .unwrap();
        assert!(matches!(denied, Err(snapshot_wit::SnapshotError::Denied)));

        // 2. Authorized `prepare` acquires exclusive hold; second `prepare` answers `Busy`;
        //    explicit `drop` releases immediately so a subsequent `prepare` succeeds.
        let mut auth = ProcessAuthority::empty();
        auth.grant_machine_rights(MachineAuthorityRights::CONTROL);
        let data = store_data_authorized(auth.clone(), |state| {
            state.install_machine_generation(crate::MachineGeneration::new(None));
        });
        let shared_state = data.runtime_state.clone();
        let mut store = Store::new(&engine, data);

        let hold = block_on(store.run_concurrent(async |accessor| {
            <HasSelf<TestStoreData> as snapshot_wit::HostWithStore<_>>::prepare(accessor)
                .await
                .unwrap()
        }))
        .unwrap()
        .expect("machine control cap must permit snapshot.prepare");
        assert!(shared_state.snapshot_hold_active());
        assert!(
            !store
                .data_mut()
                .has_generation_id(Resource::new_borrow(hold.rep()))
                .unwrap()
        );

        let busy = block_on(store.run_concurrent(async |accessor| {
            <HasSelf<TestStoreData> as snapshot_wit::HostWithStore<_>>::prepare(accessor)
                .await
                .unwrap()
        }))
        .unwrap();
        assert!(matches!(busy, Err(snapshot_wit::SnapshotError::Busy)));

        snapshot_wit::HostSnapshotHold::drop(store.data_mut(), hold).unwrap();
        assert!(
            !shared_state.snapshot_hold_active(),
            "explicit resource drop must release the snapshot hold immediately"
        );

        // 3. Re-acquire and drop the entire `Store` WITHOUT calling `HostSnapshotHold::drop`
        //    (simulating guest crash / condemnation while holding the lease).
        let leaked_hold = block_on(store.run_concurrent(async |accessor| {
            <HasSelf<TestStoreData> as snapshot_wit::HostWithStore<_>>::prepare(accessor)
                .await
                .unwrap()
        }))
        .unwrap()
        .expect("re-acquiring after drop must succeed");
        let _ = leaked_hold.rep();
        assert!(shared_state.snapshot_hold_active());

        drop(store);
        assert!(
            !shared_state.snapshot_hold_active(),
            "store teardown with an open snapshot-hold resource must reopen the snapshot gate"
        );
    }

    #[test]
    fn snapshot_hold_clears_on_vm_restore_and_ignores_stale_drops_from_before_restore() {
        let engine = build_component_engine_for_platform(&TestCpu::with_entropy(0x44)).unwrap();
        let mut auth = ProcessAuthority::empty();
        auth.grant_machine_rights(MachineAuthorityRights::CONTROL);

        let pre_restore_data = store_data_authorized(auth.clone(), |state| {
            state.install_machine_generation(crate::MachineGeneration::new(None));
        });
        let shared_state = pre_restore_data.runtime_state.clone();
        let mut pre_restore_store = Store::new(&engine, pre_restore_data);

        // 1. Acquire a hold before the VM snapshot/restore.
        let stale_hold = block_on(pre_restore_store.run_concurrent(async |accessor| {
            <HasSelf<TestStoreData> as snapshot_wit::HostWithStore<_>>::prepare(accessor)
                .await
                .unwrap()
        }))
        .unwrap()
        .expect("initial snapshot.prepare must succeed");
        assert!(shared_state.snapshot_hold_active());

        // 2. Simulate VM restore clearing the pre-snapshot hold token.
        shared_state.clear_snapshot_hold_on_restore();
        assert!(
            !shared_state.snapshot_hold_active(),
            "VM restore must clear any pre-snapshot hold so the restored copy can snapshot again"
        );

        // 3. Acquire a new post-restore hold while `stale_hold` is still alive.
        let post_restore_hold = block_on(pre_restore_store.run_concurrent(async |accessor| {
            <HasSelf<TestStoreData> as snapshot_wit::HostWithStore<_>>::prepare(accessor)
                .await
                .unwrap()
        }))
        .unwrap()
        .expect("post-restore snapshot.prepare must succeed even before stale handle drops");
        assert!(shared_state.snapshot_hold_active());

        // 4. Explicitly dropping the stale pre-restore handle must NOT release the newer hold.
        snapshot_wit::HostSnapshotHold::drop(pre_restore_store.data_mut(), stale_hold).unwrap();
        assert!(
            shared_state.snapshot_hold_active(),
            "dropping a stale pre-restore snapshot-hold must not cancel a newer post-restore hold"
        );

        // 5. Simulate another restore + stale store teardown while a newer direct hold is active.
        shared_state.clear_snapshot_hold_on_restore();
        let newer_direct_hold = block_on(shared_state.prepare_snapshot_hold())
            .expect("second post-restore hold must succeed");
        let _ = post_restore_hold.rep();
        drop(pre_restore_store);
        assert!(
            shared_state.snapshot_hold_active(),
            "store teardown of a stale pre-restore hold must not cancel a newer post-restore hold"
        );

        // 6. Dropping the active hold releases the gate cleanly.
        drop(newer_direct_hold);
        assert!(!shared_state.snapshot_hold_active());
    }
}
