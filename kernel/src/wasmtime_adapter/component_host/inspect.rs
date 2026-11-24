//! `helios:system/inspect` for the component host.
//!
//! Served identically across every component world (`init`, `debugger`,
//! `compositor`, `http-handler`, `device-driver`) through one binding set:
//!
//! - `inspect.publish(name, span)` validates `span` against the calling
//!   subcomponent's unshared linear memory (`Access::caller_memory()`) and
//!   active kernel views (`ViewTable`), then registers an RAII
//!   [`crate::InspectPublication`] handle in the component's resource table.
//!   Dropping the resource (explicitly or on store teardown) revokes the
//!   mapping synchronously before linear memory is recycled.
//! - `inspect.snapshot(query, limit)` lifts `query.prefixes` through
//!   [`InspectQueryView`] (`WasmList<WasmStr>`) so prefix count and byte
//!   length bounds are enforced before copying guest memory, then executes a
//!   bounded, non-blocking snapshot gated by [`crate::InspectReadCap`].

use alloc::string::String;

use helios_hal::cpu::Cpu;
use wasmtime::component::{
    Access, ComponentType, HasSelf, Lift, Linker, Resource, WasmList, WasmStr,
};
use wasmtime::{AsContext, StoreContextMut};

use crate::buffer::{PinnedRangeId, Span};
use crate::wasmtime_adapter::bindings::inspect::bindings::helios::system::filters as inspect_filters_wit;
use crate::wasmtime_adapter::bindings::inspect::bindings::helios::system::inspect as inspect_wit;
use crate::{
    AuthorityScope, ComponentHostNetwork, ComponentPublication, InspectEntry, InspectPublication,
    InspectPublishError, InspectSnapshot, InspectValue, PrefixSet, PrefixSetError,
    PublicationStatus,
};

use super::{StoreData, caller_memory};

const INSPECT_INSTANCE: &str = "helios:system/inspect@0.1.0";

/// Host resource backing `helios:system/inspect.publication`.
///
/// Pairs the kernel [`InspectPublication`] with its [`PinnedRangeId`] in the
/// store's [`crate::buffer::ViewTable`] so no kernel view (`show_buffer` /
/// `show_device`) can substitute backing pages underneath a live inspect span.
pub struct InspectPublicationHandle {
    publication: InspectPublication,
    pin: PinnedRangeId,
}

/// Bound-checked view of `helios:system/inspect.query` whose prefix list is
/// inspected in guest memory before copying into a fixed-size [`PrefixSet`].
#[derive(ComponentType, Lift)]
#[component(record)]
struct InspectQueryView {
    prefixes: WasmList<WasmStr>,
}

impl InspectQueryView {
    fn lift<T: 'static>(
        self,
        store: &mut StoreContextMut<'_, T>,
    ) -> wasmtime::Result<Result<PrefixSet, PrefixSetError>> {
        if let Err(refusal) = PrefixSet::admit_count(self.prefixes.len()) {
            return Ok(Err(refusal));
        }
        let mut set = PrefixSet::default();
        for index in 0..self.prefixes.len() {
            let prefix = self
                .prefixes
                .get(&mut *store, index)
                .ok_or_else(|| wasmtime::Error::msg("prefix index past end of list"))??;
            let text = prefix.to_str(store.as_context())?;
            if let Err(refusal) = set.push(&text) {
                return Ok(Err(refusal));
            }
        }
        Ok(Ok(set))
    }
}

pub(super) fn add_inspect_to_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    inspect_wit::add_to_linker::<_, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>(
        linker,
        |state| state,
    )?;
    // Shadow `snapshot` with the zero-copy `WasmList<WasmStr>` view so an
    // oversized prefix list is refused before allocating kernel memory.
    let mut instance = linker.instance(INSPECT_INSTANCE)?;
    instance.func_wrap(
        "snapshot",
        |mut caller, (query, limit): (InspectQueryView, u32)| {
            let result = match query.lift(&mut caller)? {
                Ok(prefixes) => Ok(convert_snapshot(snapshot_for_store(
                    caller.data(),
                    &prefixes,
                    limit,
                ))),
                Err(error) => Err(convert_filter_error(error)),
            };
            Ok((result,))
        },
    )?;
    Ok(())
}

pub(crate) fn snapshot_for_store<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
    prefixes: &PrefixSet,
    limit: u32,
) -> InspectSnapshot
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let ticks = data.cpu.now().ticks();
    let timestamp = data.runtime_state.uptime_nanos(ticks);
    let scope = data
        .process_authority()
        .derive_inspect_read_cap()
        .ok()
        .map(|cap| cap.scope());

    let kernel_telemetry = (scope == Some(AuthorityScope::Machine)
        && prefixes.may_match_subtree("/kernel"))
    .then(|| data.runtime_state.kernel_telemetry_snapshot(ticks));

    let residency = crate::memory::GuestResidency::installed();

    data.runtime_state.inspect_registry().snapshot(
        timestamp,
        data.instance().id(),
        scope,
        &data.instance_registry,
        residency.as_ref(),
        kernel_telemetry.as_ref(),
        prefixes,
        limit,
    )
}

fn convert_publish_error(error: InspectPublishError) -> inspect_wit::PublishError {
    match error {
        InspectPublishError::BadSpan => inspect_wit::PublishError::BadSpan,
        InspectPublishError::InvalidName => inspect_wit::PublishError::InvalidName,
        InspectPublishError::DuplicateName => inspect_wit::PublishError::DuplicateName,
        InspectPublishError::TooManyPublications => inspect_wit::PublishError::TooManyPublications,
    }
}

fn convert_filter_error(error: PrefixSetError) -> inspect_filters_wit::FilterError {
    match error {
        PrefixSetError::TooManyPrefixes => {
            inspect_filters_wit::FilterError::TooManyPrefixes(crate::MAX_FILTER_PREFIXES as u32)
        }
        PrefixSetError::PrefixTooLong => {
            inspect_filters_wit::FilterError::PrefixTooLong(crate::MAX_FILTER_PREFIX_BYTES as u32)
        }
    }
}

fn convert_value(value: InspectValue) -> inspect_wit::Value {
    match value {
        InspectValue::Boolean(v) => inspect_wit::Value::Boolean(v),
        InspectValue::Signed64(v) => inspect_wit::Value::Signed64(v),
        InspectValue::Unsigned64(v) => inspect_wit::Value::Unsigned64(v),
        InspectValue::Float64(v) => inspect_wit::Value::Float64(v),
        InspectValue::Text(v) => inspect_wit::Value::Text(v),
        InspectValue::Blob(v) => inspect_wit::Value::Blob(v),
    }
}

fn convert_entry(entry: InspectEntry) -> inspect_wit::Entry {
    inspect_wit::Entry {
        path: entry.path,
        value: convert_value(entry.value),
    }
}

fn convert_publication(pub_info: ComponentPublication) -> inspect_wit::ComponentPublication {
    inspect_wit::ComponentPublication {
        instance_id: pub_info.instance_id.raw(),
        instance_name: pub_info.instance_name,
        name: pub_info.name,
        generation: pub_info.generation,
        status: match pub_info.status {
            PublicationStatus::Ok => inspect_wit::PublicationStatus::Ok,
            PublicationStatus::Busy => inspect_wit::PublicationStatus::Busy,
            PublicationStatus::Corrupt => inspect_wit::PublicationStatus::Corrupt,
            PublicationStatus::SwappedOut => inspect_wit::PublicationStatus::SwappedOut,
        },
    }
}

fn convert_snapshot(snapshot: InspectSnapshot) -> inspect_wit::SnapshotResult {
    inspect_wit::SnapshotResult {
        timestamp: snapshot.timestamp,
        entries: snapshot.entries.into_iter().map(convert_entry).collect(),
        truncated: snapshot.truncated,
        publications: snapshot
            .publications
            .into_iter()
            .map(convert_publication)
            .collect(),
    }
}

impl<CpuImpl, Net, StorageImpl> inspect_wit::Host for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn snapshot(
        &mut self,
        query: inspect_wit::Query,
        limit: u32,
    ) -> wasmtime::Result<Result<inspect_wit::SnapshotResult, inspect_filters_wit::FilterError>>
    {
        let prefixes = match PrefixSet::from_prefixes(query.prefixes.iter().map(String::as_str)) {
            Ok(prefixes) => prefixes,
            Err(error) => return Ok(Err(convert_filter_error(error))),
        };
        Ok(Ok(convert_snapshot(snapshot_for_store(
            self, &prefixes, limit,
        ))))
    }
}

impl<CpuImpl, Net, StorageImpl, U> inspect_wit::HostWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    U: 'static,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn publish(
        mut access: Access<'_, U, Self>,
        name: String,
        region: inspect_wit::Span,
    ) -> wasmtime::Result<Result<Resource<InspectPublicationHandle>, inspect_wit::PublishError>>
    {
        let Ok(memory) = caller_memory(&access) else {
            return Ok(Err(inspect_wit::PublishError::BadSpan));
        };
        let span = Span::new(region.offset, region.length);
        let data = access.get();
        let Ok(pin) = data.views.pin_range(memory, span) else {
            return Ok(Err(inspect_wit::PublishError::BadSpan));
        };
        let instance_id = data.instance().id();
        let instance_name = String::from(data.instance().name());
        let publication = match data.runtime_state.inspect_registry().publish(
            instance_id,
            instance_name,
            name,
            memory,
            span,
        ) {
            Ok(publication) => publication,
            Err(error) => {
                data.views.unpin_range(pin);
                return Ok(Err(convert_publish_error(error)));
            }
        };
        match data
            .table
            .push(InspectPublicationHandle { publication, pin })
        {
            Ok(handle) => Ok(Ok(handle)),
            Err(error) => {
                data.views.unpin_range(pin);
                Err(error.into())
            }
        }
    }
}

impl<CpuImpl, Net, StorageImpl> inspect_wit::HostPublication
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn drop(&mut self, publication: Resource<InspectPublicationHandle>) -> wasmtime::Result<()> {
        let InspectPublicationHandle { publication, pin } = self.table.delete(publication)?;
        // Revoke the inspect mapping synchronously before releasing the
        // `ViewTable` pin so no view can substitute pages underneath an
        // in-flight reader copy.
        drop(publication);
        self.views.unpin_range(pin);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec;
    use wasmtime::Store;

    use super::inspect_wit::{self, Host as _, HostPublication as _};
    use crate::buffer::{GuestMemory, Span, WASM_PAGE_BYTES};
    use crate::inspect::buffer::encode_buffer;
    use crate::test_support::TestCpu;
    use crate::wasmtime_adapter::component_host::service::test_store::store_data_authorized;
    use crate::wasmtime_adapter::engine::build_component_engine_for_platform;
    use crate::{AuthorityScope, InspectValue, ProcessAuthority};
    use helios_hal::vmm::VirtAddr;

    #[test]
    fn host_inspect_snapshot_enforces_filter_bounds_and_machine_kernel_parity() {
        let mut machine_auth = ProcessAuthority::empty();
        machine_auth.grant_inspect_read(AuthorityScope::Machine);
        let mut store = store_data_authorized(machine_auth, |_| {});

        // Exceeding MAX_FILTER_PREFIXES returns FilterError::TooManyPrefixes.
        let too_many = (0..=crate::MAX_FILTER_PREFIXES)
            .map(|i| alloc::format!("/k/{i}"))
            .collect();
        let err = store
            .snapshot(inspect_wit::Query { prefixes: too_many }, 0)
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            err,
            super::inspect_filters_wit::FilterError::TooManyPrefixes(limit)
                if limit == crate::MAX_FILTER_PREFIXES as u32
        ));

        // Exceeding MAX_FILTER_PREFIX_BYTES returns FilterError::PrefixTooLong.
        let err = store
            .snapshot(
                inspect_wit::Query {
                    prefixes: vec!["a".repeat(crate::MAX_FILTER_PREFIX_BYTES + 1)],
                },
                0,
            )
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            err,
            super::inspect_filters_wit::FilterError::PrefixTooLong(limit)
                if limit == crate::MAX_FILTER_PREFIX_BYTES as u32
        ));

        // Machine scope reads core `/kernel/*` telemetry (clock, processors, memory, hv).
        let snap = store
            .snapshot(
                inspect_wit::Query {
                    prefixes: vec![String::from("/kernel/")],
                },
                0,
            )
            .unwrap()
            .unwrap();
        assert!(
            snap.entries
                .iter()
                .any(|e| e.path == "/kernel/clock/uptime-nanos")
        );
        assert!(
            snap.entries
                .iter()
                .any(|e| e.path == "/kernel/processors/configured")
        );
        assert!(
            snap.entries
                .iter()
                .any(|e| e.path == "/kernel/memory/total-bytes")
        );
        assert!(snap.entries.iter().any(|e| e.path == "/kernel/hv/vm-count"));
    }

    #[test]
    fn publication_resource_revokes_on_explicit_drop_and_on_store_teardown() {
        let engine = build_component_engine_for_platform(&TestCpu::with_entropy(0x77)).unwrap();
        let mut auth = ProcessAuthority::empty();
        auth.grant_inspect_read(AuthorityScope::Own);
        let data = store_data_authorized(auth, |_| {});
        let registry = data.runtime_state.inspect_registry().clone();
        let mut store = Store::new(&engine, data);

        let mut backing: Box<[u64]> = vec![0u64; (WASM_PAGE_BYTES as usize) / 8].into_boxed_slice();
        {
            // SAFETY: `u64` slice is initialized and 8-byte aligned.
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    backing.as_mut_ptr().cast::<u8>(),
                    WASM_PAGE_BYTES as usize,
                )
            };
            encode_buffer(2, &[("k", InspectValue::Unsigned64(5))], bytes).unwrap();
        }
        let gm = GuestMemory::new(VirtAddr::new(backing.as_ptr() as usize), WASM_PAGE_BYTES);
        let inst_id = store.data().instance().id();

        let span = Span::new(0, WASM_PAGE_BYTES);
        let pin1 = store.data_mut().views.pin_range(gm, span).unwrap();
        let pub1 = registry
            .publish(inst_id, "test", "metrics", gm, span)
            .unwrap();
        let handle1 = store
            .data_mut()
            .table
            .push(super::InspectPublicationHandle {
                publication: pub1,
                pin: pin1,
            })
            .unwrap();
        assert_eq!(registry.publication_count(), 1);

        // Symmetric exclusion: while the inspect span is published, `ViewTable`
        // refuses any overlapping buffer/device view on the same span.
        assert_eq!(
            store.data().views.validate(gm, span, WASM_PAGE_BYTES),
            Err(crate::buffer::ViewError::Overlap)
        );
        // And pinning an overlapping second inspect span is also refused.
        assert_eq!(
            store.data_mut().views.pin_range(gm, span),
            Err(crate::buffer::ViewError::Overlap)
        );

        // Explicit drop removes publication and releases the `ViewTable` pin.
        store.data_mut().drop(handle1).unwrap();
        assert_eq!(registry.publication_count(), 0);
        assert!(
            store
                .data()
                .views
                .validate(gm, span, WASM_PAGE_BYTES)
                .is_ok()
        );

        // Re-publish and drop entire `Store` without explicit resource drop.
        let pin2 = store.data_mut().views.pin_range(gm, span).unwrap();
        let pub2 = registry
            .publish(inst_id, "test", "metrics", gm, span)
            .unwrap();
        let _leaked = store
            .data_mut()
            .table
            .push(super::InspectPublicationHandle {
                publication: pub2,
                pin: pin2,
            })
            .unwrap();
        assert_eq!(registry.publication_count(), 1);
        drop(store);
        assert_eq!(
            registry.publication_count(),
            0,
            "dropping Store must revoke any open InspectPublication before memory recycle"
        );
    }
}
