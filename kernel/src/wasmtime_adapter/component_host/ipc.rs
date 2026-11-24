//! `helios:system/ipc` for the component host.
//!
//! Bounded duplex capability channels served identically across both component
//! worlds (`init` and `debugger`). Possession of an endpoint resource is the
//! sole authority needed to read from or write to its direction; endpoints
//! carry no global namespace and enter another instance only through explicit
//! `programs.spawn` / `programs.exec` `capability-grants`.

use alloc::string::String;
use alloc::vec::Vec;

use helios_hal::cpu::Cpu;
use wasmtime::component::{Accessor, HasSelf, Linker, Resource};

use crate::ComponentHostNetwork;
use crate::wasmtime_adapter::bindings::ipc::bindings::helios::system::ipc as ipc_wit;

use super::{StoreData, lower_bytes_to_vec};

pub(super) fn add_ipc_to_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    ipc_wit::add_to_linker::<_, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>(linker, |state| {
        state
    })
}

impl<CpuImpl, Net, StorageImpl> ipc_wit::Host for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn channel(
        &mut self,
    ) -> wasmtime::Result<(Resource<crate::IpcEndpoint>, Resource<crate::IpcEndpoint>)> {
        let (left, right) = crate::ipc_channel();
        let left_handle = self.table.push(left)?;
        let right_handle = self.table.push(right)?;
        Ok((left_handle, right_handle))
    }

    fn take(&mut self, name: String) -> wasmtime::Result<Option<Resource<crate::IpcEndpoint>>> {
        match self.ipc_grants().take(&name) {
            Some(endpoint) => Ok(Some(self.table.push(endpoint)?)),
            None => Ok(None),
        }
    }
}

impl<CpuImpl, Net, StorageImpl> ipc_wit::HostEndpoint for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn close_write(&mut self, endpoint: Resource<crate::IpcEndpoint>) -> wasmtime::Result<()> {
        self.table.get(&endpoint)?.close_write();
        Ok(())
    }

    fn drop(&mut self, endpoint: Resource<crate::IpcEndpoint>) -> wasmtime::Result<()> {
        let _ = self.table.delete(endpoint)?;
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl, U> ipc_wit::HostEndpointWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    U: 'static,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn read(
        accessor: &Accessor<U, Self>,
        endpoint: Resource<crate::IpcEndpoint>,
        max_bytes: u32,
    ) -> wasmtime::Result<Result<Option<Vec<u8>>, ipc_wit::IpcError>> {
        let shared = accessor.with(|mut access| {
            Ok::<_, wasmtime::Error>(access.get().table.get(&endpoint)?.shared())
        })?;
        let response = shared
            .read(max_bytes)
            .await
            .map(|chunk| chunk.map(lower_bytes_to_vec))
            .map_err(|crate::IpcError::Closed| ipc_wit::IpcError::Closed);
        Ok(response)
    }

    async fn write(
        accessor: &Accessor<U, Self>,
        endpoint: Resource<crate::IpcEndpoint>,
        bytes: Vec<u8>,
    ) -> wasmtime::Result<Result<(), ipc_wit::IpcError>> {
        let shared = accessor.with(|mut access| {
            Ok::<_, wasmtime::Error>(access.get().table.get(&endpoint)?.shared())
        })?;
        let response = shared
            .write(&bytes)
            .await
            .map_err(|crate::IpcError::Closed| ipc_wit::IpcError::Closed);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec;
    use futures_lite::future::block_on;
    use wasmtime::Store;
    use wasmtime::component::HasSelf;

    use super::ipc_wit::{self, Host as _};
    use crate::test_support::TestCpu;
    use crate::wasmtime_adapter::component_host::service::test_store::{
        TestStoreData, store_data_authorized,
    };
    use crate::wasmtime_adapter::engine::build_component_engine_for_platform;
    use crate::{IpcEndpointGrants, ProcessAuthority, ipc_channel};

    #[test]
    fn host_ipc_channel_transfers_duplex_messages_and_closes_on_resource_drop() {
        let engine = build_component_engine_for_platform(&TestCpu::with_entropy(0x11)).unwrap();
        let data = store_data_authorized(ProcessAuthority::empty(), |_| {});
        let mut store = Store::new(&engine, data);

        let (left, right) = store.data_mut().channel().unwrap();
        block_on(store.run_concurrent(async |accessor| {
            <HasSelf<TestStoreData> as ipc_wit::HostEndpointWithStore<_>>::write(
                accessor,
                resource_borrow::as_own(&left),
                vec![1, 2, 3, 4],
            )
            .await
            .unwrap()
            .unwrap();
            let got = <HasSelf<TestStoreData> as ipc_wit::HostEndpointWithStore<_>>::read(
                accessor,
                resource_borrow::as_own(&right),
                16,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(got, Some(vec![1, 2, 3, 4]));
        }))
        .unwrap();

        // Dropping `left` closes both directions for `right`.
        ipc_wit::HostEndpoint::drop(store.data_mut(), left).unwrap();
        block_on(store.run_concurrent(async |accessor| {
            let eof = <HasSelf<TestStoreData> as ipc_wit::HostEndpointWithStore<_>>::read(
                accessor,
                resource_borrow::as_own(&right),
                16,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(eof, None);
            let closed = <HasSelf<TestStoreData> as ipc_wit::HostEndpointWithStore<_>>::write(
                accessor,
                resource_borrow::as_own(&right),
                vec![9],
            )
            .await
            .unwrap();
            assert!(matches!(closed, Err(ipc_wit::IpcError::Closed)));
        }))
        .unwrap();
        ipc_wit::HostEndpoint::drop(store.data_mut(), right).unwrap();
    }

    #[test]
    fn host_ipc_take_claims_granted_endpoint_once_and_delivers_parent_frames() {
        let engine = build_component_engine_for_platform(&TestCpu::with_entropy(0x22)).unwrap();
        let (parent_end, child_end) = ipc_channel();
        let mut grants = IpcEndpointGrants::new();
        grants.insert("rpc", child_end).unwrap();

        let data = store_data_authorized(ProcessAuthority::empty(), |_| {}).with_ipc_grants(grants);
        let mut store = Store::new(&engine, data);

        assert!(
            store
                .data_mut()
                .take(String::from("missing"))
                .unwrap()
                .is_none()
        );
        let claimed = store
            .data_mut()
            .take(String::from("rpc"))
            .unwrap()
            .expect("granted endpoint must be claimable once");
        assert!(
            store
                .data_mut()
                .take(String::from("rpc"))
                .unwrap()
                .is_none(),
            "second take of the same grant name must return None"
        );

        let payload = "你好・こんにちは・안녕하세요".as_bytes().to_vec();
        block_on(parent_end.write(&payload)).unwrap();
        parent_end.close_write();

        block_on(store.run_concurrent(async |accessor| {
            let received = <HasSelf<TestStoreData> as ipc_wit::HostEndpointWithStore<_>>::read(
                accessor,
                resource_borrow::as_own(&claimed),
                128,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(received, Some(payload));
            let eof = <HasSelf<TestStoreData> as ipc_wit::HostEndpointWithStore<_>>::read(
                accessor,
                resource_borrow::as_own(&claimed),
                128,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(eof, None);
        }))
        .unwrap();

        ipc_wit::HostEndpoint::drop(store.data_mut(), claimed).unwrap();
    }

    mod resource_borrow {
        use wasmtime::component::Resource;
        pub(super) fn as_own<T: 'static>(resource: &Resource<T>) -> Resource<T> {
            Resource::new_borrow(resource.rep())
        }
    }
}
