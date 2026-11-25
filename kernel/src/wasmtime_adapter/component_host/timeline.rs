use super::*;
use crate::{
    SharedTimeline, SignalTimeline, Timeline, TimelineError, TimelineSource, wait_timelines,
    wait_until_runtime_deadline,
};
use program_wit::sync::{self, HostSignalSourceWithStore, HostTimelineWithStore, HostWithStore};
use wasmtime::component::LinkerInstance;

fn lower_error(error: TimelineError) -> sync::Error {
    match error {
        TimelineError::Closed => sync::Error::Closed,
        TimelineError::Failed => sync::Error::Failed,
    }
}

impl<CpuImpl, Net, StorageImpl> sync::HostTimeline for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl> sync::HostSignalSource for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl, U> HostTimelineWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn value(
        mut access: Access<'_, U, Self>,
        resource: Resource<SharedTimeline>,
    ) -> wasmtime::Result<Result<u64, sync::Error>> {
        Ok(access
            .get()
            .table
            .get(&resource)?
            .value()
            .map_err(lower_error))
    }

    fn drop(
        mut access: Access<'_, U, Self>,
        resource: Resource<SharedTimeline>,
    ) -> wasmtime::Result<()> {
        access.get().table.delete(resource)?;
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl, U> HostSignalSourceWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn new(
        mut access: Access<'_, U, Self>,
        initial: u64,
    ) -> wasmtime::Result<Resource<TimelineSource>> {
        Ok(access.get().table.push(TimelineSource::new(initial))?)
    }

    fn reader(
        mut access: Access<'_, U, Self>,
        resource: Resource<TimelineSource>,
    ) -> wasmtime::Result<Resource<SharedTimeline>> {
        let data = access.get();
        let reader = data.table.get(&resource)?.reader();
        Ok(data.table.push(reader)?)
    }

    fn signal(
        mut access: Access<'_, U, Self>,
        resource: Resource<TimelineSource>,
        value: u64,
    ) -> wasmtime::Result<Result<(), sync::Error>> {
        Ok(access
            .get()
            .table
            .get(&resource)?
            .signal(value)
            .map_err(lower_error))
    }

    fn fail(
        mut access: Access<'_, U, Self>,
        resource: Resource<TimelineSource>,
    ) -> wasmtime::Result<()> {
        access.get().table.get(&resource)?.fail();
        Ok(())
    }

    fn drop(
        mut access: Access<'_, U, Self>,
        resource: Resource<TimelineSource>,
    ) -> wasmtime::Result<()> {
        access.get().table.delete(resource)?;
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl, U> HostWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn wait(
        accessor: &Accessor<U, Self>,
        points: Vec<sync::TimelinePoint>,
        wait_all: bool,
        deadline: Option<u64>,
    ) -> wasmtime::Result<Result<bool, sync::Error>> {
        let (points, timer, cpu, runtime) = accessor.with(|mut access| {
            let data = access.get();
            let points = points
                .iter()
                .map(|point| Ok(data.table.get(&point.timeline)?.point(point.value)))
                .collect::<wasmtime::Result<Vec<_>>>()?;
            Ok::<_, wasmtime::Error>((
                points,
                data.timer(),
                data.cpu.clone(),
                data.runtime_state.clone(),
            ))
        })?;
        let deadline = async move {
            match deadline {
                Some(nanos) => wait_until_runtime_deadline(timer, cpu, runtime, nanos).await,
                None => core::future::pending().await,
            }
        };
        Ok(wait_timelines(&points, wait_all, deadline)
            .await
            .map_err(lower_error))
    }
}

pub(super) fn add_to_linker<CpuImpl, Net, StorageImpl>(
    instance: &mut LinkerInstance<'_, StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    instance.resource_concurrent("timeline", ResourceType::host::<SharedTimeline>(), |accessor, rep| {
        Box::pin(async move { accessor.with(|access| <HasSelf<StoreData<CpuImpl, Net, StorageImpl>> as HostTimelineWithStore<_>>::drop(access, Resource::new_own(rep))) })
    })?;
    instance.resource_concurrent(
        "signal-source",
        ResourceType::host::<TimelineSource>(),
        |accessor, rep| {
            Box::pin(async move {
                accessor.with(|access| {
                    <HasSelf<StoreData<CpuImpl, Net, StorageImpl>> as HostSignalSourceWithStore<
                        _,
                    >>::drop(access, Resource::new_own(rep))
                })
            })
        },
    )?;
    instance.func_wrap(
        "[constructor]signal-source",
        |mut caller: StoreContextMut<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (initial,): (u64,)| {
            Ok((caller.data_mut().table.push(TimelineSource::new(initial))?,))
        },
    )?;
    instance.func_wrap(
        "[method]signal-source.reader",
        |mut caller: StoreContextMut<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<TimelineSource>,)| {
            let data = caller.data_mut();
            let reader = data.table.get(&resource)?.reader();
            Ok((data.table.push(reader)?,))
        },
    )?;
    instance.func_wrap(
        "[method]signal-source.signal",
        |caller: StoreContextMut<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (resource, value): (Resource<TimelineSource>, u64)| {
            Ok((caller
                .data()
                .table
                .get(&resource)?
                .signal(value)
                .map_err(lower_error),))
        },
    )?;
    instance.func_wrap(
        "[method]signal-source.fail",
        |caller: StoreContextMut<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<TimelineSource>,)| {
            caller.data().table.get(&resource)?.fail();
            Ok(())
        },
    )?;
    instance.func_wrap(
        "[method]timeline.value",
        |caller: StoreContextMut<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<SharedTimeline>,)| {
            Ok((caller
                .data()
                .table
                .get(&resource)?
                .value()
                .map_err(lower_error),))
        },
    )?;
    instance.func_wrap_concurrent(
        "wait",
        |accessor, (points, wait_all, deadline): (Vec<sync::TimelinePoint>, bool, Option<u64>)| {
            Box::pin(async move {
                Ok((
                    <HasSelf<StoreData<CpuImpl, Net, StorageImpl>> as HostWithStore<_>>::wait(
                        accessor, points, wait_all, deadline,
                    )
                    .await?,
                ))
            })
        },
    )?;
    Ok(())
}
