//! `helios:system/gpu` for the component host.
//!
//! Thin WIT adapter over the kernel's [`crate::gpu`] subsystem: this
//! module translates WIT resources, linear-memory [`Span`] views and
//! error codes, while session lifetimes, context/blob ownership, fence
//! admission and device cleanup live in [`crate::gpu`].

use alloc::string::String;
use alloc::vec::Vec;
use core::pin::Pin;
use core::task::{Context, Poll};

use helios_hal::display::{
    BlobMemory, BlobUsage, CapsetId, ContextName, DisplayMode, FenceId, MAX_CONTEXT_NAME,
    PixelFormat, RingCount,
};
use helios_hal::iommu::PhysicalRange;
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Access, Accessor, Destination, HasSelf, Linker, Resource, StreamProducer, StreamReader,
    StreamResult,
};

use crate::ComponentHostNetwork;
use crate::buffer::{Buffer, GuestMemory, Span, ViewError, ViewGroup, ViewId, ViewTable};
use crate::gpu::{
    BlobCreate, BlobMapping, CompletionSignal, Gpu3dServiceError, GpuBlob, GpuClient, GpuContext,
    GpuFenceReader, GpuImage, InlineCommands, MAX_EXECUTE_BYTES, SessionId, SubmitCommands,
    SubmitCompletion,
};
use crate::wasmtime_adapter::bindings::gpu::bindings::helios::system::gpu as gpu_wit;

use super::super::{StoreData, caller_memory, view_trap};

/// Register `helios:system/gpu` in a linker.
pub(in crate::wasmtime_adapter::component_host) fn add_gpu_to_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    gpu_wit::add_to_linker::<_, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>(linker, |state| {
        state
    })
}

/// One of a plugin's `gpu` handles, as its store records it.
pub struct GpuHandle {
    session: SessionId,
}

/// One renderer context, as its store records it.
pub struct ContextHandle {
    pub(crate) context: GpuContext,
}

/// One pinned command buffer, as its store records it.
pub struct CommandBufferHandle {
    pub(crate) session: SessionId,
    pub(crate) buffer: Buffer,
    pub(crate) view: ViewId,
}

/// One blob resource and its linear-memory views, as its store records it.
pub struct BlobHandle {
    pub(crate) blob: GpuBlob,
    pub(crate) backing: Option<ViewId>,
    pub(crate) mapped: Option<(ViewId, BlobMapping)>,
}

fn to_wit_error(error: Gpu3dServiceError) -> gpu_wit::Error {
    match error {
        Gpu3dServiceError::Unavailable => gpu_wit::Error::Unavailable,
        Gpu3dServiceError::NoRenderer => gpu_wit::Error::NoRenderer,
        Gpu3dServiceError::SessionEnded => gpu_wit::Error::SessionEnded,
        Gpu3dServiceError::NoSuchCapset => gpu_wit::Error::NoSuchCapset,
        Gpu3dServiceError::UnsupportedContext => gpu_wit::Error::UnsupportedContext,
        Gpu3dServiceError::TooManyContexts => gpu_wit::Error::TooManyContexts,
        Gpu3dServiceError::TooManyBlobs => gpu_wit::Error::TooManyBlobs,
        Gpu3dServiceError::ContextsExhausted => gpu_wit::Error::ContextsExhausted,
        Gpu3dServiceError::BlobsExhausted => gpu_wit::Error::BlobsExhausted,
        Gpu3dServiceError::TooManyViews => gpu_wit::Error::TooManyViews,
        Gpu3dServiceError::InvalidBlob => gpu_wit::Error::InvalidBlob,
        Gpu3dServiceError::ApertureExhausted => gpu_wit::Error::ApertureExhausted,
        Gpu3dServiceError::OutOfBounds => gpu_wit::Error::OutOfBounds,
        Gpu3dServiceError::BadRing => gpu_wit::Error::BadRing,
        Gpu3dServiceError::StaleFence => gpu_wit::Error::StaleFence,
        Gpu3dServiceError::UnsubmittedFence => gpu_wit::Error::UnsubmittedFence,
        Gpu3dServiceError::BadSpan(_) | Gpu3dServiceError::BlobSpanMismatch => {
            gpu_wit::Error::BadSpan
        }
        Gpu3dServiceError::AlreadyMapped => gpu_wit::Error::AlreadyMapped,
        Gpu3dServiceError::NotMapped => gpu_wit::Error::NotMapped,
        Gpu3dServiceError::OutOfMemory => gpu_wit::Error::OutOfMemory,
        Gpu3dServiceError::DeviceFault | Gpu3dServiceError::Closed => gpu_wit::Error::DeviceFault,
    }
}

fn from_wit_blob_memory(memory: gpu_wit::BlobMemory) -> BlobMemory {
    match memory {
        gpu_wit::BlobMemory::Guest => BlobMemory::Guest,
        gpu_wit::BlobMemory::Host3d => BlobMemory::Host3d,
        gpu_wit::BlobMemory::Host3dGuest => BlobMemory::Host3dGuest,
    }
}

fn from_wit_blob_usage(usage: gpu_wit::BlobUsage) -> BlobUsage {
    let mut flags = BlobUsage::empty();
    if usage.contains(gpu_wit::BlobUsage::MAPPABLE) {
        flags |= BlobUsage::MAPPABLE;
    }
    if usage.contains(gpu_wit::BlobUsage::SHAREABLE) {
        flags |= BlobUsage::SHAREABLE;
    }
    if usage.contains(gpu_wit::BlobUsage::CROSS_DEVICE) {
        flags |= BlobUsage::CROSS_DEVICE;
    }
    flags
}

const fn span(at: gpu_wit::Span) -> Span {
    Span::new(at.offset, at.length)
}

fn to_context_name(name: &str) -> ContextName {
    let mut label = ContextName::new();
    for ch in name.chars() {
        if label.len() + ch.len_utf8() > MAX_CONTEXT_NAME {
            break;
        }
        label.push(ch);
    }
    label
}

impl<CpuImpl, Net, StorageImpl> StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn gpu_client(&self, session: SessionId) -> Result<GpuClient, Gpu3dServiceError> {
        self.device.gpu().client_of(session)
    }

    pub(crate) fn command_range(
        &mut self,
        commands: &Resource<CommandBufferHandle>,
        offset: u64,
        length: u64,
        session: SessionId,
    ) -> wasmtime::Result<Result<SubmitCommands, gpu_wit::Error>> {
        let commands = self.table.get(commands)?;
        if commands.session != session {
            return Ok(Err(gpu_wit::Error::SessionEnded));
        }
        let Some(end) = offset.checked_add(length) else {
            return Ok(Err(gpu_wit::Error::OutOfBounds));
        };
        if end > commands.buffer.bytes() {
            return Ok(Err(gpu_wit::Error::OutOfBounds));
        }
        let physical = commands.buffer.physical();
        Ok(Ok(SubmitCommands::Pages {
            buffer: commands.buffer.clone(),
            range: PhysicalRange::new(physical.start + offset, length),
        }))
    }

    fn end_session_view(&mut self, session: SessionId, view: ViewId) -> wasmtime::Result<()> {
        if self.device.gpu().is_current(session) {
            self.views.end(view).map_err(view_trap)?;
        }
        Ok(())
    }

    fn show_in_session(
        &mut self,
        session: SessionId,
        show: impl FnOnce(&mut ViewTable, ViewGroup) -> Result<ViewId, ViewError>,
    ) -> Result<ViewId, Gpu3dServiceError> {
        self.device.gpu().session_of(session)?;
        let group = self.device.gpu().room_for_view(&self.views)?;
        Ok(show(&mut self.views, group)?)
    }

    fn check_session_span(
        &self,
        memory: GuestMemory,
        at: Span,
        bytes: u64,
    ) -> Result<(), Gpu3dServiceError> {
        self.device.gpu().room_for_view(&self.views)?;
        self.views.validate(memory, at, bytes)?;
        Ok(())
    }

    fn pin_session_buffer(
        &self,
        memory: GuestMemory,
        at: Span,
        bytes: u64,
    ) -> Result<Buffer, Gpu3dServiceError> {
        self.check_session_span(memory, at, bytes)?;
        Ok(Buffer::pinned(bytes)?)
    }

    fn build_completion(
        &self,
        completion: Option<&gpu_wit::Completion>,
    ) -> wasmtime::Result<Option<SubmitCompletion>> {
        completion
            .map(|completion| {
                let signals = completion
                    .signals
                    .iter()
                    .map(|signal| {
                        Ok(CompletionSignal {
                            source: self.table.get(&signal.source)?.clone(),
                            value: signal.value,
                        })
                    })
                    .collect::<wasmtime::Result<Vec<_>>>()?;
                Ok(SubmitCompletion {
                    fence: FenceId::new(completion.fence),
                    signals,
                })
            })
            .transpose()
    }
}

fn memory_of<U, CpuImpl, Net, StorageImpl>(
    access: &mut Access<'_, U, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>,
) -> Result<GuestMemory, Gpu3dServiceError>
where
    U: 'static,
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    Ok(caller_memory(&*access)?)
}

fn checked_memory<U, CpuImpl, Net, StorageImpl>(
    access: &mut Access<'_, U, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>,
) -> GuestMemory
where
    U: 'static,
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    memory_of(access).expect("a store whose memory took the span in the call's first step has one")
}

pub(super) const fn from_wit_format(format: gpu_wit::PixelFormat) -> PixelFormat {
    match format {
        gpu_wit::PixelFormat::Bgrx8888 => PixelFormat::Bgrx8888,
        gpu_wit::PixelFormat::Bgra8888 => PixelFormat::Bgra8888,
        gpu_wit::PixelFormat::Xrgb8888 => PixelFormat::Xrgb8888,
        gpu_wit::PixelFormat::Argb8888 => PixelFormat::Argb8888,
        gpu_wit::PixelFormat::Rgbx8888 => PixelFormat::Rgbx8888,
        gpu_wit::PixelFormat::Rgba8888 => PixelFormat::Rgba8888,
        gpu_wit::PixelFormat::Xbgr8888 => PixelFormat::Xbgr8888,
        gpu_wit::PixelFormat::Abgr8888 => PixelFormat::Abgr8888,
    }
}

fn image_layout(image: &GpuImage) -> gpu_wit::ImageLayout {
    let layout = image.layout();
    gpu_wit::ImageLayout {
        width: layout.mode.width,
        height: layout.mode.height,
        offset: layout.offset,
        stride: layout.stride,
        format: match layout.format {
            PixelFormat::Bgrx8888 => gpu_wit::PixelFormat::Bgrx8888,
            PixelFormat::Bgra8888 => gpu_wit::PixelFormat::Bgra8888,
            PixelFormat::Xrgb8888 => gpu_wit::PixelFormat::Xrgb8888,
            PixelFormat::Argb8888 => gpu_wit::PixelFormat::Argb8888,
            PixelFormat::Rgbx8888 => gpu_wit::PixelFormat::Rgbx8888,
            PixelFormat::Rgba8888 => gpu_wit::PixelFormat::Rgba8888,
            PixelFormat::Xbgr8888 => gpu_wit::PixelFormat::Xbgr8888,
            PixelFormat::Abgr8888 => gpu_wit::PixelFormat::Abgr8888,
        },
    }
}

impl<CpuImpl, Net, StorageImpl> gpu_wit::HostImage for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn drop(&mut self, image: Resource<GpuImage>) -> wasmtime::Result<()> {
        self.table.delete(image)?;
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl> gpu_wit::Host for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn describe_image(
        &mut self,
        image: Resource<GpuImage>,
    ) -> wasmtime::Result<gpu_wit::ImageLayout> {
        Ok(image_layout(self.table.get(&image)?))
    }

    fn open(&mut self) -> wasmtime::Result<Result<Resource<GpuHandle>, gpu_wit::Error>> {
        let Some(service) = self.runtime_state.gpu3d_service() else {
            return Ok(Err(gpu_wit::Error::Unavailable));
        };
        let Ok(cap) = self.process_authority().derive_gpu_open_cap() else {
            return Ok(Err(gpu_wit::Error::Unavailable));
        };
        let session = match self.device.open_gpu(&service, &mut self.views, cap) {
            Ok(session) => session,
            Err(error) => return Ok(Err(to_wit_error(error))),
        };
        let handle = self.table.push(GpuHandle { session })?;
        tracing::info!(
            target: "helios_kernel::gpu",
            session = session.raw(),
            "an instance holds the 3D engine"
        );
        Ok(Ok(handle))
    }
}

impl<CpuImpl, Net, StorageImpl> gpu_wit::HostGpu for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn drop(&mut self, handle: Resource<GpuHandle>) -> wasmtime::Result<()> {
        let handle = self.table.delete(handle)?;
        self.device
            .gpu_mut()
            .close(handle.session, &mut self.views)
            .map_err(view_trap)
    }
}

impl<CpuImpl, Net, StorageImpl> gpu_wit::HostContext for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn drop(&mut self, handle: Resource<ContextHandle>) -> wasmtime::Result<()> {
        self.table.delete(handle)?;
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl> gpu_wit::HostCommandBuffer for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn drop(&mut self, handle: Resource<CommandBufferHandle>) -> wasmtime::Result<()> {
        let commands = self.table.delete(handle)?;
        self.end_session_view(commands.session, commands.view)
    }
}

impl<CpuImpl, Net, StorageImpl> gpu_wit::HostBlob for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn image(
        &mut self,
        handle: Resource<BlobHandle>,
        layout: gpu_wit::ImageLayout,
    ) -> wasmtime::Result<Result<Resource<GpuImage>, gpu_wit::Error>> {
        let blob = self.table.get(&handle)?;
        if !self.device.gpu().is_current(blob.blob.session()) {
            return Ok(Err(gpu_wit::Error::SessionEnded));
        }
        let image = match blob.blob.image(
            DisplayMode::new(layout.width, layout.height),
            from_wit_format(layout.format),
            layout.offset,
            layout.stride,
        ) {
            Ok(image) => image,
            Err(error) => return Ok(Err(to_wit_error(error))),
        };
        Ok(Ok(self.table.push(image)?))
    }

    fn resource_id(&mut self, handle: Resource<BlobHandle>) -> wasmtime::Result<u32> {
        Ok(self.table.get(&handle)?.blob.id().raw())
    }

    fn drop(&mut self, handle: Resource<BlobHandle>) -> wasmtime::Result<()> {
        let mut blob = self.table.delete(handle)?;
        if self.device.gpu().is_current(blob.blob.session()) {
            let mapped = blob.mapped.take().map(|(view, mapping)| {
                drop(mapping);
                view
            });
            for view in [mapped, blob.backing].into_iter().flatten() {
                self.views.end(view).map_err(view_trap)?;
            }
        }
        Ok(())
    }
}

fn client_of<U, CpuImpl, Net, StorageImpl>(
    mut access: Access<'_, U, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>,
    handle: &Resource<GpuHandle>,
) -> wasmtime::Result<Result<GpuClient, gpu_wit::Error>>
where
    U: 'static,
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let data = access.get();
    let session = data.table.get(handle)?.session;
    Ok(data.gpu_client(session).map_err(to_wit_error))
}

fn context_of<U, CpuImpl, Net, StorageImpl>(
    mut access: Access<'_, U, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>,
    handle: &Resource<ContextHandle>,
) -> wasmtime::Result<Result<GpuContext, gpu_wit::Error>>
where
    U: 'static,
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let data = access.get();
    let context = data.table.get(handle)?.context.clone();
    if context.is_faulted() {
        return Ok(Err(gpu_wit::Error::DeviceFault));
    }
    if !data.device.gpu().is_current(context.session()) {
        return Ok(Err(gpu_wit::Error::SessionEnded));
    }
    Ok(Ok(context))
}

struct FenceStreamProducer {
    reader: GpuFenceReader,
}

impl<T: 'static> StreamProducer<T> for FenceStreamProducer {
    type Item = u64;
    type Buffer = Option<Self::Item>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _store: StoreContextMut<'_, T>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        match self.reader.poll_next(cx) {
            Poll::Ready(fence) => {
                destination.set_buffer(Some(fence));
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<CpuImpl, Net, StorageImpl, U> gpu_wit::HostGpuWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    U: 'static,
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn capsets(
        accessor: &Accessor<U, Self>,
        handle: Resource<GpuHandle>,
    ) -> wasmtime::Result<Result<Vec<gpu_wit::CapsetInfo>, gpu_wit::Error>> {
        let client = match accessor.with(|access| client_of(access, &handle))? {
            Ok(client) => client,
            Err(error) => return Ok(Err(error)),
        };
        Ok(client
            .capsets()
            .await
            .map(|capsets| {
                capsets
                    .iter()
                    .map(|info| gpu_wit::CapsetInfo {
                        id: info.id.raw(),
                        max_version: info.max_version,
                        max_size: info.max_size,
                    })
                    .collect()
            })
            .map_err(to_wit_error))
    }

    async fn capset(
        accessor: &Accessor<U, Self>,
        handle: Resource<GpuHandle>,
        id: u32,
        version: u32,
    ) -> wasmtime::Result<Result<Vec<u8>, gpu_wit::Error>> {
        let client = match accessor.with(|access| client_of(access, &handle))? {
            Ok(client) => client,
            Err(error) => return Ok(Err(error)),
        };
        Ok(client
            .capset(CapsetId::new(id), version)
            .await
            .map_err(to_wit_error))
    }

    async fn create_context(
        accessor: &Accessor<U, Self>,
        handle: Resource<GpuHandle>,
        capset: u32,
        rings: u8,
        name: String,
    ) -> wasmtime::Result<Result<Resource<ContextHandle>, gpu_wit::Error>> {
        let client = match accessor.with(|access| client_of(access, &handle))? {
            Ok(client) => client,
            Err(error) => return Ok(Err(error)),
        };
        let Some(rings) = RingCount::new(rings) else {
            return Ok(Err(gpu_wit::Error::BadRing));
        };
        let context = match client
            .create_context(CapsetId::new(capset), rings, to_context_name(&name))
            .await
        {
            Ok(context) => context,
            Err(error) => return Ok(Err(to_wit_error(error))),
        };
        let handle =
            accessor.with(|mut access| access.get().table.push(ContextHandle { context }))?;
        Ok(Ok(handle))
    }

    async fn create_blob(
        accessor: &Accessor<U, Self>,
        handle: Resource<GpuHandle>,
        context: Resource<ContextHandle>,
        memory: gpu_wit::BlobMemory,
        usage: gpu_wit::BlobUsage,
        size: u64,
        blob_id: u64,
        buffer: Option<gpu_wit::Span>,
    ) -> wasmtime::Result<Result<Resource<BlobHandle>, gpu_wit::Error>> {
        let client = match accessor.with(|access| client_of(access, &handle))? {
            Ok(client) => client,
            Err(error) => return Ok(Err(error)),
        };
        let context = accessor.with(|mut access| -> wasmtime::Result<GpuContext> {
            Ok(access.get().table.get(&context)?.context.clone())
        })?;
        let memory_kind = from_wit_blob_memory(memory);
        let backing = match (memory_kind, buffer) {
            (BlobMemory::Host3d, None) => None,
            (BlobMemory::Guest | BlobMemory::Host3dGuest, Some(at)) => {
                if size == 0 {
                    return Ok(Err(gpu_wit::Error::InvalidBlob));
                }
                let at = span(at);
                let pinned = accessor.with(|mut access| {
                    let memory = memory_of(&mut access)?;
                    access.get().pin_session_buffer(memory, at, size)
                });
                match pinned {
                    Ok(buffer) => Some((at, buffer)),
                    Err(error) => return Ok(Err(to_wit_error(error))),
                }
            }
            (BlobMemory::Host3d, Some(_)) | (BlobMemory::Guest | BlobMemory::Host3dGuest, None) => {
                return Ok(Err(to_wit_error(Gpu3dServiceError::BlobSpanMismatch)));
            }
        };

        let blob = match client
            .create_blob(
                &context,
                BlobCreate {
                    memory: memory_kind,
                    usage: from_wit_blob_usage(usage),
                    size,
                    blob_id,
                    backing: backing.as_ref().map(|(_, buffer)| buffer.clone()),
                },
            )
            .await
        {
            Ok(blob) => blob,
            Err(error) => return Ok(Err(to_wit_error(error))),
        };

        let session = client.session();
        let recorded = accessor.with(|mut access| {
            let shown = match &backing {
                None => Ok(None),
                Some((at, buffer)) => {
                    let memory = checked_memory(&mut access);
                    access
                        .get()
                        .show_in_session(session, |views, group| {
                            views.show_buffer(memory, *at, buffer, Some(group))
                        })
                        .map(Some)
                }
            };
            let backing_view = match shown {
                Ok(view) => view,
                Err(error) => return Ok(Err(error)),
            };
            let resource = access.get().table.push(BlobHandle {
                blob,
                backing: backing_view,
                mapped: None,
            })?;
            Ok::<_, wasmtime::Error>(Ok(resource))
        })?;
        Ok(recorded.map_err(to_wit_error))
    }
}

impl<CpuImpl, Net, StorageImpl, U> gpu_wit::HostContextWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    U: 'static,
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn commands(
        accessor: &Accessor<U, Self>,
        handle: Resource<ContextHandle>,
        buffer: gpu_wit::Span,
    ) -> wasmtime::Result<Result<Resource<CommandBufferHandle>, gpu_wit::Error>> {
        let context = match accessor.with(|access| context_of(access, &handle))? {
            Ok(context) => context,
            Err(error) => return Ok(Err(error)),
        };
        let session = context.session();
        let at = span(buffer);
        accessor.with(|mut access| {
            let shown = memory_of(&mut access).and_then(|memory| {
                let data = access.get();
                let buffer = data.pin_session_buffer(memory, at, at.length)?;
                let view = data.show_in_session(session, |views, group| {
                    views.show_buffer(memory, at, &buffer, Some(group))
                })?;
                Ok((buffer, view))
            });
            let (buffer, view) = match shown {
                Ok(shown) => shown,
                Err(error) => return Ok(Err(to_wit_error(error))),
            };
            let resource = access.get().table.push(CommandBufferHandle {
                session,
                buffer,
                view,
            })?;
            Ok(Ok(resource))
        })
    }

    async fn submit(
        accessor: &Accessor<U, Self>,
        handle: Resource<ContextHandle>,
        commands: Resource<CommandBufferHandle>,
        offset: u64,
        length: u64,
        ring: u8,
        completion: Option<gpu_wit::Completion>,
    ) -> wasmtime::Result<Result<(), gpu_wit::Error>> {
        let prepared = accessor.with(|mut access| {
            let data = access.get();
            let context = data.table.get(&handle)?.context.clone();
            if !data.device.gpu().is_current(context.session()) {
                return Ok::<_, wasmtime::Error>(Err(gpu_wit::Error::SessionEnded));
            }
            let stream = match data.command_range(&commands, offset, length, context.session())? {
                Ok(stream) => stream,
                Err(error) => return Ok(Err(error)),
            };
            let completion = data.build_completion(completion.as_ref())?;
            Ok(Ok((context, stream, completion)))
        })?;
        let (context, stream, completion) = match prepared {
            Ok(values) => values,
            Err(error) => return Ok(Err(error)),
        };
        Ok(context
            .submit(ring, stream, completion)
            .await
            .map_err(to_wit_error))
    }

    async fn execute(
        accessor: &Accessor<U, Self>,
        handle: Resource<ContextHandle>,
        commands: Vec<u8>,
        ring: u8,
        completion: Option<gpu_wit::Completion>,
    ) -> wasmtime::Result<Result<(), gpu_wit::Error>> {
        let Ok(inline) = InlineCommands::try_from(commands.as_slice()) else {
            debug_assert!(commands.len() > MAX_EXECUTE_BYTES);
            return Ok(Err(gpu_wit::Error::OutOfBounds));
        };
        let prepared = accessor.with(|mut access| {
            let data = access.get();
            let context = data.table.get(&handle)?.context.clone();
            if !data.device.gpu().is_current(context.session()) {
                return Ok::<_, wasmtime::Error>(Err(gpu_wit::Error::SessionEnded));
            }
            let completion = data.build_completion(completion.as_ref())?;
            Ok(Ok((context, completion)))
        })?;
        let (context, completion) = match prepared {
            Ok(values) => values,
            Err(error) => return Ok(Err(error)),
        };
        Ok(context
            .submit(ring, SubmitCommands::Inline(inline), completion)
            .await
            .map_err(to_wit_error))
    }

    async fn wait(
        accessor: &Accessor<U, Self>,
        handle: Resource<ContextHandle>,
        ring: u8,
        fence: u64,
    ) -> wasmtime::Result<Result<(), gpu_wit::Error>> {
        let context = accessor.with(|mut access| {
            let data = access.get();
            let context = data.table.get(&handle)?.context.clone();
            if !data.device.gpu().is_current(context.session()) {
                return Ok::<_, wasmtime::Error>(Err(gpu_wit::Error::SessionEnded));
            }
            Ok(Ok(context))
        })?;
        let context = match context {
            Ok(context) => context,
            Err(error) => return Ok(Err(error)),
        };
        Ok(context.wait(ring, fence).await.map_err(to_wit_error))
    }

    fn fences(
        mut accessor: Access<'_, U, Self>,
        handle: Resource<ContextHandle>,
        ring: u8,
    ) -> wasmtime::Result<Result<StreamReader<u64>, gpu_wit::Error>> {
        let data = accessor.get();
        let context = data.table.get(&handle)?.context.clone();
        if !data.device.gpu().is_current(context.session()) {
            return Ok(Err(gpu_wit::Error::SessionEnded));
        }
        let reader = match context.fences(ring) {
            Ok(reader) => reader,
            Err(error) => return Ok(Err(to_wit_error(error))),
        };
        Ok(Ok(StreamReader::new(
            &mut accessor,
            FenceStreamProducer { reader },
        )?))
    }

    async fn attach(
        accessor: &Accessor<U, Self>,
        handle: Resource<ContextHandle>,
        resource: Resource<BlobHandle>,
    ) -> wasmtime::Result<Result<(), gpu_wit::Error>> {
        attach_or_detach(accessor, handle, resource, true).await
    }

    async fn detach(
        accessor: &Accessor<U, Self>,
        handle: Resource<ContextHandle>,
        resource: Resource<BlobHandle>,
    ) -> wasmtime::Result<Result<(), gpu_wit::Error>> {
        attach_or_detach(accessor, handle, resource, false).await
    }
}

async fn attach_or_detach<U, CpuImpl, Net, StorageImpl>(
    accessor: &Accessor<U, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>,
    handle: Resource<ContextHandle>,
    resource: Resource<BlobHandle>,
    attach: bool,
) -> wasmtime::Result<Result<(), gpu_wit::Error>>
where
    U: 'static,
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let context = match accessor.with(|access| context_of(access, &handle))? {
        Ok(context) => context,
        Err(error) => return Ok(Err(error)),
    };
    let blob = accessor.with(|mut access| -> wasmtime::Result<GpuBlob> {
        Ok(access.get().table.get(&resource)?.blob.clone())
    })?;
    let outcome = if attach {
        context.attach(&blob).await
    } else {
        context.detach(&blob).await
    };
    Ok(outcome.map_err(to_wit_error))
}

impl<CpuImpl, Net, StorageImpl, U> gpu_wit::HostBlobWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    U: 'static,
    CpuImpl: helios_hal::cpu::Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn map_blob(
        accessor: &Accessor<U, Self>,
        handle: Resource<BlobHandle>,
        at: gpu_wit::Span,
    ) -> wasmtime::Result<Result<(), gpu_wit::Error>> {
        let at = span(at);
        let checked = accessor.with(|mut access| -> wasmtime::Result<Result<GpuBlob, _>> {
            let memory = match memory_of(&mut access) {
                Ok(memory) => memory,
                Err(error) => return Ok(Err(error)),
            };
            let data = access.get();
            let entry = data.table.get(&handle)?;
            if !data.device.gpu().is_current(entry.blob.session()) {
                return Ok(Err(Gpu3dServiceError::SessionEnded));
            }
            if entry.mapped.is_some() {
                return Ok(Err(Gpu3dServiceError::AlreadyMapped));
            }
            data.check_session_span(memory, at, at.length)?;
            Ok(Ok(entry.blob.clone()))
        })?;
        let blob = match checked {
            Ok(blob) => blob,
            Err(error) => return Ok(Err(to_wit_error(error))),
        };
        let session = blob.session();
        let mapping = match blob.map().await {
            Ok(mapping) => mapping,
            Err(error) => return Ok(Err(to_wit_error(error))),
        };
        let region = mapping.region();
        let recorded = accessor.with(|mut access| {
            let memory = checked_memory(&mut access);
            let data = access.get();
            if data.table.get(&handle)?.mapped.is_some() {
                return Ok::<_, wasmtime::Error>(Err((Gpu3dServiceError::AlreadyMapped, mapping)));
            }
            let view = match data.show_in_session(session, |views, group| {
                views.show_device(memory, at, region, Some(group))
            }) {
                Ok(view) => view,
                Err(error) => return Ok(Err((error, mapping))),
            };
            data.table.get_mut(&handle)?.mapped = Some((view, mapping));
            Ok(Ok(()))
        })?;
        match recorded {
            Ok(()) => Ok(Ok(())),
            Err((error, mapping)) => {
                let _ = mapping.unmap().await;
                Ok(Err(to_wit_error(error)))
            }
        }
    }

    async fn unmap_blob(
        accessor: &Accessor<U, Self>,
        handle: Resource<BlobHandle>,
    ) -> wasmtime::Result<Result<(), gpu_wit::Error>> {
        let taken = accessor.with(
            |mut access| -> wasmtime::Result<Result<BlobMapping, gpu_wit::Error>> {
                let data = access.get();
                let session = data.table.get(&handle)?.blob.session();
                if !data.device.gpu().is_current(session) {
                    return Ok(Err(gpu_wit::Error::SessionEnded));
                }
                let Some((view, mapping)) = data.table.get_mut(&handle)?.mapped.take() else {
                    return Ok(Err(gpu_wit::Error::NotMapped));
                };
                data.views.end(view).map_err(view_trap)?;
                Ok(Ok(mapping))
            },
        )?;
        let mapping = match taken {
            Ok(mapping) => mapping,
            Err(error) => return Ok(Err(error)),
        };
        Ok(mapping.unmap().await.map_err(to_wit_error))
    }
}

#[cfg(test)]
pub(crate) mod test_store {
    use alloc::vec::Vec;

    use helios_hal::cpu::{Cpu, ProcessorId};
    use helios_hal::watchdog::ProgressCounter;
    use triomphe::Arc;
    use wasmtime::component::ResourceTable;

    use crate::component::{ComponentOutputMode, ComponentStoreData};
    use crate::gpu::{Gpu3dService, GpuContext};
    use crate::isa::GuestIsa;
    use crate::test_support::{TestCpu, TestNetworkService, UnsupportedStorage};
    use crate::{Executor, InstanceRegistry, ProcessAuthority, TaskFunding};

    use crate::wasmtime_adapter::component_host::{HostRuntimeState, StoreData};

    pub(crate) type TestStoreData = StoreData<TestCpu, TestNetworkService, UnsupportedStorage>;

    pub(crate) struct DiscardPort;

    impl helios_hal::serial::ByteSerial for DiscardPort {
        fn try_read_byte(&self) -> Option<u8> {
            None
        }

        fn write_bytes(&self, _bytes: &[u8]) {}

        fn enable_receive_interrupt(&self) {}

        fn disable_receive_interrupt(&self) {}
    }

    static DISCARD_CONSOLE: crate::DebugConsole = crate::DebugConsole::new();

    impl crate::DebugSerialAccess for DiscardPort {
        type Port = Self;

        fn port() -> Self {
            Self
        }

        fn console() -> &'static crate::DebugConsole {
            &DISCARD_CONSOLE
        }
    }

    fn read_nothing(_: &mut Vec<u8>, _: u32) {}

    pub(crate) fn context_handle(context: GpuContext) -> super::ContextHandle {
        super::ContextHandle { context }
    }

    pub(crate) fn store_data(service: &Gpu3dService) -> TestStoreData {
        store_data_with(|runtime_state| runtime_state.install_gpu3d_service(service.clone()))
    }

    pub(crate) fn store_data_with(
        configure: impl FnOnce(&HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage>),
    ) -> TestStoreData {
        store_data_authorized(ProcessAuthority::empty(), configure)
    }

    pub(crate) fn store_data_authorized(
        authority: ProcessAuthority,
        configure: impl FnOnce(&HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage>),
    ) -> TestStoreData {
        store_data_routed(authority, ComponentOutputMode::Serial, configure)
    }

    /// As [`store_data_authorized`], for an instance whose stdout and
    /// stderr go where `output_mode` says: what a stream test needs to
    /// observe the bytes a guest's write reaches its sink as.
    pub(crate) fn store_data_routed(
        authority: ProcessAuthority,
        output_mode: ComponentOutputMode,
        configure: impl FnOnce(&HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage>),
    ) -> TestStoreData {
        let cpu = TestCpu::with_entropy(0x5a);
        let runtime_state: HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage> =
            crate::RuntimeState::new(
                cpu.timebase(),
                1,
                0,
                crate::BootPayload::for_tests(),
                GuestIsa::for_build_target(cpu.native_feature_probe()),
            );
        runtime_state.install_root_entropy(Arc::new(
            crate::RootEntropy::from_platform(
                &cpu,
                None,
                None,
                crate::MachineGeneration::new(None),
            )
            .expect("the fixture CPU has an entropy source"),
        ));
        configure(&runtime_state);
        let executor = Executor::new(
            ProgressCounter::new(),
            crate::test_support::single_node_pool(1),
            ProcessorId::new(0),
        );
        let registry = InstanceRegistry::new();
        let instance = registry.register("gpu-store", 0);
        ComponentStoreData::new(
            ResourceTable::new(),
            cpu,
            executor.timer(cpu),
            executor
                .spawner(cpu)
                .instance_spawner(TaskFunding::Instance, &instance),
            runtime_state.clone(),
            registry,
            instance,
            None,
            runtime_state.root_namespace().descend(),
            Vec::new(),
            Vec::new(),
            authority,
            output_mode,
            read_nothing,
            crate::DebugSerialWriter::of::<DiscardPort>(),
        )
    }
}
