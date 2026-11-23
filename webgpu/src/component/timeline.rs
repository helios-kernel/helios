//! The device timeline: one task per device that owns wgpu-core.
//!
//! Every wgpu-core call that can reach the host (and through wgpu-hal's
//! Vulkan backend and the Venus driver, nearly every one can) runs here, in
//! the order the content timeline queued it. The task is spawned by the
//! async `request-device` export, so it runs inside that export's
//! component-model task, which may block; synchronous exports only queue.
//!
//! The task never waits for the GPU between commands. An operation that
//! completes with the queue (a mapping, `on-submitted-work-done`, device
//! destruction, a presented frame's image) submits a completion marker and
//! spawns a watcher, which queues [`Command::Completed`] once the marker
//! signals; the task then polls the device, which runs wgpu-core's
//! callbacks in order with everything else.
//!
//! Concurrency contract: one task owns this state; the content timeline
//! reaches it only through the command queue, and the queue is the only
//! wakeup. A content export runs as its own component-model task, so a
//! command it queues wakes this task through wit-bindgen's inter-task
//! wakeup stream.

use core::{mem, ops::Range};
use std::{borrow::Cow, rc::Rc};

use async_channel::{Receiver, Sender, TryRecvError, WeakSender};
use helios_api::sync::{Timeline as Marker, wait_all};
use helios_venus::helios;
use wgpu_core::{
    binding_model,
    command::PassStateError,
    device::global::{BindGroupDescriptor, BindGroupEntry, BindingResource},
    global::Global,
    id, pipeline, resource,
};
use wgpu_types::error::WebGpuError;

use super::{
    command::{
        AfterCompletion, Binding, BundleCommand, Command, Completion, ComputeCommand, Create,
        DrawCommand, EncoderCommand, Frame, Pipeline, Present, Queued, RenderCommand, Reply,
        StandIn,
    },
    ids::{IdSpace, Release},
    pipeline::pipeline_error,
    presentation::{self, LinearImage},
    scope::{ErrorSink, ErrorTarget, internal},
    value::CompilationMessage,
    wit,
};
use crate::runtime::DeviceLoss;

type Vulkan = wgpu_hal::api::Vulkan;

/// The label core reports for a stand-in, so its "invalid object" error
/// names why the object was invalid.
const STAND_IN: &str = "an object of another device";

pub struct Timeline {
    global: Rc<Global>,
    ids: Rc<IdSpace>,
    device: id::DeviceId,
    queue: id::QueueId,
    errors: ErrorSink,
    maps: Vec<PendingMap>,
    /// Filled by wgpu-core's loss callback, which runs during this
    /// timeline's polls; observers wait on clones.
    loss: DeviceLoss,
    /// The task's own queue, for completion watchers. Weak, so that the
    /// queue closes when the last content handle goes.
    commands: WeakSender<Queued>,
}

struct PendingMap {
    buffer: id::BufferId,
    range: Range<u64>,
    done: Receiver<resource::BufferAccessResult>,
    reply: Reply<Result<Vec<u8>, wit::MapAsyncError>>,
}

fn map_error(message: String) -> wit::MapAsyncError {
    wit::MapAsyncError {
        kind: wit::MapAsyncErrorKind::OperationError,
        message,
    }
}

impl Timeline {
    pub fn new(
        global: Rc<Global>,
        ids: Rc<IdSpace>,
        device: id::DeviceId,
        queue: id::QueueId,
        commands: WeakSender<Queued>,
    ) -> Self {
        let (loss, notify) = DeviceLoss::new();
        global.device_set_device_lost_closure(device, Box::new(notify));
        Self {
            global,
            ids,
            device,
            queue,
            errors: ErrorSink::default(),
            maps: Vec::new(),
            loss,
            commands,
        }
    }

    /// Execute the queue until every content handle and watcher is gone,
    /// then release the device.
    pub async fn run(mut self, commands: Receiver<Queued>) {
        while let Ok(Queued { target, command }) = commands.recv().await {
            self.execute(&target, command);
        }
        self.close();
    }

    fn close(self) {
        // Every handle's drop has executed: only the device and its queue
        // remain. Let in-flight work finish before the device goes, so the
        // last callbacks run here rather than in a destructor. A lost
        // device fails the wait; loss already reached `lost`, and no
        // handle remains to report anything else to.
        let _ = self
            .global
            .device_poll(self.device, wgpu_types::PollType::wait_indefinitely());
        self.global.queue_drop(self.queue);
        self.global.device_drop(self.device);
        self.ids.queues.release(self.queue);
        self.ids.devices.release(self.device);
    }

    fn report(&mut self, target: &ErrorTarget, error: &impl WebGpuError) {
        self.errors.native(target, error);
    }

    fn check<E: WebGpuError>(&mut self, target: &ErrorTarget, result: Result<(), E>) {
        if let Err(error) = result {
            self.report(target, &error);
        }
    }

    fn created<T, E: WebGpuError>(&mut self, target: &ErrorTarget, (_, error): (T, Option<E>)) {
        if let Some(error) = error {
            self.report(target, &error);
        }
    }

    fn execute(&mut self, target: &ErrorTarget, command: Command) {
        let device = self.device;
        let queue = self.queue;
        match command {
            Command::Error(error) => self.errors.report(target, error),
            Command::Fence(reply) => {
                let _ = reply.try_send(());
            }
            Command::Lost(reply) => {
                let _ = reply.try_send(self.loss.clone());
            }
            Command::Subscribe { events, done } => {
                self.errors.subscribe(events);
                let _ = done.try_send(());
            }
            Command::Release(release) => release.execute(&self.global, &self.ids),
            Command::StandIn(stand_in) => self.stand_in(stand_in),
            Command::Create(create) => self.create(target, create),
            Command::DestroyBuffer(id) => self.global.buffer_destroy(id),
            Command::DestroyTexture(id) => self.global.texture_destroy(id),
            Command::DestroyQuerySet(id) => self.global.query_set_destroy(id),
            Command::Map {
                buffer,
                host,
                range,
                reply,
            } => self.map(target, buffer, host, range, reply),
            Command::Unmap { buffer, write_back } => self.unmap(target, buffer, write_back),
            Command::Submit(buffers) => {
                let result = self.global.queue_submit(queue, &buffers);
                self.check(target, result.map(drop).map_err(|(_, error)| error));
            }
            Command::WriteBuffer {
                buffer,
                offset,
                data,
            } => {
                let result = self
                    .global
                    .queue_write_buffer(queue, buffer, offset, data.as_slice());
                self.check(target, result);
            }
            Command::WriteTexture {
                destination,
                data,
                layout,
                size,
            } => {
                let result =
                    self.global
                        .queue_write_texture(queue, &destination, &data, &layout, &size);
                self.check(target, result);
            }
            Command::WorkDone(reply) => {
                // wgpu-core stages queue writes until a submission; an empty
                // one makes those writes precede the marker.
                self.flush(target);
                self.global.queue_on_submitted_work_done(
                    queue,
                    Box::new(move || {
                        let _ = reply.try_send(());
                    }),
                );
                self.watch(target, AfterCompletion::Poll);
            }
            Command::Encoder(encoder, command) => self.encode(target, encoder, command),
            Command::ComputePass(pass, command) => self.compute(target, pass, command),
            Command::RenderPass(pass, command) => self.render(target, pass, command),
            Command::Bundle(bundle, command) => self.bundle(target, bundle, command),
            Command::Present(present) => self.present(target, present),
            Command::Destroy(reply) => {
                // The marker goes in before destruction retires the queue.
                let marker = self.completion();
                self.global.device_destroy(device);
                match marker {
                    Ok(marker) => self.watch_on(target, marker, AfterCompletion::Destroyed(reply)),
                    Err(error) => {
                        self.errors.report(target, internal(error.to_string()));
                        self.complete_now(target, AfterCompletion::Destroyed(reply));
                    }
                }
            }
            Command::Completed(Completion { waited, then }) => {
                match waited {
                    Ok(true) => {}
                    Ok(false) => unreachable!("completion waits carry no deadline"),
                    Err(error) => self.errors.report(target, internal(error.to_string())),
                }
                self.maintain(target);
                self.after(then);
            }
        }
    }

    /// Submit nothing, so staged queue writes reach the queue.
    fn flush(&mut self, target: &ErrorTarget) {
        let result = self.global.queue_submit(self.queue, &[]);
        self.check(target, result.map(drop).map_err(|(_, error)| error));
    }

    /// A marker that signals once the queue has finished all prior work.
    fn completion(&self) -> Result<Marker, ash::vk::Result> {
        // SAFETY: the device was opened through the Venus Vulkan driver. The
        // queue guard is dropped before this returns, before any await.
        let raw = unsafe { self.global.queue_as_hal::<Vulkan>(self.queue) }
            .expect("Helios WebGPU queues use Vulkan");
        // SAFETY: `raw` is a live queue of the Venus entry table.
        unsafe { helios::queue_completion(raw.as_raw()) }
    }

    fn watch(&mut self, target: &ErrorTarget, then: AfterCompletion) {
        match self.completion() {
            Ok(marker) => self.watch_on(target, marker, then),
            Err(error) => {
                self.errors.report(target, internal(error.to_string()));
                self.complete_now(target, then);
            }
        }
    }

    fn watch_on(&mut self, target: &ErrorTarget, marker: Marker, then: AfterCompletion) {
        match self.commands.upgrade() {
            Some(commands) => {
                helios_api::task::spawn(watch(marker, commands, target.clone(), then));
            }
            // No content handle remains to queue behind: nothing observes
            // the answer, but the work it retires must still finish first.
            None => self.complete_now(target, then),
        }
    }

    fn complete_now(&mut self, target: &ErrorTarget, then: AfterCompletion) {
        let polled = self
            .global
            .device_poll(self.device, wgpu_types::PollType::wait_indefinitely());
        self.polled(target, polled);
        self.after(then);
    }

    /// Report a failed poll. A device error keeps its WebGPU class (loss
    /// reaches `lost` instead); a failed wait has none and is internal.
    fn polled(
        &mut self,
        target: &ErrorTarget,
        polled: Result<wgpu_types::PollStatus, wgpu_core::device::WaitIdleError>,
    ) {
        match polled {
            Ok(_) => {}
            Err(wgpu_core::device::WaitIdleError::Device(error)) => self.report(target, &error),
            Err(error) => self.errors.report(target, internal(error.to_string())),
        }
        self.settle_maps();
    }

    fn after(&mut self, then: AfterCompletion) {
        match then {
            AfterCompletion::Poll => {}
            AfterCompletion::Destroyed(reply) => {
                let _ = reply.try_send(());
            }
            AfterCompletion::Retire(image) => drop(image),
        }
    }

    /// Run wgpu-core's completed callbacks and answer settled mappings.
    fn maintain(&mut self, target: &ErrorTarget) {
        let polled = self
            .global
            .device_poll(self.device, wgpu_types::PollType::Poll);
        self.polled(target, polled);
    }

    fn map(
        &mut self,
        target: &ErrorTarget,
        buffer: id::BufferId,
        host: wgpu_core::device::HostMap,
        range: Range<u64>,
        reply: Reply<Result<Vec<u8>, wit::MapAsyncError>>,
    ) {
        let (signal, done) = async_channel::bounded(1);
        let operation = resource::BufferMapOperation {
            host,
            callback: Some(Box::new(move |result| {
                let _ = signal.try_send(result);
            })),
        };
        match self.global.buffer_map_async(
            buffer,
            range.start,
            Some(range.end - range.start),
            operation,
        ) {
            Ok(_) => {
                self.maps.push(PendingMap {
                    buffer,
                    range,
                    done,
                    reply,
                });
                self.flush(target);
                self.watch(target, AfterCompletion::Poll);
            }
            Err(error) => {
                self.report(target, &error);
                let _ = reply.try_send(Err(map_error(error.to_string())));
            }
        }
    }

    fn settle_maps(&mut self) {
        for map in mem::take(&mut self.maps) {
            let answer = match map.done.try_recv() {
                Err(TryRecvError::Empty) => {
                    self.maps.push(map);
                    continue;
                }
                Ok(Ok(())) => self.read_mapped(map.buffer, map.range),
                Ok(Err(error)) => Err(map_error(error.to_string())),
                Err(TryRecvError::Closed) => Err(map_error(
                    "wgpu dropped a mapping callback without a result".into(),
                )),
            };
            let _ = map.reply.try_send(answer);
        }
    }

    /// Copy a settled mapping for the content timeline, which answers
    /// mapped-range calls from its copy.
    fn read_mapped(
        &self,
        buffer: id::BufferId,
        range: Range<u64>,
    ) -> Result<Vec<u8>, wit::MapAsyncError> {
        let (pointer, length) = self
            .global
            .buffer_get_mapped_range(buffer, range.start, Some(range.end - range.start))
            .map_err(|error| map_error(error.to_string()))?;
        let length = usize::try_from(length).map_err(|error| map_error(error.to_string()))?;
        let mut data = Vec::new();
        data.try_reserve_exact(length)
            .map_err(|error| map_error(error.to_string()))?;
        // SAFETY: core validated the mapped range, and nothing on this
        // timeline can unmap the buffer during this synchronous copy.
        // Reservation establishes the length is addressable.
        data.extend_from_slice(unsafe { core::slice::from_raw_parts(pointer.as_ptr(), length) });
        Ok(data)
    }

    fn unmap(
        &mut self,
        target: &ErrorTarget,
        buffer: id::BufferId,
        write_back: Option<(u64, Vec<u8>)>,
    ) {
        if let Some((offset, data)) = write_back {
            match self
                .global
                .buffer_get_mapped_range(buffer, offset, Some(data.len() as u64))
            {
                // SAFETY: core validated the range for `data.len()` bytes;
                // the content copy and the mapping are distinct allocations.
                Ok((pointer, _)) => unsafe {
                    core::ptr::copy_nonoverlapping(data.as_ptr(), pointer.as_ptr(), data.len());
                },
                // A buffer core never created was reported at creation;
                // WebGPU's unmap reports nothing more for it.
                Err(resource::BufferAccessError::InvalidResource(_)) => return,
                Err(error) => self.report(target, &error),
            }
        }
        match self.global.buffer_unmap(buffer) {
            Ok(()) | Err(resource::BufferAccessError::InvalidResource(_)) => {}
            Err(error) => self.report(target, &error),
        }
        // Unmapping a pending mapping aborts it through its callback.
        self.settle_maps();
    }

    fn create(&mut self, target: &ErrorTarget, create: Create) {
        let global = Rc::clone(&self.global);
        let device = self.device;
        match create {
            Create::Buffer { id, descriptor } => {
                let created = global.device_create_buffer(device, &descriptor, Some(id));
                self.created(target, created);
            }
            Create::Texture { id, descriptor } => {
                let created = global.device_create_texture(device, &descriptor, Some(id));
                self.created(target, created);
            }
            Create::ChildTexture {
                parent,
                id,
                descriptor,
            } => {
                let created = global.texture_create_child(parent, &descriptor, Some(id));
                self.created(target, created);
            }
            Create::TextureView {
                texture,
                id,
                descriptor,
            } => {
                let created = global.texture_create_view(texture, &descriptor, Some(id));
                self.created(target, created);
            }
            Create::Sampler { id, descriptor } => {
                let created = global.device_create_sampler(device, &descriptor, Some(id));
                self.created(target, created);
            }
            Create::BindGroupLayout { id, descriptor } => {
                let created = global.device_create_bind_group_layout(device, &descriptor, Some(id));
                self.created(target, created);
            }
            Create::InvalidBindGroupLayout { id, label } => {
                global.create_bind_group_layout_error(device, Some(id), label.map(Cow::Owned));
            }
            Create::PipelineLayout { id, descriptor } => {
                let created = global.device_create_pipeline_layout(device, &descriptor, Some(id));
                self.created(target, created);
            }
            Create::BindGroup {
                id,
                label,
                layout,
                entries,
            } => self.create_bind_group(target, id, label, layout, entries),
            Create::ShaderModule {
                id,
                label,
                code,
                diagnostics,
            } => {
                let (_, error) = global.device_create_shader_module(
                    device,
                    &pipeline::ShaderModuleDescriptor {
                        label: label.map(Cow::Owned),
                        runtime_checks: wgpu_types::ShaderRuntimeChecks::default(),
                    },
                    pipeline::ShaderModuleSource::Wgsl(Cow::Borrowed(&code)),
                    Some(id),
                );
                let messages = match error {
                    Some(error) => {
                        self.report(target, &error);
                        wgpu::CompilationInfo::from(error)
                            .messages
                            .into_iter()
                            .map(|message| CompilationMessage::from_wgpu(message, &code))
                            .collect()
                    }
                    None => Vec::new(),
                };
                diagnostics
                    .set(messages)
                    .unwrap_or_else(|_| unreachable!("a shader module is created once"));
            }
            Create::ComputePipeline {
                id,
                descriptor,
                reply,
            } => {
                let (_, error) =
                    global.device_create_compute_pipeline(device, &descriptor, Some(id));
                self.pipeline_created(target, error, reply);
            }
            Create::RenderPipeline {
                id,
                descriptor,
                reply,
            } => {
                let (_, error) =
                    global.device_create_render_pipeline(device, &descriptor, Some(id));
                self.pipeline_created(target, error, reply);
            }
            Create::PipelineBindGroupLayout {
                pipeline,
                index,
                id,
            } => {
                let created = match pipeline {
                    Pipeline::Compute(pipeline) => {
                        global.compute_pipeline_get_bind_group_layout(pipeline, index, Some(id))
                    }
                    Pipeline::Render(pipeline) => {
                        global.render_pipeline_get_bind_group_layout(pipeline, index, Some(id))
                    }
                };
                self.created(target, created);
            }
            Create::CommandEncoder { id, label } => {
                let created = global.device_create_command_encoder(
                    device,
                    &wgpu_types::CommandEncoderDescriptor {
                        label: label.map(Cow::Owned),
                    },
                    Some(id),
                );
                self.created(target, created);
            }
            Create::RenderBundleEncoder { id, descriptor } => {
                let created = global.device_create_render_bundle_encoder_with_id(
                    device,
                    &descriptor,
                    Some(id),
                );
                self.created(target, created);
            }
            Create::QuerySet { id, descriptor } => {
                let created = global.device_create_query_set(device, &descriptor, Some(id));
                self.created(target, created);
            }
        }
    }

    fn pipeline_created<E: WebGpuError>(
        &mut self,
        target: &ErrorTarget,
        error: Option<E>,
        reply: Option<Reply<Result<(), wit::CreatePipelineError>>>,
    ) {
        match (reply, error) {
            (Some(reply), error) => {
                let _ = reply.try_send(error.map_or(Ok(()), |error| Err(pipeline_error(error))));
            }
            (None, Some(error)) => self.report(target, &error),
            (None, None) => {}
        }
    }

    fn create_bind_group(
        &mut self,
        target: &ErrorTarget,
        id: id::BindGroupId,
        label: Option<String>,
        layout: id::BindGroupLayoutId,
        entries: Vec<(u32, Binding)>,
    ) {
        let global = Rc::clone(&self.global);
        let mut views = Vec::new();
        let mut resolved = Vec::with_capacity(entries.len());
        for (binding, resource) in entries {
            let resource = match resource {
                Binding::Resource(resource) => resource,
                Binding::DefaultView(texture) => {
                    let view = self.ids.texture_views.allocate();
                    let created =
                        global.texture_create_view(texture, &Default::default(), Some(view));
                    self.created(target, created);
                    views.push(view);
                    BindingResource::TextureView(view)
                }
            };
            resolved.push(BindGroupEntry { binding, resource });
        }
        let created = global.device_create_bind_group(
            self.device,
            &BindGroupDescriptor {
                label: label.map(Cow::Owned),
                layout,
                entries: Cow::Owned(resolved),
            },
            Some(id),
        );
        self.created(target, created);
        // The bind group holds the default views it was created with.
        for view in views {
            Release::TextureView(view).execute(&global, &self.ids);
        }
    }

    /// Create a stand-in. Its creation fails by construction and is
    /// reported nowhere; core keeps the invalid object under the id.
    fn stand_in(&mut self, stand_in: StandIn) {
        let global = Rc::clone(&self.global);
        let device = self.device;
        let label = || Some(Cow::Borrowed(STAND_IN));
        let texture = |ids: &IdSpace| {
            let id = ids.textures.allocate();
            global.create_texture_error(device, Some(id), &invalid_texture());
            id
        };
        let layout = |ids: &IdSpace| {
            let id = ids.bind_group_layouts.allocate();
            global.create_bind_group_layout_error(device, Some(id), label());
            id
        };
        let module = |ids: &IdSpace| {
            let id = ids.shader_modules.allocate();
            // "@" opens an attribute with no name: WGSL rejects it.
            let _ = global.device_create_shader_module(
                device,
                &pipeline::ShaderModuleDescriptor {
                    label: label(),
                    runtime_checks: wgpu_types::ShaderRuntimeChecks::default(),
                },
                pipeline::ShaderModuleSource::Wgsl(Cow::Borrowed("@")),
                Some(id),
            );
            id
        };
        let stage = |module| pipeline::ProgrammableStageDescriptor {
            module,
            entry_point: None,
            constants: Default::default(),
            zero_initialize_workgroup_memory: true,
        };
        let ids = &*self.ids;
        match stand_in {
            StandIn::Buffer(id) => global.create_buffer_error(
                device,
                Some(id),
                &wgpu_types::BufferDescriptor {
                    label: label(),
                    size: 0,
                    usage: wgpu_types::BufferUsages::empty(),
                    mapped_at_creation: false,
                },
            ),
            StandIn::Texture(id) => {
                global.create_texture_error(device, Some(id), &invalid_texture());
            }
            StandIn::TextureView(id) => {
                let texture = texture(ids);
                let _ = global.texture_create_view(
                    texture,
                    &resource::TextureViewDescriptor {
                        label: label(),
                        ..Default::default()
                    },
                    Some(id),
                );
                Release::Texture(texture).execute(&global, ids);
            }
            StandIn::Sampler(id) => {
                // WebGPU requires lodMinClamp >= 0.
                let _ = global.device_create_sampler(
                    device,
                    &resource::SamplerDescriptor {
                        label: label(),
                        lod_min_clamp: -1.0,
                        ..invalid_sampler()
                    },
                    Some(id),
                );
            }
            StandIn::BindGroupLayout(id) => {
                global.create_bind_group_layout_error(device, Some(id), label());
            }
            StandIn::PipelineLayout(id) => {
                let layout = layout(ids);
                let _ = global.device_create_pipeline_layout(
                    device,
                    &binding_model::PipelineLayoutDescriptor {
                        label: label(),
                        bind_group_layouts: Cow::Owned(vec![Some(layout)]),
                        immediate_size: 0,
                    },
                    Some(id),
                );
                Release::BindGroupLayout(layout).execute(&global, ids);
            }
            StandIn::BindGroup(id) => {
                let layout = layout(ids);
                let _ = global.device_create_bind_group(
                    device,
                    &BindGroupDescriptor {
                        label: label(),
                        layout,
                        entries: Cow::Owned(Vec::new()),
                    },
                    Some(id),
                );
                Release::BindGroupLayout(layout).execute(&global, ids);
            }
            StandIn::ShaderModule(id) => {
                let _ = global.device_create_shader_module(
                    device,
                    &pipeline::ShaderModuleDescriptor {
                        label: label(),
                        runtime_checks: wgpu_types::ShaderRuntimeChecks::default(),
                    },
                    pipeline::ShaderModuleSource::Wgsl(Cow::Borrowed("@")),
                    Some(id),
                );
            }
            StandIn::ComputePipeline(id) => {
                let module = module(ids);
                let _ = global.device_create_compute_pipeline(
                    device,
                    &pipeline::ComputePipelineDescriptor {
                        label: label(),
                        layout: None,
                        stage: stage(module),
                        cache: None,
                    },
                    Some(id),
                );
                Release::ShaderModule(module).execute(&global, ids);
            }
            StandIn::RenderPipeline(id) => {
                let module = module(ids);
                let _ = global.device_create_render_pipeline(
                    device,
                    &pipeline::RenderPipelineDescriptor {
                        label: label(),
                        layout: None,
                        vertex: pipeline::VertexState {
                            stage: stage(module),
                            buffers: Cow::Owned(Vec::new()),
                        },
                        primitive: Default::default(),
                        depth_stencil: None,
                        multisample: Default::default(),
                        fragment: None,
                        multiview_mask: None,
                        cache: None,
                    },
                    Some(id),
                );
                Release::ShaderModule(module).execute(&global, ids);
            }
            StandIn::QuerySet(id) => {
                let _ = global.device_create_query_set(
                    device,
                    &wgpu_types::QuerySetDescriptor {
                        label: label(),
                        ty: wgpu_types::QueryType::Occlusion,
                        count: wgpu_types::QUERY_SET_MAX_QUERIES + 1,
                    },
                    Some(id),
                );
            }
            StandIn::RenderBundle(id) => global.create_render_bundle_error(
                device,
                Some(id),
                &wgpu_types::RenderBundleDescriptor { label: label() },
            ),
        }
    }

    fn encode(
        &mut self,
        target: &ErrorTarget,
        encoder: id::CommandEncoderId,
        command: EncoderCommand,
    ) {
        let global = Rc::clone(&self.global);
        let result = match command {
            EncoderCommand::PushDebugGroup(label) => {
                global.command_encoder_push_debug_group(encoder, &label)
            }
            EncoderCommand::PopDebugGroup => global.command_encoder_pop_debug_group(encoder),
            EncoderCommand::InsertDebugMarker(label) => {
                global.command_encoder_insert_debug_marker(encoder, &label)
            }
            EncoderCommand::BeginComputePass { id, descriptor } => {
                let created = global.command_encoder_begin_compute_pass_with_id(
                    encoder,
                    &descriptor,
                    Some(id),
                );
                return self.created(target, created);
            }
            EncoderCommand::BeginRenderPass { id, descriptor } => {
                let created = global.command_encoder_begin_render_pass_with_id(
                    encoder,
                    &descriptor,
                    Some(id),
                );
                return self.created(target, created);
            }
            EncoderCommand::CopyBufferToBuffer {
                source,
                source_offset,
                destination,
                destination_offset,
                size,
            } => global.command_encoder_copy_buffer_to_buffer(
                encoder,
                source,
                source_offset,
                destination,
                destination_offset,
                size,
            ),
            EncoderCommand::CopyBufferToTexture {
                source,
                destination,
                size,
            } => {
                global.command_encoder_copy_buffer_to_texture(encoder, &source, &destination, &size)
            }
            EncoderCommand::CopyTextureToBuffer {
                source,
                destination,
                size,
            } => {
                global.command_encoder_copy_texture_to_buffer(encoder, &source, &destination, &size)
            }
            EncoderCommand::CopyTextureToTexture {
                source,
                destination,
                size,
            } => global.command_encoder_copy_texture_to_texture(
                encoder,
                &source,
                &destination,
                &size,
            ),
            EncoderCommand::ClearBuffer {
                buffer,
                offset,
                size,
            } => global.command_encoder_clear_buffer(encoder, buffer, offset, size),
            EncoderCommand::ResolveQuerySet {
                query_set,
                first,
                count,
                destination,
                offset,
            } => global.command_encoder_resolve_query_set(
                encoder,
                query_set,
                first,
                count,
                destination,
                offset,
            ),
            EncoderCommand::Finish { id, label } => {
                let (_, error) = global.command_encoder_finish(
                    encoder,
                    &wgpu_types::CommandBufferDescriptor {
                        label: label.map(Cow::Owned),
                    },
                    Some(id),
                );
                if let Some((_, error)) = error {
                    self.report(target, &error);
                }
                return;
            }
        };
        self.check(target, result);
    }

    fn compute(
        &mut self,
        target: &ErrorTarget,
        pass: id::ComputePassEncoderId,
        command: ComputeCommand,
    ) {
        let global = Rc::clone(&self.global);
        let result = match command {
            ComputeCommand::End => {
                let result = global.compute_pass_end_with_id(pass);
                return self.check(target, result);
            }
            ComputeCommand::PushDebugGroup(label) => {
                global.compute_pass_push_debug_group_with_id(pass, &label, 0)
            }
            ComputeCommand::PopDebugGroup => global.compute_pass_pop_debug_group_with_id(pass),
            ComputeCommand::InsertDebugMarker(label) => {
                global.compute_pass_insert_debug_marker_with_id(pass, &label, 0)
            }
            ComputeCommand::SetPipeline(pipeline) => {
                global.compute_pass_set_pipeline_with_id(pass, pipeline)
            }
            ComputeCommand::Dispatch([x, y, z]) => {
                global.compute_pass_dispatch_workgroups_with_id(pass, x, y, z)
            }
            ComputeCommand::DispatchIndirect { buffer, offset } => {
                global.compute_pass_dispatch_workgroups_indirect_with_id(pass, buffer, offset)
            }
            ComputeCommand::SetBindGroup {
                index,
                group,
                offsets,
            } => global.compute_pass_set_bind_group_with_id(pass, index, group, &offsets),
            ComputeCommand::SetImmediates { offset, data } => {
                global.compute_pass_set_immediates_with_id(pass, offset, data.as_slice())
            }
        };
        self.check(target, result);
    }

    fn render(
        &mut self,
        target: &ErrorTarget,
        pass: id::RenderPassEncoderId,
        command: RenderCommand,
    ) {
        let global = Rc::clone(&self.global);
        let result = match command {
            RenderCommand::End => {
                let result = global.render_pass_end_with_id(pass);
                return self.check(target, result);
            }
            RenderCommand::Draw(command) => draw(&global, pass, command),
            RenderCommand::SetViewport {
                x,
                y,
                width,
                height,
                min_depth,
                max_depth,
            } => global
                .render_pass_set_viewport_with_id(pass, x, y, width, height, min_depth, max_depth),
            RenderCommand::SetScissorRect {
                x,
                y,
                width,
                height,
            } => global.render_pass_set_scissor_rect_with_id(pass, x, y, width, height),
            RenderCommand::SetBlendConstant(color) => {
                global.render_pass_set_blend_constant_with_id(pass, color)
            }
            RenderCommand::SetStencilReference(reference) => {
                global.render_pass_set_stencil_reference_with_id(pass, reference)
            }
            RenderCommand::BeginOcclusionQuery(index) => {
                global.render_pass_begin_occlusion_query_with_id(pass, index)
            }
            RenderCommand::EndOcclusionQuery => {
                global.render_pass_end_occlusion_query_with_id(pass)
            }
            RenderCommand::ExecuteBundles(bundles) => {
                global.render_pass_execute_bundles_with_id(pass, &bundles)
            }
        };
        self.check(target, result);
    }

    fn bundle(
        &mut self,
        target: &ErrorTarget,
        bundle: id::RenderBundleEncoderId,
        command: BundleCommand,
    ) {
        let global = Rc::clone(&self.global);
        match command {
            BundleCommand::Draw(command) => {
                let result = draw(&global, bundle, command);
                self.check(target, result);
            }
            BundleCommand::Finish { id, label, invalid } => {
                let descriptor = wgpu_types::RenderBundleDescriptor {
                    label: label.map(Cow::Owned),
                };
                if invalid {
                    global.create_render_bundle_error(self.device, Some(id), &descriptor);
                } else {
                    let created =
                        global.render_bundle_encoder_finish_with_id(bundle, &descriptor, Some(id));
                    self.created(target, created);
                }
            }
        }
    }

    fn present(&mut self, target: &ErrorTarget, present: Present) {
        let Present {
            parent,
            width,
            height,
            format,
            reply,
        } = present;
        let answer = (|| {
            let (image, exported) =
                LinearImage::allocate(&self.global, self.device, width, height, format)?;
            // SAFETY: the content timeline created `parent` on this device
            // as the canvas drawing buffer: this image's extent and format,
            // one mip, layer and sample, COPY_SRC | RENDER_ATTACHMENT. This
            // task is the only one recording or submitting on the device.
            let submitted =
                unsafe { image.submit(&self.global, &self.ids, self.device, self.queue, parent) };
            // A submit error may surface after native submission, so the
            // image is retired behind a marker either way.
            let ready = self.completion();
            self.watch(target, AfterCompletion::Retire(Box::new(image)));
            submitted?;
            Ok(Frame {
                image: exported,
                ready: ready.map_err(presentation::Error::Completion)?,
            })
        })();
        let _ = reply.try_send(answer);
    }
}

async fn watch(
    marker: Marker,
    commands: Sender<Queued>,
    target: ErrorTarget,
    then: AfterCompletion,
) {
    let waited = wait_all(&[marker.point(1)], None).await;
    // The watcher holds a sender, so the queue is open.
    let _ = commands.try_send(Queued {
        target,
        command: Command::Completed(Completion { waited, then }),
    });
}

fn invalid_texture() -> resource::TextureDescriptor<'static> {
    resource::TextureDescriptor {
        label: Some(Cow::Borrowed(STAND_IN)),
        size: wgpu_types::Extent3d::default(),
        mip_level_count: 1,
        sample_count: 1,
        dimension: wgpu_types::TextureDimension::D2,
        format: wgpu_types::TextureFormat::Rgba8Unorm,
        usage: wgpu_types::TextureUsages::empty(),
        view_formats: Vec::new(),
    }
}

fn invalid_sampler() -> resource::SamplerDescriptor<'static> {
    let defaults = wgpu_types::SamplerDescriptor::<Option<&str>>::default();
    resource::SamplerDescriptor {
        label: None,
        address_modes: [
            defaults.address_mode_u,
            defaults.address_mode_v,
            defaults.address_mode_w,
        ],
        mag_filter: defaults.mag_filter,
        min_filter: defaults.min_filter,
        mipmap_filter: defaults.mipmap_filter,
        lod_min_clamp: defaults.lod_min_clamp,
        lod_max_clamp: defaults.lod_max_clamp,
        compare: defaults.compare,
        anisotropy_clamp: defaults.anisotropy_clamp,
        border_color: None,
    }
}

/// The recording target of [`DrawCommand`]s: a render pass or a render
/// bundle encoder, each named by its id.
trait DrawTarget: Copy {
    fn push_debug_group(self, global: &Global, label: &str) -> Result<(), PassStateError>;
    fn pop_debug_group(self, global: &Global) -> Result<(), PassStateError>;
    fn insert_debug_marker(self, global: &Global, label: &str) -> Result<(), PassStateError>;
    fn set_pipeline(
        self,
        global: &Global,
        pipeline: id::RenderPipelineId,
    ) -> Result<(), PassStateError>;
    fn set_bind_group(
        self,
        global: &Global,
        index: u32,
        group: Option<id::BindGroupId>,
        offsets: &[u32],
    ) -> Result<(), PassStateError>;
    fn set_immediates(
        self,
        global: &Global,
        offset: u32,
        data: &[u8],
    ) -> Result<(), PassStateError>;
    fn set_index_buffer(
        self,
        global: &Global,
        buffer: id::BufferId,
        format: wgpu_types::IndexFormat,
        offset: u64,
        size: Option<u64>,
    ) -> Result<(), PassStateError>;
    fn set_vertex_buffer(
        self,
        global: &Global,
        slot: u32,
        buffer: Option<id::BufferId>,
        offset: u64,
        size: Option<u64>,
    ) -> Result<(), PassStateError>;
    fn draw(
        self,
        global: &Global,
        vertices: u32,
        instances: u32,
        first_vertex: u32,
        first_instance: u32,
    ) -> Result<(), PassStateError>;
    fn draw_indexed(
        self,
        global: &Global,
        indices: u32,
        instances: u32,
        first_index: u32,
        base_vertex: i32,
        first_instance: u32,
    ) -> Result<(), PassStateError>;
    fn draw_indirect(
        self,
        global: &Global,
        buffer: id::BufferId,
        offset: u64,
    ) -> Result<(), PassStateError>;
    fn draw_indexed_indirect(
        self,
        global: &Global,
        buffer: id::BufferId,
        offset: u64,
    ) -> Result<(), PassStateError>;
}

/// Debug markers carry no color in WebGPU.
const NO_COLOR: u32 = 0;

impl DrawTarget for id::RenderPassEncoderId {
    fn push_debug_group(self, global: &Global, label: &str) -> Result<(), PassStateError> {
        global.render_pass_push_debug_group_with_id(self, label, NO_COLOR)
    }
    fn pop_debug_group(self, global: &Global) -> Result<(), PassStateError> {
        global.render_pass_pop_debug_group_with_id(self)
    }
    fn insert_debug_marker(self, global: &Global, label: &str) -> Result<(), PassStateError> {
        global.render_pass_insert_debug_marker_with_id(self, label, NO_COLOR)
    }
    fn set_pipeline(
        self,
        global: &Global,
        pipeline: id::RenderPipelineId,
    ) -> Result<(), PassStateError> {
        global.render_pass_set_pipeline_with_id(self, pipeline)
    }
    fn set_bind_group(
        self,
        global: &Global,
        index: u32,
        group: Option<id::BindGroupId>,
        offsets: &[u32],
    ) -> Result<(), PassStateError> {
        global.render_pass_set_bind_group_with_id(self, index, group, offsets)
    }
    fn set_immediates(
        self,
        global: &Global,
        offset: u32,
        data: &[u8],
    ) -> Result<(), PassStateError> {
        global.render_pass_set_immediates_with_id(self, offset, data)
    }
    fn set_index_buffer(
        self,
        global: &Global,
        buffer: id::BufferId,
        format: wgpu_types::IndexFormat,
        offset: u64,
        size: Option<u64>,
    ) -> Result<(), PassStateError> {
        global.render_pass_set_index_buffer_with_id(self, buffer, format, offset, size)
    }
    fn set_vertex_buffer(
        self,
        global: &Global,
        slot: u32,
        buffer: Option<id::BufferId>,
        offset: u64,
        size: Option<u64>,
    ) -> Result<(), PassStateError> {
        global.render_pass_set_vertex_buffer_with_id(self, slot, buffer, offset, size)
    }
    fn draw(
        self,
        global: &Global,
        vertices: u32,
        instances: u32,
        first_vertex: u32,
        first_instance: u32,
    ) -> Result<(), PassStateError> {
        global.render_pass_draw_with_id(self, vertices, instances, first_vertex, first_instance)
    }
    fn draw_indexed(
        self,
        global: &Global,
        indices: u32,
        instances: u32,
        first_index: u32,
        base_vertex: i32,
        first_instance: u32,
    ) -> Result<(), PassStateError> {
        global.render_pass_draw_indexed_with_id(
            self,
            indices,
            instances,
            first_index,
            base_vertex,
            first_instance,
        )
    }
    fn draw_indirect(
        self,
        global: &Global,
        buffer: id::BufferId,
        offset: u64,
    ) -> Result<(), PassStateError> {
        global.render_pass_draw_indirect_with_id(self, buffer, offset)
    }
    fn draw_indexed_indirect(
        self,
        global: &Global,
        buffer: id::BufferId,
        offset: u64,
    ) -> Result<(), PassStateError> {
        global.render_pass_draw_indexed_indirect_with_id(self, buffer, offset)
    }
}

impl DrawTarget for id::RenderBundleEncoderId {
    fn push_debug_group(self, global: &Global, label: &str) -> Result<(), PassStateError> {
        global.render_bundle_encoder_push_debug_group_with_id(self, label)
    }
    fn pop_debug_group(self, global: &Global) -> Result<(), PassStateError> {
        global.render_bundle_encoder_pop_debug_group_with_id(self)
    }
    fn insert_debug_marker(self, global: &Global, label: &str) -> Result<(), PassStateError> {
        global.render_bundle_encoder_insert_debug_marker_with_id(self, label)
    }
    fn set_pipeline(
        self,
        global: &Global,
        pipeline: id::RenderPipelineId,
    ) -> Result<(), PassStateError> {
        global.render_bundle_encoder_set_pipeline_with_id(self, pipeline)
    }
    fn set_bind_group(
        self,
        global: &Global,
        index: u32,
        group: Option<id::BindGroupId>,
        offsets: &[u32],
    ) -> Result<(), PassStateError> {
        global.render_bundle_encoder_set_bind_group_with_id(self, index, group, offsets)
    }
    fn set_immediates(
        self,
        global: &Global,
        offset: u32,
        data: &[u8],
    ) -> Result<(), PassStateError> {
        global.render_bundle_encoder_set_immediates_with_id(self, offset, data)
    }
    fn set_index_buffer(
        self,
        global: &Global,
        buffer: id::BufferId,
        format: wgpu_types::IndexFormat,
        offset: u64,
        size: Option<u64>,
    ) -> Result<(), PassStateError> {
        global.render_bundle_encoder_set_index_buffer_with_id(self, buffer, format, offset, size)
    }
    fn set_vertex_buffer(
        self,
        global: &Global,
        slot: u32,
        buffer: Option<id::BufferId>,
        offset: u64,
        size: Option<u64>,
    ) -> Result<(), PassStateError> {
        global.render_bundle_encoder_set_vertex_buffer_with_id(self, slot, buffer, offset, size)
    }
    fn draw(
        self,
        global: &Global,
        vertices: u32,
        instances: u32,
        first_vertex: u32,
        first_instance: u32,
    ) -> Result<(), PassStateError> {
        global.render_bundle_encoder_draw_with_id(
            self,
            vertices,
            instances,
            first_vertex,
            first_instance,
        )
    }
    fn draw_indexed(
        self,
        global: &Global,
        indices: u32,
        instances: u32,
        first_index: u32,
        base_vertex: i32,
        first_instance: u32,
    ) -> Result<(), PassStateError> {
        global.render_bundle_encoder_draw_indexed_with_id(
            self,
            indices,
            instances,
            first_index,
            base_vertex,
            first_instance,
        )
    }
    fn draw_indirect(
        self,
        global: &Global,
        buffer: id::BufferId,
        offset: u64,
    ) -> Result<(), PassStateError> {
        global.render_bundle_encoder_draw_indirect_with_id(self, buffer, offset)
    }
    fn draw_indexed_indirect(
        self,
        global: &Global,
        buffer: id::BufferId,
        offset: u64,
    ) -> Result<(), PassStateError> {
        global.render_bundle_encoder_draw_indexed_indirect_with_id(self, buffer, offset)
    }
}

fn draw(
    global: &Global,
    target: impl DrawTarget,
    command: DrawCommand,
) -> Result<(), PassStateError> {
    match command {
        DrawCommand::PushDebugGroup(label) => target.push_debug_group(global, &label),
        DrawCommand::PopDebugGroup => target.pop_debug_group(global),
        DrawCommand::InsertDebugMarker(label) => target.insert_debug_marker(global, &label),
        DrawCommand::SetPipeline(pipeline) => target.set_pipeline(global, pipeline),
        DrawCommand::SetBindGroup {
            index,
            group,
            offsets,
        } => target.set_bind_group(global, index, group, &offsets),
        DrawCommand::SetImmediates { offset, data } => {
            target.set_immediates(global, offset, data.as_slice())
        }
        DrawCommand::SetIndexBuffer {
            buffer,
            format,
            offset,
            size,
        } => target.set_index_buffer(global, buffer, format, offset, size),
        DrawCommand::SetVertexBuffer {
            slot,
            buffer,
            offset,
            size,
        } => target.set_vertex_buffer(global, slot, buffer, offset, size),
        DrawCommand::Draw {
            vertices,
            instances,
            first_vertex,
            first_instance,
        } => target.draw(global, vertices, instances, first_vertex, first_instance),
        DrawCommand::DrawIndexed {
            indices,
            instances,
            first_index,
            base_vertex,
            first_instance,
        } => target.draw_indexed(
            global,
            indices,
            instances,
            first_index,
            base_vertex,
            first_instance,
        ),
        DrawCommand::DrawIndirect { buffer, offset } => {
            target.draw_indirect(global, buffer, offset)
        }
        DrawCommand::DrawIndexedIndirect { buffer, offset } => {
            target.draw_indexed_indirect(global, buffer, offset)
        }
    }
}
