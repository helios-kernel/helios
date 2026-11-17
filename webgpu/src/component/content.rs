//! The content timeline's view of one device.
//!
//! Content-side objects hold ids and the state WebGPU answers synchronously
//! (sizes, usages, descriptors, labels), never a wgpu-core object. Every
//! handle shares its device's [`DeviceShared`], whose command sender keeps
//! the device task alive: when the last handle goes, the queue closes and
//! the task tears the device down.

use core::cell::{Cell, RefCell};
use std::rc::Rc;

use async_channel::Sender;
use wgpu_core::id::{Id, markers};

use super::{
    command::{Command, Queued, StandIn},
    ids::{IdSpace, Kind},
    scope::{ErrorTarget, ScopeStack, validation},
};

/// What a device answers without asking its timeline, recorded when the
/// device was created.
pub struct Capabilities {
    pub features: wgpu_types::Features,
    pub limits: wgpu_types::Limits,
    pub downlevel: wgpu_types::DownlevelCapabilities,
    pub info: wgpu_types::AdapterInfo,
}

pub struct DeviceShared {
    commands: Sender<Queued>,
    ids: Rc<IdSpace>,
    pub capabilities: Capabilities,
    pub scopes: ScopeStack,
    stand_ins: StandIns,
}

impl DeviceShared {
    pub fn new(commands: Sender<Queued>, ids: Rc<IdSpace>, capabilities: Capabilities) -> Self {
        Self {
            commands,
            ids,
            capabilities,
            scopes: ScopeStack::default(),
            stand_ins: StandIns::default(),
        }
    }

    /// Queue `command` with the error scopes open now.
    pub fn enqueue(&self, command: Command) {
        self.send(self.scopes.current(), command);
    }

    /// Queue `command` with its errors dropped: the content timeline has
    /// already reported why the object it creates is invalid.
    pub fn enqueue_discarding(&self, command: Command) {
        self.send(ErrorTarget::Discard, command);
    }

    fn send(&self, target: ErrorTarget, command: Command) {
        // The device task drains the queue until every sender is gone, and
        // this one lives as long as `self`.
        self.commands
            .try_send(Queued { target, command })
            .unwrap_or_else(|_| unreachable!("the device task outlives its last content handle"));
    }

    /// Report a validation error the content timeline found.
    pub fn invalid(&self, message: impl Into<String>) {
        self.enqueue(Command::Error(validation(message)));
    }

    pub fn allocate<K: Kind>(&self) -> Id<K> {
        K::ids(&self.ids).allocate()
    }

    /// The id a command on this device may name for `handle`.
    pub fn resolve<K: Foreign>(&self, handle: &Handle<K>) -> Id<K> {
        if core::ptr::eq(&*handle.device, self) {
            handle.id
        } else {
            self.stand_in::<K>()
        }
    }

    /// This device's invalid object of kind `K`, created on first use.
    pub fn stand_in<K: Foreign>(&self) -> Id<K> {
        let slot = K::slot(&self.stand_ins);
        if let Some(id) = slot.get() {
            return id;
        }
        let id = self.allocate::<K>();
        slot.set(Some(id));
        self.enqueue_discarding(Command::StandIn(K::stand_in(id)));
        id
    }
}

impl Drop for DeviceShared {
    fn drop(&mut self) {
        // The stand-ins are the device's own objects; their drops are the
        // last commands before the queue closes.
        for release in self.stand_ins.take() {
            self.enqueue_discarding(Command::Release(release));
        }
    }
}

/// A content-side object: its id, its device and its label. Dropping the
/// last handle queues the object's drop on its device.
pub struct Handle<K: Kind> {
    pub id: Id<K>,
    pub device: Rc<DeviceShared>,
    label: RefCell<String>,
}

impl<K: Kind> Handle<K> {
    /// Allocate an id on `device`. The caller queues its creation.
    pub fn new(device: &Rc<DeviceShared>, label: Option<String>) -> Self {
        Self {
            id: device.allocate::<K>(),
            device: device.clone(),
            label: RefCell::new(label.unwrap_or_default()),
        }
    }

    pub fn label(&self) -> String {
        self.label.borrow().clone()
    }

    pub fn set_label(&self, label: String) {
        *self.label.borrow_mut() = label;
    }
}

impl<K: Kind> Drop for Handle<K> {
    fn drop(&mut self) {
        self.device
            .enqueue_discarding(Command::Release(K::release(self.id)));
    }
}

/// An object kind another device's commands may reference.
pub trait Foreign: Kind {
    fn slot(stand_ins: &StandIns) -> &Cell<Option<Id<Self>>>;
    fn stand_in(id: Id<Self>) -> StandIn;
}

macro_rules! foreign {
    ($($field:ident: $marker:ident => $variant:ident;)*) => {
        /// This device's stand-ins, created on first use.
        #[derive(Default)]
        pub struct StandIns {
            $($field: Cell<Option<Id<markers::$marker>>>,)*
        }

        impl StandIns {
            fn take(&self) -> Vec<super::ids::Release> {
                let mut releases = Vec::new();
                $(if let Some(id) = self.$field.take() {
                    releases.push(markers::$marker::release(id));
                })*
                releases
            }
        }

        $(impl Foreign for markers::$marker {
            fn slot(stand_ins: &StandIns) -> &Cell<Option<Id<Self>>> {
                &stand_ins.$field
            }
            fn stand_in(id: Id<Self>) -> StandIn {
                StandIn::$variant(id)
            }
        })*
    };
}

foreign! {
    buffer: Buffer => Buffer;
    texture: Texture => Texture;
    texture_view: TextureView => TextureView;
    sampler: Sampler => Sampler;
    bind_group_layout: BindGroupLayout => BindGroupLayout;
    pipeline_layout: PipelineLayout => PipelineLayout;
    bind_group: BindGroup => BindGroup;
    shader_module: ShaderModule => ShaderModule;
    compute_pipeline: ComputePipeline => ComputePipeline;
    render_pipeline: RenderPipeline => RenderPipeline;
    query_set: QuerySet => QuerySet;
    render_bundle: RenderBundle => RenderBundle;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::component::{command::Create, scope::ErrorTarget};
    use crate::runtime::GpuErrorKind;

    /// A device whose queue the test drains in place of a device task.
    pub(crate) fn new_device() -> (Rc<DeviceShared>, async_channel::Receiver<Queued>) {
        let (commands, queue) = async_channel::unbounded();
        let device = DeviceShared::new(
            commands,
            Rc::new(IdSpace::default()),
            Capabilities {
                features: wgpu_types::Features::empty(),
                limits: wgpu_types::Limits::default(),
                downlevel: wgpu_types::DownlevelCapabilities::default(),
                info: wgpu_types::AdapterInfo::new(
                    wgpu_types::DeviceType::Other,
                    wgpu_types::Backend::Vulkan,
                ),
            },
        );
        (Rc::new(device), queue)
    }

    #[test]
    fn commands_keep_call_order_and_the_scopes_of_their_call() {
        let (device, queue) = new_device();
        let first = Handle::<markers::Buffer>::new(&device, None);
        device.scopes.push(GpuErrorKind::Validation);
        device.invalid("inside");
        device.scopes.pop().unwrap();
        device.invalid("after");
        drop(first);
        let Queued {
            target: ErrorTarget::Scopes(Some(_)),
            command: Command::Error(inside),
        } = queue.try_recv().unwrap()
        else {
            panic!("the first error was not queued inside its scope");
        };
        assert_eq!(inside.message, "inside");
        let Queued {
            target: ErrorTarget::Scopes(None),
            command: Command::Error(after),
        } = queue.try_recv().unwrap()
        else {
            panic!("the second error was not queued after the pop");
        };
        assert_eq!(after.message, "after");
        assert!(matches!(
            queue.try_recv().unwrap(),
            Queued {
                target: ErrorTarget::Discard,
                command: Command::Release(super::super::ids::Release::Buffer(_)),
            }
        ));
        assert!(queue.try_recv().is_err());
    }

    #[test]
    fn foreign_handles_resolve_to_one_stand_in_released_with_the_device() {
        let (other, _other_queue) = new_device();
        let (device, queue) = new_device();
        let own = Handle::<markers::Buffer>::new(&device, None);
        let foreign = Handle::<markers::Buffer>::new(&other, None);
        assert_eq!(device.resolve(&own), own.id);
        let stand_in = device.resolve(&foreign);
        assert_ne!(stand_in, own.id);
        assert_eq!(device.resolve(&foreign), stand_in);
        let Queued {
            target: ErrorTarget::Discard,
            command: Command::StandIn(StandIn::Buffer(created)),
        } = queue.try_recv().unwrap()
        else {
            panic!("the stand-in was not created once, discarding its error");
        };
        assert_eq!(created, stand_in);
        assert!(queue.try_recv().is_err());
        drop(own);
        drop(foreign);
        drop(device);
        let released: Vec<_> = core::iter::from_fn(|| queue.try_recv().ok())
            .map(|queued| match queued.command {
                Command::Release(super::super::ids::Release::Buffer(id)) => id,
                _ => panic!("only releases follow"),
            })
            .collect();
        assert!(released.contains(&stand_in));
        assert_eq!(released.len(), 2);
        assert!(queue.is_closed());
    }

    #[test]
    fn creations_name_ids_that_are_unique_until_released() {
        let (device, queue) = new_device();
        let first = Handle::<markers::Texture>::new(&device, None);
        let second = Handle::<markers::Texture>::new(&device, None);
        assert_ne!(first.id, second.id);
        device.enqueue(Command::Create(Create::CommandEncoder {
            id: device.allocate(),
            label: None,
        }));
        assert!(matches!(
            queue.try_recv().unwrap().command,
            Command::Create(Create::CommandEncoder { .. })
        ));
    }
}
