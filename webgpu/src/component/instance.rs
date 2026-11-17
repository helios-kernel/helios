//! The Vulkan instance behind one `gpu` and the task that owns it.
//!
//! Releasing the last reference to the instance destroys it, and the Venus
//! driver flushes that destruction to the host, so no synchronous export may
//! hold that last reference. Content-side objects hold a weak reference and
//! a sender; the strong references belong to async tasks: the instance task
//! spawned by the `request-adapter` that opened it, and every device task.
//! The instance task also executes adapter drops, which content destructors
//! queue. It ends when the last `gpu` or adapter handle is gone.

use std::rc::{Rc, Weak};

use async_channel::{Receiver, Sender};
use wgpu_core::{global::Global, id};

use super::ids::IdSpace;
use crate::runtime::open_instance;

enum InstanceCommand {
    DropAdapter(id::AdapterId),
}

#[derive(Clone)]
pub struct Instance {
    global: Weak<Global>,
    commands: Sender<InstanceCommand>,
    pub ids: Rc<IdSpace>,
}

impl Instance {
    /// Open the instance and spawn its task in the current async export.
    pub fn open() -> Result<Self, wgpu_hal::InstanceError> {
        let hal = open_instance()?;
        // SAFETY: `hal` is a freshly opened Vulkan instance; core takes it whole.
        let global = Rc::new(unsafe {
            Global::from_hal_instance::<wgpu_hal::api::Vulkan>("helios-webgpu", hal)
        });
        let ids = Rc::new(IdSpace::default());
        let (commands, queue) = async_channel::unbounded();
        let instance = Self {
            global: Rc::downgrade(&global),
            commands,
            ids: ids.clone(),
        };
        helios_api::task::spawn(run(global, ids, queue));
        Ok(instance)
    }

    /// The instance, for an async export to use while it runs.
    pub fn global(&self) -> Rc<Global> {
        // The instance task holds a strong reference until every sender,
        // this one included, is gone.
        self.global
            .upgrade()
            .unwrap_or_else(|| unreachable!("the instance task outlives its handles"))
    }

    pub fn drop_adapter(&self, adapter: id::AdapterId) {
        self.commands
            .try_send(InstanceCommand::DropAdapter(adapter))
            .unwrap_or_else(|_| unreachable!("the instance task outlives its handles"));
    }
}

async fn run(global: Rc<Global>, ids: Rc<IdSpace>, queue: Receiver<InstanceCommand>) {
    while let Ok(command) = queue.recv().await {
        match command {
            InstanceCommand::DropAdapter(adapter) => {
                global.adapter_drop(adapter);
                ids.adapters.release(adapter);
            }
        }
    }
}
