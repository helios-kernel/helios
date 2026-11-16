mod descriptor;
mod event;
mod futex;
mod identity;
mod signal;
mod slots;
mod table;
mod thread;
mod threads;
pub use descriptor::*;
pub use event::*;
pub use futex::*;
pub use identity::*;
pub use signal::*;
pub use slots::*;
pub use table::*;
pub use thread::*;
pub use threads::*;

/// Adapter-owned execution target. Calls originate in task context, never IRQs.
pub trait InterruptTarget: Clone + Send + Sync {
    fn interrupt(&self);
}

mod readiness;
pub use readiness::*;

mod resource;
pub use resource::*;
