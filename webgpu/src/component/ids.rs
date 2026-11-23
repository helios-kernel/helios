//! Content-allocated wgpu-core ids.
//!
//! The content timeline names every object before the device timeline
//! creates it, the way a browser's content process allocates ids for its
//! GPU process: wgpu-core's `Global` registers whatever id it is handed
//! (`id_in`), valid or invalid. An index is reused only after the device
//! timeline has executed the drop that vacated its storage slot, so a
//! creation can never meet an occupied slot, even when it is queued on a
//! different device than the drop. Every operation runs on the one thread
//! of the component instance; the cells are never contended.

use core::{cell::RefCell, marker::PhantomData};

use wgpu_core::{
    global::Global,
    id::{Id, Marker, markers},
};

/// Allocator for one kind of id: lowest free index first, a fresh epoch on
/// every reuse.
pub struct Ids<T: Marker> {
    state: RefCell<Free>,
    marker: PhantomData<T>,
}

#[derive(Default)]
struct Free {
    next: u32,
    released: Vec<(u32, u32)>,
}

impl<T: Marker> Default for Ids<T> {
    fn default() -> Self {
        Self {
            state: RefCell::default(),
            marker: PhantomData,
        }
    }
}

impl<T: Marker> Ids<T> {
    pub fn allocate(&self) -> Id<T> {
        let mut state = self.state.borrow_mut();
        match state.released.pop() {
            // The epoch shares the id's upper 32 bits with no reserved
            // value, so it wraps like wgpu-core's own allocator.
            Some((index, epoch)) => Id::zip(index, epoch.wrapping_add(1).max(1)),
            None => {
                let index = state.next;
                state.next = index
                    .checked_add(1)
                    .expect("wgpu-core id indices are exhausted");
                // Epoch zero would make the packed id zero, which `Id` forbids.
                Id::zip(index, 1)
            }
        }
    }

    /// Return the index once the device timeline has removed `id` from its
    /// registry.
    pub fn release(&self, id: Id<T>) {
        self.state.borrow_mut().released.push(id.unzip());
    }
}

/// An object kind whose ids the content timeline allocates and drops.
pub trait Kind: Marker + Sized {
    fn ids(space: &IdSpace) -> &Ids<Self>;
    fn release(id: Id<Self>) -> Release;
}

macro_rules! kinds {
    ($($field:ident: $marker:ident => $variant:ident, $drop:ident;)*) => {
        /// Every id allocator of one `Global`.
        #[derive(Default)]
        pub struct IdSpace {
            pub adapters: Ids<markers::Adapter>,
            pub devices: Ids<markers::Device>,
            pub queues: Ids<markers::Queue>,
            $(pub $field: Ids<markers::$marker>,)*
        }

        /// A drop the content timeline queues when its last handle goes.
        pub enum Release {
            $($variant(Id<markers::$marker>),)*
        }

        $(impl Kind for markers::$marker {
            fn ids(space: &IdSpace) -> &Ids<Self> {
                &space.$field
            }
            fn release(id: Id<Self>) -> Release {
                Release::$variant(id)
            }
        })*

        impl Release {
            /// Remove the object from the registry, then free its index.
            pub fn execute(self, global: &Global, ids: &IdSpace) {
                match self {
                    $(Self::$variant(id) => {
                        global.$drop(id);
                        ids.$field.release(id);
                    })*
                }
            }
        }
    };
}

kinds! {
    buffers: Buffer => Buffer, buffer_drop;
    textures: Texture => Texture, texture_drop;
    texture_views: TextureView => TextureView, texture_view_drop;
    samplers: Sampler => Sampler, sampler_drop;
    bind_group_layouts: BindGroupLayout => BindGroupLayout, bind_group_layout_drop;
    pipeline_layouts: PipelineLayout => PipelineLayout, pipeline_layout_drop;
    bind_groups: BindGroup => BindGroup, bind_group_drop;
    shader_modules: ShaderModule => ShaderModule, shader_module_drop;
    compute_pipelines: ComputePipeline => ComputePipeline, compute_pipeline_drop;
    render_pipelines: RenderPipeline => RenderPipeline, render_pipeline_drop;
    command_encoders: CommandEncoder => CommandEncoder, command_encoder_drop;
    command_buffers: CommandBuffer => CommandBuffer, command_buffer_drop;
    render_bundle_encoders: RenderBundleEncoder => RenderBundleEncoder, render_bundle_encoder_drop;
    render_bundles: RenderBundle => RenderBundle, render_bundle_drop;
    query_sets: QuerySet => QuerySet, query_set_drop;
    compute_passes: ComputePassEncoder => ComputePass, compute_pass_drop;
    render_passes: RenderPassEncoder => RenderPass, render_pass_drop;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indices_are_reused_lowest_first_with_a_new_epoch_only_after_release() {
        let ids = Ids::<markers::Buffer>::default();
        let first = ids.allocate();
        let second = ids.allocate();
        assert_eq!(first.unzip(), (0, 1));
        assert_eq!(second.unzip(), (1, 1));
        // A queued drop that the device timeline has not executed holds
        // its index: the next allocation takes a fresh one.
        assert_eq!(ids.allocate().unzip(), (2, 1));
        ids.release(first);
        let reused = ids.allocate();
        assert_eq!(reused.unzip(), (0, 2));
        assert_ne!(reused, first);
        assert_eq!(ids.allocate().unzip(), (3, 1));
    }

    #[test]
    fn epochs_wrap_without_producing_the_zero_id() {
        let ids = Ids::<markers::Texture>::default();
        ids.release(Id::zip(7, u32::MAX));
        assert_eq!(ids.allocate().unzip(), (7, 1));
    }
}
