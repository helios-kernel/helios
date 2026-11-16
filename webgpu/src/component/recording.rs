//! Recorders have one owner; passes share their encoder's invalidation.
//!
//! Recording queues one command per call. Core validates each on the
//! device timeline and defers its errors to the end of the pass or the
//! encoder as WebGPU requires; `invalid` carries only what the content
//! timeline rejected itself (a draw-count overflow, a malformed data range),
//! which makes the encoder's command buffer unsubmittable.

use core::cell::Cell;
use std::rc::Rc;

use wgpu_core::id::{Id, markers};

use super::{
    buffer::{Buffer, range},
    command::{Bytes, Command, ComputeCommand},
    content::{DeviceShared, Foreign, Handle},
    ids::Kind,
    wit,
};

pub struct Recorder<K: Kind> {
    pub handle: Handle<K>,
    pub invalid: Rc<Cell<bool>>,
}

impl<K: Kind> Recorder<K> {
    pub fn new(handle: Handle<K>, invalid: Rc<Cell<bool>>) -> Self {
        Self { handle, invalid }
    }

    pub fn device(&self) -> &Rc<DeviceShared> {
        &self.handle.device
    }

    pub fn reject(&self, message: impl Into<String>) {
        self.invalid.set(true);
        self.handle.device.invalid(message);
    }

    pub fn resolve<F: Foreign>(&self, object: &Handle<F>) -> Id<F> {
        self.handle.device.resolve(object)
    }

    pub fn offsets(
        &self,
        values: Option<Vec<u32>>,
        start: Option<u64>,
        count: Option<u32>,
    ) -> Result<Vec<u32>, wit::SetBindGroupError> {
        let values = values.unwrap_or_default();
        let selected = range(values.len() as u64, start, count.map(u64::from)).map_err(|e| {
            wit::SetBindGroupError {
                kind: wit::SetBindGroupErrorKind::RangeError,
                message: e.to_string(),
            }
        })?;
        Ok(values[selected.start as usize..selected.end as usize].to_vec())
    }

    pub fn data(&self, data: Vec<u8>, offset: Option<u64>, size: Option<u64>) -> Option<Bytes> {
        match range(data.len() as u64, offset, size) {
            Ok(selected) => Some(Bytes {
                data,
                range: selected.start as usize..selected.end as usize,
            }),
            Err(error) => {
                self.reject(error.to_string());
                None
            }
        }
    }

    pub fn group(
        &self,
        group: Option<wit::GpuBindGroupBorrow<'_>>,
    ) -> Option<Id<markers::BindGroup>> {
        group.map(|group| self.resolve(group.get::<Handle<markers::BindGroup>>()))
    }
}

pub struct ComputePass(pub Recorder<markers::ComputePassEncoder>);

impl ComputePass {
    fn record(&self, command: ComputeCommand) {
        self.0
            .device()
            .enqueue(Command::ComputePass(self.0.handle.id, command));
    }
}

impl wit::GuestGpuComputePassEncoder for ComputePass {
    fn label(&self) -> String {
        self.0.handle.label()
    }
    fn set_label(&self, label: String) {
        self.0.handle.set_label(label);
    }
    fn end(&self) {
        self.record(ComputeCommand::End);
    }
    fn push_debug_group(&self, label: String) {
        self.record(ComputeCommand::PushDebugGroup(label));
    }
    fn pop_debug_group(&self) {
        self.record(ComputeCommand::PopDebugGroup);
    }
    fn insert_debug_marker(&self, label: String) {
        self.record(ComputeCommand::InsertDebugMarker(label));
    }
    fn set_pipeline(&self, pipeline: wit::GpuComputePipelineBorrow<'_>) {
        self.record(ComputeCommand::SetPipeline(
            self.0
                .resolve(pipeline.get::<Handle<markers::ComputePipeline>>()),
        ));
    }
    fn dispatch_workgroups(&self, x: u32, y: Option<u32>, z: Option<u32>) {
        self.record(ComputeCommand::Dispatch([
            x,
            y.unwrap_or(1),
            z.unwrap_or(1),
        ]));
    }
    fn dispatch_workgroups_indirect(&self, buffer: wit::GpuBufferBorrow<'_>, offset: u64) {
        self.record(ComputeCommand::DispatchIndirect {
            buffer: self.0.resolve(&buffer.get::<Buffer>().handle),
            offset,
        });
    }
    fn set_bind_group(
        &self,
        index: u32,
        group: Option<wit::GpuBindGroupBorrow<'_>>,
        offsets: Option<Vec<u32>>,
        start: Option<u64>,
        count: Option<u32>,
    ) -> Result<(), wit::SetBindGroupError> {
        let offsets = self.0.offsets(offsets, start, count)?;
        self.record(ComputeCommand::SetBindGroup {
            index,
            group: self.0.group(group),
            offsets,
        });
        Ok(())
    }
    fn set_immediates(
        &self,
        offset: u32,
        data: Vec<u8>,
        data_offset: Option<u64>,
        data_size: Option<u64>,
    ) {
        if let Some(data) = self.0.data(data, data_offset, data_size) {
            self.record(ComputeCommand::SetImmediates { offset, data });
        }
    }
}
