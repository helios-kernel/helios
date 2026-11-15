//! Recorders have one owner; pass resources share their encoder's invalidation.

use super::backend;

use core::cell::{Cell, RefCell};
use std::rc::Rc;

use super::{
    buffer::{Buffer, range},
    state::DeviceState,
    value::Object,
    wit,
};

pub struct Recorder<T> {
    pub object: Object<RefCell<Option<T>>>,
    pub invalid: Rc<Cell<bool>>,
}

impl<T> Recorder<T> {
    pub fn new(
        owner: Rc<DeviceState>,
        raw: Option<T>,
        label: Option<String>,
        invalid: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            object: Object::new(owner, RefCell::new(raw), label),
            invalid,
        }
    }

    pub fn reject(&self, message: impl Into<String>) {
        self.invalid.set(true);
        self.object.owner.invalid(message);
    }

    fn access<R>(&self, call: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut state = self
            .object
            .raw
            .as_ref()
            .expect("recorders own their state")
            .borrow_mut();
        let Some(raw) = state.as_mut() else {
            self.reject("command recorder is invalid or has already ended");
            return None;
        };
        Some(call(raw))
    }

    pub fn with<R, E: wgpu_types::error::WebGpuError>(
        &self,
        record: impl FnOnce(&mut T) -> Result<R, E>,
    ) -> Option<R> {
        self.access(|raw| {
            let result = self.object.owner.native(|| record(raw));
            if result.is_none() {
                self.invalid.set(true);
            }
            result
        })
        .flatten()
    }

    pub fn created<R, E: wgpu_types::error::WebGpuError>(
        &self,
        record: impl FnOnce(&mut T) -> (R, Option<E>),
    ) -> Option<R> {
        self.access(|raw| {
            let (value, error) = record(raw);
            if let Some(error) = error {
                self.invalid.set(true);
                self.object.owner.report(&error);
            }
            value
        })
    }

    pub fn take(&self) -> Option<T> {
        let raw = self
            .object
            .raw
            .as_ref()
            .expect("recorders own their state")
            .borrow_mut()
            .take();
        if raw.is_none() {
            self.reject("command recorder is invalid or has already ended");
        }
        raw
    }

    pub fn resource<'a, U>(&self, object: &'a Object<U>) -> Option<&'a U> {
        if !Rc::ptr_eq(&self.object.owner, &object.owner) {
            self.reject("command resource belongs to another device");
            return None;
        }
        if object.raw.is_none() {
            self.reject("command uses an invalid resource");
        }
        object.raw.as_ref()
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

    pub fn data<'a>(
        &self,
        data: &'a [u8],
        offset: Option<u64>,
        size: Option<u64>,
    ) -> Option<&'a [u8]> {
        match range(data.len() as u64, offset, size) {
            Ok(selected) => Some(&data[selected.start as usize..selected.end as usize]),
            Err(error) => {
                self.reject(error.to_string());
                None
            }
        }
    }
}

pub struct ComputePass(pub Recorder<wgpu_core::command::ComputePass>);

impl wit::GuestGpuComputePassEncoder for ComputePass {
    fn label(&self) -> String {
        self.0.object.label()
    }
    fn set_label(&self, label: String) {
        self.0.object.set_label(label);
    }
    fn end(&self) {
        self.0.with(|raw| raw.end());
        self.0.take();
    }
    fn push_debug_group(&self, label: String) {
        self.0.with(|raw| raw.push_debug_group(&label, 0));
    }
    fn pop_debug_group(&self) {
        self.0.with(|raw| raw.pop_debug_group());
    }
    fn insert_debug_marker(&self, label: String) {
        self.0.with(|raw| raw.insert_debug_marker(&label, 0));
    }
    fn set_pipeline(&self, pipeline: wit::GpuComputePipelineBorrow<'_>) {
        if let Some(pipeline) = self
            .0
            .resource(pipeline.get::<Object<backend::ComputePipeline>>())
        {
            self.0.with(|raw| raw.set_pipeline(pipeline.clone()));
        }
    }
    fn dispatch_workgroups(&self, x: u32, y: Option<u32>, z: Option<u32>) {
        self.0
            .with(|raw| raw.dispatch_workgroups(x, y.unwrap_or(1), z.unwrap_or(1)));
    }
    fn dispatch_workgroups_indirect(&self, buffer: wit::GpuBufferBorrow<'_>, offset: u64) {
        if let Some(buffer) = self.0.resource(&buffer.get::<Buffer>().object) {
            self.0
                .with(|raw| raw.dispatch_workgroups_indirect(buffer.clone(), offset));
        }
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
        let group = match group.as_ref() {
            Some(group) => match self.0.resource(group.get::<Object<backend::BindGroup>>()) {
                Some(group) => Some(group),
                None => return Ok(()),
            },
            None => None,
        };
        self.0
            .with(|raw| raw.set_bind_group(index, group.cloned(), &offsets));
        Ok(())
    }
    fn set_immediates(
        &self,
        offset: u32,
        data: Vec<u8>,
        data_offset: Option<u64>,
        data_size: Option<u64>,
    ) {
        if let Some(data) = self.0.data(&data, data_offset, data_size) {
            self.0.with(|raw| raw.set_immediates(offset, data));
        }
    }
}
