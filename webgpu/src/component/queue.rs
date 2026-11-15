use core::cell::RefCell;
use std::rc::Rc;

use super::{
    buffer::{Buffer, range},
    convert::Convert,
    resource::Texture,
    state::DeviceState,
    value::Object,
    wit,
};
use crate::runtime::{GpuError, GpuErrorKind};

pub struct CommandBuffer(pub Object<RefCell<Option<wgpu::CommandBuffer>>>);

impl wit::GuestGpuCommandBuffer for CommandBuffer {
    fn label(&self) -> String {
        self.0.label()
    }
    fn set_label(&self, label: String) {
        self.0.set_label(label);
    }
}

pub struct Queue {
    pub owner: Rc<DeviceState>,
    label: RefCell<String>,
}

impl Queue {
    pub fn new(owner: Rc<DeviceState>, label: Option<String>) -> Self {
        Self {
            owner,
            label: RefCell::new(label.unwrap_or_default()),
        }
    }
}

impl wit::GuestGpuQueue for Queue {
    fn label(&self) -> String {
        self.label.borrow().clone()
    }
    fn set_label(&self, label: String) {
        *self.label.borrow_mut() = label;
    }

    fn submit(&self, command_buffers: Vec<wit::GpuCommandBufferBorrow<'_>>) {
        let mut valid = true;
        let mut commands = Vec::with_capacity(command_buffers.len());
        for command in &command_buffers {
            let command = &command.get::<CommandBuffer>().0;
            if !Rc::ptr_eq(&self.owner, &command.owner) {
                self.owner
                    .invalid("submitted command buffer belongs to another device");
                valid = false;
            }
            if let Some(raw) = command.get().and_then(|raw| raw.borrow_mut().take()) {
                commands.push(raw);
            } else {
                self.owner
                    .invalid("command buffer is invalid or has already been submitted");
                valid = false;
            }
        }
        // A submission consumes every command buffer, even when validation fails.
        if valid {
            self.owner
                .native(|| self.owner.device.queue().submit(commands));
        }
    }

    async fn on_submitted_work_done(&self) {
        if let Err(error) = self.owner.device.submitted_work_done().await {
            self.owner.errors.report(GpuError {
                kind: GpuErrorKind::Internal,
                message: error.to_string(),
                causes: Vec::new(),
            });
        }
        self.owner.drain();
    }

    fn write_buffer_with_copy(
        &self,
        buffer: wit::GpuBufferBorrow<'_>,
        buffer_offset: u64,
        data: Vec<u8>,
        data_offset: Option<u64>,
        size: Option<u64>,
    ) -> Result<(), wit::WriteBufferError> {
        let invalid_data = |message: String| wit::WriteBufferError {
            kind: wit::WriteBufferErrorKind::OperationError,
            message,
        };
        let selected =
            range(data.len() as u64, data_offset, size).map_err(|e| invalid_data(e.to_string()))?;
        if !(selected.end - selected.start).is_multiple_of(wgpu::COPY_BUFFER_ALIGNMENT) {
            return Err(invalid_data(
                "upload size must be a multiple of 4 bytes".into(),
            ));
        }
        let buffer = buffer.get::<Buffer>();
        if !Rc::ptr_eq(&self.owner, &buffer.object.owner) {
            self.owner
                .invalid("upload buffer belongs to another device");
            return Ok(());
        }
        if let Some(raw) = buffer.object.get() {
            self.owner.native(|| {
                self.owner.device.queue().write_buffer(
                    raw,
                    buffer_offset,
                    &data[selected.start as usize..selected.end as usize],
                )
            });
        }
        Ok(())
    }

    fn write_texture_with_copy(
        &self,
        destination: wit::GpuTexelCopyTextureInfo<'_>,
        data: Vec<u8>,
        data_layout: wit::GpuTexelCopyBufferLayout,
        size: wit::GpuExtent3D,
    ) {
        let texture = destination.texture.get::<Texture>();
        if !Rc::ptr_eq(&self.owner, &texture.object.owner) {
            self.owner
                .invalid("upload texture belongs to another device");
            return;
        }
        let Some(raw) = texture.object.get() else {
            return;
        };
        let destination = wgpu::TexelCopyTextureInfo {
            texture: raw,
            mip_level: destination.mip_level.unwrap_or(0),
            origin: destination.origin.map(Convert::convert).unwrap_or_default(),
            aspect: destination
                .aspect
                .map(Convert::convert)
                .unwrap_or(wgpu::TextureAspect::All),
        };
        self.owner.native(|| {
            self.owner.device.queue().write_texture(
                destination,
                &data,
                data_layout.convert(),
                size.convert(),
            )
        });
    }
}
