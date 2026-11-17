use core::cell::{Cell, RefCell};
use std::rc::Rc;

use wgpu_core::id::markers;

use super::{
    buffer::{Buffer, range},
    command::{Bytes, Command},
    content::{DeviceShared, Handle},
    convert::Convert,
    resource::Texture,
    wit,
};

/// A finished command buffer. `valid` is false when the content timeline
/// rejected its encoder; core tracks its own validity.
pub struct CommandBuffer {
    pub handle: Handle<markers::CommandBuffer>,
    pub valid: bool,
    pub consumed: Cell<bool>,
}

impl wit::GuestGpuCommandBuffer for CommandBuffer {
    fn label(&self) -> String {
        self.handle.label()
    }
    fn set_label(&self, label: String) {
        self.handle.set_label(label);
    }
}

#[derive(Clone)]
pub struct Queue {
    device: Rc<DeviceShared>,
    label: Rc<RefCell<String>>,
}

impl Queue {
    pub fn new(device: Rc<DeviceShared>, label: Option<String>) -> Self {
        Self {
            device,
            label: Rc::new(RefCell::new(label.unwrap_or_default())),
        }
    }

    fn submit_buffers<'a>(&self, command_buffers: impl Iterator<Item = &'a CommandBuffer>) {
        let mut valid = true;
        let mut ids = Vec::new();
        for command in command_buffers {
            if !Rc::ptr_eq(&self.device, &command.handle.device) {
                self.device
                    .invalid("submitted command buffer belongs to another device");
                valid = false;
            }
            let consumed = command.consumed.replace(true);
            if !command.valid || consumed {
                self.device
                    .invalid("command buffer is invalid or has already been submitted");
                valid = false;
            }
            ids.push(command.handle.id);
        }
        // A submission consumes every command buffer, even when validation fails.
        if valid {
            self.device.enqueue(Command::Submit(ids));
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
        self.submit_buffers(
            command_buffers
                .iter()
                .map(|command| command.get::<CommandBuffer>()),
        );
    }

    async fn on_submitted_work_done(&self) {
        let (reply, answer) = async_channel::bounded(1);
        self.device.enqueue(Command::WorkDone(reply));
        // Device loss drops the callback unanswered; the work is done either way.
        let _ = answer.recv().await;
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
        if !(selected.end - selected.start).is_multiple_of(wgpu_types::COPY_BUFFER_ALIGNMENT) {
            return Err(invalid_data(
                "upload size must be a multiple of 4 bytes".into(),
            ));
        }
        self.device.enqueue(Command::WriteBuffer {
            buffer: self.device.resolve(&buffer.get::<Buffer>().handle),
            offset: buffer_offset,
            data: Bytes {
                data,
                range: selected.start as usize..selected.end as usize,
            },
        });
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
        self.device.enqueue(Command::WriteTexture {
            destination: wgpu_types::TexelCopyTextureInfo {
                texture: self.device.resolve(&texture.handle),
                mip_level: destination.mip_level.unwrap_or(0),
                origin: destination.origin.map(Convert::convert).unwrap_or_default(),
                aspect: destination
                    .aspect
                    .map(Convert::convert)
                    .unwrap_or(wgpu_types::TextureAspect::All),
            },
            data,
            layout: data_layout.convert(),
            size: size.convert(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::content::tests::new_device;

    fn finished(device: &Rc<DeviceShared>, valid: bool) -> CommandBuffer {
        CommandBuffer {
            handle: Handle::new(device, None),
            valid,
            consumed: Cell::new(false),
        }
    }

    fn errors(queue: &async_channel::Receiver<super::super::command::Queued>) -> Vec<String> {
        core::iter::from_fn(|| queue.try_recv().ok())
            .filter_map(|queued| match queued.command {
                Command::Error(error) => Some(error.message),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_submission_queues_each_buffer_once() {
        let (device, commands) = new_device();
        let queue = Queue::new(device.clone(), None);
        let first = finished(&device, true);
        let second = finished(&device, true);
        queue.submit_buffers([&first, &second].into_iter());
        let Command::Submit(ids) = commands.try_recv().unwrap().command else {
            panic!("the submission was not queued");
        };
        assert_eq!(ids, [first.handle.id, second.handle.id]);
        queue.submit_buffers([&first].into_iter());
        assert_eq!(
            errors(&commands),
            ["command buffer is invalid or has already been submitted"]
        );
    }

    #[test]
    fn an_invalid_or_foreign_buffer_consumes_the_whole_submission() {
        let (device, commands) = new_device();
        let (other, _other_commands) = new_device();
        let queue = Queue::new(device.clone(), None);
        let rejected = finished(&device, false);
        let foreign = finished(&other, true);
        let healthy = finished(&device, true);
        queue.submit_buffers([&rejected, &foreign, &healthy].into_iter());
        assert_eq!(
            errors(&commands),
            [
                "command buffer is invalid or has already been submitted",
                "submitted command buffer belongs to another device",
            ]
        );
        assert!(healthy.consumed.get() && foreign.consumed.get());
        queue.submit_buffers([&healthy].into_iter());
        assert_eq!(
            errors(&commands),
            ["command buffer is invalid or has already been submitted"]
        );
    }
}
