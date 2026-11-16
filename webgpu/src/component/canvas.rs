//! The canvas context and the platform canvas that presents it.
//!
//! The drawing buffer is a parent texture owned by the canvas with the usages
//! presentation needs. The texture an application sees is a child of it with
//! only the usages it configured, so destroying that texture expires the
//! handle while the pixels stay available to present, and `present` hands the
//! parent to the compositor path and starts a fresh, cleared drawing buffer.
//!
//! Both textures are created on the configured device's timeline: the
//! context allocates their ids and queues the creations, and `present`
//! queues the copy into an exported image and awaits only that frame.

use core::cell::RefCell;
use std::rc::Rc;

use helios_api::bindings::exports::helios::webgpu::canvas as platform;
use helios_api::bindings::helios::system::surface as surface_wit;
use helios_api::surface::{ImageSurface, SurfaceError};
use helios_api::wit_bindgen::StreamReader;
use wgpu_core::id::markers;

use super::{
    command::{Command, Create, Present},
    content::Handle,
    convert::Convert,
    device::Device,
    resource::Texture,
    wit,
};

/// The configuration `configure` stored, owned so it outlives the call.
struct Configuration {
    device: Device,
    format: wit::GpuTextureFormat,
    usage: Option<wit::GpuTextureUsage>,
    view_formats: Option<Vec<wit::GpuTextureFormat>>,
    color_space: Option<wit::PredefinedColorSpace>,
    tone_mapping: Option<wit::GpuCanvasToneMapping>,
    alpha_mode: Option<wit::GpuCanvasAlphaMode>,
}

impl Configuration {
    fn usage(&self) -> wit::GpuTextureUsage {
        self.usage
            .unwrap_or(wit::GpuTextureUsage::RENDER_ATTACHMENT)
    }

    fn descriptor(
        &self,
        size: surface_wit::Size,
        usage: wit::GpuTextureUsage,
    ) -> wit::GpuTextureDescriptor {
        wit::GpuTextureDescriptor {
            size: wit::GpuExtent3D {
                width: size.width,
                height: Some(size.height),
                depth_or_array_layers: Some(1),
            },
            mip_level_count: Some(1),
            sample_count: Some(1),
            dimension: Some(wit::GpuTextureDimension::D2),
            format: self.format,
            usage,
            view_formats: self.view_formats.clone(),
            texture_binding_view_dimension: None,
            label: None,
        }
    }

    /// Queue a fresh drawing buffer on the configured device.
    fn parent(&self, size: surface_wit::Size) -> Handle<markers::Texture> {
        let descriptor = self.descriptor(
            size,
            self.usage() | wit::GpuTextureUsage::COPY_SRC | wit::GpuTextureUsage::RENDER_ATTACHMENT,
        );
        let parent = Handle::new(&self.device.shared, None);
        self.device.create(Create::Texture {
            id: parent.id,
            descriptor: Texture::native(&descriptor),
        });
        parent
    }
}

/// The drawing buffer of the current frame.
struct Drawing {
    /// Owns the pixels, with `COPY_SRC | RENDER_ATTACHMENT` beside the
    /// configured usage.
    parent: Handle<markers::Texture>,
    /// The texture handed out for this frame, shared by every call to
    /// `get-current-texture` until the frame is presented.
    current: Option<Texture>,
}

#[derive(Default)]
struct State {
    configuration: Option<Configuration>,
    drawing: Option<Drawing>,
}

impl State {
    /// Expire the drawing buffer: the texture handle is destroyed and the
    /// pixels are released with the parent.
    fn expire(&mut self) -> Option<Drawing> {
        let drawing = self.drawing.take();
        if let Some(Texture { handle, .. }) = drawing.as_ref().and_then(|d| d.current.as_ref()) {
            handle.device.enqueue(Command::DestroyTexture(handle.id));
        }
        drawing
    }
}

struct Shared {
    size: surface_wit::Size,
    state: RefCell<State>,
}

pub struct CanvasContext(Rc<Shared>);

fn native_format(format: wit::GpuTextureFormat) -> wgpu_types::TextureFormat {
    format.convert()
}

impl wit::GuestGpuCanvasContext for CanvasContext {
    fn configure(
        &self,
        configuration: wit::GpuCanvasConfiguration<'_>,
    ) -> Result<(), wit::ConfigureCanvasError> {
        let type_error = |message: &str| wit::ConfigureCanvasError {
            kind: wit::ConfigureCanvasErrorKind::TypeError,
            message: message.into(),
        };
        // Only formats the linear presentation image can carry are supported.
        if !matches!(
            configuration.format,
            wit::GpuTextureFormat::Bgra8unorm | wit::GpuTextureFormat::Rgba8unorm
        ) {
            return Err(type_error("canvas format must be bgra8unorm or rgba8unorm"));
        }
        let canvas_format = native_format(configuration.format).remove_srgb_suffix();
        for view_format in configuration.view_formats.iter().flatten() {
            if native_format(*view_format).remove_srgb_suffix() != canvas_format {
                return Err(type_error(
                    "view formats must match the canvas format apart from sRGB encoding",
                ));
            }
        }
        let device = configuration.device.get::<Device>().clone();
        let mut state = self.0.state.borrow_mut();
        // A new configuration replaces the drawing buffer.
        state.expire();
        state.configuration = Some(Configuration {
            device,
            format: configuration.format,
            usage: configuration.usage,
            view_formats: configuration.view_formats,
            color_space: configuration.color_space,
            tone_mapping: configuration.tone_mapping,
            alpha_mode: configuration.alpha_mode,
        });
        Ok(())
    }

    fn unconfigure(&self) {
        let mut state = self.0.state.borrow_mut();
        state.expire();
        state.configuration = None;
    }

    fn get_configuration(&self) -> Option<wit::GpuCanvasConfigurationOwned> {
        let state = self.0.state.borrow();
        let configuration = state.configuration.as_ref()?;
        Some(wit::GpuCanvasConfigurationOwned {
            device: wit::GpuDevice::new(configuration.device.clone()),
            format: configuration.format,
            usage: configuration.usage,
            view_formats: configuration.view_formats.clone(),
            color_space: configuration.color_space,
            tone_mapping: configuration.tone_mapping,
            alpha_mode: configuration.alpha_mode,
        })
    }

    fn get_current_texture(&self) -> Result<wit::GpuTexture, wit::GetCurrentTextureError> {
        let mut state = self.0.state.borrow_mut();
        let State {
            configuration,
            drawing,
        } = &mut *state;
        let configuration = configuration
            .as_ref()
            .ok_or(wit::GetCurrentTextureError::InvalidState)?;
        let drawing = drawing.get_or_insert_with(|| Drawing {
            parent: configuration.parent(self.0.size),
            current: None,
        });
        if let Some(current) = &drawing.current {
            return Ok(wit::GpuTexture::new(current.clone()));
        }
        let descriptor = configuration.descriptor(self.0.size, configuration.usage());
        let child = Handle::new(&configuration.device.shared, None);
        configuration.device.create(Create::ChildTexture {
            parent: drawing.parent.id,
            id: child.id,
            descriptor: Texture::native(&descriptor),
        });
        let texture = Texture::new(child, descriptor);
        drawing.current = Some(texture.clone());
        Ok(wit::GpuTexture::new(texture))
    }
}

pub struct Canvas {
    surface: ImageSurface,
    shared: Rc<Shared>,
}

fn surface_error(error: SurfaceError) -> platform::Error {
    use surface_wit::Error as Wit;
    let wit = match error {
        SurfaceError::RenderFailed => Wit::RenderFailed,
        SurfaceError::Unavailable => Wit::Unavailable,
        SurfaceError::NoCompositor => Wit::NoCompositor,
        SurfaceError::UnsupportedSize => Wit::UnsupportedSize,
        SurfaceError::TooManySurfaces => Wit::TooManySurfaces,
        SurfaceError::OutOfBounds => Wit::OutOfBounds,
        SurfaceError::BadSpan => Wit::BadSpan,
        SurfaceError::OutOfMemory => Wit::OutOfMemory,
        SurfaceError::Gone => Wit::Gone,
        SurfaceError::NotTheCompositor => Wit::NotTheCompositor,
        SurfaceError::Heap(error) => return platform::Error::Presentation(error.to_string()),
    };
    platform::Error::Surface(wit)
}

impl platform::GuestCanvas for Canvas {
    async fn create(width: u32, height: u32) -> Result<platform::Canvas, platform::Error> {
        let surface = ImageSurface::create(width, height)
            .await
            .map_err(surface_error)?;
        let size = surface.size();
        Ok(platform::Canvas::new(Self {
            surface,
            shared: Rc::new(Shared {
                size,
                state: RefCell::default(),
            }),
        }))
    }

    fn size(&self) -> surface_wit::Size {
        self.shared.size
    }

    fn context(&self) -> wit::GpuCanvasContext {
        wit::GpuCanvasContext::new(CanvasContext(self.shared.clone()))
    }

    async fn present(&self) -> Result<(), platform::Error> {
        let size = self.shared.size;
        let (device, answer) = {
            let mut state = self.shared.state.borrow_mut();
            let drawing = state.expire();
            let configuration = state
                .configuration
                .as_ref()
                .ok_or(platform::Error::Unconfigured)?;
            // Nothing was drawn: present a fresh, cleared drawing buffer.
            let parent = match drawing {
                Some(drawing) => drawing.parent,
                None => configuration.parent(size),
            };
            let (reply, answer) = async_channel::bounded(1);
            configuration
                .device
                .shared
                .enqueue(Command::Present(Present {
                    parent: parent.id,
                    width: size.width,
                    height: size.height,
                    format: native_format(configuration.format),
                    reply,
                }));
            // The parent's release queues behind the copy that reads it.
            drop(parent);
            (configuration.device.clone(), answer)
        };
        let frame = answer
            .recv()
            .await
            // `device` keeps the device task alive until it answers.
            .unwrap_or_else(|_| unreachable!("the device task answers every presentation"))
            .map_err(|error| platform::Error::Presentation(error.to_string()))?;
        drop(device);
        self.surface
            .present(&frame.image, frame.ready.point(1))
            .await
            .map_err(surface_error)?;
        Ok(())
    }

    fn events(&self) -> StreamReader<surface_wit::InputEvent> {
        self.surface.events()
    }
}
