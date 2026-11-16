//! The canvas context and the platform canvas that presents it.
//!
//! The drawing buffer is a parent texture owned by the canvas with the usages
//! presentation needs. The texture an application sees is a child of it with
//! only the usages it configured, so destroying that texture expires the
//! handle while the pixels stay available to present, and `present` hands the
//! parent to the compositor path and starts a fresh, cleared drawing buffer.

use core::cell::RefCell;
use std::rc::Rc;

use helios_api::bindings::exports::helios::webgpu::canvas as platform;
use helios_api::bindings::helios::system::surface as surface_wit;
use helios_api::surface::{ImageSurface, SurfaceError};
use helios_api::wit_bindgen::StreamReader;
use wgpu_core::resource;

use super::{
    backend, convert::Convert, device::Device, presentation::LinearImage, resource::Texture, wit,
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
}

/// The drawing buffer of the current frame.
struct Drawing {
    /// Owns the pixels, with `COPY_SRC | RENDER_ATTACHMENT` beside the
    /// configured usage.
    parent: backend::Texture,
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
        if let Some(Texture { object, .. }) = drawing.as_ref().and_then(|d| d.current.as_ref())
            && let Some(child) = &object.raw
        {
            child.destroy();
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
        let owner = &configuration.device.object.owner;
        let drawing = drawing.get_or_insert_with(|| {
            let descriptor = configuration.descriptor(
                self.0.size,
                configuration.usage()
                    | wit::GpuTextureUsage::COPY_SRC
                    | wit::GpuTextureUsage::RENDER_ATTACHMENT,
            );
            let native = native_descriptor(&descriptor);
            Drawing {
                parent: owner.created(owner.device.raw.create_texture(&native)),
                current: None,
            }
        });
        if let Some(current) = &drawing.current {
            return Ok(wit::GpuTexture::new(current.clone()));
        }
        let descriptor = configuration.descriptor(self.0.size, configuration.usage());
        let native = native_descriptor(&descriptor);
        let child = match drawing.parent.create_child_texture(&native) {
            Ok(child) => super::value::Object::new(owner.clone(), child, None),
            Err(error) => {
                owner.invalid(error.to_string());
                super::value::Object::invalid(owner.clone(), None)
            }
        };
        let texture = Texture {
            object: child,
            descriptor,
        };
        drawing.current = Some(texture.clone());
        Ok(wit::GpuTexture::new(texture))
    }
}

fn native_descriptor(
    descriptor: &wit::GpuTextureDescriptor,
) -> resource::TextureDescriptor<'static> {
    resource::TextureDescriptor {
        label: None,
        size: descriptor.size.convert(),
        mip_level_count: descriptor.mip_level_count.unwrap_or(1),
        sample_count: descriptor.sample_count.unwrap_or(1),
        dimension: wgpu_types::TextureDimension::D2,
        format: descriptor.format.convert(),
        usage: descriptor.usage.convert(),
        view_formats: descriptor
            .view_formats
            .as_deref()
            .unwrap_or_default()
            .iter()
            .copied()
            .map(Convert::convert)
            .collect(),
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
        let (device, parent, format) = {
            let mut state = self.shared.state.borrow_mut();
            if state.configuration.is_none() {
                return Err(platform::Error::Unconfigured);
            }
            let drawing = state.expire();
            let configuration = state
                .configuration
                .as_ref()
                .ok_or(platform::Error::Unconfigured)?;
            let device = configuration.device.clone();
            let format = configuration.format;
            let parent = match drawing {
                Some(drawing) => drawing.parent,
                // Nothing was drawn: present the cleared drawing buffer.
                None => {
                    let descriptor = configuration.descriptor(
                        self.shared.size,
                        configuration.usage()
                            | wit::GpuTextureUsage::COPY_SRC
                            | wit::GpuTextureUsage::RENDER_ATTACHMENT,
                    );
                    let owner = &device.object.owner;
                    owner.created(
                        owner
                            .device
                            .raw
                            .create_texture(&native_descriptor(&descriptor)),
                    )
                }
            };
            (device, parent, format)
        };
        let backend = &device.object.owner.device;
        let image = LinearImage::allocate(
            backend.raw.clone(),
            self.shared.size.width,
            self.shared.size.height,
            native_format(format),
        )
        .map_err(|error| platform::Error::Presentation(error.to_string()))?;
        // SAFETY: the parent was created on this device with COPY_SRC and
        // RENDER_ATTACHMENT at the canvas extent and the configured format, one
        // mip, layer and sample; the component is single-threaded and the image
        // was just allocated on this device.
        let frame = unsafe { image.submit(backend, parent) }
            .map_err(|error| platform::Error::Presentation(error.to_string()))?;
        frame.present(&self.surface).await.map_err(surface_error)?;
        Ok(())
    }

    fn events(&self) -> StreamReader<surface_wit::InputEvent> {
        self.surface.events()
    }
}
