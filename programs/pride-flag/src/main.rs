//! `pride-flag`: a waving pride flag drawn in 3D through `wasi:webgpu`.
//!
//! The program is the whole-path acceptance of WebGPU on Helios: the
//! provider plugged into it at build time drives the GPU over Venus, the
//! canvas's frames are copied into images the compositor scans out, and a
//! screendump of the desktop shows the result. It prints a line at each
//! step, so a run that stops can be placed.

use std::time::{Duration, Instant};

use helios_api::webgpu::{
    Canvas, CanvasError, ConfigureCanvasError, GetCurrentTextureError, GpuBindGroupDescriptor,
    GpuBindGroupEntry, GpuBindingResource, GpuBufferBinding, GpuBufferDescriptor, GpuBufferUsage,
    GpuCanvasConfiguration, GpuColor, GpuColorTargetState, GpuCompareFunction,
    GpuDepthStencilState, GpuDevice, GpuExtent3D, GpuFragmentState, GpuLayoutMode, GpuLoadOp,
    GpuPrimitiveState, GpuPrimitiveTopology, GpuRenderPassColorAttachment,
    GpuRenderPassDepthStencilAttachment, GpuRenderPassDescriptor, GpuRenderPipelineDescriptor,
    GpuShaderModuleDescriptor, GpuStoreOp, GpuTextureDescriptor, GpuTextureFormat, GpuTextureUsage,
    GpuVertexState, RequestDeviceError, WriteBufferError, get_gpu,
};
use thiserror::Error;

/// The window's size in pixels, 3:2 like the flag.
const WIDTH: u32 = 480;
const HEIGHT: u32 = 320;

/// The canvas format the linear presentation image carries.
const FORMAT: GpuTextureFormat = GpuTextureFormat::Bgra8unorm;
const DEPTH_FORMAT: GpuTextureFormat = GpuTextureFormat::Depth32float;

/// The grid `flag.wgsl` builds its mesh from: `COLUMNS * ROWS` quads of
/// two triangles each.
const COLUMNS: u32 = 48;
const ROWS: u32 = 24;
const VERTICES: u32 = COLUMNS * ROWS * 6;

/// `flag.wgsl`'s `Frame` uniform: time, aspect and padding to 16 bytes.
const FRAME_UNIFORM_BYTES: u64 = 16;

/// The background, a dark blue-grey.
const CLEAR: GpuColor = GpuColor {
    r: 0.05,
    g: 0.06,
    b: 0.09,
    a: 1.0,
};

/// How long the flag waves. `screendump --run` takes its captures while
/// the program runs and calls one that exits before them a failure; the
/// captures follow a twenty-second settle, so the animation outlives
/// them with room on both sides.
const RUN: Duration = Duration::from_secs(45);

/// One progress line per this many frames.
const REPORT_EVERY: u64 = 60;

#[derive(Debug, Error)]
enum FlagError {
    #[error("no GPU adapter is available")]
    NoAdapter,
    #[error("the adapter refused a device: {0:?}")]
    Device(RequestDeviceError),
    #[error("the canvas failed: {0:?}")]
    Canvas(CanvasError),
    #[error("the canvas refused its configuration: {0:?}")]
    Configure(ConfigureCanvasError),
    #[error("the canvas has no texture to draw into: {0:?}")]
    CurrentTexture(GetCurrentTextureError),
    #[error("the frame uniform could not be written: {0:?}")]
    WriteBuffer(WriteBufferError),
}

#[helios_api::main]
async fn main() -> Result<(), FlagError> {
    let result = wave().await;
    if let Err(error) = &result {
        println!("pride-flag:error={error}");
    }
    result
}

async fn wave() -> Result<(), FlagError> {
    let adapter = get_gpu()
        .request_adapter(None)
        .await
        .ok_or(FlagError::NoAdapter)?;
    let device = adapter
        .request_device(None)
        .await
        .map_err(FlagError::Device)?;
    println!("pride-flag:device");

    let canvas = Canvas::create(WIDTH, HEIGHT)
        .await
        .map_err(FlagError::Canvas)?;
    let size = canvas.size();
    let context = canvas.context();
    context
        .configure(&GpuCanvasConfiguration {
            device: &device,
            format: FORMAT,
            usage: Some(GpuTextureUsage::RENDER_ATTACHMENT),
            view_formats: None,
            color_space: None,
            tone_mapping: None,
            alpha_mode: None,
        })
        .map_err(FlagError::Configure)?;
    println!(
        "pride-flag:canvas width={} height={}",
        size.width, size.height
    );

    let scene = Scene::new(&device, size.width, size.height);
    let queue = device.queue();
    let aspect = size.width as f32 / size.height as f32;
    let start = Instant::now();
    let mut frames = 0u64;
    while start.elapsed() < RUN {
        let time = start.elapsed().as_secs_f32();
        let mut uniform = [0u8; FRAME_UNIFORM_BYTES as usize];
        uniform[0..4].copy_from_slice(&time.to_le_bytes());
        uniform[4..8].copy_from_slice(&aspect.to_le_bytes());
        queue
            .write_buffer_with_copy(&scene.uniform, 0, &uniform, None, None)
            .map_err(FlagError::WriteBuffer)?;

        let texture = context
            .get_current_texture()
            .map_err(FlagError::CurrentTexture)?;
        let view = texture.create_view(None);
        let encoder = device.create_command_encoder(None);
        let pass = encoder.begin_render_pass(&GpuRenderPassDescriptor {
            color_attachments: vec![Some(GpuRenderPassColorAttachment {
                view: &view,
                depth_slice: None,
                resolve_target: None,
                clear_value: Some(CLEAR),
                load_op: GpuLoadOp::Clear,
                store_op: GpuStoreOp::Store,
            })],
            depth_stencil_attachment: Some(GpuRenderPassDepthStencilAttachment {
                view: &scene.depth,
                depth_clear_value: Some(1.0),
                depth_load_op: Some(GpuLoadOp::Clear),
                depth_store_op: Some(GpuStoreOp::Discard),
                depth_read_only: None,
                stencil_clear_value: None,
                stencil_load_op: None,
                stencil_store_op: None,
                stencil_read_only: None,
            }),
            occlusion_query_set: None,
            timestamp_writes: None,
            max_draw_count: None,
            label: None,
        });
        pass.set_pipeline(&scene.pipeline);
        pass.set_bind_group(0, Some(&scene.bind_group), None, None, None)
            .expect("a bind group without dynamic offsets has no offset range to violate");
        pass.draw(VERTICES, None, None, None);
        pass.end();
        queue.submit(&[&encoder.finish(None)]);
        canvas.present().await.map_err(FlagError::Canvas)?;

        if frames.is_multiple_of(REPORT_EVERY) {
            println!("pride-flag:frame {frames} time={time:.2}");
        }
        frames += 1;
    }
    println!("pride-flag:done frames={frames}");
    Ok(())
}

/// What every frame draws with.
struct Scene {
    pipeline: helios_api::webgpu::GpuRenderPipeline,
    bind_group: helios_api::webgpu::GpuBindGroup,
    uniform: helios_api::webgpu::GpuBuffer,
    depth: helios_api::webgpu::GpuTextureView,
}

impl Scene {
    fn new(device: &GpuDevice, width: u32, height: u32) -> Self {
        let module = device.create_shader_module(&GpuShaderModuleDescriptor {
            code: include_str!("flag.wgsl").to_owned(),
            compilation_hints: None,
            label: Some("flag".to_owned()),
        });
        let pipeline = device.create_render_pipeline(GpuRenderPipelineDescriptor {
            vertex: GpuVertexState {
                buffers: None,
                module: &module,
                entry_point: Some("vertex".to_owned()),
                constants: None,
            },
            primitive: Some(GpuPrimitiveState {
                topology: Some(GpuPrimitiveTopology::TriangleList),
                strip_index_format: None,
                front_face: None,
                // Both faces of the cloth show as it turns.
                cull_mode: None,
                unclipped_depth: None,
            }),
            depth_stencil: Some(GpuDepthStencilState {
                format: DEPTH_FORMAT,
                depth_write_enabled: Some(true),
                depth_compare: Some(GpuCompareFunction::Less),
                stencil_front: None,
                stencil_back: None,
                stencil_read_mask: None,
                stencil_write_mask: None,
                depth_bias: None,
                depth_bias_slope_scale: None,
                depth_bias_clamp: None,
            }),
            multisample: None,
            fragment: Some(GpuFragmentState {
                targets: vec![Some(GpuColorTargetState {
                    format: FORMAT,
                    blend: None,
                    write_mask: None,
                })],
                module: &module,
                entry_point: Some("fragment".to_owned()),
                constants: None,
            }),
            layout: GpuLayoutMode::Auto,
            label: Some("flag".to_owned()),
        });
        let uniform = device.create_buffer(&GpuBufferDescriptor {
            size: FRAME_UNIFORM_BYTES,
            usage: GpuBufferUsage::UNIFORM | GpuBufferUsage::COPY_DST,
            mapped_at_creation: None,
            label: Some("frame".to_owned()),
        });
        let layout = pipeline.get_bind_group_layout(0);
        let bind_group = device.create_bind_group(&GpuBindGroupDescriptor {
            layout: &layout,
            entries: vec![GpuBindGroupEntry {
                binding: 0,
                resource: GpuBindingResource::GpuBufferBinding(GpuBufferBinding {
                    buffer: &uniform,
                    offset: None,
                    size: None,
                }),
            }],
            label: None,
        });
        let depth = device
            .create_texture(&GpuTextureDescriptor {
                size: GpuExtent3D {
                    width,
                    height: Some(height),
                    depth_or_array_layers: None,
                },
                mip_level_count: None,
                sample_count: None,
                dimension: None,
                format: DEPTH_FORMAT,
                usage: GpuTextureUsage::RENDER_ATTACHMENT,
                view_formats: None,
                texture_binding_view_dimension: None,
                label: Some("depth".to_owned()),
            })
            .create_view(None);
        Self {
            pipeline,
            bind_group,
            uniform,
            depth,
        }
    }
}
