//! Exhaustive WIT-to-wgpu value conversions and WebGPU descriptor defaults.

use super::wit;

pub trait Convert {
    type Output;
    fn convert(self) -> Self::Output;
}

macro_rules! enumeration {
    ($source:ident => $target:ident { $($from:ident => $to:ident),* $(,)? }) => {
        impl Convert for wit::$source {
            type Output = wgpu::$target;
            fn convert(self) -> Self::Output {
                match self { $(Self::$from => wgpu::$target::$to),* }
            }
        }
    };
}

enumeration!(GpuAddressMode => AddressMode { ClampToEdge => ClampToEdge, Repeat => Repeat, MirrorRepeat => MirrorRepeat });
enumeration!(GpuBlendFactor => BlendFactor {
    Zero => Zero, One => One, Src => Src, OneMinusSrc => OneMinusSrc,
    SrcAlpha => SrcAlpha, OneMinusSrcAlpha => OneMinusSrcAlpha,
    Dst => Dst, OneMinusDst => OneMinusDst, DstAlpha => DstAlpha,
    OneMinusDstAlpha => OneMinusDstAlpha, SrcAlphaSaturated => SrcAlphaSaturated,
    Constant => Constant, OneMinusConstant => OneMinusConstant,
    Src1 => Src1, OneMinusSrc1 => OneMinusSrc1, Src1Alpha => Src1Alpha,
    OneMinusSrc1Alpha => OneMinusSrc1Alpha,
});
enumeration!(GpuBlendOperation => BlendOperation { Add => Add, Subtract => Subtract, ReverseSubtract => ReverseSubtract, Min => Min, Max => Max });
enumeration!(GpuCompareFunction => CompareFunction { Never => Never, Less => Less, Equal => Equal, LessEqual => LessEqual, Greater => Greater, NotEqual => NotEqual, GreaterEqual => GreaterEqual, Always => Always });
enumeration!(GpuFilterMode => FilterMode { Nearest => Nearest, Linear => Linear });
enumeration!(GpuMipmapFilterMode => MipmapFilterMode { Nearest => Nearest, Linear => Linear });
enumeration!(GpuFrontFace => FrontFace { Ccw => Ccw, Cw => Cw });
enumeration!(GpuIndexFormat => IndexFormat { Uint16 => Uint16, Uint32 => Uint32 });
enumeration!(GpuPrimitiveTopology => PrimitiveTopology { PointList => PointList, LineList => LineList, LineStrip => LineStrip, TriangleList => TriangleList, TriangleStrip => TriangleStrip });
enumeration!(GpuStencilOperation => StencilOperation { Keep => Keep, Zero => Zero, Replace => Replace, Invert => Invert, IncrementClamp => IncrementClamp, DecrementClamp => DecrementClamp, IncrementWrap => IncrementWrap, DecrementWrap => DecrementWrap });
enumeration!(GpuStorageTextureAccess => StorageTextureAccess { WriteOnly => WriteOnly, ReadOnly => ReadOnly, ReadWrite => ReadWrite });
enumeration!(GpuStoreOp => StoreOp { Store => Store, Discard => Discard });
enumeration!(GpuTextureAspect => TextureAspect { All => All, StencilOnly => StencilOnly, DepthOnly => DepthOnly });
enumeration!(GpuTextureDimension => TextureDimension { D1 => D1, D2 => D2, D3 => D3 });
enumeration!(GpuTextureViewDimension => TextureViewDimension { D1 => D1, D2 => D2, D2Array => D2Array, Cube => Cube, CubeArray => CubeArray, D3 => D3 });
enumeration!(GpuVertexStepMode => VertexStepMode { Vertex => Vertex, Instance => Instance });
enumeration!(GpuPowerPreference => PowerPreference { LowPower => LowPower, HighPerformance => HighPerformance });
enumeration!(GpuSamplerBindingType => SamplerBindingType { Filtering => Filtering, NonFiltering => NonFiltering, Comparison => Comparison });
enumeration!(GpuQueryType => QueryType { Occlusion => Occlusion, Timestamp => Timestamp });
enumeration!(GpuErrorFilter => ErrorFilter { Validation => Validation, OutOfMemory => OutOfMemory, Internal => Internal });
enumeration!(GpuVertexFormat => VertexFormat {
    Uint8 => Uint8, Uint8x2 => Uint8x2, Uint8x4 => Uint8x4,
    Sint8 => Sint8, Sint8x2 => Sint8x2, Sint8x4 => Sint8x4,
    Unorm8 => Unorm8, Unorm8x2 => Unorm8x2, Unorm8x4 => Unorm8x4,
    Snorm8 => Snorm8, Snorm8x2 => Snorm8x2, Snorm8x4 => Snorm8x4,
    Uint16 => Uint16, Uint16x2 => Uint16x2, Uint16x4 => Uint16x4,
    Sint16 => Sint16, Sint16x2 => Sint16x2, Sint16x4 => Sint16x4,
    Unorm16 => Unorm16, Unorm16x2 => Unorm16x2, Unorm16x4 => Unorm16x4,
    Snorm16 => Snorm16, Snorm16x2 => Snorm16x2, Snorm16x4 => Snorm16x4,
    Float16 => Float16, Float16x2 => Float16x2, Float16x4 => Float16x4,
    Float32 => Float32, Float32x2 => Float32x2, Float32x3 => Float32x3, Float32x4 => Float32x4,
    Uint32 => Uint32, Uint32x2 => Uint32x2, Uint32x3 => Uint32x3, Uint32x4 => Uint32x4,
    Sint32 => Sint32, Sint32x2 => Sint32x2, Sint32x3 => Sint32x3, Sint32x4 => Sint32x4,
    Unorm1010102 => Unorm10_10_10_2, Unorm8x4Bgra => Unorm8x4Bgra,
});

macro_rules! formats {
    (plain { $($from:ident => $to:ident),* $(,)? } astc { $($linear:ident, $srgb:ident => $block:ident),* $(,)? }) => {
        impl Convert for wit::GpuTextureFormat {
            type Output = wgpu::TextureFormat;
            fn convert(self) -> Self::Output {
                match self {
                    $(Self::$from => wgpu::TextureFormat::$to,)*
                    $(Self::$linear => wgpu::TextureFormat::Astc { block: wgpu::AstcBlock::$block, channel: wgpu::AstcChannel::Unorm },
                      Self::$srgb => wgpu::TextureFormat::Astc { block: wgpu::AstcBlock::$block, channel: wgpu::AstcChannel::UnormSrgb },)*
                }
            }
        }
    };
}

formats! {
    plain {
        R8unorm => R8Unorm, R8snorm => R8Snorm, R8uint => R8Uint, R8sint => R8Sint,
        R16unorm => R16Unorm, R16snorm => R16Snorm, R16uint => R16Uint, R16sint => R16Sint, R16float => R16Float,
        Rg8unorm => Rg8Unorm, Rg8snorm => Rg8Snorm, Rg8uint => Rg8Uint, Rg8sint => Rg8Sint,
        R32uint => R32Uint, R32sint => R32Sint, R32float => R32Float,
        Rg16unorm => Rg16Unorm, Rg16snorm => Rg16Snorm, Rg16uint => Rg16Uint, Rg16sint => Rg16Sint, Rg16float => Rg16Float,
        Rgba8unorm => Rgba8Unorm, Rgba8unormSrgb => Rgba8UnormSrgb, Rgba8snorm => Rgba8Snorm, Rgba8uint => Rgba8Uint, Rgba8sint => Rgba8Sint,
        Bgra8unorm => Bgra8Unorm, Bgra8unormSrgb => Bgra8UnormSrgb,
        Rgb9e5ufloat => Rgb9e5Ufloat, Rgb10a2uint => Rgb10a2Uint, Rgb10a2unorm => Rgb10a2Unorm, Rg11b10ufloat => Rg11b10Ufloat,
        Rg32uint => Rg32Uint, Rg32sint => Rg32Sint, Rg32float => Rg32Float,
        Rgba16unorm => Rgba16Unorm, Rgba16snorm => Rgba16Snorm, Rgba16uint => Rgba16Uint, Rgba16sint => Rgba16Sint, Rgba16float => Rgba16Float,
        Rgba32uint => Rgba32Uint, Rgba32sint => Rgba32Sint, Rgba32float => Rgba32Float,
        Stencil8 => Stencil8, Depth16unorm => Depth16Unorm, Depth24plus => Depth24Plus, Depth24plusStencil8 => Depth24PlusStencil8, Depth32float => Depth32Float, Depth32floatStencil8 => Depth32FloatStencil8,
        Bc1RgbaUnorm => Bc1RgbaUnorm, Bc1RgbaUnormSrgb => Bc1RgbaUnormSrgb,
        Bc2RgbaUnorm => Bc2RgbaUnorm, Bc2RgbaUnormSrgb => Bc2RgbaUnormSrgb,
        Bc3RgbaUnorm => Bc3RgbaUnorm, Bc3RgbaUnormSrgb => Bc3RgbaUnormSrgb,
        Bc4RUnorm => Bc4RUnorm, Bc4RSnorm => Bc4RSnorm,
        Bc5RgUnorm => Bc5RgUnorm, Bc5RgSnorm => Bc5RgSnorm,
        Bc6hRgbUfloat => Bc6hRgbUfloat, Bc6hRgbFloat => Bc6hRgbFloat,
        Bc7RgbaUnorm => Bc7RgbaUnorm, Bc7RgbaUnormSrgb => Bc7RgbaUnormSrgb,
        Etc2Rgb8unorm => Etc2Rgb8Unorm, Etc2Rgb8unormSrgb => Etc2Rgb8UnormSrgb,
        Etc2Rgb8a1unorm => Etc2Rgb8A1Unorm, Etc2Rgb8a1unormSrgb => Etc2Rgb8A1UnormSrgb,
        Etc2Rgba8unorm => Etc2Rgba8Unorm, Etc2Rgba8unormSrgb => Etc2Rgba8UnormSrgb,
        EacR11unorm => EacR11Unorm, EacR11snorm => EacR11Snorm, EacRg11unorm => EacRg11Unorm, EacRg11snorm => EacRg11Snorm,
    }
    astc {
        Astc4x4Unorm, Astc4x4UnormSrgb => B4x4,
        Astc5x4Unorm, Astc5x4UnormSrgb => B5x4,
        Astc5x5Unorm, Astc5x5UnormSrgb => B5x5,
        Astc6x5Unorm, Astc6x5UnormSrgb => B6x5,
        Astc6x6Unorm, Astc6x6UnormSrgb => B6x6,
        Astc8x5Unorm, Astc8x5UnormSrgb => B8x5,
        Astc8x6Unorm, Astc8x6UnormSrgb => B8x6,
        Astc8x8Unorm, Astc8x8UnormSrgb => B8x8,
        Astc10x5Unorm, Astc10x5UnormSrgb => B10x5,
        Astc10x6Unorm, Astc10x6UnormSrgb => B10x6,
        Astc10x8Unorm, Astc10x8UnormSrgb => B10x8,
        Astc10x10Unorm, Astc10x10UnormSrgb => B10x10,
        Astc12x10Unorm, Astc12x10UnormSrgb => B12x10,
        Astc12x12Unorm, Astc12x12UnormSrgb => B12x12,
    }
}

impl Convert for wit::GpuExtent3D {
    type Output = wgpu::Extent3d;
    fn convert(self) -> Self::Output {
        wgpu::Extent3d {
            width: self.width,
            height: self.height.unwrap_or(1),
            depth_or_array_layers: self.depth_or_array_layers.unwrap_or(1),
        }
    }
}
impl Convert for wit::GpuOrigin3D {
    type Output = wgpu::Origin3d;
    fn convert(self) -> Self::Output {
        wgpu::Origin3d {
            x: self.x.unwrap_or(0),
            y: self.y.unwrap_or(0),
            z: self.z.unwrap_or(0),
        }
    }
}
impl Convert for wit::GpuColor {
    type Output = wgpu::Color;
    fn convert(self) -> Self::Output {
        wgpu::Color {
            r: self.r,
            g: self.g,
            b: self.b,
            a: self.a,
        }
    }
}
impl Convert for wit::GpuBlendComponent {
    type Output = wgpu::BlendComponent;
    fn convert(self) -> Self::Output {
        wgpu::BlendComponent {
            operation: self
                .operation
                .map(Convert::convert)
                .unwrap_or(wgpu::BlendOperation::Add),
            src_factor: self
                .src_factor
                .map(Convert::convert)
                .unwrap_or(wgpu::BlendFactor::One),
            dst_factor: self
                .dst_factor
                .map(Convert::convert)
                .unwrap_or(wgpu::BlendFactor::Zero),
        }
    }
}
impl Convert for wit::GpuBlendState {
    type Output = wgpu::BlendState;
    fn convert(self) -> Self::Output {
        wgpu::BlendState {
            color: self.color.convert(),
            alpha: self.alpha.convert(),
        }
    }
}
impl Convert for wit::GpuColorWrite {
    type Output = wgpu::ColorWrites;
    fn convert(self) -> Self::Output {
        if self.bits() & Self::ALL.bits() != 0 {
            wgpu::ColorWrites::ALL
        } else {
            wgpu::ColorWrites::from_bits_retain(u32::from(self.bits()))
        }
    }
}
impl Convert for wit::GpuBufferUsage {
    type Output = wgpu::BufferUsages;
    fn convert(self) -> Self::Output {
        wgpu::BufferUsages::from_bits_retain(u32::from(self.bits()))
    }
}
impl Convert for wit::GpuTextureUsage {
    type Output = wgpu::TextureUsages;
    fn convert(self) -> Self::Output {
        wgpu::TextureUsages::from_bits_retain(u32::from(self.bits()))
    }
}
impl Convert for wit::GpuShaderStage {
    type Output = wgpu::ShaderStages;
    fn convert(self) -> Self::Output {
        wgpu::ShaderStages::from_bits_retain(u32::from(self.bits()))
    }
}
impl Convert for wit::GpuPrimitiveState {
    type Output = wgpu::PrimitiveState;
    fn convert(self) -> Self::Output {
        wgpu::PrimitiveState {
            topology: self.topology.map(Convert::convert).unwrap_or_default(),
            strip_index_format: self.strip_index_format.map(Convert::convert),
            front_face: self.front_face.map(Convert::convert).unwrap_or_default(),
            cull_mode: match self.cull_mode.unwrap_or(wit::GpuCullMode::None) {
                wit::GpuCullMode::None => None,
                wit::GpuCullMode::Front => Some(wgpu::Face::Front),
                wit::GpuCullMode::Back => Some(wgpu::Face::Back),
            },
            unclipped_depth: self.unclipped_depth.unwrap_or(false),
            polygon_mode: wgpu::PolygonMode::Fill,
            conservative: false,
        }
    }
}
impl Convert for wit::GpuMultisampleState {
    type Output = wgpu::MultisampleState;
    fn convert(self) -> Self::Output {
        wgpu::MultisampleState {
            count: self.count.unwrap_or(1),
            mask: u64::from(self.mask.unwrap_or(u32::MAX)),
            alpha_to_coverage_enabled: self.alpha_to_coverage_enabled.unwrap_or(false),
        }
    }
}
impl Convert for wit::GpuStencilFaceState {
    type Output = wgpu::StencilFaceState;
    fn convert(self) -> Self::Output {
        wgpu::StencilFaceState {
            compare: self
                .compare
                .map(Convert::convert)
                .unwrap_or(wgpu::CompareFunction::Always),
            fail_op: self.fail_op.map(Convert::convert).unwrap_or_default(),
            depth_fail_op: self.depth_fail_op.map(Convert::convert).unwrap_or_default(),
            pass_op: self.pass_op.map(Convert::convert).unwrap_or_default(),
        }
    }
}
impl Convert for wit::GpuDepthStencilState {
    type Output = wgpu::DepthStencilState;
    fn convert(self) -> Self::Output {
        wgpu::DepthStencilState {
            format: self.format.convert(),
            depth_write_enabled: self.depth_write_enabled,
            depth_compare: self.depth_compare.map(Convert::convert),
            stencil: wgpu::StencilState {
                front: self.stencil_front.map(Convert::convert).unwrap_or_default(),
                back: self.stencil_back.map(Convert::convert).unwrap_or_default(),
                read_mask: self.stencil_read_mask.unwrap_or(u32::MAX),
                write_mask: self.stencil_write_mask.unwrap_or(u32::MAX),
            },
            bias: wgpu::DepthBiasState {
                constant: self.depth_bias.unwrap_or(0),
                slope_scale: self.depth_bias_slope_scale.unwrap_or(0.0),
                clamp: self.depth_bias_clamp.unwrap_or(0.0),
            },
        }
    }
}
impl Convert for wit::GpuColorTargetState {
    type Output = wgpu::ColorTargetState;
    fn convert(self) -> Self::Output {
        wgpu::ColorTargetState {
            format: self.format.convert(),
            blend: self.blend.map(Convert::convert),
            write_mask: self
                .write_mask
                .map(Convert::convert)
                .unwrap_or(wgpu::ColorWrites::ALL),
        }
    }
}
impl Convert for wit::GpuVertexAttribute {
    type Output = wgpu::VertexAttribute;
    fn convert(self) -> Self::Output {
        wgpu::VertexAttribute {
            format: self.format.convert(),
            offset: self.offset,
            shader_location: self.shader_location,
        }
    }
}
impl Convert for wit::GpuTexelCopyBufferLayout {
    type Output = wgpu::TexelCopyBufferLayout;
    fn convert(self) -> Self::Output {
        wgpu::TexelCopyBufferLayout {
            offset: self.offset.unwrap_or(0),
            bytes_per_row: self.bytes_per_row,
            rows_per_image: self.rows_per_image,
        }
    }
}
