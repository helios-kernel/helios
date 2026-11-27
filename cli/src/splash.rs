//! Procedural rasteriser for the Limine UEFI bootloader splash wallpaper.
//!
//! Renders the Helios emblem (`docs/logo.svg`, `viewBox="0 0 1000 1000"`) onto
//! pure white (`#FFFFFF`) in memory as an RGB8 PNG written to
//! `/boot/limine/splash.png` during `limine-uefi-image`. No binary image is
//! checked into the repository.

/// Output splash dimensions in pixels.
///
/// Sized to fit comfortably inside small firmware GOP modes (such as 640x480)
/// while holding the emblem at the canonical 1080p scale (`0.25 * 1080 = 270 px`
/// per 1000 SVG units) with clean white margins on every side.
pub(crate) const SPLASH_WIDTH: u32 = 360;
pub(crate) const SPLASH_HEIGHT: u32 = 360;

/// SVG units (`0..1000`) mapped onto pixels at 1080p desktop scale.
const EMBLEM_SCALE: f64 = 270.0;
/// Visual centroid of the four-circle emblem in `docs/logo.svg` coordinates.
/// Anchoring this point at the PNG centre places the emblem at the exact centre
/// of the screen under Limine's `wallpaper_style: centered`.
const CENTROID_X: f64 = 500.0;
const CENTROID_Y: f64 = 560.5;

/// Sun main circle (`R = 245` passing through `(271.6, 596.7)` and `(728.4, 596.7)`).
const SUN_CX: f64 = 500.0;
const SUN_CY: f64 = 508.0522;
const SUN_R: f64 = 245.0;

/// Sun bottom cutout circle (`R = 513` passing through `(728.4, 596.7)` and `(271.6, 596.7)`).
const SUN_CUT_CY: f64 = 1056.05;
const SUN_CUT_R: f64 = 513.0;

/// Crescent outer circle (`R = 483` passing through `(158, 715)` and `(842, 715)`).
const CRESCENT_OUTER_CY: f64 = 1056.0645;
const CRESCENT_OUTER_R: f64 = 483.0;

/// Crescent inner circle (`R = 675` passing through `(842, 715)` and `(158, 715)`).
const CRESCENT_INNER_CY: f64 = 1296.9458;
const CRESCENT_INNER_R: f64 = 675.0;

/// Tight SVG bounding box around the emblem plus anti-aliasing margin.
const EMBLEM_MIN_X: f64 = 150.0;
const EMBLEM_MAX_X: f64 = 850.0;
const EMBLEM_MIN_Y: f64 = 255.0;
const EMBLEM_MAX_Y: f64 = 725.0;

const BG_RGB: [u8; 3] = [0xFF, 0xFF, 0xFF];
const SUN_RGB: [u8; 3] = [0xFF, 0x6A, 0x00];
const CRESCENT_RGB: [u8; 3] = [0x0A, 0x0A, 0x0A];

/// Subpixel grid dimension (`4x4 = 16` samples per pixel) for anti-aliased
/// coverage that preserves the sharp crescent tips and sun corners.
const SUPERSAMPLE: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SampleHit {
    Background,
    Sun,
    Crescent,
}

fn sample_svg(x: f64, y: f64) -> SampleHit {
    let dx = x - SUN_CX;
    let dy_sun = y - SUN_CY;
    if dx * dx + dy_sun * dy_sun <= SUN_R * SUN_R {
        let dy_cut = y - SUN_CUT_CY;
        if dx * dx + dy_cut * dy_cut >= SUN_CUT_R * SUN_CUT_R {
            return SampleHit::Sun;
        }
    }

    let dy_outer = y - CRESCENT_OUTER_CY;
    if dx * dx + dy_outer * dy_outer <= CRESCENT_OUTER_R * CRESCENT_OUTER_R {
        let dy_inner = y - CRESCENT_INNER_CY;
        if dx * dx + dy_inner * dy_inner >= CRESCENT_INNER_R * CRESCENT_INNER_R {
            return SampleHit::Crescent;
        }
    }

    SampleHit::Background
}

fn pixel_to_svg(px: f64, py: f64) -> (f64, f64) {
    let inv_scale = 1000.0 / EMBLEM_SCALE;
    let half_w = f64::from(SPLASH_WIDTH) * 0.5;
    let half_h = f64::from(SPLASH_HEIGHT) * 0.5;
    (
        CENTROID_X + (px - half_w) * inv_scale,
        CENTROID_Y + (py - half_h) * inv_scale,
    )
}

fn rasterize_rgb8() -> Vec<u8> {
    let width = SPLASH_WIDTH as usize;
    let height = SPLASH_HEIGHT as usize;
    let mut rgb = vec![0xFFu8; width * height * 3];
    let inv_sub = 1.0 / (SUPERSAMPLE as f64);
    let total_samples = (SUPERSAMPLE * SUPERSAMPLE) as u32;

    for y in 0..height {
        let (_, svg_y_mid) = pixel_to_svg(0.0, y as f64 + 0.5);
        if !(EMBLEM_MIN_Y..=EMBLEM_MAX_Y).contains(&svg_y_mid) {
            continue;
        }
        for x in 0..width {
            let (svg_x_mid, _) = pixel_to_svg(x as f64 + 0.5, y as f64 + 0.5);
            if !(EMBLEM_MIN_X..=EMBLEM_MAX_X).contains(&svg_x_mid) {
                continue;
            }
            let mut r_sum = 0u32;
            let mut g_sum = 0u32;
            let mut b_sum = 0u32;
            for sy in 0..SUPERSAMPLE {
                let py = y as f64 + (sy as f64 + 0.5) * inv_sub;
                for sx in 0..SUPERSAMPLE {
                    let px = x as f64 + (sx as f64 + 0.5) * inv_sub;
                    let (ux, uy) = pixel_to_svg(px, py);
                    let colour = match sample_svg(ux, uy) {
                        SampleHit::Background => BG_RGB,
                        SampleHit::Sun => SUN_RGB,
                        SampleHit::Crescent => CRESCENT_RGB,
                    };
                    r_sum += u32::from(colour[0]);
                    g_sum += u32::from(colour[1]);
                    b_sum += u32::from(colour[2]);
                }
            }
            let offset = (y * width + x) * 3;
            rgb[offset] = ((r_sum + total_samples / 2) / total_samples) as u8;
            rgb[offset + 1] = ((g_sum + total_samples / 2) / total_samples) as u8;
            rgb[offset + 2] = ((b_sum + total_samples / 2) / total_samples) as u8;
        }
    }

    rgb
}

/// Renders the Helios bootloader splash image as RGB8 PNG bytes.
pub(crate) fn render_splash_png() -> Result<Vec<u8>, png::EncodingError> {
    let rgb = rasterize_rgb8();
    let mut encoded = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut encoded, SPLASH_WIDTH, SPLASH_HEIGHT);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&rgb)?;
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::{
        BG_RGB, CENTROID_X, CENTROID_Y, CRESCENT_RGB, EMBLEM_SCALE, SPLASH_HEIGHT, SPLASH_WIDTH,
        SUN_RGB, render_splash_png,
    };

    fn svg_to_pixel(ux: f64, uy: f64) -> (usize, usize) {
        let scale = EMBLEM_SCALE / 1000.0;
        let x = (f64::from(SPLASH_WIDTH) * 0.5 + (ux - CENTROID_X) * scale).floor() as usize;
        let y = (f64::from(SPLASH_HEIGHT) * 0.5 + (uy - CENTROID_Y) * scale).floor() as usize;
        (x, y)
    }

    fn pixel_at(rgb: &[u8], x: usize, y: usize) -> [u8; 3] {
        let offset = (y * SPLASH_WIDTH as usize + x) * 3;
        [rgb[offset], rgb[offset + 1], rgb[offset + 2]]
    }

    #[test]
    fn splash_png_decodes_with_expected_geometry_and_colours() {
        let bytes = render_splash_png().expect("splash PNG encodes cleanly");
        assert!(
            bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
            "output must carry the PNG signature"
        );

        let decoder = png::Decoder::new(std::io::Cursor::new(&bytes));
        let mut reader = decoder.read_info().expect("splash PNG header decodes");
        let mut decoded = vec![0u8; reader.output_buffer_size().expect("buffer size fits")];
        let info = reader
            .next_frame(&mut decoded)
            .expect("splash PNG frame decodes");
        assert_eq!(info.width, SPLASH_WIDTH);
        assert_eq!(info.height, SPLASH_HEIGHT);
        assert_eq!(info.color_type, png::ColorType::Rgb);
        assert_eq!(info.bit_depth, png::BitDepth::Eight);
        let rgb = &decoded[..info.buffer_size()];

        // Corners stay pure white to blend seamlessly into `backdrop: ffffff`.
        assert_eq!(pixel_at(rgb, 0, 0), BG_RGB);
        assert_eq!(
            pixel_at(rgb, SPLASH_WIDTH as usize - 1, SPLASH_HEIGHT as usize - 1),
            BG_RGB
        );

        // Interior of the orange sun above the centroid.
        let (sun_x, sun_y) = svg_to_pixel(500.0, 420.0);
        assert_eq!(pixel_at(rgb, sun_x, sun_y), SUN_RGB);

        // Negative-space gap between sun cutout (y=543.05) and crescent outer arc (y=573.06).
        let (gap_x, gap_y) = svg_to_pixel(500.0, 558.0);
        assert_eq!(pixel_at(rgb, gap_x, gap_y), BG_RGB);

        // Interior of the dark crescent below the gap (y=573.06..621.95).
        let (crescent_x, crescent_y) = svg_to_pixel(500.0, 597.0);
        assert_eq!(pixel_at(rgb, crescent_x, crescent_y), CRESCENT_RGB);

        // The emblem is horizontally symmetric around the PNG centreline.
        for y in 0..SPLASH_HEIGHT as usize {
            for x in 0..(SPLASH_WIDTH as usize / 2) {
                assert_eq!(
                    pixel_at(rgb, x, y),
                    pixel_at(rgb, SPLASH_WIDTH as usize - 1 - x, y),
                    "horizontal asymmetry at ({x}, {y})"
                );
            }
        }
    }
}
