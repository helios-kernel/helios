//! Four-stage analytical SDF boot splash renderer and cross-fade transition.
//!
//! Renders the Helios emblem from `docs/logo.svg` (`viewBox 0..1000`, normalized
//! to `scale = min(width, height) * 0.25`) directly into a `bgrx8888` `u32`
//! frame buffer with tight [`Region`] damage tracking:
//!
//! 1. `0.00s..0.60s`: Crescent expands horizontally from `0.04 * scale` to
//!    `0.342 * scale` (`ease_out_quart`, opacity `smoothstep(0.0, 0.20, t)`),
//!    anchoring the full emblem centroid (`svg_y = 560.5`) at `height * 0.5`.
//! 2. `0.22s..1.25s`: Orange sun (`R = 0.245 * scale`) rises from inside the
//!    concentric inner cut circle (`R = 0.513 * scale`, `ease_out_cubic`),
//!    clipped by `max(d_sun, -d_cut)` to preserve the `0.030 * scale` gap above
//!    the crescent (`R_outer = 0.483 * scale`).
//! 3. `1.20s..2.00s`: Emblem shifts upward by `0.24 * scale` over
//!    `1.20s..1.95s` (`ease_in_out_cubic`), spanning `prev_logo_cy..logo_cy` so
//!    upward trails erase cleanly to `#FFFFFF`, while the capsule progress bar
//!    fades in over `1.40s..2.00s`.
//! 4. `2.00s+`: Static emblem (zero emblem SDF work); updates only the narrow
//!    capsule bounding box (`< 0.25%` of `1920x1080` pixels) with a chasing
//!    progress thumb.

use crate::damage::Region;
use crate::paint::Colour;

/// Pure white splash background (`#FFFFFF` in `bgrx8888`).
pub const SPLASH_BACKGROUND: Colour = Colour::new(0xFF, 0xFF, 0xFF);
/// Helios orange sun (`#FF6A00` in `bgrx8888`).
pub const SPLASH_SUN: Colour = Colour::new(0x00_FF, 0x6A, 0x00);
/// Deep black crescent and progress thumb (`#0A0A0A` in `bgrx8888`).
pub const SPLASH_FOREGROUND: Colour = Colour::new(0x0A, 0x0A, 0x0A);

/// Duration of the splash-to-console cross-fade transition in seconds.
pub const CROSSFADE_DURATION_SECS: f32 = 0.60;

const STAGE1_END: f32 = 0.60;
const STAGE2_START: f32 = 0.22;
const STAGE2_END: f32 = 1.25;
const STAGE3_SHIFT_START: f32 = 1.20;
const STAGE3_SHIFT_END: f32 = 1.95;
const STAGE3_BAR_START: f32 = 1.40;
const STAGE3_BAR_END: f32 = 2.00;

/// Normalized `docs/logo.svg` geometry (`1000` SVG units = `1.0 * scale`, origin `(500.0, 560.5)`).
///
/// Concentric cut circle (`R = 513`) and crescent outer circle (`R = 483`) share
/// center `(500.0, 1056.057)`, yielding `cy = (1056.057 - 560.5) / 1000 = 0.495557`.
const SUN_R: f32 = 0.245;
/// Final sun center offset from `(500.0, 560.5)`: `(508.052 - 560.5) / 1000`.
const SUN_CY_FINAL: f32 = -0.052_448;
const CUT_R: f32 = 0.513;
const CUT_CY: f32 = 0.495_557;
/// Starting sun center placed strictly inside the concentric cut circle (`CUT_CY - (CUT_R - SUN_R) + 0.015`).
const SUN_CY_START: f32 = CUT_CY - (CUT_R - SUN_R) + 0.015;

const ARC_OUT_R: f32 = 0.483;
const ARC_OUT_CY: f32 = CUT_CY;
const ARC_IN_R_FINAL: f32 = 0.675;
/// Inner crescent center offset from `(500.0, 560.5)`: `(1296.946 - 560.5) / 1000`.
const ARC_IN_CY: f32 = 0.736_446;
const ARC_TIP_X_START: f32 = 0.04;
const ARC_TIP_X_FINAL: f32 = 0.342;
/// Bottom tip y of the crescent in `docs/logo.svg`: `(715.0 - 560.5) / 1000`.
const ARC_TIP_Y: f32 = 0.1545;

const LOGO_SHIFT_OFFSET: f32 = 0.24;
const BAR_OFFSET_FROM_SHIFTED_LOGO: f32 = 0.42;
const BAR_FOLLOW_OFFSET: f32 = 0.05;
const BAR_HEIGHT: f32 = 4.0;
const BAR_TRACK_ALPHA: f32 = 0.12;
const CHASE_SPEED: f32 = 0.85;

/// Normalized logo bounding extents in `scale` units around `(cx, logo_cy)`.
const LOGO_HALF_W_EXTENT: f32 = 0.36;
const LOGO_TOP_EXTENT: f32 = 0.32;
const LOGO_BOT_EXTENT: f32 = 0.18;

/// Analytical SDF splash animation renderer with dirty-rectangle tracking.
#[derive(Clone, Debug)]
pub struct SplashRenderer {
    width: u32,
    height: u32,
    cleared: bool,
    prev_logo_cy: Option<f32>,
    logo_settled: bool,
    prev_bar_region: Option<Region>,
    bar_settled: bool,
    last_t: Option<f32>,
}

impl SplashRenderer {
    /// Creates a splash renderer targeting a `width x height` scanout.
    pub const fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            cleared: false,
            prev_logo_cy: None,
            logo_settled: false,
            prev_bar_region: None,
            bar_settled: false,
            last_t: None,
        }
    }

    /// Resets cached frame state so the next frame repaints the full screen.
    pub fn reset(&mut self) {
        self.cleared = false;
        self.prev_logo_cy = None;
        self.logo_settled = false;
        self.prev_bar_region = None;
        self.bar_settled = false;
        self.last_t = None;
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Renders the splash frame at `t_secs` into `pixels` (`bgrx8888` `u32` words).
    ///
    /// Returns the tight dirty [`Region`] modified on this frame, or `None` when
    /// the surface has zero area or cannot hold `height` rows of `stride_pixels`.
    pub fn render_frame(
        &mut self,
        t_secs: f32,
        pixels: &mut [u32],
        stride_pixels: usize,
    ) -> Option<Region> {
        if self.width == 0 || self.height == 0 || stride_pixels < self.width as usize {
            return None;
        }
        let required = (self.height as usize - 1)
            .checked_mul(stride_pixels)?
            .checked_add(self.width as usize)?;
        if pixels.len() < required {
            return None;
        }

        let t = t_secs.max(0.0);
        if self.last_t.is_some_and(|prev| t < prev) {
            self.reset();
        }
        self.last_t = Some(t);

        let bg_u32 = SPLASH_BACKGROUND.to_bgrx_u32();
        let full_screen = Region::new(0, 0, self.width, self.height);
        let full_clear = !self.cleared;
        if full_clear {
            fill_rect_u32(pixels, stride_pixels, full_screen, bg_u32);
            self.cleared = true;
        }

        let w = self.width as f32;
        let h = self.height as f32;
        let scale = w.min(h) * 0.25;
        let inv_scale = 1.0 / scale;
        let cx = w * 0.5;
        let cy_center = h * 0.5;

        let s1 = (t / STAGE1_END).clamp(0.0, 1.0);
        let e_horizon = ease_out_quart(s1);
        let arc_fade = smoothstep(0.0, 0.20, t);
        let tip_x = ARC_TIP_X_START + (ARC_TIP_X_FINAL - ARC_TIP_X_START) * e_horizon;
        let y_tip = ARC_OUT_CY - (ARC_OUT_R * ARC_OUT_R - tip_x * tip_x).max(0.0).sqrt();
        let arc_in_r = if s1 >= 1.0 {
            ARC_IN_R_FINAL
        } else {
            let dy = y_tip - ARC_IN_CY;
            (tip_x * tip_x + dy * dy).sqrt()
        };

        let s2 = ((t - STAGE2_START) / (STAGE2_END - STAGE2_START)).clamp(0.0, 1.0);
        let e_sun = ease_out_cubic(s2);
        let sun_cy = SUN_CY_START + (SUN_CY_FINAL - SUN_CY_START) * e_sun;

        let s3_shift =
            ((t - STAGE3_SHIFT_START) / (STAGE3_SHIFT_END - STAGE3_SHIFT_START)).clamp(0.0, 1.0);
        let e_shift = ease_in_out_cubic(s3_shift);
        let logo_cy = cy_center - LOGO_SHIFT_OFFSET * scale * e_shift;
        let final_logo_cy = cy_center - LOGO_SHIFT_OFFSET * scale;

        let mut dirty: Option<Region> = if full_clear { Some(full_screen) } else { None };

        let logo_dynamic = t <= STAGE3_SHIFT_END;
        let need_logo_draw = full_clear || logo_dynamic || !self.logo_settled;
        if need_logo_draw {
            let prev_cy = self.prev_logo_cy.unwrap_or(logo_cy);
            let min_cy = logo_cy.min(prev_cy);
            let max_cy = logo_cy.max(prev_cy);

            let lx0 = ((cx - scale * LOGO_HALF_W_EXTENT - 2.0).floor().max(0.0)) as u32;
            let lx1 = ((cx + scale * LOGO_HALF_W_EXTENT + 2.0).ceil().min(w)) as u32;
            let ly0 = ((min_cy - scale * LOGO_TOP_EXTENT - 2.0).floor().max(0.0)) as u32;
            let ly1 = ((max_cy + scale * LOGO_BOT_EXTENT + 2.0).ceil().min(h)) as u32;

            if lx1 > lx0 && ly1 > ly0 {
                let logo_region = Region::new(lx0, ly0, lx1 - lx0, ly1 - ly0);
                render_logo_region(
                    pixels,
                    stride_pixels,
                    logo_region,
                    LogoFrameParams {
                        cx,
                        logo_cy,
                        scale,
                        inv_scale,
                        t,
                        sun_cy,
                        tip_x,
                        arc_in_r,
                        arc_fade,
                    },
                );
                dirty = Some(match dirty {
                    Some(existing) => existing.union(logo_region),
                    None => logo_region,
                });
            }

            if !logo_dynamic {
                self.logo_settled = true;
            }
        }
        self.prev_logo_cy = Some(logo_cy);

        if t >= STAGE3_BAR_START {
            let bar_fade = smoothstep(STAGE3_BAR_START, STAGE3_BAR_END, t);
            let bar_w = (scale * 1.15).clamp(150.0, 260.0);
            let bar_r = BAR_HEIGHT * 0.5;
            let track_ax = cx - bar_w * 0.5 + bar_r;
            let track_bx = cx + bar_w * 0.5 - bar_r;
            let span = (track_bx - track_ax).max(0.0);

            let bar_cy_final = final_logo_cy + BAR_OFFSET_FROM_SHIFTED_LOGO * scale;
            let bar_cy = bar_cy_final + (1.0 - bar_fade) * BAR_FOLLOW_OFFSET * scale;

            let chase = (t - STAGE3_BAR_START).max(0.0) * CHASE_SPEED;
            let phase = chase - chase.floor();
            let head = ease_out_cubic((phase * 1.32).clamp(0.0, 1.0));
            let tail = ease_in_cubic(((phase - 0.28) / 0.72).clamp(0.0, 1.0));
            let pad = bar_r * 2.2;
            let seg_ax = (track_ax - pad) + (span + pad * 2.0) * tail;
            let seg_bx = ((track_ax - pad) + (span + pad * 2.0) * head).max(seg_ax + 0.4);

            let bx0 = ((cx - bar_w * 0.5 - 2.0).floor().max(0.0)) as u32;
            let bx1 = ((cx + bar_w * 0.5 + 2.0).ceil().min(w)) as u32;
            let by0 = ((bar_cy - bar_r - 2.0).floor().max(0.0)) as u32;
            let by1 = ((bar_cy + bar_r + 2.0).ceil().min(h)) as u32;

            if bx1 > bx0 && by1 > by0 {
                let current_bar_region = Region::new(bx0, by0, bx1 - bx0, by1 - by0);
                // Cover any previous vertical offset while the bar settles into place.
                let paint_region = if !self.bar_settled {
                    self.prev_bar_region
                        .map_or(current_bar_region, |prev| prev.union(current_bar_region))
                } else {
                    current_bar_region
                };
                if t >= STAGE3_BAR_END && paint_region == current_bar_region {
                    self.bar_settled = true;
                }
                self.prev_bar_region = Some(current_bar_region);

                render_bar_region(
                    pixels,
                    stride_pixels,
                    paint_region,
                    BarFrameParams {
                        track_ax,
                        track_bx,
                        seg_ax,
                        seg_bx,
                        bar_cy,
                        bar_r,
                        bar_fade,
                    },
                );
                dirty = Some(match dirty {
                    Some(existing) => existing.union(paint_region),
                    None => paint_region,
                });
            }
        }

        dirty
    }

    /// Cross-fades `splash_pixels` into `target_pixels` in `bgrx8888` using an
    /// integer fixed-point `0..=256` blend for `alpha` clamped to `0.0..=1.0`.
    pub fn render_crossfade(
        splash_pixels: &[u32],
        target_pixels: &[u32],
        out_pixels: &mut [u32],
        alpha: f32,
    ) {
        let weight = (alpha.clamp(0.0, 1.0) * 256.0 + 0.5) as u32;
        let weight = weight.min(256);
        let inv = 256 - weight;
        for ((&splash, &target), out) in splash_pixels
            .iter()
            .zip(target_pixels.iter())
            .zip(out_pixels.iter_mut())
        {
            let rb =
                (((splash & 0x00FF_00FF) * inv + (target & 0x00FF_00FF) * weight + 0x0080_0080)
                    >> 8)
                    & 0x00FF_00FF;
            let g =
                (((splash & 0x0000_FF00) * inv + (target & 0x0000_FF00) * weight + 0x0000_8000)
                    >> 8)
                    & 0x0000_FF00;
            *out = rb | g;
        }
    }

    /// Computes eased cross-fade alpha (`0.0..=1.0`) over [`CROSSFADE_DURATION_SECS`].
    pub fn crossfade_alpha(elapsed_secs: f32) -> f32 {
        smoothstep(0.0, CROSSFADE_DURATION_SECS, elapsed_secs)
    }
}

struct LogoFrameParams {
    cx: f32,
    logo_cy: f32,
    scale: f32,
    inv_scale: f32,
    t: f32,
    sun_cy: f32,
    tip_x: f32,
    arc_in_r: f32,
    arc_fade: f32,
}

fn render_logo_region(
    pixels: &mut [u32],
    stride_pixels: usize,
    region: Region,
    params: LogoFrameParams,
) {
    let bg_r = SPLASH_BACKGROUND.red as f32;
    let bg_g = SPLASH_BACKGROUND.green as f32;
    let bg_b = SPLASH_BACKGROUND.blue as f32;
    let sun_r = SPLASH_SUN.red as f32;
    let sun_g = SPLASH_SUN.green as f32;
    let sun_b = SPLASH_SUN.blue as f32;
    let arc_r = SPLASH_FOREGROUND.red as f32;
    let arc_g = SPLASH_FOREGROUND.green as f32;
    let arc_b = SPLASH_FOREGROUND.blue as f32;

    for y in region.y..region.bottom() {
        let py = (y as f32 + 0.5 - params.logo_cy) * params.inv_scale;
        let row_start = (y as usize) * stride_pixels;
        for x in region.x..region.right() {
            let px = (x as f32 + 0.5 - params.cx) * params.inv_scale;

            let a_sun = if params.t >= STAGE2_START {
                let dy_sun = py - params.sun_cy;
                let d_sun = (px * px + dy_sun * dy_sun).sqrt() - SUN_R;
                let dy_cut = py - CUT_CY;
                let d_cut = (px * px + dy_cut * dy_cut).sqrt() - CUT_R;
                let sd_sun_cut = d_sun.max(-d_cut);
                (0.5 - sd_sun_cut * params.scale).clamp(0.0, 1.0)
            } else {
                0.0
            };

            let abs_px = px.abs();
            let a_arc = if abs_px <= params.tip_x + params.inv_scale * 2.0 && py < ARC_TIP_Y + 0.02
            {
                let dy_out = py - ARC_OUT_CY;
                let d_out = (px * px + dy_out * dy_out).sqrt() - ARC_OUT_R;
                let dy_in = py - ARC_IN_CY;
                let d_in = (px * px + dy_in * dy_in).sqrt() - params.arc_in_r;
                let sd_arc = d_out
                    .max(-d_in)
                    .max(abs_px - params.tip_x)
                    .max(py - ARC_TIP_Y);
                (0.5 - sd_arc * params.scale).clamp(0.0, 1.0) * params.arc_fade
            } else {
                0.0
            };

            let mut r = bg_r;
            let mut g = bg_g;
            let mut b = bg_b;

            if a_sun > 0.0 {
                r = r * (1.0 - a_sun) + sun_r * a_sun;
                g = g * (1.0 - a_sun) + sun_g * a_sun;
                b = b * (1.0 - a_sun) + sun_b * a_sun;
            }
            if a_arc > 0.0 {
                r = r * (1.0 - a_arc) + arc_r * a_arc;
                g = g * (1.0 - a_arc) + arc_g * a_arc;
                b = b * (1.0 - a_arc) + arc_b * a_arc;
            }

            pixels[row_start + x as usize] = pack_rgb_rounded(r, g, b);
        }
    }
}

struct BarFrameParams {
    track_ax: f32,
    track_bx: f32,
    seg_ax: f32,
    seg_bx: f32,
    bar_cy: f32,
    bar_r: f32,
    bar_fade: f32,
}

fn render_bar_region(
    pixels: &mut [u32],
    stride_pixels: usize,
    region: Region,
    params: BarFrameParams,
) {
    let bg_r = SPLASH_BACKGROUND.red as f32;
    let bg_g = SPLASH_BACKGROUND.green as f32;
    let bg_b = SPLASH_BACKGROUND.blue as f32;
    let fg_r = SPLASH_FOREGROUND.red as f32;
    let fg_g = SPLASH_FOREGROUND.green as f32;
    let fg_b = SPLASH_FOREGROUND.blue as f32;
    let eff_track_alpha = BAR_TRACK_ALPHA * params.bar_fade;

    for y in region.y..region.bottom() {
        let py = y as f32 + 0.5;
        let row_start = (y as usize) * stride_pixels;
        for x in region.x..region.right() {
            let px = x as f32 + 0.5;
            let mut r = bg_r;
            let mut g = bg_g;
            let mut b = bg_b;

            if params.bar_fade > 0.001 {
                let d_track = sdf_capsule_h(
                    px,
                    py,
                    params.track_ax,
                    params.track_bx,
                    params.bar_cy,
                    params.bar_r,
                );
                let cov_track = (0.5 - d_track).clamp(0.0, 1.0);
                if cov_track > 0.0 {
                    let a_trk = cov_track * eff_track_alpha;
                    r = r * (1.0 - a_trk) + fg_r * a_trk;
                    g = g * (1.0 - a_trk) + fg_g * a_trk;
                    b = b * (1.0 - a_trk) + fg_b * a_trk;

                    let d_thumb = sdf_capsule_h(
                        px,
                        py,
                        params.seg_ax,
                        params.seg_bx,
                        params.bar_cy,
                        params.bar_r,
                    )
                    .max(d_track);
                    let a_thumb = (0.5 - d_thumb).clamp(0.0, 1.0) * params.bar_fade;
                    if a_thumb > 0.0 {
                        r = r * (1.0 - a_thumb) + fg_r * a_thumb;
                        g = g * (1.0 - a_thumb) + fg_g * a_thumb;
                        b = b * (1.0 - a_thumb) + fg_b * a_thumb;
                    }
                }
            }

            pixels[row_start + x as usize] = pack_rgb_rounded(r, g, b);
        }
    }
}

fn fill_rect_u32(pixels: &mut [u32], stride_pixels: usize, region: Region, value: u32) {
    let width = region.width as usize;
    for y in region.y..region.bottom() {
        let start = (y as usize) * stride_pixels + region.x as usize;
        pixels[start..start + width].fill(value);
    }
}

#[inline]
fn pack_rgb_rounded(r: f32, g: f32, b: f32) -> u32 {
    Colour::new(
        (r + 0.5).clamp(0.0, 255.0) as u8,
        (g + 0.5).clamp(0.0, 255.0) as u8,
        (b + 0.5).clamp(0.0, 255.0) as u8,
    )
    .to_bgrx_u32()
}

#[inline]
fn sdf_capsule_h(px: f32, py: f32, ax: f32, bx: f32, cy: f32, radius: f32) -> f32 {
    let qx = px.clamp(ax, bx);
    let dx = px - qx;
    let dy = py - cy;
    (dx * dx + dy * dy).sqrt() - radius
}

#[inline]
fn ease_out_cubic(t: f32) -> f32 {
    let u = 1.0 - t.clamp(0.0, 1.0);
    1.0 - u * u * u
}

#[inline]
fn ease_in_cubic(t: f32) -> f32 {
    let u = t.clamp(0.0, 1.0);
    u * u * u
}

#[inline]
fn ease_out_quart(t: f32) -> f32 {
    let u = 1.0 - t.clamp(0.0, 1.0);
    1.0 - u * u * u * u
}

#[inline]
fn ease_in_out_cubic(t: f32) -> f32 {
    let u = t.clamp(0.0, 1.0);
    if u < 0.5 {
        4.0 * u * u * u
    } else {
        let k = -2.0 * u + 2.0;
        1.0 - (k * k * k) * 0.5
    }
}

#[inline]
fn smoothstep(edge0: f32, edge1: f32, x: f32) -> f32 {
    let t = ((x - edge0) / (edge1 - edge0)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHITE_U32: u32 = 0x00FF_FFFF;
    const ORANGE_U32: u32 = 0x00FF_6A00;
    const CRESCENT_U32: u32 = 0x000A_0A0A;

    #[test]
    fn stage1_renders_expanding_crescent_on_white_background() {
        let (w, h) = (640, 480);
        let mut fb = vec![0_u32; w * h];
        let mut splash = SplashRenderer::new(w as u32, h as u32);
        let region = splash
            .render_frame(0.15, &mut fb, w)
            .expect("first frame draws");
        assert_eq!(region, Region::new(0, 0, w as u32, h as u32));
        assert_eq!(fb[0], WHITE_U32);
        assert!(
            fb.iter().any(|&p| Colour::from_bgrx_u32(p).red < 0x60),
            "fading crescent must darken pixels at t=0.15s"
        );
        assert!(
            !fb.contains(&ORANGE_U32),
            "sun must not appear before Stage 2 starts at t=0.22s"
        );

        let full_arc = splash
            .render_frame(0.21, &mut fb, w)
            .expect("t=0.21s reaches full crescent opacity");
        assert!(full_arc.area() < (w * h) as u64);
        assert!(fb.contains(&CRESCENT_U32));
        assert!(!fb.contains(&ORANGE_U32));

        let stage1_mid = splash
            .render_frame(0.30, &mut fb, w)
            .expect("t=0.30s draws expanding crescent");
        assert!(stage1_mid.area() < (w * h) as u64);
        assert!(fb.contains(&CRESCENT_U32));
    }

    #[test]
    fn stage2_renders_orange_sun_white_gap_and_black_crescent() {
        let (w, h) = (1920, 1080);
        let mut fb = vec![0_u32; w * h];
        let mut splash = SplashRenderer::new(w as u32, h as u32);
        let _ = splash.render_frame(0.30, &mut fb, w);
        let region = splash
            .render_frame(0.90, &mut fb, w)
            .expect("stage 2 draws");
        assert!(region.area() < (w * h) as u64);

        let scale = (w.min(h) as f32) * 0.25;
        let cx = w / 2;
        let cy = h / 2;

        // Top interior of the sun must be exact Helios orange.
        let sun_y = (cy as f32 - 0.15 * scale) as usize;
        assert_eq!(fb[sun_y * w + cx], ORANGE_U32);

        // Center of the 30-unit negative-space gap between sun cut and crescent outer circle.
        let gap_y = (cy as f32 - 0.002_4 * scale) as usize;
        assert_eq!(fb[gap_y * w + cx], WHITE_U32);

        // Center interior of the crescent must be exact deep black.
        let arc_y = (cy as f32 + 0.035 * scale) as usize;
        assert_eq!(fb[arc_y * w + cx], CRESCENT_U32);
    }

    #[test]
    fn stage3_upward_shift_erases_all_trailing_pixels_to_white() {
        let (w, h) = (800, 600);
        let mut fb = vec![0_u32; w * h];
        let mut splash = SplashRenderer::new(w as u32, h as u32);

        let _ = splash.render_frame(1.15, &mut fb, w);
        let scale = (w.min(h) as f32) * 0.25;
        let cx = w / 2;
        let old_arc_y = (h as f32 * 0.5 + 0.035 * scale) as usize;
        assert_eq!(fb[old_arc_y * w + cx], CRESCENT_U32);

        // Advance through Stage 3 upward shift.
        let _ = splash.render_frame(1.60, &mut fb, w);
        let _ = splash.render_frame(1.96, &mut fb, w);

        // Where the crescent sat at t=1.15s must now be pure white, with zero trail.
        for dx in -50_isize..=50 {
            let x = (cx as isize + dx) as usize;
            assert_eq!(
                fb[old_arc_y * w + x],
                WHITE_U32,
                "trail pixel left at ({x}, {old_arc_y})"
            );
        }
    }

    #[test]
    fn stage4_steady_state_dirty_region_is_under_quarter_percent_at_1080p() {
        let (w, h) = (1920, 1080);
        let mut fb = vec![0_u32; w * h];
        let mut splash = SplashRenderer::new(w as u32, h as u32);

        let _ = splash.render_frame(0.30, &mut fb, w);
        let _ = splash.render_frame(1.60, &mut fb, w);
        let _ = splash.render_frame(2.05, &mut fb, w);

        let dirty = splash
            .render_frame(2.20, &mut fb, w)
            .expect("stage 4 draws bar");
        let total_pixels = (w * h) as f64;
        let ratio = (dirty.area() as f64) / total_pixels;
        assert!(
            ratio < 0.0025,
            "stage 4 dirty ratio {ratio:.5} exceeds 0.25% ({dirty:?})"
        );
    }

    #[test]
    fn crossfade_blends_endpoints_and_midpoint_accurately() {
        let splash = [0x00FF_FFFF, 0x00FF_6A00, 0x000A_0A0A, 0x0000_0000];
        let target = [0x0007_0A0F, 0x0010_1218, 0x00FF_FFFF, 0x0012_3456];
        let mut out = [0_u32; 4];

        SplashRenderer::render_crossfade(&splash, &target, &mut out, 0.0);
        assert_eq!(out, splash);

        SplashRenderer::render_crossfade(&splash, &target, &mut out, 1.0);
        assert_eq!(out, target);

        SplashRenderer::render_crossfade(&splash, &target, &mut out, 0.5);
        for ((&s, &t), &o) in splash.iter().zip(target.iter()).zip(out.iter()) {
            let sc = Colour::from_bgrx_u32(s);
            let tc = Colour::from_bgrx_u32(t);
            let oc = Colour::from_bgrx_u32(o);
            assert_eq!(oc.red, (sc.red as u16 + tc.red as u16).div_ceil(2) as u8);
            assert_eq!(
                oc.green,
                (sc.green as u16 + tc.green as u16).div_ceil(2) as u8
            );
            assert_eq!(oc.blue, (sc.blue as u16 + tc.blue as u16).div_ceil(2) as u8);
        }
    }
}
