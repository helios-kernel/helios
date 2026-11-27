//! Compositor-owned GPU presentation and frame retirement.
//!
//! One desktop task owns this state. Display replacement is awaited before
//! the previous producer is signalled, and teardown closes outstanding
//! producers if device access cannot be retired successfully.

use helios_api::display::{Display, ImageSurface, Point, Rect};
use helios_api::image::Image;
use helios_api::surface::Size;
use helios_api::sync::SignalSource;
use helios_compositor_render::desktop::Desktop;

use super::{DesktopError, SCANOUT};

struct Window {
    id: u64,
    size: Size,
}

struct ActiveFrame {
    id: u64,
    _surface: ImageSurface,
    retired: SignalSource,
}

pub(super) struct Presentation {
    display: Display,
    windows: Vec<Window>,
    active: Option<ActiveFrame>,
}

impl Presentation {
    pub(super) fn new(display: Display) -> Self {
        Self {
            display,
            windows: Vec::new(),
            active: None,
        }
    }

    pub(super) const fn display(&self) -> &Display {
        &self.display
    }

    /// Re-activates any fullscreen client image surface after the compositor
    /// created a replacement desktop scanout surface.
    pub(super) async fn reactivate_if_active(&self) -> Result<bool, DesktopError> {
        let Some(active) = self.active.as_ref() else {
            return Ok(false);
        };
        active._surface.activate().await?;
        Ok(true)
    }

    pub(super) fn create(&mut self, id: u64, size: Size) {
        self.windows.push(Window { id, size });
    }

    pub(super) fn holds(&self, id: u64) -> bool {
        self.windows.iter().any(|window| window.id == id)
    }

    pub(super) async fn present(
        &mut self,
        id: u64,
        image: Image,
        retired: SignalSource,
    ) -> Result<(), DesktopError> {
        let surface = self.display.create_from_image(SCANOUT, &image).await?;
        let mode = surface.mode();
        surface
            .present(Rect {
                x: 0,
                y: 0,
                width: mode.width,
                height: mode.height,
            })
            .await?;
        let previous = self.active.replace(ActiveFrame {
            id,
            _surface: surface,
            retired,
        });
        if let Some(previous) = previous {
            previous.retired.signal(1)?;
            drop(previous);
        }
        Ok(())
    }

    pub(super) async fn remove(
        &mut self,
        id: u64,
        desktop: &Desktop,
    ) -> Result<bool, DesktopError> {
        let Some(index) = self.windows.iter().position(|window| window.id == id) else {
            return Ok(false);
        };
        self.windows.remove(index);
        if self.active.as_ref().is_some_and(|frame| frame.id == id) {
            desktop.activate().await?;
            let previous = self
                .active
                .take()
                .expect("the restored desktop replaced the active frame");
            previous.retired.signal(1)?;
            drop(previous);
        }
        Ok(true)
    }

    pub(super) fn focused(&self, desktop: &Desktop) -> Option<(u64, Point)> {
        let active = self.active.as_ref()?;
        let window = self.windows.iter().find(|window| window.id == active.id)?;
        let mode = desktop.mode();
        let pointer = desktop.pointer();
        Some((
            active.id,
            Point {
                x: (u64::from(pointer.x) * u64::from(window.size.width) / u64::from(mode.width))
                    as u32,
                y: (u64::from(pointer.y) * u64::from(window.size.height) / u64::from(mode.height))
                    as u32,
            },
        ))
    }
}
