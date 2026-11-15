//! Mapped views are copied at the component boundary and never survive a call.

use super::backend;

use core::cell::{Cell, RefCell};
use core::future::{Future, poll_fn};
use core::ops::Range;
use core::pin::pin;
use core::task::Poll;
use std::rc::Rc;

use super::{value::Object, wit};

#[derive(Debug, thiserror::Error)]
#[error("buffer range is outside the allocation or overflows its address space")]
pub struct InvalidRange;

pub fn range(
    size: u64,
    offset: Option<u64>,
    length: Option<u64>,
) -> Result<Range<u64>, InvalidRange> {
    let start = offset.unwrap_or(0);
    let length = length
        .or_else(|| size.checked_sub(start))
        .ok_or(InvalidRange)?;
    let end = start.checked_add(length).ok_or(InvalidRange)?;
    if start > size || end > size {
        return Err(InvalidRange);
    }
    Ok(start..end)
}

struct Mapping {
    range: Range<u64>,
    writable: bool,
    pending: Cell<bool>,
    cancel: async_channel::Sender<()>,
}

#[derive(Default)]
struct MappingSlot(RefCell<Option<Rc<Mapping>>>);

impl MappingSlot {
    fn owns(&self, mapping: &Rc<Mapping>) -> bool {
        self.0
            .borrow()
            .as_ref()
            .is_some_and(|current| Rc::ptr_eq(current, mapping))
    }

    fn remove(&self) -> bool {
        if let Some(mapping) = self.0.borrow_mut().take() {
            mapping.cancel.close();
            true
        } else {
            false
        }
    }
}

pub struct Buffer {
    pub object: Object<backend::Buffer>,
    pub size: u64,
    pub usage: wit::GpuBufferUsage,
    mapping: MappingSlot,
    destroyed: Cell<bool>,
}

impl Buffer {
    pub fn new(object: Object<backend::Buffer>, descriptor: &wit::GpuBufferDescriptor) -> Self {
        let mapping = MappingSlot::default();
        if descriptor.mapped_at_creation.unwrap_or(false) && object.raw.is_some() {
            let (cancel, _) = async_channel::bounded(1);
            *mapping.0.borrow_mut() = Some(Rc::new(Mapping {
                range: 0..descriptor.size,
                writable: true,
                pending: Cell::new(false),
                cancel,
            }));
        }
        Self {
            object,
            size: descriptor.size,
            usage: descriptor.usage,
            mapping,
            destroyed: Cell::new(false),
        }
    }

    fn unmap(&self) {
        if self.mapping.remove()
            && let Some(raw) = &self.object.raw
        {
            self.object.owner.native(|| raw.unmap());
        }
    }

    fn mapped_range(
        &self,
        offset: Option<u64>,
        size: Option<u64>,
        write: bool,
    ) -> Result<Range<u64>, wit::GetMappedRangeError> {
        let error = |message: String| wit::GetMappedRangeError {
            kind: wit::GetMappedRangeErrorKind::OperationError,
            message,
        };
        let requested = range(self.size, offset, size).map_err(|e| error(e.to_string()))?;
        let mapping = self.mapping.0.borrow();
        let mapping = mapping
            .as_ref()
            .ok_or_else(|| error("buffer is not mapped".into()))?;
        if mapping.pending.get()
            || (write && !mapping.writable)
            || requested.start < mapping.range.start
            || requested.end > mapping.range.end
            || !requested.start.is_multiple_of(wgpu::MAP_ALIGNMENT)
            || !(requested.end - requested.start).is_multiple_of(wgpu::COPY_BUFFER_ALIGNMENT)
        {
            return Err(error(
                "requested range is not accessible in the current mapping".into(),
            ));
        }
        Ok(requested)
    }
}

/// Dropping an async invocation cancels only the mapping it started.
struct PendingMap<'a> {
    buffer: &'a Buffer,
    mapping: Rc<Mapping>,
}

impl Drop for PendingMap<'_> {
    fn drop(&mut self) {
        if self.mapping.pending.get() && self.buffer.mapping.owns(&self.mapping) {
            self.buffer.unmap();
        }
    }
}

impl wit::GuestGpuBuffer for Buffer {
    fn size(&self) -> u64 {
        self.size
    }
    fn usage(&self) -> wit::GpuBufferUsage {
        self.usage
    }
    fn label(&self) -> String {
        self.object.label()
    }
    fn set_label(&self, label: String) {
        self.object.set_label(label);
    }
    fn map_state(&self) -> wit::GpuBufferMapState {
        match self.mapping.0.borrow().as_ref() {
            None => wit::GpuBufferMapState::Unmapped,
            Some(mapping) if mapping.pending.get() => wit::GpuBufferMapState::Pending,
            Some(_) => wit::GpuBufferMapState::Mapped,
        }
    }

    async fn map_async(
        &self,
        mode: wit::GpuMapMode,
        offset: Option<u64>,
        size: Option<u64>,
    ) -> Result<(), wit::MapAsyncError> {
        let invalid = |message: String| {
            self.object.owner.invalid(message.clone());
            wit::MapAsyncError {
                kind: wit::MapAsyncErrorKind::OperationError,
                message,
            }
        };
        if self.mapping.0.borrow().is_some() || self.destroyed.get() {
            return Err(invalid(
                "buffer is already mapped, pending, or destroyed".into(),
            ));
        }
        let mode = match mode.bits() {
            bits if bits == wit::GpuMapMode::READ.bits() => wgpu::MapMode::Read,
            bits if bits == wit::GpuMapMode::WRITE.bits() => wgpu::MapMode::Write,
            _ => return Err(invalid("map mode must be exactly read or write".into())),
        };
        let requested = range(self.size, offset, size).map_err(|e| invalid(e.to_string()))?;
        if !requested.start.is_multiple_of(wgpu::MAP_ALIGNMENT)
            || !(requested.end - requested.start).is_multiple_of(wgpu::COPY_BUFFER_ALIGNMENT)
        {
            return Err(invalid(
                "map offset must be aligned to 8 bytes and size to 4 bytes".into(),
            ));
        }
        let raw = self
            .object
            .get()
            .ok_or_else(|| invalid("buffer is invalid".into()))?;
        let required = match mode {
            wgpu::MapMode::Read => wgpu::BufferUsages::MAP_READ,
            wgpu::MapMode::Write => wgpu::BufferUsages::MAP_WRITE,
        };
        if !super::convert::Convert::convert(self.usage).contains(required) {
            return Err(invalid(
                "buffer usage does not permit the requested map mode".into(),
            ));
        }
        let (cancel, cancelled) = async_channel::bounded(1);
        let mapping = Rc::new(Mapping {
            range: requested.clone(),
            writable: mode == wgpu::MapMode::Write,
            pending: Cell::new(true),
            cancel,
        });
        *self.mapping.0.borrow_mut() = Some(mapping.clone());
        let pending = PendingMap {
            buffer: self,
            mapping,
        };
        let (answer, receive) = async_channel::bounded(1);
        let host = match mode {
            wgpu::MapMode::Read => wgpu_core::device::HostMap::Read,
            wgpu::MapMode::Write => wgpu_core::device::HostMap::Write,
        };
        if let Err(error) = raw.map_async(
            requested.start,
            Some(requested.end - requested.start),
            wgpu_core::resource::BufferMapOperation {
                host,
                callback: Some(Box::new(move |result| {
                    let _ = answer.try_send(result);
                })),
            },
        ) {
            self.object.owner.report(&error);
            return Err(wit::MapAsyncError {
                kind: wit::MapAsyncErrorKind::OperationError,
                message: error.to_string(),
            });
        }
        let mut operation = pin!(async {
            self.object
                .owner
                .device
                .submitted_work_done()
                .await
                .map_err(|e| e.to_string())?;
            let result = receive.recv().await.map_err(|e| e.to_string())?;
            result.map_err(|e| e.to_string())
        });
        let mut cancelled = pin!(cancelled.recv());
        let result = poll_fn(|cx| {
            if cancelled.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(wit::MapAsyncError {
                    kind: wit::MapAsyncErrorKind::AbortError,
                    message: "buffer mapping was cancelled".into(),
                }));
            }
            operation.as_mut().poll(cx).map(|result| {
                result.map_err(|e| wit::MapAsyncError {
                    kind: wit::MapAsyncErrorKind::OperationError,
                    message: e.to_string(),
                })
            })
        })
        .await;
        if result.is_ok() {
            pending.mapping.pending.set(false);
        }
        result
    }

    fn get_mapped_range_get_with_copy(
        &self,
        offset: Option<u64>,
        size: Option<u64>,
    ) -> Result<Vec<u8>, wit::GetMappedRangeError> {
        let requested = self.mapped_range(offset, size, false)?;
        let raw = self
            .object
            .raw
            .as_ref()
            .expect("mapped buffers own a native resource");
        let (pointer, length) = raw
            .get_mapped_range(requested.start, Some(requested.end - requested.start))
            .map_err(|e| wit::GetMappedRangeError {
                kind: wit::GetMappedRangeErrorKind::OperationError,
                message: e.to_string(),
            })?;
        let length = usize::try_from(length).map_err(|e| wit::GetMappedRangeError {
            kind: wit::GetMappedRangeErrorKind::RangeError,
            message: e.to_string(),
        })?;
        let mut data = Vec::new();
        data.try_reserve_exact(length)
            .map_err(|e| wit::GetMappedRangeError {
                kind: wit::GetMappedRangeErrorKind::RangeError,
                message: e.to_string(),
            })?;
        // SAFETY: core validates the mapped range; this single-owner resource
        // cannot be unmapped during this synchronous call. Reservation also
        // establishes the slice length is within Rust's addressable range.
        data.extend_from_slice(unsafe { core::slice::from_raw_parts(pointer.as_ptr(), length) });
        Ok(data)
    }

    fn get_mapped_range_set_with_copy(
        &self,
        data: Vec<u8>,
        offset: Option<u64>,
        size: Option<u64>,
    ) -> Result<(), wit::GetMappedRangeError> {
        let requested = self.mapped_range(offset, size, true)?;
        if requested.end - requested.start != data.len() as u64 {
            return Err(wit::GetMappedRangeError {
                kind: wit::GetMappedRangeErrorKind::RangeError,
                message: "copy length does not match the mapped range".into(),
            });
        }
        let raw = self
            .object
            .raw
            .as_ref()
            .expect("mapped buffers own a native resource");
        let (pointer, _) = raw
            .get_mapped_range(requested.start, Some(requested.end - requested.start))
            .map_err(|e| wit::GetMappedRangeError {
                kind: wit::GetMappedRangeErrorKind::OperationError,
                message: e.to_string(),
            })?;
        // SAFETY: the component owns both allocations; their lengths match,
        // they do not overlap, and no await can release the mapped buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), pointer.as_ptr(), data.len());
        }
        Ok(())
    }

    fn unmap(&self) -> Result<(), wit::UnmapError> {
        self.unmap();
        Ok(())
    }
    fn destroy(&self) {
        self.unmap();
        self.destroyed.set(true);
        if let Some(raw) = &self.object.raw {
            raw.destroy();
        }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.unmap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_allow_empty_and_reject_overflow() {
        assert_eq!(range(0, None, None).unwrap(), 0..0);
        assert_eq!(range(16, Some(16), Some(0)).unwrap(), 16..16);
        assert_eq!(range(16, Some(8), None).unwrap(), 8..16);
        assert!(range(16, Some(17), None).is_err());
        assert!(range(u64::MAX, Some(u64::MAX), Some(1)).is_err());
        assert!(range(16, Some(8), Some(12)).is_err());
    }

    #[test]
    fn stale_mapping_does_not_own_a_replacement() {
        let slot = MappingSlot::default();
        let (cancel, cancelled) = async_channel::bounded(1);
        let old = Rc::new(Mapping {
            range: 0..8,
            writable: true,
            pending: Cell::new(true),
            cancel,
        });
        *slot.0.borrow_mut() = Some(old.clone());
        assert!(slot.owns(&old));
        assert!(slot.remove());
        assert!(cancelled.is_closed());
        let (cancel, _) = async_channel::bounded(1);
        let new = Rc::new(Mapping {
            range: 0..8,
            writable: true,
            pending: Cell::new(true),
            cancel,
        });
        *slot.0.borrow_mut() = Some(new.clone());
        assert!(!slot.owns(&old));
        assert!(slot.owns(&new));
    }
}
