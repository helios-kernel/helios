//! Lock-free component and kernel state inspection registry.
//!
//! # Concurrency contract
//!
//! - [`InspectRegistry`] holds live component publication handles behind a
//!   short synchronous `spin::Mutex` (never held across `.await` and never
//!   touched from an interrupt handler).
//! - Snapshot reads clone candidate `Arc<PublishedSpan>` handles under that
//!   short lock, release it immediately, and read each span using a
//!   non-blocking `try_read()` on that publication's [`spin::RwLock`], a
//!   non-blocking [`InstanceRegistry::try_pin_for_read`] guard against swap
//!   eviction, a non-blocking swap-residency check, and aligned 64-bit atomic
//!   loads under the even/odd generation protocol.
//! - Dropping an [`InspectPublication`] (either explicitly or when its owning
//!   store tears down) acquires the publication's exclusive `write()` lock,
//!   clears the mapped span so no future reader can enter it, waits for any
//!   in-flight microsecond copy to finish, and removes the publication from
//!   the registry before the owning store's linear memory can be recycled.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use helios_hal::vmm::{VirtAddr, VirtRange};
use spin::{Mutex, RwLock};
use thiserror::Error;
use triomphe::Arc;

use crate::buffer::{GuestMemory, Span, WASM_PAGE_BYTES};
use crate::memory::GuestResidency;
use crate::{AuthorityScope, InstanceId, InstanceRegistry, PrefixSet};

pub mod buffer;
mod kernel_tree;

#[cfg(test)]
mod tests;

pub use buffer::{
    DEFAULT_INSPECT_LIMIT, INSPECT_FORMAT_VERSION, INSPECT_HEADER_BYTES, INSPECT_HEADER_MAGIC,
    MAX_BLOB_VALUE_BYTES, MAX_COMPONENT_ENTRIES, MAX_INSPECT_LIMIT, MAX_INSPECT_SPAN_BYTES,
    MAX_PUBLICATION_NAME_BYTES, MAX_PUBLICATIONS_PER_INSTANCE, MAX_RELATIVE_PATH_BYTES,
    MAX_SEQLOCK_RETRIES, MAX_TEXT_VALUE_BYTES, is_valid_publication_name, is_valid_relative_path,
};
pub use kernel_tree::{KernelTelemetrySnapshot, emit_kernel_entries};

/// Typed value of one inspect property.
#[derive(Clone, Debug, PartialEq)]
pub enum InspectValue {
    Boolean(bool),
    Signed64(i64),
    Unsigned64(u64),
    Float64(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// One property entry in an inspect snapshot.
#[derive(Clone, Debug, PartialEq)]
pub struct InspectEntry {
    pub path: String,
    pub value: InspectValue,
}

/// Outcome of reading one component publication during a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationStatus {
    Ok,
    Busy,
    Corrupt,
    SwappedOut,
}

/// Summary of one component publication admitted by scope and prefix filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentPublication {
    pub instance_id: InstanceId,
    pub instance_name: String,
    pub name: String,
    pub generation: u64,
    pub status: PublicationStatus,
}

/// Coherent result of one inspect query.
#[derive(Clone, Debug, PartialEq)]
pub struct InspectSnapshot {
    pub timestamp: u64,
    pub entries: Vec<InspectEntry>,
    pub truncated: bool,
    pub publications: Vec<ComponentPublication>,
}

/// Why registering an inspect publication span was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum InspectPublishError {
    #[error("inspect span is misaligned, empty, out of bounds, too large, or overlaps")]
    BadSpan,
    #[error("inspect publication name is invalid")]
    InvalidName,
    #[error("instance already holds an inspect publication with that name")]
    DuplicateName,
    #[error("instance already holds the maximum number of inspect publications")]
    TooManyPublications,
}

#[derive(Clone, Copy)]
struct MappedSpan {
    /// Host virtual address of byte 0 of the span.
    base: usize,
    /// Byte length of the span (`<= MAX_INSPECT_SPAN_BYTES`).
    length: usize,
}

struct PublishedSpan {
    id: u64,
    instance_id: InstanceId,
    instance_name: String,
    name: String,
    /// `Some(MappedSpan)` while published; set to `None` under the write lock
    /// on revocation so readers never access memory after teardown.
    mapping: RwLock<Option<MappedSpan>>,
}

struct InspectRegistryInner {
    next_id: AtomicU64,
    publications: Mutex<Vec<Arc<PublishedSpan>>>,
}

/// Kernel-wide registry of component-published lock-free inspect spans.
#[derive(Clone)]
pub struct InspectRegistry {
    inner: Arc<InspectRegistryInner>,
}

impl Default for InspectRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl InspectRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(InspectRegistryInner {
                next_id: AtomicU64::new(1),
                publications: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Registers a bounded span of `memory` owned by `instance_id` under
    /// `/instances/<instance_id>/<name>`.
    ///
    /// Caller must already have verified `span` does not overlap any kernel
    /// view in the store's `ViewTable`.
    pub fn publish(
        &self,
        instance_id: InstanceId,
        instance_name: impl Into<String>,
        name: impl Into<String>,
        memory: GuestMemory,
        span: Span,
    ) -> Result<InspectPublication, InspectPublishError> {
        let name = name.into();
        if !is_valid_publication_name(&name) {
            return Err(InspectPublishError::InvalidName);
        }
        let mapped = validate_span(memory, span)?;

        let mut table = self.inner.publications.lock();
        let mut owned_count = 0usize;
        for existing in table.iter() {
            if existing.instance_id != instance_id {
                continue;
            }
            owned_count += 1;
            if existing.name == name {
                return Err(InspectPublishError::DuplicateName);
            }
            if let Some(existing_map) = existing.mapping.try_read().and_then(|g| *g)
                && virt_ranges_overlap(
                    existing_map.base,
                    existing_map.length,
                    mapped.base,
                    mapped.length,
                )
            {
                return Err(InspectPublishError::BadSpan);
            }
        }
        if owned_count >= MAX_PUBLICATIONS_PER_INSTANCE {
            return Err(InspectPublishError::TooManyPublications);
        }

        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(PublishedSpan {
            id,
            instance_id,
            instance_name: instance_name.into(),
            name,
            mapping: RwLock::new(Some(mapped)),
        });
        table.push(entry.clone());
        drop(table);

        Ok(InspectPublication {
            registry: self.clone(),
            entry,
        })
    }

    /// Snapshots all component publications admitted by `scope` and `prefixes`,
    /// combining them with `kernel_telemetry` when `scope == AuthorityScope::Machine`.
    #[allow(clippy::too_many_arguments)]
    pub fn snapshot(
        &self,
        timestamp: u64,
        caller_id: InstanceId,
        scope: Option<AuthorityScope>,
        instance_registry: &InstanceRegistry,
        residency: Option<&GuestResidency>,
        kernel_telemetry: Option<&KernelTelemetrySnapshot>,
        prefixes: &PrefixSet,
        limit: u32,
    ) -> InspectSnapshot {
        let Some(scope) = scope else {
            return InspectSnapshot {
                timestamp,
                entries: Vec::new(),
                truncated: false,
                publications: Vec::new(),
            };
        };

        let effective_limit = if limit == 0 {
            DEFAULT_INSPECT_LIMIT
        } else {
            (limit as usize).min(MAX_INSPECT_LIMIT)
        };

        let mut entries = Vec::new();
        let mut publications = Vec::new();

        if scope == AuthorityScope::Machine
            && let Some(telemetry) = kernel_telemetry
        {
            emit_kernel_entries(telemetry, prefixes, &mut entries);
        }

        if prefixes.may_match_subtree("/instances") {
            let candidates: Vec<Arc<PublishedSpan>> = {
                let table = self.inner.publications.lock();
                table
                    .iter()
                    .filter(|pub_entry| {
                        scope.admits_instance(caller_id, pub_entry.instance_id, instance_registry)
                    })
                    .cloned()
                    .collect()
            };

            for pub_entry in candidates {
                let root_prefix = format!(
                    "/instances/{}/{}",
                    pub_entry.instance_id.raw(),
                    pub_entry.name
                );
                if !prefixes.may_match_subtree(&root_prefix) {
                    continue;
                }

                let Some(mapping_guard) = pub_entry.mapping.try_read() else {
                    continue;
                };
                let Some(mapped) = *mapping_guard else {
                    continue;
                };

                let Some(_pin) = instance_registry.try_pin_for_read(pub_entry.instance_id) else {
                    publications.push(ComponentPublication {
                        instance_id: pub_entry.instance_id,
                        instance_name: pub_entry.instance_name.clone(),
                        name: pub_entry.name.clone(),
                        generation: 0,
                        status: PublicationStatus::Busy,
                    });
                    continue;
                };

                if let Some(residency) = residency
                    && residency
                        .first_swapped(VirtRange::new(VirtAddr::new(mapped.base), mapped.length))
                        .is_some()
                {
                    publications.push(ComponentPublication {
                        instance_id: pub_entry.instance_id,
                        instance_name: pub_entry.instance_name.clone(),
                        name: pub_entry.name.clone(),
                        generation: 0,
                        status: PublicationStatus::SwappedOut,
                    });
                    continue;
                }

                // SAFETY: `mapping_guard` prevents the owning store from
                // revoking or recycling the linear memory, `_pin` prevents
                // swap eviction via `while_off_processor`, and residency was
                // verified above. Every access uses aligned atomic loads.
                let outcome = unsafe { buffer::read_span_snapshot(mapped.base, mapped.length) };
                drop(mapping_guard);

                match outcome {
                    buffer::SpanReadOutcome::Ok {
                        generation,
                        entries: decoded,
                    } => {
                        for (rel_path, value) in decoded {
                            let full_path = format!("{root_prefix}/{rel_path}");
                            if prefixes.admits(&full_path) {
                                entries.push(InspectEntry {
                                    path: full_path,
                                    value,
                                });
                            }
                        }
                        publications.push(ComponentPublication {
                            instance_id: pub_entry.instance_id,
                            instance_name: pub_entry.instance_name.clone(),
                            name: pub_entry.name.clone(),
                            generation,
                            status: PublicationStatus::Ok,
                        });
                    }
                    buffer::SpanReadOutcome::Busy { generation } => {
                        publications.push(ComponentPublication {
                            instance_id: pub_entry.instance_id,
                            instance_name: pub_entry.instance_name.clone(),
                            name: pub_entry.name.clone(),
                            generation,
                            status: PublicationStatus::Busy,
                        });
                    }
                    buffer::SpanReadOutcome::Corrupt { generation } => {
                        publications.push(ComponentPublication {
                            instance_id: pub_entry.instance_id,
                            instance_name: pub_entry.instance_name.clone(),
                            name: pub_entry.name.clone(),
                            generation,
                            status: PublicationStatus::Corrupt,
                        });
                    }
                }
            }
        }

        entries.sort_unstable_by(|a, b| a.path.cmp(&b.path));
        publications.sort_unstable_by(|a, b| {
            a.instance_id
                .cmp(&b.instance_id)
                .then_with(|| a.name.cmp(&b.name))
        });

        let truncated = entries.len() > effective_limit;
        if truncated {
            entries.truncate(effective_limit);
        }

        InspectSnapshot {
            timestamp,
            entries,
            truncated,
            publications,
        }
    }

    /// Number of currently live publications across all instances.
    pub fn publication_count(&self) -> usize {
        self.inner.publications.lock().len()
    }
}

/// RAII handle owning one published component inspect span.
///
/// Dropping this handle revokes the mapping synchronously (waiting for any
/// active bounded copy to finish) and removes the publication from the
/// registry before returning.
pub struct InspectPublication {
    registry: InspectRegistry,
    entry: Arc<PublishedSpan>,
}

impl InspectPublication {
    pub fn name(&self) -> &str {
        &self.entry.name
    }

    pub fn instance_id(&self) -> InstanceId {
        self.entry.instance_id
    }
}

impl Drop for InspectPublication {
    fn drop(&mut self) {
        {
            let mut guard = self.entry.mapping.write();
            *guard = None;
        }
        let id = self.entry.id;
        self.registry
            .inner
            .publications
            .lock()
            .retain(|existing| existing.id != id);
    }
}

const fn virt_ranges_overlap(a_base: usize, a_len: usize, b_base: usize, b_len: usize) -> bool {
    a_base < b_base.saturating_add(b_len) && b_base < a_base.saturating_add(a_len)
}

fn validate_span(memory: GuestMemory, span: Span) -> Result<MappedSpan, InspectPublishError> {
    if span.length == 0
        || !span.offset.is_multiple_of(WASM_PAGE_BYTES)
        || !span.length.is_multiple_of(WASM_PAGE_BYTES)
        || span.length > MAX_INSPECT_SPAN_BYTES as u64
    {
        return Err(InspectPublishError::BadSpan);
    }
    let Some(end) = span.offset.checked_add(span.length) else {
        return Err(InspectPublishError::BadSpan);
    };
    if end > memory.bytes() {
        return Err(InspectPublishError::BadSpan);
    }
    let Some(base) = (memory.base().raw() as u64)
        .checked_add(span.offset)
        .and_then(|addr| usize::try_from(addr).ok())
    else {
        return Err(InspectPublishError::BadSpan);
    };
    let Ok(length) = usize::try_from(span.length) else {
        return Err(InspectPublishError::BadSpan);
    };
    if base.checked_add(length).is_none() || !base.is_multiple_of(8) {
        return Err(InspectPublishError::BadSpan);
    }
    Ok(MappedSpan { base, length })
}
