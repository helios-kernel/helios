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

use helios_hal::vmm::VirtRange;
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

/// Top-level namespace prefix under which a published inspect span appears.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectNamespace {
    /// Ordinary component publication at `/instances/<instance_id>/<name>/*`.
    Instances,
    /// Root-supervisor component-manager publication at `/components/*`.
    Components,
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
    namespace: InspectNamespace,
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
        self.publish_in_namespace(
            instance_id,
            instance_name,
            name,
            InspectNamespace::Instances,
            memory,
            span,
        )
    }

    /// Registers a bounded span of `memory` owned by `instance_id` under the
    /// specified [`InspectNamespace`].
    ///
    /// Only the root supervisor (`RootSupervisorCap`) may publish into
    /// [`InspectNamespace::Components`], exposing live component state at
    /// `/components/*`.
    pub fn publish_in_namespace(
        &self,
        instance_id: InstanceId,
        instance_name: impl Into<String>,
        name: impl Into<String>,
        namespace: InspectNamespace,
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
            if namespace == InspectNamespace::Components
                && existing.namespace == InspectNamespace::Components
            {
                return Err(InspectPublishError::DuplicateName);
            }
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
            namespace,
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
    #[expect(
        clippy::too_many_arguments,
        reason = "snapshot binds caller scope, timestamp, registries, residency, kernel telemetry, prefix filter, and entry cap explicitly"
    )]
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
        self.snapshot_checked(
            timestamp,
            caller_id,
            scope,
            instance_registry,
            |range| residency.is_none_or(|res| res.first_swapped(range).is_none()),
            kernel_telemetry,
            prefixes,
            limit,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "snapshot_checked threads the monomorphised residency check alongside explicit snapshot parameters"
    )]
    fn snapshot_checked(
        &self,
        timestamp: u64,
        caller_id: InstanceId,
        scope: Option<AuthorityScope>,
        instance_registry: &InstanceRegistry,
        is_resident: impl Fn(VirtRange) -> bool,
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

        let mut entries = Vec::with_capacity(effective_limit.min(64));
        let mut publications = Vec::new();
        let mut truncated = false;

        // Component paths (`/components/*`, `/instances/*`) sort strictly
        // before `/kernel/*`. Reading component publications in exact sorted
        // root-prefix order lets each publication bound its decoded entries to
        // `effective_limit - entries.len()` without losing lexicographical
        // order or allocating unbounded kernel heap on a small `limit`.
        if prefixes.may_match_subtree("/instances") || prefixes.may_match_subtree("/components") {
            let mut candidates: Vec<(String, Arc<PublishedSpan>)> = {
                let table = self.inner.publications.lock();
                table
                    .iter()
                    .filter(|pub_entry| {
                        scope.admits_instance(caller_id, pub_entry.instance_id, instance_registry)
                    })
                    .filter_map(|pub_entry| {
                        let root_prefix = match pub_entry.namespace {
                            InspectNamespace::Instances => format!(
                                "/instances/{}/{}",
                                pub_entry.instance_id.raw(),
                                pub_entry.name
                            ),
                            InspectNamespace::Components => String::from("/components"),
                        };
                        prefixes
                            .may_match_subtree(&root_prefix)
                            .then(|| (root_prefix, pub_entry.clone()))
                    })
                    .collect()
            };
            // Compare with a trailing `/` so sibling names sharing a prefix
            // (`a` vs `a-b`) order identically to `"{root_prefix}/{rel_path}"`.
            candidates.sort_unstable_by(|(a, _), (b, _)| {
                a.as_bytes()
                    .iter()
                    .chain(core::iter::once(&b'/'))
                    .cmp(b.as_bytes().iter().chain(core::iter::once(&b'/')))
            });

            let mut scratch = Vec::new();
            let mut path_buf = String::new();
            for (root_prefix, pub_entry) in candidates {
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

                let remaining = effective_limit.saturating_sub(entries.len());
                // SAFETY: `mapping_guard` prevents the owning store from
                // revoking or recycling the linear memory, `_pin` prevents
                // swap eviction via `while_off_processor`, and `is_resident`
                // verifies the header and active payload ranges before each
                // aligned atomic load.
                let outcome = unsafe {
                    buffer::read_span_snapshot(
                        mapped.base,
                        mapped.length,
                        &is_resident,
                        &mut scratch,
                        &mut path_buf,
                        &root_prefix,
                        prefixes,
                        remaining,
                        &mut entries,
                    )
                };
                drop(mapping_guard);

                match outcome {
                    buffer::SpanReadOutcome::Ok {
                        generation,
                        truncated: pub_truncated,
                    } => {
                        truncated |= pub_truncated;
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
                    buffer::SpanReadOutcome::SwappedOut => {
                        publications.push(ComponentPublication {
                            instance_id: pub_entry.instance_id,
                            instance_name: pub_entry.instance_name.clone(),
                            name: pub_entry.name.clone(),
                            generation: 0,
                            status: PublicationStatus::SwappedOut,
                        });
                    }
                }
            }
        }

        if scope == AuthorityScope::Machine
            && let Some(telemetry) = kernel_telemetry
            && (!truncated || entries.len() < effective_limit)
        {
            let mut kernel_entries = Vec::new();
            emit_kernel_entries(telemetry, prefixes, &mut kernel_entries);
            if !kernel_entries.is_empty() {
                kernel_entries.sort_unstable_by(|a, b| a.path.cmp(&b.path));
                let remaining = effective_limit.saturating_sub(entries.len());
                if kernel_entries.len() > remaining {
                    truncated = true;
                    kernel_entries.truncate(remaining);
                }
                entries.extend(kernel_entries);
            }
        }

        entries.sort_unstable_by(|a, b| a.path.cmp(&b.path));
        publications.sort_unstable_by(|a, b| {
            a.instance_id
                .cmp(&b.instance_id)
                .then_with(|| a.name.cmp(&b.name))
        });

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

#[cfg(test)]
mod bounded_snapshot_tests {
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::AtomicU64;

    use helios_hal::vmm::VirtAddr;

    use super::buffer::encode_buffer;
    use super::{InspectRegistry, InspectValue, PublicationStatus};
    use crate::buffer::{GuestMemory, Span, WASM_PAGE_BYTES};
    use crate::{AuthorityScope, InstanceRegistry, PrefixSet};

    #[test]
    fn snapshot_limit_bounds_decoded_entries_across_publications_in_lexicographical_order() {
        let instances = InstanceRegistry::new();
        let inst_a = instances.register("alpha", 1);
        let inst_b = instances.register("beta", 2);
        let registry = InspectRegistry::new();

        let total_bytes = 2 * (WASM_PAGE_BYTES as usize);
        let mut words: Box<[AtomicU64]> = (0..total_bytes / 8)
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let gm = GuestMemory::new(
            VirtAddr::new(words.as_ptr() as usize),
            (words.len() * 8) as u64,
        );

        let words_per_page = WASM_PAGE_BYTES as usize / 8;
        let (page0_words, page1_words) = words.split_at_mut(words_per_page);
        let page0_ptr = page0_words.as_mut_ptr().cast::<u8>();
        // SAFETY: `AtomicU64` has the same size and alignment as `u64` with no
        // padding, and `page0_words` is uniquely borrowed from `words`.
        let page0 = unsafe { core::slice::from_raw_parts_mut(page0_ptr, WASM_PAGE_BYTES as usize) };
        encode_buffer(
            2,
            &[
                ("z-last", InspectValue::Blob(vec![0xaa; 256])),
                ("a-first", InspectValue::Unsigned64(11)),
                ("m-mid", InspectValue::Text(String::from("mid"))),
            ],
            page0,
        )
        .expect("encode page 0");

        let page1_ptr = page1_words.as_mut_ptr().cast::<u8>();
        // SAFETY: `AtomicU64` has the same size and alignment as `u64` with no
        // padding, and `page1_words` is uniquely borrowed from `words`.
        let page1 = unsafe { core::slice::from_raw_parts_mut(page1_ptr, WASM_PAGE_BYTES as usize) };
        encode_buffer(
            4,
            &[
                ("b-second", InspectValue::Blob(vec![0xbb; 512])),
                ("a-second", InspectValue::Unsigned64(22)),
            ],
            page1,
        )
        .expect("encode page 1");

        let _p_b = registry
            .publish(
                inst_b.id(),
                "beta",
                "pub",
                gm,
                Span::new(WASM_PAGE_BYTES, WASM_PAGE_BYTES),
            )
            .unwrap();
        let _p_a = registry
            .publish(
                inst_a.id(),
                "alpha",
                "pub",
                gm,
                Span::new(0, WASM_PAGE_BYTES),
            )
            .unwrap();

        let snap = registry.snapshot(
            42,
            inst_a.id(),
            Some(AuthorityScope::Machine),
            &instances,
            None,
            None,
            &PrefixSet::default(),
            1,
        );
        assert!(snap.truncated);
        assert_eq!(snap.entries.len(), 1);
        assert_eq!(
            snap.entries[0].path,
            alloc::format!("/instances/{}/pub/a-first", inst_a.id().raw())
        );
        assert_eq!(snap.entries[0].value, InspectValue::Unsigned64(11));
        assert_eq!(snap.publications.len(), 2);
        assert!(
            snap.publications
                .iter()
                .all(|p| p.status == PublicationStatus::Ok)
        );
    }

    #[test]
    fn snapshot_reads_active_payload_when_unused_tail_pages_are_swapped_out() {
        use core::cell::Cell;
        use helios_hal::pmm::PhysFrame;
        use helios_hal::vmm::VirtRange;

        let instances = InstanceRegistry::new();
        let inst = instances.register("console-session", 1);
        let registry = InspectRegistry::new();

        let mut words: Box<[AtomicU64]> = (0..(WASM_PAGE_BYTES as usize) / 8)
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let base_addr = words.as_ptr() as usize;
        let gm = GuestMemory::new(VirtAddr::new(base_addr), WASM_PAGE_BYTES);

        let encoded_end = {
            let raw_ptr = words.as_mut_ptr().cast::<u8>();
            // SAFETY: `words` is uniquely borrowed and holds `WASM_PAGE_BYTES` aligned bytes.
            let buf = unsafe { core::slice::from_raw_parts_mut(raw_ptr, WASM_PAGE_BYTES as usize) };
            encode_buffer(
                2,
                &[
                    ("request_id", InspectValue::Unsigned64(1)),
                    ("username", InspectValue::Text(String::from("lexo"))),
                    ("challenge", InspectValue::Blob(vec![0x5a; 96])),
                ],
                buf,
            )
            .expect("encode small console-auth payload in page 0")
        };
        assert!(encoded_end < PhysFrame::SIZE);

        let _pub_handle = registry
            .publish(
                inst.id(),
                "console-session",
                "console-auth",
                gm,
                Span::new(0, WASM_PAGE_BYTES),
            )
            .unwrap();

        // 1. Pages 1..15 (`base_addr + 4096 .. base_addr + 65536`) are swapped out,
        // while page 0 holding the header and active payload is resident.
        let max_checked_offset = Cell::new(0usize);
        let snap_ok = registry.snapshot_checked(
            100,
            inst.id(),
            Some(AuthorityScope::Machine),
            &instances,
            |range: VirtRange| {
                let end_offset = range.end().raw().saturating_sub(base_addr);
                max_checked_offset.set(max_checked_offset.get().max(end_offset));
                end_offset <= PhysFrame::SIZE
            },
            None,
            &PrefixSet::default(),
            256,
        );
        assert_eq!(max_checked_offset.get(), encoded_end);
        assert_eq!(snap_ok.publications.len(), 1);
        assert_eq!(snap_ok.publications[0].status, PublicationStatus::Ok);
        assert_eq!(snap_ok.entries.len(), 3);

        // 2. Header page 0 itself swapped out -> `SwappedOut` with zero entries.
        let snap_header_out = registry.snapshot_checked(
            101,
            inst.id(),
            Some(AuthorityScope::Machine),
            &instances,
            |_| false,
            None,
            &PrefixSet::default(),
            256,
        );
        assert_eq!(snap_header_out.publications.len(), 1);
        assert_eq!(
            snap_header_out.publications[0].status,
            PublicationStatus::SwappedOut
        );
        assert!(snap_header_out.entries.is_empty());

        // 3. Multi-page active payload (> 4 KiB) whose second hardware page is
        // swapped out -> `SwappedOut` without reading into the non-resident page.
        let large_end = {
            let raw_ptr = words.as_mut_ptr().cast::<u8>();
            // SAFETY: `words` is uniquely borrowed and holds `WASM_PAGE_BYTES` aligned bytes.
            let buf = unsafe { core::slice::from_raw_parts_mut(raw_ptr, WASM_PAGE_BYTES as usize) };
            encode_buffer(
                4,
                &[
                    ("blob-a", InspectValue::Blob(vec![0x11; 3000])),
                    ("blob-b", InspectValue::Blob(vec![0x22; 3000])),
                ],
                buf,
            )
            .expect("encode >4 KiB payload")
        };
        assert!(large_end > PhysFrame::SIZE);
        let snap_payload_out = registry.snapshot_checked(
            102,
            inst.id(),
            Some(AuthorityScope::Machine),
            &instances,
            |range: VirtRange| range.end().raw().saturating_sub(base_addr) <= PhysFrame::SIZE,
            None,
            &PrefixSet::default(),
            256,
        );
        assert_eq!(snap_payload_out.publications.len(), 1);
        assert_eq!(
            snap_payload_out.publications[0].status,
            PublicationStatus::SwappedOut
        );
        assert!(snap_payload_out.entries.is_empty());
    }
}
