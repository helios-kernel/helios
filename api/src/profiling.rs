//! Profiling syscalls.

pub use crate::bindings::helios::system::filters::FilterError;
use crate::bindings::helios::system::profiling as raw;
pub use crate::bindings::helios::system::profiling::{
    ControlError, Filter, FoldedSample, InstructionProfile, InstructionProfileError,
    InstructionSample, MetricFilter, MetricSample, MonoNanos, ProfileSection, RawProfileError,
    SampledCode, SamplingSession, Scope, WasmFunction,
};

/// Turns kernel-side profile sampling on or off for the machine.
///
/// Refused with [`ControlError::Denied`] unless the instance holds the
/// right to observe the machine.
pub fn set_enabled(enabled: bool) -> Result<(), ControlError> {
    raw::set_enabled(enabled)
}

/// Discards all accumulated profile and metric samples.
///
/// Refused as [`set_enabled`] is.
pub fn clear() -> Result<(), ControlError> {
    raw::clear()
}

/// Returns up to `limit` folded stack samples matching `filter`,
/// suitable for flamegraph rendering.
///
/// An instance that holds the right to observe the machine sees every
/// instance's samples and the kernel's; any other sees only its own.
///
/// A filter of more than 8 prefixes, or with a prefix longer than 128
/// bytes, is refused with the limit it exceeded.
pub fn folded(filter: &Filter, limit: u32) -> Result<Vec<FoldedSample>, FilterError> {
    raw::folded(filter, limit)
}

/// Returns up to `limit` performance-metric samples matching `filter`.
///
/// The filter is bounded as in [`folded`].
pub fn metrics(filter: &MetricFilter, limit: u32) -> Result<Vec<MetricSample>, FilterError> {
    raw::metrics(filter, limit)
}

/// Starts the kernel's instruction-address sampling, independently of
/// [`set_enabled`], returning an active [`SamplingSession`] whose drop stops
/// sampling and restores normal processor timer behavior. Starting discards
/// an earlier run's samples.
///
/// Refused with [`InstructionProfileError::Denied`] unless the instance holds
/// `diagnostics.control`, or [`InstructionProfileError::Busy`] when another
/// session is already active.
pub fn start_instruction_sampling() -> Result<SamplingSession, InstructionProfileError> {
    raw::start_instruction_sampling()
}

/// Returns the instruction addresses the kernel sampled since sampling last
/// started, attributed to the code they executed.
///
/// Refused with [`InstructionProfileError::Denied`] unless the instance holds
/// machine-wide `profile-read`.
pub fn instruction_samples() -> Result<InstructionProfile, InstructionProfileError> {
    raw::instruction_samples()
}

/// Returns the length in bytes of the kernel's LLVM raw profile.
///
/// A kernel that was not built with the `profile-generate` profile carries
/// no instrumentation and says so. An instance without the right to
/// observe the machine is refused with [`RawProfileError::Denied`].
pub fn raw_profile_size() -> Result<u64, RawProfileError> {
    raw::raw_profile_size()
}

/// Returns the window of the kernel's LLVM raw profile that starts at
/// `offset`, at most `length` bytes of it.
pub fn raw_profile_read(offset: u64, length: u32) -> Result<Vec<u8>, RawProfileError> {
    raw::raw_profile_read(offset, length)
}
