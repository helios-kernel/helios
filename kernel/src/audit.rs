//! Non-suppressible kernel security and lifecycle audit log.
//!
//! Records privileged spawns, instance kills, processor online/offline
//! transitions, and diagnostic gate changes under [`TARGET`]. Unlike
//! session-gated diagnostic targets, [`crate::log`] answers
//! `Interest::always()` for [`TARGET`] at every level and refuses any
//! attempt to gate or disable it at runtime.

use crate::{InstanceId, KillOutcome, KillReason};

/// Tracing target for non-suppressible kernel audit events.
pub const TARGET: &str = "helios_kernel::audit";

/// Emits an audit event for a spawned child that received non-empty
/// [`crate::ProcessAuthority`] or capability-channel endpoint grants.
pub fn privileged_spawn(
    parent: Option<InstanceId>,
    child: InstanceId,
    program: &str,
    ipc_grants: usize,
) {
    tracing::info!(
        target: TARGET,
        action = "spawn",
        parent = parent.map_or(0, InstanceId::raw),
        parent_is_kernel = parent.is_none(),
        child = child.raw(),
        program,
        ipc_grants,
        "privileged instance spawned"
    );
}

/// Emits an audit event when an instance kill request is refused by
/// capability or scope checks.
pub fn instance_kill_denied(caller: InstanceId, target: InstanceId) {
    tracing::info!(
        target: TARGET,
        action = "kill",
        caller = caller.raw(),
        caller_is_kernel = false,
        instance = target.raw(),
        reason = "operator",
        outcome = "denied",
        "instance kill denied"
    );
}

/// Emits an audit event for an instance kill request or OOM condemnation.
///
/// `caller` is `Some` when initiated by a guest instance and `None` when
/// initiated by the kernel itself (such as the OOM killer or supervisor).
pub fn instance_kill(
    caller: Option<InstanceId>,
    target: InstanceId,
    reason: KillReason,
    outcome: KillOutcome,
) {
    tracing::info!(
        target: TARGET,
        action = "kill",
        caller = caller.map_or(0, InstanceId::raw),
        caller_is_kernel = caller.is_none(),
        instance = target.raw(),
        reason = ?reason,
        outcome = ?outcome,
        "instance kill"
    );
}

/// Emits an audit event for a processor online/offline transition request.
pub fn processor_transition(
    caller: InstanceId,
    processor: u32,
    transition: &'static str,
    succeeded: bool,
) {
    tracing::info!(
        target: TARGET,
        action = "processor",
        caller = caller.raw(),
        processor,
        transition,
        succeeded,
        "processor transition"
    );
}

/// Emits an audit event when a diagnostic, profiling, or sampling gate
/// changes state.
pub fn diagnostic_gate_change(caller: InstanceId, gate: &'static str, target: &str, enabled: bool) {
    tracing::info!(
        target: TARGET,
        action = "diagnostic-gate",
        caller = caller.raw(),
        gate,
        target,
        enabled,
        "diagnostic gate changed"
    );
}
