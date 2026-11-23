//! What a caller may do through `helios:system/tracing` and
//! `helios:system/profiling`, decided once for both worlds.
//!
//! Both worlds link both interfaces, and every program is linked against
//! them (linkage is cached per binary while authority belongs to the
//! instance), so the refusal happens at the call. Each host function in
//! either world reaches the kernel through one function here, which reads
//! the caller's [`crate::ProcessAuthority`] and answers in kernel types;
//! the world's own conversion then renders the answer in its generated
//! types. The system component sees the whole machine because it was
//! provisioned with explicit capabilities, never because its world skips a
//! check.
//!
//! Orthogonal capability lattice:
//! - Global diagnostic controls (`tracing.set-target-enabled`,
//!   `profiling.set-enabled`, `profiling.clear`,
//!   `profiling.start-instruction-sampling`) require
//!   [`crate::DiagnosticsControlCap`] and emit a non-suppressible
//!   `helios_kernel::audit` event.
//! - Trace reads (`tracing.recent`, `tracing.subscribe`) inspect
//!   [`crate::TraceReadCap`] (`None`, `Own`, `Subtree`, `Machine`).
//! - Attributed profile reads (`profiling.folded`, `profiling.metrics`)
//!   inspect [`crate::ProfileReadCap`] (`None`, `Own`, `Subtree`, `Machine`).
//! - Unattributed machine-wide profile exports (`profiling.instruction-samples`,
//!   `profiling.raw-profile-size`, `profiling.raw-profile-read`) require
//!   [`crate::ProfileReadCap`] with [`crate::AuthorityScope::Machine`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use helios_hal::cpu::Cpu;
use triomphe::Arc;

use crate::{
    AuthorityScope, ComponentHostNetwork, ComponentSamplingSession, DiagnosticsControlCap,
    FoldedProfileSample, InstructionProfile, InstructionProfileError, KernelLlvmProfile,
    LlvmProfile, LlvmProfileError, MachineObservation, NoObservation, OwnInstance,
    PerfMetricFilter, PerfMetricSample, ProfileFilter, SubtreeObservation, TraceEvent, TraceFilter,
};

use super::StoreData;

/// The caller does not hold the required diagnostic capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Denied;

/// A control or machine-wide read that the caller may not make, or that it
/// made and the kernel could not carry out.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Refused<Failure> {
    Denied,
    Failed(Failure),
}

impl<Failure> From<Denied> for Refused<Failure> {
    fn from(Denied: Denied) -> Self {
        Self::Denied
    }
}

/// Why `set-target-enabled` did not flip a gate.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum TargetRefusal {
    Denied,
    /// The kernel gates no diagnostic target under that name; the text is
    /// the kernel's own rendering of why.
    Unknown(String),
}

impl From<Denied> for TargetRefusal {
    fn from(Denied: Denied) -> Self {
        Self::Denied
    }
}

/// The monomorphised [`crate::ObservationScope`] a trace or profile read runs in,
/// chosen from the caller's [`crate::TraceReadCap`] or [`crate::ProfileReadCap`].
#[derive(Clone, Debug)]
pub(super) enum Visibility {
    None(NoObservation),
    Own(OwnInstance),
    Subtree(SubtreeObservation),
    Machine(MachineObservation),
}

impl Visibility {
    pub(super) fn trace_of<CpuImpl, Net, StorageImpl>(
        data: &StoreData<CpuImpl, Net, StorageImpl>,
    ) -> Self
    where
        CpuImpl: Cpu + Clone,
        Net: ComponentHostNetwork,
        StorageImpl: crate::Storage,
    {
        match data.process_authority().derive_trace_read_cap() {
            Err(_) => Self::None(NoObservation),
            Ok(cap) => Self::from_scope(cap.scope(), data),
        }
    }

    pub(super) fn profile_of<CpuImpl, Net, StorageImpl>(
        data: &StoreData<CpuImpl, Net, StorageImpl>,
    ) -> Self
    where
        CpuImpl: Cpu + Clone,
        Net: ComponentHostNetwork,
        StorageImpl: crate::Storage,
    {
        match data.process_authority().derive_profile_read_cap() {
            Err(_) => Self::None(NoObservation),
            Ok(cap) => Self::from_scope(cap.scope(), data),
        }
    }

    fn from_scope<CpuImpl, Net, StorageImpl>(
        scope: AuthorityScope,
        data: &StoreData<CpuImpl, Net, StorageImpl>,
    ) -> Self
    where
        CpuImpl: Cpu + Clone,
        Net: ComponentHostNetwork,
        StorageImpl: crate::Storage,
    {
        match scope {
            AuthorityScope::Own => Self::Own(OwnInstance::new(data.instance().id())),
            AuthorityScope::Subtree(root) => Self::Subtree(SubtreeObservation::new(
                root,
                data.instance_registry.clone(),
            )),
            AuthorityScope::Machine => Self::Machine(MachineObservation),
        }
    }
}

fn diagnostics_control<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
) -> Result<DiagnosticsControlCap, Denied>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    data.process_authority()
        .derive_diagnostics_control_cap()
        .map_err(|_| Denied)
}

fn machine_profile_read<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
) -> Result<(), Denied>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    match data.process_authority().derive_profile_read_cap() {
        Ok(cap) if cap.scope() == AuthorityScope::Machine => Ok(()),
        _ => Err(Denied),
    }
}

/// `tracing.set-target-enabled`.
pub(super) fn set_target_enabled<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
    target: &str,
    enabled: bool,
) -> Result<(), TargetRefusal>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let caller_id = data.instance().id();
    if diagnostics_control(data).is_err() {
        crate::audit::diagnostic_gate_change(caller_id, "tracing.target.denied", target, false);
        return Err(TargetRefusal::Denied);
    }
    let result = crate::log::set_gated_target(target, enabled)
        .map_err(|error| TargetRefusal::Unknown(error.to_string()));
    if result.is_ok() {
        crate::audit::diagnostic_gate_change(caller_id, "tracing.target", target, enabled);
    } else {
        crate::audit::diagnostic_gate_change(caller_id, "tracing.target.rejected", target, enabled);
    }
    result
}

/// `tracing.recent`, after the filter is lifted.
pub(super) fn recent_events<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
    filter: &TraceFilter,
    limit: u32,
) -> Vec<Arc<TraceEvent>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    match Visibility::trace_of(data) {
        Visibility::None(scope) => data.runtime_state.recent(&scope, filter, limit),
        Visibility::Own(scope) => data.runtime_state.recent(&scope, filter, limit),
        Visibility::Subtree(scope) => data.runtime_state.recent(&scope, filter, limit),
        Visibility::Machine(scope) => data.runtime_state.recent(&scope, filter, limit),
    }
}

/// `profiling.set-enabled`.
pub(super) fn set_profiling_enabled<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
    enabled: bool,
) -> Result<(), Denied>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let caller_id = data.instance().id();
    if diagnostics_control(data).is_err() {
        crate::audit::diagnostic_gate_change(caller_id, "profiling.enabled", "denied", false);
        return Err(Denied);
    }
    data.runtime_state.set_profiling_enabled(enabled);
    crate::audit::diagnostic_gate_change(
        caller_id,
        "profiling.enabled",
        if enabled { "enabled" } else { "disabled" },
        true,
    );
    Ok(())
}

/// `profiling.clear`.
pub(super) fn clear_profile<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
) -> Result<(), Denied>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let caller_id = data.instance().id();
    if diagnostics_control(data).is_err() {
        crate::audit::diagnostic_gate_change(caller_id, "profiling.clear", "denied", false);
        return Err(Denied);
    }
    data.runtime_state.clear_profile();
    crate::audit::diagnostic_gate_change(caller_id, "profiling.clear", "cleared", true);
    Ok(())
}

/// `profiling.folded`, after the filter is lifted.
pub(super) fn folded_samples<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
    filter: &ProfileFilter,
    limit: u32,
) -> Vec<FoldedProfileSample>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let ticks = data.cpu.now().ticks();
    match Visibility::profile_of(data) {
        Visibility::None(scope) => data
            .runtime_state
            .folded_profile(ticks, &scope, filter, limit),
        Visibility::Own(scope) => data
            .runtime_state
            .folded_profile(ticks, &scope, filter, limit),
        Visibility::Subtree(scope) => data
            .runtime_state
            .folded_profile(ticks, &scope, filter, limit),
        Visibility::Machine(scope) => data
            .runtime_state
            .folded_profile(ticks, &scope, filter, limit),
    }
}

/// `profiling.metrics`, after the filter is lifted.
pub(super) fn metric_samples<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
    filter: &PerfMetricFilter,
    limit: u32,
) -> Vec<PerfMetricSample>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    match Visibility::profile_of(data) {
        Visibility::None(scope) => data.runtime_state.perf_metrics(&scope, filter, limit),
        Visibility::Own(scope) => data.runtime_state.perf_metrics(&scope, filter, limit),
        Visibility::Subtree(scope) => data.runtime_state.perf_metrics(&scope, filter, limit),
        Visibility::Machine(scope) => data.runtime_state.perf_metrics(&scope, filter, limit),
    }
}

/// `profiling.start-instruction-sampling`.
pub(super) fn start_instruction_sampling<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
) -> Result<ComponentSamplingSession, Refused<InstructionProfileError>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let caller_id = data.instance().id();
    if diagnostics_control(data).is_err() {
        crate::audit::diagnostic_gate_change(
            caller_id,
            "profiling.instruction-sampling",
            "denied",
            false,
        );
        return Err(Refused::Denied);
    }
    match data.runtime_state.instruction_sampler().start_sampling() {
        Ok(session) => {
            crate::audit::diagnostic_gate_change(
                caller_id,
                "profiling.instruction-sampling",
                "started",
                true,
            );
            Ok(ComponentSamplingSession(session))
        }
        Err(error) => {
            crate::audit::diagnostic_gate_change(
                caller_id,
                "profiling.instruction-sampling",
                "failed",
                false,
            );
            Err(Refused::Failed(error))
        }
    }
}

/// `profiling.instruction-samples`.
///
/// The outer error is a bring-up ordering defect, not a refusal: only the
/// program service knows the wasm code that can run, so a read before it
/// exists is not an empty profile.
pub(super) fn instruction_samples<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
) -> wasmtime::Result<Result<InstructionProfile, Refused<InstructionProfileError>>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if machine_profile_read(data).is_err() {
        return Ok(Err(Refused::Denied));
    }
    let service = data.runtime_state.program_service().ok_or_else(|| {
        wasmtime::Error::msg(
            "instruction samples were read before the program service was installed",
        )
    })?;
    Ok(data
        .runtime_state
        .instruction_sampler()
        .profile(service.code_map())
        .map_err(Refused::Failed))
}

/// `profiling.raw-profile-size`.
pub(super) fn raw_profile_size<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
) -> Result<u64, Refused<LlvmProfileError>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    machine_profile_read(data)?;
    KernelLlvmProfile.size().map_err(Refused::Failed)
}

/// `profiling.raw-profile-read`.
pub(super) fn raw_profile_read<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
    offset: u64,
    length: u32,
) -> Result<Vec<u8>, Refused<LlvmProfileError>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    machine_profile_read(data)?;
    super::read_raw_profile(offset, length).map_err(Refused::Failed)
}

#[cfg(test)]
mod observation_authority_tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::wasmtime_adapter::component_host::service::test_store::{
        TestStoreData, store_data_authorized,
    };
    use crate::{
        DiagnosticAuthorityRights, InstanceId, PerfSample, PrefixSet, ProcessAuthority,
        ProfileScope,
    };
    use helios_hal::cpu::HardwarePerfCounterDelta;

    fn unprivileged() -> TestStoreData {
        store_data_authorized(ProcessAuthority::empty(), |_| {})
    }

    fn own_reader() -> TestStoreData {
        let mut authority = ProcessAuthority::empty();
        authority.grant_trace_read(AuthorityScope::Own);
        authority.grant_profile_read(AuthorityScope::Own);
        store_data_authorized(authority, |_| {})
    }

    fn full_observer() -> TestStoreData {
        let mut authority = ProcessAuthority::empty();
        authority.grant_trace_read(AuthorityScope::Machine);
        authority.grant_profile_read(AuthorityScope::Machine);
        authority.grant_diagnostic_rights(DiagnosticAuthorityRights::CONTROL);
        store_data_authorized(authority, |_| {})
    }

    fn other_instance(data: &TestStoreData) -> InstanceId {
        InstanceId::from_raw(data.instance().id().raw() + 1000)
    }

    fn any_trace() -> TraceFilter {
        TraceFilter {
            min_level: None,
            target_prefixes: PrefixSet::default(),
        }
    }

    fn any_stack() -> ProfileFilter {
        ProfileFilter {
            scope: None,
            stack_prefixes: PrefixSet::default(),
        }
    }

    fn any_metric() -> PerfMetricFilter {
        PerfMetricFilter {
            name_prefixes: PrefixSet::default(),
        }
    }

    fn record_events(data: &TestStoreData) {
        let own = data.instance().id();
        let other = other_instance(data);
        let state = &data.runtime_state;
        state.record_console_text(1, None, "INFO [kernel] boot\n");
        state.record_console_text(2, Some(own), "INFO [guest] mine\n");
        state.record_console_text(3, Some(other), "INFO [guest] theirs\n");
    }

    fn record_profile(data: &TestStoreData) {
        let own = data.instance().id();
        let other = other_instance(data);
        let state = &data.runtime_state;
        state.set_profiling_enabled(true);
        state.record_profile_stack_str_nanos(ProfileScope::Kernel, "kernel;executor", 100);
        state.record_user_profile(own, "dash", 3);
        state.record_user_profile(other, "dash", 40);
        state.record_user_profile(other, "other", 5);
        let timed = |nanos| PerfSample::timed(nanos, HardwarePerfCounterDelta::default(), 0);
        state.record_perf_metric_str(ProfileScope::Kernel, "kernel;m", timed(9));
        state.record_perf_metric_str(ProfileScope::User, "user;m", timed(2));
    }

    fn origins(events: &[Arc<TraceEvent>]) -> Vec<Option<InstanceId>> {
        events.iter().map(|event| event.origin).collect()
    }

    #[test]
    fn visibility_distinguishes_none_own_subtree_and_machine_orthogonally() {
        let none = unprivileged();
        assert!(matches!(Visibility::trace_of(&none), Visibility::None(_)));
        assert!(matches!(Visibility::profile_of(&none), Visibility::None(_)));

        let mut trace_only = ProcessAuthority::empty();
        trace_only.grant_trace_read(AuthorityScope::Own);
        let trace_only_store = store_data_authorized(trace_only, |_| {});
        assert!(matches!(
            Visibility::trace_of(&trace_only_store),
            Visibility::Own(_)
        ));
        assert!(matches!(
            Visibility::profile_of(&trace_only_store),
            Visibility::None(_)
        ));

        let holder = full_observer();
        assert!(matches!(
            Visibility::trace_of(&holder),
            Visibility::Machine(_)
        ));
        assert!(matches!(
            Visibility::profile_of(&holder),
            Visibility::Machine(_)
        ));
    }

    #[test]
    fn unprivileged_program_reads_no_traces_no_profiles_and_is_refused_global_controls() {
        let program = unprivileged();
        record_events(&program);
        record_profile(&program);

        assert!(recent_events(&program, &any_trace(), 16).is_empty());
        assert!(folded_samples(&program, &any_stack(), 0).is_empty());
        assert!(metric_samples(&program, &any_metric(), 0).is_empty());

        let enabled_before = program.runtime_state.profiling_enabled();
        assert_eq!(
            set_target_enabled(&program, crate::exec::phases::TARGET, true),
            Err(TargetRefusal::Denied)
        );
        assert_eq!(set_profiling_enabled(&program, false), Err(Denied));
        assert_eq!(clear_profile(&program), Err(Denied));
        assert!(matches!(
            start_instruction_sampling(&program),
            Err(Refused::Denied)
        ));
        assert!(matches!(
            instruction_samples(&program).expect("the refusal precedes the bring-up check"),
            Err(Refused::Denied)
        ));
        assert_eq!(raw_profile_size(&program), Err(Refused::Denied));
        assert_eq!(raw_profile_read(&program, 0, 16), Err(Refused::Denied));
        assert_eq!(
            raw_profile_read(&program, 0, crate::MAX_PROFILE_READ + 1),
            Err(Refused::Denied)
        );
        assert_eq!(program.runtime_state.profiling_enabled(), enabled_before);
    }

    #[test]
    fn read_only_machine_observer_cannot_mutate_controls_and_control_only_cannot_read() {
        let mut read_only_auth = ProcessAuthority::empty();
        read_only_auth.grant_trace_read(AuthorityScope::Machine);
        read_only_auth.grant_profile_read(AuthorityScope::Machine);
        let reader = store_data_authorized(read_only_auth, |_| {});
        record_events(&reader);
        record_profile(&reader);

        assert_eq!(recent_events(&reader, &any_trace(), 16).len(), 3);
        assert_eq!(folded_samples(&reader, &any_stack(), 0).len(), 3);
        assert_eq!(set_profiling_enabled(&reader, false), Err(Denied));
        assert_eq!(clear_profile(&reader), Err(Denied));
        assert!(matches!(
            start_instruction_sampling(&reader),
            Err(Refused::Denied)
        ));

        let mut control_only_auth = ProcessAuthority::empty();
        control_only_auth.grant_diagnostic_rights(DiagnosticAuthorityRights::CONTROL);
        let controller = store_data_authorized(control_only_auth, |_| {});
        record_events(&controller);
        record_profile(&controller);

        assert_eq!(set_profiling_enabled(&controller, true), Ok(()));
        assert!(recent_events(&controller, &any_trace(), 16).is_empty());
        assert!(folded_samples(&controller, &any_stack(), 0).is_empty());
        assert!(matches!(
            instruction_samples(&controller).unwrap(),
            Err(Refused::Denied)
        ));
        assert_eq!(raw_profile_size(&controller), Err(Refused::Denied));
    }

    #[test]
    fn holder_of_controls_and_machine_profile_passes_every_global_operation() {
        let holder = full_observer();
        assert!(matches!(
            set_target_enabled(&holder, "helios_kernel::exec::nope", true),
            Err(TargetRefusal::Unknown(_))
        ));
        assert_eq!(set_profiling_enabled(&holder, true), Ok(()));
        assert!(holder.runtime_state.profiling_enabled());
        assert_eq!(clear_profile(&holder), Ok(()));
        assert_eq!(set_profiling_enabled(&holder, false), Ok(()));
        assert!(!holder.runtime_state.profiling_enabled());
        assert!(matches!(
            start_instruction_sampling(&holder),
            Err(Refused::Failed(InstructionProfileError::NotCaptured))
        ));
        assert!(instruction_samples(&holder).is_err());
        assert!(!matches!(raw_profile_size(&holder), Err(Refused::Denied)));
        assert!(!matches!(
            raw_profile_read(&holder, 0, 16),
            Err(Refused::Denied)
        ));
    }

    #[test]
    fn own_scope_reads_only_its_own_traces_and_profile() {
        let program = own_reader();
        record_events(&program);
        record_profile(&program);

        let seen = recent_events(&program, &any_trace(), 16);
        assert_eq!(origins(&seen), [Some(program.instance().id())]);
        assert_eq!(seen[0].target, "guest");

        let folded = folded_samples(&program, &any_stack(), 0);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].scope, ProfileScope::User);
        assert_eq!(&*folded[0].stack, "user;dash");
        assert_eq!(folded[0].weight, 3);

        assert!(metric_samples(&program, &any_metric(), 0).is_empty());
        assert!(matches!(
            instruction_samples(&program).unwrap(),
            Err(Refused::Denied)
        ));
    }

    #[test]
    fn subtree_scope_reads_descendants_including_retired_children_and_excludes_kernel_and_siblings()
    {
        let base = unprivileged();
        let root_id = base.instance().id();
        let mut subtree_auth = ProcessAuthority::empty();
        subtree_auth.grant_trace_read(AuthorityScope::Subtree(root_id));
        subtree_auth.grant_profile_read(AuthorityScope::Subtree(root_id));
        let mut store = store_data_authorized(subtree_auth, |_| {});
        // Align subtree root to `store`'s own instance.
        let store_id = store.instance().id();
        let mut aligned_auth = ProcessAuthority::empty();
        aligned_auth.grant_trace_read(AuthorityScope::Subtree(store_id));
        aligned_auth.grant_profile_read(AuthorityScope::Subtree(store_id));
        store = store_data_authorized(aligned_auth, |_| {});
        // Wait: `store_data_authorized` creates a fresh registry each time; test
        // `Subtree(child_root)` directly on `store` by rooting at a child subtree!
        let sibling = store.instance_registry.register("sibling", 1);
        let child_root =
            store
                .instance_registry
                .register_child(Some(store.instance().id()), "sub-root", 2);
        let child_root_id = child_root.id();
        let grandchild =
            store
                .instance_registry
                .register_child(Some(child_root_id), "grandchild", 3);
        let grandchild_id = grandchild.id();

        let mut scoped_auth = ProcessAuthority::empty();
        scoped_auth.grant_trace_read(AuthorityScope::Subtree(child_root_id));
        scoped_auth.grant_profile_read(AuthorityScope::Subtree(child_root_id));
        let mut observer = store_data_authorized(scoped_auth, |_| {});
        observer.instance_registry = store.instance_registry.clone();

        // Retire `grandchild` AFTER recording console & profile samples for it!
        observer
            .runtime_state
            .record_console_text(1, None, "INFO [kernel] k\n");
        observer
            .runtime_state
            .record_console_text(2, Some(sibling.id()), "INFO [sib] s\n");
        observer
            .runtime_state
            .record_console_text(3, Some(child_root_id), "INFO [root] r\n");
        observer
            .runtime_state
            .record_console_text(4, Some(grandchild_id), "INFO [gc] g\n");

        observer.runtime_state.set_profiling_enabled(true);
        observer
            .runtime_state
            .record_profile_stack_str_nanos(ProfileScope::Kernel, "kernel;k", 50);
        observer
            .runtime_state
            .record_user_profile(sibling.id(), "sib", 20);
        observer
            .runtime_state
            .record_user_profile(child_root_id, "worker", 10);
        observer
            .runtime_state
            .record_user_profile(grandchild_id, "worker", 7);

        drop(grandchild);

        let seen = recent_events(&observer, &any_trace(), 16);
        assert_eq!(origins(&seen), [Some(child_root_id), Some(grandchild_id)]);

        let folded = folded_samples(&observer, &any_stack(), 0);
        assert_eq!(folded.len(), 1);
        assert_eq!(&*folded[0].stack, "user;worker");
        assert_eq!(folded[0].weight, 17);

        drop((sibling, child_root, base));
    }

    #[test]
    fn machine_scope_reads_every_instances_events_and_merged_profile() {
        let holder = full_observer();
        record_events(&holder);
        record_profile(&holder);

        let seen = recent_events(&holder, &any_trace(), 16);
        assert_eq!(
            origins(&seen),
            [
                None,
                Some(holder.instance().id()),
                Some(other_instance(&holder))
            ]
        );

        let folded = folded_samples(&holder, &any_stack(), 0);
        let rows = folded
            .iter()
            .map(|row| (row.scope, &*row.stack, row.weight))
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            [
                (ProfileScope::Kernel, "kernel;executor", 100),
                (ProfileScope::User, "user;dash", 43),
                (ProfileScope::User, "user;other", 5),
            ]
        );
        assert_eq!(metric_samples(&holder, &any_metric(), 0).len(), 2);
    }

    #[test]
    fn sampling_session_enforces_exclusivity_and_stops_on_explicit_drop_or_store_teardown() {
        let engine = crate::wasmtime_adapter::engine::build_component_engine_for_platform(
            &crate::test_support::TestCpu::with_entropy(0x55),
        )
        .unwrap();

        let mut control_auth = ProcessAuthority::empty();
        control_auth.grant_diagnostic_rights(DiagnosticAuthorityRights::CONTROL);
        let data = store_data_authorized(control_auth, |state| {
            state
                .instruction_sampler()
                .install_capture(crate::SampleCapture {
                    period_nanos: 1_000_000,
                    kernel_image_base: 0,
                });
        });
        let sampler = data.runtime_state.instruction_sampler().clone();
        let mut store = wasmtime::Store::new(&engine, data);

        // 1. Start sampling and push the RAII resource into the component's table.
        let session = start_instruction_sampling(store.data())
            .expect("diagnostics.control with installed capture must start sampling");
        let handle = store
            .data_mut()
            .table
            .push(session)
            .expect("table push succeeds");
        assert!(sampler.sampling());

        // 2. Concurrent second start returns `Busy`.
        assert!(matches!(
            start_instruction_sampling(store.data()),
            Err(Refused::Failed(InstructionProfileError::Busy))
        ));

        // 3. Explicit resource drop stops sampling immediately.
        let removed = store
            .data_mut()
            .table
            .delete(handle)
            .expect("table delete succeeds");
        drop(removed);
        assert!(
            !sampler.sampling(),
            "dropping ComponentSamplingSession must stop instruction sampling"
        );

        // 4. Re-acquire and drop the entire `Store` WITHOUT explicit resource drop
        //    (simulating guest trap/condemnation while holding the lease).
        let leaked = start_instruction_sampling(store.data())
            .expect("re-acquiring after explicit drop must succeed");
        let _leaked_handle = store
            .data_mut()
            .table
            .push(leaked)
            .expect("table push succeeds");
        assert!(sampler.sampling());

        drop(store);
        assert!(
            !sampler.sampling(),
            "store teardown with an open ComponentSamplingSession must stop sampling"
        );

        // 5. Sampler is available again for a fresh session.
        let next = sampler
            .start_sampling()
            .expect("sampler must accept a new session after store teardown");
        assert!(sampler.sampling());
        drop(next);
        assert!(!sampler.sampling());
    }
}
