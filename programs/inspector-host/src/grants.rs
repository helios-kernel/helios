//! Translates authenticated [`SessionGrants`] into kernel-enforced
//! `helios:system/programs.capability-grant` values for spawned
//! `inspector-worker` instances.
//!
//! `MachineRight::Identity` is never delegated to any worker.

use helios_api::programs::{
    AuthorityScope, CapabilityGrant, ClockRight, DeviceClass, DiagnosticsGrant, FilesystemRight,
    LinkRight, MachineRight, MountRight, NetworkRight, ProcessRight, SettingsRight, TerminalRight,
    clock_grant, device_grant, diagnostics_grant, directory_grant, instance_control_grant,
    link_grant, machine_grant, mount_grant, network_grant, process_grant, settings_grant,
    terminal_grant,
};
use helios_inspector_protocol::auth::{
    ClockRightsMask, DeviceClassMask, DirectoryRightsMask, LinkRightsMask, MountRightsMask,
    NetworkRightsMask, ProcessRightsMask, ScopeRule, SessionGrants, TerminalRightsMask,
};

/// Converts verified [`SessionGrants`] into kernel `CapabilityGrant` values.
///
/// The kernel additionally intersects every grant against `inspector-host`'s
/// own `ProcessAuthority` on `programs::spawn`, enforcing monotonicity at the
/// kernel boundary regardless of user space.
pub fn session_grants_to_kernel(grants: &SessionGrants) -> Vec<CapabilityGrant> {
    let mut out = Vec::new();

    for dir in &grants.directories {
        let mut rights = Vec::new();
        if dir.rights.contains(DirectoryRightsMask::READ) {
            rights.push(FilesystemRight::Read);
        }
        if dir.rights.contains(DirectoryRightsMask::WRITE) {
            rights.push(FilesystemRight::Write);
        }
        if dir.rights.contains(DirectoryRightsMask::MUTATE_DIRECTORY) {
            rights.push(FilesystemRight::MutateDirectory);
        }
        if dir.rights.contains(DirectoryRightsMask::EXECUTE) {
            rights.push(FilesystemRight::Execute);
        }
        if !rights.is_empty() {
            out.push(directory_grant(
                dir.source_path.clone(),
                dir.guest_name.clone(),
                rights,
            ));
        }
    }

    if !grants.network.is_empty() {
        let mut rights = Vec::new();
        if grants.network.contains(NetworkRightsMask::TCP) {
            rights.push(NetworkRight::Tcp);
        }
        if grants.network.contains(NetworkRightsMask::UDP) {
            rights.push(NetworkRight::Udp);
        }
        if grants.network.contains(NetworkRightsMask::DNS) {
            rights.push(NetworkRight::Dns);
        }
        if grants.network.contains(NetworkRightsMask::PRIVILEGED_BIND) {
            rights.push(NetworkRight::PrivilegedBind);
        }
        if grants.network.contains(NetworkRightsMask::MULTICAST) {
            rights.push(NetworkRight::Multicast);
        }
        if grants.network.contains(NetworkRightsMask::ADMIN) {
            rights.push(NetworkRight::Admin);
        }
        out.push(network_grant(rights));
    }

    if grants.clock.contains(ClockRightsMask::SET_WALL_CLOCK) {
        out.push(clock_grant(vec![ClockRight::SetWallClock]));
    }

    if !grants.terminal.is_empty() {
        let mut rights = Vec::new();
        if grants.terminal.contains(TerminalRightsMask::INPUT) {
            rights.push(TerminalRight::Input);
        }
        if grants.terminal.contains(TerminalRightsMask::OUTPUT) {
            rights.push(TerminalRight::Output);
        }
        if grants.terminal.contains(TerminalRightsMask::CONTROL) {
            rights.push(TerminalRight::Control);
        }
        out.push(terminal_grant(rights));
    }

    if !grants.process.is_empty() {
        let mut rights = Vec::new();
        if grants.process.contains(ProcessRightsMask::SPAWN) {
            rights.push(ProcessRight::Spawn);
        }
        if grants.process.contains(ProcessRightsMask::EXEC) {
            rights.push(ProcessRight::Exec);
        }
        if grants.process.contains(ProcessRightsMask::FORK) {
            rights.push(ProcessRight::Fork);
        }
        if grants.process.contains(ProcessRightsMask::JOIN) {
            rights.push(ProcessRight::Join);
        }
        if grants.process.contains(ProcessRightsMask::SIGNAL) {
            rights.push(ProcessRight::Signal);
        }
        out.push(process_grant(rights));
    }

    if !grants.link.is_empty() {
        let mut rights = Vec::new();
        if grants.link.contains(LinkRightsMask::SOURCE) {
            rights.push(LinkRight::Source);
        }
        if grants.link.contains(LinkRightsMask::TARGET_DIRECTORY) {
            rights.push(LinkRight::TargetDirectory);
        }
        if grants.link.contains(LinkRightsMask::SYMLINK_CREATE) {
            rights.push(LinkRight::SymlinkCreate);
        }
        if grants.link.contains(LinkRightsMask::SYMLINK_READ) {
            rights.push(LinkRight::SymlinkRead);
        }
        out.push(link_grant(rights));
    }

    if !grants.mount.is_empty() {
        let mut rights = Vec::new();
        if grants.mount.contains(MountRightsMask::MOUNT) {
            rights.push(MountRight::Mount);
        }
        if grants.mount.contains(MountRightsMask::UNMOUNT) {
            rights.push(MountRight::Unmount);
        }
        out.push(mount_grant(rights));
    }

    if !grants.devices.is_empty() {
        let mut classes = Vec::new();
        if grants.devices.contains(DeviceClassMask::DISPLAY) {
            classes.push(DeviceClass::Display);
        }
        if grants.devices.contains(DeviceClassMask::INPUT) {
            classes.push(DeviceClass::Input);
        }
        if grants.devices.contains(DeviceClassMask::GPU) {
            classes.push(DeviceClass::Gpu);
        }
        if grants.devices.contains(DeviceClassMask::AUDIO) {
            classes.push(DeviceClass::Audio);
        }
        out.push(device_grant(classes));
    }

    if let Some(scope) = &grants.inspect_read {
        out.push(diagnostics_grant(DiagnosticsGrant::InspectRead(map_scope(
            scope,
        ))));
    }
    if let Some(scope) = &grants.trace_read {
        out.push(diagnostics_grant(DiagnosticsGrant::TraceRead(map_scope(
            scope,
        ))));
    }
    if let Some(scope) = &grants.profile_read {
        out.push(diagnostics_grant(DiagnosticsGrant::ProfileRead(map_scope(
            scope,
        ))));
    }
    if grants.diagnostics_control {
        out.push(diagnostics_grant(DiagnosticsGrant::Control));
    }
    if let Some(scope) = &grants.instance_control {
        out.push(instance_control_grant(map_scope(scope)));
    }
    if grants.settings_write {
        out.push(settings_grant(vec![SettingsRight::Write]));
    }

    let mut machine_rights = Vec::new();
    if grants.machine_control {
        machine_rights.push(MachineRight::Control);
    }
    if grants.virtualize {
        machine_rights.push(MachineRight::Virtualize);
    }
    // `MachineRight::Identity` is intentionally never delegated to workers.
    if !machine_rights.is_empty() {
        out.push(machine_grant(machine_rights));
    }

    out
}

fn map_scope(scope: &ScopeRule) -> AuthorityScope {
    match scope {
        ScopeRule::Own => AuthorityScope::Own,
        // Component-tree subtree scopes map to child subtree scope when rooted
        // below `/` or machine scope when rooted at `/`.
        ScopeRule::Subtree(moniker) if moniker == "/" => AuthorityScope::Machine,
        ScopeRule::Subtree(_) => AuthorityScope::Subtree(None),
        ScopeRule::Machine => AuthorityScope::Machine,
    }
}
