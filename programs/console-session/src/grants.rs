//! Translates verified operator [`SessionGrants`] into kernel-enforced
//! `helios:system/programs.capability-grant` values for spawned VT2 shells.
//!
//! Spawned operator shells NEVER receive `MachineRight::Identity` (so they
//! cannot sign `MachineIdentity` challenges) and NEVER receive
//! `DeviceClass::Display` or `DeviceClass::Input` (which belong exclusively
//! to `/plugins/compositor`).

use std::collections::BTreeMap;

use helios_api::inspect::{self, SnapshotResult, Value};
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

const COMPONENT_INSPECT_LIMIT: u32 = 1024;

/// Maximum capability ceiling delegated to a VT2 operator shell.
///
/// Mirrors `SessionGrants::full_worker_ceiling()` while stripping `Display`
/// and `Input` device classes (owned exclusively by `/plugins/compositor`).
/// `MachineRight::Identity` is unrepresentable in [`SessionGrants`].
pub fn console_shell_ceiling() -> SessionGrants {
    let mut grants = SessionGrants::full_worker_ceiling();
    grants.devices = DeviceClassMask::GPU.union(DeviceClassMask::AUDIO);
    grants
}

/// Converts verified [`SessionGrants`] into kernel `CapabilityGrant` values,
/// monotonically intersected against [`console_shell_ceiling`].
pub fn session_grants_to_kernel(grants: &SessionGrants) -> Vec<CapabilityGrant> {
    let effective = grants.intersect(&console_shell_ceiling());
    let needs_subtree_lookup = [
        &effective.inspect_read,
        &effective.trace_read,
        &effective.profile_read,
        &effective.instance_control,
    ]
    .iter()
    .any(|scope| matches!(scope, Some(ScopeRule::Subtree(_))));

    let live_instances = if needs_subtree_lookup {
        inspect::snapshot_prefixes(&["/components/"], COMPONENT_INSPECT_LIMIT)
            .ok()
            .map(|snap| index_component_instances(&snap))
            .unwrap_or_default()
    } else {
        BTreeMap::new()
    };

    session_grants_to_kernel_with_lookup(&effective, |moniker| {
        lookup_component_instance(&live_instances, moniker)
    })
}

/// Converts [`SessionGrants`] into kernel `CapabilityGrant` values using an
/// explicit moniker -> `InstanceId` resolver (for deterministic unit tests).
pub fn session_grants_to_kernel_with_lookup<F>(
    grants: &SessionGrants,
    resolve_subtree: F,
) -> Vec<CapabilityGrant>
where
    F: Fn(&str) -> Option<u64>,
{
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

    // Never delegate `Display` or `Input` to interactive shells.
    let mut classes = Vec::new();
    if grants.devices.contains(DeviceClassMask::GPU) {
        classes.push(DeviceClass::Gpu);
    }
    if grants.devices.contains(DeviceClassMask::AUDIO) {
        classes.push(DeviceClass::Audio);
    }
    if !classes.is_empty() {
        out.push(device_grant(classes));
    }

    if let Some(scope) = &grants.inspect_read {
        out.push(diagnostics_grant(DiagnosticsGrant::InspectRead(map_scope(
            scope,
            &resolve_subtree,
        ))));
    }
    if let Some(scope) = &grants.trace_read {
        out.push(diagnostics_grant(DiagnosticsGrant::TraceRead(map_scope(
            scope,
            &resolve_subtree,
        ))));
    }
    if let Some(scope) = &grants.profile_read {
        out.push(diagnostics_grant(DiagnosticsGrant::ProfileRead(map_scope(
            scope,
            &resolve_subtree,
        ))));
    }
    if grants.diagnostics_control {
        out.push(diagnostics_grant(DiagnosticsGrant::Control));
    }
    if let Some(scope) = &grants.instance_control {
        out.push(instance_control_grant(map_scope(scope, &resolve_subtree)));
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
    // `MachineRight::Identity` is intentionally never delegated to shells.
    if !machine_rights.is_empty() {
        out.push(machine_grant(machine_rights));
    }

    out
}

fn map_scope<F>(scope: &ScopeRule, resolve_subtree: &F) -> AuthorityScope
where
    F: Fn(&str) -> Option<u64>,
{
    match scope {
        ScopeRule::Own => AuthorityScope::Own,
        ScopeRule::Subtree(moniker) => AuthorityScope::Subtree(resolve_subtree(moniker)),
        ScopeRule::Machine => AuthorityScope::Machine,
    }
}

fn index_component_instances(snapshot: &SnapshotResult) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    for entry in &snapshot.entries {
        let Some(rest) = entry.path.strip_prefix("/components/") else {
            continue;
        };
        let Some(prefix) = rest.strip_suffix("/instance_id") else {
            continue;
        };
        if let Value::Unsigned64(id) = entry.value
            && id > 0
        {
            let moniker = if prefix == "root" {
                "/".to_owned()
            } else {
                format!("/{prefix}")
            };
            map.insert(moniker, id);
        }
    }
    if !map.contains_key("/")
        && let Some(pub_rec) = snapshot
            .publications
            .iter()
            .find(|p| p.name == "components" && p.instance_id > 0)
    {
        map.insert("/".to_owned(), pub_rec.instance_id);
    }
    map
}

fn lookup_component_instance(map: &BTreeMap<String, u64>, moniker: &str) -> Option<u64> {
    let normalized = if moniker == "/" {
        "/".to_owned()
    } else {
        let trimmed = moniker.trim_matches('/');
        if trimmed.is_empty() {
            "/".to_owned()
        } else {
            format!("/{trimmed}")
        }
    };
    map.get(&normalized).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_shell_grants_never_delegate_identity_display_or_input() {
        let full = SessionGrants::full_worker_ceiling();
        let effective = full.intersect(&console_shell_ceiling());
        let kernel_grants = session_grants_to_kernel_with_lookup(&effective, |_| None);

        for grant in &kernel_grants {
            if let CapabilityGrant::Machine(machine) = grant {
                assert!(
                    !machine.rights.contains(&MachineRight::Identity),
                    "spawned VT2 shells must never receive MachineRight::Identity"
                );
                assert!(machine.rights.contains(&MachineRight::Control));
                assert!(machine.rights.contains(&MachineRight::Virtualize));
            }
            if let CapabilityGrant::Device(dev) = grant {
                assert!(
                    !dev.classes.contains(&DeviceClass::Display),
                    "spawned VT2 shells must never receive Display device class"
                );
                assert!(
                    !dev.classes.contains(&DeviceClass::Input),
                    "spawned VT2 shells must never receive Input device class"
                );
                assert!(dev.classes.contains(&DeviceClass::Gpu));
                assert!(dev.classes.contains(&DeviceClass::Audio));
            }
        }
    }
}
