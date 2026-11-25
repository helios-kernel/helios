//! Translates authenticated [`SessionGrants`] into kernel-enforced
//! `helios:system/programs.capability-grant` values for spawned
//! `inspector-worker` instances.
//!
//! `MachineRight::Identity` is never delegated to any worker.

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

/// Maximum entries read from `/components/` when resolving live subtree
/// component monikers to kernel `InstanceId`s.
const COMPONENT_INSPECT_LIMIT: u32 = 1024;

/// Converts verified [`SessionGrants`] into kernel `CapabilityGrant` values,
/// resolving live `ScopeRule::Subtree(moniker)` targets through
/// `helios:system/inspect` (`/components/<moniker>/instance_id`).
///
/// The kernel additionally intersects every grant against `inspector-host`'s
/// own `ProcessAuthority` on `programs::spawn`, enforcing monotonicity at the
/// kernel boundary regardless of user space.
pub fn session_grants_to_kernel(grants: &SessionGrants) -> Vec<CapabilityGrant> {
    let needs_subtree_lookup = [
        &grants.inspect_read,
        &grants.trace_read,
        &grants.profile_read,
        &grants.instance_control,
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

    session_grants_to_kernel_with_lookup(grants, |moniker| {
        lookup_component_instance(&live_instances, moniker)
    })
}

/// Converts verified [`SessionGrants`] into kernel `CapabilityGrant` values
/// using an explicit `resolve_subtree` callback for `ScopeRule::Subtree`.
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
    // `MachineRight::Identity` is intentionally never delegated to workers.
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
        // Never promote `Subtree("/")` to `AuthorityScope::Machine`: machine
        // scope exposes `/kernel/*` telemetry, whereas `Subtree` is strictly
        // bounded to the target component's live instance subtree (or the
        // worker's own descendants when that component is not currently live).
        ScopeRule::Subtree(moniker) => AuthorityScope::Subtree(resolve_subtree(moniker)),
        ScopeRule::Machine => AuthorityScope::Machine,
    }
}

/// Indexes live component monikers -> kernel `InstanceId`s from a
/// `/components/` inspect snapshot published by `programs/init`.
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
    // Root `/` is a realm hosted by the root `init` component itself, so its
    // `ComponentStateRecord.instance_id` is `0`; resolve `/` to the root
    // supervisor instance that owns the `"components"` publication.
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
    use helios_api::inspect::{ComponentPublication, Entry, PublicationStatus};

    use super::*;

    fn sample_snapshot() -> SnapshotResult {
        SnapshotResult {
            timestamp: 100,
            entries: vec![
                Entry {
                    path: "/components/root/instance_id".to_owned(),
                    value: Value::Unsigned64(0),
                },
                Entry {
                    path: "/components/core/http-client/instance_id".to_owned(),
                    value: Value::Unsigned64(7),
                },
                Entry {
                    path: "/components/stopped/instance_id".to_owned(),
                    value: Value::Unsigned64(0),
                },
            ],
            truncated: false,
            publications: vec![ComponentPublication {
                instance_id: 1,
                instance_name: "init".to_owned(),
                name: "components".to_owned(),
                generation: 2,
                status: PublicationStatus::Ok,
            }],
        }
    }

    #[test]
    fn subtree_root_never_escalates_to_machine() {
        let index = index_component_instances(&sample_snapshot());
        assert_eq!(lookup_component_instance(&index, "/"), Some(1));

        let grants = SessionGrants {
            inspect_read: Some(ScopeRule::Subtree("/".to_owned())),
            trace_read: Some(ScopeRule::Subtree("/".to_owned())),
            profile_read: Some(ScopeRule::Subtree("/".to_owned())),
            instance_control: Some(ScopeRule::Subtree("/".to_owned())),
            ..SessionGrants::empty()
        };

        // When root init is live (instance 1), Subtree("/") resolves to Subtree(Some(1)) — never Machine.
        let live =
            session_grants_to_kernel_with_lookup(&grants, |m| lookup_component_instance(&index, m));
        assert!(live.iter().any(|g| matches!(
            g,
            CapabilityGrant::Diagnostics(DiagnosticsGrant::InspectRead(AuthorityScope::Subtree(
                Some(1)
            )))
        )));
        assert!(live.iter().any(|g| matches!(
            g,
            CapabilityGrant::InstanceControl(AuthorityScope::Subtree(Some(1)))
        )));
        assert!(!live.iter().any(|g| matches!(
            g,
            CapabilityGrant::Diagnostics(
                DiagnosticsGrant::InspectRead(AuthorityScope::Machine)
                    | DiagnosticsGrant::TraceRead(AuthorityScope::Machine)
                    | DiagnosticsGrant::ProfileRead(AuthorityScope::Machine)
            ) | CapabilityGrant::InstanceControl(AuthorityScope::Machine)
        )));

        // When root is absent from inspect, Subtree("/") stays Subtree(None) — never Machine.
        let absent = session_grants_to_kernel_with_lookup(&grants, |_| None);
        assert!(absent.iter().any(|g| matches!(
            g,
            CapabilityGrant::Diagnostics(DiagnosticsGrant::InspectRead(AuthorityScope::Subtree(
                None
            )))
        )));
        assert!(!absent.iter().any(|g| matches!(
            g,
            CapabilityGrant::Diagnostics(DiagnosticsGrant::InspectRead(AuthorityScope::Machine))
        )));
    }

    #[test]
    fn subtree_moniker_resolves_live_component_and_falls_back_when_stopped() {
        let index = index_component_instances(&sample_snapshot());
        assert_eq!(
            lookup_component_instance(&index, "/core/http-client"),
            Some(7)
        );
        assert_eq!(lookup_component_instance(&index, "/stopped"), None);
        assert_eq!(lookup_component_instance(&index, "/missing"), None);

        let grants = SessionGrants {
            inspect_read: Some(ScopeRule::Subtree("/core/http-client".to_owned())),
            trace_read: Some(ScopeRule::Subtree("/stopped".to_owned())),
            profile_read: Some(ScopeRule::Own),
            instance_control: Some(ScopeRule::Machine),
            machine_control: true,
            virtualize: true,
            ..SessionGrants::empty()
        };

        let kernel_grants =
            session_grants_to_kernel_with_lookup(&grants, |m| lookup_component_instance(&index, m));
        assert!(kernel_grants.iter().any(|g| matches!(
            g,
            CapabilityGrant::Diagnostics(DiagnosticsGrant::InspectRead(AuthorityScope::Subtree(
                Some(7)
            )))
        )));
        assert!(kernel_grants.iter().any(|g| matches!(
            g,
            CapabilityGrant::Diagnostics(DiagnosticsGrant::TraceRead(AuthorityScope::Subtree(
                None
            )))
        )));
        assert!(kernel_grants.iter().any(|g| matches!(
            g,
            CapabilityGrant::Diagnostics(DiagnosticsGrant::ProfileRead(AuthorityScope::Own))
        )));
        assert!(
            kernel_grants
                .iter()
                .any(|g| matches!(g, CapabilityGrant::InstanceControl(AuthorityScope::Machine)))
        );
        // MachineRight::Identity must never be delegated to any worker.
        for g in &kernel_grants {
            if let CapabilityGrant::Machine(grant) = g {
                assert!(!grant.rights.contains(&MachineRight::Identity));
                assert!(grant.rights.contains(&MachineRight::Control));
                assert!(grant.rights.contains(&MachineRight::Virtualize));
            }
        }
    }
}
