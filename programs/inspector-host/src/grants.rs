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
use helios_component_manager::{
    AuthorityScopeSpec, CapabilityCeiling, ClockRights, DeviceClasses, FsRights, LinkRights,
    MachineRights, MountRights, NetRights, OomTier, ProcessRights, TerminalRights,
};
use helios_inspector_protocol::auth::{
    ClockRightsMask, DeviceClassMask, DirectoryRightsMask, DirectoryRule, LinkRightsMask,
    MountRightsMask, NetworkRightsMask, ProcessRightsMask, ScopeRule, SessionGrants,
    TerminalRightsMask,
};

mod compiled_ceilings {
    include!(concat!(env!("OUT_DIR"), "/inspector_ceilings.rs"));
}

/// Compile-time validated OOM tier declared in `components/inspector/tls/component.toml`.
pub const fn compiled_tls_oom_tier() -> OomTier {
    compiled_ceilings::INSPECTOR_TLS_OOM_TIER
}

/// Compile-time validated OOM tier declared in `components/inspector/worker/component.toml`.
pub const fn compiled_worker_oom_tier() -> OomTier {
    compiled_ceilings::INSPECTOR_WORKER_OOM_TIER
}

/// Compile-time validated capability ceiling declared in `components/inspector/tls/component.toml`.
pub fn compiled_tls_ceiling() -> SessionGrants {
    capability_ceiling_to_session_grants(&compiled_ceilings::INSPECTOR_TLS_CEILING)
}

/// Compile-time validated capability ceiling declared in `components/inspector/worker/component.toml`.
pub fn compiled_worker_ceiling() -> SessionGrants {
    capability_ceiling_to_session_grants(&compiled_ceilings::INSPECTOR_WORKER_CEILING)
}

/// Converts a compile-time validated [`CapabilityCeiling`] into [`SessionGrants`].
///
/// `MachineRights::IDENTITY` is never representable in [`SessionGrants`] and is
/// asserted absent so child components can never receive machine identity signing rights.
pub fn capability_ceiling_to_session_grants(cap: &CapabilityCeiling) -> SessionGrants {
    debug_assert!(
        !cap.machine.contains(MachineRights::IDENTITY),
        "inspector child ceiling must never carry MachineRights::IDENTITY"
    );

    let directories = cap
        .directories
        .iter()
        .map(|d| {
            let mut rights = DirectoryRightsMask::EMPTY;
            if d.rights.contains(FsRights::READ) {
                rights = rights.union(DirectoryRightsMask::READ);
            }
            if d.rights.contains(FsRights::WRITE) {
                rights = rights.union(DirectoryRightsMask::WRITE);
            }
            if d.rights.contains(FsRights::MUTATE_DIRECTORY) {
                rights = rights.union(DirectoryRightsMask::MUTATE_DIRECTORY);
            }
            if d.rights.contains(FsRights::EXECUTE) {
                rights = rights.union(DirectoryRightsMask::EXECUTE);
            }
            DirectoryRule::new(d.source.as_ref(), d.guest.as_ref(), rights)
        })
        .collect();

    let mut network = NetworkRightsMask::EMPTY;
    if cap.network.contains(NetRights::TCP) {
        network = network.union(NetworkRightsMask::TCP);
    }
    if cap.network.contains(NetRights::UDP) {
        network = network.union(NetworkRightsMask::UDP);
    }
    if cap.network.contains(NetRights::DNS) {
        network = network.union(NetworkRightsMask::DNS);
    }
    if cap.network.contains(NetRights::PRIVILEGED_BIND) {
        network = network.union(NetworkRightsMask::PRIVILEGED_BIND);
    }
    if cap.network.contains(NetRights::MULTICAST) {
        network = network.union(NetworkRightsMask::MULTICAST);
    }
    if cap.network.contains(NetRights::ADMIN) {
        network = network.union(NetworkRightsMask::ADMIN);
    }

    let mut clock = ClockRightsMask::EMPTY;
    if cap.clock.contains(ClockRights::SET_WALL_CLOCK) {
        clock = clock.union(ClockRightsMask::SET_WALL_CLOCK);
    }

    let mut terminal = TerminalRightsMask::EMPTY;
    if cap.terminal.contains(TerminalRights::INPUT) {
        terminal = terminal.union(TerminalRightsMask::INPUT);
    }
    if cap.terminal.contains(TerminalRights::OUTPUT) {
        terminal = terminal.union(TerminalRightsMask::OUTPUT);
    }
    if cap.terminal.contains(TerminalRights::CONTROL) {
        terminal = terminal.union(TerminalRightsMask::CONTROL);
    }

    let mut process = ProcessRightsMask::EMPTY;
    if cap.process.contains(ProcessRights::SPAWN) {
        process = process.union(ProcessRightsMask::SPAWN);
    }
    if cap.process.contains(ProcessRights::EXEC) {
        process = process.union(ProcessRightsMask::EXEC);
    }
    if cap.process.contains(ProcessRights::FORK) {
        process = process.union(ProcessRightsMask::FORK);
    }
    if cap.process.contains(ProcessRights::JOIN) {
        process = process.union(ProcessRightsMask::JOIN);
    }
    if cap.process.contains(ProcessRights::SIGNAL) {
        process = process.union(ProcessRightsMask::SIGNAL);
    }

    let mut link = LinkRightsMask::EMPTY;
    if cap.link.contains(LinkRights::SOURCE) {
        link = link.union(LinkRightsMask::SOURCE);
    }
    if cap.link.contains(LinkRights::TARGET_DIRECTORY) {
        link = link.union(LinkRightsMask::TARGET_DIRECTORY);
    }
    if cap.link.contains(LinkRights::SYMLINK_CREATE) {
        link = link.union(LinkRightsMask::SYMLINK_CREATE);
    }
    if cap.link.contains(LinkRights::SYMLINK_READ) {
        link = link.union(LinkRightsMask::SYMLINK_READ);
    }

    let mut mount = MountRightsMask::EMPTY;
    if cap.mount.contains(MountRights::MOUNT) {
        mount = mount.union(MountRightsMask::MOUNT);
    }
    if cap.mount.contains(MountRights::UNMOUNT) {
        mount = mount.union(MountRightsMask::UNMOUNT);
    }

    let mut devices = DeviceClassMask::EMPTY;
    if cap.devices.contains(DeviceClasses::DISPLAY) {
        devices = devices.union(DeviceClassMask::DISPLAY);
    }
    if cap.devices.contains(DeviceClasses::INPUT) {
        devices = devices.union(DeviceClassMask::INPUT);
    }
    if cap.devices.contains(DeviceClasses::GPU) {
        devices = devices.union(DeviceClassMask::GPU);
    }
    if cap.devices.contains(DeviceClasses::AUDIO) {
        devices = devices.union(DeviceClassMask::AUDIO);
    }

    let map_ceiling_scope = |scope: AuthorityScopeSpec| match scope {
        AuthorityScopeSpec::None => None,
        AuthorityScopeSpec::Own => Some(ScopeRule::Own),
        AuthorityScopeSpec::Subtree => Some(ScopeRule::Subtree("/".to_owned())),
        AuthorityScopeSpec::Machine => Some(ScopeRule::Machine),
    };

    let instance_control = map_ceiling_scope(cap.instance_control);
    SessionGrants {
        directories,
        network,
        clock,
        terminal,
        process,
        link,
        mount,
        devices,
        inspect_read: map_ceiling_scope(cap.inspect_read),
        trace_read: map_ceiling_scope(cap.trace_read),
        profile_read: map_ceiling_scope(cap.profile_read),
        diagnostics_control: cap.diagnostics_control,
        instance_control: instance_control.clone(),
        settings_write: cap.settings_write,
        machine_control: cap.machine.contains(MachineRights::CONTROL),
        virtualize: cap.machine.contains(MachineRights::VIRTUALIZE),
        component_control: instance_control,
    }
}

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

    #[test]
    fn compiled_tls_ceiling_is_empty_and_user_oom_tier() {
        assert_eq!(compiled_tls_oom_tier(), OomTier::User);
        assert_eq!(
            compiled_ceilings::INSPECTOR_TLS_CEILING,
            CapabilityCeiling::EMPTY
        );
        let tls = compiled_tls_ceiling();
        assert_eq!(tls, SessionGrants::empty());
        assert!(tls.directories.is_empty());
        assert!(tls.network.is_empty());
        assert!(tls.clock.is_empty());
        assert!(tls.terminal.is_empty());
        assert!(tls.process.is_empty());
        assert!(tls.link.is_empty());
        assert!(tls.mount.is_empty());
        assert!(tls.devices.is_empty());
        assert!(tls.inspect_read.is_none());
        assert!(tls.trace_read.is_none());
        assert!(tls.profile_read.is_none());
        assert!(!tls.diagnostics_control);
        assert!(tls.instance_control.is_none());
        assert!(!tls.settings_write);
        assert!(!tls.machine_control);
        assert!(!tls.virtualize);
        assert!(tls.component_control.is_none());
        assert!(session_grants_to_kernel_with_lookup(&tls, |_| None).is_empty());
    }

    #[test]
    fn compiled_worker_ceiling_matches_manifest_excludes_identity_and_bounds_certs() {
        use ed25519_dalek::SigningKey;
        use helios_inspector_protocol::auth::{
            AUTH_PROTOCOL_VERSION, AuthError, AuthPolicy, CapabilityCert, CapabilityCertPayload,
            ClientIdentity, MACHINE_IDENTITY_HANDSHAKE_DOMAIN, ServerHello, TransportKind,
            TransportMask, TrustedAuthorityCa, compute_handshake_challenge,
            sign_machine_identity_seed, verify_client_auth,
        };

        assert_eq!(compiled_worker_oom_tier(), OomTier::User);
        assert!(
            !compiled_ceilings::INSPECTOR_WORKER_CEILING
                .machine
                .contains(MachineRights::IDENTITY),
            "/inspector/worker manifest must never carry MachineRights::IDENTITY"
        );
        let worker = compiled_worker_ceiling();
        assert_eq!(worker, SessionGrants::full_worker_ceiling());

        let kernel_grants = session_grants_to_kernel_with_lookup(&worker, |_| None);
        for g in &kernel_grants {
            if let CapabilityGrant::Machine(grant) = g {
                assert!(
                    !grant.rights.contains(&MachineRight::Identity),
                    "worker kernel grants must never include MachineRight::Identity"
                );
            }
        }

        // Verify that a CapabilityCert requesting rights outside a compiled
        // worker ceiling is rejected by `verify_client_auth` and attenuated by
        // `intersect`, never escalated.
        let mut restricted_cap = compiled_ceilings::INSPECTOR_WORKER_CEILING.clone();
        restricted_cap.machine = MachineRights::CONTROL; // drop VIRTUALIZE
        restricted_cap.settings_write = false;
        let restricted_ceiling = capability_ceiling_to_session_grants(&restricted_cap);
        assert!(!restricted_ceiling.virtualize);
        assert!(!restricted_ceiling.settings_write);
        assert!(restricted_ceiling.machine_control);

        let ca_signing = SigningKey::from_bytes(&[0x10; 32]);
        let client_seed = [0x20; 32];
        let client_pub = SigningKey::from_bytes(&client_seed)
            .verifying_key()
            .to_bytes();
        let machine_seed = [0x30; 32];
        let machine_pub = ClientIdentity::from_static_seed(machine_seed).public_key();
        let now = 1_700_000_000;

        let policy = AuthPolicy {
            version: AUTH_PROTOCOL_VERSION,
            static_keys: Vec::new(),
            trusted_cas: vec![TrustedAuthorityCa {
                label: "test-ca".to_owned(),
                public_key: ca_signing.verifying_key().to_bytes(),
                max_ttl_secs: 3600,
                allowed_transports: TransportMask::ALL,
                ceiling: SessionGrants::full_worker_ceiling(),
            }],
        };

        let mut requested = restricted_ceiling.clone();
        requested.virtualize = true; // exceeds `restricted_ceiling`!
        let cert = CapabilityCert::issue(
            &ca_signing,
            CapabilityCertPayload {
                version: AUTH_PROTOCOL_VERSION,
                principal: "operator".to_owned(),
                subject_public_key: client_pub,
                node_public_key: Some(machine_pub),
                not_before_unix: now - 60,
                expires_at_unix: now + 600,
                allowed_transports: TransportMask::VSOCK,
                grants: requested.clone(),
            },
        )
        .expect("issue cert");

        let server_nonce = [0x55; 32];
        let client_nonce = [0x66; 32];
        let challenge = compute_handshake_challenge(
            AUTH_PROTOCOL_VERSION,
            TransportKind::Vsock,
            server_nonce,
            now,
            None,
            None,
        );
        let hello = ServerHello {
            protocol_version: AUTH_PROTOCOL_VERSION,
            transport: TransportKind::Vsock,
            machine_public_key: machine_pub,
            server_nonce,
            server_unix_time: now,
            tls_binding_required: false,
            machine_signature: sign_machine_identity_seed(
                &machine_seed,
                MACHINE_IDENTITY_HANDSHAKE_DOMAIN,
                &challenge,
            ),
        };
        let identity = ClientIdentity::from_capability_cert(client_seed, cert, Vec::new());
        let auth = identity
            .build_client_auth(&hello, None, client_nonce)
            .expect("build client auth");

        let err = verify_client_auth(&policy, &restricted_ceiling, &hello, None, &auth, now)
            .expect_err("cert exceeding compiled worker ceiling must be rejected");
        assert!(matches!(
            err,
            AuthError::CapabilityEscalation {
                dimension: "virtualize",
                ..
            }
        ));

        // Intersection also strictly drops rights outside the compiled ceiling.
        let intersected = requested.intersect(&restricted_ceiling);
        assert!(!intersected.virtualize);
        assert!(!intersected.settings_write);
        assert!(intersected.machine_control);
    }
}
