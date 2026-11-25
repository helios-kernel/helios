//! Static and runtime validation of monotonic capability ceilings
//! (`Cap(child) <= Cap(parent)`), OOM tiers, routing integrity, socket bindings,
//! and dependency cycle detection.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::model::{
    AuthorityScopeSpec, CapabilityCeiling, ComponentNode, ComponentTopology, Criticality,
    DirectoryGrantSpec, FsRights, IpAddrSpec, MachineRights, MountRights, NetRights, ProviderSlot,
    RunnerSpec, SocketActivationSpec, WasmSharding,
};

/// First unprivileged TCP port (`1..1024` requires `NetRights::PRIVILEGED_BIND`).
const FIRST_UNPRIVILEGED_TCP_PORT: u16 = 1024;

/// Why a component topology or dynamic subtree failed monotonic capability or
/// structural validation.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("component topology must not be empty")]
    EmptyTopology,
    #[error("topology root node must have moniker `/` (found `{found}`)")]
    InvalidRootMoniker { found: String },
    #[error("invalid component moniker `{moniker}`: {reason}")]
    InvalidMoniker {
        moniker: String,
        reason: &'static str,
    },
    #[error("duplicate component moniker `{moniker}`")]
    DuplicateMoniker { moniker: String },
    #[error("component `{moniker}` references missing parent index {parent_index}")]
    MissingParent {
        moniker: String,
        parent_index: usize,
    },
    #[error(
        "capability escalation in `{child}` relative to parent `{parent}` ({dimension}): {detail}"
    )]
    CapabilityEscalation {
        child: String,
        parent: String,
        dimension: &'static str,
        detail: String,
    },
    #[error(
        "OOM tier escalation in `{child}` (`{child_tier}`) exceeds parent `{parent}` ceiling (`{parent_tier}`)"
    )]
    OomTierEscalation {
        child: String,
        child_tier: &'static str,
        parent: String,
        parent_tier: &'static str,
    },
    #[error("routing cycle detected: {cycle}")]
    RoutingCycle { cycle: String },
    #[error("component `{consumer}` uses `{interface}` from unknown moniker `{from}`")]
    UnknownRouteTarget {
        consumer: String,
        interface: String,
        from: String,
    },
    #[error("component `{consumer}` uses `{interface}` from `{from}`, which does not expose it")]
    UnexposedInterface {
        consumer: String,
        interface: String,
        from: String,
    },
    #[error("component `{moniker}` declares duplicate exposed interface `{interface}`")]
    DuplicateExpose { moniker: String, interface: String },
    #[error("component `{moniker}` declares duplicate IPC channel name `{channel}`")]
    DuplicateChannel { moniker: String, channel: String },
    #[error("component `{moniker}` references unknown `after` dependency index {dependency_index}")]
    UnknownDependency {
        moniker: String,
        dependency_index: usize,
    },
    #[error("component `{moniker}` cannot declare `critical = \"parent\"` at the root realm")]
    RootCriticalParent { moniker: String },
    #[error("component `{moniker}` has invalid runner configuration: {detail}")]
    InvalidRunnerConfig { moniker: String, detail: String },
    #[error("duplicate socket binding `{socket}` claimed by both `{first}` and `{second}`")]
    DuplicateSocket {
        socket: String,
        first: String,
        second: String,
    },
    #[error("duplicate kernel provider slot `{slot}` claimed by both `{first}` and `{second}`")]
    DuplicateProviderSlot {
        slot: &'static str,
        first: String,
        second: String,
    },
    #[error(
        "component `{moniker}` requests socket `{socket}` without required authority: {detail}"
    )]
    SocketAuthorityDenied {
        moniker: String,
        socket: String,
        detail: String,
    },
    #[error(
        "component `{moniker}` declares mount at `{path}` without required authority: {detail}"
    )]
    MountAuthorityDenied {
        moniker: String,
        path: String,
        detail: String,
    },
    #[error(
        "component `{moniker}` uses WIT interface `{interface}` outside its own capability ceiling"
    )]
    WitInterfaceDenied { moniker: String, interface: String },
    #[error(
        "dynamic mount refused under `{parent}`: parent realm does not allow `dynamic_mount = true`"
    )]
    DynamicMountNotPermitted { parent: String },
}

/// Normalizes an absolute POSIX-like path, rejecting empty or traversal paths.
pub fn normalize_abs_path(raw: &str) -> Result<String, &'static str> {
    if !raw.starts_with('/') {
        return Err("path must be absolute (start with `/`)");
    }
    let mut segments = Vec::new();
    for part in raw.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err("path must not contain `..` segments");
        }
        segments.push(part);
    }
    if segments.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(format!("/{}", segments.join("/")))
    }
}

/// Returns true if normalized `parent` is a directory prefix of normalized `child`.
///
/// `"/"` covers every path; `"/data"` covers `"/data"` and `"/data/pg"`, but
/// NOT `"/database"`.
#[must_use]
pub fn path_is_prefix(parent: &str, child: &str) -> bool {
    if parent == "/" {
        return child.starts_with('/');
    }
    if child == parent {
        return true;
    }
    child
        .strip_prefix(parent)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Validates that `parent` admits `child` across every capability dimension
/// (`Cap(child) <= Cap(parent)`).
pub fn verify_monotonic_ceiling(
    parent_moniker: &str,
    parent: &CapabilityCeiling,
    child_moniker: &str,
    child: &CapabilityCeiling,
) -> Result<(), ValidationError> {
    // 1. Directory prefixes and rights.
    for dir in child.directories.iter() {
        let child_src = normalize_abs_path(dir.source.as_ref()).map_err(|reason| {
            ValidationError::CapabilityEscalation {
                child: child_moniker.to_owned(),
                parent: parent_moniker.to_owned(),
                dimension: "directories",
                detail: format!("invalid source path `{}`: {reason}", dir.source),
            }
        })?;
        let covered = directory_covered_by(parent.directories.as_ref(), &child_src, dir.rights);
        if !covered {
            return Err(ValidationError::CapabilityEscalation {
                child: child_moniker.to_owned(),
                parent: parent_moniker.to_owned(),
                dimension: "directories",
                detail: format!(
                    "directory `{}` with rights 0b{:04b} exceeds parent directory ceiling",
                    dir.source,
                    dir.rights.bits()
                ),
            });
        }
    }

    // 2. Network rights & TCP / vsock port ceilings.
    if !parent.network.contains(child.network) {
        return Err(ValidationError::CapabilityEscalation {
            child: child_moniker.to_owned(),
            parent: parent_moniker.to_owned(),
            dimension: "network",
            detail: format!(
                "network rights 0b{:06b} exceed parent 0b{:06b}",
                child.network.bits(),
                parent.network.bits()
            ),
        });
    }
    if !parent.tcp_ports.admits_ceiling(&child.tcp_ports) {
        return Err(ValidationError::CapabilityEscalation {
            child: child_moniker.to_owned(),
            parent: parent_moniker.to_owned(),
            dimension: "tcp_ports",
            detail: format!(
                "TCP port ceiling {:?} exceeds parent {:?}",
                child.tcp_ports, parent.tcp_ports
            ),
        });
    }
    if !parent.vsock_ports.admits_ceiling(&child.vsock_ports) {
        return Err(ValidationError::CapabilityEscalation {
            child: child_moniker.to_owned(),
            parent: parent_moniker.to_owned(),
            dimension: "vsock_ports",
            detail: format!(
                "vsock port ceiling {:?} exceeds parent {:?}",
                child.vsock_ports, parent.vsock_ports
            ),
        });
    }

    // 3. Scalar bitflag capability dimensions.
    check_bits(
        parent_moniker,
        child_moniker,
        "clock",
        parent.clock.bits(),
        child.clock.bits(),
    )?;
    check_bits(
        parent_moniker,
        child_moniker,
        "terminal",
        parent.terminal.bits(),
        child.terminal.bits(),
    )?;
    check_bits(
        parent_moniker,
        child_moniker,
        "process",
        parent.process.bits(),
        child.process.bits(),
    )?;
    check_bits(
        parent_moniker,
        child_moniker,
        "link",
        parent.link.bits(),
        child.link.bits(),
    )?;
    check_bits(
        parent_moniker,
        child_moniker,
        "mount",
        parent.mount.bits(),
        child.mount.bits(),
    )?;
    check_bits(
        parent_moniker,
        child_moniker,
        "devices",
        parent.devices.bits(),
        child.devices.bits(),
    )?;
    check_bits(
        parent_moniker,
        child_moniker,
        "machine",
        parent.machine.bits(),
        child.machine.bits(),
    )?;

    // 4. Raw named hardware devices.
    if !parent.named_devices.admits_ceiling(&child.named_devices) {
        return Err(ValidationError::CapabilityEscalation {
            child: child_moniker.to_owned(),
            parent: parent_moniker.to_owned(),
            dimension: "named_devices",
            detail: format!(
                "named devices {:?} exceed parent {:?}",
                child.named_devices, parent.named_devices
            ),
        });
    }

    // 5. Diagnostics, instance control, and settings.
    check_scope(
        parent_moniker,
        child_moniker,
        "inspect_read",
        parent.inspect_read,
        child.inspect_read,
    )?;
    check_scope(
        parent_moniker,
        child_moniker,
        "trace_read",
        parent.trace_read,
        child.trace_read,
    )?;
    check_scope(
        parent_moniker,
        child_moniker,
        "profile_read",
        parent.profile_read,
        child.profile_read,
    )?;
    if child.diagnostics_control && !parent.diagnostics_control {
        return Err(ValidationError::CapabilityEscalation {
            child: child_moniker.to_owned(),
            parent: parent_moniker.to_owned(),
            dimension: "diagnostics_control",
            detail: "child requests diagnostics_control not held by parent".to_owned(),
        });
    }
    check_scope(
        parent_moniker,
        child_moniker,
        "instance_control",
        parent.instance_control,
        child.instance_control,
    )?;
    if child.settings_write && !parent.settings_write {
        return Err(ValidationError::CapabilityEscalation {
            child: child_moniker.to_owned(),
            parent: parent_moniker.to_owned(),
            dimension: "settings_write",
            detail: "child requests settings_write not held by parent".to_owned(),
        });
    }

    // 6. Routed WIT/IPC interface ceiling.
    if !parent.wit_interfaces.admits_ceiling(&child.wit_interfaces) {
        return Err(ValidationError::CapabilityEscalation {
            child: child_moniker.to_owned(),
            parent: parent_moniker.to_owned(),
            dimension: "wit_interfaces",
            detail: format!(
                "WIT interface ceiling {:?} exceeds parent {:?}",
                child.wit_interfaces, parent.wit_interfaces
            ),
        });
    }

    Ok(())
}

/// Checks whether `directories` grants at least `required` rights covering `target_path`.
#[must_use]
pub fn directory_covered_by(
    directories: &[DirectoryGrantSpec],
    target_path: &str,
    required: FsRights,
) -> bool {
    let Ok(normalized_target) = normalize_abs_path(target_path) else {
        return false;
    };
    let mut combined = FsRights::EMPTY;
    for grant in directories {
        let Ok(normalized_src) = normalize_abs_path(grant.source.as_ref()) else {
            continue;
        };
        if path_is_prefix(&normalized_src, &normalized_target) {
            combined = combined.union(grant.rights);
        }
    }
    combined.contains(required)
}

fn check_bits(
    parent_moniker: &str,
    child_moniker: &str,
    dimension: &'static str,
    parent_bits: u8,
    child_bits: u8,
) -> Result<(), ValidationError> {
    if (child_bits & !parent_bits) != 0 {
        return Err(ValidationError::CapabilityEscalation {
            child: child_moniker.to_owned(),
            parent: parent_moniker.to_owned(),
            dimension,
            detail: format!("requested bits 0b{child_bits:b} exceed parent 0b{parent_bits:b}"),
        });
    }
    Ok(())
}

fn check_scope(
    parent_moniker: &str,
    child_moniker: &str,
    dimension: &'static str,
    parent_scope: AuthorityScopeSpec,
    child_scope: AuthorityScopeSpec,
) -> Result<(), ValidationError> {
    if !parent_scope.admits(child_scope) {
        return Err(ValidationError::CapabilityEscalation {
            child: child_moniker.to_owned(),
            parent: parent_moniker.to_owned(),
            dimension,
            detail: format!(
                "requested scope `{}` exceeds parent `{}`",
                child_scope.as_str(),
                parent_scope.as_str()
            ),
        });
    }
    Ok(())
}

/// Validates an entire [`ComponentTopology`] statically or at runtime.
pub fn validate_topology(topology: &ComponentTopology) -> Result<(), ValidationError> {
    let nodes = topology.nodes.as_ref();
    if nodes.is_empty() {
        return Err(ValidationError::EmptyTopology);
    }
    if nodes[0].moniker.as_ref() != "/" {
        return Err(ValidationError::InvalidRootMoniker {
            found: nodes[0].moniker.to_string(),
        });
    }
    if nodes[0].critical == Criticality::Parent {
        return Err(ValidationError::RootCriticalParent {
            moniker: "/".to_owned(),
        });
    }

    let mut seen_monikers = BTreeSet::new();
    let mut bound_tcp: BTreeMap<(IpAddrSpec, u16), &str> = BTreeMap::new();
    let mut bound_vsock: BTreeMap<u32, &str> = BTreeMap::new();
    let mut provider_slots: BTreeMap<&'static str, &str> = BTreeMap::new();

    for (idx, node) in nodes.iter().enumerate() {
        validate_moniker(node.moniker.as_ref())?;
        if !seen_monikers.insert(node.moniker.as_ref()) {
            return Err(ValidationError::DuplicateMoniker {
                moniker: node.moniker.to_string(),
            });
        }

        if idx == 0 {
            if node.parent_index.is_some() {
                return Err(ValidationError::InvalidRootMoniker {
                    found: node.moniker.to_string(),
                });
            }
        } else {
            let parent_idx = node
                .parent_index
                .ok_or_else(|| ValidationError::MissingParent {
                    moniker: node.moniker.to_string(),
                    parent_index: usize::MAX,
                })?;
            let parent = nodes
                .get(parent_idx)
                .ok_or_else(|| ValidationError::MissingParent {
                    moniker: node.moniker.to_string(),
                    parent_index: parent_idx,
                })?;
            verify_monotonic_ceiling(
                parent.moniker.as_ref(),
                &parent.capabilities,
                node.moniker.as_ref(),
                &node.capabilities,
            )?;
            if !parent.oom_tier.admits(node.oom_tier) {
                return Err(ValidationError::OomTierEscalation {
                    child: node.moniker.to_string(),
                    child_tier: node.oom_tier.as_str(),
                    parent: parent.moniker.to_string(),
                    parent_tier: parent.oom_tier.as_str(),
                });
            }
        }

        validate_node_runner(node, &mut provider_slots)?;
        validate_node_mounts(node)?;
        validate_node_sockets(node, &mut bound_tcp, &mut bound_vsock)?;
        validate_node_channels(node, nodes)?;

        for &dep_idx in node.after.iter() {
            if dep_idx >= nodes.len() {
                return Err(ValidationError::UnknownDependency {
                    moniker: node.moniker.to_string(),
                    dependency_index: dep_idx,
                });
            }
        }
    }

    detect_dependency_cycles(nodes)?;
    Ok(())
}

/// Validates a dynamic subtree rooted under an existing `parent` realm.
///
/// Enforces `parent.dynamic_mount == true`, monotonic capability and OOM
/// attenuation from `parent`, internal subtree validity, and acyclicity.
pub fn validate_dynamic_subtree(
    parent: &ComponentNode,
    subtree: &ComponentTopology,
) -> Result<(), ValidationError> {
    if !parent.dynamic_mount {
        return Err(ValidationError::DynamicMountNotPermitted {
            parent: parent.moniker.to_string(),
        });
    }
    let nodes = subtree.nodes.as_ref();
    if nodes.is_empty() {
        return Err(ValidationError::EmptyTopology);
    }

    let mut seen_monikers = BTreeSet::new();
    let mut bound_tcp: BTreeMap<(IpAddrSpec, u16), &str> = BTreeMap::new();
    let mut bound_vsock: BTreeMap<u32, &str> = BTreeMap::new();
    let mut provider_slots: BTreeMap<&'static str, &str> = BTreeMap::new();

    for (idx, node) in nodes.iter().enumerate() {
        validate_moniker(node.moniker.as_ref())?;
        if !seen_monikers.insert(node.moniker.as_ref()) {
            return Err(ValidationError::DuplicateMoniker {
                moniker: node.moniker.to_string(),
            });
        }
        let enclosing = if idx == 0 {
            parent
        } else {
            let p_idx = node
                .parent_index
                .ok_or_else(|| ValidationError::MissingParent {
                    moniker: node.moniker.to_string(),
                    parent_index: usize::MAX,
                })?;
            nodes
                .get(p_idx)
                .ok_or_else(|| ValidationError::MissingParent {
                    moniker: node.moniker.to_string(),
                    parent_index: p_idx,
                })?
        };
        if !is_direct_child_moniker(enclosing.moniker.as_ref(), node.moniker.as_ref()) {
            return Err(ValidationError::InvalidMoniker {
                moniker: node.moniker.to_string(),
                reason: "dynamic component moniker must be a direct child of its enclosing realm",
            });
        }
        verify_monotonic_ceiling(
            enclosing.moniker.as_ref(),
            &enclosing.capabilities,
            node.moniker.as_ref(),
            &node.capabilities,
        )?;
        if !enclosing.oom_tier.admits(node.oom_tier) {
            return Err(ValidationError::OomTierEscalation {
                child: node.moniker.to_string(),
                child_tier: node.oom_tier.as_str(),
                parent: enclosing.moniker.to_string(),
                parent_tier: enclosing.oom_tier.as_str(),
            });
        }
        validate_node_runner(node, &mut provider_slots)?;
        validate_node_mounts(node)?;
        validate_node_sockets(node, &mut bound_tcp, &mut bound_vsock)?;
        validate_node_channels(node, nodes)?;

        for &dep_idx in node.after.iter() {
            if dep_idx >= nodes.len() {
                return Err(ValidationError::UnknownDependency {
                    moniker: node.moniker.to_string(),
                    dependency_index: dep_idx,
                });
            }
        }
    }
    detect_dependency_cycles(nodes)?;
    Ok(())
}

/// Returns `true` iff `child_moniker` is a direct single-segment child of `parent_moniker`.
#[must_use]
pub fn is_direct_child_moniker(parent_moniker: &str, child_moniker: &str) -> bool {
    if child_moniker == "/" || !child_moniker.starts_with('/') {
        return false;
    }
    if parent_moniker == "/" {
        let rest = &child_moniker[1..];
        !rest.is_empty() && !rest.contains('/')
    } else {
        let Some(rest) = child_moniker.strip_prefix(parent_moniker) else {
            return false;
        };
        let Some(segment) = rest.strip_prefix('/') else {
            return false;
        };
        !segment.is_empty() && !segment.contains('/')
    }
}

/// Validates a normalized component moniker (`"/"` or `"/a/b"` with `[A-Za-z0-9._-]`).
pub fn validate_moniker(moniker: &str) -> Result<(), ValidationError> {
    if moniker == "/" {
        return Ok(());
    }
    if !moniker.starts_with('/') || moniker.ends_with('/') {
        return Err(ValidationError::InvalidMoniker {
            moniker: moniker.to_owned(),
            reason: "non-root moniker must start with `/` and must not end with `/`",
        });
    }
    for segment in moniker[1..].split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ValidationError::InvalidMoniker {
                moniker: moniker.to_owned(),
                reason: "moniker contains empty or traversal segment",
            });
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(ValidationError::InvalidMoniker {
                moniker: moniker.to_owned(),
                reason: "moniker segments must use ASCII `[A-Za-z0-9._-]`",
            });
        }
    }
    Ok(())
}

fn validate_node_runner<'a>(
    node: &'a ComponentNode,
    provider_slots: &mut BTreeMap<&'static str, &'a str>,
) -> Result<(), ValidationError> {
    match &node.runner {
        RunnerSpec::Realm => {
            if !node.sockets.is_empty() {
                return Err(ValidationError::InvalidRunnerConfig {
                    moniker: node.moniker.to_string(),
                    detail: "pure realm cannot bind listening sockets".to_owned(),
                });
            }
            if !node.exposes.is_empty() {
                return Err(ValidationError::InvalidRunnerConfig {
                    moniker: node.moniker.to_string(),
                    detail: "pure realm cannot expose IPC/WIT services directly".to_owned(),
                });
            }
        }
        RunnerSpec::Wasm(spec) => {
            if spec.program.is_empty() {
                return Err(ValidationError::InvalidRunnerConfig {
                    moniker: node.moniker.to_string(),
                    detail: "wasm runner requires a non-empty `program` path".to_owned(),
                });
            }
            if let Some(slot) = spec.provider {
                if let Some(prev) = provider_slots.insert(slot.as_str(), node.moniker.as_ref()) {
                    return Err(ValidationError::DuplicateProviderSlot {
                        slot: slot.as_str(),
                        first: prev.to_owned(),
                        second: node.moniker.to_string(),
                    });
                }
                match slot {
                    ProviderSlot::Compiler => {
                        if spec.sharding != WasmSharding::Singleton {
                            return Err(ValidationError::InvalidRunnerConfig {
                                moniker: node.moniker.to_string(),
                                detail: "compiler provider must use `sharding = \"singleton\"`"
                                    .to_owned(),
                            });
                        }
                        if !node.capabilities.is_empty() {
                            return Err(ValidationError::InvalidRunnerConfig {
                                moniker: node.moniker.to_string(),
                                detail:
                                    "compiler provider runs isolated and accepts zero capabilities"
                                        .to_owned(),
                            });
                        }
                    }
                    ProviderSlot::HttpClient => {
                        if spec.sharding != WasmSharding::PerProcessor {
                            return Err(ValidationError::InvalidRunnerConfig {
                                moniker: node.moniker.to_string(),
                                detail:
                                    "http-client provider must use `sharding = \"per-processor\"`"
                                        .to_owned(),
                            });
                        }
                    }
                    ProviderSlot::Surface => {
                        if spec.sharding != WasmSharding::Singleton {
                            return Err(ValidationError::InvalidRunnerConfig {
                                moniker: node.moniker.to_string(),
                                detail: "surface provider must use `sharding = \"singleton\"`"
                                    .to_owned(),
                            });
                        }
                    }
                }
            }
        }
        RunnerSpec::Oci(spec) => {
            if spec.image.is_none() && spec.rootfs.is_none() {
                return Err(ValidationError::InvalidRunnerConfig {
                    moniker: node.moniker.to_string(),
                    detail: "oci runner requires `oci.image` or `oci.rootfs`".to_owned(),
                });
            }
            if let Some(rootfs) = &spec.rootfs
                && !directory_covered_by(
                    node.capabilities.directories.as_ref(),
                    rootfs.as_ref(),
                    FsRights::READ.union(FsRights::EXECUTE),
                )
            {
                return Err(ValidationError::CapabilityEscalation {
                    child: node.moniker.to_string(),
                    parent: node.moniker.to_string(),
                    dimension: "oci.rootfs",
                    detail: format!(
                        "oci rootfs `{rootfs}` requires read+execute directory capability"
                    ),
                });
            }
            for mount in spec.mounts.iter() {
                if !directory_covered_by(
                    node.capabilities.directories.as_ref(),
                    mount.source.as_ref(),
                    mount.rights,
                ) {
                    return Err(ValidationError::CapabilityEscalation {
                        child: node.moniker.to_string(),
                        parent: node.moniker.to_string(),
                        dimension: "oci.mounts",
                        detail: format!(
                            "oci mount source `{}` exceeds component directory rights",
                            mount.source
                        ),
                    });
                }
            }
        }
        RunnerSpec::Exec(spec) => {
            if spec.program.is_empty() {
                return Err(ValidationError::InvalidRunnerConfig {
                    moniker: node.moniker.to_string(),
                    detail: "exec runner requires a non-empty `program` path".to_owned(),
                });
            }
        }
        RunnerSpec::Vm(spec) => {
            if spec.kernel.is_empty() {
                return Err(ValidationError::InvalidRunnerConfig {
                    moniker: node.moniker.to_string(),
                    detail: "vm runner requires a non-empty `vm.kernel` path".to_owned(),
                });
            }
            if spec.cpus == 0 || spec.cpus > 256 {
                return Err(ValidationError::InvalidRunnerConfig {
                    moniker: node.moniker.to_string(),
                    detail: format!("vm.cpus must be in 1..=256 (found {})", spec.cpus),
                });
            }
            if spec.memory_mib == 0 {
                return Err(ValidationError::InvalidRunnerConfig {
                    moniker: node.moniker.to_string(),
                    detail: "vm.memory_mib must be > 0".to_owned(),
                });
            }
            if !node
                .capabilities
                .machine
                .contains(MachineRights::VIRTUALIZE)
            {
                return Err(ValidationError::CapabilityEscalation {
                    child: node.moniker.to_string(),
                    parent: node.moniker.to_string(),
                    dimension: "machine.virtualize",
                    detail: "vm runner requires `machine = [..., \"virtualize\"]`".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn validate_node_mounts(node: &ComponentNode) -> Result<(), ValidationError> {
    if node.mounts.is_empty() {
        return Ok(());
    }
    if !node.capabilities.mount.contains(MountRights::MOUNT) {
        return Err(ValidationError::MountAuthorityDenied {
            moniker: node.moniker.to_string(),
            path: node.mounts[0].path.to_string(),
            detail: "declaring `[[mounts]]` requires `mount = [\"mount\"]` capability".to_owned(),
        });
    }
    for mount in node.mounts.iter() {
        let normalized = normalize_abs_path(mount.path.as_ref()).map_err(|reason| {
            ValidationError::MountAuthorityDenied {
                moniker: node.moniker.to_string(),
                path: mount.path.to_string(),
                detail: reason.to_owned(),
            }
        })?;
        if normalized == "/" {
            return Err(ValidationError::MountAuthorityDenied {
                moniker: node.moniker.to_string(),
                path: mount.path.to_string(),
                detail: "mount point must be below `/`".to_owned(),
            });
        }
        if !directory_covered_by(
            node.capabilities.directories.as_ref(),
            &normalized,
            FsRights::MUTATE_DIRECTORY,
        ) {
            return Err(ValidationError::MountAuthorityDenied {
                moniker: node.moniker.to_string(),
                path: mount.path.to_string(),
                detail: "mount point requires `mutate-directory` directory capability".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_node_sockets<'a>(
    node: &'a ComponentNode,
    bound_tcp: &mut BTreeMap<(IpAddrSpec, u16), &'a str>,
    bound_vsock: &mut BTreeMap<u32, &'a str>,
) -> Result<(), ValidationError> {
    for socket in node.sockets.iter() {
        match *socket {
            SocketActivationSpec::Tcp { address, port, .. } => {
                let label = format!("tcp://{address}:{port}");
                if !node.capabilities.network.contains(NetRights::TCP) {
                    return Err(ValidationError::SocketAuthorityDenied {
                        moniker: node.moniker.to_string(),
                        socket: label,
                        detail: "TCP socket requires `network = [..., \"tcp\"]`".to_owned(),
                    });
                }
                if port != 0
                    && port < FIRST_UNPRIVILEGED_TCP_PORT
                    && !node
                        .capabilities
                        .network
                        .contains(NetRights::PRIVILEGED_BIND)
                {
                    return Err(ValidationError::SocketAuthorityDenied {
                        moniker: node.moniker.to_string(),
                        socket: label,
                        detail: format!(
                            "privileged TCP port {port} requires `network = [..., \"privileged-bind\"]`"
                        ),
                    });
                }
                if !node.capabilities.tcp_ports.admits_port(port) {
                    return Err(ValidationError::SocketAuthorityDenied {
                        moniker: node.moniker.to_string(),
                        socket: label,
                        detail: format!("port {port} is outside component `tcp_ports` ceiling"),
                    });
                }
                if port != 0
                    && let Some(prev) = bound_tcp.insert((address, port), node.moniker.as_ref())
                {
                    return Err(ValidationError::DuplicateSocket {
                        socket: label,
                        first: prev.to_owned(),
                        second: node.moniker.to_string(),
                    });
                }
            }
            SocketActivationSpec::Vsock { port, .. } => {
                let label = format!("vsock://:{port}");
                if !node.capabilities.vsock_ports.admits_port(port) {
                    return Err(ValidationError::SocketAuthorityDenied {
                        moniker: node.moniker.to_string(),
                        socket: label,
                        detail: format!("port {port} is outside component `vsock_ports` ceiling"),
                    });
                }
                if port != 0
                    && let Some(prev) = bound_vsock.insert(port, node.moniker.as_ref())
                {
                    return Err(ValidationError::DuplicateSocket {
                        socket: label,
                        first: prev.to_owned(),
                        second: node.moniker.to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_node_channels(
    node: &ComponentNode,
    all_nodes: &[ComponentNode],
) -> Result<(), ValidationError> {
    let mut exposed_interfaces = BTreeSet::new();
    let mut channel_names = BTreeSet::new();
    for expose in node.exposes.iter() {
        if !exposed_interfaces.insert(expose.interface.as_ref()) {
            return Err(ValidationError::DuplicateExpose {
                moniker: node.moniker.to_string(),
                interface: expose.interface.to_string(),
            });
        }
        if !channel_names.insert(expose.channel.as_ref()) {
            return Err(ValidationError::DuplicateChannel {
                moniker: node.moniker.to_string(),
                channel: expose.channel.to_string(),
            });
        }
    }
    for route in node.routes.iter() {
        if !channel_names.insert(route.consumer_channel.as_ref()) {
            return Err(ValidationError::DuplicateChannel {
                moniker: node.moniker.to_string(),
                channel: route.consumer_channel.to_string(),
            });
        }
        if !node
            .capabilities
            .wit_interfaces
            .admits_name(route.interface.as_ref())
        {
            return Err(ValidationError::WitInterfaceDenied {
                moniker: node.moniker.to_string(),
                interface: route.interface.to_string(),
            });
        }
        let provider = all_nodes.get(route.provider_index).ok_or_else(|| {
            ValidationError::UnknownRouteTarget {
                consumer: node.moniker.to_string(),
                interface: route.interface.to_string(),
                from: route.provider_moniker.to_string(),
            }
        })?;
        if provider.moniker.as_ref() != route.provider_moniker.as_ref() {
            return Err(ValidationError::UnknownRouteTarget {
                consumer: node.moniker.to_string(),
                interface: route.interface.to_string(),
                from: route.provider_moniker.to_string(),
            });
        }
        let exposes = provider.exposes.iter().any(|exp| {
            exp.interface.as_ref() == route.interface.as_ref()
                && exp.channel.as_ref() == route.provider_channel.as_ref()
        });
        if !exposes {
            return Err(ValidationError::UnexposedInterface {
                consumer: node.moniker.to_string(),
                interface: route.interface.to_string(),
                from: route.provider_moniker.to_string(),
            });
        }
    }
    Ok(())
}

/// Detects cycles across both `[[use]]` WIT/IPC routing edges and `after` ordering edges.
fn detect_dependency_cycles(nodes: &[ComponentNode]) -> Result<(), ValidationError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Color {
        White,
        Gray,
        Black,
    }

    fn dfs(
        node_idx: usize,
        nodes: &[ComponentNode],
        colors: &mut [Color],
        stack: &mut Vec<usize>,
    ) -> Result<(), ValidationError> {
        colors[node_idx] = Color::Gray;
        stack.push(node_idx);

        let node = &nodes[node_idx];
        let neighbors = node
            .routes
            .iter()
            .map(|route| route.provider_index)
            .chain(node.after.iter().copied());

        for next in neighbors {
            match colors[next] {
                Color::Gray => {
                    let start = stack.iter().position(|&idx| idx == next).unwrap_or(0);
                    let mut cycle_names: Vec<&str> = stack[start..]
                        .iter()
                        .map(|&idx| nodes[idx].moniker.as_ref())
                        .collect();
                    cycle_names.push(nodes[next].moniker.as_ref());
                    return Err(ValidationError::RoutingCycle {
                        cycle: cycle_names.join(" -> "),
                    });
                }
                Color::White => dfs(next, nodes, colors, stack)?,
                Color::Black => {}
            }
        }

        stack.pop();
        colors[node_idx] = Color::Black;
        Ok(())
    }

    let mut colors = vec![Color::White; nodes.len()];
    let mut stack = Vec::new();
    for idx in 0..nodes.len() {
        if colors[idx] == Color::White {
            dfs(idx, nodes, &mut colors, &mut stack)?;
        }
    }
    Ok(())
}
