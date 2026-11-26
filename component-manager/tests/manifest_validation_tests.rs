#![cfg(feature = "manifest")]

use std::borrow::Cow;
use std::collections::BTreeMap;

use helios_component_manager::{
    CapabilityCeiling, ComponentNode, ComponentTopology, Criticality, DirectoryGrantSpec,
    EscalationAction, FsRights, HardwarePredicates, LifecycleKind, MachineRights, ManifestError,
    NameCeiling, OciRunnerSpec, OomTier, ProviderSlot, RestartPolicy, RunnerSpec, StartupPolicy,
    ValidationError, VmRunnerSpec, VmShareSpec, WasmRunnerSpec, WasmSharding, load_tree_from_dir,
    load_tree_from_map, validate_dynamic_subtree, validate_topology,
};

fn root_manifest_full() -> String {
    r#"
runner = "realm"
oom_tier = "protected"

[capabilities]
directories = [
  { source = "/", guest = "/", rights = ["read", "write", "mutate-directory", "execute"] },
]
network = ["tcp", "udp", "dns", "privileged-bind", "multicast", "admin"]
allow_all_tcp_ports = true
allow_all_vsock_ports = true
clock = ["set-wall-clock"]
terminal = ["input", "output", "control"]
process = ["spawn", "exec", "fork", "join", "signal"]
link = ["source", "target-directory", "symlink-create", "symlink-read"]
mount = ["mount", "unmount"]
devices = ["display", "input", "gpu", "audio"]
allow_all_named_devices = true
inspect_read = "machine"
trace_read = "machine"
profile_read = "machine"
diagnostics_control = true
instance_control = "machine"
settings_write = true
machine = ["control", "identity", "virtualize"]
allow_all_wit_interfaces = true
"#
    .to_owned()
}

fn tree(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn rejects_unknown_fields_in_manifest_and_nested_sections() {
    let cases = [
        (
            "top-level",
            r#"
runner = "realm"
mystery_knob = true
"#,
        ),
        (
            "capabilities",
            r#"
runner = "realm"
[capabilities]
sudo = true
"#,
        ),
        (
            "socket",
            r#"
runner = "wasm"
program = "/bin/a"
[[sockets]]
kind = "tcp"
port = 8080
extra = 1
"#,
        ),
        (
            "mount",
            r#"
runner = "realm"
[[mounts]]
source = "memory"
path = "/tmp"
sharing = "shared"
bogus = "x"
"#,
        ),
    ];

    for (label, toml_src) in cases {
        let err = load_tree_from_map(tree(&[("/", toml_src)]))
            .expect_err(&format!("unknown field in {label} must fail"));
        assert!(
            matches!(err, ManifestError::Parse { .. }),
            "{label}: expected parse error, got {err:?}"
        );
    }
}

#[test]
fn rejects_directory_prefix_and_right_escalation() {
    let parent = r#"
runner = "realm"
[capabilities]
directories = [
  { source = "/data", guest = "/data", rights = ["read"] },
]
"#;
    // Sibling prefix trick: `/data` must NOT cover `/database`.
    let child_sibling = r#"
runner = "wasm"
program = "/bin/app"
[capabilities]
directories = [
  { source = "/database", guest = "/database", rights = ["read"] },
]
"#;
    let err = load_tree_from_map(tree(&[
        ("/", &root_manifest_full()),
        ("/apps", parent),
        ("/apps/svc", child_sibling),
    ]))
    .expect_err("sibling prefix /database must be rejected under /data");
    assert!(matches!(
        err,
        ManifestError::Validation(ValidationError::CapabilityEscalation {
            dimension: "directories",
            ..
        })
    ));

    // Right escalation: parent has `read`, child asks for `read` + `write`.
    let child_write = r#"
runner = "wasm"
program = "/bin/app"
[capabilities]
directories = [
  { source = "/data/sub", guest = "/data/sub", rights = ["read", "write"] },
]
"#;
    let err = load_tree_from_map(tree(&[
        ("/", &root_manifest_full()),
        ("/apps", parent),
        ("/apps/svc", child_write),
    ]))
    .expect_err("write escalation under read-only parent must fail");
    assert!(matches!(
        err,
        ManifestError::Validation(ValidationError::CapabilityEscalation {
            dimension: "directories",
            ..
        })
    ));
}

#[test]
fn rejects_network_ports_devices_virtualize_oom_and_wit_escalation() {
    let parent = r#"
runner = "realm"
oom_tier = "plugin"
[capabilities]
network = ["tcp"]
tcp_ports = [8080]
vsock_ports = [5000]
devices = ["display"]
named_devices = ["pci-00:01.0"]
inspect_read = "subtree"
machine = ["identity"]
wit_interfaces = ["helios:demo/allowed"]
"#;

    let cases: &[(&str, &str, &str)] = &[
        (
            "network",
            r#"
runner = "wasm"
program = "/bin/a"
oom_tier = "user"
[capabilities]
network = ["tcp", "admin"]
"#,
            "network",
        ),
        (
            "tcp_ports",
            r#"
runner = "wasm"
program = "/bin/a"
oom_tier = "user"
[capabilities]
network = ["tcp"]
tcp_ports = [8080, 9090]
"#,
            "tcp_ports",
        ),
        (
            "vsock_ports",
            r#"
runner = "wasm"
program = "/bin/a"
oom_tier = "user"
[capabilities]
vsock_ports = [6000]
"#,
            "vsock_ports",
        ),
        (
            "devices",
            r#"
runner = "wasm"
program = "/bin/a"
oom_tier = "user"
[capabilities]
devices = ["display", "gpu"]
"#,
            "devices",
        ),
        (
            "named_devices",
            r#"
runner = "wasm"
program = "/bin/a"
oom_tier = "user"
[capabilities]
named_devices = ["pci-00:02.0"]
"#,
            "named_devices",
        ),
        (
            "inspect_read",
            r#"
runner = "wasm"
program = "/bin/a"
oom_tier = "user"
[capabilities]
inspect_read = "machine"
"#,
            "inspect_read",
        ),
        (
            "virtualize",
            r#"
runner = "vm"
oom_tier = "user"
[vm]
kernel = "/boot/Image"
[capabilities]
machine = ["virtualize"]
"#,
            "machine",
        ),
        (
            "wit_interfaces",
            r#"
runner = "wasm"
program = "/bin/a"
oom_tier = "user"
[capabilities]
wit_interfaces = ["helios:demo/forbidden"]
"#,
            "wit_interfaces",
        ),
    ];

    for (label, child, expected_dim) in cases {
        let err = load_tree_from_map(tree(&[
            ("/", &root_manifest_full()),
            ("/realm", parent),
            ("/realm/child", child),
        ]))
        .expect_err(&format!("{label} escalation must fail"));
        assert!(
            matches!(
                err,
                ManifestError::Validation(ValidationError::CapabilityEscalation { dimension, .. })
                if dimension == *expected_dim
            ),
            "{label}: expected escalation on {expected_dim}, got {err:?}"
        );
    }

    // OOM tier escalation: parent is `plugin`, child asks for `protected`.
    let child_oom = r#"
runner = "wasm"
program = "/bin/a"
oom_tier = "protected"
"#;
    let err = load_tree_from_map(tree(&[
        ("/", &root_manifest_full()),
        ("/realm", parent),
        ("/realm/child", child_oom),
    ]))
    .expect_err("oom_tier escalation must fail");
    assert!(matches!(
        err,
        ManifestError::Validation(ValidationError::OomTierEscalation { .. })
    ));
}

#[test]
fn rejects_routing_and_after_cycles() {
    let a = r#"
runner = "wasm"
program = "/bin/a"
[capabilities]
wit_interfaces = ["demo:a/svc", "demo:b/svc"]
[[expose]]
interface = "demo:a/svc"
channel = "a-srv"
[[use]]
interface = "demo:b/svc"
from = "/b"
channel = "b-cli"
"#;
    let b = r#"
runner = "wasm"
program = "/bin/b"
[capabilities]
wit_interfaces = ["demo:a/svc", "demo:b/svc"]
[[expose]]
interface = "demo:b/svc"
channel = "b-srv"
[[use]]
interface = "demo:a/svc"
from = "/a"
channel = "a-cli"
"#;
    let err = load_tree_from_map(tree(&[("/", &root_manifest_full()), ("/a", a), ("/b", b)]))
        .expect_err("WIT routing cycle must be rejected");
    assert!(
        matches!(
            err,
            ManifestError::Validation(ValidationError::RoutingCycle { .. })
        ),
        "expected RoutingCycle, got {err:?}"
    );

    // Mixed `after` cycle: /x -> /y -> /x.
    let x = r#"
runner = "wasm"
program = "/bin/x"
after = ["/y"]
"#;
    let y = r#"
runner = "wasm"
program = "/bin/y"
after = ["/x"]
"#;
    let err = load_tree_from_map(tree(&[("/", &root_manifest_full()), ("/x", x), ("/y", y)]))
        .expect_err("`after` dependency cycle must be rejected");
    assert!(matches!(
        err,
        ManifestError::Validation(ValidationError::RoutingCycle { .. })
    ));
}

#[test]
fn rejects_privileged_tcp_socket_without_privileged_bind_and_duplicate_ports() {
    let priv_missing = r#"
runner = "wasm"
program = "/bin/web"
[capabilities]
network = ["tcp"]
tcp_ports = [443]
[[sockets]]
kind = "tcp"
port = 443
"#;
    let err = load_tree_from_map(tree(&[
        ("/", &root_manifest_full()),
        ("/web", priv_missing),
    ]))
    .expect_err("privileged port 443 without privileged-bind must fail");
    assert!(matches!(
        err,
        ManifestError::Validation(ValidationError::SocketAuthorityDenied { .. })
    ));

    let dup_a = r#"
runner = "wasm"
program = "/bin/a"
[capabilities]
network = ["tcp"]
tcp_ports = [8080]
[[sockets]]
kind = "tcp"
port = 8080
"#;
    let dup_b = r#"
runner = "wasm"
program = "/bin/b"
[capabilities]
network = ["tcp"]
tcp_ports = [8080]
[[sockets]]
kind = "tcp"
port = 8080
"#;
    let err = load_tree_from_map(tree(&[
        ("/", &root_manifest_full()),
        ("/a", dup_a),
        ("/b", dup_b),
    ]))
    .expect_err("duplicate TCP port binding must fail");
    assert!(matches!(
        err,
        ManifestError::Validation(ValidationError::DuplicateSocket { .. })
    ));
}

#[test]
fn loads_default_repository_components_directory_cleanly() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("component-manager lives under workspace root");
    let topology = load_tree_from_dir(&repo_root.join("components"))
        .expect("default components tree is valid");
    assert!(topology.find_by_moniker("/").is_some());
    assert!(topology.find_by_moniker("/plugins").is_some());
    assert!(topology.find_by_moniker("/plugins/compiler").is_some());
    assert!(topology.find_by_moniker("/plugins/http-client").is_some());
    assert!(topology.find_by_moniker("/plugins/compositor").is_some());
    assert!(topology.find_by_moniker("/debugger").is_none());

    let inspector = &topology.nodes[topology
        .find_by_moniker("/inspector")
        .expect("/inspector manifest must exist")];
    let inspector_tls = &topology.nodes[topology
        .find_by_moniker("/inspector/tls")
        .expect("/inspector/tls manifest must exist")];
    let inspector_worker = &topology.nodes[topology
        .find_by_moniker("/inspector/worker")
        .expect("/inspector/worker manifest must exist")];

    assert_eq!(
        inspector_tls.capabilities,
        helios_component_manager::CapabilityCeiling::EMPTY,
        "/inspector/tls must statically declare empty capabilities"
    );
    assert!(
        inspector
            .capabilities
            .machine
            .contains(helios_component_manager::MachineRights::IDENTITY),
        "/inspector holds machine.identity for handshake signing"
    );
    assert!(
        !inspector_worker
            .capabilities
            .machine
            .contains(helios_component_manager::MachineRights::IDENTITY),
        "/inspector/worker must never hold machine.identity"
    );
}

#[test]
fn rejects_traversal_and_uncovered_paths_for_oci_and_vm_runners() {
    // 1. Manifest rejects `..` and relative paths in OCI and VM fields.
    let bad_manifests: &[(&str, &str)] = &[
        (
            "oci.store traversal",
            r#"
runner = "oci"
[oci]
image = "alpine:3.20"
store = "/var/lib/oci/../secret"
[capabilities]
directories = [{ source = "/", guest = "/", rights = ["read", "write", "execute"] }]
"#,
        ),
        (
            "oci.rootfs relative",
            r#"
runner = "oci"
[oci]
rootfs = "relative/rootfs"
[capabilities]
directories = [{ source = "/", guest = "/", rights = ["read", "write", "execute"] }]
"#,
        ),
        (
            "vm.kernel traversal",
            r#"
runner = "vm"
[vm]
kernel = "/boot/../etc/passwd"
[capabilities]
machine = ["virtualize"]
directories = [{ source = "/", guest = "/", rights = ["read", "write", "execute"] }]
"#,
        ),
        (
            "vm.initramfs traversal",
            r#"
runner = "vm"
[vm]
kernel = "/boot/Image"
initramfs = "/boot/../initrd"
[capabilities]
machine = ["virtualize"]
directories = [{ source = "/", guest = "/", rights = ["read", "write", "execute"] }]
"#,
        ),
        (
            "vm.disk traversal",
            r#"
runner = "vm"
[vm]
kernel = "/boot/Image"
disk = "/var/vm/../disk.raw"
[capabilities]
machine = ["virtualize"]
directories = [{ source = "/", guest = "/", rights = ["read", "write", "execute"] }]
"#,
        ),
        (
            "vm.rootfs_dir relative",
            r#"
runner = "vm"
[vm]
kernel = "/boot/Image"
rootfs_dir = "vm/rootfs"
[capabilities]
machine = ["virtualize"]
directories = [{ source = "/", guest = "/", rights = ["read", "write", "execute"] }]
"#,
        ),
        (
            "vm.share_dirs traversal",
            r#"
runner = "vm"
[vm]
kernel = "/boot/Image"
share_dirs = ["work:/srv/work/../../etc"]
[capabilities]
machine = ["virtualize"]
directories = [{ source = "/", guest = "/", rights = ["read", "write", "execute"] }]
"#,
        ),
    ];

    for (label, manifest) in bad_manifests {
        let err = load_tree_from_map(tree(&[("/", &root_manifest_full()), ("/app", manifest)]))
            .expect_err(&format!("{label} must be rejected"));
        assert!(
            matches!(err, ManifestError::InvalidField { .. }),
            "{label}: expected InvalidField, got {err:?}"
        );
    }

    // 2. Authority enforces directory ceilings for OCI default store, custom store, and VM paths.
    let ceiling_cases: &[(&str, &str, &str)] = &[
        (
            "oci default store missing read",
            r#"
runner = "oci"
[oci]
image = "alpine:3.20"
[capabilities]
directories = [{ source = "/data", guest = "/data", rights = ["read"] }]
"#,
            "oci.store",
        ),
        (
            "oci explicit store missing read",
            r#"
runner = "oci"
[oci]
image = "alpine:3.20"
store = "/srv/oci"
[capabilities]
directories = [{ source = "/var/lib/oci", guest = "/var/lib/oci", rights = ["read"] }]
"#,
            "oci.store",
        ),
        (
            "vm kernel missing read",
            r#"
runner = "vm"
[vm]
kernel = "/boot/Image"
[capabilities]
machine = ["virtualize"]
"#,
            "vm.kernel",
        ),
        (
            "vm initramfs missing read",
            r#"
runner = "vm"
[vm]
kernel = "/boot/Image"
initramfs = "/images/initrd"
[capabilities]
machine = ["virtualize"]
directories = [{ source = "/boot", guest = "/boot", rights = ["read"] }]
"#,
            "vm.initramfs",
        ),
        (
            "vm disk requires read+write",
            r#"
runner = "vm"
[vm]
kernel = "/boot/Image"
disk = "/vm/disk.raw"
[capabilities]
machine = ["virtualize"]
directories = [
  { source = "/boot", guest = "/boot", rights = ["read"] },
  { source = "/vm", guest = "/vm", rights = ["read"] },
]
"#,
            "vm.disk",
        ),
        (
            "vm rootfs_dir requires read+write",
            r#"
runner = "vm"
[vm]
kernel = "/boot/Image"
rootfs_dir = "/vm/rootfs"
[capabilities]
machine = ["virtualize"]
directories = [
  { source = "/boot", guest = "/boot", rights = ["read"] },
  { source = "/vm", guest = "/vm", rights = ["read"] },
]
"#,
            "vm.rootfs_dir",
        ),
        (
            "vm share_dirs requires read+write",
            r#"
runner = "vm"
[vm]
kernel = "/boot/Image"
share_dirs = ["data:/srv/data"]
[capabilities]
machine = ["virtualize"]
directories = [
  { source = "/boot", guest = "/boot", rights = ["read"] },
  { source = "/srv/data", guest = "/srv/data", rights = ["read"] },
]
"#,
            "vm.share_dirs",
        ),
    ];

    for (label, manifest, expected_dim) in ceiling_cases {
        let err = load_tree_from_map(tree(&[("/", &root_manifest_full()), ("/app", manifest)]))
            .expect_err(&format!("{label} must fail directory ceiling validation"));
        assert!(
            matches!(
                err,
                ManifestError::Validation(ValidationError::CapabilityEscalation { dimension, .. })
                if dimension == *expected_dim
            ),
            "{label}: expected CapabilityEscalation({expected_dim}), got {err:?}"
        );
    }

    // 3. OCI rejects elevated oom_tier and named_devices, and accepts valid ceilings.
    let oci_elevated_oom = r#"
runner = "oci"
oom_tier = "plugin"
[oci]
image = "alpine:3.20"
[capabilities]
directories = [{ source = "/var/lib/oci", guest = "/var/lib/oci", rights = ["read"] }]
"#;
    assert!(matches!(
        load_tree_from_map(tree(&[
            ("/", &root_manifest_full()),
            ("/app", oci_elevated_oom)
        ])),
        Err(ManifestError::Validation(
            ValidationError::InvalidRunnerConfig { .. }
        ))
    ));

    let oci_named_devices = r#"
runner = "oci"
[oci]
image = "alpine:3.20"
[capabilities]
directories = [{ source = "/var/lib/oci", guest = "/var/lib/oci", rights = ["read"] }]
named_devices = ["pci:00:01.0"]
"#;
    assert!(matches!(
        load_tree_from_map(tree(&[
            ("/", &root_manifest_full()),
            ("/app", oci_named_devices)
        ])),
        Err(ManifestError::Validation(
            ValidationError::InvalidRunnerConfig { .. }
        ))
    ));

    let valid_vm = r#"
runner = "vm"
[vm]
kernel = "/boot/Image"
initramfs = "/boot/initrd"
disk = "/vm/disk.raw"
rootfs_dir = "/vm/rootfs"
share_dirs = ["work:/srv/work"]
[capabilities]
machine = ["virtualize"]
directories = [
  { source = "/boot", guest = "/boot", rights = ["read"] },
  { source = "/vm", guest = "/vm", rights = ["read", "write"] },
  { source = "/srv/work", guest = "/srv/work", rights = ["read", "write"] },
]
"#;
    load_tree_from_map(tree(&[("/", &root_manifest_full()), ("/vm", valid_vm)]))
        .expect("valid VM runner with covered paths must succeed");

    // 4. Statically constructed topologies are also checked for `..` in authority::validate_topology.
    let mut root_node = make_node("/", None, RunnerSpec::Realm);
    root_node.children_indices = Cow::Borrowed(&[1]);
    root_node.oom_tier = OomTier::Protected;
    root_node.capabilities.directories = Cow::Owned(vec![DirectoryGrantSpec {
        source: Cow::Borrowed("/"),
        guest: Cow::Borrowed("/"),
        rights: FsRights::ALL,
    }]);
    root_node.capabilities.machine = MachineRights::VIRTUALIZE;

    let mut static_bad_vm = make_node(
        "/vm",
        Some(0),
        RunnerSpec::Vm(VmRunnerSpec {
            kernel: Cow::Borrowed("/boot/Image"),
            initramfs: None,
            disk: None,
            memory_mib: 64,
            cpus: 1,
            cmdline: None,
            rootfs_dir: None,
            share_dirs: Cow::Owned(vec![VmShareSpec {
                tag: Cow::Borrowed("escape"),
                host_path: Cow::Borrowed("/srv/../etc"),
            }]),
        }),
    );
    static_bad_vm.capabilities.machine = MachineRights::VIRTUALIZE;
    static_bad_vm.capabilities.directories = Cow::Owned(vec![DirectoryGrantSpec {
        source: Cow::Borrowed("/"),
        guest: Cow::Borrowed("/"),
        rights: FsRights::ALL,
    }]);
    assert!(matches!(
        validate_topology(&ComponentTopology {
            nodes: Cow::Owned(vec![root_node.clone(), static_bad_vm]),
        }),
        Err(ValidationError::InvalidRunnerConfig { .. })
    ));

    let mut static_bad_oci = make_node(
        "/oci",
        Some(0),
        RunnerSpec::Oci(OciRunnerSpec {
            image: Some(Cow::Borrowed("alpine:3.20")),
            rootfs: None,
            store: Some(Cow::Borrowed("/var/lib/oci/../../etc")),
            hostname: Cow::Borrowed("oci"),
            uid: 0,
            gid: 0,
            entrypoint: Cow::Borrowed(&[]),
            cmd: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            mounts: Cow::Borrowed(&[]),
        }),
    );
    static_bad_oci.capabilities.directories = Cow::Owned(vec![DirectoryGrantSpec {
        source: Cow::Borrowed("/"),
        guest: Cow::Borrowed("/"),
        rights: FsRights::ALL,
    }]);
    assert!(matches!(
        validate_topology(&ComponentTopology {
            nodes: Cow::Owned(vec![root_node, static_bad_oci]),
        }),
        Err(ValidationError::InvalidRunnerConfig { .. })
    ));
}

#[test]
fn validate_dynamic_subtree_forbids_system_criticality_root_parent_criticality_and_providers() {
    let mut parent = make_node("/sandbox", Some(0), RunnerSpec::Realm);
    parent.dynamic_mount = true;
    parent.oom_tier = OomTier::Plugin;
    parent.capabilities.directories = Cow::Owned(vec![DirectoryGrantSpec {
        source: Cow::Borrowed("/"),
        guest: Cow::Borrowed("/"),
        rights: FsRights::ALL,
    }]);
    parent.capabilities.named_devices = NameCeiling::EMPTY;

    let wasm_spec = || {
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/app"),
            sharding: WasmSharding::Singleton,
            provider: None,
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        })
    };

    // 1. `critical = "system"` denied in dynamic subtree.
    let mut sys_node = make_node("/sandbox/sys", None, wasm_spec());
    sys_node.critical = Criticality::System;
    assert!(matches!(
        validate_dynamic_subtree(
            &parent,
            &ComponentTopology {
                nodes: Cow::Owned(vec![sys_node]),
            },
        ),
        Err(ValidationError::DynamicCriticalityDenied {
            setting: "critical = \"system\"",
            ..
        })
    ));

    // 2. `escalation = "reboot"` denied in dynamic subtree.
    let mut reboot_node = make_node("/sandbox/reboot", None, wasm_spec());
    reboot_node.escalation = EscalationAction::Reboot;
    assert!(matches!(
        validate_dynamic_subtree(
            &parent,
            &ComponentTopology {
                nodes: Cow::Owned(vec![reboot_node]),
            },
        ),
        Err(ValidationError::DynamicCriticalityDenied {
            setting: "escalation = \"reboot\"",
            ..
        })
    ));

    // 3. `critical = "parent"` denied on dynamic subtree root.
    let mut root_parent_crit = make_node("/sandbox/app", None, wasm_spec());
    root_parent_crit.critical = Criticality::Parent;
    assert!(matches!(
        validate_dynamic_subtree(
            &parent,
            &ComponentTopology {
                nodes: Cow::Owned(vec![root_parent_crit]),
            },
        ),
        Err(ValidationError::DynamicCriticalityDenied {
            setting: "critical = \"parent\"",
            ..
        })
    ));

    // 4. `critical = "parent"` ALLOWED on a descendant whose parent is inside the dynamic subtree.
    let mut dyn_realm = make_node("/sandbox/app", None, RunnerSpec::Realm);
    dyn_realm.children_indices = Cow::Borrowed(&[1]);
    let mut dyn_child = make_node("/sandbox/app/worker", Some(0), wasm_spec());
    dyn_child.critical = Criticality::Parent;
    validate_dynamic_subtree(
        &parent,
        &ComponentTopology {
            nodes: Cow::Owned(vec![dyn_realm.clone(), dyn_child]),
        },
    )
    .expect("descendant critical=parent inside dynamic realm must be allowed");

    // 5. Kernel provider slots forbidden in dynamic subtree (root or descendant).
    let provider_child = make_node(
        "/sandbox/app/http",
        Some(0),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/http-client"),
            sharding: WasmSharding::PerProcessor,
            provider: Some(ProviderSlot::HttpClient),
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    assert!(matches!(
        validate_dynamic_subtree(
            &parent,
            &ComponentTopology {
                nodes: Cow::Owned(vec![dyn_realm, provider_child]),
            },
        ),
        Err(ValidationError::DynamicProviderDenied {
            slot: "http-client",
            ..
        })
    ));
}

fn make_node(
    moniker: &'static str,
    parent_index: Option<usize>,
    runner: RunnerSpec,
) -> ComponentNode {
    ComponentNode {
        moniker: Cow::Borrowed(moniker),
        instance_name: Cow::Borrowed(moniker.trim_start_matches('/')),
        parent_index,
        children_indices: Cow::Borrowed(&[]),
        runner,
        startup: StartupPolicy::Lazy,
        lifecycle: LifecycleKind::Service,
        requires: HardwarePredicates::NONE,
        after: Cow::Borrowed(&[]),
        mounts: Cow::Borrowed(&[]),
        restart: RestartPolicy::Never,
        restart_backoff_ms: 100,
        restart_backoff_max_ms: 500,
        burst_limit: 3,
        burst_window_ms: 10_000,
        stop_timeout_ms: 200,
        critical: Criticality::None,
        escalation: EscalationAction::Halt,
        oom_tier: OomTier::User,
        dynamic_mount: false,
        capabilities: CapabilityCeiling::EMPTY,
        exposes: Cow::Borrowed(&[]),
        routes: Cow::Borrowed(&[]),
        sockets: Cow::Borrowed(&[]),
    }
}
