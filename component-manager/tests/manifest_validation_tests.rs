#![cfg(feature = "manifest")]

use std::collections::BTreeMap;

use helios_component_manager::{
    ManifestError, ValidationError, load_tree_from_dir, load_tree_from_map,
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
