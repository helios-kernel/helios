use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use askama::Template;
use helios_component_manager::{
    AuthorityScopeSpec, COMPONENT_MANIFEST_FILE, CapabilityCeiling, MachineRights, NameCeiling,
    OomTier, PortCeiling, load_tree_from_dir, verify_monotonic_ceiling,
};

struct RustStrLit<'a>(&'a str);

impl fmt::Display for RustStrLit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.0, f)
    }
}

#[derive(Template)]
#[template(path = "inspector_ceilings.rs.askama", escape = "none")]
struct InspectorCeilingsTemplate<'a> {
    tls_oom_tier: OomTier,
    tls_ceiling: &'a CapabilityCeiling,
    worker_oom_tier: OomTier,
    worker_ceiling: &'a CapabilityCeiling,
}

impl InspectorCeilingsTemplate<'_> {
    const fn str_lit(s: &str) -> RustStrLit<'_> {
        RustStrLit(s)
    }
}

fn emit_rerun_tree(dir: &Path) {
    println!("cargo:rerun-if-changed={}", dir.display());
    let manifest = dir.join(COMPONENT_MANIFEST_FILE);
    if manifest.is_file() {
        println!("cargo:rerun-if-changed={}", manifest.display());
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut subdirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_dir()
                && !path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with('.'))
        })
        .collect();
    subdirs.sort();
    for subdir in subdirs {
        emit_rerun_tree(&subdir);
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=HELIOS_INSPECTOR_COMPONENTS_DIR");
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    );
    let components_dir = match env::var_os("HELIOS_INSPECTOR_COMPONENTS_DIR") {
        Some(dir) => {
            let path = PathBuf::from(dir);
            if path.is_absolute() {
                path
            } else {
                manifest_dir.join(path)
            }
        }
        None => manifest_dir.join("../../components"),
    };
    let components_dir = fs::canonicalize(&components_dir).unwrap_or_else(|err| {
        panic!(
            "failed to locate inspector components directory `{}`: {err}",
            components_dir.display()
        )
    });
    emit_rerun_tree(&components_dir);

    let topology = load_tree_from_dir(&components_dir).unwrap_or_else(|err| {
        panic!(
            "failed to load and validate component topology `{}`: {err}",
            components_dir.display()
        )
    });

    let inspector_idx = topology
        .find_by_moniker("/inspector")
        .expect("components topology must define `/inspector`");
    let tls_idx = topology
        .find_by_moniker("/inspector/tls")
        .expect("components topology must define `/inspector/tls`");
    let worker_idx = topology
        .find_by_moniker("/inspector/worker")
        .expect("components topology must define `/inspector/worker`");

    let inspector = &topology.nodes[inspector_idx];
    let tls = &topology.nodes[tls_idx];
    let worker = &topology.nodes[worker_idx];

    for child in [tls, worker] {
        assert_eq!(
            child.parent_index,
            Some(inspector_idx),
            "`{}` must be a direct child of `/inspector`",
            child.moniker
        );
        verify_monotonic_ceiling(
            inspector.moniker.as_ref(),
            &inspector.capabilities,
            child.moniker.as_ref(),
            &child.capabilities,
        )
        .unwrap_or_else(|err| {
            panic!(
                "inspector child `{}` violates ceiling: {err}",
                child.moniker
            )
        });
        assert!(
            inspector.oom_tier.admits(child.oom_tier),
            "`{}` oom_tier `{}` exceeds `/inspector` tier `{}`",
            child.moniker,
            child.oom_tier.as_str(),
            inspector.oom_tier.as_str()
        );
        assert_eq!(
            child.oom_tier,
            OomTier::User,
            "`{}` must declare `oom_tier = \"user\"` (spawned via `helios:system/programs`)",
            child.moniker
        );
        assert!(
            !child.capabilities.machine.contains(MachineRights::IDENTITY),
            "`{}` must never hold `machine.identity` authority",
            child.moniker
        );
    }

    let rendered = InspectorCeilingsTemplate {
        tls_oom_tier: tls.oom_tier,
        tls_ceiling: &tls.capabilities,
        worker_oom_tier: worker.oom_tier,
        worker_ceiling: &worker.capabilities,
    }
    .render()
    .expect("render inspector_ceilings.rs.askama");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let dest = out_dir.join("inspector_ceilings.rs");
    fs::write(&dest, rendered)
        .unwrap_or_else(|err| panic!("failed to write `{}`: {err}", dest.display()));
}
