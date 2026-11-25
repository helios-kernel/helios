use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=HELIOS_COMPONENT_TOPOLOGY_RS");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let dest = out_dir.join("generated_topology.rs");

    let source = match env::var_os("HELIOS_COMPONENT_TOPOLOGY_RS") {
        Some(path) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            path
        }
        None => {
            let manifest_dir = PathBuf::from(
                env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
            );
            let default_path = manifest_dir.join("src/default_topology.rs");
            println!("cargo:rerun-if-changed={}", default_path.display());
            default_path
        }
    };

    let bytes = fs::read(&source).unwrap_or_else(|error| {
        panic!(
            "failed to read generated component topology `{}`: {error}",
            source.display()
        )
    });
    fs::write(&dest, bytes)
        .unwrap_or_else(|error| panic!("failed to write `{}`: {error}", dest.display()));
}
