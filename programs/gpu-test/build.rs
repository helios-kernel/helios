use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo::rerun-if-changed=src/compute.wgsl");
    let module = naga::front::wgsl::parse_str(include_str!("src/compute.wgsl"))
        .expect("compute smoke WGSL must parse");
    let info = naga::valid::Validator::new(
        naga::valid::ValidationFlags::all(),
        naga::valid::Capabilities::empty(),
    )
    .validate(&module)
    .expect("compute smoke WGSL must validate");
    let pipeline = naga::back::spv::PipelineOptions {
        shader_stage: naga::ShaderStage::Compute,
        entry_point: "main".into(),
    };
    let words = naga::back::spv::write_vec(
        &module,
        &info,
        &naga::back::spv::Options::default(),
        Some(&pipeline),
    )
    .expect("compute smoke SPIR-V must encode");
    let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    fs::write(output.join("compute.spv"), bytes).expect("compute smoke SPIR-V must be written");
}
