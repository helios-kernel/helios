//! Writing the guest's instruction-address samples as a folded profile,
//! delegating ELF/DWARF symbolization to `helios_ops::symbolize`.

use std::path::{Path, PathBuf};

use helios_ops::symbolize::{KernelImageSymbolizer, KernelSymbolsError};
use helios_wit_rpc::inspector::helios::system::profiling::{
    self as system_profiling, InstructionProfile, InstructionProfileError, SamplingSession,
};

use crate::serial::RpcClient;

/// Why the instruction profile a run asked for was not written.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InstructionProfileOutputError {
    #[error(
        "failed to {} the guest's instruction sampling: {source}",
        if *.enabled { "start" } else { "stop" }
    )]
    Control {
        enabled: bool,
        #[source]
        source: helios_wit_rpc::RpcError,
    },
    #[error("failed to read the guest's instruction samples: {source}")]
    Read {
        #[source]
        source: helios_wit_rpc::RpcError,
    },
    #[error("the guest kernel cannot produce an instruction profile: {}", refusal_reason(*.refusal))]
    Refused { refusal: InstructionProfileError },
    #[error("cannot name the kernel addresses of the instruction profile: {source}")]
    Symbols {
        #[source]
        source: KernelSymbolsError,
    },
    #[error("failed to write {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to report the written instruction profile: {source}")]
    Report {
        #[source]
        source: std::io::Error,
    },
}

fn refusal_reason(refusal: InstructionProfileError) -> &'static str {
    match refusal {
        InstructionProfileError::NotCaptured => {
            "this architecture's backend does not sample instruction addresses (only x86-64 does)"
        }
        InstructionProfileError::Denied => {
            "the session does not hold the required diagnostic capability"
        }
        InstructionProfileError::Busy => "another instruction-sampling session is already active",
    }
}

/// Starts the guest's instruction sampling for the workload that follows.
pub(crate) async fn start(
    client: &RpcClient,
) -> Result<SamplingSession, InstructionProfileOutputError> {
    system_profiling::RpcClient::new(client.peer())
        .start_instruction_sampling()
        .await
        .map_err(|source| InstructionProfileOutputError::Control {
            enabled: true,
            source,
        })?
        .map_err(|refusal| InstructionProfileOutputError::Refused { refusal })
}

/// Reads the guest's instruction samples and writes them to `output`, naming
/// native addresses against the kernel ELF/DWARF image at `kernel`.
pub(crate) async fn collect(
    client: &RpcClient,
    kernel: &Path,
    output: &Path,
) -> Result<(), InstructionProfileOutputError> {
    let profile = system_profiling::RpcClient::new(client.peer())
        .instruction_samples()
        .await
        .map_err(|source| InstructionProfileOutputError::Read { source })?
        .map_err(|refusal| InstructionProfileOutputError::Refused { refusal })?;
    let kernel = kernel.to_path_buf();
    let output = output.to_path_buf();
    blocking::unblock(move || write(&profile, &kernel, &output)).await
}

fn write(
    profile: &InstructionProfile,
    kernel: &Path,
    output: &PathBuf,
) -> Result<(), InstructionProfileOutputError> {
    use std::io::Write as _;

    let symbols = |source| InstructionProfileOutputError::Symbols { source };
    let symbolizer = KernelImageSymbolizer::from_path(kernel).map_err(symbols)?;
    let folded = symbolizer.render_folded(profile).map_err(symbols)?;
    std::fs::write(output, folded).map_err(|source| InstructionProfileOutputError::Write {
        path: output.display().to_string(),
        source,
    })?;
    let samples = profile
        .samples
        .iter()
        .map(|sample| sample.count)
        .sum::<u64>();
    let mut stderr = std::io::stderr().lock();
    writeln!(
        stderr,
        "instruction_profile_output={} samples={samples} dropped={} period_ns={}",
        output.display(),
        profile.dropped,
        profile.period_nanos,
    )
    .map_err(|source| InstructionProfileOutputError::Report { source })
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use gimli::write::{Address, AttributeValue, DwarfUnit, EndianVec, Sections, UnitEntryId};
    use gimli::{Encoding, Format, LittleEndian, RunTimeEndian};
    use helios_ops::symbolize::{
        KernelImageSymbolizer, render_folded_samples, symbolize_with_parts,
    };
    use helios_wit_rpc::inspector::helios::system::profiling::{
        InstructionProfile, InstructionSample, SampledCode, WasmFunction,
    };

    use crate::vm::kernel_image::{DwarfReader, Function, KernelDebugInfo, KernelSymbols};

    const PARK: u64 = 0xffff_ffff_8000_1000;

    fn function(
        dwarf: &mut DwarfUnit,
        parent: UnitEntryId,
        linkage_name: Option<&str>,
        name: &str,
    ) -> UnitEntryId {
        let id = dwarf.unit.add(parent, gimli::DW_TAG_subprogram);
        let entry = dwarf.unit.get_mut(id);
        if let Some(linkage_name) = linkage_name {
            entry.set(
                gimli::DW_AT_linkage_name,
                AttributeValue::String(linkage_name.as_bytes().to_vec()),
            );
        }
        entry.set(
            gimli::DW_AT_name,
            AttributeValue::String(name.as_bytes().to_vec()),
        );
        id
    }

    fn code_range(dwarf: &mut DwarfUnit, id: UnitEntryId, start: u64, length: u64) {
        let entry = dwarf.unit.get_mut(id);
        entry.set(
            gimli::DW_AT_low_pc,
            AttributeValue::Address(Address::Constant(start)),
        );
        entry.set(gimli::DW_AT_high_pc, AttributeValue::Udata(length));
    }

    fn inlined(
        dwarf: &mut DwarfUnit,
        parent: UnitEntryId,
        origin: UnitEntryId,
        start: u64,
        length: u64,
    ) -> UnitEntryId {
        let id = dwarf.unit.add(parent, gimli::DW_TAG_inlined_subroutine);
        dwarf.unit.get_mut(id).set(
            gimli::DW_AT_abstract_origin,
            AttributeValue::UnitRef(origin),
        );
        code_range(dwarf, id, start, length);
        id
    }

    fn debug_info() -> KernelDebugInfo {
        let mut dwarf = DwarfUnit::new(Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        });
        let root = dwarf.unit.root();
        dwarf.unit.get_mut(root).set(
            gimli::DW_AT_language,
            AttributeValue::Language(gimli::DW_LANG_Rust),
        );
        code_range(&mut dwarf, root, PARK, 0x100);
        let wait = function(
            &mut dwarf,
            root,
            Some("_RNvNtCs1234_13helios_kernel4exec4wait"),
            "wait",
        );
        let relax = function(&mut dwarf, root, None, "relax");
        let park = function(
            &mut dwarf,
            root,
            Some("_RNvNtCs1234_13helios_kernel4exec4park"),
            "park",
        );
        code_range(&mut dwarf, park, PARK, 0x100);
        let waiting = inlined(&mut dwarf, park, wait, PARK, 0x8);
        inlined(&mut dwarf, waiting, relax, PARK + 0x4, 0x2);
        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf
            .write(&mut sections)
            .expect("the test DWARF is well formed");
        let dwarf = gimli::Dwarf::load(|section| {
            let bytes: Arc<[u8]> = match sections.get(section) {
                Some(data) => Arc::from(data.slice()),
                None => Arc::from([]),
            };
            Ok::<_, gimli::Error>(DwarfReader::new(bytes, RunTimeEndian::Little))
        })
        .expect("loading in-memory sections cannot fail");
        KernelDebugInfo::from_dwarf(Path::new("test-kernel"), dwarf).expect("the test DWARF parses")
    }

    #[test]
    fn samples_fold_into_wasm_frames_kernel_inline_chains_and_unknown() {
        let text = PARK..0xffff_ffff_8000_2000;
        let symbols = KernelSymbols::new(
            0xffff_ffff_8000_0000,
            vec![text],
            vec![
                Function {
                    name: "_RNvNtCs1234_13helios_kernel4exec4park".to_owned(),
                    address: PARK,
                    size: 0x100,
                },
                Function {
                    name: "rdtsc_now".to_owned(),
                    address: 0xffff_ffff_8000_1100,
                    size: 0x10,
                },
            ],
        );
        let debug = debug_info();
        let function = |name: Option<&str>, index| {
            SampledCode::Wasm(WasmFunction {
                module: "python3;bad".to_owned(),
                static_module: 1,
                index,
                name: name.map(str::to_owned),
            })
        };
        let profile = InstructionProfile {
            period_nanos: 1_000_000,
            kernel_image_base: 0xffff_ffff_8120_0000,
            samples: vec![
                InstructionSample {
                    code: function(Some("_PyEval_EvalFrameDefault"), 7),
                    count: 40,
                },
                InstructionSample {
                    code: SampledCode::Native(0xffff_ffff_8120_1004),
                    count: 12,
                },
                InstructionSample {
                    code: SampledCode::Native(0xffff_ffff_8120_1005),
                    count: 4,
                },
                InstructionSample {
                    code: SampledCode::Native(0xffff_ffff_8120_1006),
                    count: 6,
                },
                InstructionSample {
                    code: SampledCode::Native(0xffff_ffff_8120_1008),
                    count: 3,
                },
                InstructionSample {
                    code: SampledCode::Native(0xffff_ffff_8120_1104),
                    count: 5,
                },
                InstructionSample {
                    code: SampledCode::Native(0xffff_ffff_8120_1800),
                    count: 1,
                },
                InstructionSample {
                    code: function(None, 9),
                    count: 2,
                },
                InstructionSample {
                    code: SampledCode::WasmTrampoline("python3;bad".to_owned()),
                    count: 2,
                },
                InstructionSample {
                    code: SampledCode::Native(0x4000),
                    count: 1,
                },
            ],
            dropped: 0,
        };

        let symbolized = symbolize_with_parts(
            &profile,
            symbols.loaded_at(profile.kernel_image_base),
            Some(&debug),
        )
        .expect("every address resolves against the test DWARF");
        let folded = render_folded_samples(&symbolized.samples);
        let via_symbolizer = KernelImageSymbolizer::from_parts(symbols, Some(debug))
            .render_folded(&profile)
            .expect("symbolizer renders identically");
        assert_eq!(folded, via_symbolizer);

        assert_eq!(
            folded,
            "wasm;python3_bad;_PyEval_EvalFrameDefault 40\n\
             kernel;helios_kernel::exec::park;helios_kernel::exec::wait;relax 16\n\
             kernel;helios_kernel::exec::park;helios_kernel::exec::wait 6\n\
             kernel;rdtsc_now 5\n\
             kernel;helios_kernel::exec::park 3\n\
             wasm;python3_bad;[trampoline] 2\n\
             wasm;python3_bad;func[1:9] 2\n\
             kernel;[unsymbolized] 1\n\
             unknown 1\n"
        );
    }
}
