//! ELF/DWARF kernel symbolization and instruction-profile rendering.
//!
//! Shared between `helios-ops` (SDK callers, `helios profile instructions`, and
//! `helios-ops-py`) and `helios-inspector` (`vm` vCPU state capture, x86 image
//! audits, and instruction profile collection).

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use askama::Template as _;
use gimli::{EndianArcSlice, RunTimeEndian};
use helios_wit_rpc::inspector::helios::system::profiling::{InstructionProfile, SampledCode};
use object::elf::PF_X;
use object::{
    Object as _, ObjectSection as _, ObjectSegment as _, ObjectSymbol as _, SegmentFlags,
    SymbolKind,
};
use serde::{Deserialize, Serialize};

/// One function the image defines, as its symbol table records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionSymbol<'data> {
    pub name: &'data str,
    /// The link-time virtual address of the function's first byte.
    pub address: u64,
    pub size: u64,
}

/// Every defined `STT_FUNC` symbol of `image`.
pub fn function_symbols<'data, 'file>(
    image: &'file object::File<'data>,
) -> impl Iterator<Item = Result<FunctionSymbol<'data>, object::Error>> + 'file {
    image
        .symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::Text && !symbol.is_undefined())
        .map(|symbol| {
            Ok(FunctionSymbol {
                name: symbol.name()?,
                address: symbol.address(),
                size: symbol.size(),
            })
        })
}

/// Read the bytes of the kernel ELF image at `path`.
pub fn read_image(path: &Path) -> Result<Vec<u8>, KernelSymbolsError> {
    std::fs::read(path).map_err(|source| KernelSymbolsError::Read {
        path: path.display().to_string(),
        source,
    })
}

/// Parse `bytes`, read from `path`, as an object file.
pub fn parse_image<'data>(
    path: &Path,
    bytes: &'data [u8],
) -> Result<object::File<'data>, KernelSymbolsError> {
    object::File::parse(bytes).map_err(|source| KernelSymbolsError::Symbols {
        path: path.display().to_string(),
        source,
    })
}

/// Why a kernel ELF image could not be turned into a symbol table or DWARF index.
#[derive(Debug, thiserror::Error)]
pub enum KernelSymbolsError {
    #[error("failed to read kernel image {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read the symbols of kernel image {path}: {source}")]
    Symbols {
        path: String,
        #[source]
        source: object::Error,
    },
    #[error("kernel image {path} has no loadable segment to take its link base from")]
    NoLoadSegment { path: String },
    #[error("kernel image {path} has no executable loadable segment")]
    NoExecutableSegment { path: String },
    #[error("kernel image {path} has a segment carrying {flags:?} rather than ELF flags")]
    NotElfSegment { path: String, flags: SegmentFlags },
    #[error(
        "kernel image {path} has an executable segment of {size:#x} bytes at {address:#x}, \
         which runs past the end of the address space"
    )]
    SegmentOverflow {
        path: String,
        address: u64,
        size: u64,
    },
    #[error(
        "kernel image {path} carries no DWARF (.debug_info), so its addresses cannot be \
         expanded into inline chains; build it with `helios vm` and one of \
         --release, --profile-generate, --profile-use or --kernel-debug, which keep debuginfo"
    )]
    NoDebugInfo { path: String },
    #[error("failed to read DWARF section {section} of kernel image {path}: {source}")]
    DebugSection {
        path: String,
        section: &'static str,
        #[source]
        source: object::Error,
    },
    #[error("failed to parse the DWARF of kernel image {path}: {source}")]
    Dwarf {
        path: String,
        #[source]
        source: gimli::Error,
    },
}

/// A function of the image, owned so the table outlives the file bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub address: u64,
    pub size: u64,
}

/// The image's functions, ordered by address, the address the image was
/// linked to start at, and the link-time ranges of its executable segments.
#[derive(Debug)]
pub struct KernelSymbols {
    link_base: u64,
    text: Vec<Range<u64>>,
    functions: Vec<Function>,
}

impl KernelSymbols {
    /// Reads the function symbols and the link base out of the ELF at `path`.
    pub fn read(path: &Path) -> Result<Self, KernelSymbolsError> {
        let bytes = read_image(path)?;
        Self::from_image(path, &parse_image(path, &bytes)?)
    }

    /// The function symbols and the link base of an already parsed image.
    pub fn from_image(path: &Path, image: &object::File<'_>) -> Result<Self, KernelSymbolsError> {
        let display = || path.display().to_string();
        let symbols = |source| KernelSymbolsError::Symbols {
            path: display(),
            source,
        };
        let link_base = image
            .segments()
            .map(|segment| segment.address())
            .min()
            .ok_or_else(|| KernelSymbolsError::NoLoadSegment { path: display() })?;
        let mut text = Vec::new();
        for segment in image.segments() {
            let executable = match segment.flags() {
                SegmentFlags::Elf { p_flags } => p_flags & PF_X != 0,
                flags => {
                    return Err(KernelSymbolsError::NotElfSegment {
                        path: display(),
                        flags,
                    });
                }
            };
            if executable {
                let (address, size) = (segment.address(), segment.size());
                let end = address.checked_add(size).ok_or_else(|| {
                    KernelSymbolsError::SegmentOverflow {
                        path: display(),
                        address,
                        size,
                    }
                })?;
                text.push(address..end);
            }
        }
        if text.is_empty() {
            return Err(KernelSymbolsError::NoExecutableSegment { path: display() });
        }
        let functions = function_symbols(image)
            .map(|symbol| {
                symbol.map(|symbol| Function {
                    name: symbol.name.to_owned(),
                    address: symbol.address,
                    size: symbol.size,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(symbols)?;
        Ok(Self::new(link_base, text, functions))
    }

    /// A table from its parts, all at link-time addresses.
    #[must_use]
    pub fn new(link_base: u64, text: Vec<Range<u64>>, mut functions: Vec<Function>) -> Self {
        functions.retain(|function| function.size != 0);
        functions.sort_by_key(|function| function.address);
        Self {
            link_base,
            text,
            functions,
        }
    }

    /// The table at the addresses the image was linked to.
    #[must_use]
    pub const fn linked(&self) -> LoadedKernelSymbols<'_> {
        self.loaded_at(self.link_base)
    }

    /// The table as seen from a kernel the bootloader placed at `virtual_base`.
    #[must_use]
    pub const fn loaded_at(&self, virtual_base: u64) -> LoadedKernelSymbols<'_> {
        LoadedKernelSymbols {
            symbols: self,
            slide: virtual_base.wrapping_sub(self.link_base),
        }
    }
}

/// A symbol table shifted by the distance between where the image was
/// linked and where it runs.
#[derive(Debug, Clone, Copy)]
pub struct LoadedKernelSymbols<'table> {
    symbols: &'table KernelSymbols,
    slide: u64,
}

/// A runtime address named by the function containing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolizedAddress {
    /// The demangled name, without the crate hash.
    pub function: String,
    pub offset: u64,
}

impl core::fmt::Display for SymbolizedAddress {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}+{:#x}", self.function, self.offset)
    }
}

impl LoadedKernelSymbols<'_> {
    /// The link-time address the runtime address `address` corresponds to.
    #[must_use]
    pub const fn link_address(&self, address: u64) -> u64 {
        address.wrapping_sub(self.slide)
    }

    /// The signed slide (`virtual_base - link_base`, wrapping).
    #[must_use]
    pub const fn slide(&self) -> u64 {
        self.slide
    }

    /// Whether the runtime address `address` lies in one of the image's executable segments.
    #[must_use]
    pub fn contains_text(&self, address: u64) -> bool {
        let link_address = self.link_address(address);
        self.symbols
            .text
            .iter()
            .any(|segment| segment.contains(&link_address))
    }

    /// The function whose bytes contain the runtime address `address`.
    #[must_use]
    pub fn symbolize(&self, address: u64) -> Option<SymbolizedAddress> {
        let link_address = self.link_address(address);
        let functions = &self.symbols.functions;
        let after = functions.partition_point(|function| function.address <= link_address);
        let function = functions[..after].last()?;
        let offset = link_address - function.address;
        (offset < function.size).then(|| SymbolizedAddress {
            function: format!("{:#}", rustc_demangle::demangle(&function.name)),
            offset,
        })
    }
}

/// The reader the kernel's DWARF is parsed through.
pub type DwarfReader = EndianArcSlice<RunTimeEndian>;

/// The kernel image's DWARF, indexed for the inline chain at an address.
pub struct KernelDebugInfo {
    path: String,
    context: addr2line::Context<DwarfReader>,
}

impl KernelDebugInfo {
    /// The DWARF of an already parsed image; `path` names it in errors.
    pub fn from_image(path: &Path, image: &object::File<'_>) -> Result<Self, KernelSymbolsError> {
        let display = || path.display().to_string();
        if image.section_by_name(".debug_info").is_none() {
            return Err(KernelSymbolsError::NoDebugInfo { path: display() });
        }
        let endian = if image.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let dwarf = gimli::Dwarf::load(|section| {
            let bytes: Arc<[u8]> = match image.section_by_name(section.name()) {
                Some(data) => Arc::from(&*data.uncompressed_data().map_err(|source| {
                    KernelSymbolsError::DebugSection {
                        path: display(),
                        section: section.name(),
                        source,
                    }
                })?),
                None => Arc::from([]),
            };
            Ok::<_, KernelSymbolsError>(DwarfReader::new(bytes, endian))
        })?;
        Self::from_dwarf(path, dwarf)
    }

    /// The table over sections already loaded.
    pub fn from_dwarf(
        path: &Path,
        dwarf: gimli::Dwarf<DwarfReader>,
    ) -> Result<Self, KernelSymbolsError> {
        let path = path.display().to_string();
        match addr2line::Context::from_dwarf(dwarf) {
            Ok(context) => Ok(Self { path, context }),
            Err(source) => Err(KernelSymbolsError::Dwarf { path, source }),
        }
    }

    /// The demangled functions executing at link-time `address`, outermost first.
    pub fn inline_chain(&self, address: u64) -> Result<Vec<String>, KernelSymbolsError> {
        let dwarf = |source| KernelSymbolsError::Dwarf {
            path: self.path.clone(),
            source,
        };
        let mut frames = self
            .context
            .find_frames(address)
            .skip_all_loads()
            .map_err(dwarf)?;
        let mut chain = Vec::new();
        while let Some(frame) = frames.next().map_err(dwarf)? {
            if frame.dw_die_offset.is_none() {
                continue;
            }
            chain.push(match frame.function {
                Some(function) => format!(
                    "{:#}",
                    rustc_demangle::demangle(&function.raw_name().map_err(dwarf)?)
                ),
                None => "[unnamed]".to_owned(),
            });
        }
        chain.reverse();
        Ok(chain)
    }
}

/// One symbolized folded stack entry from an [`InstructionProfile`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolizedSample {
    pub stack: String,
    pub count: u64,
}

/// Complete symbolized instruction profile produced against a kernel ELF image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolizedInstructionProfile {
    pub period_nanos: u64,
    pub kernel_image_base: u64,
    pub dropped: u64,
    pub total_samples: u64,
    pub samples: Vec<SymbolizedSample>,
}

/// One folded-stack line rendered by `ops/templates/folded_profile.txt`.
pub struct FoldedProfileLine {
    pub stack: String,
    pub weight: u64,
}

#[derive(askama::Template)]
#[template(path = "folded_profile.txt")]
struct FoldedProfileTemplate {
    lines: Vec<FoldedProfileLine>,
}

/// Pre-loaded ELF symbols and optional DWARF debug info for symbolizing instruction samples.
pub struct KernelImageSymbolizer {
    symbols: KernelSymbols,
    debug: Option<KernelDebugInfo>,
}

impl KernelImageSymbolizer {
    /// Load ELF symbols and DWARF debug info from `kernel_path` (requiring `.debug_info`).
    pub fn from_path(kernel_path: &Path) -> Result<Self, KernelSymbolsError> {
        let bytes = read_image(kernel_path)?;
        let image = parse_image(kernel_path, &bytes)?;
        let symbols = KernelSymbols::from_image(kernel_path, &image)?;
        let debug = KernelDebugInfo::from_image(kernel_path, &image)?;
        Ok(Self {
            symbols,
            debug: Some(debug),
        })
    }

    /// Load ELF symbols and, when `.debug_info` is present, DWARF inline chains.
    ///
    /// Unlike [`Self::from_path`], an ELF without `.debug_info` still symbolizes
    /// outer function symbols from `.symtab`.
    pub fn from_path_allow_no_dwarf(kernel_path: &Path) -> Result<Self, KernelSymbolsError> {
        let bytes = read_image(kernel_path)?;
        let image = parse_image(kernel_path, &bytes)?;
        let symbols = KernelSymbols::from_image(kernel_path, &image)?;
        let debug = match KernelDebugInfo::from_image(kernel_path, &image) {
            Ok(info) => Some(info),
            Err(KernelSymbolsError::NoDebugInfo { .. }) => None,
            Err(err) => return Err(err),
        };
        Ok(Self { symbols, debug })
    }

    /// Construct directly from pre-built symbols and optional DWARF info.
    #[must_use]
    pub const fn from_parts(symbols: KernelSymbols, debug: Option<KernelDebugInfo>) -> Self {
        Self { symbols, debug }
    }

    /// Borrow the underlying symbol table.
    #[must_use]
    pub const fn symbols(&self) -> &KernelSymbols {
        &self.symbols
    }

    /// Symbolize `profile` into sorted folded samples (heaviest first).
    pub fn symbolize_profile(
        &self,
        profile: &InstructionProfile,
    ) -> Result<SymbolizedInstructionProfile, KernelSymbolsError> {
        symbolize_with_parts(
            profile,
            self.symbols.loaded_at(profile.kernel_image_base),
            self.debug.as_ref(),
        )
    }

    /// Symbolize `profile` and render it into flamegraph folded-stack text.
    pub fn render_folded(
        &self,
        profile: &InstructionProfile,
    ) -> Result<String, KernelSymbolsError> {
        let symbolized = self.symbolize_profile(profile)?;
        Ok(render_folded_samples(&symbolized.samples))
    }
}

/// Symbolize `profile` against `symbols` (shifted to `profile.kernel_image_base`) and
/// optional `debug` info.
pub fn symbolize_with_parts(
    profile: &InstructionProfile,
    loaded: LoadedKernelSymbols<'_>,
    debug: Option<&KernelDebugInfo>,
) -> Result<SymbolizedInstructionProfile, KernelSymbolsError> {
    let mut stacks = BTreeMap::<String, u64>::new();
    let mut total_samples = 0_u64;
    for sample in &profile.samples {
        total_samples = total_samples.saturating_add(sample.count);
        *stacks
            .entry(symbolize_code(&sample.code, loaded, debug)?)
            .or_insert(0) += sample.count;
    }
    let mut samples = stacks
        .into_iter()
        .map(|(stack, count)| SymbolizedSample { stack, count })
        .collect::<Vec<_>>();
    samples.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.stack.cmp(&right.stack))
    });
    Ok(SymbolizedInstructionProfile {
        period_nanos: profile.period_nanos,
        kernel_image_base: profile.kernel_image_base,
        dropped: profile.dropped,
        total_samples,
        samples,
    })
}

/// Render already-symbolized folded stack samples using the compile-time Askama template.
#[must_use]
pub fn render_folded_samples(samples: &[SymbolizedSample]) -> String {
    let lines = samples
        .iter()
        .map(|sample| FoldedProfileLine {
            stack: sample.stack.clone(),
            weight: sample.count,
        })
        .collect();
    FoldedProfileTemplate { lines }
        .render()
        .expect("folded profile template rendering is infallible")
}

/// Symbolize an [`InstructionProfile`] against the kernel ELF at `kernel_path`
/// (offloading ELF/DWARF loading onto Tokio's blocking pool so the async executor never blocks).
pub async fn symbolize_instruction_profile(
    profile: InstructionProfile,
    kernel_path: &Path,
) -> Result<SymbolizedInstructionProfile, KernelSymbolsError> {
    let path = kernel_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let symbolizer = KernelImageSymbolizer::from_path_allow_no_dwarf(&path)?;
        symbolizer.symbolize_profile(&profile)
    })
    .await
    .expect("symbolization task panicked")
}

/// Symbolize an [`InstructionProfile`] against `kernel_path` (requiring DWARF) and render folded text.
pub async fn render_folded_instruction_profile(
    profile: InstructionProfile,
    kernel_path: &Path,
) -> Result<String, KernelSymbolsError> {
    let path = kernel_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let symbolizer = KernelImageSymbolizer::from_path(&path)?;
        symbolizer.render_folded(&profile)
    })
    .await
    .expect("symbolization task panicked")
}

fn symbolize_code(
    code: &SampledCode,
    loaded: LoadedKernelSymbols<'_>,
    debug: Option<&KernelDebugInfo>,
) -> Result<String, KernelSymbolsError> {
    Ok(match code {
        SampledCode::Wasm(function) => {
            let name = match &function.name {
                Some(name) => frame(&format!("{:#}", rustc_demangle::demangle(name))),
                None => format!("func[{}:{}]", function.static_module, function.index),
            };
            format!("wasm;{};{name}", frame(&function.module))
        }
        SampledCode::WasmTrampoline(module) => format!("wasm;{};[trampoline]", frame(module)),
        SampledCode::Native(address) if loaded.contains_text(*address) => {
            let chain = match debug {
                Some(dbg) => dbg.inline_chain(loaded.link_address(*address))?,
                None => Vec::new(),
            };
            if chain.is_empty() {
                match loaded.symbolize(*address) {
                    Some(symbol) => format!("kernel;{}", frame(&symbol.function)),
                    None => "kernel;[unsymbolized]".to_owned(),
                }
            } else {
                let frames = chain
                    .iter()
                    .map(|function| frame(function))
                    .collect::<Vec<_>>();
                format!("kernel;{}", frames.join(";"))
            }
        }
        SampledCode::Native(_) => "unknown".to_owned(),
    })
}

fn frame(name: &str) -> String {
    name.replace([';', '\n', '\r'], "_")
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use gimli::write::{Address, AttributeValue, DwarfUnit, EndianVec, Sections, UnitEntryId};
    use gimli::{Encoding, Format, LittleEndian, RunTimeEndian};
    use helios_wit_rpc::inspector::helios::system::profiling::{
        InstructionProfile, InstructionSample, SampledCode, WasmFunction,
    };

    use super::*;

    const PARK: u64 = 0xffff_ffff_8000_1000;

    fn add_function(
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

    fn set_code_range(dwarf: &mut DwarfUnit, id: UnitEntryId, start: u64, length: u64) {
        let entry = dwarf.unit.get_mut(id);
        entry.set(
            gimli::DW_AT_low_pc,
            AttributeValue::Address(Address::Constant(start)),
        );
        entry.set(gimli::DW_AT_high_pc, AttributeValue::Udata(length));
    }

    fn add_inlined(
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
        set_code_range(dwarf, id, start, length);
        id
    }

    #[test]
    fn symbolizes_instruction_profile_with_dwarf_inline_chains_and_wasm() {
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
        set_code_range(&mut dwarf, root, PARK, 0x100);
        let wait = add_function(
            &mut dwarf,
            root,
            Some("_RNvNtCs1234_13helios_kernel4exec4wait"),
            "wait",
        );
        let park = add_function(
            &mut dwarf,
            root,
            Some("_RNvNtCs1234_13helios_kernel4exec4park"),
            "park",
        );
        set_code_range(&mut dwarf, park, PARK, 0x100);
        add_inlined(&mut dwarf, park, wait, PARK, 0x8);

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).expect("write test DWARF");
        let parsed_dwarf = gimli::Dwarf::load(|section| {
            let bytes: Arc<[u8]> = match sections.get(section) {
                Some(data) => Arc::from(data.slice()),
                None => Arc::from([]),
            };
            Ok::<_, gimli::Error>(DwarfReader::new(bytes, RunTimeEndian::Little))
        })
        .expect("load DWARF");
        let debug = KernelDebugInfo::from_dwarf(Path::new("test-kernel"), parsed_dwarf)
            .expect("parse test DWARF");

        let symbols = KernelSymbols::new(
            0xffff_ffff_8000_0000,
            std::iter::once(PARK..0xffff_ffff_8000_2000).collect(),
            vec![Function {
                name: "_RNvNtCs1234_13helios_kernel4exec4park".to_owned(),
                address: PARK,
                size: 0x100,
            }],
        );
        let symbolizer = KernelImageSymbolizer::from_parts(symbols, Some(debug));
        let profile = InstructionProfile {
            period_nanos: 1_000_000,
            kernel_image_base: 0xffff_ffff_8120_0000,
            samples: vec![
                InstructionSample {
                    code: SampledCode::Native(0xffff_ffff_8120_1004),
                    count: 10,
                },
                InstructionSample {
                    code: SampledCode::Wasm(WasmFunction {
                        module: "compiler".to_owned(),
                        static_module: 0,
                        index: 3,
                        name: Some("compile_fn".to_owned()),
                    }),
                    count: 25,
                },
            ],
            dropped: 1,
        };

        let symbolized = symbolizer.symbolize_profile(&profile).expect("symbolize");
        assert_eq!(symbolized.total_samples, 35);
        assert_eq!(symbolized.dropped, 1);
        assert_eq!(symbolized.samples[0].stack, "wasm;compiler;compile_fn");
        assert_eq!(symbolized.samples[0].count, 25);
        assert_eq!(
            symbolized.samples[1].stack,
            "kernel;helios_kernel::exec::park;helios_kernel::exec::wait"
        );
        assert_eq!(symbolized.samples[1].count, 10);

        let folded = symbolizer.render_folded(&profile).expect("render folded");
        assert_eq!(
            folded,
            "wasm;compiler;compile_fn 25\n\
             kernel;helios_kernel::exec::park;helios_kernel::exec::wait 10\n"
        );
    }
}
