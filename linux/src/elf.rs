use object::Object;
use object::elf::{ET_DYN, ET_EXEC, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_TLS};
use object::read::elf::{ElfFile64, FileHeader, ProgramHeader};

use crate::abi::Abi;

/// Both ABIs' Linux page size (4 KiB on x86-64 and AArch64).
const PAGE: u64 = 4096;
/// Maximum `PT_INTERP` pathname size including NUL terminator (`PATH_MAX`,
/// Linux `fs/binfmt_elf.c` `load_elf_binary`).
const INTERP_PATH_MAX: usize = 4096;
/// `CONFIG_DEFAULT_MMAP_MIN_ADDR` (`security/min_addr.c`): keep placed `ET_DYN`
/// images above the low null-pointer guard range.
const MMAP_MIN_ADDR: u64 = 65_536;
/// Upper bound of the downward-growing initial-stack reservation below
/// `stack_top` so `ET_DYN` interpreters never collide with stack growth.
const STACK_RESERVE_MAX: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid ELF: {0}")]
    Parse(#[from] object::Error),
    #[error("not a little-endian ET_EXEC or ET_DYN image of the process's ABI")]
    UnsupportedImage,
    #[error("invalid or unsupported interpreter segment")]
    InvalidInterpreter,
    #[error("invalid load segment range, alignment or permissions")]
    InvalidSegment,
    #[error("load segments overlap at page granularity")]
    Overlap,
    #[error("entry point is not in executable file-backed bytes")]
    InvalidEntry,
}

/// Whether an ELF image uses fixed addresses (`ET_EXEC`) or is relocatable
/// (`ET_DYN`, used for PIE executables and dynamic linkers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageKind {
    Executable,
    Dynamic,
}

/// Permissions and bytes to install in an otherwise empty address space.
pub struct Segment<'a> {
    pub address: u64,
    pub memory_size: u64,
    pub bytes: &'a [u8],
    pub writable: bool,
    pub executable: bool,
}

/// Location of the ELF64 program headers in the process's mapped image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramHeaders {
    pub address: u64,
    pub count: u64,
}

/// Planned non-overlapping virtual placement for a main ELF image and its
/// optional `PT_INTERP` dynamic linker per Linux `fs/binfmt_elf.c`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    /// Load bias added to the main image's virtual addresses (`0` for `ET_EXEC`).
    pub main_bias: u64,
    /// Where `brk` starts: the page-aligned end of the main executable's
    /// highest `PT_LOAD` (`mm->start_brk`).
    pub program_break: u64,
    /// Load bias added to the interpreter's virtual addresses, when a
    /// `PT_INTERP` dynamic linker is present.
    pub interpreter_bias: Option<u64>,
    /// Auxiliary vector `AT_BASE` value: the interpreter's load address when
    /// loaded, or `0` for images without an interpreter.
    pub at_base: u64,
    /// Initial user instruction pointer: the interpreter's entry point when
    /// present, otherwise the main image's entry point.
    pub initial_pc: u64,
    /// Relocated entry point of the main executable (`AT_ENTRY`).
    pub main_entry: u64,
    /// Relocated location of the main executable's program headers (`AT_PHDR`,
    /// `AT_PHNUM`).
    pub program_headers: ProgramHeaders,
    /// Highest page-aligned end across both main image and interpreter,
    /// bounding downward initial-stack growth.
    pub image_end: u64,
}

/// Validated ELF64 executable (`ET_EXEC` or `ET_DYN`) or dynamic linker.
/// Validation completes before the caller maps any bytes; the caller owns
/// allocation failures and rolls back its address space.
pub struct Image<'a> {
    file: ElfFile64<'a>,
    kind: ImageKind,
    interpreter: Option<&'a str>,
}

impl<'a> Image<'a> {
    /// Validates `bytes` as a little-endian `ET_EXEC` or `ET_DYN` image of
    /// `abi` whose segments fit inside `user_end`, the end of the user range.
    pub fn parse(bytes: &'a [u8], abi: Abi, user_end: u64) -> Result<Self, Error> {
        let file = ElfFile64::parse(bytes)?;
        let endian = file.endian();
        if file.elf_header().e_machine(endian) != abi.elf_machine() || !file.is_little_endian() {
            return Err(Error::UnsupportedImage);
        }
        let kind = match file.elf_header().e_type(endian) {
            ET_EXEC => ImageKind::Executable,
            ET_DYN => ImageKind::Dynamic,
            _ => return Err(Error::UnsupportedImage),
        };
        let mut entry_valid = false;
        let mut interpreter: Option<&'a str> = None;
        let mut min_page = u64::MAX;
        let mut max_page = 0u64;
        let headers = file.elf_program_headers();
        for (index, header) in headers.iter().enumerate() {
            match header.p_type(endian) {
                PT_INTERP => {
                    if interpreter.is_some() {
                        return Err(Error::InvalidInterpreter);
                    }
                    let data = header
                        .data(endian, bytes)
                        .map_err(|_| Error::InvalidInterpreter)?;
                    // Linux `fs/binfmt_elf.c` `load_elf_binary`: `p_filesz`
                    // must fit within `PATH_MAX` and terminate with NUL.
                    if data.len() < 2 || data.len() > INTERP_PATH_MAX || data.last() != Some(&0) {
                        return Err(Error::InvalidInterpreter);
                    }
                    let nul = data
                        .iter()
                        .position(|&b| b == 0)
                        .expect("checked trailing NUL");
                    let path = core::str::from_utf8(&data[..nul])
                        .map_err(|_| Error::InvalidInterpreter)?;
                    if path.is_empty() {
                        return Err(Error::InvalidInterpreter);
                    }
                    interpreter = Some(path);
                    continue;
                }
                // `PT_DYNAMIC` is handled by the dynamic linker (or by a static
                // PIE's self-relocation startup code) at runtime.
                PT_DYNAMIC => continue,
                PT_TLS => {
                    let address = header.p_vaddr(endian);
                    let size = header.p_filesz(endian);
                    let align = header.p_align(endian);
                    let end = address.checked_add(size).ok_or(Error::InvalidSegment)?;
                    if size > header.p_memsz(endian)
                        || address
                            .checked_add(header.p_memsz(endian))
                            .is_none_or(|end| end > user_end)
                        || (align > 1
                            && (!align.is_power_of_two()
                                || (size > 0
                                    && address % align != header.p_offset(endian) % align)))
                        || !headers.iter().any(|load| {
                            load.p_type(endian) == PT_LOAD
                                && load.p_flags(endian) & PF_R != 0
                                && address >= load.p_vaddr(endian)
                                && (size == 0
                                    || load
                                        .p_offset(endian)
                                        .checked_add(address - load.p_vaddr(endian))
                                        == Some(header.p_offset(endian)))
                                && load
                                    .p_vaddr(endian)
                                    .checked_add(if size == 0 {
                                        load.p_memsz(endian)
                                    } else {
                                        load.p_filesz(endian)
                                    })
                                    .is_some_and(|limit| end <= limit)
                        })
                    {
                        return Err(Error::InvalidSegment);
                    }
                    continue;
                }
                PT_LOAD => {}
                _ => continue,
            }
            let address = header.p_vaddr(endian);
            let size = header.p_memsz(endian);
            let data = header
                .data(endian, bytes)
                .map_err(|_| Error::InvalidSegment)?;
            let flags = header.p_flags(endian);
            let align = header.p_align(endian);
            let end = address.checked_add(size).ok_or(Error::InvalidSegment)?;
            // Page zero is deliberately unmapped for fixed `ET_EXEC` images;
            // `ET_DYN` images use relative virtual addresses starting at 0 and
            // are placed above `PAGE` via `plan_placement`.
            if (kind == ImageKind::Executable && address < PAGE)
                || end > user_end
                || data.len() as u64 > size
                || flags & !(PF_R | PF_W | PF_X) != 0
                || flags & PF_R == 0
                // PF_W | PF_X loads writable and executable: fs/binfmt_elf.c
                // `load_elf_binary` maps each PT_LOAD through `elf_map` with
                // `make_prot(p_flags)`, which turns PF_W and PF_X into
                // PROT_WRITE and PROT_EXEC together.
                || (align > 1
                    && (!align.is_power_of_two()
                        || address % align != header.p_offset(endian) % align))
            {
                return Err(Error::InvalidSegment);
            }
            if size == 0 {
                continue;
            }
            let seg_first = address & !(PAGE - 1);
            let seg_last = end.checked_add(PAGE - 1).ok_or(Error::InvalidSegment)? & !(PAGE - 1);
            min_page = min_page.min(seg_first);
            max_page = max_page.max(seg_last);
            for earlier in &headers[..index] {
                if earlier.p_type(endian) != PT_LOAD || earlier.p_memsz(endian) == 0 {
                    continue;
                }
                let first = earlier.p_vaddr(endian) & !(PAGE - 1);
                let last =
                    (earlier.p_vaddr(endian) + earlier.p_memsz(endian) + (PAGE - 1)) & !(PAGE - 1);
                if seg_first < last && first < seg_last {
                    return Err(Error::Overlap);
                }
            }
            entry_valid |=
                flags & PF_X != 0 && (address..address + data.len() as u64).contains(&file.entry());
        }
        if !entry_valid {
            return Err(Error::InvalidEntry);
        }
        if kind == ImageKind::Dynamic
            && (max_page <= min_page || (max_page - min_page) > user_end.saturating_sub(PAGE))
        {
            return Err(Error::InvalidSegment);
        }
        Ok(Self {
            file,
            kind,
            interpreter,
        })
    }

    /// Validates `bytes` as an ELF interpreter (`PT_INTERP` target) for `abi`.
    /// Rejects recursive `PT_INTERP` headers per Linux `fs/binfmt_elf.c`.
    pub fn parse_interpreter(bytes: &'a [u8], abi: Abi, user_end: u64) -> Result<Self, Error> {
        let image = Self::parse(bytes, abi, user_end)?;
        if image.interpreter.is_some() {
            return Err(Error::InvalidInterpreter);
        }
        Ok(image)
    }

    pub fn kind(&self) -> ImageKind {
        self.kind
    }

    pub fn is_dynamic(&self) -> bool {
        self.kind == ImageKind::Dynamic
    }

    /// Pathname declared by `PT_INTERP`, when the executable requests a
    /// dynamic linker.
    pub fn interpreter(&self) -> Option<&'a str> {
        self.interpreter
    }

    /// Page-aligned virtual span `(min_vaddr_page, total_size)` across all
    /// non-empty `PT_LOAD` segments (`total_mapping_size` in Linux
    /// `fs/binfmt_elf.c`).
    pub fn load_span(&self, page_size: u64) -> (u64, u64) {
        let endian = self.file.endian();
        let mask = page_size - 1;
        let mut min_page = u64::MAX;
        let mut max_page = 0u64;
        for header in self.file.elf_program_headers() {
            if header.p_type(endian) != PT_LOAD || header.p_memsz(endian) == 0 {
                continue;
            }
            let start = header.p_vaddr(endian) & !mask;
            let end = (header.p_vaddr(endian) + header.p_memsz(endian)).next_multiple_of(page_size);
            min_page = min_page.min(start);
            max_page = max_page.max(end);
        }
        debug_assert!(min_page < max_page, "a validated image has a load segment");
        (min_page, max_page - min_page)
    }

    /// Virtual address of the first `PT_LOAD` minus its file offset (used for
    /// `AT_BASE` of a fixed-address `ET_EXEC` interpreter per Linux
    /// `fs/binfmt_elf.c` `load_elf_interp`).
    fn first_load_base(&self) -> u64 {
        let endian = self.file.endian();
        for header in self.file.elf_program_headers() {
            if header.p_type(endian) == PT_LOAD && header.p_memsz(endian) > 0 {
                return header.p_vaddr(endian).wrapping_sub(header.p_offset(endian));
            }
        }
        unreachable!("a validated image has a load segment")
    }

    pub fn program_headers(&self) -> Result<ProgramHeaders, Error> {
        self.program_headers_at(0)
    }

    /// Location of the ELF64 program headers in memory after applying
    /// `load_bias`.
    pub fn program_headers_at(&self, load_bias: u64) -> Result<ProgramHeaders, Error> {
        let endian = self.file.endian();
        let offset = self.file.elf_header().e_phoff(endian);
        let count = self.file.elf_program_headers().len() as u64;
        // ELF64 program-header entries are 56 bytes (System V ABI).
        let end = offset
            .checked_add(count * 56)
            .ok_or(Error::InvalidSegment)?;
        for header in self.file.elf_program_headers() {
            let start = header.p_offset(endian);
            if header.p_type(endian) == PT_LOAD
                && offset >= start
                && start
                    .checked_add(header.p_filesz(endian))
                    .is_some_and(|limit| end <= limit)
            {
                return Ok(ProgramHeaders {
                    address: load_bias.wrapping_add(header.p_vaddr(endian) + offset - start),
                    count,
                });
            }
        }
        Err(Error::InvalidSegment)
    }

    pub fn entry(&self) -> u64 {
        self.file.entry()
    }

    /// Entry point after applying `load_bias`.
    pub fn entry_at(&self, load_bias: u64) -> u64 {
        load_bias.wrapping_add(self.file.entry())
    }

    /// Where the program break starts: the end of the highest load segment
    /// rounded up to a page, as fs/binfmt_elf.c's `load_elf_binary` sets
    /// `mm->start_brk` (`ELF_PAGEALIGN(elf_brk)`) when it does not
    /// randomise the break.
    pub fn program_break(&self, page_size: u64) -> u64 {
        self.program_break_at(0, page_size)
    }

    /// Relocated initial program break after applying `load_bias`.
    pub fn program_break_at(&self, load_bias: u64, page_size: u64) -> u64 {
        self.segments_at(load_bias)
            .map(|segment| segment.address + segment.memory_size)
            .max()
            .expect("a validated image has a load segment")
            .next_multiple_of(page_size)
    }

    pub fn segments(&self) -> impl Iterator<Item = Segment<'a>> + '_ {
        self.segments_at(0)
    }

    /// Every non-empty `PT_LOAD` segment relocated by `load_bias`.
    ///
    /// For file-backed segments whose `p_vaddr` starts mid-page with matching
    /// `p_offset` congruence (`p_vaddr % PAGE == p_offset % PAGE`), includes
    /// the leading page bytes from `ELF_PAGESTART(p_offset)` exactly as Linux
    /// `fs/binfmt_elf.c` `elf_map` does.
    pub fn segments_at(&self, load_bias: u64) -> impl Iterator<Item = Segment<'a>> + '_ {
        let endian = self.file.endian();
        self.file
            .elf_program_headers()
            .iter()
            .filter_map(move |header| {
                if header.p_type(endian) != PT_LOAD || header.p_memsz(endian) == 0 {
                    return None;
                }
                let raw_vaddr = header.p_vaddr(endian);
                let vaddr = load_bias.wrapping_add(raw_vaddr);
                let memsz = header.p_memsz(endian);
                let filesz = header.p_filesz(endian);
                let offset = header.p_offset(endian);
                let page_off = vaddr & (PAGE - 1);
                let (address, memory_size, bytes) = if filesz > 0
                    && offset >= page_off
                    && (raw_vaddr & (PAGE - 1)) == (offset & (PAGE - 1))
                {
                    let file_start = (offset - page_off) as usize;
                    let file_end = (offset + filesz) as usize;
                    (
                        vaddr - page_off,
                        page_off + memsz,
                        &self.file.data()[file_start..file_end],
                    )
                } else {
                    (
                        vaddr,
                        memsz,
                        header
                            .data(endian, self.file.data())
                            .expect("validated segment"),
                    )
                };
                Some(Segment {
                    address,
                    memory_size,
                    bytes,
                    writable: header.p_flags(endian) & PF_W != 0,
                    executable: header.p_flags(endian) & PF_X != 0,
                })
            })
    }

    fn page_ranges(&self, load_bias: u64, page_size: u64) -> impl Iterator<Item = (u64, u64)> + '_ {
        let endian = self.file.endian();
        let mask = page_size - 1;
        self.file
            .elf_program_headers()
            .iter()
            .filter_map(move |header| {
                if header.p_type(endian) != PT_LOAD || header.p_memsz(endian) == 0 {
                    return None;
                }
                let start = load_bias.wrapping_add(header.p_vaddr(endian));
                let first = start & !mask;
                let last = (start + header.p_memsz(endian)).next_multiple_of(page_size);
                Some((first, last))
            })
    }
}

/// Computes non-overlapping virtual bases for `main` and optional `interp`
/// inside `[user_start, stack_top)` per Linux `fs/binfmt_elf.c`:
///
/// - `ET_EXEC` main images keep their fixed addresses (`main_bias = 0`).
/// - `ET_DYN` main images (PIE) are placed at `ELF_ET_DYN_BASE`
///   (`(stack_top / 3) * 2` aligned down to `page_size`), falling back to the
///   low mappable floor if the image does not fit there.
/// - `ET_DYN` interpreters (`PT_INTERP`, e.g. `ld-musl` / `ld-linux`) are
///   placed in the high mmap region below the downward-growing initial stack
///   reservation, leaving contiguous space above `main`'s `program_break` for
///   `brk(2)` growth and avoiding any overlap with `main`.
pub fn plan_placement(
    main: &Image<'_>,
    interp: Option<&Image<'_>>,
    user_start: u64,
    stack_top: u64,
    page_size: u64,
) -> Result<Placement, Error> {
    let mask = page_size - 1;
    let user_start = user_start.next_multiple_of(page_size);
    let stack_top = stack_top & !mask;
    if stack_top <= user_start {
        return Err(Error::InvalidSegment);
    }
    let user_size = stack_top - user_start;
    let stack_reserve = (user_size / 8).min(STACK_RESERVE_MAX) & !mask;
    let ceiling = if stack_top.saturating_sub(stack_reserve) > user_start {
        (stack_top - stack_reserve) & !mask
    } else {
        stack_top
    };
    let floor = if user_start.max(MMAP_MIN_ADDR).next_multiple_of(page_size) < ceiling {
        user_start.max(MMAP_MIN_ADDR).next_multiple_of(page_size)
    } else {
        user_start
    };

    let (main_bias, main_min, main_end) = match main.kind() {
        ImageKind::Executable => {
            let mut min_addr = u64::MAX;
            let mut max_addr = 0u64;
            for (first, last) in main.page_ranges(0, page_size) {
                if first < user_start || last > stack_top {
                    return Err(Error::InvalidSegment);
                }
                min_addr = min_addr.min(first);
                max_addr = max_addr.max(last);
            }
            (0u64, min_addr, max_addr)
        }
        ImageKind::Dynamic => {
            let (min_page, total_size) = main.load_span(page_size);
            // Linux `arch/x86/include/asm/elf.h` & `arch/arm64/include/asm/elf.h`:
            // `ELF_ET_DYN_BASE = TASK_SIZE / 3 * 2`, page-aligned.
            let preferred = (((stack_top / 3) * 2) & !mask).max(floor);
            let main_base = if preferred
                .checked_add(total_size)
                .is_some_and(|end| end <= ceiling)
            {
                preferred
            } else if floor
                .checked_add(total_size)
                .is_some_and(|end| end <= ceiling)
            {
                floor
            } else if user_start
                .checked_add(total_size)
                .is_some_and(|end| end <= stack_top)
            {
                user_start
            } else {
                return Err(Error::InvalidSegment);
            };
            (
                main_base.wrapping_sub(min_page),
                main_base,
                main_base + total_size,
            )
        }
    };

    let overlaps_main = |first: u64, last: u64| {
        main.page_ranges(main_bias, page_size)
            .any(|(m_first, m_last)| first < m_last && m_first < last)
    };

    let (interpreter_bias, at_base, initial_pc, image_end) = match interp {
        None => (None, 0, main.entry_at(main_bias), main_end),
        Some(interp) => {
            if interp.interpreter().is_some() {
                return Err(Error::InvalidInterpreter);
            }
            let (interp_bias, at_base, interp_end) = match interp.kind() {
                ImageKind::Executable => {
                    let mut max_addr = 0u64;
                    for (first, last) in interp.page_ranges(0, page_size) {
                        if first < user_start || last > stack_top {
                            return Err(Error::InvalidSegment);
                        }
                        if overlaps_main(first, last) {
                            return Err(Error::Overlap);
                        }
                        max_addr = max_addr.max(last);
                    }
                    (0u64, interp.first_load_base(), max_addr)
                }
                ImageKind::Dynamic => {
                    let (interp_min, interp_size) = interp.load_span(page_size);
                    // Prefer the high mmap area below the stack reservation so
                    // `brk` has contiguous growth room above `main_end`.
                    let candidates = [
                        ceiling
                            .checked_sub(interp_size)
                            .map(|addr| addr & !mask)
                            .filter(|&addr| addr >= floor),
                        main_min
                            .checked_sub(interp_size)
                            .map(|addr| addr & !mask)
                            .filter(|&addr| addr >= floor),
                        (main_end < stack_top).then_some(main_end),
                        Some(user_start),
                    ];
                    let interp_base = candidates
                        .into_iter()
                        .flatten()
                        .find(|&base| {
                            base >= user_start
                                && base
                                    .checked_add(interp_size)
                                    .is_some_and(|end| end <= stack_top)
                                && !overlaps_main(base, base + interp_size)
                        })
                        .ok_or(Error::Overlap)?;
                    let bias = interp_base.wrapping_sub(interp_min);
                    (bias, bias, interp_base + interp_size)
                }
            };
            (
                Some(interp_bias),
                at_base,
                interp.entry_at(interp_bias),
                main_end.max(interp_end),
            )
        }
    };

    Ok(Placement {
        main_bias,
        program_break: main.program_break_at(main_bias, page_size),
        interpreter_bias,
        at_base,
        initial_pc,
        main_entry: main.entry_at(main_bias),
        program_headers: main.program_headers_at(main_bias)?,
        image_end,
    })
}
