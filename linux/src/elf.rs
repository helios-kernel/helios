use object::elf::{ET_EXEC, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_TLS};
use object::read::elf::{ElfFile64, FileHeader, ProgramHeader};
use object::{Architecture, Object};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid ELF: {0}")]
    Parse(#[from] object::Error),
    #[error("prototype requires a little-endian static x86-64 ET_EXEC image")]
    UnsupportedImage,
    #[error("prototype cannot load an interpreter or dynamic relocations")]
    UnsupportedSegment,
    #[error("invalid load segment range, alignment or permissions")]
    InvalidSegment,
    #[error("load segments overlap at page granularity")]
    Overlap,
    #[error("entry point is not in executable file-backed bytes")]
    InvalidEntry,
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
#[derive(Clone, Copy)]
pub struct ProgramHeaders {
    pub address: u64,
    pub count: u64,
}

/// Validated static executable. Validation completes before the caller maps any
/// bytes. The caller owns allocation failures and rolls back its address space.
pub struct Image<'a> {
    file: ElfFile64<'a>,
}

impl<'a> Image<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let file = ElfFile64::parse(bytes)?;
        let endian = file.endian();
        if file.architecture() != Architecture::X86_64
            || !file.is_little_endian()
            || file.elf_header().e_type(endian) != ET_EXEC
        {
            return Err(Error::UnsupportedImage);
        }
        let mut entry_valid = false;
        let headers = file.elf_program_headers();
        for (index, header) in headers.iter().enumerate() {
            match header.p_type(endian) {
                PT_INTERP | PT_DYNAMIC => return Err(Error::UnsupportedSegment),
                PT_TLS => {
                    let address = header.p_vaddr(endian);
                    let size = header.p_filesz(endian);
                    let align = header.p_align(endian);
                    let end = address.checked_add(size).ok_or(Error::InvalidSegment)?;
                    if size > header.p_memsz(endian)
                        || address
                            .checked_add(header.p_memsz(endian))
                            .is_none_or(|end| end > 1 << 47)
                        || (align > 1
                            && (!align.is_power_of_two()
                                || address % align != header.p_offset(endian) % align))
                        || !headers.iter().any(|load| {
                            load.p_type(endian) == PT_LOAD
                                && load.p_flags(endian) & PF_R != 0
                                && address >= load.p_vaddr(endian)
                                && load
                                    .p_offset(endian)
                                    .checked_add(address - load.p_vaddr(endian))
                                    == Some(header.p_offset(endian))
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
            let bytes = header
                .data(endian, bytes)
                .map_err(|_| Error::InvalidSegment)?;
            let flags = header.p_flags(endian);
            let align = header.p_align(endian);
            let end = address.checked_add(size).ok_or(Error::InvalidSegment)?;
            // x86-64's four-level user half; page zero is deliberately unmapped.
            if address < 4096
                || end > 1 << 47
                || bytes.len() as u64 > size
                || flags & !(PF_R | PF_W | PF_X) != 0
                || flags & PF_R == 0
                || flags & (PF_W | PF_X) == PF_W | PF_X
                || (align > 1
                    && (!align.is_power_of_two()
                        || address % align != header.p_offset(endian) % align))
            {
                return Err(Error::InvalidSegment);
            }
            if size == 0 {
                continue;
            }
            for earlier in &headers[..index] {
                if earlier.p_type(endian) != PT_LOAD || earlier.p_memsz(endian) == 0 {
                    continue;
                }
                let first = earlier.p_vaddr(endian) & !4095;
                let last = (earlier.p_vaddr(endian) + earlier.p_memsz(endian) + 4095) & !4095;
                if (address & !4095) < last && first < ((end + 4095) & !4095) {
                    return Err(Error::Overlap);
                }
            }
            entry_valid |= flags & PF_X != 0
                && (address..address + bytes.len() as u64).contains(&file.entry());
        }
        if !entry_valid {
            return Err(Error::InvalidEntry);
        }
        Ok(Self { file })
    }

    pub fn program_headers(&self) -> Result<ProgramHeaders, Error> {
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
                    address: header.p_vaddr(endian) + offset - start,
                    count,
                });
            }
        }
        Err(Error::InvalidSegment)
    }

    pub fn entry(&self) -> u64 {
        self.file.entry()
    }

    pub fn segments(&self) -> impl Iterator<Item = Segment<'a>> + '_ {
        let endian = self.file.endian();
        self.file
            .elf_program_headers()
            .iter()
            .filter_map(move |header| {
                if header.p_type(endian) != PT_LOAD || header.p_memsz(endian) == 0 {
                    return None;
                }
                Some(Segment {
                    address: header.p_vaddr(endian),
                    memory_size: header.p_memsz(endian),
                    bytes: header
                        .data(endian, self.file.data())
                        .expect("validated segment"),
                    writable: header.p_flags(endian) & PF_W != 0,
                    executable: header.p_flags(endian) & PF_X != 0,
                })
            })
    }
}
