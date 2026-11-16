use object::elf::{ET_EXEC, PF_R, PF_W, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_TLS};
use object::read::elf::{ElfFile64, FileHeader, ProgramHeader};
use object::{Architecture, Object};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid ELF: {0}")]
    Parse(#[from] object::Error),
    #[error("prototype requires a little-endian static x86-64 ET_EXEC image")]
    UnsupportedImage,
    #[error("prototype cannot load an interpreter, dynamic relocations or TLS")]
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
                PT_INTERP | PT_DYNAMIC | PT_TLS => return Err(Error::UnsupportedSegment),
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
