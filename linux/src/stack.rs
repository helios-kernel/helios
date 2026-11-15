//! AMD64 System V process entry stack for static Linux executables.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("initial stack buffer is too small")]
    Capacity,
    #[error("initial stack address overflows")]
    Address,
    #[error("process argument contains a NUL byte")]
    Argument,
}

pub struct Startup {
    pub entry: u64,
    pub page_size: u64,
    pub headers: crate::elf::ProgramHeaders,
    pub random: [u8; 16],
}

/// Builds argc=1, argv, an empty environment, and the page-size and entry-point
/// auxiliary entries in caller-owned storage. Returns the 16-byte aligned RSP.
/// The caller maps the entire buffer at `base` before starting the process.
pub fn initialize(
    buffer: &mut [u8],
    base: u64,
    program: &[u8],
    startup: &Startup,
) -> Result<u64, Error> {
    if program.contains(&0) {
        return Err(Error::Argument);
    }
    base.checked_add(buffer.len() as u64)
        .ok_or(Error::Address)?;
    let string_offset = buffer
        .len()
        .checked_sub(program.len().checked_add(1).ok_or(Error::Capacity)?)
        .ok_or(Error::Capacity)?;
    let random_offset = string_offset.checked_sub(16).ok_or(Error::Capacity)?;
    // AMD64 psABI and Linux elf.h auxiliary tags: PHDR/PHENT/PHNUM,
    // PAGESZ, ENTRY, RANDOM, EXECFN and NULL.
    let words = [
        1,
        base + string_offset as u64,
        0,
        0,
        3,
        startup.headers.address,
        4,
        56,
        5,
        startup.headers.count,
        6,
        startup.page_size,
        9,
        startup.entry,
        25,
        base + random_offset as u64,
        31,
        base + string_offset as u64,
        0,
        0,
    ];
    let unaligned = random_offset
        .checked_sub(words.len() * 8)
        .ok_or(Error::Capacity)?;
    let rsp = (base + unaligned as u64) & !15;
    let offset = rsp.checked_sub(base).ok_or(Error::Capacity)? as usize;
    buffer.fill(0);
    buffer[random_offset..random_offset + 16].copy_from_slice(&startup.random);
    buffer[string_offset..string_offset + program.len()].copy_from_slice(program);
    for (index, word) in words.into_iter().enumerate() {
        buffer[offset + index * 8..offset + (index + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    Ok(rsp)
}
