//! AMD64 System V process entry stack for static Linux executables.

use alloc::vec::Vec;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("initial stack address overflows")]
    Address,
    #[error("process argument or environment string contains a NUL byte")]
    Argument,
}

pub struct Startup<'a> {
    pub entry: u64,
    pub page_size: u64,
    pub headers: crate::elf::ProgramHeaders,
    pub random: [u8; 16],
    /// `argv`, `argv[0]` included.
    pub arguments: &'a [&'a [u8]],
    /// `envp`, each entry `NAME=value`.
    pub environment: &'a [&'a [u8]],
    /// The path the program was executed by, for `AT_EXECFN`.
    pub executable: &'a [u8],
}

/// The bytes of a process's initial stack and where they go.
pub struct InitialStack {
    /// Page-multiple contents, to be mapped at `base`.
    pub bytes: Vec<u8>,
    pub base: u64,
    /// The stack pointer at entry: 16-byte aligned, at `argc`.
    pub pointer: u64,
}

// AMD64 psABI and Linux uapi/linux/auxvec.h auxiliary tags.
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_ENTRY: u64 = 9;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;
// ELF64 program-header entries are 56 bytes (System V gABI).
const ELF64_PHDR_BYTES: u64 = 56;

/// Builds `argc`, `argv`, `envp` and the auxiliary vector below `top`, the
/// strings and `AT_RANDOM`'s bytes above them, as Linux's `create_elf_tables`
/// lays them out.
pub fn build(startup: &Startup<'_>, top: u64) -> Result<InitialStack, Error> {
    let strings = core::iter::once(startup.executable)
        .chain(startup.arguments.iter().copied())
        .chain(startup.environment.iter().copied());
    let mut string_bytes = 0usize;
    for string in strings.clone() {
        if string.contains(&0) {
            return Err(Error::Argument);
        }
        string_bytes += string.len() + 1;
    }
    let auxiliary = 8;
    let words = 1 + startup.arguments.len() + 1 + startup.environment.len() + 1 + auxiliary * 2;
    let random_offset_from_top = string_bytes + 16;
    // The vector sits below the random bytes, aligned so `argc` is at a
    // 16-byte boundary.
    let vector_from_top = (random_offset_from_top + words * 8).next_multiple_of(16);
    let size = (vector_from_top as u64).next_multiple_of(startup.page_size);
    let base = top.checked_sub(size).ok_or(Error::Address)?;
    let at = |from_top: usize| top - from_top as u64;

    let mut bytes = alloc::vec![0; size as usize];
    let offset = |address: u64| (address - base) as usize;
    let mut cursor = top;
    let mut place = |string: &[u8], bytes: &mut [u8]| {
        cursor -= string.len() as u64 + 1;
        bytes[offset(cursor)..offset(cursor) + string.len()].copy_from_slice(string);
        cursor
    };
    let executable = place(startup.executable, &mut bytes);
    let mut arguments = Vec::with_capacity(startup.arguments.len());
    for argument in startup.arguments {
        arguments.push(place(argument, &mut bytes));
    }
    let mut environment = Vec::with_capacity(startup.environment.len());
    for variable in startup.environment {
        environment.push(place(variable, &mut bytes));
    }
    let random = at(random_offset_from_top);
    bytes[offset(random)..offset(random) + 16].copy_from_slice(&startup.random);

    let pointer = at(vector_from_top);
    let mut vector = Vec::with_capacity(words);
    vector.push(startup.arguments.len() as u64);
    vector.extend_from_slice(&arguments);
    vector.push(0);
    vector.extend_from_slice(&environment);
    vector.push(0);
    vector.extend_from_slice(&[
        AT_PHDR,
        startup.headers.address,
        AT_PHENT,
        ELF64_PHDR_BYTES,
        AT_PHNUM,
        startup.headers.count,
        AT_PAGESZ,
        startup.page_size,
        AT_ENTRY,
        startup.entry,
        AT_RANDOM,
        random,
        AT_EXECFN,
        executable,
        AT_NULL,
        0,
    ]);
    debug_assert_eq!(vector.len(), words);
    for (index, word) in vector.into_iter().enumerate() {
        let at = offset(pointer) + index * 8;
        bytes[at..at + 8].copy_from_slice(&word.to_le_bytes());
    }
    Ok(InitialStack {
        bytes,
        base,
        pointer,
    })
}
