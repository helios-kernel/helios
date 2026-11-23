//! `std::io::Error` constructors shared by the `fs` and `io` helpers.
//!
//! The SDK reports every fault as `std::io::Error` so programs interact
//! with one error vocabulary; these constructors attach the failing
//! path or stream and the WASI error code as the message.

use std::io;

/// Result alias used across the SDK's I/O surfaces.
pub type Result<T> = io::Result<T>;

#[cfg(feature = "fs")]
pub fn missing_root_directory() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "helios root directory '/' is not mounted",
    )
}

#[cfg(feature = "fs")]
pub fn parent_traversal(path: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("path {path:?} contains unsupported parent traversal"),
    )
}

#[cfg(feature = "fs")]
pub fn non_utf8_path(path: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("path {path:?} contains a non-utf8 segment"),
    )
}

#[cfg(feature = "fs")]
fn filesystem_error_kind(
    code: &crate::bindings::wasi::filesystem::types::ErrorCode,
) -> io::ErrorKind {
    use crate::bindings::wasi::filesystem::types::ErrorCode;

    match code {
        ErrorCode::Access | ErrorCode::NotPermitted => io::ErrorKind::PermissionDenied,
        ErrorCode::Busy => io::ErrorKind::ResourceBusy,
        ErrorCode::CrossDevice => io::ErrorKind::CrossesDevices,
        ErrorCode::Deadlock => io::ErrorKind::Deadlock,
        ErrorCode::Exist => io::ErrorKind::AlreadyExists,
        ErrorCode::FileTooLarge => io::ErrorKind::FileTooLarge,
        ErrorCode::IllegalByteSequence => io::ErrorKind::InvalidData,
        ErrorCode::InsufficientMemory => io::ErrorKind::OutOfMemory,
        ErrorCode::InsufficientSpace => io::ErrorKind::StorageFull,
        ErrorCode::Interrupted => io::ErrorKind::Interrupted,
        ErrorCode::Invalid => io::ErrorKind::InvalidInput,
        ErrorCode::InvalidSeek => io::ErrorKind::NotSeekable,
        ErrorCode::IsDirectory => io::ErrorKind::IsADirectory,
        ErrorCode::NameTooLong => io::ErrorKind::InvalidFilename,
        ErrorCode::NoEntry => io::ErrorKind::NotFound,
        ErrorCode::NotDirectory => io::ErrorKind::NotADirectory,
        ErrorCode::NotEmpty => io::ErrorKind::DirectoryNotEmpty,
        ErrorCode::Pipe => io::ErrorKind::BrokenPipe,
        ErrorCode::Quota => io::ErrorKind::QuotaExceeded,
        ErrorCode::ReadOnly => io::ErrorKind::ReadOnlyFilesystem,
        ErrorCode::TextFileBusy => io::ErrorKind::ExecutableFileBusy,
        ErrorCode::TooManyLinks => io::ErrorKind::TooManyLinks,
        ErrorCode::Unsupported => io::ErrorKind::Unsupported,
        ErrorCode::Already
        | ErrorCode::BadDescriptor
        | ErrorCode::InProgress
        | ErrorCode::Io
        | ErrorCode::Loop
        | ErrorCode::MessageSize
        | ErrorCode::NoDevice
        | ErrorCode::NoLock
        | ErrorCode::NoSuchDevice
        | ErrorCode::NoTty
        | ErrorCode::NotRecoverable
        | ErrorCode::Overflow
        | ErrorCode::Other(_) => io::ErrorKind::Other,
    }
}

#[cfg(feature = "fs")]
pub fn filesystem(
    path: &str,
    code: crate::bindings::wasi::filesystem::types::ErrorCode,
) -> io::Error {
    io::Error::new(
        filesystem_error_kind(&code),
        format!("filesystem operation on {path:?} failed: {code:?}"),
    )
}

#[cfg(feature = "io")]
pub fn stdout(code: crate::bindings::wasi::cli::types::ErrorCode) -> io::Error {
    io::Error::other(format!("stdout write failed: {code:?}"))
}

#[cfg(feature = "io")]
pub fn stderr(code: crate::bindings::wasi::cli::types::ErrorCode) -> io::Error {
    io::Error::other(format!("stderr write failed: {code:?}"))
}

#[cfg(feature = "io")]
pub fn stdin(code: crate::bindings::wasi::cli::types::ErrorCode) -> io::Error {
    io::Error::other(format!("stdin read failed: {code:?}"))
}

#[cfg(any(feature = "fs", feature = "io"))]
pub fn stream_closed(target: &str, unwritten: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        format!("{target} stream closed by the reader with {unwritten} bytes unwritten"),
    )
}

#[cfg(feature = "fs")]
pub fn invalid_utf8(path: &str, error: std::string::FromUtf8Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("file {path:?} is not valid utf-8: {error}"),
    )
}

#[cfg(feature = "fs")]
pub fn file_too_large(path: &str, size: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("file {path:?} size {size} does not fit into usize"),
    )
}

#[cfg(all(test, feature = "fs"))]
mod tests {
    use std::io::ErrorKind;

    use crate::bindings::wasi::filesystem::types::ErrorCode;

    use super::filesystem;

    #[test]
    fn filesystem_maps_wasi_error_codes_to_io_error_kinds_and_keeps_message() {
        let cases = [
            (ErrorCode::NoEntry, ErrorKind::NotFound),
            (ErrorCode::Access, ErrorKind::PermissionDenied),
            (ErrorCode::NotPermitted, ErrorKind::PermissionDenied),
            (ErrorCode::Busy, ErrorKind::ResourceBusy),
            (ErrorCode::CrossDevice, ErrorKind::CrossesDevices),
            (ErrorCode::Deadlock, ErrorKind::Deadlock),
            (ErrorCode::Exist, ErrorKind::AlreadyExists),
            (ErrorCode::FileTooLarge, ErrorKind::FileTooLarge),
            (ErrorCode::IllegalByteSequence, ErrorKind::InvalidData),
            (ErrorCode::InsufficientMemory, ErrorKind::OutOfMemory),
            (ErrorCode::InsufficientSpace, ErrorKind::StorageFull),
            (ErrorCode::Interrupted, ErrorKind::Interrupted),
            (ErrorCode::Invalid, ErrorKind::InvalidInput),
            (ErrorCode::InvalidSeek, ErrorKind::NotSeekable),
            (ErrorCode::IsDirectory, ErrorKind::IsADirectory),
            (ErrorCode::NameTooLong, ErrorKind::InvalidFilename),
            (ErrorCode::NotDirectory, ErrorKind::NotADirectory),
            (ErrorCode::NotEmpty, ErrorKind::DirectoryNotEmpty),
            (ErrorCode::Pipe, ErrorKind::BrokenPipe),
            (ErrorCode::Quota, ErrorKind::QuotaExceeded),
            (ErrorCode::ReadOnly, ErrorKind::ReadOnlyFilesystem),
            (ErrorCode::TextFileBusy, ErrorKind::ExecutableFileBusy),
            (ErrorCode::TooManyLinks, ErrorKind::TooManyLinks),
            (ErrorCode::Unsupported, ErrorKind::Unsupported),
            (ErrorCode::Io, ErrorKind::Other),
            (
                ErrorCode::Other(Some("custom".to_owned())),
                ErrorKind::Other,
            ),
        ];

        for (code, expected_kind) in cases {
            let expected_suffix = format!("{code:?}");
            let error = filesystem("/etc/ssl/certs/ca-certificates.crt", code);
            assert_eq!(error.kind(), expected_kind);
            let message = error.to_string();
            assert!(
                message.contains("/etc/ssl/certs/ca-certificates.crt")
                    && message.contains(&expected_suffix),
                "unexpected message: {message}"
            );
        }
    }
}
