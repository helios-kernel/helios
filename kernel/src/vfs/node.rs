//! The filesystem node handle every guest ABI holds for an open object.
//!
//! A component's filesystem resource holds it directly; a POSIX descriptor,
//! whether a wasm program's or a native Linux process's, holds it through
//! the open file description in `helios-unix`. It is immutable once opened,
//! so clones are interchangeable; what POSIX shares between duplicated
//! descriptors (the offset, the status flags) lives in the open file
//! description, never here.

use alloc::string::String;

use bitflags::bitflags;

use crate::{ComponentFsNodeKind, MountHold, ObjectIdentity};

bitflags! {
    /// The rights a node handle was opened with, and the synchronisation it
    /// asked for. Each guest ABI maps its own open flags onto these.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct FsDescriptorFlags: u8 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const FILE_INTEGRITY_SYNC = 1 << 2;
        const DATA_INTEGRITY_SYNC = 1 << 3;
        const REQUESTED_WRITE_SYNC = 1 << 4;
        const MUTATE_DIRECTORY = 1 << 5;
    }
}

/// An open filesystem node: the guest path it names, what it named when it
/// was opened, and the rights it was opened with.
#[derive(Clone)]
pub struct FsDescriptor {
    pub(crate) path: String,
    pub(crate) kind: ComponentFsNodeKind,
    pub(crate) flags: FsDescriptorFlags,
    pub(crate) identity: Option<ObjectIdentity>,
    /// The hold on the mount `open-at` resolved this through, which keeps
    /// that mount from being unmounted while the node is open. `None` for a
    /// preopen or a working directory, which the process's authority names
    /// rather than an open, and for the namespace's root.
    #[expect(
        dead_code,
        reason = "held for its effect: a live share is what makes unmount busy"
    )]
    pub(crate) mount: Option<MountHold>,
}
