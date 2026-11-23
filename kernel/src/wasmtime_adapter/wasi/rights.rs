//! The proof a filesystem operation demands of a descriptor.
//!
//! A descriptor's rights are plain flags, and a flag nobody tests is a right
//! nobody enforces. The operations in `fs.rs` therefore take a [`Granted`]
//! instead of the descriptor: a value that only [`FsDescriptor::grant`] and
//! [`FsDescriptor::grant_touch`] can make, and that they make only after
//! testing the kind and the right it names. A surface that forwards a call
//! has to mint the proof to make the call, and an operation cannot skip the
//! test because it never sees bare flags.
//!
//! Minting borrows the descriptor and touches no filesystem, so a refusal
//! always precedes any filesystem traffic, a host share's included.

use core::marker::PhantomData;

use super::*;

mod sealed {
    pub trait Sealed {}
}

/// A right an operation needs from a descriptor.
pub(crate) trait Right: sealed::Sealed {
    /// Holding any one of these grants the right.
    const ANY_OF: &'static [FsDescriptorFlags];
    /// What the operation answers a descriptor without it.
    const REFUSED: fs_types::ErrorCode;
}

/// What the descriptor must name.
pub(crate) trait Kind: sealed::Sealed {
    /// The one node kind it must be, or `None` for any.
    const KIND: Option<FsNodeKind>;
    /// What the operation answers a descriptor of another kind.
    const MISMATCH: fs_types::ErrorCode;
}

/// The right to read a file's data or list a directory.
pub(crate) enum Read {}
/// The right to change a file's data.
pub(crate) enum Write {}
/// The right to change a directory's entries.
pub(crate) enum Mutate {}
/// What changing the times of an object below a directory needs: its
/// `write` or its `mutate-directory`.
pub(crate) enum Retime {}
/// What changing the times of a descriptor's own object needs, which depends
/// on its kind: see [`FsDescriptor::grant_touch`].
pub(crate) enum Touch {}

/// A descriptor that names a directory.
pub(crate) enum Directory {}
/// A descriptor that names a regular file.
pub(crate) enum RegularFile {}
/// A descriptor of any kind.
pub(crate) enum AnyKind {}

impl sealed::Sealed for Read {}
impl sealed::Sealed for Write {}
impl sealed::Sealed for Mutate {}
impl sealed::Sealed for Retime {}
impl sealed::Sealed for Directory {}
impl sealed::Sealed for RegularFile {}
impl sealed::Sealed for AnyKind {}

impl Right for Read {
    const ANY_OF: &'static [FsDescriptorFlags] = &[FsDescriptorFlags::READ];
    const REFUSED: fs_types::ErrorCode = fs_types::ErrorCode::NotPermitted;
}

impl Right for Write {
    const ANY_OF: &'static [FsDescriptorFlags] = &[FsDescriptorFlags::WRITE];
    const REFUSED: fs_types::ErrorCode = fs_types::ErrorCode::ReadOnly;
}

impl Right for Mutate {
    const ANY_OF: &'static [FsDescriptorFlags] = &[FsDescriptorFlags::MUTATE_DIRECTORY];
    const REFUSED: fs_types::ErrorCode = fs_types::ErrorCode::ReadOnly;
}

impl Right for Retime {
    const ANY_OF: &'static [FsDescriptorFlags] = &[
        FsDescriptorFlags::WRITE,
        FsDescriptorFlags::MUTATE_DIRECTORY,
    ];
    const REFUSED: fs_types::ErrorCode = fs_types::ErrorCode::ReadOnly;
}

impl Kind for AnyKind {
    const KIND: Option<FsNodeKind> = None;
    const MISMATCH: fs_types::ErrorCode = fs_types::ErrorCode::Invalid;
}

impl Kind for Directory {
    const KIND: Option<FsNodeKind> = Some(FsNodeKind::Directory);
    const MISMATCH: fs_types::ErrorCode = fs_types::ErrorCode::NotDirectory;
}

impl Kind for RegularFile {
    const KIND: Option<FsNodeKind> = Some(FsNodeKind::File);
    const MISMATCH: fs_types::ErrorCode = fs_types::ErrorCode::IsDirectory;
}

/// Proof that a descriptor names a `K` and holds the right `R`.
///
/// Only [`FsDescriptor::grant`] and [`FsDescriptor::grant_touch`] make one:
/// its field is private to this module. It borrows the descriptor the call
/// cloned at entry, so a later `fd_fdstat_set_rights` narrows the table
/// entry and applies from the next call.
pub(crate) struct Granted<'d, K, R> {
    descriptor: &'d FsDescriptor,
    _proof: PhantomData<fn() -> (K, R)>,
}

impl<K, R> Clone for Granted<'_, K, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K, R> Copy for Granted<'_, K, R> {}

impl<'d, K, R> Granted<'d, K, R> {
    fn new(descriptor: &'d FsDescriptor) -> Self {
        Self {
            descriptor,
            _proof: PhantomData,
        }
    }

    /// The descriptor the proof was made for.
    pub(crate) fn descriptor(&self) -> &'d FsDescriptor {
        self.descriptor
    }
}

/// Proof of both bases of an operation that makes an object reachable
/// under a second directory, checked together: the source base may be read
/// and the destination base may have its entries changed.
///
/// A hard link and a rename both do this: the object is reachable through
/// the destination afterwards, with the destination's rights. A destination
/// that can write must therefore not be fed by a source the caller could not
/// have opened for writing; only [`Granted::alias_into`] makes one.
///
/// `Removal` is the proof the operation needs beyond that. A link leaves
/// the source entry alone and carries `()`; a rename removes it, and
/// [`AliasGrant::removing_source`] adds the source base's `mutate-directory`.
pub(crate) struct AliasGrant<'s, 'd, Removal = ()> {
    source: Granted<'s, Directory, Read>,
    destination: Granted<'d, Directory, Mutate>,
    _removal: Removal,
}

/// The proof a rename takes: [`AliasGrant`] with the source base's
/// `mutate-directory`.
pub(crate) type RenameGrant<'s, 'd> = AliasGrant<'s, 'd, Granted<'s, Directory, Mutate>>;

impl<'s> Granted<'s, Directory, Read> {
    /// Pairs this source base with a destination base. Refuses with
    /// `NotPermitted` when the destination holds `WRITE` and the source
    /// does not: the second name would otherwise make a file writable that
    /// the caller could only read.
    pub(crate) fn alias_into<'d>(
        self,
        destination: Granted<'d, Directory, Mutate>,
    ) -> FsOpResult<AliasGrant<'s, 'd>> {
        let writable = destination
            .descriptor()
            .flags
            .contains(FsDescriptorFlags::WRITE);
        if writable && !self.descriptor().flags.contains(FsDescriptorFlags::WRITE) {
            return Err(fs_types::ErrorCode::NotPermitted);
        }
        Ok(AliasGrant {
            source: self,
            destination,
            _removal: (),
        })
    }
}

impl<'s, 'd> AliasGrant<'s, 'd> {
    /// Adds what a rename needs: the source base's `mutate-directory`,
    /// refused as `ReadOnly`, since the rename removes the source entry.
    pub(crate) fn removing_source(self) -> FsOpResult<RenameGrant<'s, 'd>> {
        let removal = self.source.descriptor().grant()?;
        Ok(AliasGrant {
            source: self.source,
            destination: self.destination,
            _removal: removal,
        })
    }
}

impl<'s, 'd, Removal> AliasGrant<'s, 'd, Removal> {
    /// The source base.
    pub(crate) fn source(&self) -> &'s FsDescriptor {
        self.source.descriptor()
    }

    /// The destination base.
    pub(crate) fn destination(&self) -> &'d FsDescriptor {
        self.destination.descriptor()
    }
}

impl FsDescriptor {
    /// Proves this descriptor names a `K` and holds `R`: the kind is tested
    /// first, then the right, and each refusal is the one its marker names.
    pub(crate) fn grant<K: Kind, R: Right>(&self) -> FsOpResult<Granted<'_, K, R>> {
        if K::KIND.is_some_and(|kind| kind != self.kind) {
            return Err(K::MISMATCH);
        }
        if !R::ANY_OF.iter().any(|right| self.flags.contains(*right)) {
            return Err(R::REFUSED);
        }
        Ok(Granted::new(self))
    }

    /// Proves this descriptor may have its own times changed: a directory
    /// needs `mutate-directory`, every other object needs `write`. The
    /// refusal is `read-only`.
    pub(crate) fn grant_touch(&self) -> FsOpResult<Granted<'_, AnyKind, Touch>> {
        let needed = if self.kind == FsNodeKind::Directory {
            FsDescriptorFlags::MUTATE_DIRECTORY
        } else {
            FsDescriptorFlags::WRITE
        };
        if !self.flags.contains(needed) {
            return Err(fs_types::ErrorCode::ReadOnly);
        }
        Ok(Granted::new(self))
    }
}

/// The rights checked for one open operation, held with its descriptor snapshot.
/// The owner is either the caller's borrow or an owned snapshot crossing an await.
/// No other task can narrow this snapshot after the proof is constructed.
pub(crate) struct OpenGrant<D> {
    descriptor: D,
    create: Option<CreatePermission>,
    truncate: Option<TruncatePermission>,
}

struct CreatePermission;
struct TruncatePermission;

impl<D: core::borrow::Borrow<FsDescriptor>> OpenGrant<D> {
    // Callers in this module have already proved Directory + Read.
    fn new(descriptor: D, flags: fs_types::OpenFlags) -> FsOpResult<Self> {
        let base = descriptor.borrow();
        let truncate = if flags.contains(fs_types::OpenFlags::TRUNCATE) {
            base.grant::<Directory, Mutate>()?;
            base.grant::<Directory, Write>()?;
            Some(TruncatePermission)
        } else {
            None
        };
        let create = if flags.contains(fs_types::OpenFlags::CREATE) {
            base.grant::<Directory, Mutate>()?;
            Some(CreatePermission)
        } else {
            None
        };
        if flags.contains(fs_types::OpenFlags::CREATE | fs_types::OpenFlags::DIRECTORY) {
            return Err(fs_types::ErrorCode::Invalid);
        }
        Ok(Self {
            descriptor,
            create,
            truncate,
        })
    }

    pub(crate) fn base(&self) -> Granted<'_, Directory, Read> {
        Granted::new(self.descriptor.borrow())
    }

    pub(crate) fn create(&self) -> Option<Granted<'_, Directory, Mutate>> {
        self.create
            .as_ref()
            .map(|_| Granted::new(self.descriptor.borrow()))
    }

    pub(crate) fn truncate(
        &self,
    ) -> Option<(
        Granted<'_, Directory, Mutate>,
        Granted<'_, Directory, Write>,
    )> {
        self.truncate.as_ref().map(|_| {
            (
                Granted::new(self.descriptor.borrow()),
                Granted::new(self.descriptor.borrow()),
            )
        })
    }
}

impl<'d> Granted<'d, Directory, Read> {
    pub(crate) fn prepare_open(
        self,
        flags: fs_types::OpenFlags,
    ) -> FsOpResult<OpenGrant<&'d FsDescriptor>> {
        OpenGrant::new(self.descriptor, flags)
    }
}

impl FsDescriptor {
    pub(crate) fn prepare_open(self, flags: fs_types::OpenFlags) -> FsOpResult<OpenGrant<Self>> {
        self.grant::<Directory, Read>()?;
        OpenGrant::new(self, flags)
    }
}
