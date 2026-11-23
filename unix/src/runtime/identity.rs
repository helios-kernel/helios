use core::num::NonZeroU64;
/// Execution identity supplied by the owner that allocates process IDs.
/// Immutable and freely shared across processors. ID zero is never a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    id: NonZeroU64,
}
impl ProcessIdentity {
    pub const fn new(id: NonZeroU64) -> Self {
        Self { id }
    }
    pub const fn id(self) -> NonZeroU64 {
        self.id
    }
}
