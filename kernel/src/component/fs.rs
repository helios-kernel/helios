#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentFsNodeKind {
    Directory,
    File,
    Symlink,
    /// The four kinds below are report-only, as for `helios_hal::fs::NodeKind`:
    /// a listing or `stat` names them and no descriptor is ever opened on one.
    CharacterDevice,
    BlockDevice,
    Fifo,
    Socket,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentResourceTableError {
    NotPresent,
    WrongType,
    HasChildren,
    Full,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentFsResourceError {
    BadDescriptor,
    Busy,
    Overflow,
}

pub fn map_resource_table_error(error: ComponentResourceTableError) -> ComponentFsResourceError {
    match error {
        ComponentResourceTableError::NotPresent | ComponentResourceTableError::WrongType => {
            ComponentFsResourceError::BadDescriptor
        }
        ComponentResourceTableError::HasChildren => ComponentFsResourceError::Busy,
        ComponentResourceTableError::Full => ComponentFsResourceError::Overflow,
    }
}
