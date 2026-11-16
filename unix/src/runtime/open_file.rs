use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

/// The POSIX open file description of a filesystem object: the node handle
/// the platform opened and the file offset every read, write and seek
/// through it moves. A descriptor's status flags live beside it in its
/// [`crate::FileDescriptorEntry`], shared the same way.
///
/// Clones share one description: `dup`, `dup2`, `fork`, spawn descriptor
/// actions and exec inheritance clone it, so every descriptor they produce
/// reads and writes at the same offset, while opening the node again makes
/// a new one. The node handle is the platform's and is never touched here;
/// the platform performs the I/O and reports the offset it reached.
///
/// # Concurrency contract
///
/// Every operation is lock-free. The offset is one atomic word and is never
/// held across the platform's I/O: an operation reads the offset it starts
/// at and stores the offset it reached, so operations through one
/// description that overlap in time each start from the offset they read,
/// and the last to finish sets it.
pub struct OpenFile<Node>(Arc<OpenFileDescription<Node>>);

struct OpenFileDescription<Node> {
    node: Node,
    offset: AtomicU64,
}

impl<Node> OpenFile<Node> {
    /// A new open file description of `node`, at offset 0.
    pub fn new(node: Node) -> Self {
        Self(Arc::new(OpenFileDescription {
            node,
            offset: AtomicU64::new(0),
        }))
    }

    /// The node handle the description was opened on.
    pub fn node(&self) -> &Node {
        &self.0.node
    }

    /// The offset the next read or write without an explicit position
    /// starts at.
    pub fn offset(&self) -> u64 {
        // The offset publishes no other memory, so it needs no ordering
        // beyond its own atomicity.
        self.0.offset.load(Ordering::Relaxed)
    }

    /// Moves the offset: after a read or write to the offset it reached, or
    /// to where a seek placed it.
    pub fn set_offset(&self, offset: u64) {
        self.0.offset.store(offset, Ordering::Relaxed);
    }

    /// Whether `self` and `other` are the same open file description.
    pub fn same_description(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<Node> Clone for OpenFile<Node> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::OpenFile;

    #[test]
    fn clones_share_the_offset_and_a_new_open_does_not() {
        let file = OpenFile::new("node");
        let duplicate = file.clone();
        duplicate.set_offset(12);
        assert_eq!(file.offset(), 12);
        assert!(file.same_description(&duplicate));

        let reopened = OpenFile::new(*file.node());
        assert_eq!(reopened.offset(), 0);
        assert!(!reopened.same_description(&file));
    }
}
