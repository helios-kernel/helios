use crate::{DescriptorLimit, DescriptorTableError, FreeDescriptorSlots};
use alloc::vec::Vec;

/// Single-owner descriptor-number storage. A cloned table has independent slots;
/// an entry controls which underlying resource a duplicate shares. Mutation is
/// serialized by the process owner and never holds a lock across suspension.
#[derive(Clone)]
pub struct DescriptorSlots<Entry> {
    pub entries: Vec<Option<Entry>>,
    pub free: FreeDescriptorSlots,
    pub limit: DescriptorLimit,
}
impl<Entry> Default for DescriptorSlots<Entry> {
    fn default() -> Self {
        Self::new()
    }
}
impl<Entry> DescriptorSlots<Entry> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            free: FreeDescriptorSlots::new(),
            limit: DescriptorLimit::DEFAULT,
        }
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            free: FreeDescriptorSlots::with_capacity(capacity),
            limit: DescriptorLimit::DEFAULT,
        }
    }
    pub fn from_entries(entries: Vec<Option<Entry>>) -> Self {
        let mut free = FreeDescriptorSlots::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            if entry.is_none() {
                free.release(index);
            }
        }
        Self {
            entries,
            free,
            limit: DescriptorLimit::DEFAULT,
        }
    }
    pub fn allocate_slot_index(&mut self) -> Result<usize, DescriptorTableError> {
        while let Some(index) = self.free.allocate() {
            if !self.limit.admits(index) {
                self.free.release(index);
                break;
            }
            if self.entries.get(index).is_some_and(Option::is_none) {
                return Ok(index);
            }
        }
        let index = self.entries.len();
        if !self.limit.admits(index) {
            return Err(DescriptorTableError::TooManyDescriptors {
                limit: self.limit.get(),
            });
        }
        self.entries.push(None);
        Ok(index)
    }
    pub fn insert_entry(&mut self, entry: Entry) -> Result<u32, DescriptorTableError> {
        let index = self.allocate_slot_index()?;
        let number = u32::try_from(index).map_err(|_| DescriptorTableError::IndexOverflow)?;
        self.entries[index] = Some(entry);
        Ok(number)
    }
    pub fn target_index(&self, fd: i32) -> Result<usize, DescriptorTableError> {
        usize::try_from(fd)
            .ok()
            .filter(|index| self.limit.admits(*index))
            .ok_or(DescriptorTableError::BadDescriptor(fd as u32))
    }
    pub fn insert_entry_at(&mut self, fd: i32, entry: Entry) -> Result<u32, DescriptorTableError> {
        let to = self.target_index(fd)?;
        if self.entries.len() <= to {
            let previous_len = self.entries.len();
            self.entries.resize_with(to + 1, || None);
            self.free.release_range(previous_len..to);
        }
        self.entries[to] = Some(entry);
        Ok(to as u32)
    }
    pub fn get_entry(&self, fd: i32) -> Option<&Entry> {
        usize::try_from(fd)
            .ok()
            .and_then(|index| self.entries.get(index))
            .and_then(Option::as_ref)
    }
    pub fn get_entry_mut(&mut self, fd: i32) -> Option<&mut Entry> {
        usize::try_from(fd)
            .ok()
            .and_then(|index| self.entries.get_mut(index))
            .and_then(Option::as_mut)
    }
    pub fn close(&mut self, fd: i32) -> Result<Entry, DescriptorTableError> {
        let index =
            usize::try_from(fd).map_err(|_| DescriptorTableError::BadDescriptor(fd as u32))?;
        let entry = self
            .entries
            .get_mut(index)
            .and_then(Option::take)
            .ok_or(DescriptorTableError::BadDescriptor(fd as u32))?;
        self.free.release(index);
        Ok(entry)
    }
}
