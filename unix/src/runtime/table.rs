use alloc::vec::Vec;

use thiserror::Error;

/// Authority owner supplies its typed operation tokens and subset relation.
pub trait ProcessPermissions: Clone {
    type Spawn;
    type Fork;
    type Exec;
    type Join;
    type Signal;
    fn contains_authority(&self, child: &Self) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(u64);

impl ProcessId {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Exited(u32),
    Signaled(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessRecord<A: ProcessPermissions> {
    id: ProcessId,
    parent: Option<ProcessId>,
    authority: A,
    state: ProcessState,
}

impl<A: ProcessPermissions> ProcessRecord<A> {
    pub fn id(&self) -> ProcessId {
        self.id
    }

    pub fn parent(&self) -> Option<ProcessId> {
        self.parent
    }

    pub fn authority(&self) -> &A {
        &self.authority
    }

    pub fn state(&self) -> ProcessState {
        self.state
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProcessTableError {
    #[error("unknown process id {0}")]
    UnknownProcess(u64),
    #[error("child authority exceeds caller authority")]
    AuthorityWidening,
    #[error("process id allocation overflowed")]
    ProcessIdOverflow,
}

pub struct ProcessTable<A: ProcessPermissions> {
    next_id: u64,
    records: Vec<ProcessRecord<A>>,
}

impl<A: ProcessPermissions> ProcessTable<A> {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            records: Vec::new(),
        }
    }

    pub fn register_root(&mut self, authority: A) -> Result<ProcessId, ProcessTableError> {
        self.insert(None, authority)
    }

    pub fn spawn(
        &mut self,
        _: &A::Spawn,
        caller: ProcessId,
        child_authority: A,
    ) -> Result<ProcessId, ProcessTableError> {
        let caller_authority = self.record(caller)?.authority.clone();
        if !caller_authority.contains_authority(&child_authority) {
            return Err(ProcessTableError::AuthorityWidening);
        }
        self.insert(Some(caller), child_authority)
    }

    pub fn fork(&mut self, _: &A::Fork, parent: ProcessId) -> Result<ProcessId, ProcessTableError> {
        let authority = self.record(parent)?.authority.clone();
        self.insert(Some(parent), authority)
    }

    pub fn exec(&mut self, _: &A::Exec, process: ProcessId) -> Result<(), ProcessTableError> {
        self.record_mut(process)?.state = ProcessState::Running;
        Ok(())
    }

    pub fn exit(&mut self, process: ProcessId, code: u32) -> Result<(), ProcessTableError> {
        self.record_mut(process)?.state = ProcessState::Exited(code);
        Ok(())
    }

    pub fn join(&self, _: &A::Join, process: ProcessId) -> Result<Option<u32>, ProcessTableError> {
        Ok(match self.record(process)?.state {
            ProcessState::Exited(code) => Some(code),
            ProcessState::Running | ProcessState::Signaled(_) => None,
        })
    }

    pub fn signal(
        &mut self,
        _: &A::Signal,
        process: ProcessId,
        signal: u32,
    ) -> Result<(), ProcessTableError> {
        self.record_mut(process)?.state = ProcessState::Signaled(signal);
        Ok(())
    }

    pub fn record(&self, process: ProcessId) -> Result<&ProcessRecord<A>, ProcessTableError> {
        self.records
            .iter()
            .find(|record| record.id == process)
            .ok_or(ProcessTableError::UnknownProcess(process.raw()))
    }

    fn record_mut(
        &mut self,
        process: ProcessId,
    ) -> Result<&mut ProcessRecord<A>, ProcessTableError> {
        self.records
            .iter_mut()
            .find(|record| record.id == process)
            .ok_or(ProcessTableError::UnknownProcess(process.raw()))
    }

    fn insert(
        &mut self,
        parent: Option<ProcessId>,
        authority: A,
    ) -> Result<ProcessId, ProcessTableError> {
        let id = ProcessId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(ProcessTableError::ProcessIdOverflow)?;
        self.records.push(ProcessRecord {
            id,
            parent,
            authority,
            state: ProcessState::Running,
        });
        Ok(id)
    }
}

impl<A: ProcessPermissions> Default for ProcessTable<A> {
    fn default() -> Self {
        Self::new()
    }
}
