use alloc::vec::Vec;

use thiserror::Error;

use crate::ProcessId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(u64);

impl ThreadId {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Runnable,
    Sleeping { wake_at_nanos: u64 },
    Exited(u32),
    Signaled(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadRecord {
    id: ThreadId,
    process: ProcessId,
    state: ThreadState,
}

impl ThreadRecord {
    pub fn id(&self) -> ThreadId {
        self.id
    }

    pub fn process(&self) -> ProcessId {
        self.process
    }

    pub fn state(&self) -> ThreadState {
        self.state
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ThreadTableError {
    #[error("unknown thread id {0}")]
    UnknownThread(u64),
    #[error("thread id allocation overflowed")]
    ThreadIdOverflow,
}

#[derive(Default)]
pub struct ThreadTable {
    next_id: u64,
    records: Vec<ThreadRecord>,
}

impl ThreadTable {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            records: Vec::new(),
        }
    }

    pub fn spawn(&mut self, process: ProcessId) -> Result<ThreadId, ThreadTableError> {
        let id = ThreadId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(ThreadTableError::ThreadIdOverflow)?;
        self.records.push(ThreadRecord {
            id,
            process,
            state: ThreadState::Runnable,
        });
        Ok(id)
    }

    pub fn set_sleeping(
        &mut self,
        thread: ThreadId,
        wake_at_nanos: u64,
    ) -> Result<(), ThreadTableError> {
        self.record_mut(thread)?.state = ThreadState::Sleeping { wake_at_nanos };
        Ok(())
    }

    pub fn wake_due(&mut self, now_nanos: u64) -> usize {
        let mut woken = 0;
        for record in &mut self.records {
            if let ThreadState::Sleeping { wake_at_nanos } = record.state
                && wake_at_nanos <= now_nanos
            {
                record.state = ThreadState::Runnable;
                woken += 1;
            }
        }
        woken
    }

    pub fn signal(&mut self, thread: ThreadId, signal: u32) -> Result<(), ThreadTableError> {
        self.record_mut(thread)?.state = ThreadState::Signaled(signal);
        Ok(())
    }

    pub fn exit(&mut self, thread: ThreadId, code: u32) -> Result<(), ThreadTableError> {
        self.record_mut(thread)?.state = ThreadState::Exited(code);
        Ok(())
    }

    pub fn join(&self, thread: ThreadId) -> Result<Option<u32>, ThreadTableError> {
        Ok(match self.record(thread)?.state {
            ThreadState::Exited(code) => Some(code),
            ThreadState::Runnable | ThreadState::Sleeping { .. } | ThreadState::Signaled(_) => None,
        })
    }

    pub fn record(&self, thread: ThreadId) -> Result<&ThreadRecord, ThreadTableError> {
        self.records
            .iter()
            .find(|record| record.id == thread)
            .ok_or(ThreadTableError::UnknownThread(thread.raw()))
    }

    pub fn process_parallelism(&self, process: ProcessId) -> usize {
        self.records
            .iter()
            .filter(|record| record.process == process)
            .filter(|record| !matches!(record.state, ThreadState::Exited(_)))
            .count()
    }

    fn record_mut(&mut self, thread: ThreadId) -> Result<&mut ThreadRecord, ThreadTableError> {
        self.records
            .iter_mut()
            .find(|record| record.id == thread)
            .ok_or(ThreadTableError::UnknownThread(thread.raw()))
    }
}
