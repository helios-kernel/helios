use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interest<Data> {
    pub fd: i32,
    pub events: u32,
    pub data: Data,
    pub one_shot: bool,
}
/// Registration state, owned and mutated by one process task. The adapter
/// translates ABI flags and supplies readiness and wake sources.
#[derive(Clone)]
pub struct InterestSet<Data> {
    pub interests: Vec<Interest<Data>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InterestError {
    #[error("descriptor already registered")]
    Exists,
    #[error("descriptor is not registered")]
    NotFound,
}
impl<Data> InterestSet<Data> {
    pub fn add(&mut self, interest: Interest<Data>) -> Result<(), InterestError> {
        if self.interests.iter().any(|entry| entry.fd == interest.fd) {
            return Err(InterestError::Exists);
        }
        self.interests.push(interest);
        Ok(())
    }
    pub fn modify(&mut self, interest: Interest<Data>) -> Result<(), InterestError> {
        let entry = self
            .interests
            .iter_mut()
            .find(|entry| entry.fd == interest.fd)
            .ok_or(InterestError::NotFound)?;
        *entry = interest;
        Ok(())
    }
    pub fn remove(&mut self, fd: i32) -> Result<(), InterestError> {
        let index = self
            .interests
            .iter()
            .position(|entry| entry.fd == fd)
            .ok_or(InterestError::NotFound)?;
        self.interests.remove(index);
        Ok(())
    }
}

/// Shared epoll object. Duplicating a descriptor shares registration state.
/// Every operation takes one bounded task-context lock and releases it before
/// a caller probes resources or suspends.
#[derive(Clone)]
pub struct Epoll<Data> {
    state: alloc::sync::Arc<spin::Mutex<EpollState<Data>>>,
}
impl<Data> Default for Epoll<Data> {
    fn default() -> Self {
        Self::new()
    }
}
impl<Data> Epoll<Data> {
    pub fn new() -> Self {
        Self {
            state: alloc::sync::Arc::new(spin::Mutex::new(EpollState {
                interests: InterestSet {
                    interests: Vec::new(),
                },
                disabled: Vec::new(),
            })),
        }
    }
    pub fn same_object(&self, other: &Self) -> bool {
        alloc::sync::Arc::ptr_eq(&self.state, &other.state)
    }
    pub fn add(&self, interest: Interest<Data>) -> Result<(), InterestError> {
        self.state.lock().interests.add(interest)
    }
    pub fn modify(&self, interest: Interest<Data>) -> Result<(), InterestError> {
        let mut state = self.state.lock();
        let fd = interest.fd;
        state.interests.modify(interest)?;
        state.disabled.retain(|disabled| *disabled != fd);
        Ok(())
    }
    pub fn remove(&self, fd: i32) -> Result<(), InterestError> {
        let mut state = self.state.lock();
        state.interests.remove(fd)?;
        state.disabled.retain(|disabled| *disabled != fd);
        Ok(())
    }
    pub fn delivered(&self, fd: i32) {
        let mut state = self.state.lock();
        if state
            .interests
            .interests
            .iter()
            .any(|interest| interest.fd == fd && interest.one_shot)
            && !state.disabled.contains(&fd)
        {
            state.disabled.push(fd);
        }
    }
}
struct EpollState<Data> {
    interests: InterestSet<Data>,
    disabled: Vec<i32>,
}
impl<Data: Clone> Epoll<Data> {
    /// All registrations, including disabled one-shot entries, for graph checks.
    pub fn registrations(&self) -> Vec<Interest<Data>> {
        self.state.lock().interests.interests.clone()
    }
    pub fn interests(&self) -> Vec<Interest<Data>> {
        let state = self.state.lock();
        state
            .interests
            .interests
            .iter()
            .filter(|interest| !state.disabled.contains(&interest.fd))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{Epoll, Interest, InterestError};

    #[test]
    fn one_shot_remains_registered_and_modify_rearms_shared_object() {
        let epoll = Epoll::new();
        let duplicate = epoll.clone();
        let interest = Interest {
            fd: 7,
            events: 1,
            data: 123,
            one_shot: true,
        };
        epoll.add(interest).unwrap();
        duplicate.delivered(7);
        assert!(epoll.interests().is_empty());
        assert_eq!(epoll.registrations(), alloc::vec![interest]);
        assert_eq!(epoll.add(interest), Err(InterestError::Exists));
        duplicate
            .modify(Interest {
                data: 456,
                ..interest
            })
            .unwrap();
        assert_eq!(epoll.interests()[0].data, 456);
        epoll.remove(7).unwrap();
        assert!(duplicate.interests().is_empty());
    }
}
