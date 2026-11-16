//! Capability bridge for optional UNIX process bookkeeping.
#[cfg(test)]
mod process_tests {
    use crate::{
        DirectoryAuthorityRights, DirectoryPreopen, ProcessAuthority, ProcessAuthorityRights,
    };
    use helios_unix::{ProcessState, ProcessTable, ProcessTableError};

    fn authority_with(rights: ProcessAuthorityRights) -> ProcessAuthority {
        let mut authority = ProcessAuthority::empty();
        authority.grant_process_rights(rights);
        authority
    }

    #[test]
    fn spawn_requires_child_authority_subset() {
        let mut table = ProcessTable::new();
        let mut parent_authority = authority_with(ProcessAuthorityRights::SPAWN);
        parent_authority.insert_directory_preopen(
            DirectoryPreopen::new("/bin", "/", DirectoryAuthorityRights::READ)
                .expect("test preopen should be valid"),
        );
        let spawn = parent_authority
            .derive_spawn_authority()
            .expect("parent should derive spawn authority");
        let parent = table
            .register_root(parent_authority)
            .expect("root registration should succeed");

        let mut child_authority = ProcessAuthority::empty();
        child_authority.insert_directory_preopen(
            DirectoryPreopen::new("/bin", "/", DirectoryAuthorityRights::READ)
                .expect("test preopen should be valid"),
        );
        let child = table
            .spawn(&spawn, parent, child_authority)
            .expect("subset child authority should spawn");
        assert_eq!(table.record(child).unwrap().parent(), Some(parent));

        let mut overgrant = ProcessAuthority::empty();
        overgrant.insert_directory_preopen(
            DirectoryPreopen::new("/bin", "/", DirectoryAuthorityRights::WRITE)
                .expect("test preopen should be valid"),
        );
        assert_eq!(
            table.spawn(&spawn, parent, overgrant),
            Err(ProcessTableError::AuthorityWidening)
        );
    }

    #[test]
    fn spawn_with_empty_child_authority_has_zero_ambient_rights() {
        let mut table = ProcessTable::new();
        let parent_authority = ProcessAuthority::root();
        let spawn = parent_authority
            .derive_spawn_authority()
            .expect("root should derive spawn authority");
        let parent = table
            .register_root(parent_authority)
            .expect("root registration should succeed");

        let child = table
            .spawn(&spawn, parent, ProcessAuthority::empty())
            .expect("empty child authority should be a valid subset");
        assert_eq!(
            table.record(child).unwrap().authority(),
            &ProcessAuthority::empty()
        );
    }

    #[test]
    fn fork_inherits_and_exec_preserves_authority() {
        let mut table = ProcessTable::new();
        let authority = authority_with(ProcessAuthorityRights::FORK | ProcessAuthorityRights::EXEC);
        let fork = authority
            .derive_fork_authority()
            .expect("parent should derive fork authority");
        let exec = authority
            .derive_exec_authority()
            .expect("parent should derive exec authority");
        let parent = table
            .register_root(authority.clone())
            .expect("root registration should succeed");
        let child = table
            .fork(&fork, parent)
            .expect("fork should inherit parent authority");

        assert_eq!(table.record(child).unwrap().authority(), &authority);
        table
            .exec(&exec, child)
            .expect("exec should preserve authority");
        assert_eq!(table.record(child).unwrap().authority(), &authority);
    }

    #[test]
    fn join_and_signal_require_typed_caps() {
        let mut table = ProcessTable::new();
        let authority =
            authority_with(ProcessAuthorityRights::JOIN | ProcessAuthorityRights::SIGNAL);
        let join = authority
            .derive_join_authority()
            .expect("join authority should derive");
        let signal = authority
            .derive_signal_authority()
            .expect("signal authority should derive");
        let process = table
            .register_root(authority)
            .expect("root registration should succeed");

        assert_eq!(table.join(&join, process).unwrap(), None);
        table.signal(&signal, process, 9).unwrap();
        assert_eq!(
            table.record(process).unwrap().state(),
            ProcessState::Signaled(9)
        );
        assert_eq!(table.join(&join, process).unwrap(), None);
        table.exit(process, 7).unwrap();
        assert_eq!(table.join(&join, process).unwrap(), Some(7));
    }
}

#[cfg(test)]
mod thread_tests {
    use crate::{ProcessAuthority, ProcessAuthorityRights};
    use helios_unix::{ProcessId, ProcessTable, ThreadState, ThreadTable};

    fn process(raw: u64) -> ProcessId {
        let mut table = ProcessTable::new();
        let mut authority = ProcessAuthority::empty();
        authority.grant_process_rights(ProcessAuthorityRights::SPAWN);
        let process = table.register_root(authority).unwrap();
        assert_eq!(process.raw(), raw);
        process
    }

    #[test]
    fn thread_lifecycle_tracks_join_state() {
        let mut table = ThreadTable::new();
        let thread = table.spawn(process(1)).unwrap();

        assert_eq!(table.join(thread), Ok(None));
        table.exit(thread, 7).unwrap();
        assert_eq!(table.join(thread), Ok(Some(7)));
    }

    #[test]
    fn sleeping_threads_wake_when_deadline_passes() {
        let mut table = ThreadTable::new();
        let thread = table.spawn(process(1)).unwrap();
        table.set_sleeping(thread, 50).unwrap();

        assert_eq!(table.wake_due(49), 0);
        assert_eq!(
            table.record(thread).unwrap().state(),
            ThreadState::Sleeping { wake_at_nanos: 50 }
        );
        assert_eq!(table.wake_due(50), 1);
        assert_eq!(table.record(thread).unwrap().state(), ThreadState::Runnable);
    }

    #[test]
    fn process_parallelism_counts_live_threads() {
        let mut table = ThreadTable::new();
        let first = table.spawn(process(1)).unwrap();
        let second = table.spawn(process(1)).unwrap();
        table.spawn(process(1)).unwrap();

        assert_eq!(table.process_parallelism(process(1)), 3);
        table.exit(first, 0).unwrap();
        assert_eq!(table.process_parallelism(process(1)), 2);
        table.signal(second, 9).unwrap();
        assert_eq!(table.process_parallelism(process(1)), 2);
    }
}

impl helios_unix::ProcessPermissions for crate::ProcessAuthority {
    type Spawn = crate::SpawnAuthority;
    type Fork = crate::ForkAuthority;
    type Exec = crate::ExecAuthority;
    type Join = crate::JoinAuthority;
    type Signal = crate::SignalAuthority;
    fn contains_authority(&self, child: &Self) -> bool {
        self.contains_authority(child)
    }
}
