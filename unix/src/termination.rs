/// Termination by a signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalTermination {
    pub signal: u8,
    pub core_dumped: bool,
}

/// How a child program ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildTermination {
    /// The program exited of its own accord with this status code.
    Exited(u32),
    /// A signal ended the program.
    Signaled(SignalTermination),
    /// The program trapped.
    Trapped,
    /// The program's owner killed it.
    Killed,
}
