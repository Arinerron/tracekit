use crate::{Pid, ProcKey};

/// A `fork`/`clone` reported by the producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkEvent {
    /// Event timestamp.
    pub ts_ns: u64,
    /// Thread-group id of the forking process.
    pub parent: Pid,
    /// The new process (or thread: see `is_thread`).
    pub child: ProcKey,
    /// The clone created a thread in the parent's group (`CLONE_THREAD`). Such events
    /// create no record.
    pub is_thread: bool,
}

/// An `execve` that succeeded.
///
/// Byte fields borrow from the producer's buffer. `None` means the producer did not
/// capture that field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecEvent<'a> {
    /// Event timestamp.
    pub ts_ns: u64,
    /// The process that exec'd: its thread-group id and the group leader's start.
    pub key: ProcKey,
    /// Parent pid.
    pub ppid: Option<Pid>,
    /// New `comm`. If absent, the table derives it from `filename` as the kernel does.
    pub comm: Option<&'a [u8]>,
    /// Path passed to `execve`.
    pub filename: Option<&'a [u8]>,
    /// NUL-separated arguments (a trailing NUL is optional).
    pub argv: Option<&'a [u8]>,
    /// Working directory.
    pub cwd: Option<&'a [u8]>,
    /// NUL-separated `KEY=VALUE` environment. It may be pre-filtered to
    /// [`ENV_KEYS`](crate::ENV_KEYS).
    pub env: Option<&'a [u8]>,
    /// The producer cut `argv` short.
    pub argv_truncated: bool,
    /// cgroup v2 id (`bpf_get_current_cgroup_id`).
    pub cgroup_id: Option<u64>,
    /// Real user id.
    pub uid: Option<u32>,
    /// Real group id.
    pub gid: Option<u32>,
}

impl ExecEvent<'_> {
    /// An exec with only a timestamp and key; set the captured fields with struct
    /// update syntax.
    pub fn new(ts_ns: u64, key: ProcKey) -> Self {
        Self {
            ts_ns,
            key,
            ppid: None,
            comm: None,
            filename: None,
            argv: None,
            cwd: None,
            env: None,
            argv_truncated: false,
            cgroup_id: None,
            uid: None,
            gid: None,
        }
    }
}

/// The exit of a whole process (the last thread of its group).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitEvent {
    /// Event timestamp.
    pub ts_ns: u64,
    /// The process that exited. The start disambiguates a late event from a newer
    /// process that already reuses the pid.
    pub key: ProcKey,
    /// Exit status (normally the kernel's `task->exit_code`).
    pub code: i32,
}
