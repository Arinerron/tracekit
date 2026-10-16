use std::{ffi::OsStr, num::NonZeroU64, path::Path, sync::Arc};

use crate::{CgroupInfo, EnvFacts};

/// Kernel process id (the thread-group id for multi-threaded processes).
pub type Pid = u32;

/// Identity of one process lifetime: a pid plus its start time.
///
/// Pids are recycled; `(pid, start)` is not. `start` is opaque to this crate
/// except for ordering: the table compares starts to tell which process held a
/// pid when a child forked, so every producer of keys (fork/exec/exit events and
/// `/proc` reads) must use one clock. The table converts `/proc` start ticks into
/// that clock through [`Config::start_clock`](crate::Config::start_clock).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ProcKey {
    /// Process id.
    pub pid: Pid,
    /// Start time in the clock selected by [`StartClock`].
    pub start: u64,
}

const NANOS_PER_SEC: u128 = 1_000_000_000;

/// The clock of [`ProcKey::start`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum StartClock {
    /// Clock ticks since boot, exactly `/proc/<pid>/stat` field 22 (`starttime`).
    #[default]
    Ticks,
    /// Nanoseconds since boot, as in the kernel's `task->start_boottime`; `/proc` exposes
    /// it in ticks. Use [`ProcFs::clock_ticks_per_sec`](crate::ProcFs::clock_ticks_per_sec)
    /// to get the kernel's `USER_HZ` rather than assuming it. Do not use
    /// `task->start_time` here: that clock stops during suspend, but `/proc` does not.
    BootNs {
        /// Kernel `USER_HZ` (`AT_CLKTCK`).
        ticks_per_sec: NonZeroU64,
    },
}

impl StartClock {
    /// Converts a key start into `/proc` clock ticks. A `BootNs` start rounds down,
    /// exactly as the kernel rounds `start_boottime` when it formats `starttime`.
    pub fn start_to_ticks(self, start: u64) -> u64 {
        match self {
            Self::Ticks => start,
            Self::BootNs { ticks_per_sec } => {
                let ticks = u128::from(start) * u128::from(ticks_per_sec.get()) / NANOS_PER_SEC;
                u64::try_from(ticks).unwrap_or(u64::MAX)
            }
        }
    }

    /// Converts `/proc` clock ticks into a key start. A `BootNs` start rounds up, so
    /// [`start_to_ticks`](Self::start_to_ticks) maps the result back to `ticks` exactly.
    pub fn ticks_to_start(self, ticks: u64) -> u64 {
        match self {
            Self::Ticks => ticks,
            Self::BootNs { ticks_per_sec } => {
                let nanos =
                    (u128::from(ticks) * NANOS_PER_SEC).div_ceil(u128::from(ticks_per_sec.get()));
                u64::try_from(nanos).unwrap_or(u64::MAX)
            }
        }
    }
}

/// Where a record's fields came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// Only fork/exec/comm/exit events, or inheritance from an event-sourced parent.
    Event,
    /// Only `/proc`.
    Procfs,
    /// Events plus `/proc` reads, or inheritance from a parent that used `/proc`.
    Mixed,
}

impl Source {
    /// The source after adding facts from `other` to a record built from `self`.
    pub(crate) fn merge(self, other: Self) -> Self {
        if self == other { self } else { Self::Mixed }
    }
}

/// How and when a process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExitInfo {
    /// Exit timestamp, in the producer's event clock. For an inferred exit (see
    /// [`code`](Self::code)) it is the newest event timestamp the table had seen when it
    /// noticed, which is an upper bound. It is 0 if no event had been seen yet.
    pub ts_ns: u64,
    /// Exit status as the producer reported it (normally the kernel's
    /// `task->exit_code`, a `wait(2)`-style status). `None` means the exit was inferred
    /// from pid reuse or a zombie in `/proc`, and no exit event has supplied the status.
    pub code: Option<i32>,
}

/// Everything known about one process lifetime.
///
/// Records are shared (`Arc`) and immutable once handed out; the table copies on
/// write when later events update a record that a caller still holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    /// Identity of this process lifetime.
    pub key: ProcKey,
    /// Parent at fork time. `Some(0)` means no parent (init, kthreadd). `None` means
    /// unknown: no fork event or exec ppid was seen and `/proc` was not read. This
    /// keeps the original parent after re-parenting, so ancestry follows real lineage.
    pub ppid: Option<Pid>,
    /// Command name (kernel `comm`, at most 15 bytes, lossily decoded). Empty if unknown.
    pub comm: Arc<str>,
    /// Executable. From an exec event this is the filename passed to `execve` (it may
    /// be relative). From `/proc` it is the resolved `exe` link. `None` means unknown,
    /// a kernel thread, or unreadable.
    pub exe: Option<Arc<Path>>,
    /// Arguments, capped at [`Config::max_argv_bytes`](crate::Config::max_argv_bytes).
    /// Empty when unknown, or for kernel threads and zombies.
    pub argv: Arc<[Box<OsStr>]>,
    /// `argv` lost bytes, either to the producer's limit or to `max_argv_bytes`.
    pub argv_truncated: bool,
    /// Working directory. `None` means unknown or unreadable.
    pub cwd: Option<Arc<Path>>,
    /// Real user id. `None` means unknown.
    pub uid: Option<u32>,
    /// Real group id. `None` means unknown.
    pub gid: Option<u32>,
    /// Session id. `None` means unknown (`/proc` not read).
    pub sid: Option<Pid>,
    /// Process group id. `None` means unknown (`/proc` not read).
    pub pgid: Option<Pid>,
    /// Controlling terminal as encoded in `/proc/<pid>/stat` (0 means none). `None`
    /// means unknown (`/proc` not read).
    pub tty_nr: Option<u32>,
    /// Cgroup v2 membership. `None` means unknown, still unresolved, or not cgroup v2.
    pub cgroup: Option<Arc<CgroupInfo>>,
    /// Allow-listed environment facts. `None` means the environment was not captured:
    /// the exec event carried none, `/proc` was unreadable, or
    /// [`Config::read_environ`](crate::Config::read_environ) is off.
    pub env: Option<Arc<EnvFacts>>,
    /// Set once the process has exited. `None` means it is believed alive.
    pub exit: Option<ExitInfo>,
    /// Where the fields came from.
    pub source: Source,
    /// Timestamp of the exec that loaded the current image. `None` means no exec
    /// event was seen, including for a forked child that has not exec'd.
    pub exec_ts_ns: Option<u64>,
    /// Timestamp of the fork that created the process. `None` means no fork event was seen.
    pub fork_ts_ns: Option<u64>,
}

impl ProcInfo {
    /// Whether no exit has been recorded or inferred.
    pub fn is_alive(&self) -> bool {
        self.exit.is_none()
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::StartClock;

    fn boot_ns(hz: u64) -> StartClock {
        StartClock::BootNs {
            ticks_per_sec: NonZeroU64::new(hz).unwrap(),
        }
    }

    #[test]
    fn boot_ns_matches_kernel_rounding() {
        let clock = boot_ns(100);
        // starttime = start_boottime / (NSEC_PER_SEC / USER_HZ), truncating.
        assert_eq!(clock.start_to_ticks(19_999_999), 1);
        assert_eq!(clock.start_to_ticks(20_000_000), 2);
        assert_eq!(clock.ticks_to_start(2), 20_000_000);
    }

    #[test]
    fn ticks_round_trip_for_non_divisor_hz() {
        for hz in [100, 250, 300, 1024] {
            let clock = boot_ns(hz);
            for ticks in [0, 1, 7, 12_345, u64::from(u32::MAX)] {
                assert_eq!(
                    clock.start_to_ticks(clock.ticks_to_start(ticks)),
                    ticks,
                    "hz={hz}"
                );
            }
        }
    }

    #[test]
    fn huge_values_saturate() {
        assert_eq!(boot_ns(100).ticks_to_start(u64::MAX), u64::MAX);
        assert_eq!(StartClock::Ticks.ticks_to_start(42), 42);
        assert_eq!(StartClock::Ticks.start_to_ticks(42), 42);
    }
}
