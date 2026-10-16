//! Mapping BPF load and attach errors to names and to the checks that explain them.

use crate::checks::PREFLIGHT_IDS;

/// Kernel-internal "operation not supported" (distinct from `EOPNOTSUPP`), which
/// leaks to user space from some BPF attach paths.
pub(crate) const ENOTSUPP: i32 = 524;

/// Symbolic name of an errno commonly returned by `bpf(2)` and perf attach, e.g.
/// `EPERM`. Accepts negated values as returned by raw syscalls.
pub fn errno_name(errno: i32) -> Option<&'static str> {
    Some(match errno.wrapping_abs() {
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::EINTR => "EINTR",
        libc::E2BIG => "E2BIG",
        libc::EBADF => "EBADF",
        libc::EAGAIN => "EAGAIN",
        libc::ENOMEM => "ENOMEM",
        libc::EACCES => "EACCES",
        libc::EFAULT => "EFAULT",
        libc::EBUSY => "EBUSY",
        libc::EEXIST => "EEXIST",
        libc::ENODEV => "ENODEV",
        libc::EINVAL => "EINVAL",
        libc::ENOSPC => "ENOSPC",
        libc::ERANGE => "ERANGE",
        libc::ENOSYS => "ENOSYS",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        ENOTSUPP => "ENOTSUPP",
        _ => return None,
    })
}

/// Shared check ids worth re-running after a BPF load or attach failure with
/// `errno` (negated values accepted). Unrecognised errnos map to the preflight set.
pub fn ids_for_errno(errno: i32) -> &'static [&'static str] {
    match errno.wrapping_abs() {
        libc::EPERM => &[
            "priv.capabilities",
            "priv.file_caps",
            "priv.nosuid",
            "priv.nnp",
            "sec.lockdown",
            "rlimit.memlock",
            "env.userns",
            "env.seccomp",
        ],
        libc::EACCES => &[
            "kernel.version",
            "kernel.btf",
            "priv.capabilities",
            "sec.lockdown",
            "sec.lsm",
        ],
        libc::EINVAL | libc::E2BIG => &[
            "platform.os_arch",
            "kernel.version",
            "kernel.btf",
            "probe.ringbuf",
        ],
        libc::ENOENT => &["kernel.version", "kernel.btf"],
        libc::ENOMEM => &["rlimit.memlock", "probe.memcg"],
        libc::ENOSYS => &["kernel.version", "env.seccomp"],
        libc::EOPNOTSUPP | ENOTSUPP => &["platform.os_arch", "kernel.version", "kernel.btf"],
        _ => &PREFLIGHT_IDS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_accept_negated_errnos() {
        assert_eq!(errno_name(libc::EPERM), Some("EPERM"));
        assert_eq!(errno_name(-libc::EACCES), Some("EACCES"));
        assert_eq!(errno_name(ENOTSUPP), Some("ENOTSUPP"));
        assert_eq!(errno_name(i32::MIN), None);
        assert_eq!(errno_name(4095), None);
    }
}
