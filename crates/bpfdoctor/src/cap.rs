//! Linux capabilities relevant to BPF tracing tools.

use std::fmt;

/// A Linux capability a BPF tool may need.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cap {
    /// `CAP_BPF` (5.8+): create maps and load programs.
    Bpf,
    /// `CAP_PERFMON` (5.8+): attach tracing programs.
    Perfmon,
    /// `CAP_SYS_ADMIN`: a superset of `CAP_BPF` and `CAP_PERFMON`.
    SysAdmin,
    /// `CAP_SYS_RESOURCE`: raise `RLIMIT_MEMLOCK`.
    SysResource,
    /// `CAP_SYS_PTRACE`: inspect other users' processes.
    SysPtrace,
    /// `CAP_SYSLOG`: read unmasked kernel addresses.
    Syslog,
    /// `CAP_DAC_READ_SEARCH`: bypass directory read and search permissions.
    DacReadSearch,
}

impl Cap {
    /// Every capability, in display order.
    pub const ALL: [Self; 7] = [
        Self::Bpf,
        Self::Perfmon,
        Self::SysAdmin,
        Self::SysResource,
        Self::SysPtrace,
        Self::Syslog,
        Self::DacReadSearch,
    ];

    /// Capability number, i.e. its bit position in capability masks.
    pub const fn bit(self) -> u32 {
        match self {
            Self::Bpf => 39,
            Self::Perfmon => 38,
            Self::SysAdmin => 21,
            Self::SysResource => 24,
            Self::SysPtrace => 19,
            Self::Syslog => 34,
            Self::DacReadSearch => 2,
        }
    }

    /// Single-bit mask for this capability.
    pub const fn mask(self) -> u64 {
        1 << self.bit()
    }

    /// Kernel name, e.g. `CAP_BPF`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bpf => "CAP_BPF",
            Self::Perfmon => "CAP_PERFMON",
            Self::SysAdmin => "CAP_SYS_ADMIN",
            Self::SysResource => "CAP_SYS_RESOURCE",
            Self::SysPtrace => "CAP_SYS_PTRACE",
            Self::Syslog => "CAP_SYSLOG",
            Self::DacReadSearch => "CAP_DAC_READ_SEARCH",
        }
    }

    /// Name as accepted by `setcap`, e.g. `cap_bpf`.
    pub const fn setcap_name(self) -> &'static str {
        match self {
            Self::Bpf => "cap_bpf",
            Self::Perfmon => "cap_perfmon",
            Self::SysAdmin => "cap_sys_admin",
            Self::SysResource => "cap_sys_resource",
            Self::SysPtrace => "cap_sys_ptrace",
            Self::Syslog => "cap_syslog",
            Self::DacReadSearch => "cap_dac_read_search",
        }
    }

    /// What the capability is needed for, phrased to follow its name.
    pub const fn rationale(self) -> &'static str {
        match self {
            Self::Bpf => "loads BPF programs and maps",
            Self::Perfmon => "attaches them to tracepoints",
            Self::SysAdmin => {
                "grants every BPF operation on kernels without CAP_BPF and CAP_PERFMON"
            }
            Self::SysResource => "lifts RLIMIT_MEMLOCK for BPF memory on kernels before 5.11",
            Self::SysPtrace => "reads other users' /proc entries (exe, cwd, environment)",
            Self::Syslog => "reads kernel addresses from /proc/kallsyms for symbolisation",
            Self::DacReadSearch => "resolves file handles and paths regardless of permissions",
        }
    }

    /// Whether capability mask `mask` grants this capability.
    ///
    /// `CAP_SYS_ADMIN` satisfies `CAP_BPF` and `CAP_PERFMON`, as the kernel's
    /// `bpf_capable()` and `perfmon_capable()` do.
    pub const fn granted_by(self, mask: u64) -> bool {
        mask & self.mask() != 0
            || (matches!(self, Self::Bpf | Self::Perfmon) && mask & Self::SysAdmin.mask() != 0)
    }
}

impl fmt::Display for Cap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// `CAP_BPF, CAP_PERFMON`.
pub(crate) fn names(caps: &[Cap]) -> String {
    join(caps.iter().map(|cap| cap.name()), ", ")
}

/// `cap_bpf,cap_perfmon`, as `setcap` expects.
pub(crate) fn setcap_list(caps: &[Cap]) -> String {
    join(caps.iter().map(|cap| cap.setcap_name()), ",")
}

/// `CAP_BPF loads ...; CAP_PERFMON attaches ...`.
pub(crate) fn rationale(caps: &[Cap]) -> String {
    caps.iter()
        .map(|cap| format!("{cap} {}", cap.rationale()))
        .collect::<Vec<_>>()
        .join("; ")
}

fn join<'a>(parts: impl Iterator<Item = &'a str>, sep: &str) -> String {
    parts.collect::<Vec<_>>().join(sep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sys_admin_implies_bpf_and_perfmon_only() {
        let admin = Cap::SysAdmin.mask();
        assert!(Cap::Bpf.granted_by(admin));
        assert!(Cap::Perfmon.granted_by(admin));
        assert!(!Cap::SysResource.granted_by(admin));
        assert!(!Cap::SysAdmin.granted_by(Cap::Bpf.mask() | Cap::Perfmon.mask()));
    }

    #[test]
    fn bits_match_linux_capability_numbers() {
        assert_eq!(Cap::Bpf.mask(), 1 << 39);
        assert_eq!(Cap::Perfmon.mask(), 1 << 38);
        assert_eq!(Cap::DacReadSearch.mask(), 1 << 2);
        let unique: std::collections::HashSet<u32> = Cap::ALL.iter().map(|c| c.bit()).collect();
        assert_eq!(unique.len(), Cap::ALL.len());
    }
}
