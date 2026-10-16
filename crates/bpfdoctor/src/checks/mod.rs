//! The shared checks, in display order.

mod isolation;
mod platform;
mod privilege;
mod security;
mod system;

use std::path::Path;

use crate::{BpfProbe, Cap, Check, Diagnostic, Env, Status, Tool, errno_name, parse_release};

/// A built-in check: static metadata plus the function that evaluates it.
#[derive(Clone, Copy)]
pub(crate) struct Shared {
    id: &'static str,
    title: &'static str,
    required: bool,
    run: fn(&Shared, &dyn Env, &Tool) -> Diagnostic,
}

impl Shared {
    /// A diagnostic for this check with the given outcome.
    fn diag(&self, status: Status, observed: impl Into<String>) -> Diagnostic {
        Diagnostic::new(self.id, self.title, self.required, status, observed)
    }
}

impl Check for Shared {
    fn id(&self) -> &'static str {
        self.id
    }

    fn run(&self, env: &dyn Env, tool: &Tool) -> Diagnostic {
        (self.run)(self, env, tool)
    }
}

/// Every shared check, in display order.
pub(crate) static SHARED: [Shared; 23] = [
    Shared {
        id: "platform.os_arch",
        title: "Operating system and architecture",
        required: true,
        run: platform::os_arch,
    },
    Shared {
        id: "kernel.version",
        title: "Kernel version",
        required: true,
        run: platform::kernel_version,
    },
    Shared {
        id: "kernel.btf",
        title: "Kernel BTF",
        required: true,
        run: platform::kernel_btf,
    },
    Shared {
        id: "priv.capabilities",
        title: "Required capabilities",
        required: true,
        run: privilege::capabilities,
    },
    Shared {
        id: "priv.file_caps",
        title: "File capabilities",
        required: false,
        run: privilege::file_caps,
    },
    Shared {
        id: "priv.nosuid",
        title: "nosuid mount",
        required: true,
        run: privilege::nosuid,
    },
    Shared {
        id: "priv.nnp",
        title: "no_new_privs",
        required: false,
        run: privilege::nnp,
    },
    Shared {
        id: "priv.optional_caps",
        title: "Optional capabilities",
        required: false,
        run: privilege::optional_caps,
    },
    Shared {
        id: "priv.sudo",
        title: "sudo",
        required: false,
        run: privilege::sudo,
    },
    Shared {
        id: "sec.lockdown",
        title: "Kernel lockdown",
        required: false,
        run: security::lockdown,
    },
    Shared {
        id: "sec.lsm",
        title: "Linux security modules",
        required: false,
        run: security::lsm,
    },
    Shared {
        id: "sysctl.unpriv_bpf",
        title: "kernel.unprivileged_bpf_disabled",
        required: false,
        run: security::unpriv_bpf,
    },
    Shared {
        id: "sysctl.perf_paranoid",
        title: "kernel.perf_event_paranoid",
        required: false,
        run: security::perf_paranoid,
    },
    Shared {
        id: "sysctl.jit",
        title: "BPF JIT",
        required: false,
        run: security::jit,
    },
    Shared {
        id: "rlimit.memlock",
        title: "Locked-memory limit",
        required: true,
        run: system::memlock,
    },
    Shared {
        id: "env.userns",
        title: "User namespace",
        required: true,
        run: isolation::userns,
    },
    Shared {
        id: "env.pidns",
        title: "PID namespace",
        required: true,
        run: isolation::pidns,
    },
    Shared {
        id: "env.container",
        title: "Container",
        required: false,
        run: isolation::container,
    },
    Shared {
        id: "env.seccomp",
        title: "Seccomp",
        required: true,
        run: isolation::seccomp,
    },
    Shared {
        id: "fs.cgroup2",
        title: "cgroup v2",
        required: false,
        run: system::cgroup2,
    },
    Shared {
        id: "fs.proc_hidepid",
        title: "/proc hidepid",
        required: false,
        run: system::proc_hidepid,
    },
    Shared {
        id: "probe.ringbuf",
        title: "BPF ring buffer",
        required: true,
        run: system::ringbuf,
    },
    Shared {
        id: "probe.memcg",
        title: "BPF memcg accounting",
        required: false,
        run: system::memcg,
    },
];

/// Ids of the fast checks run before every start.
pub(crate) const PREFLIGHT_IDS: [&str; 9] = [
    "platform.os_arch",
    "kernel.version",
    "kernel.btf",
    "priv.capabilities",
    "priv.nosuid",
    "priv.nnp",
    "sec.lockdown",
    "env.userns",
    "env.pidns",
];

const PROC_STATUS: &str = "/proc/self/status";

/// First kernel that charges BPF memory to memcg instead of `RLIMIT_MEMLOCK`.
const MEMCG_KERNEL: (u32, u32) = (5, 11);

/// Reads a file as (lossy) UTF-8.
fn read_text(env: &dyn Env, path: &str) -> Option<String> {
    env.read(Path::new(path))
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Reads a single-value file such as a sysctl, trimmed.
fn read_value(env: &dyn Env, path: &str) -> Option<String> {
    read_text(env, path).map(|text| text.trim().to_owned())
}

/// The capabilities in `caps` that capability mask `mask` does not grant.
fn missing_caps(mask: u64, caps: &[Cap]) -> Vec<Cap> {
    caps.iter()
        .copied()
        .filter(|cap| !cap.granted_by(mask))
        .collect()
}

/// Whether every capability the tool requires is effective.
fn privileged(env: &dyn Env, tool: &Tool) -> bool {
    let effective = env.caps().effective;
    tool.required_caps
        .iter()
        .all(|cap| cap.granted_by(effective))
}

fn kernel_at_least(env: &dyn Env, version: (u32, u32)) -> bool {
    parse_release(&env.uname().release).is_some_and(|(major, minor, _)| (major, minor) >= version)
}

/// Whether BPF memory is charged to memcg; `None` when the probe was refused
/// for lack of privilege and so says nothing about the kernel.
fn memcg_accounting(env: &dyn Env) -> Option<bool> {
    match env.bpf_probe(BpfProbe::MemcgAccounting) {
        Ok(()) => Some(true),
        Err(libc::EPERM | libc::EACCES) => None,
        Err(_) => Some(false),
    }
}

/// `EPERM`, or `errno 4000` for unnamed values.
fn errno_label(errno: i32) -> String {
    errno_name(errno).map_or_else(|| format!("errno {errno}"), str::to_owned)
}

/// `sudo whytime ...`.
fn sudo_tool(tool: &Tool) -> String {
    format!("sudo {} ...", tool.name)
}
