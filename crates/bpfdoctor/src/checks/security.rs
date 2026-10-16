//! Kernel lockdown, LSMs and BPF-related sysctls.

use super::{Shared, read_text, read_value};
use crate::{Cap, Diagnostic, Env, Fix, Status, Tool};

const LOCKDOWN: &str = "/sys/kernel/security/lockdown";
const LSM_LIST: &str = "/sys/kernel/security/lsm";
const SELINUX_ENFORCE: &str = "/sys/fs/selinux/enforce";
const UNPRIV_BPF: &str = "/proc/sys/kernel/unprivileged_bpf_disabled";
const PERF_PARANOID: &str = "/proc/sys/kernel/perf_event_paranoid";
const BPF_JIT: &str = "/proc/sys/net/core/bpf_jit_enable";

pub(super) fn lockdown(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    let Some(text) = read_text(env, LOCKDOWN) else {
        return check.diag(
            Status::Info,
            format!("lockdown state unknown ({LOCKDOWN} not readable)"),
        );
    };
    // The active mode is the bracketed one: "none [integrity] confidentiality".
    let active = text
        .split_whitespace()
        .find_map(|mode| mode.strip_prefix('[')?.strip_suffix(']'));
    match active {
        Some("none") => check.diag(Status::Pass, "lockdown: none"),
        Some("integrity") => check.diag(Status::Pass, "lockdown: integrity (no impact)"),
        Some("confidentiality") => check
            .diag(Status::Warn, "lockdown: confidentiality")
            .with_impact(format!(
                "bpf_probe_read_kernel and kprobes are disabled; {} runs with reduced detail",
                tool.name
            ))
            .with_fix(Fix::new(
                "none at runtime; lockdown is set by Secure Boot policy \
                 (boot param lockdown=integrity if your policy allows)",
                "",
            )),
        _ => check.diag(
            Status::Info,
            format!("unrecognised lockdown state {:?}", text.trim()),
        ),
    }
}

pub(super) fn lsm(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    if read_value(env, SELINUX_ENFORCE).as_deref() == Some("1") {
        return check
            .diag(Status::Info, "SELinux enforcing")
            .with_fix(Fix::new(
                format!("sudo ausearch -m avc -c {}", tool.name),
                "if loading fails with EACCES; lists the SELinux denials",
            ));
    }
    match read_value(env, LSM_LIST) {
        Some(list) => check.diag(
            Status::Pass,
            format!("SELinux not enforcing; active LSMs: {list}"),
        ),
        None => check.diag(Status::Pass, "SELinux not enforcing"),
    }
}

pub(super) fn unpriv_bpf(check: &Shared, env: &dyn Env, _: &Tool) -> Diagnostic {
    match read_value(env, UNPRIV_BPF) {
        Some(value) => check
            .diag(
                Status::Info,
                format!("kernel.unprivileged_bpf_disabled = {value}"),
            )
            .with_explain(
                "unprivileged BPF never allows tracing programs; leave this setting alone",
            ),
        None => check.diag(
            Status::Skip,
            "kernel.unprivileged_bpf_disabled not readable",
        ),
    }
}

pub(super) fn perf_paranoid(check: &Shared, env: &dyn Env, _: &Tool) -> Diagnostic {
    let Some(value) = read_value(env, PERF_PARANOID) else {
        return check.diag(Status::Skip, "kernel.perf_event_paranoid not readable");
    };
    if Cap::Perfmon.granted_by(env.caps().effective) {
        check.diag(
            Status::Pass,
            format!("kernel.perf_event_paranoid = {value}; ignored because CAP_PERFMON is present"),
        )
    } else {
        check.diag(
            Status::Info,
            format!("kernel.perf_event_paranoid = {value}; ignored when CAP_PERFMON is present"),
        )
    }
}

pub(super) fn jit(check: &Shared, env: &dyn Env, _: &Tool) -> Diagnostic {
    match read_value(env, BPF_JIT).as_deref() {
        Some("0") => check
            .diag(Status::Warn, "BPF JIT disabled (~10x overhead)")
            .with_fix(Fix::new(
                "sudo sysctl -w net.core.bpf_jit_enable=1",
                "add net.core.bpf_jit_enable=1 to /etc/sysctl.d/ to persist",
            )),
        Some(value) => check.diag(Status::Pass, format!("net.core.bpf_jit_enable = {value}")),
        None => check.diag(Status::Skip, "net.core.bpf_jit_enable not readable"),
    }
}
