//! Namespaces, containers and seccomp.

use std::path::Path;

use super::{PROC_STATUS, Shared, privileged, read_text};
use crate::env::status_field;
use crate::{BpfProbe, Diagnostic, Env, Fix, Status, Tool};

const UID_MAP: &str = "/proc/self/uid_map";
const INIT_CGROUP: &str = "/proc/1/cgroup";
const CONTAINER_MARKERS: [&str; 2] = ["/.dockerenv", "/run/.containerenv"];
/// Substrings of `/proc/1/cgroup` paths and the runtime they indicate.
const CGROUP_RUNTIMES: [(&str, &str); 6] = [
    ("/docker", "docker"),
    ("/kubepods", "kubernetes"),
    ("/libpod", "podman"),
    ("/lxc", "lxc"),
    ("containerd", "containerd"),
    ("crio-", "cri-o"),
];
const CONTAINER_RECIPE: &str = "docker run --cap-add BPF --cap-add PERFMON --pid=host -v /sys/kernel/btf:/sys/kernel/btf:ro ...";

pub(super) fn userns(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    let Some(map) = read_text(env, UID_MAP) else {
        return check.diag(Status::Skip, format!("{UID_MAP} not readable"));
    };
    if map.split_whitespace().eq(["0", "0", "4294967295"]) {
        return check.diag(Status::Pass, "initial user namespace");
    }
    check
        .diag(Status::Fail, "running inside a user namespace; capabilities there do not grant BPF")
        .with_impact(format!("{} cannot load BPF programs", tool.name))
        .with_fix(Fix::new(
            "run on the host, or in a container started with --cap-add BPF --cap-add PERFMON --pid=host",
            "",
        ))
}

pub(super) fn pidns(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    let Some(status) = read_text(env, PROC_STATUS) else {
        return check.diag(Status::Skip, format!("{PROC_STATUS} not readable"));
    };
    let Some(nspid) = status_field(&status, "NSpid") else {
        return check.diag(Status::Skip, "NSpid not reported (kernel before 4.1)");
    };
    let pids: Vec<&str> = nspid.split_whitespace().collect();
    if pids.len() <= 1 {
        return check.diag(Status::Pass, "initial PID namespace");
    }
    check
        .diag(
            Status::Fail,
            format!(
                "nested PID namespace: kernel pids differ from /proc pids (NSpid {})",
                pids.join(" ")
            ),
        )
        .with_impact(format!(
            "{} cannot match kernel-reported pids to processes",
            tool.name
        ))
        .with_fix(Fix::new(
            "docker run --pid=host ...",
            "Kubernetes: hostPID: true",
        ))
}

pub(super) fn container(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    let evidence = CONTAINER_MARKERS
        .into_iter()
        .find(|marker| env.exists(Path::new(marker)))
        .map(str::to_owned)
        .or_else(|| {
            let cgroup = read_text(env, INIT_CGROUP)?;
            CGROUP_RUNTIMES
                .iter()
                .find(|(pattern, _)| cgroup.contains(pattern))
                .map(|(_, runtime)| format!("{runtime} cgroup"))
        });
    match evidence {
        None => check.diag(Status::Pass, "not running in a container"),
        Some(evidence) => check
            .diag(Status::Info, format!("running in a container ({evidence})"))
            .with_fix(Fix::new(
                CONTAINER_RECIPE,
                format!("the privileges and mounts {} needs", tool.name),
            )),
    }
}

pub(super) fn seccomp(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    let Some(status) = read_text(env, PROC_STATUS) else {
        return check.diag(Status::Skip, format!("{PROC_STATUS} not readable"));
    };
    let Some(mode) = status_field(&status, "Seccomp") else {
        return check.diag(Status::Skip, "seccomp mode not reported");
    };
    if mode == "0" {
        return check.diag(Status::Pass, "no seccomp filter");
    }
    // Only with capabilities in effect does EPERM point at the filter.
    if privileged(env, tool) {
        match env.bpf_probe(BpfProbe::RingBuf) {
            Err(libc::EPERM) => {
                return check
                    .diag(
                        Status::Fail,
                        "seccomp filter blocks bpf() (EPERM despite capabilities)",
                    )
                    .with_impact(format!("{} cannot load BPF programs", tool.name))
                    .with_fix(Fix::new(
                        "docker run --cap-add BPF --cap-add PERFMON ...",
                        "Docker's default seccomp profile permits bpf() with CAP_BPF",
                    ))
                    .with_fix(Fix::new(
                        "docker run --security-opt seccomp=unconfined ...",
                        "disables syscall filtering for the whole container",
                    ));
            }
            Ok(()) => {
                return check.diag(
                    Status::Info,
                    format!("seccomp filter active (mode {mode}); bpf() allowed"),
                );
            }
            Err(_) => {}
        }
    }
    check.diag(Status::Info, format!("seccomp filter active (mode {mode})"))
}
