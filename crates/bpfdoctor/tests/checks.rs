//! Every shared check against fixtures: a passing path and a non-passing path each.

mod common;

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use bpfdoctor::{
    BpfProbe, Cap, CapSets, Diagnostic, Doctor, FileCaps, FixtureEnv, Ids, MountFlags, Status, Tool,
};
use common::{host, tool};

const EXE: &str = "/usr/local/bin/whytime";
const BPF_PERFMON: u64 = Cap::Bpf.mask() | Cap::Perfmon.mask();
const SETCAP: &str = "sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/whytime";
/// A `cargo install` target on a nosuid `/home`.
const CARGO_EXE: &str = "/home/me/.cargo/bin/whytime";
const NOSUID: MountFlags = MountFlags {
    nosuid: true,
    readonly: false,
};
const RECIPE: &str = "docker run --cap-add BPF --cap-add PERFMON --pid=host -v /sys/kernel/btf:/sys/kernel/btf:ro ...";
/// Docker's default capability set, which is also its bounding set.
const DOCKER_CAPS: u64 = 0xa804_25fb;

fn user() -> Ids {
    Ids {
        uid: 1000,
        euid: 1000,
        gid: 1000,
        egid: 1000,
        sudo_uid: None,
        sudo_user: None,
    }
}

fn caps(effective: u64) -> CapSets {
    CapSets {
        effective,
        permitted: effective,
        bounding: (1 << 41) - 1,
    }
}

/// File capabilities installed with `setcap …+ep`.
fn ep(permitted: u64) -> FileCaps {
    FileCaps {
        permitted,
        effective: true,
    }
}

fn cargo_tool() -> Tool {
    Tool {
        exe: CARGO_EXE.into(),
        ..tool()
    }
}

/// Root in a default Docker container, whose bounding set lacks every BPF capability.
fn docker_root() -> FixtureEnv {
    host()
        .with_caps(CapSets {
            effective: DOCKER_CAPS,
            permitted: DOCKER_CAPS,
            bounding: DOCKER_CAPS,
        })
        .with_file("/.dockerenv", "")
}

/// A non-root user without capabilities.
fn unprivileged() -> FixtureEnv {
    host().with_ids(user()).with_caps(caps(0))
}

/// A non-root user whose executable carries working file capabilities.
fn setcap_user() -> FixtureEnv {
    host()
        .with_ids(user())
        .with_caps(caps(BPF_PERFMON))
        .with_file_caps(EXE, ep(BPF_PERFMON))
}

fn proc_status(nspid: &str, seccomp: u8) -> String {
    format!(
        "Name:\twhytime\nNSpid:\t{nspid}\nNoNewPrivs:\t0\nSeccomp:\t{seccomp}\nSeccomp_filters:\t0\n"
    )
}

fn run(env: &FixtureEnv, id: &str) -> Diagnostic {
    run_with(env, &tool(), id)
}

fn run_with(env: &FixtureEnv, tool: &Tool, id: &str) -> Diagnostic {
    let mut report = Doctor::with_shared().run_ids(env, tool, &[id]);
    assert_eq!(report.checks.len(), 1, "no shared check {id}");
    let diag = report.checks.remove(0);
    assert_eq!(diag.id, id);
    diag
}

fn fixes(diag: &Diagnostic) -> Vec<&str> {
    diag.fixes.iter().map(|fix| fix.cmd.as_str()).collect()
}

#[test]
fn shared_checks_run_in_display_order() {
    let ids: Vec<_> = Doctor::with_shared().check_ids().collect();
    assert_eq!(
        ids,
        [
            "platform.os_arch",
            "kernel.version",
            "kernel.btf",
            "priv.capabilities",
            "priv.file_caps",
            "priv.nosuid",
            "priv.nnp",
            "priv.optional_caps",
            "priv.sudo",
            "sec.lockdown",
            "sec.lsm",
            "sysctl.unpriv_bpf",
            "sysctl.perf_paranoid",
            "sysctl.jit",
            "rlimit.memlock",
            "env.userns",
            "env.pidns",
            "env.container",
            "env.seccomp",
            "fs.cgroup2",
            "fs.proc_hidepid",
            "probe.ringbuf",
            "probe.memcg",
        ]
    );
}

#[test]
fn healthy_root_host_has_no_findings() {
    let report = Doctor::with_shared().run(&host(), &tool());
    let findings: Vec<_> = report
        .checks
        .iter()
        .filter(|d| matches!(d.status, Status::Warn | Status::Fail))
        .map(|d| d.id)
        .collect();
    assert_eq!(findings, Vec::<&str>::new());
    assert_eq!(report.verdict, Status::Pass);
}

// platform.os_arch

#[test]
fn os_arch_accepts_linux_x86_64_and_aarch64() {
    assert_eq!(run(&host(), "platform.os_arch").status, Status::Pass);
    let arm = host().with_uname("Linux", "6.8.0", "aarch64");
    assert_eq!(run(&arm, "platform.os_arch").status, Status::Pass);
}

#[test]
fn os_arch_fails_on_other_architectures_and_systems() {
    let riscv = run(
        &host().with_uname("Linux", "6.8.0", "riscv64"),
        "platform.os_arch",
    );
    assert_eq!(riscv.status, Status::Fail);
    assert_eq!(
        riscv.explain.as_deref(),
        Some("BPF objects are compiled per architecture")
    );
    let bsd = run(
        &host().with_uname("FreeBSD", "14.1-RELEASE", "x86_64"),
        "platform.os_arch",
    );
    assert_eq!(bsd.status, Status::Fail);
}

// kernel.version

#[test]
fn kernel_version_passes_from_5_11() {
    let diag = run(
        &host().with_uname("Linux", "7.2.6-arch2-1", "x86_64"),
        "kernel.version",
    );
    assert_eq!(diag.status, Status::Pass);
    assert_eq!(diag.observed, "7.2.6 ≥ 5.8");
    let boundary = host().with_uname("Linux", "5.11.0", "x86_64");
    assert_eq!(run(&boundary, "kernel.version").status, Status::Pass);
}

#[test]
fn kernel_version_fails_below_5_8() {
    let diag = run(
        &host().with_uname("Linux", "5.4.0-150-generic", "x86_64"),
        "kernel.version",
    );
    assert_eq!(diag.status, Status::Fail);
    assert_eq!(diag.observed, "kernel 5.4.0 is older than 5.8");
    assert_eq!(
        diag.impact.as_deref(),
        Some("no BPF ring buffer / CAP_BPF; whytime cannot run")
    );
    assert_eq!(
        fixes(&diag),
        ["upgrade to a 5.15+ distro kernel (Ubuntu 22.04+, Debian 12+, RHEL 9+, Fedora, Arch)"]
    );
}

#[test]
fn kernel_version_warns_on_tier_2_kernels() {
    for release in ["5.8.0", "5.10.0-28-amd64"] {
        let diag = run(
            &host().with_uname("Linux", release, "x86_64"),
            "kernel.version",
        );
        assert_eq!(diag.status, Status::Warn, "{release}");
    }
}

#[test]
fn kernel_version_enforces_tool_minimum() {
    let newer = Tool {
        min_kernel: (6, 1),
        ..tool()
    };
    let diag = run_with(
        &host().with_uname("Linux", "5.15.0-91-generic", "x86_64"),
        &newer,
        "kernel.version",
    );
    assert_eq!(diag.status, Status::Fail);
    assert_eq!(diag.observed, "kernel 5.15.0 is older than 6.1");
    let ok = run_with(
        &host().with_uname("Linux", "6.1.0", "x86_64"),
        &newer,
        "kernel.version",
    );
    assert_eq!(
        (ok.status, ok.observed.as_str()),
        (Status::Pass, "6.1.0 ≥ 6.1")
    );
}

// kernel.btf

#[test]
fn btf_passes_with_vmlinux_magic() {
    assert_eq!(run(&host(), "kernel.btf").status, Status::Pass);
}

#[test]
fn btf_fails_when_missing_or_corrupt() {
    let missing = run(
        &host().without_file("/sys/kernel/btf/vmlinux"),
        "kernel.btf",
    );
    assert_eq!(missing.status, Status::Fail);
    assert_eq!(
        missing.impact.as_deref(),
        Some("tp_btf/fentry programs cannot be loaded")
    );
    assert!(
        fixes(&missing)[0].starts_with("use a distro kernel built with CONFIG_DEBUG_INFO_BTF=y")
    );
    // Big-endian magic is not BTF for this host.
    let swapped = host().with_file("/sys/kernel/btf/vmlinux", [0xEB_u8, 0x9F, 1, 0]);
    assert_eq!(run(&swapped, "kernel.btf").status, Status::Fail);
}

// priv.capabilities

#[test]
fn capabilities_pass_with_file_caps_root_or_sys_admin() {
    assert_eq!(
        run(&setcap_user(), "priv.capabilities").status,
        Status::Pass
    );
    assert_eq!(run(&host(), "priv.capabilities").status, Status::Pass);
    // CAP_SYS_ADMIN implies CAP_BPF and CAP_PERFMON.
    let admin = unprivileged().with_caps(caps(Cap::SysAdmin.mask()));
    assert_eq!(run(&admin, "priv.capabilities").status, Status::Pass);
}

#[test]
fn capabilities_fail_with_exact_setcap_line() {
    let diag = run(&unprivileged(), "priv.capabilities");
    assert_eq!(diag.status, Status::Fail);
    assert_eq!(
        diag.observed,
        "missing CAP_BPF, CAP_PERFMON (uid 1000, no file capabilities on /usr/local/bin/whytime)"
    );
    assert_eq!(fixes(&diag), [SETCAP, "sudo whytime ..."]);
    assert_eq!(diag.fixes[0].note, "one-time; re-run after every reinstall");
    assert_eq!(
        diag.explain.as_deref(),
        Some("CAP_BPF loads BPF programs and maps; CAP_PERFMON attaches them to tracepoints")
    );
}

#[test]
fn capabilities_report_only_missing_caps_and_file_cap_state() {
    let env = unprivileged()
        .with_caps(caps(Cap::Bpf.mask()))
        .with_file_caps(EXE, ep(BPF_PERFMON));
    let diag = run(&env, "priv.capabilities");
    assert_eq!(
        diag.observed,
        "missing CAP_PERFMON (uid 1000, file capabilities on /usr/local/bin/whytime are not in effect)"
    );
}

#[test]
fn capabilities_quote_exe_paths_in_fixes() {
    let spaced = Tool {
        exe: "/home/me/my tools/whytime".into(),
        ..tool()
    };
    let diag = run_with(&unprivileged(), &spaced, "priv.capabilities");
    assert_eq!(
        fixes(&diag)[0],
        "sudo setcap cap_bpf,cap_perfmon+ep '/home/me/my tools/whytime'"
    );
}

#[test]
fn capabilities_quote_non_utf8_exe_paths_byte_exact() {
    let latin1 = Tool {
        exe: OsStr::from_bytes(b"/opt/caf\xe9/it's").into(),
        ..tool()
    };
    let diag = run_with(&unprivileged(), &latin1, "priv.capabilities");
    assert_eq!(
        fixes(&diag)[0],
        r"sudo setcap cap_bpf,cap_perfmon+ep $'/opt/caf\xe9/it\x27s'"
    );
}

#[test]
fn capabilities_setcap_fix_installs_off_nosuid_mount() {
    let env = unprivileged().with_mount_flags(CARGO_EXE, NOSUID);
    let diag = run_with(&env, &cargo_tool(), "priv.capabilities");
    assert_eq!(
        fixes(&diag),
        [
            "sudo install -m 0755 /home/me/.cargo/bin/whytime /usr/local/bin/whytime \
          && sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/whytime",
            "sudo whytime ...",
        ]
    );
    assert_eq!(
        diag.fixes[0].note,
        "installs onto a mount that honours file capabilities; one-time; re-run after every reinstall"
    );
    // The same command priv.nosuid gives.
    let nosuid = run_with(&env, &cargo_tool(), "priv.nosuid");
    assert_eq!(fixes(&nosuid), fixes(&diag)[..1]);
}

#[test]
fn capabilities_outside_bounding_set_get_container_recipe() {
    let diag = run(&docker_root(), "priv.capabilities");
    assert_eq!(diag.status, Status::Fail);
    assert_eq!(
        diag.observed,
        "missing CAP_BPF, CAP_PERFMON (uid 0, bounding set excludes CAP_BPF, CAP_PERFMON)"
    );
    // Neither setcap nor sudo can exceed the bounding set.
    assert_eq!(fixes(&diag), [RECIPE]);
    // CAP_SYS_ADMIN in the bounding set still covers CAP_BPF and CAP_PERFMON.
    let admin_bound = docker_root().with_caps(CapSets {
        effective: DOCKER_CAPS,
        permitted: DOCKER_CAPS,
        bounding: DOCKER_CAPS | Cap::SysAdmin.mask(),
    });
    assert_eq!(
        fixes(&run(&admin_bound, "priv.capabilities")),
        [SETCAP, "sudo whytime ..."]
    );
}

// priv.file_caps

#[test]
fn file_caps_pass_when_in_effect() {
    assert_eq!(run(&setcap_user(), "priv.file_caps").status, Status::Pass);
    assert_eq!(run(&host(), "priv.file_caps").status, Status::Pass);
}

#[test]
fn file_caps_do_not_pass_root_without_effective_caps() {
    let diag = run(&docker_root(), "priv.file_caps");
    assert_eq!(diag.status, Status::Info);
    assert_eq!(
        diag.observed,
        "/usr/local/bin/whytime not installed with file capabilities"
    );
}

#[test]
fn file_caps_name_why_they_are_not_in_effect() {
    let lost = setcap_user().with_caps(caps(0));

    // `setcap …+p`: permitted only, never raised to effective.
    let permitted_only = lost.clone().with_file_caps(
        EXE,
        FileCaps {
            permitted: BPF_PERFMON,
            effective: false,
        },
    );
    let diag = run(&permitted_only, "priv.file_caps");
    assert_eq!(diag.status, Status::Warn);
    assert_eq!(
        diag.observed,
        "file capabilities on /usr/local/bin/whytime lack the effective flag (+e)"
    );
    assert_eq!(fixes(&diag), [SETCAP]);
    assert!(
        run(&permitted_only, "priv.capabilities")
            .observed
            .ends_with("lack the effective flag (+e))")
    );

    let bounded = lost.clone().with_caps(CapSets::default());
    let diag = run(&bounded, "priv.file_caps");
    assert_eq!(
        diag.observed,
        "file capabilities on /usr/local/bin/whytime are masked by the bounding set, \
         which excludes CAP_BPF, CAP_PERFMON"
    );
    assert_eq!(fixes(&diag), [RECIPE]);

    let nosuid = run(
        &lost.clone().with_mount_flags(EXE, NOSUID),
        "priv.file_caps",
    );
    assert_eq!(
        nosuid.observed,
        "file capabilities on /usr/local/bin/whytime are ignored on its nosuid mount"
    );
    assert!(
        nosuid
            .explain
            .is_some_and(|why| why.contains("priv.nosuid"))
    );

    let nnp = run(&lost.clone().with_no_new_privs(true), "priv.file_caps");
    assert_eq!(
        nnp.observed,
        "file capabilities on /usr/local/bin/whytime are ignored under no_new_privs"
    );
    assert!(nnp.explain.is_some_and(|why| why.contains("priv.nnp")));

    let unexplained = run(&lost, "priv.file_caps");
    assert_eq!(
        unexplained.observed,
        "file capabilities on /usr/local/bin/whytime are not in effect"
    );
    assert_eq!(unexplained.fixes, []);
}

#[test]
fn file_caps_warn_when_incomplete_and_inform_when_absent() {
    let partial = run(
        &unprivileged().with_file_caps(EXE, ep(Cap::Bpf.mask())),
        "priv.file_caps",
    );
    assert_eq!(partial.status, Status::Warn);
    assert_eq!(fixes(&partial), [SETCAP]);
    let absent = run(&unprivileged(), "priv.file_caps");
    assert_eq!(absent.status, Status::Info);
    assert_eq!(
        absent.observed,
        "/usr/local/bin/whytime not installed with file capabilities"
    );
}

// priv.nosuid

#[test]
fn nosuid_passes_on_normal_mounts_and_for_root() {
    assert_eq!(run(&unprivileged(), "priv.nosuid").status, Status::Pass);
    let nosuid = MountFlags {
        nosuid: true,
        readonly: false,
    };
    assert_eq!(
        run(&host().with_mount_flags(EXE, nosuid), "priv.nosuid").status,
        Status::Pass
    );
}

#[test]
fn nosuid_fails_with_install_and_setcap_command() {
    let local = Tool {
        exe: "/home/me/.cargo/bin/whytime".into(),
        ..tool()
    };
    let flags = MountFlags {
        nosuid: true,
        readonly: false,
    };
    let env = unprivileged().with_mount_flags("/home/me/.cargo/bin/whytime", flags);
    let diag = run_with(&env, &local, "priv.nosuid");
    assert_eq!(diag.status, Status::Fail);
    assert_eq!(
        diag.observed,
        "/home/me/.cargo/bin/whytime is on a nosuid mount; file capabilities are ignored there"
    );
    assert_eq!(
        fixes(&diag),
        [
            "sudo install -m 0755 /home/me/.cargo/bin/whytime /usr/local/bin/whytime \
          && sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/whytime"
        ]
    );
}

// priv.nnp

#[test]
fn nnp_passes_when_clear() {
    assert_eq!(run(&unprivileged(), "priv.nnp").status, Status::Pass);
}

#[test]
fn nnp_warns_only_when_capabilities_are_lost() {
    let blocked = run(
        &setcap_user().with_caps(caps(0)).with_no_new_privs(true),
        "priv.nnp",
    );
    assert_eq!(blocked.status, Status::Warn);
    assert!(
        blocked
            .impact
            .as_deref()
            .is_some_and(|i| i.starts_with("file capabilities are ignored under no_new_privs"))
    );
    assert_eq!(fixes(&blocked)[0], "sudo whytime ...");
    let harmless = run(&host().with_no_new_privs(true), "priv.nnp");
    assert_eq!(harmless.status, Status::Info);
}

// priv.optional_caps

#[test]
fn optional_caps_pass_when_effective() {
    assert_eq!(run(&host(), "priv.optional_caps").status, Status::Pass);
}

#[test]
fn optional_caps_warn_with_full_setcap_line() {
    let diag = run(&setcap_user(), "priv.optional_caps");
    assert_eq!(diag.status, Status::Warn);
    assert_eq!(diag.observed, "missing optional CAP_SYS_PTRACE");
    assert_eq!(
        diag.impact.as_deref(),
        Some("CAP_SYS_PTRACE enables names of other users' processes")
    );
    assert_eq!(
        fixes(&diag),
        ["sudo setcap cap_bpf,cap_perfmon,cap_sys_ptrace+ep /usr/local/bin/whytime"]
    );
}

#[test]
fn optional_caps_fix_respects_nosuid_and_bounding_set() {
    let nosuid = host()
        .with_ids(user())
        .with_caps(caps(BPF_PERFMON))
        .with_mount_flags(CARGO_EXE, NOSUID);
    assert_eq!(
        fixes(&run_with(&nosuid, &cargo_tool(), "priv.optional_caps")),
        [
            "sudo install -m 0755 /home/me/.cargo/bin/whytime /usr/local/bin/whytime \
          && sudo setcap cap_bpf,cap_perfmon,cap_sys_ptrace+ep /usr/local/bin/whytime"
        ]
    );
    assert_eq!(
        fixes(&run(&docker_root(), "priv.optional_caps")),
        [
            "docker run --cap-add BPF --cap-add PERFMON --cap-add SYS_PTRACE --pid=host \
             -v /sys/kernel/btf:/sys/kernel/btf:ro ..."
        ]
    );
}

// priv.sudo

#[test]
fn sudo_passes_without_sudo() {
    assert_eq!(run(&host(), "priv.sudo").status, Status::Pass);
    // SUDO_UID inherited by a non-root process is not "running via sudo".
    let stale = host().with_ids(Ids {
        sudo_uid: Some(1000),
        ..user()
    });
    assert_eq!(run(&stale, "priv.sudo").status, Status::Pass);
}

#[test]
fn sudo_reports_invoking_user() {
    let env = host().with_ids(Ids {
        sudo_uid: Some(1000),
        sudo_user: Some("alice".into()),
        ..Ids::default()
    });
    let diag = run(&env, "priv.sudo");
    assert_eq!(diag.status, Status::Info);
    assert_eq!(diag.observed, "running via sudo (invoking user uid 1000)");
}

// sec.lockdown

#[test]
fn lockdown_none_and_integrity_pass() {
    assert_eq!(run(&host(), "sec.lockdown").observed, "lockdown: none");
    let integrity = host().with_file(
        "/sys/kernel/security/lockdown",
        "none [integrity] confidentiality\n",
    );
    let diag = run(&integrity, "sec.lockdown");
    assert_eq!(
        (diag.status, diag.observed.as_str()),
        (Status::Pass, "lockdown: integrity (no impact)")
    );
}

#[test]
fn lockdown_confidentiality_warns_and_unreadable_informs() {
    let env = host().with_file(
        "/sys/kernel/security/lockdown",
        "none integrity [confidentiality]\n",
    );
    let diag = run(&env, "sec.lockdown");
    assert_eq!(diag.status, Status::Warn);
    assert_eq!(
        diag.impact.as_deref(),
        Some("bpf_probe_read_kernel and kprobes are disabled; whytime runs with reduced detail")
    );
    assert!(fixes(&diag)[0].starts_with("none at runtime; lockdown is set by Secure Boot policy"));
    let unreadable = host().without_file("/sys/kernel/security/lockdown");
    assert_eq!(run(&unreadable, "sec.lockdown").status, Status::Info);
}

// sec.lsm

#[test]
fn lsm_passes_without_enforcing_selinux() {
    assert_eq!(run(&host(), "sec.lsm").status, Status::Pass);
    let permissive = host().with_file("/sys/fs/selinux/enforce", "0");
    assert_eq!(run(&permissive, "sec.lsm").status, Status::Pass);
}

#[test]
fn lsm_points_at_ausearch_when_selinux_enforces() {
    let diag = run(&host().with_file("/sys/fs/selinux/enforce", "1"), "sec.lsm");
    assert_eq!(diag.status, Status::Info);
    assert_eq!(fixes(&diag), ["sudo ausearch -m avc -c whytime"]);
}

// sysctl.unpriv_bpf

#[test]
fn unpriv_bpf_reports_value() {
    let diag = run(&host(), "sysctl.unpriv_bpf");
    assert_eq!(
        (diag.status, diag.observed.as_str()),
        (Status::Info, "kernel.unprivileged_bpf_disabled = 2")
    );
    assert_eq!(
        diag.explain.as_deref(),
        Some("unprivileged BPF never allows tracing programs; leave this setting alone")
    );
}

#[test]
fn unpriv_bpf_skips_when_unreadable() {
    let env = host().without_file("/proc/sys/kernel/unprivileged_bpf_disabled");
    assert_eq!(run(&env, "sysctl.unpriv_bpf").status, Status::Skip);
}

// sysctl.perf_paranoid

#[test]
fn perf_paranoid_passes_with_perfmon() {
    assert_eq!(
        run(&setcap_user(), "sysctl.perf_paranoid").status,
        Status::Pass
    );
}

#[test]
fn perf_paranoid_informs_without_perfmon() {
    let diag = run(&unprivileged(), "sysctl.perf_paranoid");
    assert_eq!(diag.status, Status::Info);
    assert_eq!(
        diag.observed,
        "kernel.perf_event_paranoid = 2; ignored when CAP_PERFMON is present"
    );
}

// sysctl.jit

#[test]
fn jit_passes_when_enabled() {
    assert_eq!(run(&host(), "sysctl.jit").status, Status::Pass);
}

#[test]
fn jit_warns_when_disabled() {
    let diag = run(
        &host().with_file("/proc/sys/net/core/bpf_jit_enable", "0\n"),
        "sysctl.jit",
    );
    assert_eq!(diag.status, Status::Warn);
    assert_eq!(diag.observed, "BPF JIT disabled (~10x overhead)");
    assert_eq!(fixes(&diag), ["sudo sysctl -w net.core.bpf_jit_enable=1"]);
}

// rlimit.memlock

/// A pre-5.11 kernel with a 64 KiB memlock limit and only `CAP_BPF` and `CAP_PERFMON`.
fn old_kernel_low_memlock() -> FixtureEnv {
    setcap_user()
        .with_uname("Linux", "5.8.0", "x86_64")
        .with_probe(BpfProbe::MemcgAccounting, Err(libc::EINVAL))
        .with_memlock(64 << 10, 64 << 10)
}

#[test]
fn memlock_skips_under_memcg_accounting() {
    assert_eq!(run(&host(), "rlimit.memlock").status, Status::Skip);
}

#[test]
fn memlock_passes_when_hard_limit_suffices_or_raisable() {
    let enough = old_kernel_low_memlock().with_memlock(64 << 10, 64 << 20);
    assert_eq!(run(&enough, "rlimit.memlock").status, Status::Pass);
    let raisable = old_kernel_low_memlock().with_caps(caps(BPF_PERFMON | Cap::SysResource.mask()));
    assert_eq!(run(&raisable, "rlimit.memlock").status, Status::Pass);
}

#[test]
fn memlock_fails_with_three_fixes() {
    let diag = run(
        &old_kernel_low_memlock().with_var("USER", "alice"),
        "rlimit.memlock",
    );
    assert_eq!(diag.status, Status::Fail);
    assert_eq!(
        diag.observed,
        "RLIMIT_MEMLOCK hard limit 64 KiB is below the 64 MiB whytime needs"
    );
    assert_eq!(
        fixes(&diag),
        [
            "sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep /usr/local/bin/whytime",
            "sudo prlimit --memlock=unlimited:unlimited --pid $$",
            "echo 'alice hard memlock unlimited' | sudo tee -a /etc/security/limits.conf",
        ]
    );
    assert_eq!(
        diag.explain.as_deref(),
        Some(
            "before 5.11 BPF memory counts against RLIMIT_MEMLOCK; since 5.11 it is charged to memcg"
        )
    );
}

#[test]
fn memlock_limits_line_falls_back_to_uid_range() {
    let diag = run(&old_kernel_low_memlock(), "rlimit.memlock");
    assert_eq!(
        fixes(&diag)[2],
        "echo '1000:1000 hard memlock unlimited' | sudo tee -a /etc/security/limits.conf"
    );
}

#[test]
fn memlock_setcap_fix_installs_off_nosuid_mount() {
    let env = old_kernel_low_memlock().with_mount_flags(CARGO_EXE, NOSUID);
    let diag = run_with(&env, &cargo_tool(), "rlimit.memlock");
    assert_eq!(
        fixes(&diag)[0],
        "sudo install -m 0755 /home/me/.cargo/bin/whytime /usr/local/bin/whytime \
         && sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep /usr/local/bin/whytime"
    );
}

#[test]
fn memlock_uses_kernel_version_when_probe_is_refused() {
    // An unprivileged probe says nothing; the release decides.
    let old = unprivileged()
        .with_uname("Linux", "5.10.0", "x86_64")
        .with_probe(BpfProbe::MemcgAccounting, Err(libc::EPERM))
        .with_memlock(64 << 10, 64 << 10);
    assert_eq!(run(&old, "rlimit.memlock").status, Status::Fail);
    let new = old.with_uname("Linux", "5.11.0", "x86_64");
    assert_eq!(run(&new, "rlimit.memlock").status, Status::Skip);
}

// env.userns

#[test]
fn userns_passes_on_identity_map() {
    assert_eq!(run(&host(), "env.userns").status, Status::Pass);
}

#[test]
fn userns_fails_inside_user_namespace() {
    let diag = run(
        &host().with_file("/proc/self/uid_map", "0 1000 1\n"),
        "env.userns",
    );
    assert_eq!(diag.status, Status::Fail);
    assert_eq!(
        diag.observed,
        "running inside a user namespace; capabilities there do not grant BPF"
    );
    assert_eq!(
        fixes(&diag),
        [
            "run on the host, or in a container started with --cap-add BPF --cap-add PERFMON --pid=host"
        ]
    );
    // A full-range map that is shifted is still a user namespace.
    let shifted = host().with_file("/proc/self/uid_map", "0 100000 4294967295\n");
    assert_eq!(run(&shifted, "env.userns").status, Status::Fail);
}

// env.pidns

#[test]
fn pidns_passes_with_single_nspid() {
    assert_eq!(run(&host(), "env.pidns").status, Status::Pass);
}

#[test]
fn pidns_fails_when_nested() {
    let diag = run(
        &host().with_file("/proc/self/status", proc_status("4242\t7", 0)),
        "env.pidns",
    );
    assert_eq!(diag.status, Status::Fail);
    assert!(
        diag.observed
            .starts_with("nested PID namespace: kernel pids differ from /proc pids")
    );
    assert_eq!(fixes(&diag), ["docker run --pid=host ..."]);
}

// env.container

#[test]
fn container_passes_on_host() {
    assert_eq!(run(&host(), "env.container").status, Status::Pass);
}

#[test]
fn container_detected_by_marker_or_cgroup() {
    let docker = run(&host().with_file("/.dockerenv", ""), "env.container");
    assert_eq!(docker.status, Status::Info);
    assert_eq!(docker.observed, "running in a container (/.dockerenv)");
    assert_eq!(fixes(&docker), [RECIPE]);
    let k8s = host().with_file(
        "/proc/1/cgroup",
        "0::/kubepods/besteffort/pod1234/cri-containerd-abc\n",
    );
    assert_eq!(
        run(&k8s, "env.container").observed,
        "running in a container (kubernetes cgroup)"
    );
}

// env.seccomp

#[test]
fn seccomp_passes_without_filter() {
    assert_eq!(run(&host(), "env.seccomp").status, Status::Pass);
}

#[test]
fn seccomp_fails_only_when_bpf_is_blocked_despite_caps() {
    let filtered = host().with_file("/proc/self/status", proc_status("4242", 2));
    let allowed = run(&filtered, "env.seccomp");
    assert_eq!(allowed.status, Status::Info);

    let blocked = run(
        &filtered
            .clone()
            .with_probe(BpfProbe::RingBuf, Err(libc::EPERM)),
        "env.seccomp",
    );
    assert_eq!(blocked.status, Status::Fail);
    assert_eq!(
        fixes(&blocked),
        [
            "docker run --cap-add BPF --cap-add PERFMON ...",
            "docker run --security-opt seccomp=unconfined ...",
        ]
    );

    // Without capabilities, EPERM is expected and says nothing about seccomp.
    let no_caps = filtered
        .with_ids(user())
        .with_caps(caps(0))
        .with_probe(BpfProbe::RingBuf, Err(libc::EPERM));
    assert_eq!(run(&no_caps, "env.seccomp").status, Status::Info);
}

#[test]
fn seccomp_does_not_blame_eperm_inside_user_namespace() {
    // Rootless Podman: full capabilities that bpf() ignores outside the initial namespace.
    let rootless = host()
        .with_file("/proc/self/status", proc_status("4242", 2))
        .with_file("/proc/self/uid_map", "0 100000 65536\n")
        .with_probe(BpfProbe::RingBuf, Err(libc::EPERM));
    let diag = run(&rootless, "env.seccomp");
    assert_eq!(diag.status, Status::Info);
    assert_eq!(diag.observed, "seccomp filter active (mode 2)");
    assert_eq!(diag.fixes, []);
    assert_eq!(run(&rootless, "env.userns").status, Status::Fail);
}

// fs.cgroup2

#[test]
fn cgroup2_passes_when_mounted() {
    assert_eq!(run(&host(), "fs.cgroup2").status, Status::Pass);
}

#[test]
fn cgroup2_warns_when_missing() {
    let diag = run(
        &host().without_file("/sys/fs/cgroup/cgroup.controllers"),
        "fs.cgroup2",
    );
    assert_eq!(diag.status, Status::Warn);
    assert_eq!(
        diag.observed,
        "cgroup v2 not mounted; unit/container attribution degraded"
    );
}

// fs.proc_hidepid

#[test]
fn hidepid_passes_without_option() {
    assert_eq!(run(&host(), "fs.proc_hidepid").status, Status::Pass);
}

const HIDEPID_MOUNTINFO: &str =
    "23 22 0:21 / /proc rw,nosuid,relatime shared:5 - proc proc rw,hidepid=invisible\n";

#[test]
fn hidepid_warns_when_set() {
    let diag = run(
        &unprivileged().with_file("/proc/self/mountinfo", HIDEPID_MOUNTINFO),
        "fs.proc_hidepid",
    );
    assert_eq!(diag.status, Status::Warn);
    assert_eq!(diag.observed, "/proc mounted with hidepid=invisible");
}

#[test]
fn hidepid_has_no_effect_with_sys_ptrace() {
    let root = run(
        &host().with_file("/proc/self/mountinfo", HIDEPID_MOUNTINFO),
        "fs.proc_hidepid",
    );
    assert_eq!(root.status, Status::Info);
    assert_eq!(root.fixes, []);
    let ptrace = unprivileged()
        .with_caps(caps(Cap::SysPtrace.mask()))
        .with_file("/proc/self/mountinfo", HIDEPID_MOUNTINFO);
    assert_eq!(run(&ptrace, "fs.proc_hidepid").status, Status::Info);
}

// probe.ringbuf

#[test]
fn ringbuf_passes_when_map_created() {
    assert_eq!(run(&host(), "probe.ringbuf").status, Status::Pass);
}

#[test]
fn ringbuf_fails_with_errno_name_and_skips_unprivileged() {
    let diag = run(
        &host().with_probe(BpfProbe::RingBuf, Err(libc::EINVAL)),
        "probe.ringbuf",
    );
    assert_eq!(diag.status, Status::Fail);
    assert_eq!(diag.observed, "BPF ring buffer map creation failed: EINVAL");
    let skipped = unprivileged().with_probe(BpfProbe::RingBuf, Err(libc::EPERM));
    assert_eq!(run(&skipped, "probe.ringbuf").status, Status::Skip);
}

// probe.memcg

#[test]
fn memcg_reports_yes_when_probe_loads() {
    let diag = run(&host(), "probe.memcg");
    assert_eq!(
        (diag.status, diag.observed.as_str()),
        (Status::Info, "memcg accounting: yes")
    );
}

#[test]
fn memcg_reports_no_or_unknown() {
    let no = run(
        &host().with_probe(BpfProbe::MemcgAccounting, Err(libc::EINVAL)),
        "probe.memcg",
    );
    assert_eq!(no.observed, "memcg accounting: no");
    let refused = unprivileged().with_probe(BpfProbe::MemcgAccounting, Err(libc::EPERM));
    assert_eq!(run(&refused, "probe.memcg").status, Status::Skip);
}
