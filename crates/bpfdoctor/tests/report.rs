//! Doctor composition, verdicts, rendering and errno mapping.

mod common;

use bpfdoctor::{
    BpfProbe, CapSets, Check, Diagnostic, Doctor, Env, Fix, Ids, Report, Status, Tool, Uname,
    ids_for_errno,
};
use common::{host, tool};

fn uname() -> Uname {
    Uname {
        sysname: "Linux".into(),
        release: "7.2.6-arch2-1".into(),
        machine: "x86_64".into(),
    }
}

fn diag(id: &'static str, status: Status, required: bool) -> Diagnostic {
    Diagnostic::new(id, "title", required, status, "observed")
}

fn verdict(checks: Vec<Diagnostic>) -> Status {
    Report::new("whytime", uname(), checks).verdict
}

#[test]
fn verdict_is_worst_required_status() {
    assert_eq!(verdict(vec![]), Status::Pass);
    assert_eq!(
        verdict(vec![
            diag("a", Status::Pass, true),
            diag("b", Status::Info, false),
            diag("c", Status::Skip, true)
        ]),
        Status::Pass
    );
    assert_eq!(
        verdict(vec![
            diag("a", Status::Warn, true),
            diag("b", Status::Pass, true)
        ]),
        Status::Warn
    );
    assert_eq!(
        verdict(vec![
            diag("a", Status::Warn, false),
            diag("b", Status::Fail, true)
        ]),
        Status::Fail
    );
}

#[test]
fn optional_failures_only_warn() {
    let report = Report::new(
        "whytime",
        uname(),
        vec![
            diag("a", Status::Fail, false),
            diag("b", Status::Pass, true),
        ],
    );
    assert_eq!(report.verdict, Status::Warn);
    assert!(!report.has_fail());
    let report = Report::new("whytime", uname(), vec![diag("a", Status::Fail, true)]);
    assert!(report.has_fail());
}

#[test]
fn json_shape() {
    let checks = vec![
        diag("kernel.version", Status::Pass, true),
        diag("priv.capabilities", Status::Fail, true)
            .with_fix(Fix::new("sudo setcap cap_bpf+ep /x", "note")),
    ];
    let mut out = Vec::new();
    Report::new("whytime", uname(), checks)
        .render_json(&mut out)
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["schema"], "bpfdoctor/1");
    assert_eq!(json["tool"], "whytime");
    assert_eq!(json["kernel"], "7.2.6-arch2-1");
    assert_eq!(json["arch"], "x86_64");
    assert_eq!(json["verdict"], "fail");
    assert_eq!(json["checks"][0]["id"], "kernel.version");
    assert_eq!(json["checks"][0]["status"], "pass");
    assert_eq!(json["checks"][1]["id"], "priv.capabilities");
    assert_eq!(json["checks"][1]["required"], true);
    assert_eq!(
        json["checks"][1]["fixes"][0]["cmd"],
        "sudo setcap cap_bpf+ep /x"
    );
    assert_eq!(json["checks"][1]["impact"], serde_json::Value::Null);
}

#[test]
fn human_rendering_matches_reference_layout() {
    let checks = vec![
        Diagnostic::new("kernel.version", "Kernel version", true, Status::Pass, "7.2.6 ≥ 5.8"),
        Diagnostic::new(
            "priv.capabilities",
            "Required capabilities",
            true,
            Status::Fail,
            "missing CAP_BPF, CAP_PERFMON (uid 1000, no file capabilities on /usr/local/bin/whytime)",
        )
        .with_impact("cannot load tracing programs; whytime cannot run")
        .with_fix(Fix::new("sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/whytime", ""))
        .with_fix(Fix::new("sudo whytime ...", ""))
        .with_explain("CAP_BPF loads BPF programs and maps; CAP_PERFMON attaches them to tracepoints"),
    ];
    let mut out = Vec::new();
    Report::new("whytime", uname(), checks)
        .render_human(&mut out, false)
        .unwrap();
    let expected = "\
whytime doctor · kernel 7.2.6-arch2-1 x86_64
 PASS kernel.version     7.2.6 ≥ 5.8
 FAIL priv.capabilities  missing CAP_BPF, CAP_PERFMON (uid 1000, no file capabilities on /usr/local/bin/whytime)
      impact: cannot load tracing programs; whytime cannot run
      fix:    sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/whytime
      or:     sudo whytime ...
      why:    CAP_BPF loads BPF programs and maps; CAP_PERFMON attaches them to tracepoints
summary: 1 fail · 0 warn · 1 pass → whytime will not run
";
    assert_eq!(String::from_utf8(out).unwrap(), expected);
}

#[test]
fn human_rendering_notes_counts_and_colour() {
    let checks = vec![
        diag("sysctl.jit", Status::Warn, false).with_fix(Fix::new(
            "sudo sysctl -w net.core.bpf_jit_enable=1",
            "persist it",
        )),
        diag("probe.memcg", Status::Info, false),
        diag("probe.ringbuf", Status::Skip, true),
    ];
    let report = Report::new("whytime", uname(), checks);

    let mut plain = Vec::new();
    report.render_human(&mut plain, false).unwrap();
    let plain = String::from_utf8(plain).unwrap();
    assert!(plain.contains(
        "\n      fix:    sudo sysctl -w net.core.bpf_jit_enable=1\n      note:   persist it\n"
    ));
    assert!(plain.ends_with(
        "summary: 0 fail · 1 warn · 0 pass · 1 info · 1 skip → whytime will run with reduced functionality\n"
    ));
    assert!(!plain.contains('\x1b'));

    let mut coloured = Vec::new();
    report.render_human(&mut coloured, true).unwrap();
    let coloured = String::from_utf8(coloured).unwrap();
    assert!(coloured.contains("\n \x1b[33mWARN\x1b[0m sysctl.jit     observed\n"));
    assert!(coloured.contains("\n \x1b[2mINFO\x1b[0m probe.memcg"));
    assert!(coloured.contains("\n \x1b[2mSKIP\x1b[0m probe.ringbuf"));
}

#[test]
fn human_fix_lines_hold_only_the_command() {
    // Notes contain `;` and `'`, which would run as shell syntax if pasted along.
    let env = host()
        .with_ids(Ids {
            uid: 1000,
            euid: 1000,
            ..Ids::default()
        })
        .with_caps(CapSets {
            bounding: u64::MAX,
            ..CapSets::default()
        })
        .with_uname("Linux", "5.8.0", "x86_64")
        .with_probe(BpfProbe::MemcgAccounting, Err(libc::EINVAL))
        .with_memlock(64 << 10, 64 << 10);
    let report = Doctor::with_shared().run(&env, &tool());
    let mut out = Vec::new();
    report.render_human(&mut out, false).unwrap();
    let out = String::from_utf8(out).unwrap();

    let cmds: Vec<&str> = out
        .lines()
        .filter_map(|line| {
            line.strip_prefix("      fix:    ")
                .or_else(|| line.strip_prefix("      or:     "))
        })
        .collect();
    let notes: Vec<&str> = out
        .lines()
        .filter_map(|line| line.strip_prefix("      note:   "))
        .collect();
    let fixes = report.checks.iter().flat_map(|check| &check.fixes);
    assert_eq!(
        cmds,
        fixes
            .clone()
            .map(|fix| fix.cmd.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        notes,
        fixes
            .map(|fix| fix.note.as_str())
            .filter(|note| !note.is_empty())
            .collect::<Vec<_>>()
    );
    assert!(notes.iter().any(|note| note.contains(';')));
}

#[test]
fn preflight_is_the_fast_subset() {
    let ids: Vec<_> = Doctor::preflight().check_ids().collect();
    assert_eq!(
        ids,
        [
            "platform.os_arch",
            "kernel.version",
            "kernel.btf",
            "priv.capabilities",
            "priv.nosuid",
            "priv.nnp",
            "sec.lockdown",
            "env.userns",
            "env.pidns",
        ]
    );
}

#[test]
fn run_ids_keeps_display_order_and_ignores_unknown_ids() {
    let report =
        Doctor::with_shared().run_ids(&host(), &tool(), &["probe.memcg", "nope", "kernel.btf"]);
    let ids: Vec<_> = report.checks.iter().map(|d| d.id).collect();
    assert_eq!(ids, ["kernel.btf", "probe.memcg"]);
    assert_eq!(report.kernel, "6.8.0");
}

struct Custom(&'static str, Status);

impl Check for Custom {
    fn id(&self) -> &'static str {
        self.0
    }

    fn run(&self, _: &dyn Env, _: &Tool) -> Diagnostic {
        Diagnostic::new(self.0, "custom", true, self.1, "custom")
    }
}

#[test]
fn add_replaces_same_id_in_place_and_appends_new_ids() {
    let mut doctor = Doctor::preflight();
    doctor
        .add(Box::new(Custom("kernel.btf", Status::Fail)))
        .add(Box::new(Custom("whytime.sched", Status::Pass)));
    let report = doctor.run(&host(), &tool());
    let ids: Vec<_> = report.checks.iter().map(|d| d.id).collect();
    assert_eq!(ids.len(), 10);
    assert_eq!(ids[2], "kernel.btf");
    assert_eq!(ids[9], "whytime.sched");
    assert_eq!(report.checks[2].observed, "custom");
    assert_eq!(report.verdict, Status::Fail);
}

#[test]
fn errno_mapping_names_only_shared_checks() {
    let shared: Vec<_> = Doctor::with_shared().check_ids().collect();
    for errno in [
        libc::EPERM,
        libc::EACCES,
        libc::EINVAL,
        libc::E2BIG,
        libc::ENOENT,
        libc::ENOMEM,
        libc::ENOSYS,
        libc::EOPNOTSUPP,
        524,
        9999,
    ] {
        let ids = ids_for_errno(errno);
        assert!(!ids.is_empty(), "errno {errno}");
        for id in ids {
            assert!(
                shared.contains(id),
                "errno {errno} maps to unknown check {id}"
            );
        }
    }
}

#[test]
fn errno_mapping_targets_likely_causes() {
    assert!(ids_for_errno(libc::EPERM).contains(&"priv.capabilities"));
    assert!(ids_for_errno(libc::EPERM).contains(&"rlimit.memlock"));
    assert!(ids_for_errno(libc::EACCES).contains(&"sec.lsm"));
    assert!(ids_for_errno(libc::ENOENT).contains(&"kernel.btf"));
    // Lockdown rejects bpf_probe_read_kernel at load time with EINVAL.
    assert!(ids_for_errno(libc::EINVAL).contains(&"sec.lockdown"));
    assert_eq!(ids_for_errno(-libc::EPERM), ids_for_errno(libc::EPERM));
}
