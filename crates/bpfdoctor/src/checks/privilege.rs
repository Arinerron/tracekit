//! Capabilities and the mechanisms that grant or block them.

use super::{Shared, missing_caps, privileged, setcap_fix, sudo_tool};
use crate::cap::{names, rationale};
use crate::{Cap, Diagnostic, Env, FileCaps, Fix, Status, Tool};

const SETCAP_NOTE: &str = "one-time; re-run after every reinstall";

pub(super) fn capabilities(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    if tool.required_caps.is_empty() {
        return check.diag(Status::Pass, "no capabilities required");
    }
    let caps = env.caps();
    let missing = missing_caps(caps.effective, tool.required_caps);
    if missing.is_empty() {
        return check.diag(
            Status::Pass,
            format!("{} effective", names(tool.required_caps)),
        );
    }
    let unbounded = missing_caps(caps.bounding, tool.required_caps);
    let state = if unbounded.is_empty() {
        file_caps_state(env, tool)
    } else {
        format!("bounding set excludes {}", names(&unbounded))
    };
    let observed = format!(
        "missing {} (uid {}, {state})",
        names(&missing),
        env.ids().uid
    );
    let diag = check
        .diag(Status::Fail, observed)
        .with_impact(format!(
            "cannot load tracing programs; {} cannot run",
            tool.name
        ))
        .with_fix(setcap_fix(env, tool, &[], SETCAP_NOTE));
    // Not even root gains capabilities outside the bounding set.
    let diag = if unbounded.is_empty() {
        diag.with_fix(Fix::new(sudo_tool(tool), "run once with root"))
    } else {
        diag
    };
    diag.with_explain(rationale(tool.required_caps))
}

/// The executable's file capabilities, unless it has none.
fn installed_caps(env: &dyn Env, tool: &Tool) -> Option<FileCaps> {
    env.file_caps(&tool.exe).filter(|file| file.permitted != 0)
}

/// How the executable's file capabilities relate to the required set.
fn file_caps_state(env: &dyn Env, tool: &Tool) -> String {
    let Some(file) = installed_caps(env, tool) else {
        return format!("no file capabilities on {}", tool.exe.display());
    };
    let lacking = missing_caps(file.permitted, tool.required_caps);
    if lacking.is_empty() {
        Lost::of(env, tool, file).observed(tool)
    } else {
        format!(
            "file capabilities on {} lack {}",
            tool.exe.display(),
            names(&lacking)
        )
    }
}

/// Why file capabilities that grant every required capability are not in effect.
enum Lost {
    /// The bounding set excludes these required capabilities.
    Bounding(Vec<Cap>),
    /// The executable is on a nosuid mount.
    Nosuid,
    /// `no_new_privs` is set.
    NoNewPrivs,
    /// Installed `+p` without `+e`: permitted, but not raised to effective.
    NoEffectiveFlag,
    /// None of the above.
    Unknown,
}

impl Lost {
    fn of(env: &dyn Env, tool: &Tool, file: FileCaps) -> Self {
        let unbounded = missing_caps(env.caps().bounding, tool.required_caps);
        if !unbounded.is_empty() {
            Self::Bounding(unbounded)
        } else if env.mount_flags(&tool.exe).is_some_and(|flags| flags.nosuid) {
            Self::Nosuid
        } else if env.no_new_privs() {
            Self::NoNewPrivs
        } else if !file.effective {
            Self::NoEffectiveFlag
        } else {
            Self::Unknown
        }
    }

    /// E.g. `file capabilities on /usr/local/bin/whytime lack the effective flag (+e)`.
    fn observed(&self, tool: &Tool) -> String {
        let exe = tool.exe.display();
        match self {
            Self::Bounding(caps) => format!(
                "file capabilities on {exe} are masked by the bounding set, which excludes {}",
                names(caps)
            ),
            Self::Nosuid => format!("file capabilities on {exe} are ignored on its nosuid mount"),
            Self::NoNewPrivs => {
                format!("file capabilities on {exe} are ignored under no_new_privs")
            }
            Self::NoEffectiveFlag => {
                format!("file capabilities on {exe} lack the effective flag (+e)")
            }
            Self::Unknown => format!("file capabilities on {exe} are not in effect"),
        }
    }
}

pub(super) fn file_caps(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    let exe = tool.exe.display();
    let Some(file) = installed_caps(env, tool) else {
        return if env.ids().euid == 0 && privileged(env, tool) {
            check.diag(
                Status::Pass,
                format!("no file capabilities on {exe}; not needed as root"),
            )
        } else {
            check.diag(
                Status::Info,
                format!("{exe} not installed with file capabilities"),
            )
        };
    };
    let lacking = missing_caps(file.permitted, tool.required_caps);
    if !lacking.is_empty() {
        return check
            .diag(
                Status::Warn,
                format!("file capabilities on {exe} lack {}", names(&lacking)),
            )
            .with_fix(setcap_fix(env, tool, &[], SETCAP_NOTE));
    }
    if privileged(env, tool) {
        return check.diag(
            Status::Pass,
            format!("file capabilities on {exe} in effect"),
        );
    }
    let lost = Lost::of(env, tool, file);
    let diag = check
        .diag(Status::Warn, lost.observed(tool))
        .with_impact(format!(
            "{} runs without the capabilities it was installed with",
            tool.name
        ));
    match lost {
        Lost::Bounding(_) => diag
            .with_fix(setcap_fix(env, tool, &[], SETCAP_NOTE))
            .with_explain("the kernel masks file capabilities with the bounding set"),
        Lost::Nosuid => diag
            .with_explain("the kernel ignores file capabilities on nosuid mounts; see priv.nosuid"),
        Lost::NoNewPrivs => diag
            .with_explain("the kernel ignores file capabilities under no_new_privs; see priv.nnp"),
        Lost::NoEffectiveFlag => diag
            .with_fix(setcap_fix(env, tool, &[], SETCAP_NOTE))
            .with_explain(
                "without +e the capabilities are only permitted; \
                 the kernel does not make them effective at execve",
            ),
        Lost::Unknown => diag.with_explain(
            "the kernel grants file capabilities at execve, but not while an unprivileged \
             tracer is attached, and the process may drop them afterwards",
        ),
    }
}

pub(super) fn nosuid(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    let exe = tool.exe.display();
    let Some(flags) = env.mount_flags(&tool.exe) else {
        return check.diag(Status::Skip, format!("cannot read mount flags for {exe}"));
    };
    if !flags.nosuid {
        return check.diag(
            Status::Pass,
            format!("{exe} is on a mount that honours file capabilities"),
        );
    }
    if env.ids().euid == 0 || privileged(env, tool) {
        return check.diag(
            Status::Pass,
            format!("{exe} is on a nosuid mount; irrelevant while capabilities are effective"),
        );
    }
    check
        .diag(
            Status::Fail,
            format!("{exe} is on a nosuid mount; file capabilities are ignored there"),
        )
        .with_impact(format!(
            "setcap on {exe} has no effect; {} cannot run unprivileged",
            tool.name
        ))
        .with_fix(setcap_fix(env, tool, &[], SETCAP_NOTE))
}

pub(super) fn nnp(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    if !env.no_new_privs() {
        return check.diag(Status::Pass, "no_new_privs not set");
    }
    if privileged(env, tool) {
        return check.diag(
            Status::Info,
            "no_new_privs set; no effect while capabilities are effective",
        );
    }
    check
        .diag(Status::Warn, "no_new_privs set")
        .with_impact(
            "file capabilities are ignored under no_new_privs \
             (sandbox, systemd NoNewPrivileges, some IDE terminals)",
        )
        .with_fix(Fix::new(
            sudo_tool(tool),
            "from a shell without no_new_privs, which blocks sudo too",
        ))
        .with_fix(Fix::new(
            format!("run {} from a terminal outside the sandbox", tool.name),
            "",
        ))
}

pub(super) fn optional_caps(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    if tool.optional_caps.is_empty() {
        return check.diag(Status::Pass, "no optional capabilities");
    }
    let all: Vec<Cap> = tool.optional_caps.iter().map(|&(cap, _)| cap).collect();
    let effective = env.caps().effective;
    let missing: Vec<(Cap, &str)> = tool
        .optional_caps
        .iter()
        .copied()
        .filter(|(cap, _)| !cap.granted_by(effective))
        .collect();
    if missing.is_empty() {
        return check.diag(Status::Pass, format!("{} effective", names(&all)));
    }
    let missing_caps: Vec<Cap> = missing.iter().map(|&(cap, _)| cap).collect();
    let impact = missing
        .iter()
        .map(|(cap, enables)| format!("{cap} enables {enables}"))
        .collect::<Vec<_>>()
        .join("; ");
    check
        .diag(
            Status::Warn,
            format!("missing optional {}", names(&missing_caps)),
        )
        .with_impact(impact)
        .with_fix(setcap_fix(env, tool, &all, SETCAP_NOTE))
        .with_explain(rationale(&missing_caps))
}

pub(super) fn sudo(check: &Shared, env: &dyn Env, _: &Tool) -> Diagnostic {
    let ids = env.ids();
    match ids.sudo_uid {
        Some(uid) if ids.euid == 0 => check.diag(
            Status::Info,
            format!("running via sudo (invoking user uid {uid})"),
        ),
        _ => check.diag(Status::Pass, "not running via sudo"),
    }
}
