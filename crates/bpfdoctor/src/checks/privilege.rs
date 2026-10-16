//! Capabilities and the mechanisms that grant or block them.

use std::path::Path;

use super::{Shared, missing_caps, privileged, sudo_tool};
use crate::cap::{names, rationale};
use crate::tool::shell_quote;
use crate::{Cap, Diagnostic, Env, Fix, Status, Tool};

const SETCAP_NOTE: &str = "one-time; re-run after every reinstall";

pub(super) fn capabilities(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    if tool.required_caps.is_empty() {
        return check.diag(Status::Pass, "no capabilities required");
    }
    let missing = missing_caps(env.caps().effective, tool.required_caps);
    if missing.is_empty() {
        return check.diag(
            Status::Pass,
            format!("{} effective", names(tool.required_caps)),
        );
    }
    let observed = format!(
        "missing {} (uid {}, {})",
        names(&missing),
        env.ids().uid,
        file_caps_state(env, tool)
    );
    check
        .diag(Status::Fail, observed)
        .with_impact(format!(
            "cannot load tracing programs; {} cannot run",
            tool.name
        ))
        .with_fix(Fix::new(tool.setcap_command(&[], &tool.exe), SETCAP_NOTE))
        .with_fix(Fix::new(sudo_tool(tool), "run once with root"))
        .with_explain(rationale(tool.required_caps))
}

/// How the executable's file capabilities relate to the required set.
fn file_caps_state(env: &dyn Env, tool: &Tool) -> String {
    let exe = tool.exe.display();
    let Some(mask) = env.file_caps(&tool.exe).filter(|&mask| mask != 0) else {
        return format!("no file capabilities on {exe}");
    };
    let lacking = missing_caps(mask, tool.required_caps);
    if lacking.is_empty() {
        format!("file capabilities on {exe} are not in effect")
    } else {
        format!("file capabilities on {exe} lack {}", names(&lacking))
    }
}

pub(super) fn file_caps(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    let exe = tool.exe.display();
    let Some(mask) = env.file_caps(&tool.exe).filter(|&mask| mask != 0) else {
        return if env.ids().euid == 0 {
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
    let lacking = missing_caps(mask, tool.required_caps);
    if !lacking.is_empty() {
        return check
            .diag(
                Status::Warn,
                format!("file capabilities on {exe} lack {}", names(&lacking)),
            )
            .with_fix(Fix::new(tool.setcap_command(&[], &tool.exe), SETCAP_NOTE));
    }
    if privileged(env, tool) {
        return check.diag(
            Status::Pass,
            format!("file capabilities on {exe} in effect"),
        );
    }
    check
        .diag(
            Status::Warn,
            format!("file capabilities on {exe} are not in effect"),
        )
        .with_impact(format!(
            "{} runs without the capabilities it was installed with",
            tool.name
        ))
        .with_explain(
            "the kernel ignores file capabilities on nosuid mounts and under no_new_privs; \
             see priv.nosuid and priv.nnp",
        )
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
    let target = format!("/usr/local/bin/{}", tool.name);
    let install = format!(
        "sudo install -m 0755 {} {target} && {}",
        shell_quote(&tool.exe),
        tool.setcap_command(&[], Path::new(&target))
    );
    check
        .diag(
            Status::Fail,
            format!("{exe} is on a nosuid mount; file capabilities are ignored there"),
        )
        .with_impact(format!(
            "setcap on {exe} has no effect; {} cannot run unprivileged",
            tool.name
        ))
        .with_fix(Fix::new(
            install,
            "installs onto a mount that honours file capabilities",
        ))
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
        .with_fix(Fix::new(tool.setcap_command(&all, &tool.exe), SETCAP_NOTE))
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
