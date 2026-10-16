//! Operating system, architecture, kernel version and BTF.

use std::io;
use std::path::Path;

use super::{MEMCG_KERNEL, Shared};
use crate::{Diagnostic, Env, Fix, Status, Tool, parse_release};

/// Oldest kernel with BPF ring buffers and `CAP_BPF`.
const MIN_KERNEL: (u32, u32) = (5, 8);
const BACKPORTS: &str =
    "distro kernels backport BPF features, so the probe.* checks are authoritative";
const UPGRADE: &str =
    "upgrade to a 5.15+ distro kernel (Ubuntu 22.04+, Debian 12+, RHEL 9+, Fedora, Arch)";
const VMLINUX: &str = "/sys/kernel/btf/vmlinux";
const BTF_MAGIC: u16 = 0xEB9F;

pub(super) fn os_arch(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    let uname = env.uname();
    let observed = format!("{} {}", uname.sysname, uname.machine);
    if uname.sysname == "Linux" && matches!(uname.machine.as_str(), "x86_64" | "aarch64") {
        return check.diag(Status::Pass, observed);
    }
    check
        .diag(Status::Fail, format!("{observed} is not supported"))
        .with_impact(format!(
            "{} ships BPF objects for Linux x86_64 and aarch64 only",
            tool.name
        ))
        .with_fix(Fix::new("run on a Linux x86_64 or aarch64 host", ""))
        .with_explain("BPF objects are compiled per architecture")
}

pub(super) fn kernel_version(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    let release = env.uname().release;
    let Some((major, minor, patch)) = parse_release(&release) else {
        return check
            .diag(
                Status::Warn,
                format!("cannot parse kernel release {release:?}"),
            )
            .with_explain(BACKPORTS);
    };
    let version = format!("{major}.{minor}.{patch}");
    let floor = MIN_KERNEL.max(tool.min_kernel);
    if (major, minor) < floor {
        let impact = if (major, minor) < MIN_KERNEL {
            format!("no BPF ring buffer / CAP_BPF; {} cannot run", tool.name)
        } else {
            format!(
                "{} needs kernel {}.{} or newer",
                tool.name, floor.0, floor.1
            )
        };
        return check
            .diag(
                Status::Fail,
                format!("kernel {version} is older than {}.{}", floor.0, floor.1),
            )
            .with_impact(impact)
            .with_fix(Fix::new(UPGRADE, ""))
            .with_explain(BACKPORTS);
    }
    if (major, minor) < MEMCG_KERNEL {
        return check
            .diag(
                Status::Warn,
                format!("{version}: tier-2 kernel; some probes may fall back"),
            )
            .with_explain(BACKPORTS);
    }
    check.diag(Status::Pass, format!("{version} ≥ {}.{}", floor.0, floor.1))
}

pub(super) fn kernel_btf(check: &Shared, env: &dyn Env, _: &Tool) -> Diagnostic {
    let problem = match env.read_head(Path::new(VMLINUX), 2) {
        Ok(head) if head.starts_with(&BTF_MAGIC.to_le_bytes()) => {
            return check.diag(Status::Pass, format!("{VMLINUX} present"));
        }
        Ok(_) => format!("{VMLINUX} has no BTF header"),
        Err(err) if err.kind() == io::ErrorKind::NotFound => format!("{VMLINUX} is missing"),
        Err(err) => format!("{VMLINUX} is unreadable ({err})"),
    };
    check
        .diag(Status::Fail, problem)
        .with_impact("tp_btf/fentry programs cannot be loaded")
        .with_fix(Fix::new(
            "use a distro kernel built with CONFIG_DEBUG_INFO_BTF=y \
             (default on Fedora 31+, Ubuntu 20.10+, Debian 11+, RHEL 8.2+, Arch)",
            "",
        ))
        .with_explain("tracing programs need the running kernel's own BTF; external BTF (BTFHub) is not sufficient")
}
