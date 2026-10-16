//! Memory limits, filesystems and BPF feature probes.

use std::path::Path;

use super::{
    MEMCG_KERNEL, Shared, errno_label, kernel_at_least, memcg_accounting, privileged, read_text,
    sudo_tool,
};
use crate::{BpfProbe, Cap, Diagnostic, Env, Fix, Status, Tool};

const CGROUP2_CONTROLLERS: &str = "/sys/fs/cgroup/cgroup.controllers";
const MOUNTINFO: &str = "/proc/self/mountinfo";

pub(super) fn memlock(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    if memcg_accounting(env).unwrap_or_else(|| kernel_at_least(env, MEMCG_KERNEL)) {
        return check.diag(
            Status::Skip,
            "BPF memory is charged to memcg; RLIMIT_MEMLOCK does not apply",
        );
    }
    let (soft, hard) = env.memlock();
    let need = tool.memlock_bytes;
    if hard >= need || Cap::SysResource.granted_by(env.caps().effective) {
        return check.diag(
            Status::Pass,
            format!(
                "RLIMIT_MEMLOCK {} soft / {} hard; {} needs {}",
                bytes(soft),
                bytes(hard),
                tool.name,
                bytes(need)
            ),
        );
    }
    let ids = env.ids();
    // limits.conf accepts `uid:uid` ranges when no user name is known.
    let user = ids
        .sudo_user
        .or_else(|| env.env_var("USER"))
        .unwrap_or_else(|| format!("{0}:{0}", ids.uid));
    check
        .diag(
            Status::Fail,
            format!(
                "RLIMIT_MEMLOCK hard limit {} is below the {} {} needs",
                bytes(hard),
                bytes(need),
                tool.name
            ),
        )
        .with_impact(format!("BPF map creation fails with EPERM; {} cannot run", tool.name))
        .with_fix(Fix::new(
            tool.setcap_command(&[Cap::SysResource], &tool.exe),
            format!("lets {} raise its own limit", tool.name),
        ))
        .with_fix(Fix::new(
            "sudo prlimit --memlock=unlimited:unlimited --pid $$",
            format!("raises the limit of this shell; run {} from it", tool.name),
        ))
        .with_fix(Fix::new(
            format!("echo '{user} hard memlock unlimited' | sudo tee -a /etc/security/limits.conf"),
            "persistent; applies from the next login",
        ))
        .with_explain("before 5.11 BPF memory counts against RLIMIT_MEMLOCK; since 5.11 it is charged to memcg")
}

/// `8 MiB`, `64 KiB`, `1000 B` or `unlimited`.
fn bytes(n: u64) -> String {
    const UNITS: [(u64, &str); 3] = [(1 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")];
    if n == u64::MAX {
        return "unlimited".to_owned();
    }
    UNITS
        .iter()
        .find(|&&(size, _)| n >= size && n.is_multiple_of(size))
        .map_or_else(
            || format!("{n} B"),
            |&(size, unit)| format!("{} {unit}", n / size),
        )
}

pub(super) fn cgroup2(check: &Shared, env: &dyn Env, _: &Tool) -> Diagnostic {
    if env.exists(Path::new(CGROUP2_CONTROLLERS)) {
        return check.diag(Status::Pass, "cgroup v2 mounted at /sys/fs/cgroup");
    }
    check
        .diag(
            Status::Warn,
            "cgroup v2 not mounted; unit/container attribution degraded",
        )
        .with_fix(Fix::new(
            "boot with systemd.unified_cgroup_hierarchy=1",
            "kernel command line; the default on current distros",
        ))
}

pub(super) fn proc_hidepid(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    let Some(mountinfo) = read_text(env, MOUNTINFO) else {
        return check.diag(Status::Skip, format!("{MOUNTINFO} not readable"));
    };
    match hidepid(&mountinfo) {
        None => check.diag(Status::Pass, "/proc mounted without hidepid"),
        Some(level) => check
            .diag(Status::Warn, format!("/proc mounted with hidepid={level}"))
            .with_impact(format!(
                "other users' processes are hidden from /proc; {} cannot name them",
                tool.name
            ))
            .with_fix(Fix::new(sudo_tool(tool), "root sees every process")),
    }
}

/// The active `hidepid=` level of the topmost proc mount on `/proc`, unless off.
fn hidepid(mountinfo: &str) -> Option<&str> {
    // Format: "id parent maj:min root mountpoint opts [optional...] - fstype source superopts".
    let super_options = mountinfo
        .lines()
        .filter_map(|line| {
            let (mount, fs) = line.split_once(" - ")?;
            if mount.split_whitespace().nth(4) != Some("/proc") {
                return None;
            }
            let mut fs = fs.split_whitespace();
            if fs.next() != Some("proc") {
                return None;
            }
            fs.nth(1)
        })
        .next_back()?;
    super_options
        .split(',')
        .find_map(|option| option.strip_prefix("hidepid="))
        .filter(|level| !matches!(*level, "0" | "off"))
}

pub(super) fn ringbuf(check: &Shared, env: &dyn Env, tool: &Tool) -> Diagnostic {
    if !privileged(env, tool) {
        return check.diag(Status::Skip, "skipped: required capabilities not effective");
    }
    match env.bpf_probe(BpfProbe::RingBuf) {
        Ok(()) => check.diag(Status::Pass, "BPF ring buffer map created"),
        Err(errno) => check
            .diag(
                Status::Fail,
                format!(
                    "BPF ring buffer map creation failed: {}",
                    errno_label(errno)
                ),
            )
            .with_impact(format!("{} cannot stream events", tool.name))
            .with_explain(ringbuf_hint(errno)),
    }
}

fn ringbuf_hint(errno: i32) -> &'static str {
    match errno {
        libc::EPERM | libc::EACCES => {
            "the kernel refused bpf(); see priv.capabilities, env.seccomp, sec.lsm and rlimit.memlock"
        }
        libc::EINVAL => "BPF_MAP_TYPE_RINGBUF needs kernel 5.8+; see kernel.version",
        libc::ENOSYS => {
            "bpf() is unavailable: kernel built without CONFIG_BPF_SYSCALL, or filtered by seccomp"
        }
        libc::ENOMEM => "the kernel could not allocate the map; see rlimit.memlock",
        _ => "unexpected bpf(BPF_MAP_CREATE) failure",
    }
}

pub(super) fn memcg(check: &Shared, env: &dyn Env, _: &Tool) -> Diagnostic {
    match memcg_accounting(env) {
        Some(true) => check.diag(Status::Info, "memcg accounting: yes"),
        Some(false) => check
            .diag(Status::Info, "memcg accounting: no")
            .with_explain("BPF memory counts against RLIMIT_MEMLOCK; see rlimit.memlock"),
        None => check.diag(
            Status::Skip,
            "memcg accounting: unknown (probe needs privileges)",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{bytes, hidepid};

    #[test]
    fn formats_exact_binary_units_only() {
        assert_eq!(bytes(64 << 10), "64 KiB");
        assert_eq!(bytes(8 << 20), "8 MiB");
        assert_eq!(bytes(2 << 30), "2 GiB");
        assert_eq!(bytes(1536 << 10), "1536 KiB");
        assert_eq!(bytes(1000), "1000 B");
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(u64::MAX), "unlimited");
    }

    #[test]
    fn hidepid_reads_topmost_proc_mount_super_options() {
        let base = "22 1 259:2 / / rw - ext4 /dev/root rw\n";
        let first = "23 22 0:21 / /proc rw,nosuid shared:5 - proc proc rw,hidepid=2\n";
        let over = "40 23 0:30 / /proc rw - proc proc rw,hidepid=off\n";
        assert_eq!(hidepid(&format!("{base}{first}")), Some("2"));
        assert_eq!(hidepid(&format!("{base}{first}{over}")), None);
        assert_eq!(hidepid(&format!("{base}{over}{first}")), Some("2"));
        // Only the proc filesystem mounted on /proc counts.
        let elsewhere = "50 22 0:31 / /srv/proc rw - proc proc rw,hidepid=invisible\n";
        assert_eq!(hidepid(&format!("{base}{elsewhere}")), None);
        assert_eq!(
            hidepid("60 22 0:32 / /proc rw - proc proc rw,hidepid=invisible"),
            Some("invisible")
        );
    }
}
