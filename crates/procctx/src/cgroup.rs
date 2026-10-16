use std::{fmt, sync::Arc};

/// A cgroup v2 directory and what its path reveals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CgroupInfo {
    /// cgroup id (the directory's inode, as `bpf_get_current_cgroup_id` reports).
    /// `None` means the path came from `/proc/<pid>/cgroup`, which carries no id.
    pub id: Option<u64>,
    /// Path relative to the cgroup2 mount, starting with `/`.
    pub path: Arc<str>,
    /// Owning systemd unit. `None` means the path names no unit.
    pub unit: Option<SystemdUnit>,
    /// Innermost container. `None` means the path matches no known runtime layout.
    pub container: Option<Container>,
}

impl CgroupInfo {
    /// Classifies a cgroup v2 path.
    pub fn new(id: Option<u64>, path: Arc<str>) -> Self {
        let unit = parse_unit(&path);
        let container = parse_container(&path);
        Self {
            id,
            path,
            unit,
            container,
        }
    }
}

/// A systemd unit that owns a cgroup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemdUnit {
    /// Unit name, such as `nginx.service` or `tmux-spawn-1a2b.scope`.
    pub name: Box<str>,
    /// The systemd instance managing the unit.
    pub manager: Manager,
    /// Nearest enclosing slice under the same manager. `None` means the unit sits
    /// directly under the manager's root.
    pub slice: Option<Box<str>>,
}

/// Which systemd instance manages a unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Manager {
    /// PID 1.
    System,
    /// A per-user manager (`user@<uid>.service`).
    User {
        /// Owner of the manager.
        uid: u32,
    },
}

/// A container a cgroup belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Container {
    /// Runtime that created it.
    pub runtime: Runtime,
    /// Full container id (64 hex digits), or the machine/container name for
    /// LXC and nspawn.
    pub id: Box<str>,
}

impl Container {
    /// The first 12 characters of the id, as `docker ps` shows it.
    pub fn short_id(&self) -> &str {
        match self.id.char_indices().nth(12) {
            Some((end, _)) => &self.id[..end],
            None => &self.id,
        }
    }
}

impl fmt::Display for Container {
    /// Formats as `<runtime>:<short id>`, such as `docker:3f4e5d6c7b8a`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.runtime, self.short_id())
    }
}

/// Container runtimes recognised from cgroup paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Runtime {
    /// `docker-<id>.scope` (systemd driver) or `/docker/<id>` (cgroupfs driver).
    Docker,
    /// `libpod-<id>.scope` (systemd driver) or `/libpod-<id>/` (cgroupfs driver).
    Podman,
    /// `cri-containerd-<id>.scope`.
    Containerd,
    /// `crio-<id>.scope`.
    CriO,
    /// `lxc.payload.<name>`.
    Lxc,
    /// `machine.slice/systemd-nspawn@<name>.service` or `machine-<name>.scope`.
    Nspawn,
}

impl Runtime {
    /// Lower-case runtime name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
            Self::Containerd => "containerd",
            Self::CriO => "cri-o",
            Self::Lxc => "lxc",
            Self::Nspawn => "nspawn",
        }
    }
}

impl fmt::Display for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

const UNIT_SUFFIXES: [&str; 5] = [".service", ".scope", ".socket", ".mount", ".swap"];

/// Finds the systemd unit owning a cgroup v2 path.
///
/// The unit is the last component with a unit suffix (`.service`, `.scope`,
/// `.socket`, `.mount` or `.swap`), and the slice is the nearest `.slice` above it.
/// Units below `user@<uid>.service` belong to that user's manager. A path that ends
/// at the manager itself belongs to the system manager.
pub fn parse_unit(path: &str) -> Option<SystemdUnit> {
    let parts: Vec<&str> = components(path).collect();
    let user = parts
        .iter()
        .enumerate()
        .find_map(|(at, part)| Some((at, user_manager_uid(part)?)));
    if let Some((at, uid)) = user
        && let Some(unit) = unit_in(&parts[at + 1..], Manager::User { uid })
    {
        return Some(unit);
    }
    unit_in(&parts, Manager::System)
}

/// Finds the innermost container in a cgroup v2 path (see [`Runtime`] for the
/// layouts recognised).
pub fn parse_container(path: &str) -> Option<Container> {
    let mut found = None;
    let mut parent = "";
    for part in components(path) {
        if let Some(container) = container_at(parent, part) {
            found = Some(container);
        }
        parent = part;
    }
    found
}

/// Extracts the cgroup v2 path (the `0::` line) from `/proc/<pid>/cgroup`.
pub(crate) fn cgroup_v2_path(contents: &[u8]) -> Option<&[u8]> {
    contents
        .split(|&b| b == b'\n')
        .find_map(|line| line.strip_prefix(b"0::"))
        .filter(|path| !path.is_empty())
}

fn components(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|part| !part.is_empty())
}

fn user_manager_uid(part: &str) -> Option<u32> {
    part.strip_prefix("user@")?
        .strip_suffix(".service")?
        .parse()
        .ok()
}

fn has_stem(name: &str, suffix: &str) -> bool {
    name.strip_suffix(suffix)
        .is_some_and(|stem| !stem.is_empty())
}

fn unit_in(parts: &[&str], manager: Manager) -> Option<SystemdUnit> {
    let at = parts
        .iter()
        .rposition(|part| UNIT_SUFFIXES.iter().any(|s| has_stem(part, s)))?;
    let slice = parts[..at]
        .iter()
        .rev()
        .find(|part| has_stem(part, ".slice"));
    Some(SystemdUnit {
        name: Box::from(parts[at]),
        manager,
        slice: slice.map(|&slice| Box::from(slice)),
    })
}

fn is_container_hex(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn scope_id<'a>(part: &'a str, prefix: &str) -> Option<&'a str> {
    part.strip_prefix(prefix)?
        .strip_suffix(".scope")
        .filter(|id| is_container_hex(id))
}

fn named<'a>(part: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    part.strip_prefix(prefix)?
        .strip_suffix(suffix)
        .filter(|name| !name.is_empty())
}

fn container_at(parent: &str, part: &str) -> Option<Container> {
    let (runtime, id) = if let Some(id) = scope_id(part, "docker-") {
        (Runtime::Docker, id)
    } else if parent == "docker" && is_container_hex(part) {
        (Runtime::Docker, part)
    } else if let Some(id) = scope_id(part, "libpod-").or_else(|| {
        part.strip_prefix("libpod-")
            .filter(|id| is_container_hex(id))
    }) {
        (Runtime::Podman, id)
    } else if let Some(id) = scope_id(part, "cri-containerd-") {
        (Runtime::Containerd, id)
    } else if let Some(id) = scope_id(part, "crio-") {
        (Runtime::CriO, id)
    } else if let Some(name) = part.strip_prefix("lxc.payload.").filter(|n| !n.is_empty()) {
        (Runtime::Lxc, name)
    } else if let Some(name) = named(part, "machine-", ".scope").or_else(|| {
        named(part, "systemd-nspawn@", ".service").filter(|_| parent == "machine.slice")
    }) {
        (Runtime::Nspawn, name)
    } else {
        return None;
    };
    Some(Container {
        runtime,
        id: Box::from(id),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CgroupInfo, Container, Manager, Runtime, SystemdUnit, cgroup_v2_path, parse_container,
        parse_unit,
    };

    const HEX: &str = "3f4e5d6c7b8a99001122334455667788990011223344556677889900aabbccdd";

    // `Option`-returning so assertions compare directly against `parse_*` results.
    #[allow(clippy::unnecessary_wraps)]
    fn unit(name: &str, manager: Manager, slice: Option<&str>) -> Option<SystemdUnit> {
        Some(SystemdUnit {
            name: name.into(),
            manager,
            slice: slice.map(Into::into),
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn container(runtime: Runtime, id: &str) -> Option<Container> {
        Some(Container {
            runtime,
            id: id.into(),
        })
    }

    #[test]
    fn system_units_and_slices() {
        assert_eq!(
            parse_unit("/system.slice/nginx.service"),
            unit("nginx.service", Manager::System, Some("system.slice"))
        );
        assert_eq!(
            parse_unit("/init.scope"),
            unit("init.scope", Manager::System, None)
        );
        assert_eq!(
            parse_unit("/system.slice/system-getty.slice/getty@tty1.service"),
            unit(
                "getty@tty1.service",
                Manager::System,
                Some("system-getty.slice")
            )
        );
        for name in ["dbus.socket", "boot.mount", "dev-sda2.swap"] {
            let path = format!("/system.slice/{name}");
            assert_eq!(parse_unit(&path).unwrap().name.as_ref(), name);
        }
        // The last unit component wins, even with plain directories below it.
        assert_eq!(
            parse_unit("/system.slice/containerd.service/payload/sub")
                .unwrap()
                .name
                .as_ref(),
            "containerd.service"
        );
    }

    #[test]
    fn no_unit() {
        assert_eq!(parse_unit("/"), None);
        assert_eq!(parse_unit("/user.slice"), None);
        assert_eq!(parse_unit("/lxc.payload.web"), None);
        // A bare suffix is not a unit name.
        assert_eq!(parse_unit("/.service"), None);
        assert_eq!(parse_unit("/system.slice/.scope"), None);
    }

    #[test]
    fn user_manager_units() {
        let path = "/user.slice/user-1000.slice/user@1000.service/app.slice/tmux-spawn-5f2c.scope";
        assert_eq!(
            parse_unit(path),
            unit(
                "tmux-spawn-5f2c.scope",
                Manager::User { uid: 1000 },
                Some("app.slice")
            )
        );
        // The system manager's user-1000.slice must not leak into the user unit.
        assert_eq!(
            parse_unit("/user.slice/user-1000.slice/user@1000.service/init.scope"),
            unit("init.scope", Manager::User { uid: 1000 }, None)
        );
        // The manager process itself: owned by the system manager.
        assert_eq!(
            parse_unit("/user.slice/user-1000.slice/user@1000.service"),
            unit(
                "user@1000.service",
                Manager::System,
                Some("user-1000.slice")
            )
        );
        // Login session scopes live outside the user manager.
        assert_eq!(
            parse_unit("/user.slice/user-1000.slice/session-3.scope"),
            unit("session-3.scope", Manager::System, Some("user-1000.slice"))
        );
        // Non-numeric uid: not a user manager.
        assert_eq!(
            parse_unit("/user.slice/user@me.service/app.slice/x.scope")
                .unwrap()
                .manager,
            Manager::System
        );
    }

    #[test]
    fn every_runtime_layout() {
        let cases = [
            (
                format!("/system.slice/docker-{HEX}.scope"),
                container(Runtime::Docker, HEX),
            ),
            (format!("/docker/{HEX}"), container(Runtime::Docker, HEX)),
            (
                format!("/machine.slice/libpod-{HEX}.scope/container"),
                container(Runtime::Podman, HEX),
            ),
            (
                format!("/libpod_parent/libpod-{HEX}/sub"),
                container(Runtime::Podman, HEX),
            ),
            (
                format!("/kubepods.slice/kubepods-pod1.slice/cri-containerd-{HEX}.scope"),
                container(Runtime::Containerd, HEX),
            ),
            (
                format!("/kubepods.slice/crio-{HEX}.scope"),
                container(Runtime::CriO, HEX),
            ),
            (
                "/lxc.payload.web/system.slice/x.service".into(),
                container(Runtime::Lxc, "web"),
            ),
            (
                "/machine.slice/systemd-nspawn@arch.service/payload".into(),
                container(Runtime::Nspawn, "arch"),
            ),
            (
                "/machine.slice/machine-arch.scope".into(),
                container(Runtime::Nspawn, "arch"),
            ),
        ];
        for (path, expected) in cases {
            assert_eq!(parse_container(&path), expected, "{path}");
        }
    }

    #[test]
    fn container_near_misses() {
        let cases = [
            // Short or non-hex ids.
            "/system.slice/docker-abc.scope".to_owned(),
            format!("/system.slice/docker-{}.scope", &HEX[1..]),
            format!("/system.slice/docker-{}zz.scope", &HEX[2..]),
            // conmon monitors run beside the container, not in it.
            format!("/machine.slice/libpod-conmon-{HEX}.scope"),
            format!("/kubepods.slice/crio-conmon-{HEX}.scope"),
            // The hex directory must sit directly under `docker`.
            format!("/notdocker/{HEX}"),
            format!("/docker/x/{HEX}"),
            // nspawn's service form only counts under machine.slice.
            "/system.slice/systemd-nspawn@arch.service".into(),
            "/lxc.payload.".into(),
            "/machine.slice/machine-.scope".into(),
        ];
        for path in cases {
            assert_eq!(parse_container(&path), None, "{path}");
        }
    }

    #[test]
    fn innermost_container_wins() {
        let inner = "0123456789abcdef".repeat(4);
        let path = format!("/lxc.payload.host/system.slice/docker-{inner}.scope");
        assert_eq!(parse_container(&path), container(Runtime::Docker, &inner));
    }

    #[test]
    fn short_id_and_display() {
        let docker = container(Runtime::Docker, HEX).unwrap();
        assert_eq!(docker.short_id(), "3f4e5d6c7b8a");
        assert_eq!(docker.to_string(), "docker:3f4e5d6c7b8a");
        let lxc = container(Runtime::Lxc, "web").unwrap();
        assert_eq!(lxc.short_id(), "web");
        // Names may be non-ASCII; the cut must land on a character boundary.
        let nspawn = container(Runtime::Nspawn, "ééééééééééééé").unwrap();
        assert_eq!(nspawn.short_id(), "éééééééééééé");
        assert_eq!(Runtime::CriO.to_string(), "cri-o");
    }

    #[test]
    fn info_combines_unit_and_container() {
        let info = CgroupInfo::new(Some(42), format!("/system.slice/docker-{HEX}.scope").into());
        assert_eq!(
            info.unit.unwrap().name.as_ref(),
            format!("docker-{HEX}.scope")
        );
        assert_eq!(info.container.unwrap().runtime, Runtime::Docker);
        assert_eq!(info.id, Some(42));
    }

    #[test]
    fn proc_cgroup_v2_line() {
        let hybrid = b"12:cpu,cpuacct:/user.slice\n1:name=systemd:/user.slice/x.scope\n\
0::/user.slice/x.scope\n";
        assert_eq!(cgroup_v2_path(hybrid), Some(&b"/user.slice/x.scope"[..]));
        assert_eq!(cgroup_v2_path(b"0::/\n"), Some(&b"/"[..]));
        // cgroup v1 only.
        assert_eq!(cgroup_v2_path(b"4:memory:/foo\n"), None);
        assert_eq!(cgroup_v2_path(b"0::\n"), None);
        // Paths may contain colons.
        assert_eq!(cgroup_v2_path(b"0::/a:b\n"), Some(&b"/a:b"[..]));
    }
}
