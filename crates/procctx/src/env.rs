use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::PathBuf, str::FromStr};

use crate::Pid;

/// Every environment variable procctx reads; everything else in an environment block
/// is ignored. Producers that filter environments in-kernel need only forward these.
pub const ENV_KEYS: &[&str] = &[
    "npm_lifecycle_event",
    "npm_package_name",
    "npm_package_version",
    "npm_config_user_agent",
    "CARGO_PKG_NAME",
    "CARGO_PKG_VERSION",
    "CARGO_MANIFEST_DIR",
    "OUT_DIR",
    "MAKELEVEL",
    "PIP_BUILD_TRACKER",
    "TMUX",
    "TMUX_PANE",
];

/// The facts procctx keeps from a process environment. This is an allow-list
/// ([`ENV_KEYS`]); the full environment is never stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvFacts {
    /// The tmux pane the process runs in. `None` means `TMUX_PANE` is unset.
    pub tmux: Option<TmuxPane>,
    /// Package-manager and build-tool variables.
    pub lifecycle: LifecycleEnv,
}

impl EnvFacts {
    /// Whether no allow-listed variable was present.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Variables that package managers and build tools export to the scripts they run.
/// For every field, `None`/`false` means unset or empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LifecycleEnv {
    /// `npm_lifecycle_event`: the running script (`install`, `postinstall`, ...).
    pub npm_lifecycle_event: Option<Box<str>>,
    /// `npm_package_name`: the package whose script runs.
    pub npm_package_name: Option<Box<str>>,
    /// `npm_package_version`.
    pub npm_package_version: Option<Box<str>>,
    /// `npm_config_user_agent`, such as `pnpm/8.15.1 npm/? node/v20.11.0 linux x64`.
    pub npm_config_user_agent: Option<Box<str>>,
    /// `CARGO_PKG_NAME`: the package Cargo is building.
    pub cargo_pkg_name: Option<Box<str>>,
    /// `CARGO_PKG_VERSION`.
    pub cargo_pkg_version: Option<Box<str>>,
    /// `CARGO_MANIFEST_DIR`.
    pub cargo_manifest_dir: Option<Box<str>>,
    /// `OUT_DIR` is set. Cargo sets it only for build scripts and the crates they build.
    pub out_dir_set: bool,
    /// `MAKELEVEL`: recursion depth below the outermost `make`. `None` means unset or
    /// not a number.
    pub makelevel: Option<u32>,
    /// `PIP_BUILD_TRACKER` is set. pip sets it while it builds packages.
    pub pip_build_tracker: bool,
}

/// A tmux pane, from `TMUX_PANE=%N` and `TMUX=<socket>,<server_pid>,<session>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TmuxPane {
    /// Pane id as tmux prints it, such as `%3`.
    pub pane: Box<str>,
    /// Server socket. `None` means `TMUX` is unset.
    pub socket: Option<PathBuf>,
    /// tmux server pid. `None` means `TMUX` is unset or malformed.
    pub server_pid: Option<Pid>,
    /// Session index. `None` means `TMUX` is unset or malformed.
    pub session: Option<u32>,
}

/// First occurrence of each allow-listed variable, mirroring `getenv`.
#[derive(Default)]
struct Raw<'a> {
    npm_lifecycle_event: Option<&'a [u8]>,
    npm_package_name: Option<&'a [u8]>,
    npm_package_version: Option<&'a [u8]>,
    npm_config_user_agent: Option<&'a [u8]>,
    cargo_pkg_name: Option<&'a [u8]>,
    cargo_pkg_version: Option<&'a [u8]>,
    cargo_manifest_dir: Option<&'a [u8]>,
    out_dir: Option<&'a [u8]>,
    makelevel: Option<&'a [u8]>,
    pip_build_tracker: Option<&'a [u8]>,
    tmux: Option<&'a [u8]>,
    tmux_pane: Option<&'a [u8]>,
}

/// Extracts [`EnvFacts`] from a NUL-separated `KEY=VALUE` block, such as
/// `/proc/<pid>/environ` or an exec event's (possibly pre-filtered) environment.
///
/// When a key repeats, the first occurrence wins, as with `getenv`. Empty values
/// count as unset, and entries without `=` are skipped.
pub fn parse_env_facts(environ: &[u8]) -> EnvFacts {
    let mut raw = Raw::default();
    for entry in environ.split(|&b| b == 0) {
        let Some(eq) = entry.iter().position(|&b| b == b'=') else {
            continue;
        };
        let (key, value) = (&entry[..eq], &entry[eq + 1..]);
        let slot = match key {
            b"npm_lifecycle_event" => &mut raw.npm_lifecycle_event,
            b"npm_package_name" => &mut raw.npm_package_name,
            b"npm_package_version" => &mut raw.npm_package_version,
            b"npm_config_user_agent" => &mut raw.npm_config_user_agent,
            b"CARGO_PKG_NAME" => &mut raw.cargo_pkg_name,
            b"CARGO_PKG_VERSION" => &mut raw.cargo_pkg_version,
            b"CARGO_MANIFEST_DIR" => &mut raw.cargo_manifest_dir,
            b"OUT_DIR" => &mut raw.out_dir,
            b"MAKELEVEL" => &mut raw.makelevel,
            b"PIP_BUILD_TRACKER" => &mut raw.pip_build_tracker,
            b"TMUX" => &mut raw.tmux,
            b"TMUX_PANE" => &mut raw.tmux_pane,
            _ => continue,
        };
        if slot.is_none() {
            *slot = Some(value);
        }
    }
    EnvFacts {
        tmux: tmux_pane(set(raw.tmux), set(raw.tmux_pane)),
        lifecycle: LifecycleEnv {
            npm_lifecycle_event: text(raw.npm_lifecycle_event),
            npm_package_name: text(raw.npm_package_name),
            npm_package_version: text(raw.npm_package_version),
            npm_config_user_agent: text(raw.npm_config_user_agent),
            cargo_pkg_name: text(raw.cargo_pkg_name),
            cargo_pkg_version: text(raw.cargo_pkg_version),
            cargo_manifest_dir: text(raw.cargo_manifest_dir),
            out_dir_set: set(raw.out_dir).is_some(),
            makelevel: set(raw.makelevel).and_then(number),
            pip_build_tracker: set(raw.pip_build_tracker).is_some(),
        },
    }
}

fn set(value: Option<&[u8]>) -> Option<&[u8]> {
    value.filter(|v| !v.is_empty())
}

fn text(value: Option<&[u8]>) -> Option<Box<str>> {
    set(value).map(|v| Box::from(String::from_utf8_lossy(v)))
}

fn number<T: FromStr>(value: &[u8]) -> Option<T> {
    std::str::from_utf8(value).ok()?.parse().ok()
}

fn tmux_pane(tmux: Option<&[u8]>, pane: Option<&[u8]>) -> Option<TmuxPane> {
    let mut out = TmuxPane {
        pane: Box::from(String::from_utf8_lossy(pane?)),
        socket: None,
        server_pid: None,
        session: None,
    };
    if let Some(tmux) = tmux {
        // The socket path may itself contain commas, so split from the right.
        let mut parts = tmux.rsplitn(3, |&b| b == b',');
        let (session, server_pid) = (parts.next(), parts.next());
        if let Some(socket) = parts.next() {
            out.socket = set(Some(socket)).map(socket_path);
            out.server_pid = server_pid.and_then(number);
            out.session = session.and_then(number);
        } else {
            out.socket = Some(socket_path(tmux));
        }
    }
    Some(out)
}

fn socket_path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{ENV_KEYS, EnvFacts, LifecycleEnv, TmuxPane, parse_env_facts};

    #[test]
    fn every_allow_listed_key_is_parsed() {
        // Guards against ENV_KEYS and the parser drifting apart.
        let base = parse_env_facts(b"TMUX_PANE=%1");
        for key in ENV_KEYS {
            let environ = format!("{key}=1\0TMUX_PANE=%1");
            let reference = if *key == "TMUX_PANE" {
                EnvFacts::default()
            } else {
                base.clone()
            };
            assert_ne!(
                parse_env_facts(environ.as_bytes()),
                reference,
                "{key} ignored"
            );
        }
    }

    #[test]
    fn full_lifecycle_block() {
        let environ = b"PATH=/usr/bin\0npm_lifecycle_event=postinstall\0\
npm_package_name=@scope/pkg\0\
npm_package_version=1.2.3\0npm_config_user_agent=pnpm/8.15.1 npm/? node/v20.11.0\0\
CARGO_PKG_NAME=ring\0CARGO_PKG_VERSION=0.17.8\0CARGO_MANIFEST_DIR=/src/ring\0OUT_DIR=/t/out\0\
MAKELEVEL=2\0PIP_BUILD_TRACKER=/tmp/pip-build-tracker-x\0";
        let facts = parse_env_facts(environ);
        assert_eq!(
            facts.lifecycle,
            LifecycleEnv {
                npm_lifecycle_event: Some("postinstall".into()),
                npm_package_name: Some("@scope/pkg".into()),
                npm_package_version: Some("1.2.3".into()),
                npm_config_user_agent: Some("pnpm/8.15.1 npm/? node/v20.11.0".into()),
                cargo_pkg_name: Some("ring".into()),
                cargo_pkg_version: Some("0.17.8".into()),
                cargo_manifest_dir: Some("/src/ring".into()),
                out_dir_set: true,
                makelevel: Some(2),
                pip_build_tracker: true,
            }
        );
        assert_eq!(facts.tmux, None);
    }

    #[test]
    fn first_occurrence_wins_and_empty_is_unset() {
        let facts = parse_env_facts(b"MAKELEVEL=1\0MAKELEVEL=5\0OUT_DIR=\0npm_package_name=\0");
        assert_eq!(facts.lifecycle.makelevel, Some(1));
        assert!(!facts.lifecycle.out_dir_set);
        assert_eq!(facts.lifecycle.npm_package_name, None);

        // An empty first value shadows later ones, as getenv would.
        let facts = parse_env_facts(b"OUT_DIR=\0OUT_DIR=/x\0");
        assert!(!facts.lifecycle.out_dir_set);
    }

    #[test]
    fn near_miss_keys_and_garbage_are_ignored() {
        let facts = parse_env_facts(
            b"XTMUX_PANE=%1\0TMUX_PANEX=%2\0npm_lifecycle_eventX=a\0MAKELEVEL\0=MAKELEVEL\0\0\0",
        );
        assert!(facts.is_empty());
    }

    #[test]
    fn makelevel_must_be_numeric() {
        assert_eq!(parse_env_facts(b"MAKELEVEL=x1").lifecycle.makelevel, None);
        assert_eq!(parse_env_facts(b"MAKELEVEL=-1").lifecycle.makelevel, None);
        assert_eq!(parse_env_facts(b"MAKELEVEL=0").lifecycle.makelevel, Some(0));
    }

    #[test]
    fn values_may_contain_equals_signs() {
        let facts = parse_env_facts(b"npm_config_user_agent=a=b\0");
        assert_eq!(
            facts.lifecycle.npm_config_user_agent.as_deref(),
            Some("a=b")
        );
    }

    #[test]
    fn tmux_pane_and_server() {
        let facts = parse_env_facts(b"TMUX=/tmp/tmux-1000/default,1200,0\0TMUX_PANE=%3\0");
        assert_eq!(
            facts.tmux,
            Some(TmuxPane {
                pane: "%3".into(),
                socket: Some("/tmp/tmux-1000/default".into()),
                server_pid: Some(1200),
                session: Some(0),
            })
        );
    }

    #[test]
    fn tmux_socket_with_commas_splits_from_the_right() {
        let tmux = parse_env_facts(b"TMUX_PANE=%0\0TMUX=/tmp/a,b/sock,77,4\0")
            .tmux
            .unwrap();
        assert_eq!(tmux.socket.as_deref(), Some(Path::new("/tmp/a,b/sock")));
        assert_eq!(tmux.server_pid, Some(77));
        assert_eq!(tmux.session, Some(4));
    }

    #[test]
    fn tmux_malformed_or_missing() {
        // No commas: the whole value is the socket and nothing else is known.
        let tmux = parse_env_facts(b"TMUX_PANE=%9\0TMUX=/tmp/sock\0")
            .tmux
            .unwrap();
        assert_eq!(tmux.socket.as_deref(), Some(Path::new("/tmp/sock")));
        assert_eq!((tmux.server_pid, tmux.session), (None, None));

        // Non-numeric pid is dropped but the socket survives.
        let tmux = parse_env_facts(b"TMUX_PANE=%9\0TMUX=/s,pid,1\0")
            .tmux
            .unwrap();
        assert_eq!(tmux.socket.as_deref(), Some(Path::new("/s")));
        assert_eq!((tmux.server_pid, tmux.session), (None, Some(1)));

        // TMUX without TMUX_PANE: no pane, so no tmux context.
        assert_eq!(parse_env_facts(b"TMUX=/s,1,0\0").tmux, None);

        // TMUX_PANE without TMUX (TMUX unset to nest): pane without server details.
        let tmux = parse_env_facts(b"TMUX_PANE=%2\0").tmux.unwrap();
        assert_eq!((tmux.pane.as_ref(), tmux.socket), ("%2", None));
    }
}
