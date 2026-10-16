use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path, sync::Arc};

use crate::{Pid, ProcInfo, ProcKey};

/// Which package-manager or build-tool step a process runs under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// The kind of step.
    pub kind: OriginKind,
    /// Package being installed or built. `None` means the evidence does not name it.
    pub package: Option<Box<str>>,
    /// Package version. `None` means the evidence does not name it.
    pub version: Option<Box<str>>,
    /// Lifecycle phase, such as `postinstall`. `None` for kinds without phases, or
    /// when unknown.
    pub phase: Option<Box<str>>,
    /// How strongly the evidence supports the classification.
    pub confidence: Confidence,
    /// The process whose facts matched (the nearest matching ancestor).
    pub via: ProcKey,
    /// What matched, as `<source>:<item>@<pid>`, such as `env:npm_lifecycle_event@8812`.
    pub evidence: Vec<Box<str>>,
}

/// Kinds of [`Origin`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OriginKind {
    /// An npm lifecycle script (also the default for unknown user agents).
    NpmLifecycle,
    /// A pnpm lifecycle script.
    PnpmLifecycle,
    /// A Yarn lifecycle script.
    YarnLifecycle,
    /// A Bun lifecycle script.
    BunLifecycle,
    /// A Cargo build script (`build.rs`).
    CargoBuildScript,
    /// A pip package build.
    PipBuild,
    /// A `make` recipe.
    Make,
}

/// Strength of an [`Origin`] classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Confidence {
    /// Direct, specific evidence (the variables the tool itself exports).
    High,
    /// Indirect evidence (paths, or variables that do not name the package).
    Medium,
    /// Weak evidence (`make`, or a lifecycle event without a package).
    Low,
}

/// Classifies the build step behind a process from its ancestry, nearest first
/// (as [`Ancestry::chain`](crate::Ancestry::chain) orders it).
///
/// The nearest process with specific evidence wins. Within one process the rules
/// rank as follows:
/// 1. Cargo build script: `CARGO_PKG_NAME` and `OUT_DIR` are set, and the exe or
///    `argv[0]` basename starts with `build-script-`.
/// 2. pip: a Python interpreter runs `setup.py` (an argument whose basename is
///    `setup.py`, or pip's `-c` shim quoting such a path).
/// 3. npm-style lifecycle: `npm_lifecycle_event`, with the kind taken from
///    `npm_config_user_agent`. When the package name is missing, a cwd below
///    `node_modules/<pkg>` names the package. If the environment was not captured,
///    that cwd alone is enough.
/// 4. pip: `PIP_BUILD_TRACKER` is set.
///
/// The rules that look at the process's own exe and arguments come before
/// inherited variables, which leak into every descendant. `MAKELEVEL` is used only
/// when no process in the chain matches anything better.
pub fn classify_origin(chain: &[Arc<ProcInfo>]) -> Option<Origin> {
    let mut make = None;
    for info in chain {
        let found = cargo_build_script(info)
            .or_else(|| pip_setup_py(info))
            .or_else(|| package_script(info))
            .or_else(|| pip_build_tracker(info));
        if found.is_some() {
            return found;
        }
        if make.is_none() {
            make = make_recipe(info);
        }
    }
    make
}

fn evidence(source: &str, item: &str, pid: Pid) -> Box<str> {
    format!("{source}:{item}@{pid}").into_boxed_str()
}

fn is_build_script(base: &&OsStr) -> bool {
    base.as_bytes().starts_with(b"build-script-")
}

fn cargo_build_script(info: &ProcInfo) -> Option<Origin> {
    let env = &info.env.as_deref()?.lifecycle;
    let package = env.cargo_pkg_name.as_ref().filter(|_| env.out_dir_set)?;
    let pid = info.key.pid;
    let exe = info
        .exe
        .as_deref()
        .and_then(Path::file_name)
        .filter(is_build_script);
    let (source, script) = exe.map(|base| ("exe", base)).or_else(|| {
        let argv0 = info.argv.first().and_then(|arg| Path::new(arg).file_name());
        argv0.filter(is_build_script).map(|base| ("argv0", base))
    })?;
    Some(Origin {
        kind: OriginKind::CargoBuildScript,
        package: Some(package.clone()),
        version: env.cargo_pkg_version.clone(),
        phase: None,
        confidence: Confidence::High,
        via: info.key,
        evidence: vec![
            evidence("env", "CARGO_PKG_NAME", pid),
            evidence("env", "OUT_DIR", pid),
            evidence(source, &script.to_string_lossy(), pid),
        ],
    })
}

fn pip(info: &ProcInfo, item: Box<str>) -> Origin {
    Origin {
        kind: OriginKind::PipBuild,
        package: None,
        version: None,
        phase: None,
        confidence: Confidence::Medium,
        via: info.key,
        evidence: vec![item],
    }
}

fn is_python(argv0: &OsStr) -> bool {
    let base = Path::new(argv0)
        .file_name()
        .map_or(&[][..], OsStr::as_bytes);
    base.starts_with(b"python") || base.starts_with(b"pypy")
}

/// Whether `code` holds a string literal naming a `setup.py` file, as pip's `-c`
/// shim does (`__file__ = '/tmp/pip-install-x/pkg/setup.py'`).
fn quotes_setup_py(code: &[u8]) -> bool {
    code.windows(10).any(|w| {
        matches!(w[0], b'/' | b'\'' | b'"')
            && &w[1..9] == b"setup.py"
            && matches!(w[9], b'\'' | b'"')
    })
}

/// A Python interpreter running `setup.py`: `python setup.py ...`, or pip's
/// `python -c "...'/tmp/.../setup.py'..."` shim.
fn pip_setup_py(info: &ProcInfo) -> Option<Origin> {
    let (argv0, args) = info.argv.split_first()?;
    let runs = is_python(argv0)
        && args.iter().any(|arg| {
            Path::new(arg).file_name() == Some(OsStr::new("setup.py"))
                || quotes_setup_py(arg.as_bytes())
        });
    runs.then(|| pip(info, evidence("argv", "setup.py", info.key.pid)))
}

fn pip_build_tracker(info: &ProcInfo) -> Option<Origin> {
    let tracked = info.env.as_deref()?.lifecycle.pip_build_tracker;
    tracked.then(|| pip(info, evidence("env", "PIP_BUILD_TRACKER", info.key.pid)))
}

/// The package manager named by `npm_config_user_agent` (`<tool>/<version> ...`).
fn manager_kind(user_agent: &str) -> Option<OriginKind> {
    let tool = user_agent.split_once('/')?.0;
    match tool {
        "npm" => Some(OriginKind::NpmLifecycle),
        "pnpm" => Some(OriginKind::PnpmLifecycle),
        "yarn" => Some(OriginKind::YarnLifecycle),
        "bun" => Some(OriginKind::BunLifecycle),
        _ => None,
    }
}

/// The package owning a directory below `node_modules`: `<pkg>` or `@scope/<pkg>`.
/// The innermost `node_modules` counts, so nested and pnpm layouts name the dependency.
fn node_modules_package(cwd: &Path) -> Option<String> {
    let parts: Vec<&OsStr> = cwd.iter().collect();
    let at = parts.iter().rposition(|part| *part == "node_modules")?;
    let first = parts.get(at + 1)?.to_str()?;
    if first.starts_with('.') {
        // `.bin`, `.pnpm`, `.cache`: tooling directories, not packages.
        return None;
    }
    if first.starts_with('@') {
        let name = parts.get(at + 2)?.to_str()?;
        return Some(format!("{first}/{name}"));
    }
    Some(first.to_owned())
}

fn package_script(info: &ProcInfo) -> Option<Origin> {
    let pid = info.key.pid;
    let env = info.env.as_deref().map(|env| &env.lifecycle);
    let event = env.and_then(|env| env.npm_lifecycle_event.as_ref());
    let name = env.and_then(|env| env.npm_package_name.as_ref());
    let mut found = Vec::new();
    let (package, version, confidence) = if let (Some(_), Some(name)) = (event, name) {
        found.push(evidence("env", "npm_lifecycle_event", pid));
        found.push(evidence("env", "npm_package_name", pid));
        let version = env.and_then(|env| env.npm_package_version.clone());
        (Some(name.clone()), version, Confidence::High)
    } else if let Some(package) = info
        .cwd
        .as_deref()
        // A captured environment without the event shows this is no lifecycle script.
        .filter(|_| event.is_some() || info.env.is_none())
        .and_then(node_modules_package)
    {
        found.push(evidence("cwd", &format!("node_modules/{package}"), pid));
        if event.is_some() {
            found.push(evidence("env", "npm_lifecycle_event", pid));
        }
        (Some(package.into_boxed_str()), None, Confidence::Medium)
    } else if event.is_some() {
        found.push(evidence("env", "npm_lifecycle_event", pid));
        (None, None, Confidence::Low)
    } else {
        return None;
    };
    let agent = env
        .and_then(|env| env.npm_config_user_agent.as_deref())
        .and_then(manager_kind);
    if agent.is_some() {
        found.push(evidence("env", "npm_config_user_agent", pid));
    }
    Some(Origin {
        kind: agent.unwrap_or(OriginKind::NpmLifecycle),
        package,
        version,
        phase: event.cloned(),
        confidence,
        via: info.key,
        evidence: found,
    })
}

fn make_recipe(info: &ProcInfo) -> Option<Origin> {
    let under_make = info.env.as_deref()?.lifecycle.makelevel.is_some();
    under_make.then(|| Origin {
        kind: OriginKind::Make,
        package: None,
        version: None,
        phase: None,
        confidence: Confidence::Low,
        via: info.key,
        evidence: vec![evidence("env", "MAKELEVEL", info.key.pid)],
    })
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path, sync::Arc};

    use super::{Confidence, Origin, OriginKind, classify_origin};
    use crate::{Pid, ProcInfo, ProcKey, Source, parse_env_facts};

    fn process(pid: Pid, env: Option<&[u8]>) -> ProcInfo {
        ProcInfo {
            key: ProcKey {
                pid,
                start: u64::from(pid),
            },
            ppid: None,
            comm: Arc::from("sh"),
            exe: None,
            argv: Arc::from([]),
            argv_truncated: false,
            cwd: None,
            uid: None,
            gid: None,
            sid: None,
            pgid: None,
            tty_nr: None,
            cgroup: None,
            env: env.map(|raw| Arc::new(parse_env_facts(raw))),
            exit: None,
            source: Source::Event,
            exec_ts_ns: None,
            fork_ts_ns: None,
        }
    }

    fn with_argv(mut info: ProcInfo, args: &[&str]) -> ProcInfo {
        info.argv = args
            .iter()
            .map(|a| Box::from(OsStr::from_bytes(a.as_bytes())))
            .collect();
        info
    }

    fn with_cwd(mut info: ProcInfo, cwd: &str) -> ProcInfo {
        info.cwd = Some(Arc::from(Path::new(cwd)));
        info
    }

    fn classify(chain: Vec<ProcInfo>) -> Option<Origin> {
        let chain: Vec<Arc<ProcInfo>> = chain.into_iter().map(Arc::new).collect();
        classify_origin(&chain)
    }

    const NPM_SCRIPT: &[u8] = b"npm_lifecycle_event=postinstall\0npm_package_name=esbuild\0\
npm_package_version=0.19.2\0npm_config_user_agent=npm/10.2.4 node/v20.10.0 linux x64\0\
MAKELEVEL=1\0";

    #[test]
    fn npm_lifecycle_high_confidence() {
        let origin = classify(vec![process(8812, Some(NPM_SCRIPT))]).unwrap();
        assert_eq!(
            origin,
            Origin {
                kind: OriginKind::NpmLifecycle,
                package: Some("esbuild".into()),
                version: Some("0.19.2".into()),
                phase: Some("postinstall".into()),
                confidence: Confidence::High,
                via: ProcKey {
                    pid: 8812,
                    start: 8812
                },
                evidence: vec![
                    "env:npm_lifecycle_event@8812".into(),
                    "env:npm_package_name@8812".into(),
                    "env:npm_config_user_agent@8812".into(),
                ],
            }
        );
    }

    #[test]
    fn user_agent_selects_the_manager() {
        let cases = [
            ("pnpm/8.15.1 npm/? node/v20.11.0", OriginKind::PnpmLifecycle),
            (
                "yarn/1.22.19 npm/? node/v20.11.0",
                OriginKind::YarnLifecycle,
            ),
            ("bun/1.0.25 npm/? node/v21.6.0", OriginKind::BunLifecycle),
            ("npm/10.2.4 node/v20.10.0", OriginKind::NpmLifecycle),
            // Unknown or prefix-only matches fall back to npm.
            ("pnpmx/1 node/v20", OriginKind::NpmLifecycle),
            ("deno", OriginKind::NpmLifecycle),
        ];
        for (agent, kind) in cases {
            let env = format!(
                "npm_lifecycle_event=install\0npm_package_name=x\0npm_config_user_agent={agent}"
            );
            let origin = classify(vec![process(1, Some(env.as_bytes()))]).unwrap();
            assert_eq!(origin.kind, kind, "{agent}");
        }
    }

    #[test]
    fn npm_beats_an_outer_make() {
        // make -> sh (MAKELEVEL) -> npm -> postinstall script (npm env + inherited MAKELEVEL).
        let origin = classify(vec![
            process(40, Some(NPM_SCRIPT)),
            process(30, Some(b"MAKELEVEL=1\0")),
            process(20, Some(b"MAKELEVEL=1\0")),
            process(10, Some(b"")),
        ])
        .unwrap();
        assert_eq!(
            (origin.kind, origin.via.pid),
            (OriginKind::NpmLifecycle, 40)
        );

        // Also when the nearest process only has MAKELEVEL and npm sits further up.
        let origin = classify(vec![
            process(50, Some(b"MAKELEVEL=1\0")),
            process(40, Some(NPM_SCRIPT)),
        ])
        .unwrap();
        assert_eq!(
            (origin.kind, origin.via.pid),
            (OriginKind::NpmLifecycle, 40)
        );
    }

    #[test]
    fn make_is_the_fallback_and_nearest_make_wins() {
        let origin = classify(vec![
            process(3, None),
            process(2, Some(b"MAKELEVEL=2\0")),
            process(1, Some(b"MAKELEVEL=1\0")),
        ])
        .unwrap();
        assert_eq!(
            (origin.kind, origin.confidence, origin.via.pid),
            (OriginKind::Make, Confidence::Low, 2)
        );
        assert_eq!(origin.evidence, vec![Box::<str>::from("env:MAKELEVEL@2")]);
    }

    #[test]
    fn nothing_matches() {
        assert_eq!(classify(vec![]), None);
        assert_eq!(
            classify(vec![process(1, None), process(2, Some(b"PATH=/bin\0"))]),
            None
        );
    }

    #[test]
    fn node_modules_cwd_fallback() {
        // Environment unreadable: the cwd alone names the package.
        let origin = classify(vec![with_cwd(
            process(7, None),
            "/home/dev/proj/node_modules/@esbuild/linux-x64",
        )])
        .unwrap();
        assert_eq!(origin.package.as_deref(), Some("@esbuild/linux-x64"));
        assert_eq!(
            (origin.kind, origin.confidence, origin.phase),
            (OriginKind::NpmLifecycle, Confidence::Medium, None)
        );
        let cwd = Box::<str>::from("cwd:node_modules/@esbuild/linux-x64@7");
        assert_eq!(origin.evidence, vec![cwd]);

        // Event without package name: cwd supplies it, the event the phase.
        let origin = classify(vec![with_cwd(
            process(
                7,
                Some(b"npm_lifecycle_event=install\0npm_config_user_agent=pnpm/8 x\0"),
            ),
            "/p/node_modules/.pnpm/sharp@0.33.2/node_modules/sharp/build",
        )])
        .unwrap();
        assert_eq!(origin.package.as_deref(), Some("sharp"));
        assert_eq!(origin.phase.as_deref(), Some("install"));
        assert_eq!(
            (origin.kind, origin.confidence),
            (OriginKind::PnpmLifecycle, Confidence::Medium)
        );

        // Event without a package anywhere: low confidence, no package.
        let origin = classify(vec![process(7, Some(b"npm_lifecycle_event=test\0"))]).unwrap();
        assert_eq!((origin.package, origin.confidence), (None, Confidence::Low));
    }

    #[test]
    fn node_modules_non_packages() {
        for cwd in [
            "/p/node_modules",
            "/p/node_modules/@scope",
            "/p/node_modules/.bin",
            "/p/node_modules/.pnpm",
            "/p/not_node_modules/x",
        ] {
            assert_eq!(
                classify(vec![with_cwd(process(7, None), cwd)]),
                None,
                "{cwd}"
            );
        }
    }

    #[test]
    fn node_modules_cwd_needs_an_unknown_env_or_an_event() {
        // A shell that cd'd into a dependency: its environment shows no npm script.
        let git = with_cwd(
            with_argv(process(7, Some(b"PATH=/usr/bin\0")), &["git", "status"]),
            "/home/u/proj/node_modules/lodash",
        );
        assert_eq!(classify(vec![git]), None);
    }

    #[test]
    fn package_name_from_env_beats_cwd() {
        let script = with_cwd(process(9, Some(NPM_SCRIPT)), "/p/node_modules/other");
        let origin = classify(vec![script]).unwrap();
        assert_eq!(
            (origin.package.as_deref(), origin.confidence),
            (Some("esbuild"), Confidence::High)
        );
    }

    const CARGO_ENV: &[u8] =
        b"CARGO_PKG_NAME=ring\0CARGO_PKG_VERSION=0.17.8\0OUT_DIR=/t/build/ring-1/out\0";

    #[test]
    fn cargo_build_script_by_exe_or_argv0() {
        let mut script = process(5, Some(CARGO_ENV));
        script.exe = Some(Arc::from(Path::new(
            "/t/debug/build/ring-1a2b/build-script-build",
        )));
        let origin = classify(vec![script]).unwrap();
        assert_eq!(
            (
                origin.kind,
                origin.package.as_deref(),
                origin.version.as_deref(),
                origin.confidence
            ),
            (
                OriginKind::CargoBuildScript,
                Some("ring"),
                Some("0.17.8"),
                Confidence::High
            )
        );
        let last = origin.evidence.last().map(|item| &**item);
        assert_eq!(last, Some("exe:build-script-build@5"));

        let script = with_argv(
            process(5, Some(CARGO_ENV)),
            &["/t/debug/build/ring-1a2b/build-script-main"],
        );
        let origin = classify(vec![script]).unwrap();
        let last = origin.evidence.last().map(|item| &**item);
        assert_eq!(last, Some("argv0:build-script-main@5"));
    }

    #[test]
    fn cargo_requires_all_three_signals() {
        let exe = |mut info: ProcInfo| {
            info.exe = Some(Arc::from(Path::new("/t/build-script-build")));
            info
        };
        // rustc compiling the crate has the env but is not a build script.
        let rustc = with_argv(
            process(5, Some(CARGO_ENV)),
            &["rustc", "--crate-name", "ring"],
        );
        assert_eq!(classify(vec![rustc]), None);
        // No OUT_DIR: a plain `cargo run` binary.
        assert_eq!(
            classify(vec![exe(process(5, Some(b"CARGO_PKG_NAME=ring\0")))]),
            None
        );
        // No CARGO_PKG_NAME.
        assert_eq!(classify(vec![exe(process(5, Some(b"OUT_DIR=/o\0")))]), None);
    }

    #[test]
    fn cargo_build_script_beats_inherited_npm_and_pip() {
        let env = [CARGO_ENV, NPM_SCRIPT, b"PIP_BUILD_TRACKER=/tmp/t\0"].concat();
        let mut script = process(5, Some(&env));
        script.exe = Some(Arc::from(Path::new("/t/build-script-build")));
        assert_eq!(
            classify(vec![script]).unwrap().kind,
            OriginKind::CargoBuildScript
        );
    }

    #[test]
    fn pip_by_argv_or_tracker() {
        let setup = with_argv(process(6, None), &["python3", "setup.py", "bdist_wheel"]);
        let origin = classify(vec![setup]).unwrap();
        assert_eq!(
            (origin.kind, origin.confidence),
            (OriginKind::PipBuild, Confidence::Medium)
        );
        assert_eq!(origin.evidence, vec![Box::<str>::from("argv:setup.py@6")]);

        let shim = with_argv(
            process(6, None),
            &[
                "python",
                "-c",
                "import sys; sys.argv[0] = '/tmp/pip-install-x/pkg/setup.py'",
            ],
        );
        assert_eq!(classify(vec![shim]).unwrap().kind, OriginKind::PipBuild);

        let tracked = process(6, Some(b"PIP_BUILD_TRACKER=/tmp/pip-build-tracker-1\0"));
        let origin = classify(vec![tracked]).unwrap();
        assert_eq!(
            origin.evidence,
            vec![Box::<str>::from("env:PIP_BUILD_TRACKER@6")]
        );
    }

    #[test]
    fn setup_py_must_be_run_by_python() {
        let pip_build = |args: &[&str]| {
            classify(vec![with_argv(process(6, None), args)]).map(|origin| origin.kind)
        };
        for args in [
            &["python3", "./pkg/setup.py", "build"][..],
            &[
                "/venv/bin/python3.12",
                "/tmp/pip-req-build-x/setup.py",
                "egg_info",
            ],
            &[
                "python",
                "-u",
                "-c",
                "import setuptools, tokenize;__file__='/tmp/pip-req-build-x/setup.py'",
            ],
        ] {
            assert_eq!(pip_build(args), Some(OriginKind::PipBuild), "{args:?}");
        }
        for args in [
            &["vim", "tests/test_setup.py"][..],
            &["git", "add", "setup.py"],
            &["python3", "mysetup.py"],
            &["python3", "setup.pyc"],
            &["python3", "-c", "print('test_setup.py')"],
        ] {
            assert_eq!(pip_build(args), None, "{args:?}");
        }
    }

    #[test]
    fn setup_py_beats_inherited_npm_env_but_tracker_does_not() {
        let env = [NPM_SCRIPT, b"PIP_BUILD_TRACKER=/t\0"].concat();
        let setup = with_argv(process(6, Some(&env)), &["python", "setup.py", "build"]);
        assert_eq!(classify(vec![setup]).unwrap().kind, OriginKind::PipBuild);
        let gcc = with_argv(process(6, Some(&env)), &["gcc", "-c", "x.c"]);
        assert_eq!(classify(vec![gcc]).unwrap().kind, OriginKind::NpmLifecycle);
    }

    #[test]
    fn nearest_specific_match_wins() {
        let origin = classify(vec![
            process(3, Some(b"PATH=/bin\0")),
            process(2, Some(b"PIP_BUILD_TRACKER=/t\0")),
            process(1, Some(NPM_SCRIPT)),
        ])
        .unwrap();
        assert_eq!((origin.kind, origin.via.pid), (OriginKind::PipBuild, 2));
    }
}
