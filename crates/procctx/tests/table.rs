//! `ProcTable` behaviour from events and the bundled `/proc` fixtures.
//!
//! Event-only processes use pids 10000 and up, which the fixtures lack, so lazy
//! `/proc` lookups for them fail like they would for exited processes.

use std::{num::NonZeroU64, os::unix::fs::MetadataExt, path::Path};

use procctx::{
    Ancestry, Confidence, Config, ExecEvent, ExitEvent, ExitInfo, ForkEvent, Manager, OriginKind,
    Pid, ProcError, ProcFile, ProcInfo, ProcKey, ProcTable, Runtime, Source, StartClock, Stop,
    testing::FixtureSource,
};

const CGROUP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cgroup");
const HEX: &str = "3f4e5d6c7b8a99001122334455667788990011223344556677889900aabbccdd";

fn table() -> ProcTable<FixtureSource> {
    with_config(Config::default())
}

fn with_config(cfg: Config) -> ProcTable<FixtureSource> {
    ProcTable::new(FixtureSource::bundled(), cfg)
}

fn key(pid: Pid, start: u64) -> ProcKey {
    ProcKey { pid, start }
}

fn fork(table: &mut ProcTable<FixtureSource>, ts_ns: u64, parent: Pid, child: ProcKey) {
    table.on_fork(ForkEvent {
        ts_ns,
        parent,
        child,
        is_thread: false,
    });
}

fn exec(table: &mut ProcTable<FixtureSource>, ts_ns: u64, key: ProcKey, comm: &str) {
    table.on_exec(ExecEvent {
        comm: Some(comm.as_bytes()),
        ..ExecEvent::new(ts_ns, key)
    });
}

/// An exec of a login shell whose parent is the fixture's pid 1.
fn exec_shell(table: &mut ProcTable<FixtureSource>, ts_ns: u64, key: ProcKey, comm: &str) {
    let ev = ExecEvent {
        ppid: Some(1),
        comm: Some(comm.as_bytes()),
        ..ExecEvent::new(ts_ns, key)
    };
    table.on_exec(ev);
}

fn exit(table: &mut ProcTable<FixtureSource>, ts_ns: u64, key: ProcKey, code: i32) {
    table.on_exit(ExitEvent { ts_ns, key, code });
}

fn pids(ancestry: &Ancestry) -> Vec<Pid> {
    ancestry.chain.iter().map(|info| info.key.pid).collect()
}

fn keys(ancestry: &Ancestry) -> Vec<ProcKey> {
    ancestry.chain.iter().map(|info| info.key).collect()
}

fn argv(info: &ProcInfo) -> Vec<&str> {
    info.argv.iter().map(|arg| arg.to_str().unwrap()).collect()
}

#[test]
fn snapshot_reads_the_fixture_tree() {
    let mut t = table();
    assert_eq!(t.snapshot_all().unwrap(), 11);
    assert_eq!(t.len(), 11);

    let evil = t.get(1440).unwrap();
    assert_eq!((evil.key, &*evil.comm), (key(1440, 6105), "evil) (x"));
    assert_eq!(argv(evil), ["node", "install.js"]);
    assert_eq!(evil.exe.as_deref(), Some(Path::new("/usr/bin/node")));
    assert_eq!(
        (
            evil.ppid,
            evil.uid,
            evil.gid,
            evil.sid,
            evil.pgid,
            evil.tty_nr
        ),
        (
            Some(1430),
            Some(1000),
            Some(1000),
            Some(1300),
            Some(1400),
            Some(34_819)
        )
    );
    assert_eq!(evil.source, Source::Procfs);
    let unit = evil
        .cgroup
        .as_ref()
        .and_then(|cgroup| cgroup.unit.as_ref())
        .unwrap();
    assert_eq!(unit.name.as_ref(), "tmux-spawn-5f2c.scope");

    let zombie = t.get(1500).unwrap();
    assert_eq!(zombie.exit.map(|exit| exit.code), Some(None));
    assert!(zombie.argv.is_empty() && zombie.exe.is_none());

    let chain = t.ancestry(1440, Stop::Root);
    assert!(chain.complete);
    assert_eq!(pids(&chain), [1440, 1430, 1420, 1410, 1400, 1300, 1200, 1]);

    // A rescan neither duplicates records nor resurrects the zombie.
    assert_eq!(t.snapshot_all().unwrap(), 11);
    assert_eq!(t.len(), 11);
}

#[test]
fn ancestry_survives_exited_ancestors() {
    let mut t = table();
    exec_shell(&mut t, 10, key(10_050, 100), "zsh");
    fork(&mut t, 20, 10_050, key(10_100, 200));
    exec(&mut t, 21, key(10_100, 200), "make");
    fork(&mut t, 30, 10_100, key(10_101, 300));
    exec(&mut t, 31, key(10_101, 300), "cc");
    exit(&mut t, 40, key(10_100, 200), 0);
    exit(&mut t, 41, key(10_050, 100), 0);

    let chain = t.ancestry(10_101, Stop::Root);
    assert!(chain.complete);
    assert_eq!(pids(&chain), [10_101, 10_100, 10_050, 1]);
    assert_eq!(&*chain.chain[1].comm, "make");
    assert_eq!(
        chain.chain[1].exit,
        Some(ExitInfo {
            ts_ns: 40,
            code: Some(0)
        })
    );
}

#[test]
fn reused_pid_does_not_inherit_old_lineage() {
    let mut t = table();
    exec_shell(&mut t, 10, key(10_050, 100), "shell-a");
    exec_shell(&mut t, 11, key(10_060, 110), "shell-b");
    fork(&mut t, 20, 10_050, key(10_100, 200));
    fork(&mut t, 25, 10_100, key(10_101, 250));
    exit(&mut t, 30, key(10_100, 200), 0);
    fork(&mut t, 40, 10_060, key(10_100, 400));
    exec(&mut t, 41, key(10_100, 400), "new");

    let new = t.ancestry(10_100, Stop::Root);
    assert_eq!(keys(&new), [key(10_100, 400), key(10_060, 110), key(1, 2)]);
    // Forked before the reuse: its parent is the old process, now a tombstone.
    let old = t.ancestry(10_101, Stop::Root);
    assert_eq!(
        keys(&old),
        [
            key(10_101, 250),
            key(10_100, 200),
            key(10_050, 100),
            key(1, 2)
        ]
    );
    assert_eq!(&*old.chain[1].comm, "shell-a");

    assert_eq!(t.get(10_100).unwrap().key, key(10_100, 400));
    assert_eq!(
        t.get_key(key(10_100, 200)).unwrap().exit.unwrap().code,
        Some(0)
    );

    // A fork onto a pid whose exit was missed retires the stale record.
    fork(&mut t, 50, 10_060, key(10_101, 500));
    let stale = t.get_key(key(10_101, 250)).unwrap();
    assert_eq!(
        stale.exit,
        Some(ExitInfo {
            ts_ns: 50,
            code: None
        })
    );
    assert_eq!(t.get(10_101).unwrap().key, key(10_101, 500));
}

#[test]
fn forked_child_inherits_until_enriched() {
    let mut t = table();
    t.on_exec(ExecEvent {
        ppid: Some(1410),
        comm: Some(b"npm ci"),
        cwd: Some(b"/elsewhere"),
        env: Some(b"TMUX_PANE=%9\0MAKELEVEL=4\0"),
        uid: Some(1000),
        ..ExecEvent::new(10, key(1420, 6002))
    });
    fork(&mut t, 20, 1420, key(1430, 6100));
    let child = t.get(1430).unwrap();
    assert_eq!(child.cwd.as_deref(), Some(Path::new("/elsewhere")));
    assert_eq!(
        child
            .env
            .as_ref()
            .unwrap()
            .tmux
            .as_ref()
            .unwrap()
            .pane
            .as_ref(),
        "%9"
    );
    assert_eq!(
        (
            &*child.comm,
            child.ppid,
            child.uid,
            child.fork_ts_ns,
            child.exec_ts_ns
        ),
        ("npm ci", Some(1420), Some(1000), Some(20), None)
    );

    t.enrich(1430).unwrap();
    let child = t.get(1430).unwrap();
    assert_eq!(
        child.cwd.as_deref(),
        Some(Path::new("/home/dev/proj/node_modules/esbuild"))
    );
    let env = child.env.as_ref().unwrap();
    let pane = env.tmux.as_ref().unwrap().pane.as_ref();
    assert_eq!((pane, env.lifecycle.makelevel), ("%3", Some(1)));
    assert_eq!(
        (&*child.comm, argv(child)),
        ("sh", vec!["sh", "-c", "node install.js"])
    );
    assert_eq!(child.source, Source::Mixed);
    // The fork-time parent stays, and the parent's own record is untouched.
    assert_eq!(child.ppid, Some(1420));
    assert_eq!(
        t.get(1420).unwrap().cwd.as_deref(),
        Some(Path::new("/elsewhere"))
    );
}

#[test]
fn enrich_fills_only_missing_fields_of_exec_records() {
    let mut t = table();
    t.on_exec(ExecEvent {
        filename: Some(b"/opt/node"),
        argv: Some(b"node\0custom\0"),
        cwd: Some(b"/from/event"),
        ..ExecEvent::new(10, key(1440, 6105))
    });
    t.enrich(1440).unwrap();
    let info = t.get(1440).unwrap();
    assert_eq!(info.exe.as_deref(), Some(Path::new("/opt/node")));
    assert_eq!(argv(info), ["node", "custom"]);
    assert_eq!(info.cwd.as_deref(), Some(Path::new("/from/event")));
    // Missing ones come from /proc.
    assert_eq!(
        (info.ppid, info.uid, info.sid),
        (Some(1430), Some(1000), Some(1300))
    );
    assert_eq!(
        info.env
            .as_ref()
            .unwrap()
            .lifecycle
            .npm_package_name
            .as_deref(),
        Some("esbuild")
    );
    assert_eq!(info.source, Source::Mixed);
}

#[test]
fn exec_replaces_the_image() {
    let mut t = table();
    t.on_exec(ExecEvent {
        ppid: Some(1),
        comm: Some(b"bash"),
        filename: Some(b"/bin/bash"),
        argv: Some(b"bash\0"),
        cwd: Some(b"/w"),
        env: Some(b"MAKELEVEL=2\0"),
        uid: Some(7),
        ..ExecEvent::new(10, key(10_200, 100))
    });
    t.on_exec(ExecEvent {
        filename: Some(b"/usr/lib/very-long-tool-name"),
        argv: Some(b"tool\0-v\0"),
        ..ExecEvent::new(20, key(10_200, 100))
    });
    let info = t.get(10_200).unwrap();
    // The kernel names the process after the first 15 bytes of the basename.
    assert_eq!(&*info.comm, "very-long-tool-");
    assert_eq!(
        info.exe.as_deref(),
        Some(Path::new("/usr/lib/very-long-tool-name"))
    );
    assert_eq!(argv(info), ["tool", "-v"]);
    // The old image's environment no longer applies; cwd, ids and parent survive.
    assert_eq!(info.env, None);
    assert_eq!(
        (info.cwd.as_deref(), info.uid, info.ppid),
        (Some(Path::new("/w")), Some(7), Some(1))
    );
    assert_eq!(info.exec_ts_ns, Some(20));

    t.on_comm(10_200, b"renamed");
    assert_eq!(&*t.get(10_200).unwrap().comm, "renamed");

    t.on_fork(ForkEvent {
        ts_ns: 30,
        parent: 10_200,
        child: key(10_201, 150),
        is_thread: true,
    });
    assert!(t.get(10_201).is_none());
}

#[test]
fn late_fork_event_keeps_exec_facts() {
    let mut t = table();
    exec(&mut t, 20, key(10_210, 100), "cc");
    fork(&mut t, 10, 10_050, key(10_210, 100));
    let info = t.get(10_210).unwrap();
    assert_eq!(
        (&*info.comm, info.ppid, info.fork_ts_ns, info.exec_ts_ns),
        ("cc", Some(10_050), Some(10), Some(20))
    );
}

#[test]
fn argv_is_capped_at_byte_boundaries() {
    let mut t = with_config(Config {
        max_argv_bytes: 8,
        ..Config::default()
    });
    let cases: [(Pid, &[u8], &[&str], bool); 5] = [
        (10_700, b"abc\0def\0", &["abc", "def"], false),
        (10_701, b"abc\0defgh\0ij\0", &["abc", "defg"], true),
        (10_702, b"a\0\0b\0", &["a", "", "b"], false),
        (10_703, b"\0", &[""], false),
        (10_704, b"abc\0def", &["abc", "def"], false),
    ];
    for (pid, raw, expected, truncated) in cases {
        t.on_exec(ExecEvent {
            argv: Some(raw),
            ..ExecEvent::new(1, key(pid, 1))
        });
        let info = t.get(pid).unwrap();
        assert_eq!(
            (argv(info), info.argv_truncated),
            (expected.to_vec(), truncated),
            "{pid}"
        );
    }
    // The producer's own truncation is kept.
    let ev = ExecEvent {
        argv: Some(b"a\0"),
        argv_truncated: true,
        ..ExecEvent::new(1, key(10_705, 1))
    };
    t.on_exec(ev);
    assert!(t.get(10_705).unwrap().argv_truncated);
}

#[test]
fn enrich_detects_a_reused_pid() {
    let mut t = table();
    // The table believes pid 1430 is an older process; /proc says it started at 6100.
    exec(&mut t, 10, key(1430, 50), "old");
    assert!(matches!(t.enrich(1430), Err(ProcError::Reused(1430))));
    let old = t.get_key(key(1430, 50)).unwrap();
    assert_eq!(
        old.exit,
        Some(ExitInfo {
            ts_ns: 10,
            code: None
        })
    );

    t.enrich(1430).unwrap();
    assert_eq!(t.get(1430).unwrap().key, key(1430, 6100));

    // A late exit event for the old process completes it without touching the new one.
    exit(&mut t, 60, key(1430, 50), 9);
    assert_eq!(
        t.get_key(key(1430, 50)).unwrap().exit,
        Some(ExitInfo {
            ts_ns: 60,
            code: Some(9)
        })
    );
    assert!(t.get(1430).unwrap().is_alive());
}

#[test]
fn enrich_of_a_vanished_process() {
    let mut t = table();
    t.source().remove(1440);
    assert!(matches!(t.enrich(1440), Err(ProcError::NotFound(1440))));
    assert!(t.is_empty());
}

#[test]
fn unreadable_environ_falls_back_to_node_modules_cwd() {
    let src = FixtureSource::bundled();
    src.deny(1440, ProcFile::Environ);
    let mut t = ProcTable::new(src, Config::default());
    t.enrich(1440).unwrap();
    let info = t.get(1440).unwrap();
    assert_eq!(info.env, None);
    assert_eq!(info.uid, Some(1000), "other files are still read");

    let origin = t.origin(1440).unwrap();
    assert_eq!(
        (
            origin.kind,
            origin.package.as_deref(),
            origin.confidence,
            origin.via
        ),
        (
            OriginKind::NpmLifecycle,
            Some("@esbuild/linux-x64"),
            Confidence::Medium,
            key(1440, 6105)
        )
    );
    // tmux comes from the nearest ancestor whose environment is readable.
    assert_eq!(t.context(1440).tmux.unwrap().pane.as_ref(), "%3");
}

#[test]
fn origin_from_proc() {
    let mut t = table();
    t.snapshot_all().unwrap();
    let npm = t.origin(1440).unwrap();
    assert_eq!(
        (
            npm.kind,
            npm.package.as_deref(),
            npm.version.as_deref(),
            npm.phase.as_deref()
        ),
        (
            OriginKind::NpmLifecycle,
            Some("esbuild"),
            Some("0.19.2"),
            Some("postinstall")
        )
    );
    assert_eq!(
        (npm.confidence, npm.via),
        (Confidence::High, key(1440, 6105))
    );
    // Under `make` but not npm: only make is left.
    let make = t.origin(1410).unwrap();
    assert_eq!((make.kind, make.via), (OriginKind::Make, key(1410, 6001)));
    let cargo = t.origin(2100).unwrap();
    assert_eq!(
        (cargo.kind, cargo.package.as_deref()),
        (OriginKind::CargoBuildScript, Some("ring"))
    );
    assert_eq!(t.origin(1300), None);
}

#[test]
fn context_from_proc() {
    let mut t = table();
    let ctx = t.context(1440);
    let unit = ctx.unit.unwrap();
    assert_eq!(
        (unit.name.as_ref(), unit.manager, unit.slice.as_deref()),
        (
            "tmux-spawn-5f2c.scope",
            Manager::User { uid: 1000 },
            Some("app.slice")
        )
    );
    let tmux = ctx.tmux.unwrap();
    assert_eq!(
        (tmux.pane.as_ref(), tmux.server_pid, tmux.session),
        ("%3", Some(1200), Some(0))
    );
    assert_eq!(ctx.container, None);

    let nginx = t.context(2000);
    let container = nginx.container.unwrap();
    assert_eq!(
        (container.runtime, container.short_id()),
        (Runtime::Docker, "3f4e5d6c7b8a")
    );
    assert_eq!(
        nginx.unit.unwrap().name.as_ref(),
        format!("docker-{HEX}.scope")
    );
    assert_eq!(nginx.tmux, None);
}

#[test]
fn exec_cgroup_ids_resolve_off_the_event_path() {
    let mut t = table();
    let id = std::fs::metadata(format!("{CGROUP}/system.slice/docker-{HEX}.scope"))
        .unwrap()
        .ino();
    let ev = ExecEvent::new(10, key(10_300, 100));
    t.on_exec(ExecEvent {
        ppid: Some(1),
        cgroup_id: Some(id),
        ..ev
    });
    assert_eq!(
        t.get(10_300).unwrap().cgroup,
        None,
        "the event path must not walk cgroupfs"
    );

    let ctx = t.context(10_300);
    assert_eq!(ctx.cgroup.unwrap().id, Some(id));
    assert_eq!(ctx.container.unwrap().runtime, Runtime::Docker);
    // Resolved into the record, so later forks inherit it.
    fork(&mut t, 20, 10_300, key(10_301, 200));
    assert_eq!(t.get(10_301).unwrap().cgroup.as_ref().unwrap().id, Some(id));
    // Once cached, exec events attach it directly.
    t.on_exec(ExecEvent {
        cgroup_id: Some(id),
        ..ExecEvent::new(30, key(10_302, 300))
    });
    assert_eq!(t.get(10_302).unwrap().cgroup.as_ref().unwrap().id, Some(id));
}

#[test]
fn ancestry_stops_and_loads_lazily() {
    let mut t = table();
    let at = t.ancestry(1440, Stop::At(1400));
    assert!(at.complete);
    assert_eq!(pids(&at), [1440, 1430, 1420, 1410, 1400]);
    assert_eq!(t.len(), 5, "only the walked ancestors are loaded");

    assert_eq!(pids(&t.ancestry(1440, Stop::Depth(2))), [1440, 1430, 1420]);
    assert_eq!(pids(&t.ancestry(1440, Stop::Depth(0))), [1440]);
    assert_eq!(
        t.ancestry(4242, Stop::Root),
        Ancestry {
            chain: Vec::new(),
            complete: false
        }
    );
}

#[test]
fn ancestry_gap_is_incomplete() {
    let mut t = table();
    let ev = ExecEvent {
        ppid: Some(10_999),
        ..ExecEvent::new(1, key(10_900, 100))
    };
    t.on_exec(ev);
    let chain = t.ancestry(10_900, Stop::Root);
    assert_eq!((pids(&chain), chain.complete), (vec![10_900], false));
}

#[test]
fn parent_cycles_terminate() {
    let mut t = table();
    t.on_exec(ExecEvent {
        ppid: Some(10_601),
        ..ExecEvent::new(1, key(10_600, 10))
    });
    t.on_exec(ExecEvent {
        ppid: Some(10_600),
        ..ExecEvent::new(2, key(10_601, 10))
    });
    let chain = t.ancestry(10_600, Stop::Root);
    assert_eq!(
        (pids(&chain), chain.complete),
        (vec![10_600, 10_601], false)
    );
}

#[test]
fn zombie_exit_status_survives_rescans() {
    let mut t = table();
    exec(&mut t, 10, key(1500, 6200), "sleep");
    t.enrich(1500).unwrap();
    assert_eq!(
        t.get(1500).unwrap().exit,
        Some(ExitInfo {
            ts_ns: 10,
            code: None
        })
    );
    exit(&mut t, 20, key(1500, 6200), 0);
    assert_eq!(
        t.get(1500).unwrap().exit,
        Some(ExitInfo {
            ts_ns: 20,
            code: Some(0)
        })
    );
    t.snapshot_all().unwrap();
    assert_eq!(
        t.get(1500).unwrap().exit,
        Some(ExitInfo {
            ts_ns: 20,
            code: Some(0)
        })
    );
}

#[test]
fn boot_ns_keys_match_proc_ticks() {
    let ticks_per_sec = NonZeroU64::new(100).unwrap();
    let mut t = with_config(Config {
        start_clock: StartClock::BootNs { ticks_per_sec },
        ..Config::default()
    });
    // start_boottime 61.057 s is tick 6105, as /proc reports for pid 1440.
    let start = 61_057_000_000;
    exec(&mut t, 10, key(1440, start), "node");
    t.enrich(1440).unwrap();
    // /proc-loaded ancestors get keys in the same clock and order correctly.
    let chain = t.ancestry(1440, Stop::At(1430));
    assert_eq!(keys(&chain), [key(1440, start), key(1430, 61_000_000_000)]);
}

#[test]
fn tombstones_expire_after_ttl() {
    let mut t = with_config(Config {
        tombstone_ttl_ns: 100,
        ..Config::default()
    });
    exec(&mut t, 0, key(10_400, 1), "a");
    exec(&mut t, 0, key(10_401, 1), "b");
    exit(&mut t, 1_000, key(10_400, 1), 0);
    t.expire(1_100);
    assert!(
        t.get_key(key(10_400, 1)).is_some(),
        "exactly TTL old is kept"
    );
    t.expire(1_101);
    assert!(t.get_key(key(10_400, 1)).is_none());
    assert!(t.get(10_401).is_some(), "live records never age out");
}

#[test]
fn cap_evicts_tombstones_first_then_least_recently_updated() {
    let mut t = with_config(Config {
        max_entries: 3,
        ..Config::default()
    });
    for (ts, pid) in [
        (10, 10_500),
        (11, 10_501),
        (12, 10_502),
        (13, 10_503),
        (14, 10_504),
    ] {
        exec(&mut t, ts, key(pid, 1), "p");
    }
    exit(&mut t, 15, key(10_504, 1), 0);
    t.on_comm(10_500, b"renamed");
    t.expire(16);
    assert_eq!(t.len(), 3);
    assert!(t.get(10_504).is_none(), "the tombstone goes first");
    assert!(
        t.get(10_501).is_none(),
        "then the least recently updated live record"
    );
    for pid in [10_500, 10_502, 10_503] {
        assert!(t.get(pid).is_some(), "{pid}");
    }
}
