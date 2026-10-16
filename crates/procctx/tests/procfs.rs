//! `ProcFs` against the bundled fixture tree, through `FixtureSource`.

use std::{os::unix::fs::MetadataExt, path::Path};

use procctx::{ProcError, ProcFile, ProcFs, ProcLink, ProcSource, testing::FixtureSource};

const CGROUP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cgroup");
const DOCKER: &str =
    "/system.slice/docker-3f4e5d6c7b8a99001122334455667788990011223344556677889900aabbccdd.scope";

fn inode(rel: &str) -> u64 {
    std::fs::metadata(format!("{CGROUP}{rel}")).unwrap().ino()
}

#[test]
fn lists_only_numeric_entries() {
    let pids = FixtureSource::bundled().list_pids().unwrap();
    assert_eq!(
        pids,
        [
            1, 1200, 1300, 1400, 1410, 1420, 1430, 1440, 1500, 2000, 2100
        ]
    );
}

#[test]
fn stat_survives_hostile_comm() {
    let stat = FixtureSource::bundled().stat(1440).unwrap();
    assert_eq!(
        (
            stat.comm.as_ref(),
            stat.ppid,
            stat.pgrp,
            stat.session,
            stat.tty_nr,
            stat.start_ticks
        ),
        ("evil) (x", 1430, 1400, 1300, 34_819, 6105)
    );
}

#[test]
fn zombie_has_exited_and_no_exe() {
    let src = FixtureSource::bundled();
    assert!(src.stat(1500).unwrap().has_exited());
    assert!(matches!(
        src.readlink(1500, ProcLink::Exe),
        Err(ProcError::NotFound(1500))
    ));
    assert_eq!(src.read(1500, ProcFile::Cmdline).unwrap(), b"");
}

#[test]
fn files_and_links() {
    let src = FixtureSource::bundled();
    assert_eq!(
        src.read(1410, ProcFile::Cmdline).unwrap(),
        b"/bin/sh\0-c\0npm ci\0"
    );
    assert_eq!(src.read(1300, ProcFile::Comm).unwrap(), b"bash\n");
    assert_eq!(
        src.readlink(1300, ProcLink::Cwd).unwrap(),
        Path::new("/home/dev/proj")
    );
    assert!(matches!(src.stat(4242), Err(ProcError::NotFound(4242))));
    assert!(matches!(
        src.read(4242, ProcFile::Environ),
        Err(ProcError::NotFound(4242))
    ));
}

#[test]
fn missing_proc_root_is_an_io_error() {
    let fs = ProcFs::with_roots("/nonexistent/procctx/proc", CGROUP);
    assert!(matches!(fs.list_pids(), Err(ProcError::Io(_))));
}

#[test]
fn cgroup_ids_are_directory_inodes() {
    let src = FixtureSource::bundled();
    assert_eq!(
        src.cgroup_path_by_id(inode(DOCKER)).as_deref(),
        Some(DOCKER)
    );
    assert_eq!(src.cgroup_path_by_id(inode("")).as_deref(), Some("/"));
    let tmux = "/user.slice/user-1000.slice/user@1000.service/app.slice/tmux-spawn-5f2c.scope";
    assert_eq!(src.cgroup_path_by_id(inode(tmux)).as_deref(), Some(tmux));
    // Control files are not cgroups.
    assert_eq!(
        src.cgroup_path_by_id(inode("/init.scope/cgroup.procs")),
        None
    );
    assert_eq!(src.cgroup_path_by_id(u64::MAX), None);
    // A remembered miss does not hide ids found by the same walk.
    assert_eq!(
        src.cgroup_path_by_id(inode("/init.scope")).as_deref(),
        Some("/init.scope")
    );
}

#[test]
fn injected_faults() {
    let src = FixtureSource::bundled();
    src.deny(1430, ProcFile::Environ);
    src.deny_link(1430, ProcLink::Cwd);
    assert!(matches!(
        src.read(1430, ProcFile::Environ),
        Err(ProcError::Permission(1430))
    ));
    assert!(matches!(
        src.readlink(1430, ProcLink::Cwd),
        Err(ProcError::Permission(1430))
    ));
    assert_eq!(
        src.read(1430, ProcFile::Cmdline).unwrap(),
        b"sh\0-c\0node install.js\0"
    );
    src.remove(1430);
    assert!(matches!(src.stat(1430), Err(ProcError::NotFound(1430))));
    assert!(matches!(
        src.read(1430, ProcFile::Cmdline),
        Err(ProcError::NotFound(1430))
    ));
    assert!(!src.list_pids().unwrap().contains(&1430));
}
