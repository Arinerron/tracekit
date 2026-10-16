//! Test support for code built on procctx (enabled by the `testing` feature).

use std::{
    collections::HashSet,
    ffi::OsStr,
    fs,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    sync::{Mutex, MutexGuard, PoisonError},
};

use crate::{Pid, ProcError, ProcFile, ProcFs, ProcLink, ProcSource, StatLine};

/// A [`ProcSource`] over a fixture tree laid out like `/proc` and a cgroup2 mount, with
/// injectable faults.
///
/// Per-process links (`exe`, `cwd`, `root`) are regular files that hold the target
/// path, not symlinks. Cargo and other tools that walk the source tree follow
/// symlinks to directories, and a fixture `cwd -> /` would send them across the
/// whole filesystem.
///
/// Faults can be added through `&self` while a [`ProcTable`](crate::ProcTable) owns
/// the source (via [`ProcTable::source`](crate::ProcTable::source)), so tests can
/// change the world between table calls.
#[derive(Debug)]
pub struct FixtureSource {
    fs: ProcFs,
    faults: Mutex<Faults>,
}

#[derive(Debug, Default)]
struct Faults {
    files: HashSet<(Pid, ProcFile)>,
    links: HashSet<(Pid, ProcLink)>,
    gone: HashSet<Pid>,
}

impl FixtureSource {
    /// Serves `proc_root/<pid>/...` and walks `cgroup_root` for cgroup ids (directory inodes).
    pub fn new(proc_root: impl Into<PathBuf>, cgroup_root: impl Into<PathBuf>) -> Self {
        Self {
            fs: ProcFs::with_roots(proc_root, cgroup_root),
            faults: Mutex::default(),
        }
    }

    /// procctx's own fixtures (`tests/fixtures/proc` and `tests/fixtures/cgroup` in this
    /// crate), a small desktop session:
    ///
    /// | pid  | process                                   | notes                         |
    /// |------|-------------------------------------------|-------------------------------|
    /// | 1    | systemd                                   | `/init.scope`                 |
    /// | 1200 | tmux server                               | user tmux scope               |
    /// | 1300 | bash in pane `%3`                         | `TMUX`, `TMUX_PANE`           |
    /// | 1400 | `make install`                            |                               |
    /// | 1410 | `sh -c "npm ci"`                          | `MAKELEVEL=1`                 |
    /// | 1420 | `npm ci`                                  |                               |
    /// | 1430 | esbuild `postinstall` shell               | npm lifecycle env             |
    /// | 1440 | `node install.js`, comm `evil) (x`        | cwd `node_modules/@esbuild/…` |
    /// | 1500 | zombie `sleep`                            | state `Z`, child of 1300      |
    /// | 2000 | nginx                                     | Docker container              |
    /// | 2100 | Cargo `build-script-build` for `ring`     | child of 1300                 |
    pub fn bundled() -> Self {
        Self::new(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/proc"),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cgroup"),
        )
    }

    /// The underlying fixture reader.
    pub fn procfs(&self) -> &ProcFs {
        &self.fs
    }

    /// Makes reads of `file` for `pid` fail with [`ProcError::Permission`], like
    /// another user's `environ`.
    pub fn deny(&self, pid: Pid, file: ProcFile) {
        self.faults().files.insert((pid, file));
    }

    /// Makes resolving `link` for `pid` fail with [`ProcError::Permission`].
    pub fn deny_link(&self, pid: Pid, link: ProcLink) {
        self.faults().links.insert((pid, link));
    }

    /// Makes `pid` vanish, as if it exited and was reaped: every access fails with
    /// [`ProcError::NotFound`] and `list_pids` omits it.
    pub fn remove(&self, pid: Pid) {
        self.faults().gone.insert(pid);
    }

    fn faults(&self) -> MutexGuard<'_, Faults> {
        self.faults.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn present(&self, pid: Pid) -> Result<(), ProcError> {
        if self.faults().gone.contains(&pid) {
            Err(ProcError::NotFound(pid))
        } else {
            Ok(())
        }
    }
}

impl ProcSource for FixtureSource {
    fn stat(&self, pid: Pid) -> Result<StatLine, ProcError> {
        self.present(pid)?;
        self.fs.stat(pid)
    }

    fn read(&self, pid: Pid, file: ProcFile) -> Result<Vec<u8>, ProcError> {
        self.present(pid)?;
        if self.faults().files.contains(&(pid, file)) {
            return Err(ProcError::Permission(pid));
        }
        self.fs.read(pid, file)
    }

    fn readlink(&self, pid: Pid, link: ProcLink) -> Result<PathBuf, ProcError> {
        self.present(pid)?;
        if self.faults().links.contains(&(pid, link)) {
            return Err(ProcError::Permission(pid));
        }
        let path = self.fs.proc_root().join(pid.to_string()).join(link.name());
        let raw = fs::read(path).map_err(|err| ProcError::from_io(pid, err))?;
        let target = raw.strip_suffix(b"\n").unwrap_or(raw.as_slice());
        Ok(PathBuf::from(OsStr::from_bytes(target)))
    }

    fn list_pids(&self) -> Result<Vec<Pid>, ProcError> {
        let mut pids = self.fs.list_pids()?;
        let faults = self.faults();
        pids.retain(|pid| !faults.gone.contains(pid));
        Ok(pids)
    }

    fn cgroup_path_by_id(&self, id: u64) -> Option<Box<str>> {
        self.fs.cgroup_path_by_id(id)
    }
}
