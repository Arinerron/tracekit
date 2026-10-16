//! [`FixtureEnv`]: a fully scripted [`Env`] for testing checks.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::{BpfProbe, CapSets, Env, Ids, MountFlags, Uname};

/// An [`Env`] backed by a directory tree standing in for `/`, with in-memory
/// file overrides and scripted credentials, limits and probe results.
///
/// Defaults describe a healthy host running as root: Linux 6.8.0 on `x86_64`,
/// every capability effective, no file capabilities, no `nosuid` mounts,
/// `no_new_privs` clear, an 8 MiB memlock limit and successful probes.
#[derive(Clone, Debug)]
pub struct FixtureEnv {
    root: PathBuf,
    files: HashMap<PathBuf, Option<Vec<u8>>>,
    uname: Uname,
    caps: CapSets,
    file_caps: HashMap<PathBuf, u64>,
    mounts: HashMap<PathBuf, MountFlags>,
    no_new_privs: bool,
    ids: Ids,
    memlock: (u64, u64),
    vars: HashMap<String, String>,
    probes: HashMap<BpfProbe, Result<(), i32>>,
}

/// Capabilities 0 through 40 (`CAP_CHECKPOINT_RESTORE`), as root holds them.
const ALL_CAPS: u64 = (1 << 41) - 1;

impl FixtureEnv {
    /// A fixture whose absolute paths resolve under `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            files: HashMap::new(),
            uname: Uname {
                sysname: "Linux".to_owned(),
                release: "6.8.0".to_owned(),
                machine: "x86_64".to_owned(),
            },
            caps: CapSets {
                effective: ALL_CAPS,
                permitted: ALL_CAPS,
                bounding: ALL_CAPS,
            },
            file_caps: HashMap::new(),
            mounts: HashMap::new(),
            no_new_privs: false,
            ids: Ids::default(),
            memlock: (8 << 20, 8 << 20),
            vars: HashMap::new(),
            probes: HashMap::new(),
        }
    }

    /// Overrides the contents of absolute `path`, shadowing the root tree.
    #[must_use]
    pub fn with_file(mut self, path: impl Into<PathBuf>, contents: impl Into<Vec<u8>>) -> Self {
        self.files.insert(path.into(), Some(contents.into()));
        self
    }

    /// Makes absolute `path` absent even if the root tree contains it.
    #[must_use]
    pub fn without_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.files.insert(path.into(), None);
        self
    }

    /// Sets the `uname` triple.
    #[must_use]
    pub fn with_uname(mut self, sysname: &str, release: &str, machine: &str) -> Self {
        self.uname = Uname {
            sysname: sysname.to_owned(),
            release: release.to_owned(),
            machine: machine.to_owned(),
        };
        self
    }

    /// Sets the process capability sets.
    #[must_use]
    pub fn with_caps(mut self, caps: CapSets) -> Self {
        self.caps = caps;
        self
    }

    /// Sets the permitted file-capability mask of `path`.
    #[must_use]
    pub fn with_file_caps(mut self, path: impl Into<PathBuf>, mask: u64) -> Self {
        self.file_caps.insert(path.into(), mask);
        self
    }

    /// Sets the mount flags reported for `path`; other paths report none set.
    #[must_use]
    pub fn with_mount_flags(mut self, path: impl Into<PathBuf>, flags: MountFlags) -> Self {
        self.mounts.insert(path.into(), flags);
        self
    }

    /// Sets `no_new_privs`.
    #[must_use]
    pub fn with_no_new_privs(mut self, set: bool) -> Self {
        self.no_new_privs = set;
        self
    }

    /// Sets the process credentials.
    #[must_use]
    pub fn with_ids(mut self, ids: Ids) -> Self {
        self.ids = ids;
        self
    }

    /// Sets `RLIMIT_MEMLOCK`; `u64::MAX` means unlimited.
    #[must_use]
    pub fn with_memlock(mut self, soft: u64, hard: u64) -> Self {
        self.memlock = (soft, hard);
        self
    }

    /// Sets an environment variable.
    #[must_use]
    pub fn with_var(mut self, key: &str, value: &str) -> Self {
        self.vars.insert(key.to_owned(), value.to_owned());
        self
    }

    /// Scripts the result of a feature probe; unscripted probes succeed.
    #[must_use]
    pub fn with_probe(mut self, probe: BpfProbe, result: Result<(), i32>) -> Self {
        self.probes.insert(probe, result);
        self
    }

    fn host_path(&self, path: &Path) -> PathBuf {
        self.root.join(path.strip_prefix("/").unwrap_or(path))
    }
}

impl Env for FixtureEnv {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        match self.files.get(path) {
            Some(Some(contents)) => Ok(contents.clone()),
            Some(None) => Err(io::ErrorKind::NotFound.into()),
            None => fs::read(self.host_path(path)),
        }
    }

    fn exists(&self, path: &Path) -> bool {
        match self.files.get(path) {
            Some(contents) => contents.is_some(),
            None => self.host_path(path).exists(),
        }
    }

    fn uname(&self) -> Uname {
        self.uname.clone()
    }

    fn caps(&self) -> CapSets {
        self.caps
    }

    fn file_caps(&self, path: &Path) -> Option<u64> {
        self.file_caps.get(path).copied()
    }

    fn mount_flags(&self, path: &Path) -> Option<MountFlags> {
        Some(self.mounts.get(path).copied().unwrap_or_default())
    }

    fn no_new_privs(&self) -> bool {
        self.no_new_privs
    }

    fn ids(&self) -> Ids {
        self.ids.clone()
    }

    fn memlock(&self) -> (u64, u64) {
        self.memlock
    }

    fn env_var(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned()
    }

    fn bpf_probe(&self, probe: BpfProbe) -> Result<(), i32> {
        self.probes.get(&probe).copied().unwrap_or(Ok(()))
    }
}
