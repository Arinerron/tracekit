use std::{
    collections::{HashMap, HashSet},
    fs,
    num::NonZeroU64,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    str::{FromStr, SplitAsciiWhitespace},
    sync::{Mutex, PoisonError},
};

use crate::{Pid, ProcError};

/// Per-process files a [`ProcSource`] can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProcFile {
    /// `cmdline`: NUL-separated arguments.
    Cmdline,
    /// `environ`: NUL-separated initial environment. Readable only by the owner or root.
    Environ,
    /// `cgroup`: cgroup memberships, one hierarchy per line.
    Cgroup,
    /// `status`: human-readable `Key:\tvalue` lines.
    Status,
    /// `comm`: the command name and a newline.
    Comm,
}

impl ProcFile {
    /// File name below `/proc/<pid>/`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Cmdline => "cmdline",
            Self::Environ => "environ",
            Self::Cgroup => "cgroup",
            Self::Status => "status",
            Self::Comm => "comm",
        }
    }
}

/// Per-process symlinks a [`ProcSource`] can resolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProcLink {
    /// `exe`: the executable.
    Exe,
    /// `cwd`: the working directory.
    Cwd,
    /// `root`: the root directory (differs inside chroots and containers).
    Root,
}

impl ProcLink {
    /// Link name below `/proc/<pid>/`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Exe => "exe",
            Self::Cwd => "cwd",
            Self::Root => "root",
        }
    }
}

/// The fields procctx uses from `/proc/<pid>/stat`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatLine {
    /// Field 1: pid.
    pub pid: Pid,
    /// Field 2: command name without the parentheses, lossily decoded.
    pub comm: Box<str>,
    /// Field 3: state letter (`R`, `S`, `D`, `Z`, ...).
    pub state: u8,
    /// Field 4: parent pid, after any re-parenting.
    pub ppid: Pid,
    /// Field 5: process group id.
    pub pgrp: Pid,
    /// Field 6: session id.
    pub session: Pid,
    /// Field 7: controlling terminal device (0 means none).
    pub tty_nr: u32,
    /// Field 22: start time in clock ticks since boot.
    pub start_ticks: u64,
}

impl StatLine {
    /// Parses a `stat` line. `pid` is only used in errors.
    ///
    /// `comm` may contain spaces, parentheses and even newlines, so the fields are
    /// located from the last `)`.
    pub fn parse(pid: Pid, line: &[u8]) -> Result<Self, ProcError> {
        let err = |what| ProcError::Parse { pid, what };
        let open = line
            .iter()
            .position(|&b| b == b'(')
            .ok_or_else(|| err("stat comm"))?;
        let close = line
            .iter()
            .rposition(|&b| b == b')')
            .filter(|&close| close > open)
            .ok_or_else(|| err("stat comm"))?;
        let stat_pid = std::str::from_utf8(&line[..open])
            .ok()
            .and_then(|head| head.trim().parse().ok())
            .ok_or_else(|| err("stat pid"))?;
        let comm = Box::from(String::from_utf8_lossy(&line[open + 1..close]));
        let rest = std::str::from_utf8(&line[close + 1..]).map_err(|_| err("stat fields"))?;
        let mut fields = rest.split_ascii_whitespace();
        let Some(&[state]) = fields.next().map(str::as_bytes) else {
            return Err(err("stat state"));
        };
        let parent = field(&mut fields).ok_or_else(|| err("stat ppid"))?;
        let pgrp = field(&mut fields).ok_or_else(|| err("stat pgrp"))?;
        let session = field(&mut fields).ok_or_else(|| err("stat session"))?;
        // The kernel prints the u32 device number with %d.
        let tty_nr: i32 = field(&mut fields).ok_or_else(|| err("stat tty_nr"))?;
        // Fields 8..=21 are not needed; field 22 is starttime.
        let start_ticks = fields
            .nth(14)
            .and_then(|f| f.parse().ok())
            .ok_or_else(|| err("stat starttime"))?;
        Ok(Self {
            pid: stat_pid,
            comm,
            state,
            ppid: parent,
            pgrp,
            session,
            tty_nr: u32::from_ne_bytes(tty_nr.to_ne_bytes()),
            start_ticks,
        })
    }

    /// Whether the process has exited and awaits reaping (`Z`) or is being torn down (`X`).
    pub fn has_exited(&self) -> bool {
        matches!(self.state, b'Z' | b'X')
    }
}

fn field<T: FromStr>(fields: &mut SplitAsciiWhitespace<'_>) -> Option<T> {
    fields.next()?.parse().ok()
}

/// Real uid and gid from `/proc/<pid>/status` (`None` for absent or malformed lines).
pub(crate) fn parse_status_ids(status: &[u8]) -> (Option<u32>, Option<u32>) {
    let first = |rest: &[u8]| -> Option<u32> {
        std::str::from_utf8(rest)
            .ok()?
            .split_ascii_whitespace()
            .next()?
            .parse()
            .ok()
    };
    let mut ids = (None, None);
    for line in status.split(|&b| b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"Uid:") {
            ids.0 = first(rest);
        } else if let Some(rest) = line.strip_prefix(b"Gid:") {
            ids.1 = first(rest);
        }
    }
    ids
}

const AT_NULL: usize = 0;
const AT_CLKTCK: usize = 17;

/// `AT_CLKTCK` from an auxiliary vector (native-endian `usize` key/value pairs).
fn parse_auxv_clktck(auxv: &[u8]) -> Option<NonZeroU64> {
    const WORD: usize = size_of::<usize>();
    let word = |bytes: &[u8]| <[u8; WORD]>::try_from(bytes).ok().map(usize::from_ne_bytes);
    auxv.chunks_exact(2 * WORD)
        .map(|pair| (word(&pair[..WORD]), word(&pair[WORD..])))
        .take_while(|&(key, _)| key != Some(AT_NULL))
        .find(|&(key, _)| key == Some(AT_CLKTCK))
        .and_then(|(_, hz)| NonZeroU64::new(u64::try_from(hz?).ok()?))
}

/// Read access to process state. [`ProcFs`] is the real implementation; tests can
/// substitute fixtures or inject faults.
///
/// Errors follow [`ProcError`]: a missing process is `NotFound`, an unreadable
/// file is `Permission`.
pub trait ProcSource: Send {
    /// Parses `/proc/<pid>/stat`.
    fn stat(&self, pid: Pid) -> Result<StatLine, ProcError>;
    /// Reads a per-process file.
    fn read(&self, pid: Pid, file: ProcFile) -> Result<Vec<u8>, ProcError>;
    /// Resolves a per-process symlink.
    fn readlink(&self, pid: Pid, link: ProcLink) -> Result<PathBuf, ProcError>;
    /// Every visible process (thread-group ids only).
    fn list_pids(&self) -> Result<Vec<Pid>, ProcError>;
    /// The cgroup v2 path (relative to the cgroup2 mount, starting with `/`) whose
    /// directory inode is `id`. `None` means no such cgroup exists, or it was removed.
    fn cgroup_path_by_id(&self, id: u64) -> Option<Box<str>>;
}

/// [`ProcSource`] over a procfs mount and a cgroup2 mount.
#[derive(Debug)]
pub struct ProcFs {
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    cgroups: Mutex<CgroupIndex>,
}

/// Cached id → path map from the last walk of the cgroup tree.
#[derive(Debug, Default)]
struct CgroupIndex {
    paths: HashMap<u64, Box<str>>,
    /// Ids a fresh walk did not find. cgroup ids are never reused, so a miss is permanent.
    missing: HashSet<u64>,
}

impl ProcFs {
    /// The host's `/proc` and `/sys/fs/cgroup`.
    pub fn new() -> Self {
        Self::with_roots("/proc", "/sys/fs/cgroup")
    }

    /// A procfs and cgroup2 tree mounted elsewhere, or fixtures laid out the same way.
    pub fn with_roots(proc_root: impl Into<PathBuf>, cgroup_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            cgroup_root: cgroup_root.into(),
            cgroups: Mutex::default(),
        }
    }

    /// The procfs mount.
    pub fn proc_root(&self) -> &Path {
        &self.proc_root
    }

    /// The cgroup2 mount.
    pub fn cgroup_root(&self) -> &Path {
        &self.cgroup_root
    }

    /// The kernel's `USER_HZ` (the unit of `/proc` start times), read from `AT_CLKTCK` in
    /// `<proc_root>/self/auxv`. Use it to build [`StartClock::BootNs`](crate::StartClock::BootNs).
    ///
    /// Caveat: `/proc/self/auxv` is unreadable (`Permission`) for a non-dumpable process, which
    /// includes any binary launched with elevated file capabilities (e.g. `setcap cap_bpf+ep`).
    /// Such callers should instead read `AT_CLKTCK` via `libc::getauxval(libc::AT_CLKTCK)`, which
    /// needs no file access.
    pub fn clock_ticks_per_sec(&self) -> Result<NonZeroU64, ProcError> {
        let pid = std::process::id();
        let auxv = fs::read(self.proc_root.join("self/auxv"))
            .map_err(|err| ProcError::from_io(pid, err))?;
        parse_auxv_clktck(&auxv).ok_or(ProcError::Parse {
            pid,
            what: "auxv AT_CLKTCK",
        })
    }

    fn pid_path(&self, pid: Pid, name: &str) -> PathBuf {
        let mut path = self.proc_root.join(pid.to_string());
        path.push(name);
        path
    }
}

impl Default for ProcFs {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcSource for ProcFs {
    fn stat(&self, pid: Pid) -> Result<StatLine, ProcError> {
        let line =
            fs::read(self.pid_path(pid, "stat")).map_err(|err| ProcError::from_io(pid, err))?;
        StatLine::parse(pid, &line)
    }

    fn read(&self, pid: Pid, file: ProcFile) -> Result<Vec<u8>, ProcError> {
        fs::read(self.pid_path(pid, file.name())).map_err(|err| ProcError::from_io(pid, err))
    }

    fn readlink(&self, pid: Pid, link: ProcLink) -> Result<PathBuf, ProcError> {
        fs::read_link(self.pid_path(pid, link.name())).map_err(|err| ProcError::from_io(pid, err))
    }

    fn list_pids(&self) -> Result<Vec<Pid>, ProcError> {
        let mut pids: Vec<Pid> = fs::read_dir(&self.proc_root)
            .map_err(ProcError::Io)?
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        pids.sort_unstable();
        Ok(pids)
    }

    /// Looks `id` up in a cached index of the cgroup tree. An unknown id triggers one
    /// fresh walk; ids still missing afterwards are remembered and never walked for again.
    fn cgroup_path_by_id(&self, id: u64) -> Option<Box<str>> {
        let mut index = self.cgroups.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(path) = index.paths.get(&id) {
            return Some(path.clone());
        }
        if index.missing.contains(&id) {
            return None;
        }
        index.paths = walk_cgroups(&self.cgroup_root);
        let found = index.paths.get(&id).cloned();
        if found.is_none() {
            index.missing.insert(id);
        }
        found
    }
}

/// Maps every directory inode below `root` to its path relative to `root`.
/// Unreadable or vanishing subtrees are skipped.
fn walk_cgroups(root: &Path) -> HashMap<u64, Box<str>> {
    let mut paths = HashMap::new();
    let Ok(meta) = fs::metadata(root) else {
        return paths;
    };
    paths.insert(meta.ino(), Box::from("/"));
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = pending.pop() {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            // d_type avoids a stat for the many control files in each cgroup.
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let child = format!("{rel}/{}", entry.file_name().to_string_lossy());
            paths.insert(meta.ino(), Box::from(child.as_str()));
            pending.push((entry.path(), child));
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::{StatLine, parse_auxv_clktck, parse_status_ids};
    use crate::ProcError;

    const TAIL: &str = "4194560 1200 0 3 0 5 3 0 0 20 0 1 0 6105 12345678 900 18446744073709551615";

    fn line(head: &str) -> Vec<u8> {
        format!("{head} {TAIL}\n").into_bytes()
    }

    #[test]
    fn parses_plain_line() {
        let stat = StatLine::parse(1300, &line("1300 (bash) S 1200 1300 1300 34819 1400")).unwrap();
        assert_eq!(
            stat,
            StatLine {
                pid: 1300,
                comm: "bash".into(),
                state: b'S',
                ppid: 1200,
                pgrp: 1300,
                session: 1300,
                tty_nr: 34_819,
                start_ticks: 6105,
            }
        );
        assert!(!stat.has_exited());
    }

    #[test]
    fn comm_with_parens_spaces_and_newline() {
        let stat = StatLine::parse(9, &line("9 (evil) (x) S 1 9 9 0 -1")).unwrap();
        assert_eq!(
            (stat.comm.as_ref(), stat.ppid, stat.start_ticks),
            ("evil) (x", 1, 6105)
        );
        let stat = StatLine::parse(9, &line("9 (a)\n) 4 (b) R 7 9 9 0 -1")).unwrap();
        assert_eq!(
            (stat.comm.as_ref(), stat.state, stat.ppid),
            ("a)\n) 4 (b", b'R', 7)
        );
        let stat = StatLine::parse(9, &line("9 () S 1 9 9 0 -1")).unwrap();
        assert_eq!(stat.comm.as_ref(), "");
    }

    #[test]
    fn zombie_and_dead_states() {
        let zombie = StatLine::parse(5, &line("5 (sleep) Z 1300 5 1300 0 -1")).unwrap();
        assert!(zombie.has_exited());
        let dead = StatLine::parse(5, &line("5 (sleep) X 1300 5 1300 0 -1")).unwrap();
        assert!(dead.has_exited());
    }

    #[test]
    fn negative_tty_keeps_device_bits() {
        let stat = StatLine::parse(5, &line("5 (x) S 1 5 5 -2 -1")).unwrap();
        assert_eq!(stat.tty_nr, u32::MAX - 1);
    }

    #[test]
    fn malformed_lines_name_the_field() {
        let what = |raw: &[u8]| match StatLine::parse(4, raw) {
            Err(ProcError::Parse { pid: 4, what }) => what,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(what(b"4 bash S 1 4 4 0"), "stat comm");
        assert_eq!(what(b"4 )bash( S 1 4 4 0"), "stat comm");
        assert_eq!(what(b"x (bash) S 1 4 4 0"), "stat pid");
        assert_eq!(what(b"4 (bash)"), "stat state");
        assert_eq!(what(b"4 (bash) SS 1"), "stat state");
        assert_eq!(what(b"4 (bash) S -1 4 4 0"), "stat ppid");
        // Truncated before field 22.
        let short = b"4 (bash) S 1 4 4 0 -1 4194560 1200 0 3 0 5 3 0 0 20 0 1 0";
        assert_eq!(what(short), "stat starttime");
    }

    #[test]
    fn status_ids_use_the_real_id() {
        let status = b"Name:\tbash\nUid:\t1000\t0\t0\t0\nGid:\t100\t100\t100\t100\n";
        assert_eq!(parse_status_ids(status), (Some(1000), Some(100)));
        assert_eq!(parse_status_ids(b"Name:\tx\nUid:\tbogus\n"), (None, None));
    }

    #[test]
    fn auxv_clock_ticks() {
        let auxv: Vec<u8> = [6, 4096, 17, 100, 0, 0, 17, 250]
            .iter()
            .flat_map(|w: &usize| w.to_ne_bytes())
            .collect();
        assert_eq!(parse_auxv_clktck(&auxv), NonZeroU64::new(100));
        // AT_NULL ends the vector: entries after it are ignored.
        let auxv: Vec<u8> = [6, 4096, 0, 0, 17, 100]
            .iter()
            .flat_map(|w: &usize| w.to_ne_bytes())
            .collect();
        assert_eq!(parse_auxv_clktck(&auxv), None);
        // A zero rate would divide by zero later.
        let auxv: Vec<u8> = [17, 0]
            .iter()
            .flat_map(|w: &usize| w.to_ne_bytes())
            .collect();
        assert_eq!(parse_auxv_clktck(&auxv), None);
    }
}
