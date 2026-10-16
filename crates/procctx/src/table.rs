use std::{
    collections::{BTreeMap, HashMap, hash_map::Entry},
    ffi::OsStr,
    ops::RangeInclusive,
    os::unix::ffi::OsStrExt,
    path::Path,
    sync::Arc,
};

use crate::{
    CgroupInfo, Container, EnvFacts, ExecEvent, ExitEvent, ExitInfo, ForkEvent, Origin, Pid,
    ProcError, ProcFile, ProcInfo, ProcKey, ProcLink, ProcSource, Source, StartClock, StatLine,
    SystemdUnit, TmuxPane, cgroup::cgroup_v2_path, classify_origin, intern::Interner,
    parse_env_facts, source::parse_status_ids,
};

/// [`ProcTable`] tuning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Records (live and exited) kept after [`ProcTable::expire`]. The default is 65536.
    pub max_entries: usize,
    /// How long exited processes stay available for ancestry, in the event clock.
    /// The default is 600 s.
    pub tombstone_ttl_ns: u64,
    /// Read `/proc/<pid>/environ` when enriching. The default is `true`.
    pub read_environ: bool,
    /// Cap on stored argument bytes per process (NULs included). The default is 4096.
    pub max_argv_bytes: usize,
    /// Clock of every [`ProcKey::start`] the caller passes in. The default is
    /// [`StartClock::Ticks`].
    pub start_clock: StartClock,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_entries: 65_536,
            tombstone_ttl_ns: 600_000_000_000,
            read_environ: true,
            max_argv_bytes: 4096,
            start_clock: StartClock::Ticks,
        }
    }
}

/// Where [`ProcTable::ancestry`] stops climbing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stop {
    /// At a process without a parent (pid 1, kthreadd).
    Root,
    /// After including the first process with this pid.
    At(Pid),
    /// After this many ancestors above the starting process (0 means only itself).
    Depth(u16),
}

/// A process and its ancestors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ancestry {
    /// The process first, then its parent, grandparent, and so on.
    pub chain: Vec<Arc<ProcInfo>>,
    /// The walk reached its [`Stop`] or a root. `false` means it ended at a gap: an
    /// ancestor that is unknown, unreadable, already reused, or part of a parent cycle.
    pub complete: bool,
}

/// Where a process runs, from itself or its nearest ancestor that knows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    /// cgroup of the process, or of its nearest ancestor with a known cgroup.
    pub cgroup: Option<Arc<CgroupInfo>>,
    /// Nearest systemd unit.
    pub unit: Option<SystemdUnit>,
    /// Nearest container.
    pub container: Option<Container>,
    /// Nearest tmux pane.
    pub tmux: Option<TmuxPane>,
}

/// Process table built from fork/exec/comm/exit events, with `/proc` as a fallback.
///
/// The event handlers (`on_*`) and lookups (`get`, `get_key`) never touch the
/// [`ProcSource`]. They allocate only what the new record stores: repeated command
/// names and paths are interned, unchanged fields are shared with the parent, and an
/// unknown cgroup id is resolved later instead of walking the cgroup tree. Only
/// [`enrich`](Self::enrich), [`snapshot_all`](Self::snapshot_all), the ancestry-based
/// queries and [`resolve_cgroup`](Self::resolve_cgroup) do blocking I/O.
///
/// Exited processes stay as tombstones until [`expire`](Self::expire) drops them,
/// so a child whose parent has exited still has its full lineage.
#[derive(Debug)]
pub struct ProcTable<S> {
    src: S,
    cfg: Config,
    live: HashMap<Pid, Slot>,
    dead: BTreeMap<ProcKey, Slot>,
    names: Interner<str>,
    paths: Interner<Path>,
    cgroups: Cgroups,
    blank: Blank,
    /// Mutation counter; orders records for LRU eviction.
    clock: u64,
    /// Newest event timestamp seen; dates inferred exits.
    last_ts_ns: u64,
}

#[derive(Debug)]
struct Slot {
    info: Arc<ProcInfo>,
    /// cgroup id from an exec event not yet resolved to a path.
    pending_cgroup: Option<u64>,
    /// Fields were copied from the parent at fork. Enrichment replaces them with the
    /// process's own `/proc` values.
    inherited: bool,
    /// The table's mutation counter at the last change.
    touched: u64,
}

impl Slot {
    fn new(info: ProcInfo, touched: u64) -> Self {
        Self {
            info: Arc::new(info),
            pending_cgroup: None,
            inherited: false,
            touched,
        }
    }
}

/// Shared empty values, so unknown fields cost no allocation.
#[derive(Debug)]
struct Blank {
    comm: Arc<str>,
    argv: Arc<[Box<OsStr>]>,
    env: Arc<EnvFacts>,
}

impl Blank {
    fn new() -> Self {
        Self {
            comm: Arc::from(""),
            argv: Arc::from([]),
            env: Arc::default(),
        }
    }

    fn info(&self, key: ProcKey, source: Source) -> ProcInfo {
        ProcInfo {
            key,
            ppid: None,
            comm: Arc::clone(&self.comm),
            exe: None,
            argv: Arc::clone(&self.argv),
            argv_truncated: false,
            cwd: None,
            uid: None,
            gid: None,
            sid: None,
            pgid: None,
            tty_nr: None,
            cgroup: None,
            env: None,
            exit: None,
            source,
            exec_ts_ns: None,
            fork_ts_ns: None,
        }
    }

    fn env(&self, facts: EnvFacts) -> Arc<EnvFacts> {
        if facts.is_empty() {
            Arc::clone(&self.env)
        } else {
            Arc::new(facts)
        }
    }

    /// Splits NUL-separated arguments, keeping at most `cap` bytes.
    fn argv(&self, raw: &[u8], cap: usize, truncated: bool) -> (Arc<[Box<OsStr>]>, bool) {
        let (raw, truncated) = if raw.len() > cap {
            (&raw[..cap], true)
        } else {
            (raw, truncated)
        };
        if raw.is_empty() {
            return (Arc::clone(&self.argv), truncated);
        }
        // A trailing NUL ends the last argument; it does not start an empty one.
        let raw = raw.strip_suffix(b"\0").unwrap_or(raw);
        let args = raw
            .split(|&b| b == 0)
            .map(|arg| Box::from(OsStr::from_bytes(arg)))
            .collect();
        (args, truncated)
    }
}

/// Interned cgroups: by id for event-sourced records, by path for `/proc`-sourced ones.
#[derive(Debug, Default)]
struct Cgroups {
    by_id: HashMap<u64, Arc<CgroupInfo>>,
    by_path: HashMap<Arc<str>, Arc<CgroupInfo>>,
}

impl Cgroups {
    fn resolve(&mut self, src: &impl ProcSource, id: u64) -> Option<Arc<CgroupInfo>> {
        if let Some(info) = self.by_id.get(&id) {
            return Some(Arc::clone(info));
        }
        let info = Arc::new(CgroupInfo::new(
            Some(id),
            Arc::from(src.cgroup_path_by_id(id)?),
        ));
        self.by_id.insert(id, Arc::clone(&info));
        Some(info)
    }

    fn by_path(&mut self, path: &str) -> Arc<CgroupInfo> {
        if let Some(info) = self.by_path.get(path) {
            return Arc::clone(info);
        }
        let info = Arc::new(CgroupInfo::new(None, Arc::from(path)));
        self.by_path
            .insert(Arc::clone(&info.path), Arc::clone(&info));
        info
    }

    fn prune(&mut self) {
        self.by_id.retain(|_, info| Arc::strong_count(info) > 1);
        self.by_path.retain(|_, info| Arc::strong_count(info) > 1);
    }
}

/// `/proc` facts for one process. `None` means not needed or unreadable; either way
/// the record keeps its value.
struct ProcRead {
    comm: Option<Arc<str>>,
    exe: Option<Arc<Path>>,
    argv: Option<(Arc<[Box<OsStr>]>, bool)>,
    cwd: Option<Arc<Path>>,
    ids: Option<(Option<u32>, Option<u32>)>,
    cgroup: Option<Arc<CgroupInfo>>,
    env: Option<Arc<EnvFacts>>,
}

impl ProcRead {
    fn apply(self, slot: &mut Slot, stat: &StatLine) {
        let refresh = slot.inherited;
        let info = Arc::make_mut(&mut slot.info);
        // The fork-time parent stays: /proc shows the re-parented one.
        info.ppid = info.ppid.or(Some(stat.ppid));
        if refresh || info.sid.is_none() {
            info.sid = Some(stat.session);
        }
        if refresh || info.pgid.is_none() {
            info.pgid = Some(stat.pgrp);
        }
        if refresh || info.tty_nr.is_none() {
            info.tty_nr = Some(stat.tty_nr);
        }
        if let Some(comm) = self.comm {
            info.comm = comm;
        }
        if let Some(exe) = self.exe {
            info.exe = Some(exe);
        }
        if let Some((argv, truncated)) = self.argv {
            info.argv = argv;
            info.argv_truncated = truncated;
        }
        if let Some(cwd) = self.cwd {
            info.cwd = Some(cwd);
        }
        if let Some(ids) = self.ids {
            info.uid = ids.0.or(info.uid);
            info.gid = ids.1.or(info.gid);
        }
        if let Some(cgroup) = self.cgroup {
            info.cgroup = Some(cgroup);
            slot.pending_cgroup = None;
        }
        if let Some(env) = self.env {
            info.env = Some(env);
        }
        info.source = info.source.merge(Source::Procfs);
        slot.inherited = false;
    }
}

enum Parent {
    Found(Arc<ProcInfo>),
    Root,
    Unknown,
}

const TASK_COMM_MAX: usize = 15;

/// The kernel's `comm` after exec of `filename`: the basename, cut to 15 bytes.
fn exec_comm(filename: &[u8]) -> &[u8] {
    let base = filename.rsplit(|&b| b == b'/').next().unwrap_or(filename);
    &base[..base.len().min(TASK_COMM_MAX)]
}

fn bytes_path(bytes: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(bytes))
}

fn pid_keys(pid: Pid) -> RangeInclusive<ProcKey> {
    ProcKey { pid, start: 0 }..=ProcKey {
        pid,
        start: u64::MAX,
    }
}

fn slot_mut<'a>(
    live: &'a mut HashMap<Pid, Slot>,
    dead: &'a mut BTreeMap<ProcKey, Slot>,
    key: ProcKey,
) -> Option<&'a mut Slot> {
    match live.get_mut(&key.pid) {
        Some(slot) if slot.info.key == key => Some(slot),
        _ => dead.get_mut(&key),
    }
}

impl<S: ProcSource> ProcTable<S> {
    /// An empty table reading `/proc` through `src`.
    pub fn new(src: S, cfg: Config) -> Self {
        Self {
            src,
            cfg,
            live: HashMap::new(),
            dead: BTreeMap::new(),
            names: Interner::default(),
            paths: Interner::default(),
            cgroups: Cgroups::default(),
            blank: Blank::new(),
            clock: 0,
            last_ts_ns: 0,
        }
    }

    /// The process source.
    pub fn source(&self) -> &S {
        &self.src
    }

    /// Number of records, live and exited.
    pub fn len(&self) -> usize {
        self.live.len() + self.dead.len()
    }

    /// Whether the table holds no records.
    pub fn is_empty(&self) -> bool {
        self.live.is_empty() && self.dead.is_empty()
    }

    /// The newest record for `pid`: the live process if there is one, otherwise the
    /// most recently started exited one.
    pub fn get(&self, pid: Pid) -> Option<&Arc<ProcInfo>> {
        let slot = self
            .live
            .get(&pid)
            .or_else(|| Some(self.dead.range(pid_keys(pid)).next_back()?.1))?;
        Some(&slot.info)
    }

    /// The record for exactly this process lifetime, live or exited.
    pub fn get_key(&self, key: ProcKey) -> Option<&Arc<ProcInfo>> {
        let live = self.live.get(&key.pid).filter(|slot| slot.info.key == key);
        live.or_else(|| self.dead.get(&key)).map(|slot| &slot.info)
    }

    /// Records a fork. The child starts as a copy of its parent's record (comm, exe,
    /// argv, cwd, ids, cgroup, environment facts) until its own exec or
    /// [`enrich`](Self::enrich) replaces those fields. Thread creation is ignored.
    pub fn on_fork(&mut self, ev: ForkEvent) {
        self.observe(ev.ts_ns);
        if ev.is_thread {
            return;
        }
        let touched = self.tick();
        let child = ev.child;
        if let Some(slot) = self.live.get_mut(&child.pid)
            && slot.info.key == child
        {
            // Exec or /proc got here first (events can arrive out of order across
            // CPUs): add only what the fork knows.
            let info = Arc::make_mut(&mut slot.info);
            info.fork_ts_ns = Some(ev.ts_ns);
            info.ppid = info.ppid.or(Some(ev.parent));
            slot.touched = touched;
            return;
        }
        self.retire(child.pid);
        let parent = self
            .live
            .get(&ev.parent)
            .filter(|parent| self.predates(parent.info.key, child.start));
        let (mut info, pending_cgroup, inherited) = if let Some(parent) = parent {
            (ProcInfo::clone(&parent.info), parent.pending_cgroup, true)
        } else {
            (self.blank.info(child, Source::Event), None, false)
        };
        info.key = child;
        info.ppid = Some(ev.parent);
        info.exec_ts_ns = None;
        info.fork_ts_ns = Some(ev.ts_ns);
        info.source = info.source.merge(Source::Event);
        let slot = Slot {
            info: Arc::new(info),
            pending_cgroup,
            inherited,
            touched,
        };
        self.live.insert(child.pid, slot);
    }

    /// Records a successful exec. Fields the event carries replace the record's.
    /// Without `filename`, `argv` or `env`, those become unknown, because the old
    /// values described the previous image. `cwd`, ppid, ids and cgroup survive the
    /// exec when the event omits them.
    ///
    /// When a non-leader thread execs, the kernel gives it the leader's identity. The
    /// caller must report such an exec with the thread-group id and the leader's start.
    pub fn on_exec(&mut self, ev: ExecEvent<'_>) {
        self.observe(ev.ts_ns);
        let touched = self.tick();
        let pid = ev.key.pid;
        if self
            .live
            .get(&pid)
            .is_some_and(|slot| slot.info.key != ev.key)
        {
            self.retire(pid);
        }
        let comm = ev
            .comm
            .or_else(|| ev.filename.map(exec_comm))
            .map(|comm| self.names.intern(&String::from_utf8_lossy(comm)));
        let exe = ev
            .filename
            .map(|filename| self.paths.intern(bytes_path(filename)));
        let cwd = ev.cwd.map(|cwd| self.paths.intern(bytes_path(cwd)));
        let (argv, argv_truncated) = ev.argv.map_or_else(
            || (Arc::clone(&self.blank.argv), false),
            |raw| {
                self.blank
                    .argv(raw, self.cfg.max_argv_bytes, ev.argv_truncated)
            },
        );
        let env = ev.env.map(|raw| self.blank.env(parse_env_facts(raw)));
        let cgroup = ev
            .cgroup_id
            .map(|id| (id, self.cgroups.by_id.get(&id).cloned()));
        let slot = self
            .live
            .entry(pid)
            .or_insert_with(|| Slot::new(self.blank.info(ev.key, Source::Event), touched));
        let info = Arc::make_mut(&mut slot.info);
        if let Some(comm) = comm {
            info.comm = comm;
        }
        info.exe = exe;
        info.argv = argv;
        info.argv_truncated = argv_truncated;
        info.env = env;
        if let Some(cwd) = cwd {
            info.cwd = Some(cwd);
        }
        info.ppid = ev.ppid.or(info.ppid);
        info.uid = ev.uid.or(info.uid);
        info.gid = ev.gid.or(info.gid);
        info.exec_ts_ns = Some(ev.ts_ns);
        info.source = info.source.merge(Source::Event);
        if let Some((id, cached)) = cgroup
            && info.cgroup.as_ref().and_then(|cgroup| cgroup.id) != Some(id)
        {
            // Unknown ids are resolved on demand, off the event path.
            slot.pending_cgroup = cached.is_none().then_some(id);
            info.cgroup = cached;
        }
        slot.touched = touched;
    }

    /// Records a `comm` change (`prctl(PR_SET_NAME)` or a write to `/proc/<pid>/comm`).
    pub fn on_comm(&mut self, pid: Pid, comm: &[u8]) {
        let comm = String::from_utf8_lossy(comm);
        let touched = self.tick();
        if let Some(slot) = self.live.get_mut(&pid)
            && *slot.info.comm != *comm
        {
            Arc::make_mut(&mut slot.info).comm = self.names.intern(&comm);
            slot.touched = touched;
        }
    }

    /// Records the exit of a whole process (deliver only the thread-group exit, not
    /// each thread's). The record becomes a tombstone. If the table had already
    /// inferred this exit, the event supplies the real time and status.
    pub fn on_exit(&mut self, ev: ExitEvent) {
        self.observe(ev.ts_ns);
        let exit = ExitInfo {
            ts_ns: ev.ts_ns,
            code: Some(ev.code),
        };
        if let Entry::Occupied(entry) = self.live.entry(ev.key.pid)
            && entry.get().info.key == ev.key
        {
            let slot = entry.remove();
            self.bury(slot, exit);
            return;
        }
        let touched = self.tick();
        if let Some(slot) = self.dead.get_mut(&ev.key)
            && slot.info.exit.is_some_and(|known| known.code.is_none())
        {
            Arc::make_mut(&mut slot.info).exit = Some(exit);
            slot.touched = touched;
        }
    }

    /// Fills the live record of `pid` from `/proc` (blocking I/O). Missing fields are
    /// filled, and fields a forked child inherited are replaced with the process's own
    /// values. Without a record, one is built from `/proc` alone. A zombie becomes a
    /// tombstone. An optional file that cannot be read (such as another user's
    /// `environ`) leaves its fields unset instead of failing.
    ///
    /// If the start time in `/proc` shows that the pid now belongs to a different
    /// process than the live record, the record is retired as exited and
    /// [`ProcError::Reused`] is returned. A second call then records the new process.
    pub fn enrich(&mut self, pid: Pid) -> Result<(), ProcError> {
        let stat = self.src.stat(pid)?;
        if self.retire_if_reused(pid, &stat) {
            return Err(ProcError::Reused(pid));
        }
        self.absorb(pid, &stat);
        Ok(())
    }

    /// Records every process in `/proc` (blocking I/O) and enriches the ones already
    /// known. Live records whose pid now belongs to another process are retired.
    /// Processes that vanish during the scan are skipped. Returns how many processes
    /// were recorded.
    pub fn snapshot_all(&mut self) -> Result<usize, ProcError> {
        let pids = self.src.list_pids()?;
        let mut recorded = 0;
        for pid in pids {
            let Ok(stat) = self.src.stat(pid) else {
                continue;
            };
            self.retire_if_reused(pid, &stat);
            self.absorb(pid, &stat);
            recorded += 1;
        }
        Ok(recorded)
    }

    /// The process and its ancestors, nearest first.
    ///
    /// Each step follows the fork-time parent. The parent is the record for `ppid`
    /// that started no later than the child, so an exited parent is found among the
    /// tombstones, and a process that reused the parent's pid is never mistaken for
    /// it. Processes the table does not know are loaded from `/proc` on the way
    /// (blocking I/O), including `pid` itself when it has no live record.
    pub fn ancestry(&mut self, pid: Pid, stop: Stop) -> Ancestry {
        let mut chain = Vec::new();
        let Some(mut current) = self.lookup(pid) else {
            return Ancestry {
                chain,
                complete: false,
            };
        };
        let complete = loop {
            let stop_here = match stop {
                Stop::Root => false,
                Stop::At(at) => current.key.pid == at,
                Stop::Depth(depth) => chain.len() >= usize::from(depth),
            };
            let parent = if stop_here {
                Parent::Root
            } else {
                self.parent_of(&current)
            };
            chain.push(current);
            match parent {
                Parent::Root => break true,
                Parent::Unknown => break false,
                Parent::Found(parent) => {
                    if chain.iter().any(|seen| seen.key == parent.key) {
                        break false;
                    }
                    current = parent;
                }
            }
        };
        Ancestry { chain, complete }
    }

    /// Where `pid` runs: cgroup, systemd unit, container and tmux pane, each taken
    /// from the process itself or its nearest ancestor that has one. Walks the
    /// ancestry, so this may do blocking I/O.
    pub fn context(&mut self, pid: Pid) -> Context {
        let chain = self.ancestry(pid, Stop::Root).chain;
        Context {
            cgroup: chain.iter().find_map(|info| info.cgroup.clone()),
            unit: chain
                .iter()
                .find_map(|info| info.cgroup.as_ref()?.unit.clone()),
            container: chain
                .iter()
                .find_map(|info| info.cgroup.as_ref()?.container.clone()),
            tmux: chain
                .iter()
                .find_map(|info| info.env.as_ref()?.tmux.clone()),
        }
    }

    /// The build step `pid` runs under ([`classify_origin`] over its full ancestry).
    /// Walks the ancestry, so this may do blocking I/O.
    pub fn origin(&mut self, pid: Pid) -> Option<Origin> {
        classify_origin(&self.ancestry(pid, Stop::Root).chain)
    }

    /// The cgroup with this id, from the table's cache or (with I/O) the source.
    pub fn resolve_cgroup(&mut self, id: u64) -> Option<Arc<CgroupInfo>> {
        self.cgroups.resolve(&self.src, id)
    }

    /// Drops tombstones whose exit is more than `tombstone_ttl_ns` before `now_ns`.
    /// Then, while more than `max_entries` records remain, evicts the least recently
    /// updated: tombstones first, then live records (`enrich` can reload those from
    /// `/proc`). Event handlers never evict, so call this periodically.
    pub fn expire(&mut self, now_ns: u64) {
        let ttl = self.cfg.tombstone_ttl_ns;
        self.dead.retain(|_, slot| {
            slot.info
                .exit
                .is_some_and(|exit| now_ns.saturating_sub(exit.ts_ns) <= ttl)
        });
        let excess = self.len().saturating_sub(self.cfg.max_entries);
        if excess > 0 {
            self.evict(excess);
        }
        self.names.prune();
        self.paths.prune();
        self.cgroups.prune();
    }

    fn evict(&mut self, count: usize) {
        let mut dead: Vec<(u64, ProcKey)> = self
            .dead
            .iter()
            .map(|(key, slot)| (slot.touched, *key))
            .collect();
        dead.sort_unstable();
        let from_dead = count.min(dead.len());
        for (_, key) in &dead[..from_dead] {
            self.dead.remove(key);
        }
        let from_live = count - from_dead;
        if from_live == 0 {
            return;
        }
        let mut live: Vec<(u64, Pid)> = self
            .live
            .iter()
            .map(|(pid, slot)| (slot.touched, *pid))
            .collect();
        live.sort_unstable();
        for (_, pid) in live.iter().take(from_live) {
            self.live.remove(pid);
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn observe(&mut self, ts_ns: u64) {
        self.last_ts_ns = self.last_ts_ns.max(ts_ns);
    }

    /// Whether `candidate` started no later than a process started at `start`, so it
    /// may be that process's parent. Compares in `/proc` ticks: keys read from
    /// `/proc` are rounded to a tick, and event keys may be finer.
    fn predates(&self, candidate: ProcKey, start: u64) -> bool {
        let clock = self.cfg.start_clock;
        clock.start_to_ticks(candidate.start) <= clock.start_to_ticks(start)
    }

    fn bury(&mut self, mut slot: Slot, exit: ExitInfo) {
        Arc::make_mut(&mut slot.info).exit = Some(exit);
        slot.touched = self.tick();
        self.dead.insert(slot.info.key, slot);
    }

    /// Moves the live record of `pid` to the tombstones. The process is gone, though
    /// no exit event said so.
    fn retire(&mut self, pid: Pid) {
        if let Some(slot) = self.live.remove(&pid) {
            let exit = ExitInfo {
                ts_ns: self.last_ts_ns,
                code: None,
            };
            self.bury(slot, exit);
        }
    }

    fn retire_if_reused(&mut self, pid: Pid, stat: &StatLine) -> bool {
        let clock = self.cfg.start_clock;
        let reused = self
            .live
            .get(&pid)
            .is_some_and(|slot| clock.start_to_ticks(slot.info.key.start) != stat.start_ticks);
        if reused {
            self.retire(pid);
        }
        reused
    }

    /// Merges `/proc` facts into the live record of `pid`, creating it if needed.
    /// The caller has already retired a record of a different process.
    fn absorb(&mut self, pid: Pid, stat: &StatLine) {
        let clock = self.cfg.start_clock;
        let known_dead = self
            .dead
            .range(pid_keys(pid))
            .any(|(key, _)| clock.start_to_ticks(key.start) == stat.start_ticks);
        if stat.has_exited() && known_dead {
            // A zombie whose exit is already recorded: /proc has nothing newer.
            return;
        }
        let key = ProcKey {
            pid,
            start: clock.ticks_to_start(stat.start_ticks),
        };
        let read = self.read_proc(pid, stat);
        let touched = self.tick();
        let slot = self
            .live
            .entry(pid)
            .or_insert_with(|| Slot::new(self.blank.info(key, Source::Procfs), touched));
        read.apply(slot, stat);
        slot.touched = touched;
        if stat.has_exited() {
            self.retire(pid);
        }
    }

    /// Reads the `/proc` files for what the live record of `pid` lacks, or holds only
    /// by inheritance from its parent. Without a record, it reads everything.
    fn read_proc(&mut self, pid: Pid, stat: &StatLine) -> ProcRead {
        let slot = self.live.get(&pid);
        let refresh = slot.is_some_and(|slot| slot.inherited);
        let lacks = |missing: fn(&ProcInfo) -> bool| slot.is_none_or(|slot| missing(&slot.info));
        let stale = |missing: fn(&ProcInfo) -> bool| refresh || lacks(missing);
        let (src, paths, blank) = (&self.src, &mut self.paths, &self.blank);
        let mut link = |which: ProcLink| Some(paths.intern(&src.readlink(pid, which).ok()?));
        let max_argv = self.cfg.max_argv_bytes;
        ProcRead {
            comm: stale(|info| info.comm.is_empty()).then(|| self.names.intern(&stat.comm)),
            exe: if lacks(|info| info.exe.is_none()) {
                link(ProcLink::Exe)
            } else {
                None
            },
            argv: if lacks(|info| info.argv.is_empty() && !info.argv_truncated) {
                let raw = src.read(pid, ProcFile::Cmdline).ok();
                raw.map(|raw| blank.argv(&raw, max_argv, false))
            } else {
                None
            },
            cwd: if stale(|info| info.cwd.is_none()) {
                link(ProcLink::Cwd)
            } else {
                None
            },
            ids: if stale(|info| info.uid.is_none() || info.gid.is_none()) {
                src.read(pid, ProcFile::Status)
                    .ok()
                    .map(|status| parse_status_ids(&status))
            } else {
                None
            },
            cgroup: if stale(|info| info.cgroup.is_none()) {
                // A pending id names the cgroup at exec; /proc names the current one.
                let pending = slot.and_then(|slot| slot.pending_cgroup);
                let cgroups = &mut self.cgroups;
                pending.and_then(|id| cgroups.resolve(src, id)).or_else(|| {
                    let raw = src.read(pid, ProcFile::Cgroup).ok()?;
                    let path = String::from_utf8_lossy(cgroup_v2_path(&raw)?);
                    Some(cgroups.by_path(&path))
                })
            } else {
                None
            },
            env: if self.cfg.read_environ && stale(|info| info.env.is_none()) {
                let raw = src.read(pid, ProcFile::Environ).ok();
                raw.map(|raw| blank.env(parse_env_facts(&raw)))
            } else {
                None
            },
        }
    }

    /// The record for `pid`, loading it from `/proc` when there is no live record:
    /// the pid may belong to a process the table never saw. If that fails, the newest
    /// tombstone is used.
    fn lookup(&mut self, pid: Pid) -> Option<Arc<ProcInfo>> {
        if !self.live.contains_key(&pid) {
            // Failure is expected for exited processes; the tombstone answers then.
            let _ = self.enrich(pid);
        }
        let key = self.get(pid)?.key;
        self.settle(key)
    }

    fn parent_of(&mut self, child: &ProcInfo) -> Parent {
        let known = child.ppid.or_else(|| {
            // Only /proc can tell, and only while this very process is alive.
            if child.is_alive() && self.enrich(child.key.pid).is_ok() {
                self.get_key(child.key)?.ppid
            } else {
                None
            }
        });
        let Some(ppid) = known else {
            return Parent::Unknown;
        };
        if ppid == 0 {
            return Parent::Root;
        }
        let start = child.key.start;
        let key = self.parent_key(ppid, start).or_else(|| {
            // Unknown to the table: load it, unless a live record shows that the pid
            // was already reused.
            if self.live.contains_key(&ppid) || self.enrich(ppid).is_err() {
                return None;
            }
            self.parent_key(ppid, start)
        });
        key.and_then(|key| self.settle(key))
            .map_or(Parent::Unknown, Parent::Found)
    }

    /// The record of `ppid` that existed when a child started at `child_start` forked.
    fn parent_key(&self, ppid: Pid, child_start: u64) -> Option<ProcKey> {
        if let Some(slot) = self.live.get(&ppid)
            && self.predates(slot.info.key, child_start)
        {
            return Some(slot.info.key);
        }
        self.dead
            .range(pid_keys(ppid))
            .rev()
            .map(|(key, _)| *key)
            .find(|key| self.predates(*key, child_start))
    }

    /// The current record for `key`, after resolving its pending cgroup id.
    fn settle(&mut self, key: ProcKey) -> Option<Arc<ProcInfo>> {
        let slot = slot_mut(&mut self.live, &mut self.dead, key)?;
        if let Some(id) = slot.pending_cgroup.take()
            && let Some(cgroup) = self.cgroups.resolve(&self.src, id)
        {
            Arc::make_mut(&mut slot.info).cgroup = Some(cgroup);
        }
        Some(Arc::clone(&slot.info))
    }
}
