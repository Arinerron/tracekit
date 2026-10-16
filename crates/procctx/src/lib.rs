//! Process context for eBPF tools: who ran a process, where it runs, and which build
//! step started it.
//!
//! A [`ProcTable`] tracks process lifetimes from fork/exec/comm/exit events and uses
//! `/proc` ([`ProcFs`]) for processes that predate the tracer or whose events were
//! lost. From it, tools get:
//! - [`ancestry`](ProcTable::ancestry): the parent chain, including parents that
//!   have already exited;
//! - [`context`](ProcTable::context): cgroup, systemd unit, container and tmux pane;
//! - [`origin`](ProcTable::origin): the npm/pnpm/yarn/bun lifecycle script, Cargo
//!   build script, pip build or `make` recipe the process runs under.
//!
//! A process is identified by its [`ProcKey`] (pid plus start time), so a reused pid
//! never mixes up two processes' lineage.
//!
//! Linux only. The crate has no dependencies beyond std and contains no `unsafe`.

#![forbid(unsafe_code)]

mod cgroup;
mod env;
mod error;
mod event;
mod info;
mod intern;
mod origin;
mod source;
mod table;
#[cfg(feature = "testing")]
pub mod testing;

pub use cgroup::{
    CgroupInfo, Container, Manager, Runtime, SystemdUnit, parse_container, parse_unit,
};
pub use env::{ENV_KEYS, EnvFacts, LifecycleEnv, TmuxPane, parse_env_facts};
pub use error::ProcError;
pub use event::{ExecEvent, ExitEvent, ForkEvent};
pub use info::{ExitInfo, Pid, ProcInfo, ProcKey, Source, StartClock};
pub use origin::{Confidence, Origin, OriginKind, classify_origin};
pub use source::{ProcFile, ProcFs, ProcLink, ProcSource, StatLine};
pub use table::{Ancestry, Config, Context, ProcTable, Stop};
