//! Preflight and doctor checks for BPF tracing tools.
//!
//! A tool describes itself with a [`Tool`], builds a [`Doctor`] from the shared
//! checks plus its own [`Check`]s, and runs it against an [`Env`]: [`RealEnv`] in
//! production, `FixtureEnv` (feature `testing`) in tests. Every non-passing
//! [`Diagnostic`] states what was observed, what it breaks, and the exact command
//! that fixes it.
//!
//! ```no_run
//! use bpfdoctor::{Cap, Doctor, RealEnv, Tool};
//!
//! let tool = Tool {
//!     name: "whytime",
//!     exe: std::env::current_exe()?,
//!     required_caps: &[Cap::Bpf, Cap::Perfmon],
//!     optional_caps: &[(Cap::SysPtrace, "executable paths of other users' processes")],
//!     min_kernel: (5, 8),
//!     memlock_bytes: 64 << 20,
//! };
//! let report = Doctor::with_shared().run(&RealEnv, &tool);
//! report.render_human(&mut std::io::stdout(), false)?;
//! # Ok::<(), std::io::Error>(())
//! ```

mod cap;
mod checks;
mod doctor;
mod env;
mod errno;
#[cfg(feature = "testing")]
mod fixture;
mod model;
mod real;
mod release;
mod tool;

pub use cap::Cap;
pub use doctor::{Check, Doctor, Report};
pub use env::{BpfProbe, CapSets, Env, FileCaps, Ids, MountFlags, Uname};
pub use errno::{errno_name, ids_for_errno};
#[cfg(feature = "testing")]
pub use fixture::FixtureEnv;
pub use model::{Diagnostic, Fix, Status};
pub use real::RealEnv;
pub use release::parse_release;
pub use tool::Tool;
