//! [`Doctor`] runs checks; [`Report`] collects and renders their results.

use std::fmt;
use std::io;

use serde::Serialize;

use crate::checks::{PREFLIGHT_IDS, SHARED};
use crate::{Diagnostic, Env, Status, Tool, Uname};

/// One diagnosis step. Implement it for tool-specific checks.
pub trait Check {
    /// Stable dotted identifier, e.g. `priv.capabilities`; must equal the
    /// [`Diagnostic::id`] that [`run`](Check::run) returns.
    fn id(&self) -> &'static str;

    /// Evaluates the check; all system access goes through `env`.
    fn run(&self, env: &dyn Env, tool: &Tool) -> Diagnostic;
}

/// An ordered set of checks.
#[derive(Default)]
pub struct Doctor {
    checks: Vec<Box<dyn Check>>,
}

impl Doctor {
    /// An empty doctor.
    pub fn new() -> Self {
        Self::default()
    }

    /// All shared checks, in display order.
    pub fn with_shared() -> Self {
        Self::from_shared(|_| true)
    }

    /// The fast subset run before every start: `platform.os_arch`,
    /// `kernel.version`, `kernel.btf`, `priv.capabilities`, `priv.nosuid`,
    /// `priv.nnp`, `sec.lockdown`, `env.userns` and `env.pidns`.
    pub fn preflight() -> Self {
        Self::from_shared(|id| PREFLIGHT_IDS.contains(&id))
    }

    fn from_shared(keep: impl Fn(&str) -> bool) -> Self {
        let checks = SHARED
            .iter()
            .filter(|check| keep(check.id()))
            .map(|&check| Box::new(check) as Box<dyn Check>)
            .collect();
        Self { checks }
    }

    /// Registers a check. A check with the same id is replaced in place, so a
    /// tool can override a shared check without changing the display order.
    pub fn add(&mut self, check: Box<dyn Check>) -> &mut Self {
        match self
            .checks
            .iter_mut()
            .find(|existing| existing.id() == check.id())
        {
            Some(existing) => *existing = check,
            None => self.checks.push(check),
        }
        self
    }

    /// Ids of the registered checks, in display order.
    pub fn check_ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.checks.iter().map(|check| check.id())
    }

    /// Runs every registered check.
    pub fn run(&self, env: &dyn Env, tool: &Tool) -> Report {
        self.run_matching(env, tool, |_| true)
    }

    /// Runs the registered checks whose id is in `ids`, in display order; e.g.
    /// with [`ids_for_errno`](crate::ids_for_errno) after a load or attach failure.
    pub fn run_ids(&self, env: &dyn Env, tool: &Tool, ids: &[&str]) -> Report {
        self.run_matching(env, tool, |id| ids.contains(&id))
    }

    fn run_matching(&self, env: &dyn Env, tool: &Tool, keep: impl Fn(&str) -> bool) -> Report {
        let checks = self
            .checks
            .iter()
            .filter(|check| keep(check.id()))
            .map(|check| check.run(env, tool))
            .collect();
        Report::new(tool.name, env.uname(), checks)
    }
}

impl fmt::Debug for Doctor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Doctor")
            .field("checks", &self.check_ids().collect::<Vec<_>>())
            .finish()
    }
}

/// Results of a doctor run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    /// JSON schema identifier, [`Report::SCHEMA`].
    pub schema: &'static str,
    /// Tool name.
    pub tool: &'static str,
    /// Kernel release.
    pub kernel: String,
    /// Machine architecture.
    pub arch: String,
    /// [`Status::Fail`] if a required check failed, [`Status::Warn`] if any check
    /// warned or an optional one failed, otherwise [`Status::Pass`].
    pub verdict: Status,
    /// Results in display order.
    pub checks: Vec<Diagnostic>,
}

const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

impl Report {
    /// Version of the JSON layout.
    pub const SCHEMA: &'static str = "bpfdoctor/1";

    /// Builds a report and computes its verdict.
    pub fn new(tool: &'static str, uname: Uname, checks: Vec<Diagnostic>) -> Self {
        let verdict = checks
            .iter()
            .map(|check| match check.status {
                Status::Pass | Status::Info | Status::Skip => Status::Pass,
                Status::Fail if check.required => Status::Fail,
                Status::Warn | Status::Fail => Status::Warn,
            })
            .max()
            .unwrap_or(Status::Pass);
        Self {
            schema: Self::SCHEMA,
            tool,
            kernel: uname.release,
            arch: uname.machine,
            verdict,
            checks,
        }
    }

    /// Whether a required check failed, i.e. the tool cannot run.
    pub fn has_fail(&self) -> bool {
        self.verdict == Status::Fail
    }

    /// Writes the aligned, human-readable report; `color` adds ANSI colours.
    pub fn render_human(&self, w: &mut dyn io::Write, color: bool) -> io::Result<()> {
        writeln!(
            w,
            "{} doctor · kernel {} {}",
            self.tool, self.kernel, self.arch
        )?;
        let width = self
            .checks
            .iter()
            .map(|check| check.id.len())
            .max()
            .unwrap_or(0);
        for check in &self.checks {
            let tag = check.status.tag();
            if color {
                let style = match check.status {
                    Status::Fail => RED,
                    Status::Warn => YELLOW,
                    Status::Pass => GREEN,
                    Status::Info | Status::Skip => DIM,
                };
                write!(w, " {style}{tag}{RESET}")?;
            } else {
                write!(w, " {tag}")?;
            }
            writeln!(w, " {:<width$}  {}", check.id, check.observed)?;
            if let Some(impact) = &check.impact {
                writeln!(w, "      impact: {impact}")?;
            }
            for (index, fix) in check.fixes.iter().enumerate() {
                let label = if index == 0 { "fix:" } else { "or:" };
                write!(w, "      {label:<8}{}", fix.cmd)?;
                // A shell comment keeps the line copy-pasteable.
                if !fix.note.is_empty() {
                    write!(w, "  # {}", fix.note)?;
                }
                writeln!(w)?;
            }
            if let Some(explain) = &check.explain {
                writeln!(w, "      why:    {explain}")?;
            }
        }
        self.render_summary(w)
    }

    fn render_summary(&self, w: &mut dyn io::Write) -> io::Result<()> {
        let count = |status: Status| {
            self.checks
                .iter()
                .filter(|check| check.status == status)
                .count()
        };
        write!(
            w,
            "summary: {} fail · {} warn · {} pass",
            count(Status::Fail),
            count(Status::Warn),
            count(Status::Pass)
        )?;
        for (status, label) in [(Status::Info, "info"), (Status::Skip, "skip")] {
            let n = count(status);
            if n > 0 {
                write!(w, " · {n} {label}")?;
            }
        }
        let outcome = match self.verdict {
            Status::Fail => "will not run",
            Status::Warn => "will run with reduced functionality",
            Status::Pass | Status::Info | Status::Skip => "is ready",
        };
        writeln!(w, " → {} {outcome}", self.tool)
    }

    /// Writes the report as pretty-printed JSON followed by a newline.
    pub fn render_json(&self, w: &mut dyn io::Write) -> io::Result<()> {
        serde_json::to_writer_pretty(&mut *w, self)?;
        writeln!(w)
    }
}
