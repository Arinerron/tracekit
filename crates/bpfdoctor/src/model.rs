//! Check results: [`Status`], [`Fix`] and [`Diagnostic`].

use serde::Serialize;

/// Outcome of a single check, ordered from best to worst.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The requirement is met.
    Pass,
    /// Informational; nothing to do.
    Info,
    /// The check did not apply or could not be evaluated.
    Skip,
    /// The tool runs, with reduced detail or performance.
    Warn,
    /// The requirement is not met.
    Fail,
}

impl Status {
    /// Four-letter upper-case tag used in human output, e.g. `PASS`.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Info => "INFO",
            Self::Skip => "SKIP",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

/// One way to resolve a finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Fix {
    /// Copy-pasteable shell command, or a short instruction when no single command applies.
    pub cmd: String,
    /// Caveat shown next to the command; empty when there is none.
    pub note: String,
}

impl Fix {
    /// Creates a fix from a command and its caveat (empty for none).
    pub fn new(cmd: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            cmd: cmd.into(),
            note: note.into(),
        }
    }
}

/// Result of running one [`Check`](crate::Check).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    /// Stable dotted identifier, e.g. `priv.capabilities`.
    pub id: &'static str,
    /// Short human title.
    pub title: &'static str,
    /// Outcome.
    pub status: Status,
    /// Whether the tool cannot run when this check fails; optional failures only warn.
    pub required: bool,
    /// What was found, in one line.
    pub observed: String,
    /// What the finding breaks.
    pub impact: Option<String>,
    /// Ways to resolve the finding, best first.
    pub fixes: Vec<Fix>,
    /// Why the requirement exists.
    pub explain: Option<String>,
}

impl Diagnostic {
    /// Creates a diagnostic without impact, fixes or explanation.
    pub fn new(
        id: &'static str,
        title: &'static str,
        required: bool,
        status: Status,
        observed: impl Into<String>,
    ) -> Self {
        Self {
            id,
            title,
            status,
            required,
            observed: observed.into(),
            impact: None,
            fixes: Vec::new(),
            explain: None,
        }
    }

    /// Sets what the finding breaks.
    #[must_use]
    pub fn with_impact(mut self, impact: impl Into<String>) -> Self {
        self.impact = Some(impact.into());
        self
    }

    /// Appends a fix; the first one is rendered as `fix:`, later ones as `or:`.
    #[must_use]
    pub fn with_fix(mut self, fix: Fix) -> Self {
        self.fixes.push(fix);
        self
    }

    /// Sets why the requirement exists.
    #[must_use]
    pub fn with_explain(mut self, explain: impl Into<String>) -> Self {
        self.explain = Some(explain.into());
        self
    }
}
