use std::{error::Error, fmt, io};

use crate::Pid;

/// `ESRCH` on every Linux architecture; std has no portable [`io::ErrorKind`] for it.
const ESRCH: i32 = 3;

/// Failure reading or reconciling process state.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProcError {
    /// The process does not exist (`ENOENT`/`ESRCH`): it exited, or never existed.
    NotFound(Pid),
    /// The caller may not read this process's files (`EACCES`/`EPERM`).
    Permission(Pid),
    /// The pid now belongs to a different process than the one the table recorded.
    Reused(Pid),
    /// A procfs file had an unexpected format.
    Parse {
        /// Process whose file was malformed.
        pid: Pid,
        /// Which file or field failed to parse.
        what: &'static str,
    },
    /// Any other I/O failure.
    Io(io::Error),
}

impl ProcError {
    /// Classifies an I/O error from a per-process file of `pid`.
    pub(crate) fn from_io(pid: Pid, err: io::Error) -> Self {
        if err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(ESRCH) {
            Self::NotFound(pid)
        } else if err.kind() == io::ErrorKind::PermissionDenied {
            Self::Permission(pid)
        } else {
            Self::Io(err)
        }
    }
}

impl fmt::Display for ProcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(pid) => write!(f, "process {pid} not found"),
            Self::Permission(pid) => write!(f, "permission denied reading process {pid}"),
            Self::Reused(pid) => write!(f, "pid {pid} now belongs to a different process"),
            Self::Parse { pid, what } => write!(f, "malformed {what} for process {pid}"),
            Self::Io(err) => write!(f, "procfs I/O error: {err}"),
        }
    }
}

impl Error for ProcError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::ProcError;

    #[test]
    fn errno_classification() {
        let enoent = io::Error::from_raw_os_error(2);
        let esrch = io::Error::from_raw_os_error(3);
        let eacces = io::Error::from_raw_os_error(13);
        let eperm = io::Error::from_raw_os_error(1);
        let eio = io::Error::from_raw_os_error(5);
        assert!(matches!(
            ProcError::from_io(7, enoent),
            ProcError::NotFound(7)
        ));
        assert!(matches!(
            ProcError::from_io(7, esrch),
            ProcError::NotFound(7)
        ));
        assert!(matches!(
            ProcError::from_io(7, eacces),
            ProcError::Permission(7)
        ));
        assert!(matches!(
            ProcError::from_io(7, eperm),
            ProcError::Permission(7)
        ));
        assert!(matches!(ProcError::from_io(7, eio), ProcError::Io(_)));
    }
}
