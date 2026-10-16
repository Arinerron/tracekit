//! Identity of the tool being diagnosed.

use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::Cap;
use crate::cap::setcap_list;

/// The tool being diagnosed; used to evaluate checks and to render exact fix commands.
#[derive(Clone, Debug)]
pub struct Tool {
    /// Command name, e.g. `whytime`.
    pub name: &'static str,
    /// Resolved path of the running executable (`/proc/self/exe`); the `setcap` target.
    pub exe: PathBuf,
    /// Capabilities the tool cannot run without.
    pub required_caps: &'static [Cap],
    /// Capabilities that add detail, each with a noun phrase describing what it enables.
    pub optional_caps: &'static [(Cap, &'static str)],
    /// Oldest supported kernel as `(major, minor)`; never below 5.8.
    pub min_kernel: (u32, u32),
    /// Planned BPF map and program memory in bytes, checked against the
    /// `RLIMIT_MEMLOCK` hard limit on kernels before 5.11. The tool is expected
    /// to raise its soft limit to the hard limit before loading.
    pub memlock_bytes: u64,
}

impl Tool {
    /// `sudo setcap <required caps + extra>+ep <target>`, with `target` shell-quoted:
    /// in single quotes, or in bash/zsh `$'…'` with `\xNN` escapes if it is not UTF-8.
    pub fn setcap_command(&self, extra: &[Cap], target: &Path) -> String {
        format!(
            "sudo setcap {}+ep {}",
            setcap_list(&self.caps_with(extra)),
            shell_quote(target)
        )
    }

    /// The required capabilities followed by those in `extra` not already required.
    pub(crate) fn caps_with(&self, extra: &[Cap]) -> Vec<Cap> {
        let mut caps = self.required_caps.to_vec();
        for &cap in extra {
            if !caps.contains(&cap) {
                caps.push(cap);
            }
        }
        caps
    }
}

/// Bytes that never need quoting in a shell word.
fn shell_safe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"/._-+:,@%=".contains(&byte)
}

/// Quotes `path` for the shell unless it consists only of safe characters.
///
/// UTF-8 paths are single-quoted, which every POSIX shell accepts. Other paths
/// are written in bash/zsh ANSI-C quoting, `$'…'`, with each unsafe byte as a
/// `\xNN` escape, so the command still names the exact file.
pub(crate) fn shell_quote(path: &Path) -> String {
    let Some(text) = path.to_str() else {
        let mut quoted = String::from("$'");
        for &byte in path.as_os_str().as_bytes() {
            if shell_safe(byte) {
                quoted.push(char::from(byte));
            } else {
                // Writing to a `String` cannot fail.
                let _ = write!(quoted, "\\x{byte:02x}");
            }
        }
        quoted.push('\'');
        return quoted;
    };
    if !text.is_empty() && text.bytes().all(shell_safe) {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool() -> Tool {
        Tool {
            name: "whytime",
            exe: PathBuf::from("/usr/local/bin/whytime"),
            required_caps: &[Cap::Bpf, Cap::Perfmon],
            optional_caps: &[],
            min_kernel: (5, 8),
            memlock_bytes: 0,
        }
    }

    #[test]
    fn setcap_appends_extra_caps_without_duplicates() {
        let cmd = tool().setcap_command(&[Cap::Perfmon, Cap::SysResource], Path::new("/opt/w"));
        assert_eq!(
            cmd,
            "sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep /opt/w"
        );
    }

    #[test]
    fn quotes_paths_with_shell_metacharacters() {
        assert_eq!(shell_quote(Path::new("/usr/bin/x")), "/usr/bin/x");
        assert_eq!(shell_quote(Path::new("/home/a b/x")), "'/home/a b/x'");
        assert_eq!(shell_quote(Path::new("/tmp/it's")), r"'/tmp/it'\''s'");
        assert_eq!(shell_quote(Path::new("")), "''");
    }
}
