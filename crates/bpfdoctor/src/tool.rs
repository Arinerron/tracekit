//! Identity of the tool being diagnosed.

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
    /// `sudo setcap <required caps + extra>+ep <target>`, with `target` shell-quoted.
    pub fn setcap_command(&self, extra: &[Cap], target: &Path) -> String {
        let mut caps = self.required_caps.to_vec();
        for &cap in extra {
            if !caps.contains(&cap) {
                caps.push(cap);
            }
        }
        format!(
            "sudo setcap {}+ep {}",
            setcap_list(&caps),
            shell_quote(target)
        )
    }
}

/// Quotes `path` for POSIX shells unless it consists only of safe characters.
pub(crate) fn shell_quote(path: &Path) -> String {
    let text = path.to_string_lossy();
    let safe = |b: u8| b.is_ascii_alphanumeric() || b"/._-+:,@%=".contains(&b);
    if !text.is_empty() && text.bytes().all(safe) {
        text.into_owned()
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
