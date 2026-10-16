//! The [`Env`] abstraction through which every check observes the system.

use std::io;
use std::path::Path;

/// Kernel identification from `uname(2)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Uname {
    /// Operating system name, e.g. `Linux`.
    pub sysname: String,
    /// Kernel release, e.g. `6.8.0-45-generic`.
    pub release: String,
    /// Hardware name, e.g. `x86_64`.
    pub machine: String,
}

/// Capability sets of the current process, as bitmasks indexed by [`Cap::bit`](crate::Cap::bit).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapSets {
    /// Capabilities in effect.
    pub effective: u64,
    /// Capabilities the process may make effective.
    pub permitted: u64,
    /// Upper bound for capabilities gained through `execve`.
    pub bounding: u64,
}

/// Mount flags of the filesystem holding a path, from `statvfs(3)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MountFlags {
    /// Mounted `nosuid`: set-user-ID bits and file capabilities are ignored.
    pub nosuid: bool,
    /// Mounted read-only.
    pub readonly: bool,
}

/// The `security.capability` attribute of an executable, as set by `setcap`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileCaps {
    /// Permitted capabilities, as a bitmask indexed by [`Cap::bit`](crate::Cap::bit).
    pub permitted: u64,
    /// The effective flag (`+e` in `setcap …+ep`): the permitted capabilities
    /// are raised to effective at `execve`. Without it (`+p`) they are only
    /// permitted, and a program that does not raise them itself runs without them.
    pub effective: bool,
}

/// Process credentials plus the invoking user when run via `sudo`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ids {
    /// Real user ID.
    pub uid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// `SUDO_UID` of the invoking user, if set.
    pub sudo_uid: Option<u32>,
    /// `SUDO_USER` of the invoking user, if set.
    pub sudo_user: Option<String>,
}

/// Kernel feature probes that need a real `bpf(2)` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BpfProbe {
    /// Create a `BPF_MAP_TYPE_RINGBUF` map.
    RingBuf,
    /// Load a program calling `bpf_ktime_get_coarse_ns`, which shipped in the
    /// same release (5.11) as memcg-based BPF memory accounting.
    MemcgAccounting,
}

/// Read-only view of the system; all checks observe it exclusively through this
/// trait so they can run against fixtures.
pub trait Env {
    /// Reads a whole file.
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Reads at most `len` bytes from the start of a file.
    ///
    /// The default reads the whole file; override it where files can be large.
    fn read_head(&self, path: &Path, len: usize) -> io::Result<Vec<u8>> {
        let mut data = self.read(path)?;
        data.truncate(len);
        Ok(data)
    }

    /// Whether a path exists.
    fn exists(&self, path: &Path) -> bool;

    /// Kernel identification.
    fn uname(&self) -> Uname;

    /// Capability sets of the current process.
    fn caps(&self) -> CapSets;

    /// The `security.capability` attribute on `path`, if any.
    fn file_caps(&self, path: &Path) -> Option<FileCaps>;

    /// Mount flags of the filesystem holding `path`, if they can be determined.
    fn mount_flags(&self, path: &Path) -> Option<MountFlags>;

    /// Whether `no_new_privs` is set on the current process.
    fn no_new_privs(&self) -> bool;

    /// Process credentials.
    fn ids(&self) -> Ids;

    /// `RLIMIT_MEMLOCK` as `(soft, hard)`; `u64::MAX` means unlimited.
    fn memlock(&self) -> (u64, u64);

    /// An environment variable of the current process.
    fn env_var(&self, key: &str) -> Option<String>;

    /// Runs a kernel feature probe; `Err` carries the errno.
    fn bpf_probe(&self, probe: BpfProbe) -> Result<(), i32>;
}

/// Decodes a `security.capability` attribute (`struct vfs_cap_data`, revisions
/// 1 to 3) into its permitted mask and effective flag.
pub(crate) fn decode_vfs_cap(raw: &[u8]) -> Option<FileCaps> {
    const REVISION_MASK: u32 = 0xFF00_0000;
    const REVISION_1: u32 = 0x0100_0000;
    const REVISION_2: u32 = 0x0200_0000;
    const REVISION_3: u32 = 0x0300_0000;
    const FLAGS_EFFECTIVE: u32 = 0x0000_0001;

    let word = |index: usize| {
        raw.get(index * 4..index * 4 + 4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_le_bytes)
    };
    let magic = word(0)?;
    let (low, high) = match (magic & REVISION_MASK, raw.len()) {
        (REVISION_1, 12) => (word(1)?, 0),
        (REVISION_2, 20) | (REVISION_3, 24) => (word(1)?, word(3)?),
        _ => return None,
    };
    Some(FileCaps {
        permitted: (u64::from(high) << 32) | u64::from(low),
        effective: magic & FLAGS_EFFECTIVE != 0,
    })
}

/// Value of `Key:` in a `/proc/<pid>/status` style file, trimmed.
pub(crate) fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
        .map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vfs_cap(magic: u32, words: &[u32]) -> Vec<u8> {
        std::iter::once(magic)
            .chain(words.iter().copied())
            .flat_map(u32::to_le_bytes)
            .collect()
    }

    /// `(permitted, effective)` of a decoded attribute.
    fn decode(raw: &[u8]) -> Option<(u64, bool)> {
        decode_vfs_cap(raw).map(|caps| (caps.permitted, caps.effective))
    }

    #[test]
    fn decodes_v2_and_v3_permitted_masks_across_both_words() {
        // cap_bpf (39) and cap_perfmon (38) live in the high word; effective flag set.
        let v2 = vfs_cap(0x0200_0001, &[1 << 21, 0, 0xC0, 0]);
        assert_eq!(decode(&v2), Some(((0xC0 << 32) | (1 << 21), true)));
        let v3 = vfs_cap(0x0300_0001, &[0, 0, 0xC0, 0, 1000]);
        assert_eq!(decode(&v3), Some((0xC0 << 32, true)));
    }

    #[test]
    fn decodes_missing_effective_flag() {
        // `setcap cap_bpf,cap_perfmon+p`: permitted only.
        let v2 = vfs_cap(0x0200_0000, &[0, 0, 0xC0, 0]);
        assert_eq!(decode(&v2), Some((0xC0 << 32, false)));
    }

    #[test]
    fn decodes_v1_low_word_only() {
        assert_eq!(
            decode(&vfs_cap(0x0100_0000, &[1 << 21, 0])),
            Some((1 << 21, false))
        );
    }

    #[test]
    fn rejects_unknown_revisions_and_truncated_data() {
        assert_eq!(decode_vfs_cap(&vfs_cap(0x0400_0000, &[1, 0, 0, 0])), None);
        assert_eq!(decode_vfs_cap(&vfs_cap(0x0200_0000, &[1, 0, 0])), None);
        assert_eq!(decode_vfs_cap(&vfs_cap(0x0300_0000, &[1, 0, 0, 0])), None);
        assert_eq!(decode_vfs_cap(&[]), None);
    }

    #[test]
    fn status_field_matches_whole_key_only() {
        let status = "Seccomp:\t2\nSeccomp_filters:\t1\nNSpid:\t42\t1\n";
        assert_eq!(status_field(status, "Seccomp"), Some("2"));
        assert_eq!(status_field(status, "Seccomp_filters"), Some("1"));
        assert_eq!(status_field(status, "NSpid"), Some("42\t1"));
        assert_eq!(status_field(status, "NSpgid"), None);
    }
}
