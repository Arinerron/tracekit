//! [`RealEnv`]: the running system, observed through `/proc` and libc.

use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::env::{BpfProbe, CapSets, Env, Ids, MountFlags, Uname, decode_vfs_cap, status_field};

/// The running system.
#[derive(Clone, Copy, Debug, Default)]
pub struct RealEnv;

impl RealEnv {
    fn status() -> Option<String> {
        fs::read_to_string("/proc/self/status").ok()
    }
}

impl Env for RealEnv {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    fn read_head(&self, path: &Path, len: usize) -> io::Result<Vec<u8>> {
        let mut data = Vec::with_capacity(len);
        File::open(path)?
            .take(u64::try_from(len).unwrap_or(u64::MAX))
            .read_to_end(&mut data)?;
        Ok(data)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn uname(&self) -> Uname {
        let mut raw = MaybeUninit::<libc::utsname>::zeroed();
        // SAFETY: `raw` points to writable memory for one `utsname`.
        if unsafe { libc::uname(raw.as_mut_ptr()) } != 0 {
            return Uname::default();
        }
        // SAFETY: `uname` succeeded and filled the struct.
        let raw = unsafe { raw.assume_init() };
        Uname {
            sysname: utsname_field(&raw.sysname),
            release: utsname_field(&raw.release),
            machine: utsname_field(&raw.machine),
        }
    }

    fn caps(&self) -> CapSets {
        let Some(status) = Self::status() else {
            return CapSets::default();
        };
        let mask = |key: &str| {
            status_field(&status, key)
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                .unwrap_or(0)
        };
        CapSets {
            effective: mask("CapEff"),
            permitted: mask("CapPrm"),
            bounding: mask("CapBnd"),
        }
    }

    fn file_caps(&self, path: &Path) -> Option<u64> {
        let path = CString::new(path.as_os_str().as_bytes()).ok()?;
        // Large enough for `vfs_ns_cap_data`, the biggest revision.
        let mut buf = [0u8; 24];
        // SAFETY: both names are NUL-terminated and `buf` is writable for `buf.len()` bytes.
        let len = unsafe {
            libc::getxattr(
                path.as_ptr(),
                c"security.capability".as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        decode_vfs_cap(buf.get(..usize::try_from(len).ok()?)?)
    }

    fn mount_flags(&self, path: &Path) -> Option<MountFlags> {
        let path = CString::new(path.as_os_str().as_bytes()).ok()?;
        let mut stat = MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `path` is NUL-terminated and `stat` is writable for one `statvfs`.
        if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: `statvfs` succeeded and filled the struct.
        let flags = unsafe { stat.assume_init() }.f_flag;
        Some(MountFlags {
            nosuid: flags & libc::ST_NOSUID != 0,
            readonly: flags & libc::ST_RDONLY != 0,
        })
    }

    fn no_new_privs(&self) -> bool {
        Self::status().is_some_and(|status| status_field(&status, "NoNewPrivs") == Some("1"))
    }

    fn ids(&self) -> Ids {
        // SAFETY (all four calls): the credential getters have no preconditions and cannot fail.
        Ids {
            uid: unsafe { libc::getuid() },
            euid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getgid() },
            egid: unsafe { libc::getegid() },
            sudo_uid: self.env_var("SUDO_UID").and_then(|uid| uid.parse().ok()),
            sudo_user: self.env_var("SUDO_USER"),
        }
    }

    fn memlock(&self) -> (u64, u64) {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid, writable `rlimit`.
        if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut limit) } != 0 {
            return (0, 0);
        }
        // `RLIM_INFINITY` is `u64::MAX` on Linux.
        (limit.rlim_cur, limit.rlim_max)
    }

    fn env_var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn bpf_probe(&self, probe: BpfProbe) -> Result<(), i32> {
        match probe {
            BpfProbe::RingBuf => probe_ringbuf(),
            BpfProbe::MemcgAccounting => probe_memcg_accounting(),
        }
    }
}

/// Copies a NUL-terminated `utsname` field.
fn utsname_field(field: &[libc::c_char]) -> String {
    // SAFETY: the struct was zero-initialised and the kernel NUL-terminates every
    // field within its bounds, so the scan stays inside `field`.
    unsafe { CStr::from_ptr(field.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

const BPF_MAP_CREATE: libc::c_int = 0;
const BPF_PROG_LOAD: libc::c_int = 5;
const BPF_MAP_TYPE_RINGBUF: u32 = 27;
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
const BPF_FUNC_KTIME_GET_COARSE_NS: i32 = 160;

/// Leading fields of `union bpf_attr` for `BPF_MAP_CREATE`.
#[repr(C)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
}

/// Leading fields of `union bpf_attr` for `BPF_PROG_LOAD`.
#[repr(C)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
}

/// `struct bpf_insn`; `regs` packs `dst_reg` (low nibble) and `src_reg` (high nibble).
#[repr(C)]
struct Insn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

/// Creates and closes the smallest ring buffer the kernel accepts (one page).
fn probe_ringbuf() -> Result<(), i32> {
    // SAFETY: `sysconf` has no preconditions.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let attr = MapCreateAttr {
        map_type: BPF_MAP_TYPE_RINGBUF,
        key_size: 0,
        value_size: 0,
        max_entries: u32::try_from(page).unwrap_or(4096).max(4096),
    };
    sys_bpf(BPF_MAP_CREATE, &attr).map(drop)
}

/// Mirrors libbpf's `probe_memcg_account`: a socket filter calling
/// `bpf_ktime_get_coarse_ns` loads only on kernels with memcg accounting.
fn probe_memcg_accounting() -> Result<(), i32> {
    let insns = [
        // call bpf_ktime_get_coarse_ns
        Insn {
            code: 0x85,
            regs: 0,
            off: 0,
            imm: BPF_FUNC_KTIME_GET_COARSE_NS,
        },
        // r0 = 0
        Insn {
            code: 0xb7,
            regs: 0,
            off: 0,
            imm: 0,
        },
        // exit
        Insn {
            code: 0x95,
            regs: 0,
            off: 0,
            imm: 0,
        },
    ];
    let attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
        insn_cnt: u32::try_from(insns.len()).map_err(|_| libc::E2BIG)?,
        insns: insns.as_ptr().expose_provenance() as u64,
        license: c"GPL".as_ptr().expose_provenance() as u64,
    };
    sys_bpf(BPF_PROG_LOAD, &attr).map(drop)
}

/// Calls `bpf(cmd, attr, size_of::<T>())`, returning the new fd or the errno.
fn sys_bpf<T>(cmd: libc::c_int, attr: &T) -> Result<OwnedFd, i32> {
    // SAFETY: `attr` is a live `#[repr(C)]` prefix of `union bpf_attr` spanning
    // `size_of::<T>()` bytes; the kernel zero-fills the rest. Any pointers inside
    // it reference locals that outlive the call.
    let ret =
        unsafe { libc::syscall(libc::SYS_bpf, cmd, std::ptr::from_ref(attr), size_of::<T>()) };
    if ret < 0 {
        return Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    let fd = libc::c_int::try_from(ret).map_err(|_| libc::EBADF)?;
    // SAFETY: on success `BPF_MAP_CREATE` and `BPF_PROG_LOAD` return a new fd that
    // nothing else owns; `OwnedFd` closes it on drop.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
