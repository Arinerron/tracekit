//! Single-sourced kernel/user ABI types for eBPF tools.
//!
//! Event and map layouts shared between BPF C programs and their Rust loaders are declared once,
//! in Rust, with [`wire!`] and [`wire_consts!`]. Each declaration yields:
//!
//! - a `#[repr(C)]` Rust struct, statically checked to contain no implicit padding;
//! - a [`Pod`] impl for zero-copy decoding of ring buffer and map data ([`from_bytes`], [`read`],
//!   [`as_bytes`]);
//! - layout metadata ([`WireStruct`]) from which a build script renders the matching C header
//!   with `HeaderBuilder` (feature `std`).
//!
//! The header carries a `_Static_assert` for every struct size, alignment and field offset, so
//! any drift between the Rust and C views is a clang compile error. It also defines
//! `<GUARD>_ABI_HASH`, an [`fnv1a64`] digest of the declarations, which the BPF object can embed
//! so the loader detects stale objects at load time.
//!
//! # Example
//!
//! ```
//! wire::wire! {
//!     /// Common prefix of every event.
//!     pub struct EvHeader {
//!         pub kind: u32,
//!         pub pid: u32,
//!         pub ts_ns: u64,
//!     }
//!
//!     /// A process exec.
//!     pub struct ExecEvent {
//!         pub hdr: EvHeader,
//!         pub comm: [u8; 16],
//!     }
//! }
//!
//! wire::wire_consts! {
//!     /// Constants shared with the BPF program.
//!     pub group ABI_CONSTS;
//!     /// Event kind of [`ExecEvent`].
//!     pub const EV_EXEC: u32 = 1;
//! }
//!
//! // build.rs, with the `std` feature:
//! let header = wire::HeaderBuilder::new("WHYTIME_WIRE_H")
//!     .structs::<EvHeader>()
//!     .structs::<ExecEvent>()
//!     .consts(&ABI_CONSTS)
//!     .finish();
//! assert!(header.contains("struct exec_event {\n\tstruct ev_header hdr;\n\t__u8 comm[16];\n};"));
//! assert!(header.contains("#define EV_EXEC 1U"));
//!
//! // Loader: decode a ring buffer record.
//! let bytes = [0_u8; 32];
//! let event: ExecEvent = wire::read(&bytes).unwrap();
//! assert_eq!(event.hdr.kind, 0);
//! ```
//!
//! # Features
//!
//! - `std`: enables `HeaderBuilder` (requires `alloc`). Off by default so runtime users stay
//!   `no_std`-clean; build scripts enable it through `[build-dependencies]`.
//!
//! Loaders that hand wire types to aya maps declare the aya marker trait with [`impl_aya_pod!`].

#![no_std]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate alloc;

mod consts;
mod ctype;
#[cfg(feature = "std")]
mod header;
mod macros;
mod pod;
mod private;

pub use consts::{ConstDesc, ConstGroup, ConstValue};
pub use ctype::{CType, FieldDesc, WireStruct};
#[cfg(feature = "std")]
pub use header::HeaderBuilder;
pub use pod::{Pod, as_bytes, from_bytes, read};

/// Implementation details of the exported macros. Not public API.
#[doc(hidden)]
pub mod __private {
    pub use crate::private::{
        CName, Dims, FieldFmt, WireField, c_name_capacity, const_value, require_pod,
    };
}

/// 64-bit FNV-1a hash of `bytes`.
///
/// Used for the header's ABI hash; `const` so loaders can also hash at compile time.
pub const fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET_BASIS;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(PRIME);
        i += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::fnv1a64;

    #[test]
    fn fnv1a64_matches_reference_vectors() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }
}
