//! Plain-old-data marker and byte conversions.

use core::{mem, ptr, slice};

/// Marker for plain-old-data wire types.
///
/// Implemented for the fixed-width integers, arrays of `Pod` types, and every struct declared with
/// [`wire!`](crate::wire!).
///
/// # Safety
///
/// Implementors must be `#[repr(C)]` (or primitive) with no padding bytes, so no byte is left
/// uninitialised when the kernel side fills a value, and every bit pattern must be a valid value.
pub unsafe trait Pod: Copy + 'static {}

// SAFETY: fixed-width integers have no padding and accept every bit pattern.
unsafe impl Pod for u8 {}
// SAFETY: as above.
unsafe impl Pod for u16 {}
// SAFETY: as above.
unsafe impl Pod for u32 {}
// SAFETY: as above.
unsafe impl Pod for u64 {}
// SAFETY: as above.
unsafe impl Pod for i8 {}
// SAFETY: as above.
unsafe impl Pod for i16 {}
// SAFETY: as above.
unsafe impl Pod for i32 {}
// SAFETY: as above.
unsafe impl Pod for i64 {}
// SAFETY: arrays are laid out contiguously without padding between elements.
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}

/// Zero-copy view of a `T` at the start of `bytes`.
///
/// Returns `None` if `bytes` is shorter than `T` or not aligned for `T`; use [`read`] for
/// unaligned input. Trailing bytes are ignored.
pub fn from_bytes<T: Pod>(bytes: &[u8]) -> Option<&T> {
    let ptr = bytes.as_ptr().cast::<T>();
    if bytes.len() < mem::size_of::<T>() || !ptr.is_aligned() {
        return None;
    }
    // SAFETY: the pointer is aligned and in bounds for `size_of::<T>()` bytes borrowed for the
    // returned lifetime, and `T: Pod` accepts any bit pattern.
    Some(unsafe { &*ptr })
}

/// Copies a `T` out of the start of `bytes`, tolerating any alignment.
///
/// Returns `None` if `bytes` is shorter than `T`. Trailing bytes are ignored.
pub fn read<T: Pod>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < mem::size_of::<T>() {
        return None;
    }
    // SAFETY: `size_of::<T>()` bytes are readable, `read_unaligned` imposes no alignment
    // requirement, and `T: Pod` accepts any bit pattern.
    Some(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

/// Views a `Pod` value as its raw bytes.
pub fn as_bytes<T: Pod>(v: &T) -> &[u8] {
    // SAFETY: `T: Pod` has no padding, so all `size_of::<T>()` bytes are initialised, and `u8`
    // has no alignment requirement.
    unsafe { slice::from_raw_parts(ptr::from_ref(v).cast::<u8>(), mem::size_of::<T>()) }
}
