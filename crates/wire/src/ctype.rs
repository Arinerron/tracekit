//! C type descriptions used for header generation.

use crate::Pod;

/// C spelling of a wire type.
///
/// Implemented for the fixed-width integers (`__u8` … `__s64`) and by [`wire!`](crate::wire!) for
/// each struct, whose name is the snake case of the Rust name (`EvHeader` → `ev_header`). Arrays
/// have no standalone name; their dimensions are part of each field's [`FieldDesc`].
pub trait CType {
    /// C type name, without the `struct` keyword for structs.
    const C_NAME: &'static str;
}

/// Layout and C spelling of one field of a [`WireStruct`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDesc {
    /// Rust field name, as written (raw identifiers keep their `r#` prefix).
    pub name: &'static str,
    /// C type of the field, or of its innermost element for arrays: `__u32`, `struct ev_header`.
    pub c_type: &'static str,
    /// Array dimensions, outermost first; empty for scalars. `[[u8; 20]; 8]` is `[8, 20]`.
    pub dims: &'static [usize],
    /// Byte offset of the field in the Rust struct.
    pub offset: usize,
}

/// A `#[repr(C)]`, padding-free struct declared with [`wire!`](crate::wire!).
pub trait WireStruct: Pod + CType {
    /// Fields in declaration order.
    const FIELDS: &'static [FieldDesc];
    /// `size_of::<Self>()`.
    const SIZE: usize;
    /// `align_of::<Self>()`.
    const ALIGN: usize;
}
