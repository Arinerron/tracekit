//! Support items for the exported macros, re-exported as `__private`. Not public API.

use core::fmt;

use crate::{CType, Pod};

/// Deepest array nesting supported in a wire field.
const MAX_DIMS: usize = 8;

/// Array dimensions of a field type, outermost first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dims {
    buf: [usize; MAX_DIMS],
    len: usize,
}

impl Dims {
    /// Dimensions of a non-array type.
    pub const SCALAR: Self = Self {
        buf: [0; MAX_DIMS],
        len: 0,
    };

    /// Dimensions of `[T; outer]`, where `inner` are the dimensions of `T`.
    ///
    /// # Panics
    ///
    /// At compile time, if the nesting exceeds the supported depth.
    pub const fn wrap(outer: usize, inner: &Self) -> Self {
        assert!(
            inner.len < MAX_DIMS,
            "wire arrays support at most 8 dimensions"
        );
        let mut buf = [0; MAX_DIMS];
        buf[0] = outer;
        let mut i = 0;
        while i < inner.len {
            buf[i + 1] = inner.buf[i];
            i += 1;
        }
        Self {
            buf,
            len: inner.len + 1,
        }
    }

    /// The dimensions as a slice.
    pub const fn as_slice(&self) -> &[usize] {
        self.buf.as_slice().split_at(self.len).0
    }
}

/// A type usable as a field of a wire struct: its C spelling and its `Debug` rendering.
pub trait WireField: Pod {
    /// C type of the field, or of its innermost element for arrays.
    const C_TYPE: &'static str;
    /// Array dimensions, outermost first.
    const DIMS: &'static Dims;

    /// Formats a field value for the generated `Debug` impl.
    fn fmt_field(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;

    /// Formats an array of `Self`; a list by default.
    fn fmt_elems(elems: &[Self], f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(elems.iter().map(FieldFmt)).finish()
    }
}

/// Formats a field through [`WireField::fmt_field`].
pub struct FieldFmt<'a, T>(pub &'a T);

impl<T: WireField> fmt::Debug for FieldFmt<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt_field(f)
    }
}

macro_rules! integer_fields {
    ($($ty:ty => $c_name:literal),* $(,)?) => {$(
        impl CType for $ty {
            const C_NAME: &'static str = $c_name;
        }

        impl WireField for $ty {
            const C_TYPE: &'static str = $c_name;
            const DIMS: &'static Dims = &Dims::SCALAR;

            fn fmt_field(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(self, f)
            }
        }
    )*};
}

integer_fields! {
    u16 => "__u16",
    u32 => "__u32",
    u64 => "__u64",
    i8 => "__s8",
    i16 => "__s16",
    i32 => "__s32",
    i64 => "__s64",
}

impl CType for u8 {
    const C_NAME: &'static str = "__u8";
}

impl WireField for u8 {
    const C_TYPE: &'static str = "__u8";
    const DIMS: &'static Dims = &Dims::SCALAR;

    fn fmt_field(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }

    /// Byte arrays (`comm`, paths, addresses) print as an escaped byte string with trailing NUL
    /// padding omitted: `b"bash"` rather than sixteen decimal numbers.
    fn fmt_elems(elems: &[Self], f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = elems
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |last| last + 1);
        write!(f, "b\"{}\"", elems[..len].escape_ascii())
    }
}

impl<T: WireField, const N: usize> WireField for [T; N] {
    const C_TYPE: &'static str = T::C_TYPE;
    const DIMS: &'static Dims = &Dims::wrap(N, T::DIMS);

    fn fmt_field(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        T::fmt_elems(self, f)
    }
}

const STRUCT_KEYWORD: &str = "struct ";

/// Buffer capacity [`CName`] needs for the Rust type name `rust_name`.
pub const fn c_name_capacity(rust_name: &str) -> usize {
    // Snake case adds at most one `_` per character.
    STRUCT_KEYWORD.len() + 2 * rust_name.len()
}

/// Compile-time C spelling of a wire struct: `struct ev_header` for `EvHeader`.
#[derive(Debug, Clone, Copy)]
pub struct CName<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> CName<N> {
    /// Converts an ASCII `UpperCamelCase` Rust name to `struct snake_case`.
    ///
    /// An `_` goes before each uppercase letter that follows a lowercase letter or digit, or that
    /// starts a new word after an acronym (`HTTPReq` → `http_req`).
    ///
    /// # Panics
    ///
    /// At compile time, if `rust_name` is not ASCII or `N` is below [`c_name_capacity`].
    pub const fn new(rust_name: &str) -> Self {
        let src = rust_name.as_bytes();
        assert!(N >= c_name_capacity(rust_name), "CName buffer too small");

        let mut buf = [0; N];
        let mut len = 0;
        while len < STRUCT_KEYWORD.len() {
            buf[len] = STRUCT_KEYWORD.as_bytes()[len];
            len += 1;
        }

        let mut i = 0;
        while i < src.len() {
            let c = src[i];
            assert!(c.is_ascii(), "wire struct names must be ASCII");
            if c.is_ascii_uppercase() && i > 0 {
                let prev = src[i - 1];
                let after_word = prev.is_ascii_lowercase() || prev.is_ascii_digit();
                let after_acronym = prev.is_ascii_uppercase()
                    && i + 1 < src.len()
                    && src[i + 1].is_ascii_lowercase();
                if after_word || after_acronym {
                    buf[len] = b'_';
                    len += 1;
                }
            }
            buf[len] = c.to_ascii_lowercase();
            len += 1;
            i += 1;
        }
        Self { buf, len }
    }

    /// The C type name: `ev_header`.
    pub const fn c_name(&self) -> &str {
        ascii_str(self.bytes().split_at(STRUCT_KEYWORD.len()).1)
    }

    /// The C type as used in declarations: `struct ev_header`.
    pub const fn c_type(&self) -> &str {
        ascii_str(self.bytes())
    }

    const fn bytes(&self) -> &[u8] {
        self.buf.as_slice().split_at(self.len).0
    }
}

const fn ascii_str(bytes: &[u8]) -> &str {
    match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => panic!("C names are ASCII"),
    }
}

/// Compile-time proof that `T` is [`Pod`].
pub const fn require_pod<T: Pod>() {}

/// Typed constructors for [`ConstValue`](crate::ConstValue), named after the Rust type so
/// `wire_consts!` can select one from the declared type.
pub mod const_value {
    use crate::ConstValue;

    macro_rules! constructors {
        ($($ty:ident => $variant:ident),* $(,)?) => {$(
            #[doc = concat!("Wraps a `", stringify!($ty), "` constant.")]
            pub const fn $ty(value: $ty) -> ConstValue {
                ConstValue::$variant(value)
            }
        )*};
    }

    constructors! {
        u8 => U8,
        u16 => U16,
        u32 => U32,
        u64 => U64,
        i8 => I8,
        i16 => I16,
        i32 => I32,
        i64 => I64,
    }
}

#[cfg(test)]
mod tests {
    use super::{CName, Dims, c_name_capacity};

    #[track_caller]
    fn assert_snake(rust_name: &str, c_name: &str) {
        let name: CName<64> = CName::new(rust_name);
        assert_eq!(name.c_name(), c_name);
        assert_eq!(name.c_type().strip_prefix("struct "), Some(c_name));
    }

    #[test]
    fn snake_case_splits_words_acronyms_and_digits() {
        assert_snake("EvHeader", "ev_header");
        assert_snake("Event", "event");
        assert_snake("HTTPReq", "http_req");
        assert_snake("ExecEventV2", "exec_event_v2");
        assert_snake("Ipv4Addr", "ipv4_addr");
        assert_snake("TCP", "tcp");
        assert_snake("Ev_Header", "ev_header");
    }

    #[test]
    fn capacity_covers_worst_case() {
        const NAME: &str = "aBcDeF";
        const N: usize = c_name_capacity(NAME);
        let name: CName<N> = CName::new(NAME);
        assert_eq!(name.c_name(), "a_bc_de_f");
    }

    #[test]
    fn dims_prepend_outer_dimension() {
        let inner = Dims::wrap(20, &Dims::SCALAR);
        let outer = Dims::wrap(8, &inner);
        assert_eq!(Dims::SCALAR.as_slice(), &[] as &[usize]);
        assert_eq!(inner.as_slice(), &[20]);
        assert_eq!(outer.as_slice(), &[8, 20]);
    }
}
