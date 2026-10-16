//! Declarative macros defining wire types.

/// Declares `#[repr(C)]` wire structs shared with BPF C code.
///
/// ```
/// wire::wire! {
///     /// Common prefix of every event.
///     pub struct EvHeader {
///         pub kind: u32,
///         pub pid: u32,
///         pub ts_ns: u64,
///     }
///
///     pub struct ConnEvent {
///         pub hdr: EvHeader,
///         /// Up to eight raw socket addresses.
///         pub addrs: [[u8; 20]; 8],
///         pub count: u32,
///         pub _pad: u32,
///     }
/// }
///
/// use wire::{CType, WireStruct};
/// assert_eq!(ConnEvent::C_NAME, "conn_event");
/// assert_eq!(ConnEvent::FIELDS[1].dims, &[8, 20]);
/// assert_eq!(ConnEvent::SIZE, 184);
/// ```
///
/// Each struct gets:
///
/// - `#[repr(C)]` and `#[derive(Clone, Copy, PartialEq, Eq)]`; further attributes pass through.
/// - A compact `Debug` impl: byte arrays print as byte strings with trailing NULs omitted
///   (`comm: b"bash"`), other arrays as lists.
/// - [`Pod`](crate::Pod), [`CType`](crate::CType) (C name in snake case, `ConnEvent` →
///   `conn_event`) and [`WireStruct`](crate::WireStruct) impls.
/// - A compile-time check that the struct has no implicit padding, which C code could leave
///   uninitialised. Fill gaps with explicit `_pad` fields instead:
///
/// ```compile_fail
/// wire::wire! {
///     pub struct Padded {
///         pub a: u8,
///         pub b: u32, // three padding bytes before `b`
///     }
/// }
/// ```
///
/// ```
/// wire::wire! {
///     pub struct Padded {
///         pub a: u8,
///         pub _pad: [u8; 3],
///         pub b: u32,
///     }
/// }
/// ```
///
/// Field types are the fixed-width integers (`u8` … `i64`), other wire structs, and arrays
/// (nested up to eight deep) of either. In C they become `__u32 kind;`,
/// `struct ev_header hdr;` and `__u8 addrs[8][20];`.
#[macro_export]
macro_rules! wire {
    ($(
        $(#[$attr:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_attr:meta])*
                $field_vis:vis $field:ident : $ty:ty
            ),* $(,)?
        }
    )*) => {$(
        $(#[$attr])*
        #[repr(C)]
        #[derive(Clone, Copy, PartialEq, Eq)]
        // Explicit `_pad` fields are part of the ABI and must stay public for struct literals.
        #[allow(clippy::pub_underscore_fields)]
        $vis struct $name {
            $(
                $(#[$field_attr])*
                $field_vis $field: $ty,
            )*
        }

        const _: () = {
            const NAME: &$crate::__private::CName<
                { $crate::__private::c_name_capacity(::core::stringify!($name)) },
            > = &$crate::__private::CName::new(::core::stringify!($name));

            ::core::assert!(
                ::core::mem::size_of::<$name>() == 0 $(+ ::core::mem::size_of::<$ty>())*,
                ::core::concat!(
                    "wire struct `", ::core::stringify!($name),
                    "` has implicit padding; add explicit `_pad` fields so field sizes sum to its size",
                ),
            );

            // SAFETY: `repr(C)` with no padding (asserted above), and every field is `Pod`
            // (`WireField: Pod` is required by `FIELDS` below), so all bit patterns are valid.
            unsafe impl $crate::Pod for $name {}

            impl $crate::CType for $name {
                const C_NAME: &'static str = NAME.c_name();
            }

            impl $crate::__private::WireField for $name {
                const C_TYPE: &'static str = NAME.c_type();
                const DIMS: &'static $crate::__private::Dims = &$crate::__private::Dims::SCALAR;

                fn fmt_field(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    ::core::fmt::Debug::fmt(self, f)
                }
            }

            impl $crate::WireStruct for $name {
                const FIELDS: &'static [$crate::FieldDesc] = &[$(
                    $crate::FieldDesc {
                        name: ::core::stringify!($field),
                        c_type: <$ty as $crate::__private::WireField>::C_TYPE,
                        dims: <$ty as $crate::__private::WireField>::DIMS.as_slice(),
                        offset: ::core::mem::offset_of!($name, $field),
                    },
                )*];
                const SIZE: usize = ::core::mem::size_of::<$name>();
                const ALIGN: usize = ::core::mem::align_of::<$name>();
            }

            impl ::core::fmt::Debug for $name {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    f.debug_struct(::core::stringify!($name))
                        $(.field(
                            ::core::stringify!($field),
                            &$crate::__private::FieldFmt(&self.$field),
                        ))*
                        .finish()
                }
            }
        };
    )*};
}

/// Declares integer constants shared with BPF C code, plus a
/// [`ConstGroup`](crate::ConstGroup) listing them for `HeaderBuilder::consts`.
///
/// The first line names the group constant; each following item is an ordinary `const` of type
/// `u8` … `u64` or `i8` … `i64`. The header gets `#define NAME VALUE` per constant, in decimal
/// with a C suffix matching the type (see [`ConstValue`](crate::ConstValue)).
///
/// ```
/// wire::wire_consts! {
///     /// Constants shared with the BPF program.
///     pub group ABI_CONSTS;
///     /// Ring buffer size in bytes.
///     pub const RINGBUF_BYTES: u32 = 1 << 20;
///     pub const EV_EXEC: u8 = 1;
/// }
///
/// assert_eq!(RINGBUF_BYTES, 1 << 20);
/// assert_eq!(ABI_CONSTS.name, "ABI_CONSTS");
/// assert_eq!(ABI_CONSTS.consts[1].name, "EV_EXEC");
/// assert_eq!(ABI_CONSTS.consts[1].value, wire::ConstValue::U8(1));
/// ```
#[macro_export]
macro_rules! wire_consts {
    (
        $(#[$group_attr:meta])*
        $group_vis:vis group $group:ident;
        $(
            $(#[$attr:meta])*
            $vis:vis const $name:ident : $ty:ident = $value:expr;
        )*
    ) => {
        $(
            $(#[$attr])*
            $vis const $name: $ty = $value;
        )*

        $(#[$group_attr])*
        $group_vis const $group: $crate::ConstGroup = $crate::ConstGroup {
            name: ::core::stringify!($group),
            consts: &[$(
                $crate::ConstDesc {
                    name: ::core::stringify!($name),
                    value: $crate::__private::const_value::$ty($name),
                },
            )*],
        };
    };
}

/// Implements `aya::Pod` for wire types, so they can be used as aya map keys and values.
///
/// The orphan rule forbids a blanket impl from this crate, so the crate that owns the types
/// invokes this macro; `::aya` resolves to that crate's own `aya` dependency and this crate does
/// not depend on aya. Gate the call on the user crate's own feature if aya is optional:
///
/// ```ignore
/// #[cfg(feature = "user")]
/// wire::impl_aya_pod!(EvHeader, ExecEvent);
/// ```
///
/// Each type must implement [`Pod`](crate::Pod), whose contract matches aya's; anything else is a
/// compile error.
#[macro_export]
macro_rules! impl_aya_pod {
    ($($ty:ty),+ $(,)?) => {$(
        const _: () = $crate::__private::require_pod::<$ty>();

        // SAFETY: `$ty: wire::Pod`, which guarantees what `aya::Pod` requires.
        unsafe impl ::aya::Pod for $ty {}
    )+};
}
