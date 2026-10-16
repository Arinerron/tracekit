//! Constants shared with C, declared through [`wire_consts!`](crate::wire_consts!).

use core::fmt;

/// A named set of constants declared by one [`wire_consts!`](crate::wire_consts!) invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstGroup {
    /// Name of the group's Rust constant; used as a comment in the header.
    pub name: &'static str,
    /// Constants in declaration order.
    pub consts: &'static [ConstDesc],
}

/// One constant: rendered as `#define NAME VALUE` in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstDesc {
    /// Constant name, shared by Rust and C.
    pub name: &'static str,
    /// Typed value.
    pub value: ConstValue,
}

/// Value of a shared constant, keeping its Rust type so the C literal has a matching type.
///
/// `Display` renders a C integer literal in decimal: unsigned values carry a `U` suffix (`ULL`
/// for 64-bit), 64-bit signed values `LL`, and negative values are parenthesised so they expand
/// safely inside expressions. The minimum of each signed type is written as `(-MAX - 1)` because
/// its magnitude does not fit the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstValue {
    /// A `u8` constant.
    U8(u8),
    /// A `u16` constant.
    U16(u16),
    /// A `u32` constant.
    U32(u32),
    /// A `u64` constant.
    U64(u64),
    /// An `i8` constant.
    I8(i8),
    /// An `i16` constant.
    I16(i16),
    /// An `i32` constant.
    I32(i32),
    /// An `i64` constant.
    I64(i64),
}

impl fmt::Display for ConstValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::U8(v) => write!(f, "{v}U"),
            Self::U16(v) => write!(f, "{v}U"),
            Self::U32(v) => write!(f, "{v}U"),
            Self::U64(v) => write!(f, "{v}ULL"),
            Self::I8(v) => write_signed(f, v.into(), i8::MIN.into(), ""),
            Self::I16(v) => write_signed(f, v.into(), i16::MIN.into(), ""),
            Self::I32(v) => write_signed(f, v.into(), i32::MIN.into(), ""),
            Self::I64(v) => write_signed(f, v, i64::MIN, "LL"),
        }
    }
}

fn write_signed(f: &mut fmt::Formatter<'_>, value: i64, min: i64, suffix: &str) -> fmt::Result {
    let magnitude = value.unsigned_abs();
    if value >= 0 {
        write!(f, "{magnitude}{suffix}")
    } else if value == min {
        write!(f, "(-{}{suffix} - 1)", magnitude - 1)
    } else {
        write!(f, "(-{magnitude}{suffix})")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::ToString;

    use super::ConstValue;

    #[test]
    fn literals_carry_c_type_suffixes() {
        assert_eq!(ConstValue::U8(7).to_string(), "7U");
        assert_eq!(ConstValue::U32(u32::MAX).to_string(), "4294967295U");
        assert_eq!(
            ConstValue::U64(u64::MAX).to_string(),
            "18446744073709551615ULL"
        );
        assert_eq!(ConstValue::I32(42).to_string(), "42");
        assert_eq!(ConstValue::I64(0).to_string(), "0LL");
    }

    #[test]
    fn negative_literals_are_parenthesised() {
        assert_eq!(ConstValue::I16(-1).to_string(), "(-1)");
        assert_eq!(ConstValue::I64(-3).to_string(), "(-3LL)");
    }

    #[test]
    fn signed_minimum_avoids_out_of_range_literal() {
        assert_eq!(ConstValue::I8(i8::MIN).to_string(), "(-127 - 1)");
        assert_eq!(ConstValue::I32(i32::MIN).to_string(), "(-2147483647 - 1)");
        assert_eq!(
            ConstValue::I64(i64::MIN).to_string(),
            "(-9223372036854775807LL - 1)"
        );
        assert_eq!(ConstValue::I32(i32::MIN + 1).to_string(), "(-2147483647)");
    }
}
