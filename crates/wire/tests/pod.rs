//! Zero-copy and copying decoding of wire types.

use wire::{as_bytes, from_bytes, read, wire};

wire! {
    pub struct Sample {
        pub kind: u32,
        pub pid: u32,
        pub ts_ns: u64,
    }
}

/// Byte buffer with a known 8-byte alignment, so offsets control misalignment.
#[repr(C, align(8))]
struct Aligned([u8; 32]);

fn encoded() -> Aligned {
    let mut buf = Aligned([0; 32]);
    buf.0[..4].copy_from_slice(&7_u32.to_ne_bytes());
    buf.0[4..8].copy_from_slice(&42_u32.to_ne_bytes());
    buf.0[8..16].copy_from_slice(&123_456_u64.to_ne_bytes());
    buf
}

const EXPECTED: Sample = Sample {
    kind: 7,
    pid: 42,
    ts_ns: 123_456,
};

#[test]
fn from_bytes_views_aligned_input_and_ignores_trailing_bytes() {
    let buf = encoded();
    assert_eq!(from_bytes::<Sample>(&buf.0), Some(&EXPECTED));
    assert_eq!(from_bytes::<Sample>(&buf.0[..16]), Some(&EXPECTED));
}

#[test]
fn from_bytes_rejects_short_input() {
    let buf = encoded();
    assert_eq!(from_bytes::<Sample>(&buf.0[..15]), None);
    assert_eq!(from_bytes::<Sample>(&[]), None);
}

#[test]
fn from_bytes_rejects_misaligned_input() {
    let mut buf = Aligned([0; 32]);
    buf.0[1..17].copy_from_slice(&encoded().0[..16]);
    assert_eq!(from_bytes::<Sample>(&buf.0[1..]), None);
    // `u32` only needs 4-byte alignment.
    assert!(from_bytes::<u32>(&buf.0[4..]).is_some());
    assert_eq!(from_bytes::<u32>(&buf.0[2..]), None);
}

#[test]
fn read_tolerates_misalignment_but_not_short_input() {
    let mut buf = Aligned([0; 32]);
    buf.0[1..17].copy_from_slice(&encoded().0[..16]);
    assert_eq!(read::<Sample>(&buf.0[1..]), Some(EXPECTED));
    assert_eq!(read::<Sample>(&buf.0[1..16]), None);
}

#[test]
fn as_bytes_round_trips() {
    let buf = encoded();
    assert_eq!(as_bytes(&EXPECTED), &buf.0[..16]);
    assert_eq!(read::<Sample>(as_bytes(&EXPECTED)), Some(EXPECTED));
    assert_eq!(
        as_bytes(&[1_u16, 2]),
        [1_u16.to_ne_bytes(), 2_u16.to_ne_bytes()].concat()
    );
}
