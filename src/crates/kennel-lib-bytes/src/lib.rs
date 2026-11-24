// SPDX-License-Identifier: Apache-2.0

//! A bounds-checked reader over a byte slice.
//!
//! # Purpose
//!
//! Every wire decoder in the workspace walks bytes it did not write: a binder transaction from
//! a workload, a control-socket frame, a spawn plan, a signature blob. Each used to carry its
//! own cursor with its own copy of the one check that matters, "are there `n` more bytes".
//! [`ByteReader`] is that check, written once.
//!
//! # Shape
//!
//! Deliberately small. It knows positions and lengths and nothing about formats: no
//! endianness, no length prefixes, no strings. A decoder reads a fixed-size array with
//! [`ByteReader::array`] and applies its own `from_le_bytes` / `from_be_bytes`, and maps
//! `None` to its own error type. Every read either returns exactly what was asked for and
//! advances, or returns `None` and leaves the reader where it was.

#![forbid(unsafe_code)]

/// A cursor over `buf` that only ever moves forward, and never past the end.
#[derive(Debug, Clone)]
pub struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    /// A reader at the start of `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// How many bytes have been read: the offset of the next byte in the original slice.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// How many bytes are left to read.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Whether every byte has been read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// The next `n` bytes, advancing past them; `None`, without advancing, if fewer remain.
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    /// The next `N` bytes as an array, for a caller's `from_le_bytes` / `from_be_bytes`.
    pub fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let mut probe = self.clone();
        let array = <[u8; N]>::try_from(probe.take(N)?).ok()?;
        *self = probe;
        Some(array)
    }

    /// The next byte.
    pub fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[byte]| byte)
    }

    /// Everything not yet read, advancing to the end.
    pub fn rest(&mut self) -> &'a [u8] {
        let rest = self.buf.get(self.pos..).unwrap_or(&[]);
        self.pos = self.buf.len();
        rest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_advance_and_stop_at_the_end() {
        let mut r = ByteReader::new(&[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(r.remaining(), 7);
        assert_eq!(r.u8(), Some(1));
        assert_eq!(r.position(), 1);
        assert_eq!(r.take(2), Some(&[2, 3][..]));
        assert_eq!(r.position(), 3);
        assert_eq!(r.array::<4>(), Some([4, 5, 6, 7]));
        assert!(r.is_empty());
        assert_eq!(r.u8(), None);
        assert_eq!(r.take(0), Some(&[][..]), "nothing is always available");
    }

    #[test]
    fn a_read_that_does_not_fit_leaves_the_reader_where_it_was() {
        let mut r = ByteReader::new(&[1, 2, 3]);
        assert_eq!(r.take(4), None);
        assert_eq!(r.array::<4>(), None);
        assert_eq!(r.remaining(), 3, "a failed read consumes nothing");
        assert_eq!(r.take(3), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn a_length_that_overflows_is_a_miss_not_a_panic() {
        let mut r = ByteReader::new(&[1, 2, 3]);
        assert_eq!(r.u8(), Some(1));
        assert_eq!(r.take(usize::MAX), None);
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn rest_takes_what_is_left() {
        let mut r = ByteReader::new(&[1, 2, 3]);
        assert_eq!(r.u8(), Some(1));
        assert_eq!(r.rest(), &[2, 3]);
        assert!(r.is_empty());
        assert_eq!(r.rest(), &[] as &[u8]);
        assert!(ByteReader::new(&[]).is_empty());
    }
}
