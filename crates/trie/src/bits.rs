//! Canonical bit-path used as the key suffix in leaves and the prefix
//! in extension nodes.
//!
//! Bits are laid out **most-significant-bit-first within each byte**,
//! matching the conventional ordering for binary Patricia tries: the
//! lexicographic order of bit-paths agrees with the lexicographic order
//! of the underlying byte slices used to build them.
//!
//! Wire layout (used by [`crate::node::Node`] encodings):
//!
//! ```text
//! bit_len: u32 little-endian
//! bytes:   ceil(bit_len / 8) bytes, MSB-first within byte, padding bits zero
//! ```
//!
//! Decoders reject any encoding whose trailing byte has nonzero padding
//! bits so the canonical form is unique.

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::error::TrieError;

/// A length-tagged bit sequence with canonical wire encoding.
///
/// `BitPath` also derives [`BorshSerialize`] and [`BorshDeserialize`]
/// so it can be carried through proof witnesses ([`crate::Proof`]).
/// The borsh form is `bit_len: u32 LE || borsh-encoded Vec<u8>` and is
/// independent of the trie's internal canonical encoding produced by
/// [`BitPath::encode_into`]; borsh decoders do not enforce trailing-bit
/// padding because witness consumers only ever round-trip values
/// previously serialized by the trie itself.
#[derive(BorshDeserialize, BorshSerialize, Clone, Default, Eq, Hash, PartialEq)]
pub struct BitPath {
    bit_len: u32,
    bytes: Vec<u8>,
}

impl BitPath {
    /// The empty bit-path. Encodes as four little-endian zero bytes.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            bit_len: 0,
            bytes: Vec::new(),
        }
    }

    /// Build the canonical trie path for a runtime key. The path is
    /// `key_len_u32_le || key`, interpreted MSB-first as a bit string.
    /// The fixed-width length prefix lets the trie support arbitrary
    /// byte keys, including pairs where one raw key is a prefix of
    /// another.
    ///
    /// # Panics
    ///
    /// Panics if `key.len()` does not fit in `u32`.
    #[must_use]
    pub(crate) fn for_key(key: &[u8]) -> Self {
        let key_len = u32::try_from(key.len()).expect("trie key byte length fits u32");
        let mut encoded = Vec::with_capacity(4 + key.len());
        encoded.extend_from_slice(&key_len.to_le_bytes());
        encoded.extend_from_slice(key);
        Self::from_owned_key(encoded)
    }

    /// Build a path from raw bytes without adding the trie key length
    /// prefix. Each byte contributes 8 bits in
    /// MSB-first order, so `from_key(&[0xC0])` is `1 1 0 0 0 0 0 0`.
    /// This is used for node-internal suffix/prefix values and
    /// low-level tests; trie lookups use [`BitPath::for_key`].
    ///
    /// # Panics
    ///
    /// Panics if `key.len() * 8` does not fit in `u32`. Trie keys are
    /// expected to be at most `u32::MAX / 8 = 512 MiB`; this is far
    /// larger than any plausible state key.
    #[must_use]
    pub fn from_key(key: &[u8]) -> Self {
        Self::from_owned_key(key.to_vec())
    }

    /// [`BitPath::from_key`] over owned bytes, without copying them again.
    fn from_owned_key(bytes: Vec<u8>) -> Self {
        let bit_len_usize = bytes
            .len()
            .checked_mul(8)
            .expect("trie key bit length fits usize");
        let bit_len = u32::try_from(bit_len_usize).expect("trie key bit length fits u32");
        Self { bit_len, bytes }
    }

    /// The canonical one-bit path.
    #[must_use]
    pub(crate) fn single(bit: bool) -> Self {
        Self {
            bit_len: 1,
            bytes: vec![u8::from(bit) << 7],
        }
    }

    /// Number of meaningful bits.
    #[must_use]
    pub const fn bit_len(&self) -> u32 {
        self.bit_len
    }

    /// True iff the path carries no bits.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bit_len == 0
    }

    /// Borrow the packed byte representation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Read a single bit. Index `0` is the most-significant bit of
    /// `bytes[0]`.
    ///
    /// # Panics
    ///
    /// Panics if `index >= bit_len()`.
    #[must_use]
    pub fn bit(&self, index: u32) -> bool {
        assert!(
            index < self.bit_len,
            "bit index {index} out of bounds {}",
            self.bit_len
        );
        let byte_index = (index / 8) as usize;
        let bit_offset = 7 - (index % 8) as usize;
        (self.bytes[byte_index] >> bit_offset) & 1 == 1
    }

    /// Take the first `len` bits.
    ///
    /// # Panics
    ///
    /// Panics if `len > bit_len()`.
    #[must_use]
    pub fn prefix(&self, len: u32) -> Self {
        assert!(
            len <= self.bit_len,
            "prefix length {len} exceeds bit_len {}",
            self.bit_len
        );
        if len == 0 {
            return Self::empty();
        }
        let byte_len = bytes_for_bits(len);
        let mut bytes = self.bytes[..byte_len].to_vec();
        mask_padding(&mut bytes, len);
        Self {
            bit_len: len,
            bytes,
        }
    }

    /// Drop the first `from` bits and return what remains.
    ///
    /// # Panics
    ///
    /// Panics if `from > bit_len()`.
    #[must_use]
    pub fn suffix(&self, from: u32) -> Self {
        assert!(
            from <= self.bit_len,
            "suffix start {from} exceeds bit_len {}",
            self.bit_len
        );
        let new_bit_len = self.bit_len - from;
        if new_bit_len == 0 {
            return Self::empty();
        }
        let new_byte_len = bytes_for_bits(new_bit_len);
        let mut new_bytes = vec![0_u8; new_byte_len];
        let from_byte = (from / 8) as usize;
        let from_bit = (from % 8) as usize;

        if from_bit == 0 {
            new_bytes.copy_from_slice(&self.bytes[from_byte..from_byte + new_byte_len]);
        } else {
            for (out_idx, dst) in new_bytes.iter_mut().enumerate() {
                let src_idx = from_byte + out_idx;
                let high = self.bytes[src_idx] << from_bit;
                let low = if src_idx + 1 < self.bytes.len() {
                    self.bytes[src_idx + 1] >> (8 - from_bit)
                } else {
                    0
                };
                *dst = high | low;
            }
        }

        mask_padding(&mut new_bytes, new_bit_len);
        Self {
            bit_len: new_bit_len,
            bytes: new_bytes,
        }
    }

    /// Return the length of the longest common prefix shared with
    /// `other`. Always satisfies `result <= min(self.bit_len(),
    /// other.bit_len())`.
    #[must_use]
    pub fn common_prefix_len(&self, other: &Self) -> u32 {
        let max_len = min(self.bit_len, other.bit_len);
        if max_len == 0 {
            return 0;
        }
        let full_bytes = (max_len / 8) as usize;
        for i in 0..full_bytes {
            if self.bytes[i] != other.bytes[i] {
                let xor = self.bytes[i] ^ other.bytes[i];
                let leading = xor.leading_zeros();
                let byte_index = u32::try_from(i).expect("common-prefix byte index fits in u32");
                return byte_index * 8 + leading;
            }
        }
        let trailing_bits = max_len % 8;
        if trailing_bits == 0 {
            return max_len;
        }
        let xor = self.bytes[full_bytes] ^ other.bytes[full_bytes];
        let leading_match = xor.leading_zeros();
        let common_in_last = min(leading_match, trailing_bits);
        let full_bytes_u32 =
            u32::try_from(full_bytes).expect("common-prefix byte count fits in u32");
        full_bytes_u32 * 8 + common_in_last
    }

    /// Whether `other`'s bits occur in this path starting at bit `offset`,
    /// without allocating. `false` when `other` would run past the end.
    ///
    /// Only bits are compared, so for canonical paths (such as every decoded
    /// node path) this equals comparing `other` with the allocated
    /// `self.suffix(offset).prefix(other.bit_len())` whenever that is in range.
    #[must_use]
    pub(crate) fn matches_at(&self, offset: u32, other: &Self) -> bool {
        let Some(end) = offset.checked_add(other.bit_len) else {
            return false;
        };
        if end > self.bit_len {
            return false;
        }
        let start = (offset / 8) as usize;
        let shift = offset % 8;
        // Byte `index` of this path's bits read from `offset`, MSB-aligned.
        let window = |index: usize| {
            let high = self.bytes[start + index] << shift;
            if shift == 0 {
                return high;
            }
            let low = self
                .bytes
                .get(start + index + 1)
                .map_or(0, |byte| byte >> (8 - shift));
            high | low
        };
        let full = (other.bit_len / 8) as usize;
        if (0..full).any(|index| window(index) != other.bytes[index]) {
            return false;
        }
        let tail = other.bit_len % 8;
        if tail == 0 {
            return true;
        }
        let mask = 0xFF_u8 << (8 - tail);
        (window(full) & mask) == (other.bytes[full] & mask)
    }

    /// This path followed by `tail`, in canonical form. An empty operand
    /// returns a clone of the other one.
    ///
    /// # Panics
    ///
    /// Panics if the combined bit length does not fit in `u32`.
    #[must_use]
    pub(crate) fn concat(&self, tail: &Self) -> Self {
        if self.is_empty() {
            return tail.clone();
        }
        if tail.is_empty() {
            return self.clone();
        }
        let bit_len = self
            .bit_len
            .checked_add(tail.bit_len)
            .expect("concatenated bit length fits u32");
        let mut bytes = Vec::with_capacity(bytes_for_bits(bit_len) + 1);
        bytes.extend_from_slice(&self.bytes[..bytes_for_bits(self.bit_len)]);
        mask_padding(&mut bytes, self.bit_len);
        let tail_bytes = &tail.bytes[..bytes_for_bits(tail.bit_len)];
        let shift = self.bit_len % 8;
        if shift == 0 {
            bytes.extend_from_slice(tail_bytes);
        } else {
            for &byte in tail_bytes {
                let last = bytes.last_mut().expect("a non-empty head has a byte");
                *last |= byte >> shift;
                bytes.push(byte << (8 - shift));
            }
        }
        bytes.truncate(bytes_for_bits(bit_len));
        mask_padding(&mut bytes, bit_len);
        Self { bit_len, bytes }
    }

    /// Append the canonical encoding to `buf`.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.bit_len.to_le_bytes());
        buf.extend_from_slice(&self.bytes);
    }

    /// Decode a canonical encoding from the start of `bytes`. Returns
    /// the decoded path and the number of bytes consumed.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), TrieError> {
        if bytes.len() < 4 {
            return Err(TrieError::TruncatedNode);
        }
        let bit_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let byte_len = bytes_for_bits(bit_len);
        let total = 4_usize
            .checked_add(byte_len)
            .ok_or(TrieError::BitPathTooLong)?;
        if bytes.len() < total {
            return Err(TrieError::TruncatedNode);
        }
        let path_bytes = bytes[4..total].to_vec();
        if has_nonzero_padding(bit_len, &path_bytes) {
            return Err(TrieError::NonCanonicalBitPath);
        }
        Ok((
            Self {
                bit_len,
                bytes: path_bytes,
            },
            total,
        ))
    }
}

impl fmt::Debug for BitPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitPath(bit_len={}, ", self.bit_len)?;
        for i in 0..self.bit_len {
            f.write_str(if self.bit(i) { "1" } else { "0" })?;
        }
        f.write_str(")")
    }
}

const fn bytes_for_bits(bit_len: u32) -> usize {
    (bit_len as usize).div_ceil(8)
}

const fn mask_padding(bytes: &mut [u8], bit_len: u32) {
    let trailing_bits = (bit_len % 8) as usize;
    if trailing_bits == 0 {
        return;
    }
    let mask = 0xFF_u8 << (8 - trailing_bits);
    if let Some(last) = bytes.last_mut() {
        *last &= mask;
    }
}

fn has_nonzero_padding(bit_len: u32, bytes: &[u8]) -> bool {
    let trailing_bits = (bit_len % 8) as usize;
    if trailing_bits == 0 {
        return false;
    }
    let mask = 0xFF_u8 >> trailing_bits;
    bytes.last().is_some_and(|&b| b & mask != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_key_lays_out_bits_msb_first() {
        let path = BitPath::from_key(&[0xC0]);
        assert_eq!(path.bit_len(), 8);
        assert!(path.bit(0));
        assert!(path.bit(1));
        assert!(!path.bit(2));
        assert!(!path.bit(7));
    }

    #[test]
    fn empty_path_is_empty() {
        let p = BitPath::empty();
        assert!(p.is_empty());
        assert_eq!(p.bit_len(), 0);
        assert_eq!(p.as_bytes(), [] as [u8; 0]);
    }

    #[test]
    fn prefix_truncates_and_clears_padding() {
        let path = BitPath::from_key(&[0xFF, 0xFF]);
        let p = path.prefix(3);
        assert_eq!(p.bit_len(), 3);
        assert_eq!(p.as_bytes(), &[0b1110_0000]);
    }

    #[test]
    fn suffix_aligns_remaining_bits_to_msb() {
        let path = BitPath::from_key(&[0b1010_1100, 0b1100_0011]);
        let s = path.suffix(3);
        assert_eq!(s.bit_len(), 13);
        // Original bits 3..16 are 01100110_00011, MSB-aligned that becomes
        // 0110 0110 0001 1, packed as 0b0110_0110, 0b0001_1000.
        assert_eq!(s.as_bytes(), &[0b0110_0110, 0b0001_1000]);
        for i in 0..13 {
            assert_eq!(s.bit(i), path.bit(i + 3), "bit {i}");
        }
    }

    #[test]
    fn suffix_full_length_is_empty() {
        let path = BitPath::from_key(&[0xAB, 0xCD]);
        assert!(path.suffix(16).is_empty());
    }

    #[test]
    fn common_prefix_handles_byte_aligned_match() {
        let a = BitPath::from_key(&[0x12, 0x34, 0x56]);
        let b = BitPath::from_key(&[0x12, 0x34, 0xFF]);
        assert_eq!(a.common_prefix_len(&b), 16);
    }

    #[test]
    fn common_prefix_handles_intra_byte_divergence() {
        let a = BitPath::from_key(&[0b1011_0000]);
        let b = BitPath::from_key(&[0b1010_0000]);
        // Disagree at bit 3.
        assert_eq!(a.common_prefix_len(&b), 3);
    }

    #[test]
    fn common_prefix_handles_unequal_lengths() {
        let a = BitPath::from_key(&[0xAB]);
        let b = BitPath::from_key(&[0xAB, 0xCD]);
        assert_eq!(a.common_prefix_len(&b), 8);
    }

    #[test]
    fn common_prefix_with_empty_is_zero() {
        let a = BitPath::empty();
        let b = BitPath::from_key(&[0xFF]);
        assert_eq!(a.common_prefix_len(&b), 0);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let path = BitPath::from_key(&[0xAA, 0xBB, 0xCC]).prefix(20);
        let mut buf = Vec::new();
        path.encode_into(&mut buf);
        let (decoded, consumed) = BitPath::decode(&buf).expect("decode");
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded, path);
    }

    #[test]
    fn decode_rejects_short_header() {
        assert_eq!(BitPath::decode(&[0, 0, 0]), Err(TrieError::TruncatedNode));
    }

    #[test]
    fn decode_rejects_truncated_body() {
        // bit_len = 16 needs 2 body bytes; provide only 1.
        let bytes = [16, 0, 0, 0, 0xAA];
        assert_eq!(BitPath::decode(&bytes), Err(TrieError::TruncatedNode));
    }

    #[test]
    fn decode_rejects_nonzero_padding() {
        // bit_len = 3 must have low five bits zero in the trailing byte.
        let bytes = [3, 0, 0, 0, 0b1110_0001];
        assert_eq!(BitPath::decode(&bytes), Err(TrieError::NonCanonicalBitPath));
    }

    /// The pre-refactor bit-at-a-time concatenation, the reference for `concat`.
    fn legacy_concat(head: &BitPath, tail: &BitPath) -> BitPath {
        if head.is_empty() {
            return tail.clone();
        }
        if tail.is_empty() {
            return head.clone();
        }
        let mut acc = head.clone();
        for i in 0..tail.bit_len() {
            acc = legacy_push_bit(&acc, tail.bit(i));
        }
        acc
    }

    fn legacy_push_bit(path: &BitPath, bit: bool) -> BitPath {
        let new_len = path.bit_len() + 1;
        let new_byte_len = (new_len as usize).div_ceil(8);
        let mut bytes = path.as_bytes().to_vec();
        if bytes.len() < new_byte_len {
            bytes.push(0);
        }
        if bit {
            let byte_index = ((new_len - 1) / 8) as usize;
            let bit_offset = 7 - ((new_len - 1) % 8) as usize;
            bytes[byte_index] |= 1_u8 << bit_offset;
        }
        let mut buf = Vec::with_capacity(4 + bytes.len());
        buf.extend_from_slice(&new_len.to_le_bytes());
        buf.extend_from_slice(&bytes);
        let (path, _) = BitPath::decode(&buf).expect("synthesized BitPath bytes are canonical");
        path
    }

    /// Canonical paths of many lengths, taken at aligned and unaligned offsets.
    fn sample_paths() -> Vec<BitPath> {
        let source = BitPath::from_key(&[0xA5, 0x3C, 0xFF, 0x00, 0x96, 0x71, 0x0E, 0xD2]);
        let mut paths = Vec::new();
        for start in [0, 1, 3, 7, 8, 9, 13] {
            for len in 0..=24 {
                paths.push(source.suffix(start).prefix(len));
            }
        }
        paths
    }

    #[test]
    fn concat_matches_the_bit_at_a_time_reference() {
        let paths = sample_paths();
        for head in &paths {
            for tail in &paths {
                let joined = head.concat(tail);
                assert_eq!(joined, legacy_concat(head, tail), "{head:?} ++ {tail:?}");
                assert_eq!(joined.bit_len(), head.bit_len() + tail.bit_len());
            }
        }
        for bit in [false, true] {
            assert_eq!(
                BitPath::single(bit),
                legacy_push_bit(&BitPath::empty(), bit)
            );
        }
    }

    #[test]
    fn matches_at_and_offset_suffixes_agree_with_allocating_slices() {
        let paths = sample_paths();
        let long = BitPath::from_key(&[0xA5, 0x3C, 0xFF, 0x00, 0x96]);
        for path in paths.iter().chain([&long]) {
            for offset in 0..=path.bit_len() {
                let rest = path.suffix(offset);
                for first in 0..=rest.bit_len() {
                    assert_eq!(rest.suffix(first), path.suffix(offset + first));
                }
                for other in &paths {
                    let expected = offset + other.bit_len() <= path.bit_len()
                        && rest.prefix(other.bit_len()) == *other;
                    assert_eq!(path.matches_at(offset, other), expected);
                }
            }
            for other in &paths {
                assert!(!path.matches_at(path.bit_len() + 1, other));
                assert!(!path.matches_at(u32::MAX, other));
            }
        }
    }

    #[test]
    fn for_key_prefixes_the_little_endian_key_length() {
        assert_eq!(
            BitPath::for_key(b"abc"),
            BitPath::from_key(&[3, 0, 0, 0, b'a', b'b', b'c'])
        );
        assert_eq!(BitPath::for_key(&[]), BitPath::from_key(&[0; 4]));
    }

    #[test]
    fn debug_renders_bit_string() {
        let path = BitPath::from_key(&[0b1010_0000]).prefix(4);
        let s = alloc::format!("{path:?}");
        assert!(s.contains("1010"), "debug string was {s}");
    }
}
