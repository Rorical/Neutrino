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
        Self::from_key(&encoded)
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
        let bit_len_usize = key
            .len()
            .checked_mul(8)
            .expect("trie key bit length fits usize");
        let bit_len = u32::try_from(bit_len_usize).expect("trie key bit length fits u32");
        Self {
            bit_len,
            bytes: key.to_vec(),
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
        assert!(p.as_bytes().is_empty());
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

    #[test]
    fn debug_renders_bit_string() {
        let path = BitPath::from_key(&[0b1010_0000]).prefix(4);
        let s = alloc::format!("{path:?}");
        assert!(s.contains("1010"), "debug string was {s}");
    }
}
