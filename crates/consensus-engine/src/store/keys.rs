//! Key encoders for every consensus column.
//!
//! All integer keys are encoded big-endian so lexicographic iteration
//! over a column matches numeric iteration. Hash-keyed columns store the
//! raw 32-byte hash bytes.

use neutrino_primitives::{BlockHash, CheckpointIndex, ChunkId, Height, Slot};

/// Big-endian 8-byte key for a [`Height`].
#[must_use]
pub const fn height_key(height: Height) -> [u8; 8] {
    height.to_be_bytes()
}

/// Big-endian 8-byte key for a [`Slot`].
#[must_use]
pub const fn slot_key(slot: Slot) -> [u8; 8] {
    slot.to_be_bytes()
}

/// Big-endian 8-byte key for a [`ChunkId`].
#[must_use]
pub const fn chunk_id_key(chunk_id: ChunkId) -> [u8; 8] {
    chunk_id.to_be_bytes()
}

/// Big-endian 8-byte key for a [`CheckpointIndex`].
#[must_use]
pub const fn checkpoint_index_key(index: CheckpointIndex) -> [u8; 8] {
    index.to_be_bytes()
}

/// 32-byte key for any hash-addressed column (headers, bodies, block
/// proofs, witnesses).
#[must_use]
pub const fn hash_key(hash: &BlockHash) -> [u8; 32] {
    *hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_keys_sort_lexicographically_in_numeric_order() {
        let keys = [
            height_key(0),
            height_key(1),
            height_key(255),
            height_key(256),
            height_key(u64::MAX - 1),
            height_key(u64::MAX),
        ];
        for window in keys.windows(2) {
            assert!(window[0] < window[1]);
        }
    }

    #[test]
    fn slot_chunk_checkpoint_encoders_match_height_encoder() {
        // All four are big-endian 8-byte u64 encoders; this is a tripwire
        // for accidental endianness drift.
        assert_eq!(height_key(0xDEAD_BEEF), slot_key(0xDEAD_BEEF));
        assert_eq!(slot_key(0xDEAD_BEEF), chunk_id_key(0xDEAD_BEEF));
        assert_eq!(chunk_id_key(0xDEAD_BEEF), checkpoint_index_key(0xDEAD_BEEF));
    }

    #[test]
    fn hash_key_is_identity() {
        let h: BlockHash = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        assert_eq!(hash_key(&h), h);
    }
}
