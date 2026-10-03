//! Counted, append-only historical commitments in a fixed 64-level tree.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize, io};
use neutrino_primitives::{
    DOMAIN_HISTORY_LEAF, DOMAIN_HISTORY_NODE, DOMAIN_HISTORY_ROOT, Hash, blake3_256,
};

/// Number of address bits in a historical chunk index.
pub const HISTORY_DEPTH: usize = 64;

/// Number of preceding finalized chunks available to current consensus inputs.
/// Archive nodes retain more data but enforce this same protocol window.
pub const HISTORY_RETENTION_CHUNKS: u64 = 8;

/// Whether an index belongs to the eight finalized chunks before `count`.
/// Current and future chunks are excluded; genesis has no historical records.
#[must_use]
pub const fn is_recent_history_index(index: u64, count: u64) -> bool {
    index < count && index >= count.saturating_sub(HISTORY_RETENTION_CHUNKS)
}

/// Distinguish an empty slot from an occupied context commitment.
#[must_use]
pub fn history_leaf_hash(value: Option<Hash>) -> Hash {
    let mut bytes = Vec::from(DOMAIN_HISTORY_LEAF);
    bytes.push(u8::from(value.is_some()));
    if let Some(value) = value {
        bytes.extend_from_slice(&value);
    }
    blake3_256(&bytes)
}

/// Hash children of height `level`; level zero combines historical leaves.
#[must_use]
pub fn history_node_hash(level: usize, left: Hash, right: Hash) -> Hash {
    assert!(level < HISTORY_DEPTH, "historical node level");
    let mut bytes = Vec::from(DOMAIN_HISTORY_NODE);
    bytes.push(u8::try_from(level).expect("bounded history depth"));
    bytes.extend_from_slice(&left);
    bytes.extend_from_slice(&right);
    blake3_256(&bytes)
}

/// Empty subtree hashes, indexed by height (zero is an empty leaf).
#[must_use]
pub fn empty_history_hashes() -> [Hash; HISTORY_DEPTH + 1] {
    let mut empty = [[0; 32]; HISTORY_DEPTH + 1];
    empty[0] = history_leaf_hash(None);
    for level in 0..HISTORY_DEPTH {
        empty[level + 1] = history_node_hash(level, empty[level], empty[level]);
    }
    empty
}

/// Bind the append position to the tree commitment.
#[must_use]
pub fn counted_history_root(count: u64, root: Hash) -> Hash {
    let mut bytes = Vec::from(DOMAIN_HISTORY_ROOT);
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&root);
    blake3_256(&bytes)
}

/// Canonical genesis historical commitment.
#[must_use]
pub fn empty_history_root() -> Hash {
    counted_history_root(0, empty_history_hashes()[HISTORY_DEPTH])
}

/// Bounded prefix frontier; peaks correspond to set count bits, low to high.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize)]
pub struct HistoryFrontier {
    /// Number of occupied consecutive slots starting at zero.
    pub count: u64,
    /// Exactly one complete subtree root for each set bit of `count`.
    pub peaks: Vec<Hash>,
}

impl BorshDeserialize for HistoryFrontier {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let count = u64::deserialize_reader(reader)?;
        let length = u32::deserialize_reader(reader)?;
        if length != count.count_ones() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history frontier shape",
            ));
        }
        let peaks = (0..length)
            .map(|_| Hash::deserialize_reader(reader))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { count, peaks })
    }
}

impl HistoryFrontier {
    /// Frontier for the empty history.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            count: 0,
            peaks: Vec::new(),
        }
    }

    /// Build a frontier from archived context commitments.
    #[must_use]
    pub fn from_leaves(leaves: &[Hash]) -> Option<Self> {
        let mut frontier = Self::empty();
        for leaf in leaves {
            frontier.append(*leaf)?;
        }
        Some(frontier)
    }

    /// Authenticate the canonical prefix shape and derive its counted root.
    #[must_use]
    pub fn root(&self) -> Option<Hash> {
        if self.peaks.len() != self.count.count_ones() as usize {
            return None;
        }
        let empty = empty_history_hashes();
        let mut right = empty[0];
        let mut peaks = self.peaks.iter();
        for (level, empty_subtree) in empty.iter().enumerate().take(HISTORY_DEPTH) {
            right = if (self.count >> level) & 1 == 1 {
                history_node_hash(level, *peaks.next()?, right)
            } else {
                history_node_hash(level, right, *empty_subtree)
            };
        }
        Some(counted_history_root(self.count, right))
    }

    /// Append at the only permitted empty position, without a full-history scan.
    /// Invalid shape or exhausted indexes leave the frontier unchanged.
    pub fn append(&mut self, leaf: Hash) -> Option<Hash> {
        let next = self.count.checked_add(1)?;
        if self.peaks.len() != self.count.count_ones() as usize {
            return None;
        }
        let consumed = self.count.trailing_ones() as usize;
        let mut node = history_leaf_hash(Some(leaf));
        for (level, left) in self.peaks.iter().take(consumed).enumerate() {
            node = history_node_hash(level, *left, node);
        }
        let mut peaks = Vec::with_capacity(self.peaks.len() - consumed + 1);
        peaks.push(node);
        peaks.extend_from_slice(&self.peaks[consumed..]);
        self.count = next;
        self.peaks = peaks;
        self.root()
    }
}

/// Membership of one exact occupied historical index under a counted root.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize)]
pub struct HistoryPath {
    /// Chunk ID, strictly below the authenticated count.
    pub index: u64,
    /// Number of consecutive occupied historical records.
    pub count: u64,
    /// Exactly 64 siblings, starting at leaf height.
    pub siblings: Vec<Hash>,
}

impl BorshDeserialize for HistoryPath {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let index = u64::deserialize_reader(reader)?;
        let count = u64::deserialize_reader(reader)?;
        let length = u32::deserialize_reader(reader)?;
        if index >= count || length != 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history path shape",
            ));
        }
        let siblings = (0..length)
            .map(|_| Hash::deserialize_reader(reader))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            index,
            count,
            siblings,
        })
    }
}

impl HistoryPath {
    /// Build an opening from archived contexts; production stores tree nodes.
    #[must_use]
    pub fn build(leaves: &[Hash], index: usize) -> Option<Self> {
        if index >= leaves.len() {
            return None;
        }
        let count = u64::try_from(leaves.len()).ok()?;
        let empty = empty_history_hashes();
        let mut nodes: Vec<_> = leaves
            .iter()
            .map(|leaf| history_leaf_hash(Some(*leaf)))
            .collect();
        let mut position = index;
        let mut siblings = Vec::with_capacity(HISTORY_DEPTH);
        for (level, empty_subtree) in empty.iter().enumerate().take(HISTORY_DEPTH) {
            siblings.push(nodes.get(position ^ 1).copied().unwrap_or(*empty_subtree));
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    history_node_hash(
                        level,
                        pair[0],
                        pair.get(1).copied().unwrap_or(*empty_subtree),
                    )
                })
                .collect();
            position /= 2;
        }
        Some(Self {
            index: u64::try_from(index).ok()?,
            count,
            siblings,
        })
    }

    /// Verify membership, count, exact depth and occupied-leaf encoding.
    #[must_use]
    pub fn verify(&self, leaf: Hash, expected: Hash) -> bool {
        if self.index >= self.count || self.siblings.len() != HISTORY_DEPTH {
            return false;
        }
        let mut node = history_leaf_hash(Some(leaf));
        for (level, sibling) in self.siblings.iter().enumerate() {
            node = if (self.index >> level) & 1 == 0 {
                history_node_hash(level, node, *sibling)
            } else {
                history_node_hash(level, *sibling, node)
            };
        }
        counted_history_root(self.count, node) == expected
    }
}

/// Build the root of archived contexts. Runtime appends use a frontier instead.
#[must_use]
pub fn history_root(leaves: &[Hash]) -> Hash {
    HistoryFrontier::from_leaves(leaves)
        .and_then(|frontier| frontier.root())
        .expect("history length fits u64")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_history_window_has_exact_inclusive_lower_bound() {
        assert!(!is_recent_history_index(0, 0));
        for count in [1, 7, 8, 9, 10_000, u64::MAX] {
            let first = count.saturating_sub(HISTORY_RETENTION_CHUNKS);
            assert!(is_recent_history_index(first, count));
            assert!(is_recent_history_index(count - 1, count));
            assert!(!is_recent_history_index(count, count));
            if first > 0 {
                assert!(!is_recent_history_index(first - 1, count));
            }
        }
    }

    #[test]
    fn append_and_paths_match_at_power_of_two_boundaries() {
        let mut leaves = Vec::new();
        let mut frontier = HistoryFrontier::empty();
        assert_eq!(frontier.root(), Some(empty_history_root()));
        for index in 0_u64..130 {
            leaves.push(blake3_256(&index.to_le_bytes()));
            let root = frontier.append(*leaves.last().unwrap()).unwrap();
            for position in [0, leaves.len() / 2, leaves.len() - 1] {
                let path = HistoryPath::build(&leaves, position).unwrap();
                assert!(path.verify(leaves[position], root));
                assert_eq!(path.siblings.len(), HISTORY_DEPTH);
            }
            assert!(frontier.peaks.len() <= HISTORY_DEPTH);
        }
    }

    #[test]
    fn malformed_count_paths_and_frontiers_fail_closed() {
        let leaves = [[7; 32], [8; 32], [9; 32]];
        let root = history_root(&leaves);
        let path = HistoryPath::build(&leaves, 1).unwrap();
        let mut wrong = path.clone();
        wrong.count += 1;
        assert!(!wrong.verify(leaves[1], root));
        let mut wrong = path.clone();
        wrong.index = 2;
        assert!(!wrong.verify(leaves[1], root));
        let mut wrong = path.clone();
        wrong.siblings.pop();
        assert!(!wrong.verify(leaves[1], root));
        assert!(borsh::from_slice::<HistoryPath>(&borsh::to_vec(&wrong).unwrap()).is_err());
        let mut wrong = path;
        wrong.siblings[63][0] ^= 1;
        assert!(!wrong.verify(leaves[1], root));
        let mut frontier = HistoryFrontier {
            count: 3,
            peaks: Vec::new(),
        };
        assert!(frontier.root().is_none());
        assert!(frontier.append([1; 32]).is_none());
        assert_eq!(frontier.count, 3);
        assert!(borsh::from_slice::<HistoryFrontier>(&borsh::to_vec(&frontier).unwrap()).is_err());
    }

    #[test]
    fn high_counts_keep_bounded_shape_and_overflow_does_not_mutate() {
        let empty = empty_history_hashes();
        for count in [1 << 32, (1 << 63) - 1, 1 << 63, u64::MAX - 1] {
            let mut frontier = HistoryFrontier {
                count,
                peaks: (0..HISTORY_DEPTH)
                    .filter(|level| (count >> level) & 1 == 1)
                    .map(|level| empty[level])
                    .collect(),
            };
            assert!(frontier.root().is_some());
            assert!(frontier.append([1; 32]).is_some());
            assert!(frontier.peaks.len() <= HISTORY_DEPTH);
        }
        let mut full = HistoryFrontier {
            count: u64::MAX,
            peaks: alloc::vec![[1; 32]; 64],
        };
        let before = full.clone();
        assert!(full.append([2; 32]).is_none());
        assert_eq!(full, before);
        assert_ne!(history_leaf_hash(None), history_leaf_hash(Some([0; 32])));
    }
}
