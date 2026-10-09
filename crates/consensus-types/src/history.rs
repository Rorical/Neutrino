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
    is_history_index_within(index, count, HISTORY_RETENTION_CHUNKS)
}

/// Whether an index belongs to the `window` finalized chunks before `count`.
#[must_use]
pub const fn is_history_index_within(index: u64, count: u64, window: u64) -> bool {
    index < count && index >= count.saturating_sub(window)
}

/// Default number of preceding finalized chunks whose complete historical
/// records (validator vector, seed, certificate) a full node keeps so safety
/// evidence can still be constructed locally.
///
/// Safety claims have no age window, so this is a local service horizon, not
/// an admissibility bound. A still-bonded validator may have signed outside
/// this window. Older records and their openings require a retaining reporter
/// or archive node; ordinary nodes keep bounded cached openings. The
/// eight-chunk liveness window is never shrunk.
#[must_use]
pub const fn history_record_window_chunks(unbonding_delay_blocks: u64, chunk_size: u64) -> u64 {
    if chunk_size == 0 {
        return HISTORY_RETENTION_CHUNKS;
    }
    let chunks = unbonding_delay_blocks.div_ceil(chunk_size);
    if chunks > HISTORY_RETENTION_CHUNKS {
        chunks
    } else {
        HISTORY_RETENTION_CHUNKS
    }
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

    /// Open the next appended leaf using only this bounded frontier.
    /// Invalid shape or exhausted indexes return no path; the frontier is unchanged.
    #[must_use]
    pub fn append_path(&self, leaf: Hash) -> Option<HistoryPath> {
        let count = self.count.checked_add(1)?;
        if self.peaks.len() != self.count.count_ones() as usize {
            return None;
        }
        let empty = empty_history_hashes();
        let mut peaks = self.peaks.iter();
        let mut siblings = Vec::with_capacity(HISTORY_DEPTH);
        for (level, empty_subtree) in empty.iter().enumerate().take(HISTORY_DEPTH) {
            siblings.push(if (self.count >> level) & 1 == 1 {
                *peaks.next()?
            } else {
                *empty_subtree
            });
        }
        let path = HistoryPath {
            index: self.count,
            count,
            siblings,
        };
        let mut next = self.clone();
        path.verify(leaf, next.append(leaf)?).then_some(path)
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
    /// Build an opening from archived contexts.
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

    /// Authenticate and advance this opening over one finalized append.
    /// Only the sibling shared with the appended leaf changes. Returns the new
    /// counted root; invalid inputs or exhausted indexes leave the path unchanged.
    pub fn advance(
        &mut self,
        leaf: Hash,
        frontier: &HistoryFrontier,
        appended_leaf: Hash,
    ) -> Option<Hash> {
        if self.count != frontier.count || !self.verify(leaf, frontier.root()?) {
            return None;
        }
        let insertion = frontier.append_path(appended_leaf)?;
        // Membership above guarantees index < count, so the xor is nonzero.
        let changed_level = usize::try_from((self.index ^ frontier.count).ilog2()).ok()?;
        let mut sibling = history_leaf_hash(Some(appended_leaf));
        for (level, other) in insertion.siblings.iter().take(changed_level).enumerate() {
            sibling = if (frontier.count >> level) & 1 == 0 {
                history_node_hash(level, sibling, *other)
            } else {
                history_node_hash(level, *other, sibling)
            };
        }
        let mut next_frontier = frontier.clone();
        let root = next_frontier.append(appended_leaf)?;
        let mut next_path = self.clone();
        next_path.siblings[changed_level] = sibling;
        next_path.count = insertion.count;
        if !next_path.verify(leaf, root) {
            return None;
        }
        *self = next_path;
        Some(root)
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
    fn history_record_window_covers_one_unbonding_delay_of_records() {
        // 1,152 blocks of 128-block chunks: nine chunks.
        assert_eq!(history_record_window_chunks(1_152, 128), 9);
        // Fourteen days of 4 s slots at the default chunk size.
        assert_eq!(history_record_window_chunks(302_400, 128), 2_363);
        // A delay shorter than eight chunks never shrinks ordinary retention.
        assert_eq!(
            history_record_window_chunks(1, 128),
            HISTORY_RETENTION_CHUNKS
        );
        assert_eq!(
            history_record_window_chunks(10, 0),
            HISTORY_RETENTION_CHUNKS
        );
        assert!(is_history_index_within(0, 9, 9));
        assert!(!is_history_index_within(0, 10, 9));
        assert!(!is_history_index_within(10, 10, 9));
    }

    #[test]
    fn append_and_paths_match_at_power_of_two_boundaries() {
        let mut leaves = Vec::new();
        let mut frontier = HistoryFrontier::empty();
        assert_eq!(frontier.root(), Some(empty_history_root()));
        for index in 0_u64..260 {
            let positions = [
                0,
                leaves.len() / 3,
                leaves.len() / 2,
                leaves.len().saturating_sub(1),
            ];
            let paths: Vec<_> = positions
                .into_iter()
                .filter_map(|position| {
                    HistoryPath::build(&leaves, position).map(|path| (position, path))
                })
                .collect();
            let before = frontier.clone();
            leaves.push(blake3_256(&index.to_le_bytes()));
            let appended_leaf = *leaves.last().unwrap();
            let insertion = frontier.append_path(appended_leaf).unwrap();
            assert_eq!(frontier, before);
            let root = frontier.append(appended_leaf).unwrap();
            assert_eq!(
                insertion,
                HistoryPath::build(&leaves, leaves.len() - 1).unwrap()
            );
            assert!(insertion.verify(appended_leaf, root));
            for (position, mut path) in paths {
                let prior_siblings = path.siblings.clone();
                let changed_level = usize::try_from((path.index ^ before.count).ilog2()).unwrap();
                assert_eq!(
                    path.advance(leaves[position], &before, appended_leaf),
                    Some(root)
                );
                assert_eq!(path, HistoryPath::build(&leaves, position).unwrap());
                for (level, sibling) in prior_siblings.iter().enumerate() {
                    if level != changed_level {
                        assert_eq!(path.siblings[level], *sibling);
                    }
                }
            }
            for position in [0, leaves.len() / 2, leaves.len() - 1] {
                let path = HistoryPath::build(&leaves, position).unwrap();
                assert!(path.verify(leaves[position], root));
                assert_eq!(path.siblings.len(), HISTORY_DEPTH);
            }
            assert!(frontier.peaks.len() <= HISTORY_DEPTH);
        }
    }

    #[test]
    fn cached_old_paths_advance_without_archived_leaves() {
        let mut frontier = HistoryFrontier::empty();
        let mut retained = Vec::new();
        for index in 0_u64..260 {
            let leaf = blake3_256(&index.to_le_bytes());
            let insertion = frontier.append_path(leaf).unwrap();
            for (retained_leaf, path) in &mut retained {
                assert!(HistoryPath::advance(path, *retained_leaf, &frontier, leaf).is_some());
            }
            let root = frontier.append(leaf).unwrap();
            if index == 0 || index.is_power_of_two() || index == 259 {
                retained.push((leaf, insertion));
            }
            for (retained_leaf, path) in &retained {
                assert!(path.verify(*retained_leaf, root));
            }
        }
        assert_eq!(retained.first().unwrap().1.index, 0);
        assert_eq!(retained.first().unwrap().1.count, 260);
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
    fn invalid_path_advancement_never_mutates() {
        let leaves = [[7; 32], [8; 32], [9; 32]];
        let frontier = HistoryFrontier::from_leaves(&leaves).unwrap();
        let path = HistoryPath::build(&leaves, 1).unwrap();
        let mut malformed_paths = Vec::new();
        let mut wrong = path.clone();
        wrong.count += 1;
        malformed_paths.push(wrong);
        let mut wrong = path.clone();
        wrong.index = wrong.count;
        malformed_paths.push(wrong);
        let mut wrong = path.clone();
        wrong.index = 0;
        malformed_paths.push(wrong);
        let mut wrong = path.clone();
        wrong.siblings.pop();
        malformed_paths.push(wrong);
        let mut wrong = path.clone();
        wrong.siblings.push([0; 32]);
        malformed_paths.push(wrong);
        let mut wrong = path.clone();
        wrong.siblings[63][0] ^= 1;
        malformed_paths.push(wrong);
        for mut malformed in malformed_paths {
            let before = malformed.clone();
            assert!(malformed.advance(leaves[1], &frontier, [10; 32]).is_none());
            assert_eq!(malformed, before);
        }
        let mut wrong_leaf = path.clone();
        assert!(wrong_leaf.advance([0; 32], &frontier, [10; 32]).is_none());
        assert_eq!(wrong_leaf, path);
        let mut malformed_frontiers = Vec::new();
        let mut wrong = frontier.clone();
        wrong.peaks.pop();
        malformed_frontiers.push(wrong);
        let mut wrong = frontier.clone();
        wrong.peaks[0][0] ^= 1;
        malformed_frontiers.push(wrong);
        let mut wrong = frontier;
        wrong.count += 1;
        malformed_frontiers.push(wrong);
        for malformed in malformed_frontiers {
            let mut unchanged = path.clone();
            assert!(unchanged.advance(leaves[1], &malformed, [10; 32]).is_none());
            assert_eq!(unchanged, path);
        }
        let malformed = HistoryFrontier {
            count: 3,
            peaks: Vec::new(),
        };
        assert!(malformed.append_path([10; 32]).is_none());
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
            let before = frontier.clone();
            let mut path = frontier.append_path([1; 32]).unwrap();
            assert_eq!(frontier, before);
            assert!(frontier.root().is_some());
            let root = frontier.append([1; 32]).unwrap();
            assert!(path.verify([1; 32], root));
            let path_before = path.clone();
            if frontier.count == u64::MAX {
                assert!(path.advance([1; 32], &frontier, [2; 32]).is_none());
                assert_eq!(path, path_before);
            } else {
                let next_root = path.advance([1; 32], &frontier, [2; 32]).unwrap();
                assert_eq!(frontier.append([2; 32]), Some(next_root));
                assert!(path.verify([1; 32], next_root));
            }
            assert!(frontier.peaks.len() <= HISTORY_DEPTH);
        }
        let mut full = HistoryFrontier {
            count: u64::MAX,
            peaks: alloc::vec![[1; 32]; 64],
        };
        let before = full.clone();
        assert!(full.append_path([2; 32]).is_none());
        assert!(full.append([2; 32]).is_none());
        assert_eq!(full, before);
        assert_ne!(history_leaf_hash(None), history_leaf_hash(Some([0; 32])));
    }
}
