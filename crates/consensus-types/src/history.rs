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
    let mut bytes = [0; 49];
    bytes[..16].copy_from_slice(&DOMAIN_HISTORY_LEAF);
    let Some(value) = value else {
        return blake3_256(&bytes[..17]);
    };
    bytes[16] = 1;
    bytes[17..].copy_from_slice(&value);
    blake3_256(&bytes)
}

/// Hash children of height `level`; level zero combines historical leaves.
#[must_use]
pub fn history_node_hash(level: usize, left: Hash, right: Hash) -> Hash {
    assert!(level < HISTORY_DEPTH, "historical node level");
    let mut bytes = [0; 81];
    bytes[..16].copy_from_slice(&DOMAIN_HISTORY_NODE);
    bytes[16] = u8::try_from(level).expect("bounded history depth");
    bytes[17..49].copy_from_slice(&left);
    bytes[49..].copy_from_slice(&right);
    blake3_256(&bytes)
}

/// Empty subtree hashes, indexed by height (zero is an empty leaf).
///
/// Generated from `history_leaf_hash(None)` and
/// `history_node_hash(level, empty[level], empty[level])`; a unit test checks
/// every entry against that recursive definition.
pub const EMPTY_HISTORY_HASHES: [Hash; HISTORY_DEPTH + 1] = [
    hex32(b"8a88770f3a637fcf0f3a8cba69efd57bb9b9e3466825f3c13cb745f47b4095f1"),
    hex32(b"46399fac029b7cc8beb8de5825766612a89b49afdd3e7ec69dad454c1421989d"),
    hex32(b"b2fb51bcf193180e98aa0f58fa5a08823ce701d243a331e74d4790571da63dc1"),
    hex32(b"c0d15d5210adae82fc3b45650e9122bcb2ef2f12b7fc592176cea1bf95c07f8c"),
    hex32(b"9a703fed85d0bfc1f65a3870754cbf4160fe4680209cae4f165c844126e0897b"),
    hex32(b"fd00f94b55baa9d1261622685cb7cd13e9cf4a7fa9998b751e4305f945a3e6f6"),
    hex32(b"3173634146113edbed8e0579a0a8d24081321c371bafa777bd795f24572abf63"),
    hex32(b"6c84b4be78b38adcc87aca12aa60cb1cb1fdc2a6f49220f2793098a052d1b44e"),
    hex32(b"49ee7cdcf10d5795a07bd2cb2ece9ae698608a6158900c143e2d8deeccecaa3d"),
    hex32(b"9f5c16b44a0876ad2105aecfd05a0a16b4c87cb8ccc1fc608ffd63be6c2c51ff"),
    hex32(b"2b66cd0d9f5521eef16ed615c59a6bcacc1603b7418024ddf51c3cbd1543ec79"),
    hex32(b"73f22f071efae107acbb88ffce33f3dddea9e98c32246b58dfb1be957f5820ae"),
    hex32(b"217d7cf2fef1caa26a1247dafb02848409031cc80fec007af7cae67381aee8de"),
    hex32(b"de59b62a3944bacfd4c98fe3e35a23905f8621e29010727aad1a5a877227361d"),
    hex32(b"176909573b00dc653daaae498187ac286f3c94e14f367b47d54416c99516723e"),
    hex32(b"c0a2af6119aad5ec0736af78c5a165444cdc4f92baff44f4f39f6988943b0e97"),
    hex32(b"aa778aceeb367b41013f1bd040fe4b306a92124581503dfd409de57a23650b09"),
    hex32(b"973893646f98fc472660df9041100d608ea2ac9e89b40a59ebb5372f9205174b"),
    hex32(b"e392a5cc97426168b417393b8c6d0c1574917088d7bdbdf931951254fc1283df"),
    hex32(b"20f590773357c98d7445ac3b9886ce2377ea48536793f30e2f4fb7d3137f661b"),
    hex32(b"531c266d212bb74b0cae6b8e3036f62f32907c122576ae36dab5ccf982d4099c"),
    hex32(b"e12935777892fc7da1cceb178c373c00d6d558848589e13309dac7d57f5be266"),
    hex32(b"2fe7a8ae1394f7774ac6f7d6d4f511efff67b002de286592fc7a3f39a5643738"),
    hex32(b"0ea77cf4e43d261283a228b333a091236a2905740bd025224c0d1d6e85c7dbd7"),
    hex32(b"8e9eaf8e392372dd9b5ab50e06634c6a11bb5a4093a18afe88470bb27924967f"),
    hex32(b"143ecf34d111f746579c38d072f64e8574b37ceb2cdf6fccce884a90f284bfc4"),
    hex32(b"9ffeb2d95690a8d484dad31d36eafdf86abf8feed64f8757b0f1cbbc1d8869d1"),
    hex32(b"28e3b3aae401117337d8ff650284771c8119d4cfd957f13a2ad19e889f4e15e7"),
    hex32(b"0e9ef20b03440db4076fbaea366048f693f840f1a88b1ffc5b58107d22fe9bd4"),
    hex32(b"b294b4c8973ebef78eee75adff26b17d4c98bec7abfe4ea3d5b5eb0e665ba82f"),
    hex32(b"b04e8532a04ad628607f955b6cdcae1c6fcedd40d23db6df7d1d1eb23c8186e0"),
    hex32(b"8b64973da6905eddb8611e58c7b436bdab5b3fa6983167b742c811dc9dccc622"),
    hex32(b"d7c59733206696ba57c75aceecb13c343f2c7b0d350f894b07b906e323f1c8fa"),
    hex32(b"9e5a5a897bac3131777d166cb639835136ad424acaf3eab02f9fc8c8c96cf367"),
    hex32(b"13f3ee6e15d14e44739505bf2e7b78b2b0442bce963b2e1f287f4383eff1a10b"),
    hex32(b"2beb30f43075cc540254622a54431996bd0dd3679485b64c7ac567158b760cc3"),
    hex32(b"65fd923a6be396089d361b898eb2904d6c391a5b58740a1f227ce5ecc4c3dba2"),
    hex32(b"5b6a4860dbf2b768ea2f452bfbb1e674dba7b72c65c2123a6d0bd6e7d182ea9c"),
    hex32(b"117b34b97ffa239fb332b192a2bf086a9057c0ca4f140e7caba34f4af0cdcbeb"),
    hex32(b"5b58221285f0f8e88368ec7cfbfe21c4b1f4ff45c88abbfa1088f5f442860c08"),
    hex32(b"e7c27868ab0e6f6273a4ceb8efeea8e403e503e65afaf660158d7e993c6e84c9"),
    hex32(b"8b67d8304289d556221f5fe459971556902d5e42cc952bf5e801c4308075116c"),
    hex32(b"313aec27edc94e040dc4f146562fd2e249221a556653de1fef5feceda12a8f07"),
    hex32(b"17856cd0e73d2f6ef1492a5aff4901c55de091642284704a8cbe455b5fa2384a"),
    hex32(b"797c59239190138cb08731a7424871a745498268287d96910b21d6b9ff377c59"),
    hex32(b"db464ec86418afffa2612bfd92055b92b93265ce08fdd3e749981940fb3b1aa3"),
    hex32(b"66a45b821c306c8848b8fc192faedd00ae629ec1ce1a6e89db461a644fd34291"),
    hex32(b"9fe94d15192b630254c346a127e37a452242b6dcec56d63617e8102827b7a048"),
    hex32(b"28e984f6254d67af59a5efb0362d6cb077dcccfa1cb43e807353305a8fc73338"),
    hex32(b"d59ea2fa8a81dff553e92dd037ddc7df1aa58a3aa26993f18056ffeb5893acd6"),
    hex32(b"58065b90bfd299e34c30e259a0532beb41f6d9e50a87b0c88f72ff23ec9db27a"),
    hex32(b"513cef5d3955dd484d23036b51f631270cfe06af7a81c65fb1e4bac5f26b3abf"),
    hex32(b"dabb471e1ea2426e00748fab1cf5da34594df002f3759305778aa1a0d492b048"),
    hex32(b"46a718d96832f0c1fadf61549b9dade7a1d6bb38ac8e7b459b2c0118e287e3be"),
    hex32(b"98308079b9093f31056f4596fa268a0602bc9956fb6b9717d41581e2181dcc15"),
    hex32(b"ff134800208ed5974e7500a4ffbbbdf88eb292508069c4f7aa40867a297dda74"),
    hex32(b"eb0880e919981d5783c73b97f72cd41b4951b16b552534d3850fa50ce66f7536"),
    hex32(b"45a33616fe6adcf7fd8a50afec9c3c77a9b93b5cd3f2e1ad7b54934012f8190d"),
    hex32(b"d0c7eb911b67ec54a72a5c82ffba38aab0182d83cd1e577ae53f186f2ab47ec7"),
    hex32(b"aab8fb38ed95b1bbed08ae179608a92d05836a899461d20aba5639688a872f92"),
    hex32(b"32b41bb545e6b32988f8d78dde1d003e4939d662022f22d58d8a1dbcf3335bc1"),
    hex32(b"bc9f002f82af0a44057d86ee772d3cbe73e39edad16b627ddb1742e7545b3315"),
    hex32(b"231a453aa09c002be36befce24e4957c268028a2f98d3217a9437bb3ba22f7c2"),
    hex32(b"7c898f365ccd56997df2bb1320655f6202a16b9cfccadc120747b35e9b80c6de"),
    hex32(b"f4eac5417d194c3e3e336f4bfc9138ba8ee2a3583dce28e71ce26c70c88f7fb7"),
];

/// Canonical genesis historical commitment,
/// `counted_history_root(0, EMPTY_HISTORY_HASHES[HISTORY_DEPTH])`.
pub const EMPTY_HISTORY_ROOT: Hash =
    hex32(b"1a91de02bbb65cdd75d3ca5b4d4424643aa20a0e6ce91d5e5380de072928439f");

/// Decode 64 lowercase hexadecimal digits at compile time.
const fn hex32(digits: &[u8; 64]) -> Hash {
    const fn nibble(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            _ => panic!("lowercase hexadecimal digit"),
        }
    }
    let mut bytes = [0; 32];
    let mut index = 0;
    while index < 32 {
        bytes[index] = (nibble(digits[2 * index]) << 4) | nibble(digits[2 * index + 1]);
        index += 1;
    }
    bytes
}

/// Empty subtree hashes, indexed by height (zero is an empty leaf).
#[must_use]
pub const fn empty_history_hashes() -> [Hash; HISTORY_DEPTH + 1] {
    EMPTY_HISTORY_HASHES
}

/// Bind the append position to the tree commitment.
#[must_use]
pub fn counted_history_root(count: u64, root: Hash) -> Hash {
    let mut bytes = [0; 56];
    bytes[..16].copy_from_slice(&DOMAIN_HISTORY_ROOT);
    bytes[16..24].copy_from_slice(&count.to_le_bytes());
    bytes[24..].copy_from_slice(&root);
    blake3_256(&bytes)
}

/// Canonical genesis historical commitment.
#[must_use]
pub const fn empty_history_root() -> Hash {
    EMPTY_HISTORY_ROOT
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
        let empty = &EMPTY_HISTORY_HASHES;
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
        let empty = &EMPTY_HISTORY_HASHES;
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
        let empty = &EMPTY_HISTORY_HASHES;
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

    fn tagged(parts: &[&[u8]]) -> Hash {
        blake3_256(&parts.concat())
    }

    #[test]
    fn generated_empty_hashes_match_the_recursive_definition() {
        let mut empty = [[0; 32]; HISTORY_DEPTH + 1];
        empty[0] = history_leaf_hash(None);
        for level in 0..HISTORY_DEPTH {
            empty[level + 1] = history_node_hash(level, empty[level], empty[level]);
        }
        assert_eq!(EMPTY_HISTORY_HASHES, empty);
        assert_eq!(empty_history_hashes(), empty);
        assert_eq!(
            EMPTY_HISTORY_ROOT,
            counted_history_root(0, empty[HISTORY_DEPTH])
        );
        assert_eq!(empty_history_root(), EMPTY_HISTORY_ROOT);
        assert_eq!(HistoryFrontier::empty().root(), Some(EMPTY_HISTORY_ROOT));
    }

    #[test]
    fn fixed_preimages_match_tagged_concatenation() {
        let (left, right) = ([7; 32], [9; 32]);
        assert_eq!(
            history_leaf_hash(None),
            tagged(&[&DOMAIN_HISTORY_LEAF, &[0]])
        );
        assert_eq!(
            history_leaf_hash(Some(left)),
            tagged(&[&DOMAIN_HISTORY_LEAF, &[1], &left])
        );
        for level in [0, 1, HISTORY_DEPTH - 1] {
            assert_eq!(
                history_node_hash(level, left, right),
                tagged(&[
                    &DOMAIN_HISTORY_NODE,
                    &[u8::try_from(level).unwrap()],
                    &left,
                    &right,
                ])
            );
        }
        for count in [0, 5, u64::MAX] {
            assert_eq!(
                counted_history_root(count, left),
                tagged(&[&DOMAIN_HISTORY_ROOT, &count.to_le_bytes(), &left])
            );
        }
    }

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
