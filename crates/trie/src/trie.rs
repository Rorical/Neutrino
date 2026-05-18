//! In-memory binary sparse Merkle trie with prefix compression.
//!
//! See `docs/design/05-state-and-storage.md` for the protocol-level
//! design. This crate ships the M0 reference implementation: an
//! in-memory node store, BLAKE3 hasher, and full read/write/proof
//! support. Production storage and pruning live in `neutrino-storage`
//! and the consensus engine; this crate stays no_std + alloc and
//! depends only on `neutrino-primitives`.
//!
//! # Constraints
//!
//! * Raw runtime keys are length-prefixed before they become trie bit
//!   paths, so arbitrary byte keys are supported, including pairs where
//!   one raw key is a prefix of another.
//! * Empty values are allowed; they hash to a well-defined value via
//!   [`Hasher::hash_value`].
//! * The empty trie has root [`crate::EMPTY_TRIE_ROOT`] (`[0; 32]`).

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use neutrino_primitives::{Hash, ZERO_HASH};

use crate::bits::BitPath;
use crate::error::TrieError;
use crate::hasher::{Blake3Hasher, Hasher};
use crate::node::Node;
use crate::proof::{Proof, ProofStep, ProofTerminal};

/// Binary sparse Merkle trie parameterised by hash function. Defaults
/// to [`Blake3Hasher`].
///
/// The trie buffers every newly produced node and value in
/// `pending_nodes` / `pending_values` so callers wanting persistence
/// (the consensus engine) can drain just the deltas after each block.
/// Drained entries are not removed from the in-memory map; the buffers
/// only describe what is *new since the last drain*, mirroring the
/// content-addressed RocksDB columns the engine writes them to.
#[derive(Clone, Debug)]
pub struct Trie<H: Hasher = Blake3Hasher> {
    nodes: BTreeMap<Hash, Vec<u8>>,
    values: BTreeMap<Hash, Vec<u8>>,
    pending_nodes: Vec<(Hash, Vec<u8>)>,
    pending_values: Vec<(Hash, Vec<u8>)>,
    root: Hash,
    _phantom: PhantomData<H>,
}

impl<H: Hasher> Default for Trie<H> {
    fn default() -> Self {
        Self {
            nodes: BTreeMap::new(),
            values: BTreeMap::new(),
            pending_nodes: Vec::new(),
            pending_values: Vec::new(),
            root: ZERO_HASH,
            _phantom: PhantomData,
        }
    }
}

impl<H: Hasher> Trie<H> {
    /// Build a fresh empty trie. Root is [`crate::EMPTY_TRIE_ROOT`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current trie root.
    #[must_use]
    pub const fn root(&self) -> Hash {
        self.root
    }

    /// Total number of distinct nodes ever produced. Reflects the
    /// crate's append-only node store; production storage handles
    /// refcounted pruning out-of-band.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total number of distinct values ever stored. Append-only for
    /// the same reason as [`Trie::node_count`].
    #[must_use]
    pub fn value_count(&self) -> usize {
        self.values.len()
    }

    /// Drain every trie-node `(hash, bytes)` pair produced since the
    /// previous call.
    ///
    /// Used by the consensus engine to persist the delta into the
    /// `TrieNodes` storage column without re-writing the entire
    /// content-addressed node store on every block.
    pub fn drain_pending_nodes(&mut self) -> Vec<(Hash, Vec<u8>)> {
        core::mem::take(&mut self.pending_nodes)
    }

    /// Drain every state-value `(hash, bytes)` pair newly inserted
    /// since the previous call. See [`Trie::drain_pending_nodes`] for
    /// rationale.
    pub fn drain_pending_values(&mut self) -> Vec<(Hash, Vec<u8>)> {
        core::mem::take(&mut self.pending_values)
    }

    /// Rebuild a trie from persisted state.
    ///
    /// `root` is the previously committed trie root; `nodes` and
    /// `values` are the full content-addressed contents of the
    /// `TrieNodes` and `StateValues` storage columns. No
    /// `pending_nodes` / `pending_values` are recorded because the
    /// persisted entries are, by definition, already on disk.
    ///
    /// The constructor performs no integrity check beyond storing
    /// every pair as-is: a node whose hash does not match its bytes
    /// will surface as a panic at the next [`Trie::get`] / [`Trie::prove`]
    /// call. Callers wanting strong guarantees should hash-check the
    /// pairs against their keys before passing them in.
    #[must_use]
    pub fn from_persisted(
        root: Hash,
        nodes: impl IntoIterator<Item = (Hash, Vec<u8>)>,
        values: impl IntoIterator<Item = (Hash, Vec<u8>)>,
    ) -> Self {
        Self {
            nodes: nodes.into_iter().collect(),
            values: values.into_iter().collect(),
            pending_nodes: Vec::new(),
            pending_values: Vec::new(),
            root,
            _phantom: PhantomData,
        }
    }

    /// Read the value bytes for `key`. Returns `None` for keys not in
    /// the trie.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let path = BitPath::for_key(key);
        let mut current = self.root;
        let mut consumed: u32 = 0;
        loop {
            if current == ZERO_HASH {
                return None;
            }
            let node = self.fetch_node(&current);
            match node {
                Node::Leaf {
                    key_suffix,
                    value_hash,
                } => {
                    let remaining = path.suffix(consumed);
                    if remaining == key_suffix {
                        return self.values.get(&value_hash).cloned();
                    }
                    return None;
                }
                Node::Branch { left, right } => {
                    if consumed >= path.bit_len() {
                        return None;
                    }
                    let bit = path.bit(consumed);
                    consumed += 1;
                    current = if bit { right } else { left };
                }
                Node::Extension { prefix, child } => {
                    let len = prefix.bit_len();
                    if consumed + len > path.bit_len() {
                        return None;
                    }
                    let segment = path.suffix(consumed).prefix(len);
                    if segment != prefix {
                        return None;
                    }
                    consumed += len;
                    current = child;
                }
            }
        }
    }

    /// Return every raw runtime key currently present in the trie.
    ///
    /// Keys are reconstructed from leaf paths by removing the trie-internal
    /// `u32::LE length || key` prefix used by [`Trie::insert`]. The returned
    /// list is sorted lexicographically so callers can implement cursored
    /// state iteration without depending on the Patricia node shape.
    #[must_use]
    pub fn keys(&self) -> Vec<Vec<u8>> {
        let mut keys = Vec::new();
        let mut prefix = Vec::new();
        self.collect_keys(self.root, &mut prefix, &mut keys);
        keys.sort();
        keys
    }

    /// Insert (or overwrite) the value at `key`. Returns
    /// [`TrieError::PrefixCollision`] if a malformed internal path
    /// would create a prefix-colliding pair. Normal byte-string keys
    /// are length-prefixed before insertion, so callers should not see
    /// that error in practice.
    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) -> Result<(), TrieError> {
        let path = BitPath::for_key(key);
        let value_hash = H::hash_value(&value);
        if self.values.insert(value_hash, value.clone()).is_none() {
            self.pending_values.push((value_hash, value));
        }
        let new_root = self.insert_at(self.root, &path, value_hash)?;
        self.root = new_root;
        Ok(())
    }

    /// Remove the value at `key` and return it if present.
    pub fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let path = BitPath::for_key(key);
        let (new_root, removed) = self.remove_at(self.root, &path);
        self.root = new_root;
        removed.and_then(|value_hash| self.values.get(&value_hash).cloned())
    }

    /// Build an inclusion or exclusion proof for `key` against the
    /// current root.
    #[must_use]
    pub fn prove(&self, key: &[u8]) -> Proof {
        let path = BitPath::for_key(key);
        let mut steps = Vec::new();
        let mut current = self.root;
        let mut consumed: u32 = 0;
        loop {
            if current == ZERO_HASH {
                return Proof {
                    steps,
                    terminal: ProofTerminal::Empty,
                };
            }
            let node = self.fetch_node(&current);
            match node {
                Node::Leaf {
                    key_suffix,
                    value_hash,
                } => {
                    return Proof {
                        steps,
                        terminal: ProofTerminal::Leaf {
                            key_suffix,
                            value_hash,
                        },
                    };
                }
                Node::Branch { left, right } => {
                    if consumed >= path.bit_len() {
                        // No more key bits left, but the trie demands
                        // we descend. With prefix-free keys this is
                        // unreachable; defensively terminate as empty.
                        return Proof {
                            steps,
                            terminal: ProofTerminal::Empty,
                        };
                    }
                    let bit = path.bit(consumed);
                    let (sibling, child) = if bit { (left, right) } else { (right, left) };
                    steps.push(ProofStep::Branch {
                        sibling,
                        descended_right: bit,
                    });
                    consumed += 1;
                    current = child;
                }
                Node::Extension { prefix, child } => {
                    let len = prefix.bit_len();
                    let remaining = path.suffix(consumed);
                    let common = prefix.common_prefix_len(&remaining);
                    if common == len {
                        steps.push(ProofStep::Extension { prefix });
                        consumed += len;
                        current = child;
                    } else {
                        return Proof {
                            steps,
                            terminal: ProofTerminal::DivergentExtension {
                                prefix,
                                child_hash: child,
                            },
                        };
                    }
                }
            }
        }
    }

    fn fetch_node(&self, hash: &Hash) -> Node {
        let bytes = self
            .nodes
            .get(hash)
            .expect("trie invariant: every reachable hash is in the node store");
        Node::decode(bytes).expect("trie invariant: stored node bytes are canonical")
    }

    fn collect_keys(&self, hash: Hash, prefix: &mut Vec<bool>, keys: &mut Vec<Vec<u8>>) {
        if hash == ZERO_HASH {
            return;
        }
        match self.fetch_node(&hash) {
            Node::Leaf { key_suffix, .. } => {
                let original_len = prefix.len();
                append_bits(prefix, &key_suffix);
                if let Some(key) = decode_raw_key(prefix) {
                    keys.push(key);
                }
                prefix.truncate(original_len);
            }
            Node::Branch { left, right } => {
                prefix.push(false);
                self.collect_keys(left, prefix, keys);
                prefix.pop();
                prefix.push(true);
                self.collect_keys(right, prefix, keys);
                prefix.pop();
            }
            Node::Extension { prefix: ext, child } => {
                let original_len = prefix.len();
                append_bits(prefix, &ext);
                self.collect_keys(child, prefix, keys);
                prefix.truncate(original_len);
            }
        }
    }

    fn store_node(&mut self, node: &Node) -> Hash {
        let encoded = node.encode();
        let hash = H::hash_node(&encoded);
        if self.nodes.insert(hash, encoded.clone()).is_none() {
            self.pending_nodes.push((hash, encoded));
        }
        hash
    }

    fn insert_at(
        &mut self,
        node_hash: Hash,
        path: &BitPath,
        value_hash: Hash,
    ) -> Result<Hash, TrieError> {
        if node_hash == ZERO_HASH {
            return Ok(self.store_node(&Node::Leaf {
                key_suffix: path.clone(),
                value_hash,
            }));
        }

        let node = self.fetch_node(&node_hash);
        match node {
            Node::Leaf {
                key_suffix,
                value_hash: existing_vh,
            } => self.insert_into_leaf(key_suffix, existing_vh, path, value_hash),
            Node::Branch { left, right } => {
                if path.is_empty() {
                    return Err(TrieError::PrefixCollision);
                }
                let bit = path.bit(0);
                let rest = path.suffix(1);
                let (new_left, new_right) = if bit {
                    (left, self.insert_at(right, &rest, value_hash)?)
                } else {
                    (self.insert_at(left, &rest, value_hash)?, right)
                };
                Ok(self.store_node(&Node::Branch {
                    left: new_left,
                    right: new_right,
                }))
            }
            Node::Extension { prefix, child } => {
                self.insert_into_extension(prefix, child, path, value_hash)
            }
        }
    }

    fn insert_into_leaf(
        &mut self,
        existing_suffix: BitPath,
        existing_vh: Hash,
        path: &BitPath,
        value_hash: Hash,
    ) -> Result<Hash, TrieError> {
        if existing_suffix.bit_len() == path.bit_len() && &existing_suffix == path {
            return Ok(self.store_node(&Node::Leaf {
                key_suffix: existing_suffix,
                value_hash,
            }));
        }
        let common = existing_suffix.common_prefix_len(path);
        if common == existing_suffix.bit_len() || common == path.bit_len() {
            return Err(TrieError::PrefixCollision);
        }

        let existing_bit = existing_suffix.bit(common);
        let existing_tail = existing_suffix.suffix(common + 1);
        let new_tail = path.suffix(common + 1);

        let existing_leaf_hash = self.store_node(&Node::Leaf {
            key_suffix: existing_tail,
            value_hash: existing_vh,
        });
        let new_leaf_hash = self.store_node(&Node::Leaf {
            key_suffix: new_tail,
            value_hash,
        });

        let branch = if existing_bit {
            Node::Branch {
                left: new_leaf_hash,
                right: existing_leaf_hash,
            }
        } else {
            Node::Branch {
                left: existing_leaf_hash,
                right: new_leaf_hash,
            }
        };
        let branch_hash = self.store_node(&branch);
        if common == 0 {
            Ok(branch_hash)
        } else {
            Ok(self.store_node(&Node::Extension {
                prefix: path.prefix(common),
                child: branch_hash,
            }))
        }
    }

    fn insert_into_extension(
        &mut self,
        prefix: BitPath,
        child: Hash,
        path: &BitPath,
        value_hash: Hash,
    ) -> Result<Hash, TrieError> {
        let common = prefix.common_prefix_len(path);
        if common == prefix.bit_len() {
            let rest = path.suffix(common);
            if rest.is_empty() {
                return Err(TrieError::PrefixCollision);
            }
            let new_child = self.insert_at(child, &rest, value_hash)?;
            return Ok(self.store_node(&Node::Extension {
                prefix,
                child: new_child,
            }));
        }
        if common == path.bit_len() {
            return Err(TrieError::PrefixCollision);
        }

        let existing_bit = prefix.bit(common);
        let existing_tail = prefix.suffix(common + 1);
        let new_tail = path.suffix(common + 1);

        let existing_side_hash = if existing_tail.is_empty() {
            child
        } else {
            self.store_node(&Node::Extension {
                prefix: existing_tail,
                child,
            })
        };
        let new_leaf_hash = self.store_node(&Node::Leaf {
            key_suffix: new_tail,
            value_hash,
        });

        let branch = if existing_bit {
            Node::Branch {
                left: new_leaf_hash,
                right: existing_side_hash,
            }
        } else {
            Node::Branch {
                left: existing_side_hash,
                right: new_leaf_hash,
            }
        };
        let branch_hash = self.store_node(&branch);

        if common == 0 {
            Ok(branch_hash)
        } else {
            Ok(self.store_node(&Node::Extension {
                prefix: path.prefix(common),
                child: branch_hash,
            }))
        }
    }

    fn remove_at(&mut self, node_hash: Hash, path: &BitPath) -> (Hash, Option<Hash>) {
        if node_hash == ZERO_HASH {
            return (ZERO_HASH, None);
        }
        let node = self.fetch_node(&node_hash);
        match node {
            Node::Leaf {
                key_suffix,
                value_hash,
            } => {
                if &key_suffix == path {
                    (ZERO_HASH, Some(value_hash))
                } else {
                    (node_hash, None)
                }
            }
            Node::Branch { left, right } => {
                if path.is_empty() {
                    return (node_hash, None);
                }
                let bit = path.bit(0);
                let rest = path.suffix(1);
                let (new_child, removed) = if bit {
                    self.remove_at(right, &rest)
                } else {
                    self.remove_at(left, &rest)
                };
                if removed.is_none() {
                    return (node_hash, None);
                }
                let (new_left, new_right) = if bit {
                    (left, new_child)
                } else {
                    (new_child, right)
                };

                let collapsed_hash = self.collapse_branch(new_left, new_right);
                (collapsed_hash, removed)
            }
            Node::Extension { prefix, child } => {
                let len = prefix.bit_len();
                if path.bit_len() < len {
                    return (node_hash, None);
                }
                let segment = path.prefix(len);
                if segment != prefix {
                    return (node_hash, None);
                }
                let rest = path.suffix(len);
                let (new_child, removed) = self.remove_at(child, &rest);
                if removed.is_none() {
                    return (node_hash, None);
                }
                let collapsed_hash = self.collapse_extension(prefix, new_child);
                (collapsed_hash, removed)
            }
        }
    }

    fn collapse_branch(&mut self, left: Hash, right: Hash) -> Hash {
        match (left == ZERO_HASH, right == ZERO_HASH) {
            (true, true) => ZERO_HASH,
            (false, true) => self.absorb_into_parent(left, false),
            (true, false) => self.absorb_into_parent(right, true),
            (false, false) => self.store_node(&Node::Branch { left, right }),
        }
    }

    fn collapse_extension(&mut self, prefix: BitPath, child: Hash) -> Hash {
        if child == ZERO_HASH {
            return ZERO_HASH;
        }
        let child_node = self.fetch_node(&child);
        match child_node {
            Node::Leaf {
                key_suffix,
                value_hash,
            } => {
                let combined_path = concat_bits(&prefix, &key_suffix);
                self.store_node(&Node::Leaf {
                    key_suffix: combined_path,
                    value_hash,
                })
            }
            Node::Extension {
                prefix: child_prefix,
                child: grandchild,
            } => {
                let combined_prefix = concat_bits(&prefix, &child_prefix);
                self.store_node(&Node::Extension {
                    prefix: combined_prefix,
                    child: grandchild,
                })
            }
            Node::Branch { .. } => self.store_node(&Node::Extension { prefix, child }),
        }
    }

    fn absorb_into_parent(&mut self, surviving_child: Hash, child_bit: bool) -> Hash {
        let surviving_node = self.fetch_node(&surviving_child);
        let mut prefix_bits = BitPath::empty();
        prefix_bits = push_bit(&prefix_bits, child_bit);

        match surviving_node {
            Node::Leaf {
                key_suffix,
                value_hash,
            } => {
                let combined = concat_bits(&prefix_bits, &key_suffix);
                self.store_node(&Node::Leaf {
                    key_suffix: combined,
                    value_hash,
                })
            }
            Node::Extension {
                prefix: child_prefix,
                child: grandchild,
            } => {
                let combined = concat_bits(&prefix_bits, &child_prefix);
                self.store_node(&Node::Extension {
                    prefix: combined,
                    child: grandchild,
                })
            }
            Node::Branch { .. } => self.store_node(&Node::Extension {
                prefix: prefix_bits,
                child: surviving_child,
            }),
        }
    }
}

fn append_bits(out: &mut Vec<bool>, path: &BitPath) {
    for index in 0..path.bit_len() {
        out.push(path.bit(index));
    }
}

fn decode_raw_key(bits: &[bool]) -> Option<Vec<u8>> {
    if bits.len() < 32 || bits.len() % 8 != 0 {
        return None;
    }
    let mut encoded = vec![0_u8; bits.len() / 8];
    for (index, bit) in bits.iter().copied().enumerate() {
        if bit {
            encoded[index / 8] |= 1 << (7 - (index % 8));
        }
    }
    let key_len = usize::try_from(u32::from_le_bytes(encoded[..4].try_into().ok()?)).ok()?;
    if encoded.len() != 4_usize.checked_add(key_len)? {
        return None;
    }
    Some(encoded[4..].to_vec())
}

fn concat_bits(head: &BitPath, tail: &BitPath) -> BitPath {
    if head.is_empty() {
        return tail.clone();
    }
    if tail.is_empty() {
        return head.clone();
    }
    let mut acc = head.clone();
    for i in 0..tail.bit_len() {
        acc = push_bit(&acc, tail.bit(i));
    }
    acc
}

fn push_bit(path: &BitPath, bit: bool) -> BitPath {
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
    encode_bitpath_from_parts(new_len, &bytes)
}

fn encode_bitpath_from_parts(bit_len: u32, bytes: &[u8]) -> BitPath {
    let mut buf = Vec::with_capacity(4 + bytes.len());
    buf.extend_from_slice(&bit_len.to_le_bytes());
    buf.extend_from_slice(bytes);
    let (path, _) = BitPath::decode(&buf).expect("synthesized BitPath bytes are canonical");
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::{ProofError, ProofOutcome, ProofStep, ProofTerminal};
    use alloc::vec;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    type TestTrie = Trie<Blake3Hasher>;

    fn value(byte: u8) -> Vec<u8> {
        vec![byte; usize::from(byte % 7) + 1]
    }

    fn insert_many(trie: &mut TestTrie, pairs: &[(&[u8], &[u8])]) {
        for (key, value) in pairs {
            trie.insert(key, value.to_vec()).expect("insert succeeds");
        }
    }

    #[test]
    fn new_trie_has_empty_root() {
        let trie = TestTrie::new();
        assert_eq!(trie.root(), ZERO_HASH);
        assert_eq!(trie.node_count(), 0);
        assert_eq!(trie.value_count(), 0);
        assert_eq!(trie.get(b"missing"), None);
    }

    #[test]
    fn insert_and_get_single_value() {
        let mut trie = TestTrie::new();
        trie.insert(b"account:alice", b"100".to_vec())
            .expect("insert");
        assert_eq!(trie.get(b"account:alice"), Some(b"100".to_vec()));
        assert_eq!(trie.get(b"account:bob"), None);
        assert_ne!(trie.root(), ZERO_HASH);
    }

    #[test]
    fn keys_returns_raw_keys_in_lexicographic_order() {
        let mut trie = TestTrie::new();
        trie.insert(b"gamma", b"3".to_vec()).expect("insert");
        trie.insert(b"alpha", b"1".to_vec()).expect("insert");
        trie.insert(b"alphabet", b"2".to_vec()).expect("insert");

        assert_eq!(
            trie.keys(),
            vec![b"alpha".to_vec(), b"alphabet".to_vec(), b"gamma".to_vec()]
        );
    }

    #[test]
    fn overwrite_changes_value_and_root() {
        let mut trie = TestTrie::new();
        trie.insert(b"k", b"v1".to_vec()).expect("insert");
        let root_v1 = trie.root();
        trie.insert(b"k", b"v2".to_vec()).expect("overwrite");
        assert_eq!(trie.get(b"k"), Some(b"v2".to_vec()));
        assert_ne!(trie.root(), root_v1);
    }

    #[test]
    fn insertion_order_does_not_change_root() {
        let pairs: [(&[u8], &[u8]); 5] = [
            (b"alpha", b"1"),
            (b"beta", b"2"),
            (b"gamma", b"3"),
            (b"delta", b"4"),
            (b"epsilon", b"5"),
        ];

        let mut forward = TestTrie::new();
        insert_many(&mut forward, &pairs);

        let mut reverse = TestTrie::new();
        for (key, value) in pairs.iter().rev() {
            reverse.insert(key, value.to_vec()).expect("insert");
        }

        assert_eq!(forward.root(), reverse.root());
        for (key, value) in pairs {
            assert_eq!(forward.get(key), Some(value.to_vec()));
            assert_eq!(reverse.get(key), Some(value.to_vec()));
        }
    }

    #[test]
    fn prefix_like_raw_keys_are_supported() {
        let mut trie = TestTrie::new();
        trie.insert(b"a", b"short".to_vec()).expect("insert a");
        trie.insert(b"ab", b"longer".to_vec()).expect("insert ab");
        trie.insert(b"", b"empty".to_vec()).expect("insert empty");

        assert_eq!(trie.get(b"a"), Some(b"short".to_vec()));
        assert_eq!(trie.get(b"ab"), Some(b"longer".to_vec()));
        assert_eq!(trie.get(b""), Some(b"empty".to_vec()));
    }

    #[test]
    fn removing_missing_key_keeps_root() {
        let mut trie = TestTrie::new();
        trie.insert(b"present", b"value".to_vec()).expect("insert");
        let root = trie.root();
        assert_eq!(trie.remove(b"absent"), None);
        assert_eq!(trie.root(), root);
        assert_eq!(trie.get(b"present"), Some(b"value".to_vec()));
    }

    #[test]
    fn removing_last_key_restores_empty_root() {
        let mut trie = TestTrie::new();
        trie.insert(b"only", b"value".to_vec()).expect("insert");
        assert_eq!(trie.remove(b"only"), Some(b"value".to_vec()));
        assert_eq!(trie.root(), ZERO_HASH);
        assert_eq!(trie.get(b"only"), None);
    }

    #[test]
    fn removal_collapses_back_to_same_single_key_root() {
        let mut single = TestTrie::new();
        single.insert(b"left", b"1".to_vec()).expect("insert");

        let mut pair = single.clone();
        pair.insert(b"right", b"2".to_vec()).expect("insert");
        assert_ne!(pair.root(), single.root());
        assert_eq!(pair.remove(b"right"), Some(b"2".to_vec()));
        assert_eq!(pair.root(), single.root());
        assert_eq!(pair.get(b"left"), Some(b"1".to_vec()));
    }

    #[test]
    fn inclusion_proof_verifies() {
        let mut trie = TestTrie::new();
        insert_many(
            &mut trie,
            &[(b"alice", b"100"), (b"bob", b"50"), (b"carol", b"75")],
        );

        let proof = trie.prove(b"bob");
        let root = trie.root();
        assert_eq!(
            proof.verify::<Blake3Hasher>(&root, b"bob").expect("verify"),
            ProofOutcome::Included {
                value_hash: Blake3Hasher::hash_value(b"50")
            }
        );
        proof
            .verify_inclusion::<Blake3Hasher>(&root, b"bob", b"50")
            .expect("inclusion");
    }

    #[test]
    fn inclusion_proof_rejects_wrong_value() {
        let mut trie = TestTrie::new();
        trie.insert(b"bob", b"50".to_vec()).expect("insert");
        let proof = trie.prove(b"bob");
        assert_eq!(
            proof.verify_inclusion::<Blake3Hasher>(&trie.root(), b"bob", b"51"),
            Err(ProofError::ValueHashMismatch)
        );
    }

    #[test]
    fn exclusion_proof_for_empty_trie_verifies() {
        let trie = TestTrie::new();
        let proof = trie.prove(b"anything");
        assert_eq!(proof.terminal, ProofTerminal::Empty);
        proof
            .verify_exclusion::<Blake3Hasher>(&trie.root(), b"anything")
            .expect("exclusion");
    }

    #[test]
    fn exclusion_proof_for_empty_subtree_verifies() {
        let mut trie = TestTrie::new();
        trie.insert(b"alice", b"100".to_vec()).expect("insert");
        trie.insert(b"bob", b"50".to_vec()).expect("insert");
        let proof = trie.prove(b"carol");
        proof
            .verify_exclusion::<Blake3Hasher>(&trie.root(), b"carol")
            .expect("exclusion");
    }

    #[test]
    fn exclusion_proof_for_other_leaf_verifies() {
        let mut trie = TestTrie::new();
        trie.insert(b"alice", b"100".to_vec()).expect("insert");
        let proof = trie.prove(b"bob");
        assert!(matches!(proof.terminal, ProofTerminal::Leaf { .. }));
        proof
            .verify_exclusion::<Blake3Hasher>(&trie.root(), b"bob")
            .expect("exclusion");
    }

    #[test]
    fn divergent_extension_exclusion_verifies() {
        let mut trie = TestTrie::new();
        trie.insert(b"aaaaaaaa", b"1".to_vec()).expect("insert");
        trie.insert(b"aaaaaaab", b"2".to_vec()).expect("insert");
        let proof = trie.prove(b"bbbbbbbb");
        assert!(matches!(
            proof.terminal,
            ProofTerminal::DivergentExtension { .. }
        ));
        proof
            .verify_exclusion::<Blake3Hasher>(&trie.root(), b"bbbbbbbb")
            .expect("exclusion");
    }

    #[test]
    fn proof_rejects_wrong_root() {
        let mut trie = TestTrie::new();
        trie.insert(b"key", b"value".to_vec()).expect("insert");
        let proof = trie.prove(b"key");
        let mut wrong_root = trie.root();
        wrong_root[0] ^= 0x01;
        assert_eq!(
            proof.verify_inclusion::<Blake3Hasher>(&wrong_root, b"key", b"value"),
            Err(ProofError::RootMismatch)
        );
    }

    #[test]
    fn proof_rejects_tampered_branch_direction() {
        let mut trie = TestTrie::new();
        trie.insert(b"alpha", b"1".to_vec()).expect("insert");
        trie.insert(b"omega", b"2".to_vec()).expect("insert");
        let mut proof = trie.prove(b"alpha");
        let step = proof
            .steps
            .iter_mut()
            .find(|step| matches!(step, ProofStep::Branch { .. }))
            .expect("at least one branch step");
        if let ProofStep::Branch {
            descended_right, ..
        } = step
        {
            *descended_right = !*descended_right;
        }
        assert_eq!(
            proof.verify::<Blake3Hasher>(&trie.root(), b"alpha"),
            Err(ProofError::BranchBitMismatch)
        );
    }

    #[test]
    fn drain_pending_returns_new_entries_and_then_empties() {
        let mut trie = TestTrie::new();
        assert!(trie.drain_pending_nodes().is_empty());
        assert!(trie.drain_pending_values().is_empty());

        trie.insert(b"a", b"1".to_vec()).expect("insert");
        let nodes = trie.drain_pending_nodes();
        let values = trie.drain_pending_values();
        assert!(!nodes.is_empty(), "insert must produce at least one node");
        assert!(!values.is_empty(), "insert must produce at least one value");
        // Second drain returns nothing because no new writes happened.
        assert!(trie.drain_pending_nodes().is_empty());
        assert!(trie.drain_pending_values().is_empty());

        // Re-inserting an identical value-byte does not record a new
        // value, since the value hash already lives in the value store.
        trie.insert(b"a", b"1".to_vec()).expect("re-insert");
        assert!(
            trie.drain_pending_values().is_empty(),
            "duplicate value should not be queued for persistence"
        );
    }

    #[test]
    fn from_persisted_roundtrips_reads_and_proofs() {
        let mut original = TestTrie::new();
        insert_many(
            &mut original,
            &[(b"alice", b"100"), (b"bob", b"50"), (b"carol", b"75")],
        );
        let root = original.root();
        let nodes = original.drain_pending_nodes();
        let values = original.drain_pending_values();

        let reopened = TestTrie::from_persisted(root, nodes, values);
        assert_eq!(reopened.root(), root);
        assert_eq!(reopened.get(b"alice"), Some(b"100".to_vec()));
        assert_eq!(reopened.get(b"bob"), Some(b"50".to_vec()));
        assert_eq!(reopened.get(b"carol"), Some(b"75".to_vec()));
        reopened
            .prove(b"bob")
            .verify_inclusion::<Blake3Hasher>(&root, b"bob", b"50")
            .expect("inclusion in reopened trie");
    }

    #[test]
    fn random_insert_get_remove_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5452_4945);
        let mut trie = TestTrie::new();
        let mut pairs = Vec::new();

        for index in 0..64_u8 {
            let mut key = [0_u8; 16];
            rng.fill_bytes(&mut key);
            let v = value(index);
            trie.insert(&key, v.clone()).expect("insert random key");
            pairs.push((key, v));
        }

        for (key, v) in &pairs {
            assert_eq!(trie.get(key), Some(v.clone()));
            trie.prove(key)
                .verify_inclusion::<Blake3Hasher>(&trie.root(), key, v)
                .expect("random inclusion proof");
        }

        for (key, v) in pairs.iter().take(32) {
            assert_eq!(trie.remove(key), Some(v.clone()));
            assert_eq!(trie.get(key), None);
            trie.prove(key)
                .verify_exclusion::<Blake3Hasher>(&trie.root(), key)
                .expect("random exclusion proof");
        }
    }
}
