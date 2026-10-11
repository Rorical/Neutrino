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

use alloc::collections::btree_map::Entry;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use neutrino_primitives::{Hash, ZERO_HASH};

use crate::bits::BitPath;
use crate::error::TrieError;
use crate::hasher::Hasher;
use crate::node::Node;
use crate::poseidon2::Poseidon2Hasher;
use crate::proof::{Proof, ProofStep, ProofTerminal};

/// Binary sparse Merkle trie parameterised by hash function.
///
/// Defaults to [`Poseidon2Hasher`], the SP1-precompile-aligned hash;
/// [`crate::Blake3Hasher`] is an alternative for generic trie consumers
/// and reference hash tests. The runtime always selects Poseidon2.
///
/// The trie buffers every newly produced node and value in
/// `pending_nodes` / `pending_values` so callers wanting persistence
/// (the consensus engine) can drain just the deltas after each block.
/// Drained entries are not removed from the in-memory map; the buffers
/// only describe what is *new since the last drain*, mirroring the
/// content-addressed RocksDB columns the engine writes them to.
#[derive(Clone, Debug)]
pub struct Trie<H: Hasher = Poseidon2Hasher> {
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

    /// Number of distinct nodes currently retained.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of distinct values currently retained.
    #[must_use]
    pub fn value_count(&self) -> usize {
        self.values.len()
    }

    /// Iterate content-addressed nodes without copying the trie.
    pub fn node_entries(&self) -> impl Iterator<Item = (Hash, &[u8])> {
        self.nodes
            .iter()
            .map(|(hash, bytes)| (*hash, bytes.as_slice()))
    }

    /// Iterate content-addressed values without copying the trie.
    pub fn value_entries(&self) -> impl Iterator<Item = (Hash, &[u8])> {
        self.values
            .iter()
            .map(|(hash, bytes)| (*hash, bytes.as_slice()))
    }

    /// Remove entries unreachable from the current root and the supplied roots.
    ///
    /// Every retained node and value is checked before any mutation. Missing or
    /// corrupt state leaves the trie unchanged. The caller must commit matching
    /// persistent deletions atomically before installing this pruned snapshot.
    pub fn retain_roots(&mut self, roots: &[Hash]) -> Result<(), TrieError> {
        let mut nodes = BTreeSet::new();
        let mut values = BTreeSet::new();
        let mut pending = roots.to_vec();
        pending.push(self.root);
        while let Some(hash) = pending.pop() {
            if hash == ZERO_HASH || !nodes.insert(hash) {
                continue;
            }
            let bytes = self
                .nodes
                .get(&hash)
                .ok_or(TrieError::MissingRetainedEntry)?;
            if H::hash_node(bytes) != hash {
                return Err(TrieError::RetainedHashMismatch);
            }
            match Node::decode(bytes)? {
                Node::Leaf { value_hash, .. } => {
                    if values.insert(value_hash) {
                        let value = self
                            .values
                            .get(&value_hash)
                            .ok_or(TrieError::MissingRetainedEntry)?;
                        if H::hash_value(value) != value_hash {
                            return Err(TrieError::RetainedHashMismatch);
                        }
                    }
                }
                Node::Branch { left, right } => pending.extend([left, right]),
                Node::Extension { child, .. } => pending.push(child),
            }
        }
        self.nodes.retain(|hash, _| nodes.contains(hash));
        self.values.retain(|hash, _| values.contains(hash));
        self.pending_nodes.retain(|(hash, _)| nodes.contains(hash));
        self.pending_values
            .retain(|(hash, _)| values.contains(hash));
        Ok(())
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
    ///
    /// # Panics
    /// Panics when a node on the path, or the value of the leaf holding
    /// `key`, is missing from the store. A partial trie that omits the value
    /// of a present key must not read it as absent: the SP1 Guest relies on
    /// this to abort on an incomplete witness instead of proving a forged
    /// absence.
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
                        let value = self
                            .values
                            .get(&value_hash)
                            .expect("trie invariant: every reachable value is in the value store");
                        return Some(value.clone());
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
        match self.values.entry(value_hash) {
            Entry::Vacant(entry) => {
                entry.insert(value.clone());
                self.pending_values.push((value_hash, value));
            }
            Entry::Occupied(mut entry) => {
                entry.insert(value);
            }
        }
        let new_root = self.insert_at(self.root, &path, 0, value_hash)?;
        self.root = new_root;
        Ok(())
    }

    /// Remove the value at `key` and return it if present.
    pub fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let path = BitPath::for_key(key);
        let (new_root, removed) = self.remove_at(self.root, &path, 0);
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

    /// Look up the canonical encoded bytes of a node by hash. Returns
    /// `None` for hashes not in the content-addressed store.
    #[must_use]
    pub fn node_bytes(&self, hash: &Hash) -> Option<&[u8]> {
        self.nodes.get(hash).map(Vec::as_slice)
    }

    /// Look up the canonical bytes of a value by hash.
    #[must_use]
    pub fn value_bytes(&self, hash: &Hash) -> Option<&[u8]> {
        self.values.get(hash).map(Vec::as_slice)
    }

    /// Walk the trie from root to the terminal for `key`, accumulating
    /// every visited node's `(hash, bytes)` into `out_nodes`, the
    /// terminal leaf's `(value_hash, value_bytes)` (when present) into
    /// `out_values`, and the sibling node at every on-path Branch
    /// into `out_nodes` as well.
    ///
    /// # Why siblings are included
    ///
    /// Reads and inserts only walk the path to `key`; siblings are
    /// referenced by hash and never fetched. Deletes are different:
    /// when a Branch loses one child to `ZERO_HASH`, the trie
    /// inspects the surviving sibling's node bytes via
    /// `absorb_into_parent` to decide whether to fold the parent
    /// away (Leaf/Extension siblings merge into the parent path;
    /// Branch siblings get re-wrapped in an Extension). That top-
    /// level inspection is the only sibling access the trie ever
    /// performs, so harvesting one node per on-path Branch is
    /// sufficient — we do not need the sibling's subtree.
    ///
    /// Sibling *values* are not collected: `absorb_into_parent`
    /// builds the merged node from `value_hash` alone and never
    /// reads the value bytes. Callers that also need to *read* the
    /// sibling's value should call `collect_path_nodes` on the
    /// sibling's key separately.
    ///
    /// Used by witness builders: the resulting subset is the minimum
    /// data needed for a `Trie::from_persisted` reconstruction that
    /// can read `key`, insert at `key`, and remove `key` (with the
    /// guest's `Trie::remove` walking the same path and consulting
    /// the same sibling for collapse decisions).
    ///
    /// Calling this method many times with disjoint keys is the
    /// standard way to assemble a Merkle witness covering the read /
    /// write / delete set of one block.
    pub fn collect_path_nodes(
        &self,
        key: &[u8],
        out_nodes: &mut BTreeMap<Hash, Vec<u8>>,
        out_values: &mut BTreeMap<Hash, Vec<u8>>,
    ) {
        let path = BitPath::for_key(key);
        let mut current = self.root;
        let mut consumed: u32 = 0;
        loop {
            if current == ZERO_HASH {
                return;
            }
            if let Some(bytes) = self.nodes.get(&current) {
                out_nodes.insert(current, bytes.clone());
            }
            let node = self.fetch_node(&current);
            match node {
                Node::Leaf { value_hash, .. } => {
                    if let Some(bytes) = self.values.get(&value_hash) {
                        out_values.insert(value_hash, bytes.clone());
                    }
                    return;
                }
                Node::Branch { left, right } => {
                    if consumed >= path.bit_len() {
                        return;
                    }
                    let bit = path.bit(consumed);
                    let (sibling, descended) = if bit { (left, right) } else { (right, left) };
                    // Harvest the sibling so a future `Trie::remove`
                    // in the partial trie can call
                    // `absorb_into_parent` without panicking on a
                    // missing node fetch.
                    if sibling != ZERO_HASH
                        && let Some(bytes) = self.nodes.get(&sibling)
                    {
                        out_nodes.insert(sibling, bytes.clone());
                    }
                    consumed += 1;
                    current = descended;
                }
                Node::Extension { prefix, child } => {
                    let len = prefix.bit_len();
                    if consumed + len > path.bit_len() {
                        return;
                    }
                    let segment = path.suffix(consumed).prefix(len);
                    if segment != prefix {
                        return;
                    }
                    consumed += len;
                    current = child;
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
        match self.nodes.entry(hash) {
            Entry::Vacant(entry) => {
                entry.insert(encoded.clone());
                self.pending_nodes.push((hash, encoded));
            }
            Entry::Occupied(mut entry) => {
                entry.insert(encoded);
            }
        }
        hash
    }

    /// Insert below `node_hash` the key whose remaining path is `path`'s bits
    /// from `offset` onward (`offset <= path.bit_len()`).
    fn insert_at(
        &mut self,
        node_hash: Hash,
        path: &BitPath,
        offset: u32,
        value_hash: Hash,
    ) -> Result<Hash, TrieError> {
        if node_hash == ZERO_HASH {
            return Ok(self.store_node(&Node::Leaf {
                key_suffix: path.suffix(offset),
                value_hash,
            }));
        }

        let node = self.fetch_node(&node_hash);
        match node {
            Node::Leaf {
                key_suffix,
                value_hash: existing_vh,
            } => self.insert_into_leaf(key_suffix, existing_vh, &path.suffix(offset), value_hash),
            Node::Branch { left, right } => {
                if offset >= path.bit_len() {
                    return Err(TrieError::PrefixCollision);
                }
                let bit = path.bit(offset);
                let (new_left, new_right) = if bit {
                    (left, self.insert_at(right, path, offset + 1, value_hash)?)
                } else {
                    (self.insert_at(left, path, offset + 1, value_hash)?, right)
                };
                Ok(self.store_node(&Node::Branch {
                    left: new_left,
                    right: new_right,
                }))
            }
            Node::Extension { prefix, child } => {
                self.insert_into_extension(prefix, child, path, offset, value_hash)
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

    /// [`Trie::insert_at`] for an extension node; `path` and `offset` as there.
    fn insert_into_extension(
        &mut self,
        prefix: BitPath,
        child: Hash,
        path: &BitPath,
        offset: u32,
        value_hash: Hash,
    ) -> Result<Hash, TrieError> {
        if path.matches_at(offset, &prefix) {
            let rest = offset + prefix.bit_len();
            if rest == path.bit_len() {
                return Err(TrieError::PrefixCollision);
            }
            let new_child = self.insert_at(child, path, rest, value_hash)?;
            return Ok(self.store_node(&Node::Extension {
                prefix,
                child: new_child,
            }));
        }
        // The new key diverges inside the prefix; split it on the remaining path.
        let path = &path.suffix(offset);
        let common = prefix.common_prefix_len(path);
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

    /// Remove below `node_hash` the key whose remaining path is `path`'s bits
    /// from `offset` onward (`offset <= path.bit_len()`).
    fn remove_at(&mut self, node_hash: Hash, path: &BitPath, offset: u32) -> (Hash, Option<Hash>) {
        if node_hash == ZERO_HASH {
            return (ZERO_HASH, None);
        }
        let node = self.fetch_node(&node_hash);
        match node {
            Node::Leaf {
                key_suffix,
                value_hash,
            } => {
                if key_suffix.bit_len() == path.bit_len() - offset
                    && path.matches_at(offset, &key_suffix)
                {
                    (ZERO_HASH, Some(value_hash))
                } else {
                    (node_hash, None)
                }
            }
            Node::Branch { left, right } => {
                if offset >= path.bit_len() {
                    return (node_hash, None);
                }
                let bit = path.bit(offset);
                let (new_child, removed) = if bit {
                    self.remove_at(right, path, offset + 1)
                } else {
                    self.remove_at(left, path, offset + 1)
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
                if !path.matches_at(offset, &prefix) {
                    return (node_hash, None);
                }
                let rest = offset + prefix.bit_len();
                let (new_child, removed) = self.remove_at(child, path, rest);
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
                let combined_path = prefix.concat(&key_suffix);
                self.store_node(&Node::Leaf {
                    key_suffix: combined_path,
                    value_hash,
                })
            }
            Node::Extension {
                prefix: child_prefix,
                child: grandchild,
            } => {
                let combined_prefix = prefix.concat(&child_prefix);
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
        let prefix_bits = BitPath::single(child_bit);

        match surviving_node {
            Node::Leaf {
                key_suffix,
                value_hash,
            } => {
                let combined = prefix_bits.concat(&key_suffix);
                self.store_node(&Node::Leaf {
                    key_suffix: combined,
                    value_hash,
                })
            }
            Node::Extension {
                prefix: child_prefix,
                child: grandchild,
            } => {
                let combined = prefix_bits.concat(&child_prefix);
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
    if bits.len() < 32 || !bits.len().is_multiple_of(8) {
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

/// Read `key` under `root` from content-addressed node and value stores,
/// fetching only the nodes on the key's path instead of materialising the
/// whole trie. The walk is the one [`Trie::get`] performs.
///
/// # Errors
/// Returns [`TrieError::MissingRetainedEntry`] when a node or value the walk
/// reaches is absent, or the decode error of a malformed node.
pub fn lookup_persisted(
    root: Hash,
    key: &[u8],
    mut node: impl FnMut(&Hash) -> Option<Vec<u8>>,
    mut value: impl FnMut(&Hash) -> Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, TrieError> {
    let path = BitPath::for_key(key);
    let mut current = root;
    let mut consumed: u32 = 0;
    loop {
        if current == ZERO_HASH {
            return Ok(None);
        }
        let bytes = node(&current).ok_or(TrieError::MissingRetainedEntry)?;
        match Node::decode(&bytes)? {
            Node::Leaf {
                key_suffix,
                value_hash,
            } => {
                if path.suffix(consumed) != key_suffix {
                    return Ok(None);
                }
                return value(&value_hash)
                    .map(Some)
                    .ok_or(TrieError::MissingRetainedEntry);
            }
            Node::Branch { left, right } => {
                if consumed >= path.bit_len() {
                    return Ok(None);
                }
                let bit = path.bit(consumed);
                consumed += 1;
                current = if bit { right } else { left };
            }
            Node::Extension { prefix, child } => {
                let len = prefix.bit_len();
                if consumed + len > path.bit_len() || path.suffix(consumed).prefix(len) != prefix {
                    return Ok(None);
                }
                consumed += len;
                current = child;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Blake3Hasher;
    use crate::proof::{ProofError, ProofOutcome, ProofStep, ProofTerminal};
    use alloc::vec;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{Rng, SeedableRng};

    // The generic trie corpus uses `Blake3Hasher` so the reference
    // hasher keeps the same test coverage it had before the default
    // switched.  Default `Trie<>` is exercised transitively by
    // downstream crates (`runtime-core`, `runtime-host`, every node
    // integration test) which all use the new `Poseidon2Hasher`
    // default.  Adding a parallel `Poseidon2Hasher` test corpus
    // here would duplicate everything for no extra signal — the
    // hash function is plug-in.
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
    fn persisted_lookup_reads_exactly_what_the_trie_holds() {
        let mut trie = TestTrie::new();
        let keys: Vec<Vec<u8>> = (0_u8..40)
            .map(|byte| vec![byte; usize::from(byte % 5) + 1])
            .collect();
        for (index, key) in keys.iter().enumerate() {
            trie.insert(key, value(u8::try_from(index).unwrap()))
                .unwrap();
        }
        let root = trie.root();
        let lookup = |trie: &TestTrie, key: &[u8]| {
            lookup_persisted(
                root,
                key,
                |hash| trie.nodes.get(hash).cloned(),
                |hash| trie.values.get(hash).cloned(),
            )
        };
        for key in &keys {
            assert_eq!(lookup(&trie, key), Ok(trie.get(key)));
        }
        for absent in [&b""[..], b"missing", &[0_u8; 9], &[39_u8; 7]] {
            assert_eq!(trie.get(absent), None);
            assert_eq!(lookup(&trie, absent), Ok(None));
        }
        assert_eq!(
            lookup_persisted(ZERO_HASH, b"any", |_| None, |_| None),
            Ok(None)
        );
        assert_eq!(
            lookup_persisted(root, &keys[0], |_| None, |_| None),
            Err(TrieError::MissingRetainedEntry)
        );
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
    fn pruning_preserves_current_and_leased_roots_then_reclaims_released_state() {
        let mut trie = TestTrie::new();
        trie.insert(b"account", b"old".to_vec()).unwrap();
        let old_root = trie.root();
        trie.insert(b"account", b"middle".to_vec()).unwrap();
        let middle_root = trie.root();
        trie.insert(b"account", b"current".to_vec()).unwrap();
        let current_root = trie.root();
        trie.retain_roots(&[old_root]).unwrap();
        assert_eq!(trie.root(), current_root);
        assert_eq!(trie.get(b"account"), Some(b"current".to_vec()));
        assert!(trie.node_bytes(&old_root).is_some());
        assert!(trie.node_bytes(&middle_root).is_none());
        assert_eq!(trie.node_count(), 2);
        assert_eq!(trie.value_count(), 2);
        assert_eq!(trie.pending_nodes.len(), 2);
        assert_eq!(trie.pending_values.len(), 2);
        let nodes = trie.drain_pending_nodes();
        let values = trie.drain_pending_values();
        let restored = TestTrie::from_persisted(old_root, nodes, values);
        assert_eq!(restored.get(b"account"), Some(b"old".to_vec()));
        trie.retain_roots(&[]).unwrap();
        assert!(trie.node_bytes(&old_root).is_none());
        assert_eq!(trie.node_count(), 1);
        assert_eq!(trie.value_count(), 1);
    }

    #[test]
    fn pruning_checks_reachable_state_before_deleting_anything() {
        let mut trie = TestTrie::new();
        trie.insert(b"account", b"old".to_vec()).unwrap();
        trie.insert(b"account", b"current".to_vec()).unwrap();
        let original = trie.clone();
        assert_eq!(
            trie.retain_roots(&[[99; 32]]),
            Err(TrieError::MissingRetainedEntry)
        );
        assert_eq!(trie.nodes, original.nodes);
        assert_eq!(trie.values, original.values);
        let value_hash = <crate::Blake3Hasher as Hasher>::hash_value(b"current");
        trie.values.insert(value_hash, b"corrupt".to_vec());
        let corrupt_values = trie.values.clone();
        assert_eq!(trie.retain_roots(&[]), Err(TrieError::RetainedHashMismatch));
        assert_eq!(trie.nodes, original.nodes);
        assert_eq!(trie.values, corrupt_values);
        trie.values.remove(&value_hash);
        assert_eq!(trie.retain_roots(&[]), Err(TrieError::MissingRetainedEntry));
        assert_eq!(trie.nodes, original.nodes);
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
        let first_root = trie.root();
        trie.insert(b"k", b"v2".to_vec()).expect("overwrite");
        assert_eq!(trie.get(b"k"), Some(b"v2".to_vec()));
        assert_ne!(trie.root(), first_root);
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
        assert_eq!(trie.drain_pending_nodes(), [] as [(Hash, Vec<u8>); 0]);
        assert_eq!(trie.drain_pending_values(), [] as [(Hash, Vec<u8>); 0]);

        trie.insert(b"a", b"1".to_vec()).expect("insert");
        let nodes = trie.drain_pending_nodes();
        let values = trie.drain_pending_values();
        assert!(!nodes.is_empty(), "insert must produce at least one node");
        assert!(!values.is_empty(), "insert must produce at least one value");
        // Second drain returns nothing because no new writes happened.
        assert_eq!(trie.drain_pending_nodes(), [] as [(Hash, Vec<u8>); 0]);
        assert_eq!(trie.drain_pending_values(), [] as [(Hash, Vec<u8>); 0]);

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
    #[should_panic(expected = "every reachable value is in the value store")]
    fn a_present_key_whose_value_is_missing_never_reads_as_absent() {
        let mut original = TestTrie::new();
        insert_many(&mut original, &[(b"alice", b"100"), (b"bob", b"50")]);
        let root = original.root();
        let nodes = original.drain_pending_nodes();
        // Every node on the path is present; only the leaf values are not.
        let partial = TestTrie::from_persisted(root, nodes, []);
        let _ = partial.get(b"bob");
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

    /// Root of the canonical trie holding exactly `leaves`, built from scratch:
    /// one key is a leaf, keys sharing a nonempty prefix sit under an extension,
    /// and otherwise the first bit splits them under a branch.
    fn canonical_subtree(leaves: &[(BitPath, Hash)]) -> Hash {
        let node = match leaves {
            [] => return ZERO_HASH,
            [(key_suffix, value_hash)] => Node::Leaf {
                key_suffix: key_suffix.clone(),
                value_hash: *value_hash,
            },
            [(first, _), rest @ ..] => {
                let common = rest
                    .iter()
                    .map(|(path, _)| first.common_prefix_len(path))
                    .min()
                    .unwrap();
                if common > 0 {
                    let children: Vec<_> = leaves
                        .iter()
                        .map(|(path, value_hash)| (path.suffix(common), *value_hash))
                        .collect();
                    Node::Extension {
                        prefix: first.prefix(common),
                        child: canonical_subtree(&children),
                    }
                } else {
                    let (mut left, mut right) = (Vec::new(), Vec::new());
                    for (path, value_hash) in leaves {
                        let side = if path.bit(0) { &mut right } else { &mut left };
                        side.push((path.suffix(1), *value_hash));
                    }
                    Node::Branch {
                        left: canonical_subtree(&left),
                        right: canonical_subtree(&right),
                    }
                }
            }
        };
        Blake3Hasher::hash_node(&node.encode())
    }

    fn canonical_root(entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> Hash {
        let leaves: Vec<_> = entries
            .iter()
            .map(|(key, value)| (BitPath::for_key(key), Blake3Hasher::hash_value(value)))
            .collect();
        canonical_subtree(&leaves)
    }

    #[test]
    fn incremental_roots_match_a_from_scratch_canonical_build() {
        fn below(rng: &mut ChaCha20Rng, bound: u32) -> usize {
            usize::try_from(rng.next_u32() % bound).unwrap()
        }
        let alphabet = [0x00, 0x01, 0x7F, 0x80, 0xFF];
        let mut rng = ChaCha20Rng::seed_from_u64(0x4F46_4653);
        let mut keys = Vec::new();
        for _ in 0..48 {
            let len = below(&mut rng, 6);
            let key: Vec<u8> = (0..len).map(|_| alphabet[below(&mut rng, 5)]).collect();
            keys.push(key);
        }
        let mut trie = TestTrie::new();
        let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for step in 0..400_usize {
            let key = &keys[below(&mut rng, 48)];
            if below(&mut rng, 3) == 0 {
                assert_eq!(trie.remove(key), entries.remove(key), "step {step}");
            } else {
                let value = vec![u8::try_from(step % 251).unwrap(); 1 + step % 5];
                trie.insert(key, value.clone()).expect("insert");
                entries.insert(key.clone(), value);
            }
            assert_eq!(trie.root(), canonical_root(&entries), "step {step}");
        }
        for (key, value) in &entries {
            assert_eq!(trie.get(key).as_ref(), Some(value));
        }
    }

    #[test]
    fn collect_path_nodes_yields_a_partial_subtree_that_round_trips() {
        // Populate a small trie and verify that the nodes collected for
        // one key are enough to reconstruct a partial trie supporting
        // both read and write on that key.
        let mut trie: Trie<Blake3Hasher> = Trie::new();
        for (k, v) in [
            (b"alpha".as_ref(), b"1".to_vec()),
            (b"beta".as_ref(), b"2".to_vec()),
            (b"gamma".as_ref(), b"3".to_vec()),
            (b"delta".as_ref(), b"4".to_vec()),
        ] {
            trie.insert(k, v).unwrap();
        }
        let root = trie.root();

        let mut nodes = BTreeMap::new();
        let mut values = BTreeMap::new();
        // Touch alpha (read) and a fresh key (write). The witness must
        // cover both paths.
        trie.collect_path_nodes(b"alpha", &mut nodes, &mut values);
        trie.collect_path_nodes(b"epsilon", &mut nodes, &mut values);

        let partial = Trie::<Blake3Hasher>::from_persisted(
            root,
            nodes.iter().map(|(h, b)| (*h, b.clone())),
            values.iter().map(|(h, b)| (*h, b.clone())),
        );
        // Read of a witnessed key returns the same value.
        assert_eq!(partial.get(b"alpha").as_deref(), Some(b"1".as_ref()));
        // Insert at the fresh key bumps the root.
        let mut writable = partial;
        writable.insert(b"epsilon", b"5".to_vec()).unwrap();
        let mut reference = trie;
        reference.insert(b"epsilon", b"5".to_vec()).unwrap();
        assert_eq!(writable.root(), reference.root());
    }

    #[test]
    fn collect_path_nodes_on_empty_trie_yields_nothing() {
        let trie: Trie<Blake3Hasher> = Trie::new();
        let mut nodes = BTreeMap::new();
        let mut values = BTreeMap::new();
        trie.collect_path_nodes(b"alpha", &mut nodes, &mut values);
        assert!(nodes.is_empty());
        assert!(values.is_empty());
    }

    #[test]
    fn collect_path_nodes_includes_branch_siblings_so_remove_round_trips() {
        // Original bug: `Trie::remove` calls `absorb_into_parent` when
        // a branch loses one child to `ZERO_HASH`; that path fetches
        // the surviving sibling's node bytes. Without sibling harvest
        // the partial trie panics on the fetch.
        //
        // Setup a trie with `left` + `right` keys whose paths diverge
        // at a Branch close to the root, take a witness covering only
        // `left`, reconstruct a partial trie, and remove `left`. The
        // removal must complete because the sibling `right` was
        // included in the witness; the post-remove root must equal
        // the root of a trie that only ever contained `right`.
        let mut full: Trie<Blake3Hasher> = Trie::new();
        full.insert(b"left-key", b"L".to_vec()).unwrap();
        full.insert(b"right-key", b"R".to_vec()).unwrap();
        let root_full = full.root();

        // Witness covering only the left key (the one we'll remove).
        let mut nodes = BTreeMap::new();
        let mut values = BTreeMap::new();
        full.collect_path_nodes(b"left-key", &mut nodes, &mut values);

        let mut partial = Trie::<Blake3Hasher>::from_persisted(
            root_full,
            nodes.iter().map(|(h, b)| (*h, b.clone())),
            values.iter().map(|(h, b)| (*h, b.clone())),
        );
        // Sanity: partial trie can read `left-key`.
        assert_eq!(partial.get(b"left-key").as_deref(), Some(b"L".as_ref()));

        // Removing `left-key` must succeed and trigger sibling absorb.
        let removed = partial.remove(b"left-key");
        assert_eq!(removed.as_deref(), Some(b"L".as_ref()));

        // Post-remove root equals a trie that only ever held `right-key`.
        let mut reference: Trie<Blake3Hasher> = Trie::new();
        reference.insert(b"right-key", b"R".to_vec()).unwrap();
        assert_eq!(partial.root(), reference.root());
    }

    #[test]
    fn collect_path_nodes_includes_siblings_along_a_deep_path() {
        // Multiple branches between the root and the target should
        // each contribute a sibling to the witness. Build a deeper
        // trie and remove a leaf; the partial trie must reach
        // `ZERO_HASH` when its only inhabitant is the target.
        let mut full: Trie<Blake3Hasher> = Trie::new();
        let pairs: [(&[u8], &[u8]); 5] = [
            (b"alpha", b"1"),
            (b"beta", b"2"),
            (b"gamma", b"3"),
            (b"delta", b"4"),
            (b"epsilon", b"5"),
        ];
        for (k, v) in pairs {
            full.insert(k, v.to_vec()).unwrap();
        }
        let root_full = full.root();

        // Witness for every key — this is what the host's
        // TracingState would assemble if every key were touched.
        let mut nodes = BTreeMap::new();
        let mut values = BTreeMap::new();
        for (k, _) in pairs {
            full.collect_path_nodes(k, &mut nodes, &mut values);
        }

        let mut partial = Trie::<Blake3Hasher>::from_persisted(
            root_full,
            nodes.iter().map(|(h, b)| (*h, b.clone())),
            values.iter().map(|(h, b)| (*h, b.clone())),
        );

        // Remove every key one at a time. None of the removes should
        // panic; the final root is the empty-trie root.
        for (k, expected) in pairs {
            let got = partial.remove(k);
            assert_eq!(
                got.as_deref(),
                Some(expected),
                "removing {k:?} must return its stored value",
            );
        }
        assert_eq!(partial.root(), ZERO_HASH);
    }
}
