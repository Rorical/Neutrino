#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Framework code shared by every Neutrino runtime.
//!
//! Defines the [`StateBackend`] trait that the STF is generic over and
//! two backend implementations that share the binary sparse Merkle
//! trie from `neutrino-trie`:
//!
//! - [`WitnessState`] — `no_std + alloc`. Used inside the SP1 Guest;
//!   built from a [`StateWitness`] via `Trie::from_persisted`, refuses
//!   reads of unwitnessed keys, and computes `post_state_root` by
//!   re-rooting the partial trie after the STF's writes.
//! - [`host::TracingState`] — only available with the `host` feature.
//!   Used by the dynamic runtime host during dry-run to record the
//!   read / write set, then materialise it into a `StateWitness` by
//!   collecting on-path trie nodes via `Trie::collect_path_nodes`.
//!
//! Wire formats live in `neutrino-runtime-abi`. This crate is pure
//! Rust code that depends only on `neutrino-trie` and the wire types.

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use neutrino_primitives::StateRoot;
use neutrino_runtime_abi::StateWitness;
use neutrino_trie::{Blake3Hasher, Hasher, Trie};

/// State root of an empty trie. Mirrors `neutrino_trie::EMPTY_TRIE_ROOT`
/// (`[0; 32]`).
pub const EMPTY_STATE_ROOT: StateRoot = neutrino_trie::EMPTY_TRIE_ROOT;

/// Returns the canonical empty-state root.
#[must_use]
pub const fn empty_state_root() -> StateRoot {
    EMPTY_STATE_ROOT
}

/// Read/write state interface used by every STF.
///
/// Backends implement this differently for the proven path
/// ([`WitnessState`]) and the dynamic path ([`host::TracingState`]),
/// but the STF code itself is identical.
pub trait StateBackend {
    /// Read the value at `key`, or `None` if the key is absent.
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>>;

    /// Set the value at `key`.
    fn write(&mut self, key: &[u8], value: Vec<u8>);

    /// Remove `key` from the state if present.
    fn delete(&mut self, key: &[u8]);

    /// Trie root of the state before any writes this run made.
    fn pre_state_root(&self) -> StateRoot;

    /// Trie root of the state including writes from this run.
    fn post_state_root(&self) -> StateRoot;
}

/// Errors thrown when constructing a [`WitnessState`].
#[derive(Debug, Eq, PartialEq)]
pub enum WitnessError {
    /// A `TrieNodeBytes` entry's claimed hash did not match the
    /// canonical BLAKE3 of its bytes.
    NodeHashMismatch {
        /// The hash the witness claimed.
        claimed: StateRoot,
    },
    /// A `TrieValueBytes` entry's claimed hash did not match the
    /// canonical BLAKE3 of its bytes.
    ValueHashMismatch {
        /// The hash the witness claimed.
        claimed: StateRoot,
    },
    /// The `pre_state_root` is non-empty but no supplied node has a
    /// matching hash, so the root cannot be reconstructed.
    PreRootMissing {
        /// Root the witness claims to commit to.
        claimed: StateRoot,
    },
}

/// `StateBackend` driven entirely by a [`StateWitness`].
///
/// `read` panics for any key not present in `witness.witnessed_keys`,
/// which makes the SP1 Guest abort proving when the host supplies an
/// incomplete witness. Writes are applied to the partial trie via
/// `Trie::insert`; `post_state_root` returns the live root.
#[derive(Debug)]
pub struct WitnessState {
    /// Keys explicitly witnessed. Reads outside this set panic.
    witnessed: BTreeSet<Vec<u8>>,
    /// Partial trie carrying every node and value on the touched paths.
    trie: Trie<Blake3Hasher>,
    /// Pre-state root claimed by the witness, validated at construction.
    pre_root: StateRoot,
}

impl WitnessState {
    /// Build a `WitnessState` and verify the reconstructed partial
    /// trie's root matches `pre_state_root`. The SP1 Guest calls this
    /// before running the STF; any tamper aborts proving.
    ///
    /// # Errors
    /// Returns [`WitnessError::PreRootMismatch`] when the partial
    /// trie reconstructed from the witness has a different root than
    /// the witness claims.
    pub fn new(witness: &StateWitness) -> Result<Self, WitnessError> {
        // (1) Every node and value's claimed hash must match the
        //     canonical BLAKE3 of its bytes. The trie's content-
        //     addressed store assumes this invariant; we re-check it
        //     so an adversarial host can't smuggle in a forged node.
        for node in &witness.nodes {
            if Blake3Hasher::hash_node(&node.bytes) != node.hash {
                return Err(WitnessError::NodeHashMismatch { claimed: node.hash });
            }
        }
        for value in &witness.values {
            if Blake3Hasher::hash_value(&value.bytes) != value.hash {
                return Err(WitnessError::ValueHashMismatch {
                    claimed: value.hash,
                });
            }
        }

        // (2) Root must either be the canonical empty-trie root or
        //     match one of the supplied node hashes; otherwise the
        //     guest cannot reconstruct the subtree.
        if witness.pre_state_root != EMPTY_STATE_ROOT
            && !witness
                .nodes
                .iter()
                .any(|n| n.hash == witness.pre_state_root)
        {
            return Err(WitnessError::PreRootMissing {
                claimed: witness.pre_state_root,
            });
        }

        // (3) Build the partial trie. Walks will fetch on-path nodes;
        //     missing nodes panic (the engine treats this as guest
        //     abort and rejects the proof).
        let trie = Trie::<Blake3Hasher>::from_persisted(
            witness.pre_state_root,
            witness.nodes.iter().map(|n| (n.hash, n.bytes.clone())),
            witness.values.iter().map(|v| (v.hash, v.bytes.clone())),
        );

        let mut witnessed = BTreeSet::new();
        for key in &witness.witnessed_keys {
            witnessed.insert(key.clone());
        }

        Ok(Self {
            witnessed,
            trie,
            pre_root: witness.pre_state_root,
        })
    }
}

impl StateBackend for WitnessState {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        assert!(
            self.witnessed.contains(key),
            "witness missing entry for key {key:?}"
        );
        self.trie.get(key)
    }

    fn write(&mut self, key: &[u8], value: Vec<u8>) {
        // Writes implicitly witness the key for the post-root rehash.
        self.witnessed.insert(key.to_vec());
        self.trie
            .insert(key, value)
            .expect("trie insert never fails for length-prefixed keys");
    }

    fn delete(&mut self, key: &[u8]) {
        self.witnessed.insert(key.to_vec());
        let _ = self.trie.remove(key);
    }

    fn pre_state_root(&self) -> StateRoot {
        self.pre_root
    }

    fn post_state_root(&self) -> StateRoot {
        self.trie.root()
    }
}

/// Host-side state implementations used by the dynamic runtime and the
/// dry-run path that builds witnesses.
#[cfg(feature = "host")]
pub mod host {
    use super::{BTreeSet, StateBackend, StateRoot, StateWitness, Vec};
    use alloc::collections::BTreeMap;
    use neutrino_runtime_abi::{TrieNodeBytes, TrieValueBytes};
    use neutrino_trie::{Blake3Hasher, Trie};

    /// In-memory state trie used by tests and by the dry-run path.
    ///
    /// Wraps a `neutrino_trie::Trie<Blake3Hasher>` so callers get the
    /// canonical state root for free and the same partial-trie
    /// reconstruction the SP1 Guest performs.
    #[derive(Clone, Debug, Default)]
    pub struct LiveTrie {
        trie: Trie<Blake3Hasher>,
    }

    impl LiveTrie {
        /// Wrap an existing trie as a read-only snapshot. Used by the
        /// block producer to take a [`LiveTrie`] view of the engine's
        /// authoritative state trie before invoking the runtime.
        #[must_use]
        pub const fn from_trie(trie: Trie<Blake3Hasher>) -> Self {
            Self { trie }
        }

        /// Insert (or overwrite) a value.
        pub fn insert(&mut self, key: &[u8], value: Vec<u8>) {
            self.trie
                .insert(key, value)
                .expect("trie insert never fails for length-prefixed keys");
        }

        /// Remove a key from the live state.
        pub fn remove(&mut self, key: &[u8]) {
            let _ = self.trie.remove(key);
        }

        /// Read the value at `key`.
        #[must_use]
        pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.trie.get(key)
        }

        /// Current trie root.
        #[must_use]
        pub const fn state_root(&self) -> StateRoot {
            self.trie.root()
        }

        /// Borrow the underlying trie (read-only).
        #[must_use]
        pub const fn trie(&self) -> &Trie<Blake3Hasher> {
            &self.trie
        }
    }

    /// `StateBackend` that wraps a [`LiveTrie`] and records every key
    /// the STF touches. Used during dry-run so the host can build a
    /// [`StateWitness`] for the SP1 Guest.
    pub struct TracingState<'a> {
        live: &'a LiveTrie,
        /// Per-block write overlay. Keyed by raw runtime key.
        overlay: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
        /// Reads + writes performed by the STF.
        accessed: BTreeSet<Vec<u8>>,
        pre_root: StateRoot,
        /// A scratch trie used to apply overlay writes so we can return
        /// the correct `post_state_root` without mutating `live`.
        ///
        /// Lazily initialised from `live` on the first write so the
        /// read-only paths stay free.
        scratch: Option<Trie<Blake3Hasher>>,
    }

    impl<'a> TracingState<'a> {
        /// Wrap a live trie for tracing.
        #[must_use]
        pub const fn new(live: &'a LiveTrie) -> Self {
            Self {
                live,
                overlay: BTreeMap::new(),
                accessed: BTreeSet::new(),
                pre_root: live.state_root(),
                scratch: None,
            }
        }

        /// Materialise the recorded read / write set as a
        /// [`StateWitness`] the SP1 Guest can replay against.
        ///
        /// The witness embeds every trie node along the touched paths
        /// (so the Guest can both read and re-root) and the leaf value
        /// bytes for present keys. The root node is always included
        /// (when the trie is non-empty) so the Guest can bind to the
        /// claimed `pre_state_root` even on blocks where the STF
        /// reads no state.
        #[must_use]
        pub fn into_witness(self) -> StateWitness {
            self.into_committed_and_witness().1
        }

        /// Consume the tracer and return both the **post-state trie**
        /// (with every overlay write applied) and the
        /// [`StateWitness`].
        ///
        /// The block producer uses this to advance the engine's
        /// authoritative state trie in lock-step with the witness it
        /// hands to the SP1 prover. The returned trie's
        /// `drain_pending_*` lists carry exactly the new content-
        /// addressed nodes and values produced by this block, so the
        /// engine can flush only the diff to RocksDB.
        ///
        /// If the STF performed no writes the returned trie is a
        /// clone of the live snapshot; the pending lists are empty
        /// and the root equals `pre_state_root`.
        #[must_use]
        pub fn into_committed_and_witness(self) -> (Trie<Blake3Hasher>, StateWitness) {
            let mut nodes = BTreeMap::new();
            let mut values = BTreeMap::new();
            for key in &self.accessed {
                self.live
                    .trie()
                    .collect_path_nodes(key, &mut nodes, &mut values);
            }
            // Always include the root node (when present) so an empty
            // access set still produces a witness the Guest can bind
            // to `pre_state_root`.
            if self.pre_root != neutrino_trie::EMPTY_TRIE_ROOT {
                if let Some(bytes) = self.live.trie().node_bytes(&self.pre_root) {
                    nodes.entry(self.pre_root).or_insert_with(|| bytes.to_vec());
                }
            }
            let witness = StateWitness {
                pre_state_root: self.pre_root,
                nodes: nodes
                    .into_iter()
                    .map(|(hash, bytes)| TrieNodeBytes { hash, bytes })
                    .collect(),
                values: values
                    .into_iter()
                    .map(|(hash, bytes)| TrieValueBytes { hash, bytes })
                    .collect(),
                witnessed_keys: self.accessed.into_iter().collect(),
            };
            // Read-only blocks fall back to a clone of the live trie
            // so the producer can swap the result back into the
            // engine unconditionally without inspecting the
            // scratch-was-initialised flag.
            let post_state = self.scratch.unwrap_or_else(|| self.live.trie().clone());
            (post_state, witness)
        }

        fn ensure_scratch(&mut self) -> &mut Trie<Blake3Hasher> {
            if self.scratch.is_none() {
                // Clone the live trie's content-addressed maps via
                // collect_path_nodes for every accessed key. We don't
                // own the live trie's full storage, but a clone of the
                // underlying `Trie` is cheap (BTreeMap clone), and the
                // STF only writes a handful of keys per block.
                self.scratch = Some(self.live.trie().clone());
            }
            self.scratch.as_mut().expect("scratch just initialised")
        }
    }

    impl StateBackend for TracingState<'_> {
        fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
            self.accessed.insert(key.to_vec());
            if let Some(slot) = self.overlay.get(key) {
                return slot.clone();
            }
            self.live.get(key)
        }

        fn write(&mut self, key: &[u8], value: Vec<u8>) {
            self.accessed.insert(key.to_vec());
            self.overlay.insert(key.to_vec(), Some(value.clone()));
            let trie = self.ensure_scratch();
            trie.insert(key, value)
                .expect("trie insert never fails for length-prefixed keys");
        }

        fn delete(&mut self, key: &[u8]) {
            self.accessed.insert(key.to_vec());
            self.overlay.insert(key.to_vec(), None);
            let trie = self.ensure_scratch();
            let _ = trie.remove(key);
        }

        fn pre_state_root(&self) -> StateRoot {
            self.pre_root
        }

        fn post_state_root(&self) -> StateRoot {
            self.scratch
                .as_ref()
                .map_or(self.pre_root, neutrino_trie::Trie::root)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_runtime_abi::{TrieNodeBytes, TrieValueBytes};

    fn empty_witness() -> StateWitness {
        StateWitness {
            pre_state_root: EMPTY_STATE_ROOT,
            nodes: alloc::vec![],
            values: alloc::vec![],
            witnessed_keys: alloc::vec![],
        }
    }

    #[test]
    fn empty_witness_yields_empty_state_root() {
        let state = WitnessState::new(&empty_witness()).unwrap();
        assert_eq!(state.pre_state_root(), EMPTY_STATE_ROOT);
        assert_eq!(state.post_state_root(), EMPTY_STATE_ROOT);
    }

    #[test]
    fn witness_state_rejects_non_empty_root_with_no_nodes() {
        let bad = StateWitness {
            pre_state_root: [9; 32],
            nodes: alloc::vec![],
            values: alloc::vec![],
            witnessed_keys: alloc::vec![],
        };
        let err = WitnessState::new(&bad).expect_err("must reject");
        assert!(matches!(err, WitnessError::PreRootMissing { .. }));
    }

    #[test]
    fn witness_state_rejects_forged_node_hash() {
        let bad = StateWitness {
            pre_state_root: [9; 32],
            nodes: alloc::vec![TrieNodeBytes {
                hash: [9; 32],
                bytes: b"clearly not the canonical node encoding".to_vec(),
            }],
            values: alloc::vec![],
            witnessed_keys: alloc::vec![],
        };
        let err = WitnessState::new(&bad).expect_err("must reject");
        assert!(matches!(err, WitnessError::NodeHashMismatch { .. }));
    }

    #[test]
    #[should_panic(expected = "witness missing entry for key")]
    fn witness_state_panics_on_unwitnessed_read() {
        let mut state = WitnessState::new(&empty_witness()).unwrap();
        let _ = state.read(b"unknown");
    }

    /// Force-construct a witness directly from raw node bytes to keep
    /// the test independent of the host's `LiveTrie` helper (which
    /// lives behind the `host` feature).
    #[test]
    fn witness_state_writes_change_post_state_root() {
        // Build a trie with a single key/value via TracingState-style
        // raw construction.
        let mut trie = Trie::<Blake3Hasher>::new();
        trie.insert(b"k", b"v".to_vec()).unwrap();
        let pre_root = trie.root();

        let mut nodes = alloc::collections::BTreeMap::new();
        let mut values = alloc::collections::BTreeMap::new();
        trie.collect_path_nodes(b"k", &mut nodes, &mut values);

        let witness = StateWitness {
            pre_state_root: pre_root,
            nodes: nodes
                .into_iter()
                .map(|(hash, bytes)| TrieNodeBytes { hash, bytes })
                .collect(),
            values: values
                .into_iter()
                .map(|(hash, bytes)| TrieValueBytes { hash, bytes })
                .collect(),
            witnessed_keys: alloc::vec![b"k".to_vec()],
        };

        let mut state = WitnessState::new(&witness).unwrap();
        assert_eq!(state.read(b"k").as_deref(), Some(b"v".as_ref()));
        state.write(b"k", b"v2".to_vec());
        assert_eq!(state.read(b"k").as_deref(), Some(b"v2".as_ref()));
        assert_ne!(state.post_state_root(), pre_root);
    }
}
