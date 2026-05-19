#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Framework code shared by every Neutrino runtime.
//!
//! Defines the [`StateBackend`] trait that the STF is generic over, the
//! canonical [`state_root_of`] hash used to commit to a state snapshot,
//! and two backend implementations:
//!
//! - [`WitnessState`] — `no_std + alloc`. Used inside the SP1 Guest;
//!   built from a [`StateWitness`] and refuses reads of unwitnessed keys.
//! - [`host::TracingState`] — only available with the `host` feature.
//!   Used by the dynamic runtime host during dry-run to record the
//!   read/write set that becomes the witness.
//!
//! Wire formats live in `neutrino-runtime-abi`; this crate is pure Rust
//! code with no consensus-critical wire definitions of its own apart
//! from [`state_root_of`].

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use neutrino_primitives::StateRoot;
use neutrino_runtime_abi::StateWitness;

/// Domain tag for the canonical state-root hash. Disjoint from every
/// other BLAKE3 domain used in the protocol.
pub const DOMAIN_STATE_ROOT: &[u8; 16] = b"NTRO/state-root\x00";

/// Sentinel state root for an empty state: BLAKE3(domain || 0u64).
#[must_use]
pub fn empty_state_root() -> StateRoot {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_STATE_ROOT);
    hasher.update(&0u64.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Canonical hash of a state snapshot.
///
/// `BLAKE3(DOMAIN_STATE_ROOT || count_le || (key_len_le || key || value_len_le || value)*)`
/// over entries sorted ascending by key. Used by both [`WitnessState`]
/// and [`host::TracingState`] so the host and the SP1 Guest agree on
/// pre/post-state-root values for the same snapshot.
///
/// M2-new uses this canonical hash as the state commitment instead of
/// the binary Merkle trie used by storage. M4-new replaces this with a
/// Merkle witness once STF semantics warrant it.
#[must_use]
pub fn state_root_of<'a, I>(entries: I) -> StateRoot
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    let mut sorted: Vec<(&[u8], &[u8])> = entries.into_iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));

    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_STATE_ROOT);
    hasher.update(&(sorted.len() as u64).to_le_bytes());
    for (k, v) in &sorted {
        hasher.update(&(k.len() as u64).to_le_bytes());
        hasher.update(k);
        hasher.update(&(v.len() as u64).to_le_bytes());
        hasher.update(v);
    }
    *hasher.finalize().as_bytes()
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

    /// Canonical root of the state before any writes this run made.
    fn pre_state_root(&self) -> StateRoot;

    /// Canonical root of the state including writes from this run.
    fn post_state_root(&self) -> StateRoot;
}

/// Errors thrown when constructing a [`WitnessState`].
#[derive(Debug, Eq, PartialEq)]
pub enum WitnessError {
    /// The canonical hash of the witnessed entries did not match the
    /// claimed `pre_state_root`. Always treat this as adversarial.
    PreRootMismatch {
        /// Root computed from witness entries.
        computed: StateRoot,
        /// Root the witness claims to commit to.
        claimed: StateRoot,
    },
}

/// `StateBackend` driven entirely by a [`StateWitness`].
///
/// `read` panics for any key not present in the witness's entry set,
/// which makes the SP1 Guest abort proving when the host supplies an
/// incomplete witness. Writes are tracked in-memory; `post_state_root`
/// rehashes the updated state via [`state_root_of`].
#[derive(Debug)]
pub struct WitnessState {
    /// Keys explicitly witnessed. Reads outside this set panic.
    witnessed: BTreeSet<Vec<u8>>,
    /// Working state (entries with `value=None` are simply absent from
    /// this map; they remain in `witnessed`).
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Pre-state root claimed by the witness, validated at construction.
    pre_root: StateRoot,
}

impl WitnessState {
    /// Build a `WitnessState` and verify it matches the claimed
    /// `pre_state_root`. Used by the SP1 Guest as the first step of
    /// proof generation.
    ///
    /// # Errors
    /// Returns [`WitnessError::PreRootMismatch`] when the canonical
    /// hash of the witnessed entries disagrees with the claimed root.
    pub fn new(witness: &StateWitness) -> Result<Self, WitnessError> {
        let mut state = BTreeMap::new();
        let mut witnessed = BTreeSet::new();
        for entry in &witness.entries {
            witnessed.insert(entry.key.clone());
            if let Some(value) = &entry.value {
                state.insert(entry.key.clone(), value.clone());
            }
        }

        let computed = state_root_of(state.iter().map(|(k, v)| (k.as_slice(), v.as_slice())));
        if computed != witness.pre_state_root {
            return Err(WitnessError::PreRootMismatch {
                computed,
                claimed: witness.pre_state_root,
            });
        }

        Ok(Self {
            witnessed,
            state,
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
        self.state.get(key).cloned()
    }

    fn write(&mut self, key: &[u8], value: Vec<u8>) {
        // Writes are implicitly witnessed: once the STF wrote to a key,
        // its prior state was either part of the witness or the STF
        // logic created it from scratch.
        self.witnessed.insert(key.to_vec());
        self.state.insert(key.to_vec(), value);
    }

    fn delete(&mut self, key: &[u8]) {
        self.witnessed.insert(key.to_vec());
        self.state.remove(key);
    }

    fn pre_state_root(&self) -> StateRoot {
        self.pre_root
    }

    fn post_state_root(&self) -> StateRoot {
        state_root_of(self.state.iter().map(|(k, v)| (k.as_slice(), v.as_slice())))
    }
}

/// Host-side state implementations used by the dynamic runtime and the
/// dry-run path that builds witnesses.
#[cfg(feature = "host")]
pub mod host {
    use super::{BTreeMap, BTreeSet, StateBackend, StateRoot, StateWitness, Vec, state_root_of};
    use neutrino_runtime_abi::WitnessEntry;

    /// In-memory pre-state used by tests and by the dry-run path.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct LiveStateMap {
        /// Backing key/value store.
        pub state: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl LiveStateMap {
        /// Insert a key/value pair into the live state.
        pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
            self.state.insert(key, value);
        }

        /// Remove a key from the live state.
        pub fn remove(&mut self, key: &[u8]) {
            self.state.remove(key);
        }

        /// Canonical root of the live state.
        #[must_use]
        pub fn state_root(&self) -> StateRoot {
            state_root_of(self.state.iter().map(|(k, v)| (k.as_slice(), v.as_slice())))
        }
    }

    /// `StateBackend` that wraps a [`LiveStateMap`] and records every
    /// key the STF touches. Used during dry-run so the host can build
    /// a [`StateWitness`] for the SP1 Guest.
    pub struct TracingState<'a> {
        live: &'a LiveStateMap,
        overlay: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
        reads: BTreeSet<Vec<u8>>,
        pre_root: StateRoot,
    }

    impl<'a> TracingState<'a> {
        /// Wrap a live state for tracing.
        #[must_use]
        pub fn new(live: &'a LiveStateMap) -> Self {
            let pre_root = live.state_root();
            Self {
                live,
                overlay: BTreeMap::new(),
                reads: BTreeSet::new(),
                pre_root,
            }
        }

        /// Materialise the recorded reads as a [`StateWitness`] suitable
        /// for the SP1 Guest. Drops the overlay (witness is pre-state).
        #[must_use]
        pub fn into_witness(self) -> StateWitness {
            let entries: Vec<WitnessEntry> = self
                .reads
                .iter()
                .map(|k| WitnessEntry {
                    key: k.clone(),
                    value: self.live.state.get(k).cloned(),
                })
                .collect();
            StateWitness {
                pre_state_root: self.pre_root,
                entries,
            }
        }
    }

    impl StateBackend for TracingState<'_> {
        fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
            self.reads.insert(key.to_vec());
            if let Some(slot) = self.overlay.get(key) {
                return slot.clone();
            }
            self.live.state.get(key).cloned()
        }

        fn write(&mut self, key: &[u8], value: Vec<u8>) {
            self.reads.insert(key.to_vec());
            self.overlay.insert(key.to_vec(), Some(value));
        }

        fn delete(&mut self, key: &[u8]) {
            self.reads.insert(key.to_vec());
            self.overlay.insert(key.to_vec(), None);
        }

        fn pre_state_root(&self) -> StateRoot {
            self.pre_root
        }

        fn post_state_root(&self) -> StateRoot {
            // Materialise effective state = live ∪ overlay.
            let mut merged: BTreeMap<&[u8], &[u8]> = self
                .live
                .state
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect();
            for (k, slot) in &self.overlay {
                match slot {
                    Some(v) => {
                        merged.insert(k.as_slice(), v.as_slice());
                    }
                    None => {
                        merged.remove(k.as_slice());
                    }
                }
            }
            state_root_of(merged)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_runtime_abi::WitnessEntry;

    #[test]
    fn empty_state_root_is_stable() {
        // Pin the constant: this value is consensus-critical.
        let root = empty_state_root();
        assert_eq!(root, state_root_of(core::iter::empty()));
    }

    #[test]
    fn state_root_is_order_insensitive() {
        let a = state_root_of([
            (b"a".as_slice(), b"1".as_slice()),
            (b"b".as_slice(), b"2".as_slice()),
        ]);
        let b = state_root_of([
            (b"b".as_slice(), b"2".as_slice()),
            (b"a".as_slice(), b"1".as_slice()),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn witness_state_rejects_pre_root_mismatch() {
        let witness = StateWitness {
            pre_state_root: [9; 32],
            entries: alloc::vec![WitnessEntry {
                key: b"k".to_vec(),
                value: Some(b"v".to_vec()),
            }],
        };
        let err = WitnessState::new(&witness).expect_err("mismatched root must fail");
        assert!(matches!(err, WitnessError::PreRootMismatch { .. }));
    }

    #[test]
    fn witness_state_accepts_consistent_witness() {
        let pre = state_root_of([(b"k".as_slice(), b"v".as_slice())]);
        let witness = StateWitness {
            pre_state_root: pre,
            entries: alloc::vec![WitnessEntry {
                key: b"k".to_vec(),
                value: Some(b"v".to_vec()),
            }],
        };
        let state = WitnessState::new(&witness).expect("consistent witness accepted");
        assert_eq!(state.pre_state_root(), pre);
    }

    #[test]
    #[should_panic(expected = "witness missing entry for key")]
    fn witness_state_panics_on_unwitnessed_read() {
        let witness = StateWitness {
            pre_state_root: empty_state_root(),
            entries: alloc::vec![],
        };
        let mut state = WitnessState::new(&witness).expect("empty witness consistent");
        let _ = state.read(b"unknown");
    }
}
