//! Write overlay over a base state trie.
//!
//! The runtime sees a mutable key-value store while executing a block,
//! but the underlying trie is touched only once at the end. The
//! overlay buffers every `state_write` / `state_delete` in memory,
//! returns the live (overlay-aware) value for every `state_read`, and
//! commits all staged mutations to the trie when [`Overlay::commit`]
//! is called. On block rejection the overlay is dropped; the trie is
//! never partially modified.
//!
//! The overlay is keyed by the raw runtime key bytes; the trie's
//! length-prefix encoding handles prefix-free addressing internally
//! (see `neutrino-trie` docs).

use std::collections::BTreeMap;

use neutrino_primitives::StateRoot;
use neutrino_trie::Trie;

/// A single pending overlay mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OverlayEntry {
    /// A put with the given value bytes.
    Put(Vec<u8>),
    /// A delete; reads on this key return `None`.
    Delete,
}

/// Mutable view over a base [`Trie`]. Reads consult the staged entries
/// first and fall back to the trie; writes and deletes stage entries
/// that [`Overlay::commit`] flushes atomically.
#[derive(Debug)]
pub struct Overlay {
    dirty: BTreeMap<Vec<u8>, OverlayEntry>,
    base: Trie,
    base_root: StateRoot,
}

impl Overlay {
    /// Build a new overlay over `base`. Captures the trie's current
    /// root so [`Overlay::base_root`] keeps returning it even after
    /// staged mutations.
    #[must_use]
    pub const fn new(base: Trie) -> Self {
        let base_root = base.root();
        Self {
            dirty: BTreeMap::new(),
            base,
            base_root,
        }
    }

    /// Build an overlay over an empty trie.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Trie::new is not const.
    pub fn empty() -> Self {
        Self::new(Trie::new())
    }

    /// Snapshot of the trie root at the moment the overlay was created.
    /// Does not reflect staged mutations.
    #[must_use]
    pub const fn base_root(&self) -> StateRoot {
        self.base_root
    }

    /// Live trie root *of the base trie*. Equal to [`Overlay::base_root`]
    /// for as long as the overlay is held; provided for use after
    /// [`Overlay::commit`] applied the staged mutations.
    #[must_use]
    pub const fn current_root(&self) -> StateRoot {
        self.base.root()
    }

    /// Number of staged mutations (puts and deletes combined). Used by
    /// the gas accounting for `state_root(dirty)`.
    #[must_use]
    pub fn dirty_count(&self) -> usize {
        self.dirty.len()
    }

    /// Read the overlay-aware value for `key`. `None` is returned for
    /// keys not in the staged set and not in the trie, and for keys
    /// staged as deleted.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self.dirty.get(key) {
            Some(OverlayEntry::Put(v)) => Some(v.clone()),
            Some(OverlayEntry::Delete) => None,
            None => self.base.get(key),
        }
    }

    /// `true` if [`Overlay::get`] would return `Some`. Equivalent to a
    /// read without materialising the value.
    #[must_use]
    pub fn exists(&self, key: &[u8]) -> bool {
        match self.dirty.get(key) {
            Some(OverlayEntry::Put(_)) => true,
            Some(OverlayEntry::Delete) => false,
            None => self.base.get(key).is_some(),
        }
    }

    /// Stage a put. Overwrites a previously staged put or delete for
    /// the same key.
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.dirty.insert(key, OverlayEntry::Put(value));
    }

    /// Stage a delete. Overwrites a previously staged put or delete
    /// for the same key.
    pub fn delete(&mut self, key: Vec<u8>) {
        self.dirty.insert(key, OverlayEntry::Delete);
    }

    /// Apply every staged mutation to the underlying trie and return
    /// the new root. The overlay is left empty of staged mutations.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`neutrino_trie::TrieError`] when a put
    /// would create a prefix-colliding pair. The reference trie
    /// length-prefixes byte keys so this never happens for legitimate
    /// runtime keys; the error is exposed only so callers can surface
    /// it without panicking.
    pub fn commit(&mut self) -> Result<StateRoot, neutrino_trie::TrieError> {
        let dirty = core::mem::take(&mut self.dirty);
        for (key, entry) in dirty {
            match entry {
                OverlayEntry::Put(value) => {
                    self.base.insert(&key, value)?;
                }
                OverlayEntry::Delete => {
                    self.base.remove(&key);
                }
            }
        }
        Ok(self.base.root())
    }

    /// Consume the overlay and return the underlying [`Trie`].
    ///
    /// Useful for callers (e.g. the consensus engine) that build a
    /// fresh overlay per block and need to thread the live state trie
    /// across calls without cloning.
    #[must_use]
    pub fn into_base(self) -> Trie {
        self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn populated_trie() -> Trie {
        let mut t = Trie::new();
        t.insert(b"alpha", b"1".to_vec()).unwrap();
        t.insert(b"beta", b"2".to_vec()).unwrap();
        t
    }

    #[test]
    fn empty_overlay_reads_pass_through_to_trie() {
        let overlay = Overlay::new(populated_trie());
        assert_eq!(overlay.get(b"alpha"), Some(b"1".to_vec()));
        assert_eq!(overlay.get(b"beta"), Some(b"2".to_vec()));
        assert_eq!(overlay.get(b"gamma"), None);
        assert_eq!(overlay.dirty_count(), 0);
    }

    #[test]
    fn put_shadows_base_read() {
        let mut overlay = Overlay::new(populated_trie());
        overlay.put(b"alpha".to_vec(), b"updated".to_vec());
        assert_eq!(overlay.get(b"alpha"), Some(b"updated".to_vec()));
        assert_eq!(overlay.dirty_count(), 1);
    }

    #[test]
    fn put_then_overwrite_collapses_to_last_value() {
        let mut overlay = Overlay::empty();
        overlay.put(b"k".to_vec(), b"v1".to_vec());
        overlay.put(b"k".to_vec(), b"v2".to_vec());
        assert_eq!(overlay.get(b"k"), Some(b"v2".to_vec()));
        assert_eq!(overlay.dirty_count(), 1);
    }

    #[test]
    fn delete_hides_base_read() {
        let mut overlay = Overlay::new(populated_trie());
        overlay.delete(b"alpha".to_vec());
        assert_eq!(overlay.get(b"alpha"), None);
        assert!(!overlay.exists(b"alpha"));
        assert!(overlay.exists(b"beta"));
    }

    #[test]
    fn delete_followed_by_put_makes_key_visible_again() {
        let mut overlay = Overlay::new(populated_trie());
        overlay.delete(b"alpha".to_vec());
        overlay.put(b"alpha".to_vec(), b"resurrected".to_vec());
        assert_eq!(overlay.get(b"alpha"), Some(b"resurrected".to_vec()));
    }

    #[test]
    fn put_followed_by_delete_hides_key() {
        let mut overlay = Overlay::empty();
        overlay.put(b"k".to_vec(), b"v".to_vec());
        overlay.delete(b"k".to_vec());
        assert!(!overlay.exists(b"k"));
        assert_eq!(overlay.get(b"k"), None);
    }

    #[test]
    fn commit_applies_puts_and_returns_new_root() {
        let trie = populated_trie();
        let base_root = trie.root();
        let mut overlay = Overlay::new(trie);
        overlay.put(b"gamma".to_vec(), b"3".to_vec());
        let new_root = overlay.commit().unwrap();
        assert_ne!(new_root, base_root);
        assert_eq!(overlay.get(b"gamma"), Some(b"3".to_vec()));
        assert_eq!(overlay.dirty_count(), 0);
    }

    #[test]
    fn commit_applies_deletes_and_returns_new_root() {
        let trie = populated_trie();
        let base_root = trie.root();
        let mut overlay = Overlay::new(trie);
        overlay.delete(b"alpha".to_vec());
        let new_root = overlay.commit().unwrap();
        assert_ne!(new_root, base_root);
        assert_eq!(overlay.get(b"alpha"), None);
        assert_eq!(overlay.get(b"beta"), Some(b"2".to_vec()));
    }

    #[test]
    fn base_root_does_not_move_after_staging() {
        let trie = populated_trie();
        let captured = trie.root();
        let mut overlay = Overlay::new(trie);
        overlay.put(b"x".to_vec(), b"y".to_vec());
        assert_eq!(overlay.base_root(), captured);
        assert_eq!(overlay.current_root(), captured); // commit not called yet
    }

    #[test]
    fn empty_overlay_commit_returns_empty_root() {
        let mut overlay = Overlay::empty();
        let root = overlay.commit().unwrap();
        assert_eq!(root, neutrino_trie::EMPTY_TRIE_ROOT);
    }

    #[test]
    fn into_base_recovers_the_committed_trie() {
        let mut overlay = Overlay::empty();
        overlay.put(b"k1".to_vec(), b"v1".to_vec());
        overlay.put(b"k2".to_vec(), b"v2".to_vec());
        let new_root = overlay.commit().expect("commit");
        let trie = overlay.into_base();
        assert_eq!(trie.root(), new_root);
        assert_eq!(trie.get(b"k1"), Some(b"v1".to_vec()));
        assert_eq!(trie.get(b"k2"), Some(b"v2".to_vec()));
    }
}
