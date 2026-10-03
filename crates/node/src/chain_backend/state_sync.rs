//! Durable, bounded content-addressed state reconstruction.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::bootstrap::{MAX_STATE_ITEMS, StateEntry, StateItem, StateItemKind};
use neutrino_primitives::{Hash, ZERO_HASH};
use neutrino_storage::{Batch, Column, Database};
use neutrino_sync::{StateProgress, SyncBackendError};
use neutrino_trie::{Hasher, Node, Poseidon2Hasher, Trie};
use std::collections::{BTreeMap, BTreeSet};

use super::{ChainBackend, p2p_queries, rpc_queries};
use neutrino_proof_system::ProofSystem;

use neutrino_consensus_engine::store::pointers::{
    STATE_DOWNLOAD as DOWNLOAD_KEY, STATE_DOWNLOAD_ENTRY_PREFIX,
};
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(super) const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 2_000_000;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct Download {
    root: Hash,
    pending: BTreeSet<StateItem>,
    completed: BTreeSet<(StateItemKind, Hash)>,
    bytes: u64,
}

impl Download {
    fn new(root: Hash) -> Self {
        let pending = if root == ZERO_HASH {
            BTreeSet::new()
        } else {
            BTreeSet::from([StateItem::node(root)])
        };
        Self {
            root,
            pending,
            completed: BTreeSet::new(),
            bytes: 0,
        }
    }
    fn next(&self) -> Vec<StateItem> {
        self.pending.iter().take(MAX_STATE_ITEMS).copied().collect()
    }
    fn discover(&mut self, kind: StateItemKind, hash: Hash) -> Result<(), SyncBackendError> {
        if kind == StateItemKind::Node && hash == ZERO_HASH {
            return Ok(());
        }
        if !self.completed.contains(&(kind, hash))
            && !self
                .pending
                .iter()
                .any(|item| item.kind == kind && item.hash == hash)
        {
            if self.completed.len() + self.pending.len() >= MAX_ENTRIES {
                return Err(SyncBackendError::NotAvailable(
                    "state entry budget exceeded".into(),
                ));
            }
            self.pending.insert(StateItem {
                kind,
                hash,
                offset: 0,
            });
        }
        Ok(())
    }
    fn discover_children(&mut self, bytes: &[u8]) -> Result<(), SyncBackendError> {
        match Node::decode(bytes).map_err(|error| SyncBackendError::Rejected(error.to_string()))? {
            Node::Leaf { value_hash, .. } => {
                self.discover(StateItemKind::Value, value_hash)?;
            }
            Node::Branch { left, right } => {
                self.discover(StateItemKind::Node, left)?;
                self.discover(StateItemKind::Node, right)?;
            }
            Node::Extension { child, .. } => {
                self.discover(StateItemKind::Node, child)?;
            }
        }
        Ok(())
    }
}

fn key(root: Hash, kind: StateItemKind, hash: Hash) -> Vec<u8> {
    let mut key = STATE_DOWNLOAD_ENTRY_PREFIX.to_vec();
    key.extend_from_slice(&root);
    key.push(u8::from(kind != StateItemKind::Node));
    key.extend_from_slice(&hash);
    key
}

fn load<DB: Database>(db: &DB, root: Hash) -> Result<Download, SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    let Some(bytes) = db
        .get(Column::Meta, DOWNLOAD_KEY)
        .map_err(p2p_queries::storage_error)?
    else {
        return Ok(Download::new(root));
    };
    if bytes.len() > MAX_ENTRIES * 80 + 128 {
        return Err(p2p_queries::storage_error(
            "oversized state download metadata",
        ));
    }
    let download: Download = borsh::from_slice(&bytes).map_err(p2p_queries::storage_error)?;
    if download.root != root {
        return Err(SyncBackendError::NotAvailable(
            "another state snapshot is being reconstructed".into(),
        ));
    }
    if download.completed.len() + download.pending.len() > MAX_ENTRIES
        || download.bytes > DEFAULT_MAX_BYTES
    {
        return Err(p2p_queries::storage_error(
            "state download metadata exceeds budget",
        ));
    }
    Ok(download)
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(super) fn state_download_items(
        &self,
        root: Hash,
    ) -> Result<Vec<StateItem>, SyncBackendError> {
        self.with_engine(|engine| load(engine.store().db(), root).map(|download| download.next()))
    }

    pub(super) fn receive_state_entries(
        &self,
        root: Hash,
        requested: &[StateItem],
        entries: &[StateEntry],
    ) -> Result<StateProgress, SyncBackendError> {
        if requested.len() > MAX_STATE_ITEMS || requested.len() != entries.len() {
            return Err(SyncBackendError::Rejected(
                "state response does not match requested fragment count".into(),
            ));
        }
        self.with_engine_mut(|engine| {
            self.authorize_state_download(root)?;
            let db = engine.store().db();
            let mut download = load(db, root)?;
            let mut batch = Batch::new();
            for (expected, entry) in requested.iter().zip(entries) {
                if !entry.validate_for(expected) {
                    return Err(SyncBackendError::Rejected(
                        "state fragment framing mismatch".into(),
                    ));
                }
                if !download.pending.contains(expected) || entry.total_len > MAX_ENTRY_BYTES {
                    return Err(SyncBackendError::Rejected(
                        "unsolicited or oversized state fragment".into(),
                    ));
                }
                let storage_key = key(root, expected.kind, expected.hash);
                let mut bytes = db
                    .get(Column::Meta, &storage_key)
                    .map_err(p2p_queries::storage_error)?
                    .unwrap_or_default();
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != expected.offset {
                    return Err(p2p_queries::storage_error(
                        "state fragment offset disagrees with durable progress",
                    ));
                }
                bytes.extend_from_slice(entry.bytes.as_slice());
                download.bytes = download
                    .bytes
                    .checked_add(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX))
                    .filter(|bytes| *bytes <= DEFAULT_MAX_BYTES)
                    .ok_or_else(|| {
                        SyncBackendError::NotAvailable("state byte budget exceeded".into())
                    })?;
                download.pending.remove(expected);
                let offset = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                if offset == entry.total_len {
                    let hash = match expected.kind {
                        StateItemKind::Node => Poseidon2Hasher::hash_node(&bytes),
                        StateItemKind::Value => Poseidon2Hasher::hash_value(&bytes),
                    };
                    if hash != expected.hash {
                        // Retry this exact object from byte zero with another provider.
                        let mut reset = load(db, root)?;
                        reset.pending.remove(expected);
                        reset.pending.insert(StateItem {
                            offset: 0,
                            ..*expected
                        });
                        reset.bytes = reset.bytes.saturating_sub(expected.offset);
                        let mut discard = Batch::new();
                        discard.delete(Column::Meta, storage_key);
                        discard.put(
                            Column::Meta,
                            DOWNLOAD_KEY,
                            borsh::to_vec(&reset).map_err(p2p_queries::storage_error)?,
                        );
                        engine
                            .store_mut()
                            .db_mut()
                            .write_batch_durable(discard)
                            .map_err(p2p_queries::storage_error)?;
                        return Err(SyncBackendError::Rejected(
                            "state object content hash mismatch".into(),
                        ));
                    }
                    if expected.kind == StateItemKind::Node {
                        download.discover_children(&bytes)?;
                    }
                    download.completed.insert((expected.kind, expected.hash));
                } else {
                    download.pending.insert(StateItem {
                        offset,
                        ..*expected
                    });
                }
                batch.put(Column::Meta, storage_key, bytes);
            }
            batch.put(
                Column::Meta,
                DOWNLOAD_KEY,
                borsh::to_vec(&download).map_err(p2p_queries::storage_error)?,
            );
            engine
                .store_mut()
                .db_mut()
                .write_batch_durable(batch)
                .map_err(p2p_queries::storage_error)?;
            Ok(StateProgress {
                root_complete: download.pending.is_empty(),
                next_items: download.next(),
            })
        })
    }

    pub(super) fn reconstructed_state(&self, root: Hash) -> Result<Trie, SyncBackendError> {
        self.with_engine(|engine| {
            let db = engine.store().db();
            let download = load(db, root)?;
            if !download.pending.is_empty() {
                return Err(SyncBackendError::NotAvailable(
                    "state snapshot is incomplete".into(),
                ));
            }
            let mut nodes = BTreeMap::new();
            let mut values = BTreeMap::new();
            for (kind, hash) in &download.completed {
                let bytes = db
                    .get(Column::Meta, &key(root, *kind, *hash))
                    .map_err(p2p_queries::storage_error)?
                    .ok_or_else(|| {
                        p2p_queries::storage_error("completed state object is missing")
                    })?;
                match kind {
                    StateItemKind::Node => {
                        nodes.insert(*hash, bytes);
                    }
                    StateItemKind::Value => {
                        values.insert(*hash, bytes);
                    }
                }
            }
            let authenticated = rpc_queries::authenticate_state(
                root,
                |hash| {
                    nodes
                        .get(&hash)
                        .cloned()
                        .ok_or(neutrino_rpc::QueryError::StateUnavailable)
                },
                |hash| {
                    values
                        .get(&hash)
                        .cloned()
                        .ok_or(neutrino_rpc::QueryError::StateUnavailable)
                },
            )
            .map_err(p2p_queries::query_error)?;
            if authenticated.nodes.len() != nodes.len()
                || authenticated.values.len() != values.len()
            {
                return Err(SyncBackendError::Rejected(
                    "state snapshot contains unreachable entries".into(),
                ));
            }
            Ok(Trie::from_persisted(root, nodes, values))
        })
    }

    pub(super) fn clear_state_download(&self, root: Hash) -> Result<(), SyncBackendError> {
        self.with_engine_mut(|engine| {
            let download = load(engine.store().db(), root)?;
            let mut batch = Batch::new();
            for (kind, hash) in download
                .completed
                .iter()
                .copied()
                .chain(download.pending.iter().map(|item| (item.kind, item.hash)))
            {
                batch.delete(Column::Meta, key(root, kind, hash));
            }
            batch.delete(Column::Meta, DOWNLOAD_KEY);
            engine
                .store_mut()
                .db_mut()
                .write_batch_durable(batch)
                .map_err(p2p_queries::storage_error)
        })
    }
}
