//! RPC views are selected by block hash and read from its committed state root.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use neutrino_consensus_engine::{Engine, RetentionPolicy};
use neutrino_consensus_types::{Block, Header, HistoryProof};
use neutrino_mempool::InsertError;
use neutrino_primitives::{BlockHash, ChainId, Hash, Height, Validator, ZERO_HASH};
use neutrino_proof_system::ProofSystem;
use neutrino_rpc::{
    BlockId, FinalizedInfo, HeadInfo, HistoryRetention, QueryError, RpcBackend, RuntimeCallError,
    RuntimeCallResponse, SubmitError,
};
use neutrino_storage::{Column, Database};
use neutrino_trie::{Hasher, Node, Poseidon2Hasher, Trie};

use super::ChainBackend;

fn storage_error(error: impl core::fmt::Display) -> QueryError {
    QueryError::Storage(error.to_string())
}

pub(super) fn retention_info<DB: Database>(
    engine: &Engine<DB>,
) -> Result<HistoryRetention, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let retention = engine.retention_info().map_err(storage_error)?;
    Ok(HistoryRetention {
        archive: retention.policy == RetentionPolicy::Archive && retention.pruned_before_chunk == 0,
        retained_from_chunk: Some(retention.pruned_before_chunk),
        retained_from_height: Some(retention.first_retained_height),
        finalized_chunks: engine
            .latest_finalized_chunk_id()
            .map_or(0, |id| id.saturating_add(1)),
        recursive_covered_chunks: engine.recursive_covered_chunks(),
    })
}

pub(super) fn ensure_payload_height<DB: Database>(
    engine: &Engine<DB>,
    height: Height,
) -> Result<(), QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let retention = engine.retention_info().map_err(storage_error)?;
    if height > 0 && height < retention.first_retained_height {
        return Err(QueryError::Pruned {
            retained_from_chunk: retention.pruned_before_chunk,
            retained_from_height: retention.first_retained_height,
        });
    }
    Ok(())
}

pub(super) fn ensure_history_endpoints<DB: Database>(
    engine: &Engine<DB>,
    start: Hash,
    end: Hash,
) -> Result<(), QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    for hash in [start, end] {
        if engine
            .store()
            .checkpoint_by_hash(&hash)
            .map_err(storage_error)?
            .is_none()
        {
            return Err(QueryError::HistoryUnavailable);
        }
    }
    Ok(())
}

pub(super) fn read_history_proof<DB: Database>(
    engine: &Engine<DB>,
    start: Hash,
    end: Hash,
) -> Result<Option<HistoryProof>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    ensure_history_endpoints(engine, start, end)?;
    let proof = engine
        .history_proof_by_endpoints(start, end)
        .map_err(storage_error)?;
    if proof.is_none() {
        let start = engine
            .store()
            .checkpoint_by_hash(&start)
            .map_err(storage_error)?
            .ok_or(QueryError::HistoryUnavailable)?;
        let retention = engine.retention_info().map_err(storage_error)?;
        if start.boundary.next_chunk_id < retention.pruned_before_chunk {
            return Err(QueryError::Pruned {
                retained_from_chunk: retention.pruned_before_chunk,
                retained_from_height: retention.first_retained_height,
            });
        }
    }
    Ok(proof)
}

pub(super) fn checked_header<DB: Database>(
    engine: &Engine<DB>,
    hash: BlockHash,
) -> Result<Option<Header>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let header = engine.store().get_header(&hash).map_err(storage_error)?;
    if header.as_ref().is_some_and(|header| header.hash() != hash) {
        return Err(storage_error("stored header does not match its block hash"));
    }
    Ok(header)
}

fn required_header<DB: Database>(engine: &Engine<DB>, hash: BlockHash) -> Result<Header, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    checked_header(engine, hash)?.ok_or_else(|| storage_error("selected chain header is missing"))
}

pub(super) fn finalized_info<DB: Database>(engine: &Engine<DB>) -> Result<FinalizedInfo, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let block_hash = engine.fork_choice_finalized();
    let spec = engine.chain_spec();
    if block_hash == spec.genesis_block_hash {
        return Ok(FinalizedInfo {
            chunk_id: None,
            block_hash,
            height: 0,
            state_root: spec.genesis_state_root,
        });
    }
    let header = required_header(engine, block_hash)?;
    let chunk_id = engine
        .latest_finalized_chunk_id()
        .ok_or_else(|| storage_error("finalized boundary has no chunk ID"))?;
    Ok(FinalizedInfo {
        chunk_id: Some(chunk_id),
        block_hash,
        height: header.height,
        state_root: header.state_root,
    })
}

fn resolve_id<DB: Database>(
    engine: &Engine<DB>,
    id: &BlockId,
) -> Result<Option<BlockHash>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    match id {
        BlockId::Latest => {
            let hash = engine.head_hash();
            if hash != engine.chain_spec().genesis_block_hash {
                let _ = required_header(engine, hash)?;
            }
            Ok(Some(hash))
        }
        BlockId::Finalized => Ok(Some(finalized_info(engine)?.block_hash)),
        BlockId::Hash(hash) => {
            if *hash == engine.chain_spec().genesis_block_hash {
                return Ok(Some(*hash));
            }
            Ok(checked_header(engine, *hash)?.map(|_| *hash))
        }
        BlockId::Height(height) => {
            if *height > engine.head_height() {
                return Ok(None);
            }
            let hash = engine
                .store()
                .get_block_hash_by_height(*height)
                .map_err(storage_error)?;
            let Some(hash) = hash else {
                ensure_payload_height(engine, *height)?;
                return Err(storage_error("canonical height is missing"));
            };
            if *height == 0 {
                if hash != engine.chain_spec().genesis_block_hash {
                    return Err(storage_error("canonical genesis anchor is inconsistent"));
                }
            } else if required_header(engine, hash)?.height != *height {
                return Err(storage_error("canonical height does not match its header"));
            }
            Ok(Some(hash))
        }
    }
}

pub(super) fn read_block<DB: Database>(
    engine: &Engine<DB>,
    hash: BlockHash,
) -> Result<Option<Block>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let Some(header) = checked_header(engine, hash)? else {
        return Ok(None);
    };
    ensure_payload_height(engine, header.height)?;
    let body = engine
        .store()
        .get_body(&hash)
        .map_err(storage_error)?
        .ok_or(QueryError::BodyUnavailable)?;
    let roots = neutrino_consensus_engine::compute_body_roots(&body);
    if roots.da_root != header.da_root
        || roots.transactions_root != header.transactions_root
        || roots.votes_root != header.votes_root
    {
        return Err(storage_error(
            "stored body does not match the header commitment",
        ));
    }
    Ok(Some(Block { header, body }))
}

fn read_state<DB: Database>(engine: &Engine<DB>, at: &BlockId) -> Result<Trie, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let hash = resolve_id(engine, at)?.ok_or(QueryError::BlockNotFound)?;
    let (root, height) = if hash == engine.chain_spec().genesis_block_hash {
        (engine.chain_spec().genesis_state_root, 0)
    } else {
        let header = required_header(engine, hash)?;
        (header.state_root, header.height)
    };
    let data = read_state_data(engine, root).or_else(|error| {
        if error == QueryError::StateUnavailable {
            ensure_payload_height(engine, height)?;
        }
        Err(error)
    })?;
    Ok(Trie::from_persisted(root, data.nodes, data.values))
}

pub(super) struct AuthenticatedState {
    pub(super) nodes: BTreeMap<Hash, Vec<u8>>,
    pub(super) values: BTreeMap<Hash, Vec<u8>>,
}

pub(super) fn read_state_data<DB: Database>(
    engine: &Engine<DB>,
    root: Hash,
) -> Result<AuthenticatedState, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let db = engine.store().db();
    authenticate_state(
        root,
        |hash| {
            db.get(Column::TrieNodes, &hash)
                .map_err(storage_error)?
                .ok_or(QueryError::StateUnavailable)
        },
        |hash| {
            db.get(Column::StateValues, &hash)
                .map_err(storage_error)?
                .ok_or(QueryError::StateUnavailable)
        },
    )
}

pub(super) fn authenticate_state(
    root: Hash,
    mut node_bytes: impl FnMut(Hash) -> Result<Vec<u8>, QueryError>,
    mut value_bytes: impl FnMut(Hash) -> Result<Vec<u8>, QueryError>,
) -> Result<AuthenticatedState, QueryError> {
    let mut pending = vec![root];
    let mut nodes = BTreeMap::new();
    let mut values = BTreeMap::new();
    // Only the selected root's reachable nodes are loaded. Validate the complete
    // closure before Trie::get or a runtime can mistake missing data for absence.
    while let Some(hash) = pending.pop() {
        if hash == ZERO_HASH || nodes.contains_key(&hash) {
            continue;
        }
        let bytes = node_bytes(hash)?;
        if Poseidon2Hasher::hash_node(&bytes) != hash {
            return Err(storage_error("trie node does not match its content hash"));
        }
        match Node::decode(&bytes).map_err(storage_error)? {
            Node::Leaf { value_hash, .. } => {
                if let std::collections::btree_map::Entry::Vacant(entry) = values.entry(value_hash)
                {
                    let value = value_bytes(value_hash)?;
                    if Poseidon2Hasher::hash_value(&value) != value_hash {
                        return Err(storage_error("state value does not match its content hash"));
                    }
                    entry.insert(value);
                }
            }
            Node::Branch { left, right } => pending.extend([left, right]),
            Node::Extension { prefix, child } => {
                if prefix.bit_len() == 0 || child == ZERO_HASH {
                    return Err(storage_error("invalid trie extension"));
                }
                pending.push(child);
            }
        }
        nodes.insert(hash, bytes);
    }
    Ok(AuthenticatedState { nodes, values })
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    async fn rpc_state_snapshot(&self, at: &BlockId) -> Result<Trie, QueryError> {
        if self.light_checkpoint().is_some() {
            return Err(QueryError::StateUnavailable);
        }
        let engine = Arc::clone(&self.engine);
        let at = at.clone();
        tokio::task::spawn_blocking(move || {
            let engine = engine.lock().expect("engine mutex poisoned");
            read_state(&engine, &at)
        })
        .await
        .map_err(storage_error)?
    }
}

#[async_trait]
impl<DB, P> RpcBackend for ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    async fn history_retention(&self) -> Result<HistoryRetention, QueryError> {
        if let Some(checkpoint) = self.light_checkpoint() {
            return Ok(HistoryRetention {
                finalized_chunks: checkpoint.boundary.next_chunk_id,
                recursive_covered_chunks: checkpoint.boundary.next_chunk_id,
                ..HistoryRetention::default()
            });
        }
        self.with_engine(retention_info)
    }

    async fn history_latest(&self) -> Result<Vec<u8>, QueryError> {
        if self.light_checkpoint().is_some() {
            return borsh::to_vec(
                &self
                    .light_latest_proof()
                    .map_err(storage_error)?
                    .ok_or(QueryError::HistoryUnavailable)?,
            )
            .map_err(storage_error);
        }
        let proof = self
            .with_engine(neutrino_consensus_engine::Engine::latest_history_proof)
            .map_err(storage_error)?
            .ok_or(QueryError::HistoryUnavailable)?;
        borsh::to_vec(&proof).map_err(storage_error)
    }
    async fn history_request(
        &self,
        start: Hash,
        end: Hash,
    ) -> Result<neutrino_rpc::HistoryJobInfo, QueryError> {
        self.request_history(start, end)
    }
    async fn history_job(&self, id: Hash) -> Result<neutrino_rpc::HistoryJobInfo, QueryError> {
        self.history_job_status(id)
    }
    async fn history_subscribe(
        &self,
        id: Hash,
    ) -> Result<tokio::sync::watch::Receiver<neutrino_rpc::HistoryJobInfo>, QueryError> {
        self.subscribe_history(id)
    }
    async fn history_proof(&self, start: Hash, end: Hash) -> Result<Vec<u8>, QueryError> {
        if self.light_checkpoint().is_some() {
            let proof = self
                .light_latest_proof()
                .map_err(storage_error)?
                .filter(|proof| {
                    proof.statement.start_checkpoint().hash() == start
                        && proof.statement.end_checkpoint().hash() == end
                })
                .ok_or(QueryError::HistoryUnavailable)?;
            return borsh::to_vec(&proof).map_err(storage_error);
        }
        let proof = self
            .with_engine(|engine| read_history_proof(engine, start, end))?
            .ok_or(QueryError::HistoryUnavailable)?;
        borsh::to_vec(&proof).map_err(storage_error)
    }

    fn chain_id(&self) -> ChainId {
        Self::chain_id(self)
    }

    fn runtime_code_hash(&self) -> Option<Hash> {
        self.block_executor_snapshot()
            .map(|_| self.with_engine(|engine| engine.chain_spec().runtime_code_hash))
    }

    fn runtime_available(&self) -> bool {
        self.block_executor_snapshot().is_some()
    }

    fn mempool_len(&self) -> usize {
        Self::mempool_len(self)
    }

    fn peer_count(&self) -> u64 {
        self.sync_status().map_or(0, |status| status.peer_count())
    }

    fn is_syncing(&self) -> bool {
        self.sync_status().is_some_and(|status| status.is_syncing())
    }

    async fn head(&self) -> Result<HeadInfo, QueryError> {
        if let Some(checkpoint) = self.light_checkpoint() {
            let boundary = checkpoint.boundary;
            return Ok(HeadInfo {
                height: boundary.height,
                hash: boundary.block_hash,
                slot: boundary.slot,
                state_root: boundary.state_root,
            });
        }
        self.with_engine(|engine| {
            let hash = engine.head_hash();
            let slot = if hash == engine.chain_spec().genesis_block_hash {
                0
            } else {
                let header = required_header(engine, hash)?;
                if header.height != engine.head_height()
                    || header.state_root != engine.head_state_root()
                {
                    return Err(storage_error(
                        "head metadata does not match the selected header",
                    ));
                }
                header.slot
            };
            Ok(HeadInfo {
                height: engine.head_height(),
                hash,
                slot,
                state_root: engine.head_state_root(),
            })
        })
    }

    async fn finalized(&self) -> Result<FinalizedInfo, QueryError> {
        if let Some(checkpoint) = self.light_checkpoint() {
            let boundary = checkpoint.boundary;
            return Ok(FinalizedInfo {
                chunk_id: boundary.next_chunk_id.checked_sub(1),
                block_hash: boundary.block_hash,
                height: boundary.height,
                state_root: boundary.state_root,
            });
        }
        self.with_engine(finalized_info)
    }

    async fn active_validator_set(&self) -> Vec<Validator> {
        if self.light_checkpoint().is_some() {
            return Vec::new();
        }
        self.with_engine(|engine| engine.active_validator_set().to_vec())
    }

    async fn resolve_block_id(&self, id: &BlockId) -> Result<Option<BlockHash>, QueryError> {
        if let Some(checkpoint) = self.light_checkpoint() {
            let boundary = checkpoint.boundary;
            return Ok(match id {
                BlockId::Latest | BlockId::Finalized => Some(boundary.block_hash),
                BlockId::Hash(hash) if *hash == boundary.block_hash => Some(*hash),
                BlockId::Height(height) if *height == boundary.height => Some(boundary.block_hash),
                _ => None,
            });
        }
        self.with_engine(|engine| resolve_id(engine, id))
    }

    async fn header_by_hash(&self, hash: BlockHash) -> Result<Option<Header>, QueryError> {
        self.with_engine(|engine| checked_header(engine, hash))
    }

    async fn header_by_height(&self, height: Height) -> Result<Option<Header>, QueryError> {
        self.with_engine(|engine| {
            resolve_id(engine, &BlockId::Height(height))?
                .map(|hash| checked_header(engine, hash))
                .transpose()
                .map(Option::flatten)
        })
    }

    async fn block_by_hash(&self, hash: BlockHash) -> Result<Option<Block>, QueryError> {
        self.with_engine(|engine| read_block(engine, hash))
    }

    async fn block_by_height(&self, height: Height) -> Result<Option<Block>, QueryError> {
        self.with_engine(|engine| {
            resolve_id(engine, &BlockId::Height(height))?
                .map(|hash| read_block(engine, hash))
                .transpose()
                .map(Option::flatten)
        })
    }

    async fn storage_at(&self, key: &[u8], at: &BlockId) -> Result<Option<Vec<u8>>, QueryError> {
        Ok(self.rpc_state_snapshot(at).await?.get(key))
    }

    async fn submit_transaction(&self, bytes: Vec<u8>) -> Result<Hash, SubmitError> {
        if self.light_checkpoint().is_some() {
            return Err(SubmitError::Rejected {
                reason: "proof-only node has no transaction execution state".into(),
            });
        }
        Self::submit_transaction(self, bytes).map_err(|error| match error {
            InsertError::Duplicate => SubmitError::Duplicate,
            InsertError::CapacityExceeded => SubmitError::Full,
            InsertError::TooLarge => SubmitError::Rejected {
                reason: "transaction exceeds mempool entry size limit".to_owned(),
            },
            InsertError::RejectedByValidator => SubmitError::Rejected {
                reason: "runtime admission check rejected transaction".to_owned(),
            },
        })
    }

    async fn runtime_call(
        &self,
        method: String,
        args: Vec<u8>,
        at: &BlockId,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        let executor = self
            .block_executor_snapshot()
            .ok_or(RuntimeCallError::RuntimeNotConfigured)?;
        let state = self.rpc_state_snapshot(at).await?;
        let request = neutrino_runtime_abi::QueryRequest { method, args };
        let response = tokio::task::spawn_blocking(move || executor.query(&request, &state))
            .await
            .map_err(|err| RuntimeCallError::Runtime(format!("query join error: {err}")))?
            .map_err(RuntimeCallError::Runtime)?;
        Ok(RuntimeCallResponse {
            code: response.code,
            payload: response.payload,
            gas_used: 0,
        })
    }
}
