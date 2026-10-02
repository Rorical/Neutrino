//! RPC views are selected by block hash and read from its committed state root.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use neutrino_consensus_engine::Engine;
use neutrino_consensus_types::{Block, Header};
use neutrino_mempool::InsertError;
use neutrino_primitives::{BlockHash, ChainId, Hash, Height, Validator, ZERO_HASH};
use neutrino_proof_system::ProofSystem;
use neutrino_rpc::{
    BlockId, FinalizedInfo, HeadInfo, QueryError, RpcBackend, RuntimeCallError,
    RuntimeCallResponse, SubmitError,
};
use neutrino_storage::{Column, Database};
use neutrino_trie::{Hasher, Node, Poseidon2Hasher, Trie};

use super::ChainBackend;

fn storage_error(error: impl core::fmt::Display) -> QueryError {
    QueryError::Storage(error.to_string())
}

fn checked_header<DB: Database>(
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

fn finalized_info<DB: Database>(engine: &Engine<DB>) -> Result<FinalizedInfo, QueryError>
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
            // The store's height index records the most recently imported fork.
            // RPC heights follow the selected, materialized head's ancestry.
            let mut hash = engine.head_hash();
            let mut expected_height = engine.head_height();
            while expected_height > 0 {
                let header = required_header(engine, hash)?;
                if header.height != expected_height {
                    return Err(storage_error("selected chain heights are not contiguous"));
                }
                if expected_height == *height {
                    return Ok(Some(hash));
                }
                hash = header.parent_hash;
                expected_height -= 1;
            }
            if hash != engine.chain_spec().genesis_block_hash {
                return Err(storage_error(
                    "selected chain does not reach trusted genesis",
                ));
            }
            Ok(Some(hash))
        }
    }
}

fn read_block<DB: Database>(
    engine: &Engine<DB>,
    hash: BlockHash,
) -> Result<Option<Block>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let Some(header) = checked_header(engine, hash)? else {
        return Ok(None);
    };
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
    let root = if hash == engine.chain_spec().genesis_block_hash {
        engine.chain_spec().genesis_state_root
    } else {
        required_header(engine, hash)?.state_root
    };
    let db = engine.store().db();
    let mut pending = vec![root];
    let mut nodes = BTreeMap::new();
    let mut values = BTreeMap::new();
    // Only the selected root's reachable nodes are loaded. Validate the complete
    // closure before Trie::get or a runtime can mistake missing data for absence.
    while let Some(hash) = pending.pop() {
        if hash == ZERO_HASH || nodes.contains_key(&hash) {
            continue;
        }
        let bytes = db
            .get(Column::TrieNodes, &hash)
            .map_err(storage_error)?
            .ok_or(QueryError::StateUnavailable)?;
        if Poseidon2Hasher::hash_node(&bytes) != hash {
            return Err(storage_error("trie node does not match its content hash"));
        }
        match Node::decode(&bytes).map_err(storage_error)? {
            Node::Leaf { value_hash, .. } => {
                if let std::collections::btree_map::Entry::Vacant(entry) = values.entry(value_hash)
                {
                    let value = db
                        .get(Column::StateValues, &value_hash)
                        .map_err(storage_error)?
                        .ok_or(QueryError::StateUnavailable)?;
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
    Ok(Trie::from_persisted(root, nodes, values))
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    async fn rpc_state_snapshot(&self, at: &BlockId) -> Result<Trie, QueryError> {
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

    async fn head(&self) -> Result<HeadInfo, QueryError> {
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
        self.with_engine(finalized_info)
    }

    async fn active_validator_set(&self) -> Vec<Validator> {
        self.with_engine(|engine| engine.active_validator_set().to_vec())
    }

    async fn resolve_block_id(&self, id: &BlockId) -> Result<Option<BlockHash>, QueryError> {
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
