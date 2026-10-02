//! Checked, bounded P2P reads from the same materialized chain and state as RPC.

use borsh::BorshSerialize;
use neutrino_consensus_engine::Engine;
use neutrino_network::{
    rpc::{
        self, BlockProofByHashResponse, BlockProofByHeightResponse, BlocksByRangeResponse,
        BlocksByRootResponse, ChunkProofByIdResponse, FinalityCertByChunkResponse,
        RecursiveProofByIndexResponse, StateByRootResponse, Status, WitnessByBlockResponse,
    },
    sync::LocalProgress,
};
use neutrino_primitives::{
    BlockHash, Checkpoint, CheckpointIndex, ChunkId, Height, StateRoot, ZERO_HASH,
};
use neutrino_proof_system::ProofSystem;
use neutrino_rpc::QueryError;
use neutrino_storage::Database;
use neutrino_sync::SyncBackendError;
use std::collections::BTreeMap;

use super::{ChainBackend, rpc_queries};

pub(super) fn storage_error(error: impl core::fmt::Display) -> SyncBackendError {
    SyncBackendError::Storage(error.to_string())
}

pub(super) fn query_error(error: QueryError) -> SyncBackendError {
    match error {
        QueryError::Storage(reason) => SyncBackendError::Storage(reason),
        other => SyncBackendError::NotAvailable(other.to_string()),
    }
}

fn bounded<T: BorshSerialize>(payload: T) -> Result<T, SyncBackendError> {
    let size = borsh::to_vec(&payload).map_err(storage_error)?.len();
    if u64::try_from(size).unwrap_or(u64::MAX) >= rpc::DEFAULT_MAX_RESPONSE_SIZE {
        return Err(SyncBackendError::NotAvailable(
            "response exceeds the wire size limit".to_owned(),
        ));
    }
    Ok(payload)
}

fn missing(what: &str) -> SyncBackendError {
    SyncBackendError::NotAvailable(what.to_owned())
}

fn check_count(count: usize, maximum: u64) -> Result<(), SyncBackendError> {
    if u64::try_from(count).unwrap_or(u64::MAX) > maximum {
        return Err(SyncBackendError::InvalidRequest(
            "request exceeds the item limit".to_owned(),
        ));
    }
    Ok(())
}

// Resolve a whole bounded range under one lock. Archived anchors remain readable
// after a reorg; a current anchor uses the canonical index.
fn branch_hashes<DB: Database>(
    engine: &Engine<DB>,
    anchor: BlockHash,
    start: Height,
    count: u64,
    step: u64,
) -> Result<Vec<(Height, BlockHash)>, SyncBackendError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let genesis = engine.chain_spec().genesis_block_hash;
    let tip_height = if anchor == genesis {
        0
    } else {
        rpc_queries::checked_header(engine, anchor)
            .map_err(query_error)?
            .ok_or_else(|| missing("requested branch anchor is unavailable"))?
            .height
    };
    if count > 0 && (start == 0 || start > tip_height) {
        return Err(missing(
            "requested block height is unavailable on this branch",
        ));
    }
    let mut wanted = BTreeMap::new();
    for offset in 0..count {
        let Some(height) = offset
            .checked_mul(step)
            .and_then(|delta| start.checked_add(delta))
        else {
            break;
        };
        if height > tip_height {
            break;
        }
        wanted.insert(height, ZERO_HASH);
    }
    if anchor == engine.head_hash() {
        for (height, hash) in &mut wanted {
            *hash = engine
                .store()
                .get_header_by_height(*height)
                .map_err(storage_error)?
                .ok_or_else(|| storage_error("canonical header is missing"))?
                .hash();
        }
    } else if let Some((&lowest, _)) = wanted.first_key_value() {
        let mut cursor = anchor;
        for height in (lowest..=tip_height).rev() {
            let header = rpc_queries::checked_header(engine, cursor)
                .map_err(query_error)?
                .ok_or_else(|| storage_error("branch ancestor is missing"))?;
            if header.height != height {
                return Err(storage_error("branch ancestry heights are inconsistent"));
            }
            if let Some(hash) = wanted.get_mut(&height) {
                *hash = cursor;
            }
            cursor = header.parent_hash;
        }
        if lowest == 1 && cursor != genesis {
            return Err(storage_error("branch does not reach genesis"));
        }
    }
    Ok(wanted.into_iter().collect())
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    fn p2p_status_snapshot(engine: &Engine<DB>) -> Result<(Status, Checkpoint), SyncBackendError> {
        let checkpoint_index = engine.latest_checkpoint_index();
        let checkpoint = engine
            .store()
            .get_checkpoint(checkpoint_index)
            .map_err(storage_error)?
            .ok_or_else(|| storage_error("finalized checkpoint is missing"))?;
        if checkpoint.index != checkpoint_index {
            return Err(storage_error("checkpoint pointer is inconsistent"));
        }
        let finalized = rpc_queries::finalized_info(engine).map_err(query_error)?;
        let chunk_hash = match finalized.chunk_id {
            Some(id) => {
                let chunk = engine
                    .store()
                    .get_chunk(id)
                    .map_err(storage_error)?
                    .ok_or_else(|| storage_error("finalized chunk is missing"))?;
                if chunk.end_block_hash != finalized.block_hash
                    || chunk.end_height != finalized.height
                    || chunk.end_state_root != finalized.state_root
                {
                    return Err(storage_error("finalized chunk boundary is inconsistent"));
                }
                chunk.hash()
            }
            None => ZERO_HASH,
        };
        let head_slot = if engine.head_hash() == engine.chain_spec().genesis_block_hash {
            0
        } else {
            rpc_queries::checked_header(engine, engine.head_hash())
                .map_err(query_error)?
                .ok_or_else(|| storage_error("head header is missing"))?
                .slot
        };
        Ok((
            Status {
                chain_id: engine.chain_spec().chain_id,
                chain_spec_hash: engine.chain_spec_hash(),
                finalized_chunk_id: finalized.chunk_id,
                finalized_chunk_hash: chunk_hash,
                finalized_checkpoint_index: checkpoint_index,
                finalized_checkpoint_hash: checkpoint.hash(),
                head_block_hash: engine.head_hash(),
                head_slot,
                head_height: engine.head_height(),
            },
            checkpoint,
        ))
    }

    pub(super) fn p2p_local_status(&self) -> Result<Status, SyncBackendError> {
        self.with_engine(|engine| Self::p2p_status_snapshot(engine).map(|(status, _)| status))
    }

    pub(super) fn p2p_local_progress(&self) -> Result<LocalProgress, SyncBackendError> {
        self.with_engine(|engine| {
            let (status, checkpoint) = Self::p2p_status_snapshot(engine)?;
            Ok(LocalProgress {
                chain_id: status.chain_id,
                chain_spec_hash: status.chain_spec_hash,
                finalized_chunk_id: status.finalized_chunk_id,
                finalized_chunk_hash: status.finalized_chunk_hash,
                finalized_checkpoint_index: status.finalized_checkpoint_index,
                finalized_checkpoint_hash: status.finalized_checkpoint_hash,
                finalized_state_root: checkpoint.end_state_root,
                finalized_block_hash: checkpoint.end_block_hash,
                finalized_height: checkpoint.end_height,
                head_height: status.head_height,
                head_block_hash: status.head_block_hash,
                head_slot: status.head_slot,
                proven_height: Self::contiguous_proven_height(engine)?,
                body_height: Self::contiguous_body_height(engine)?,
            })
        })
    }

    pub(super) fn p2p_blocks_by_range(
        &self,
        start: Height,
        count: u64,
        step: u64,
        anchor: BlockHash,
    ) -> Result<BlocksByRangeResponse, SyncBackendError> {
        if step == 0 {
            return Err(SyncBackendError::InvalidRequest(
                "range step must be nonzero".to_owned(),
            ));
        }
        self.with_engine(|engine| {
            let hashes = branch_hashes(
                engine,
                anchor,
                start,
                count.min(rpc::MAX_BLOCKS_PER_RESPONSE),
                step,
            )?;
            let blocks = hashes
                .into_iter()
                .map(|(_, hash)| {
                    rpc_queries::read_block(engine, hash)
                        .map_err(query_error)?
                        .ok_or_else(|| storage_error("branch header is missing"))
                })
                .collect::<Result<_, _>>()?;
            bounded(BlocksByRangeResponse { blocks })
        })
    }

    pub(super) fn p2p_blocks_by_root(
        &self,
        roots: &[BlockHash],
    ) -> Result<BlocksByRootResponse, SyncBackendError> {
        check_count(roots.len(), rpc::MAX_BLOCKS_PER_RESPONSE)?;
        self.with_engine(|engine| {
            let blocks = roots
                .iter()
                .map(|hash| {
                    rpc_queries::read_block(engine, *hash)
                        .map_err(query_error)?
                        .ok_or_else(|| missing("requested block is unavailable"))
                })
                .collect::<Result<_, _>>()?;
            bounded(BlocksByRootResponse { blocks })
        })
    }

    pub(super) fn p2p_state_nodes(
        &self,
        root: StateRoot,
        paths: &[Vec<u8>],
    ) -> Result<StateByRootResponse, SyncBackendError> {
        check_count(paths.len(), rpc::MAX_STATE_PATHS_PER_REQUEST)?;
        if paths.iter().any(|path| !path.is_empty()) {
            return Err(SyncBackendError::InvalidRequest(
                "only a bounded full-root state snapshot is supported".to_owned(),
            ));
        }
        self.with_engine(|engine| {
            let data = rpc_queries::read_state_data(engine, root).map_err(query_error)?;
            bounded(StateByRootResponse {
                nodes: data.nodes.into_values().collect(),
                values: data.values.into_values().collect(),
            })
        })
    }

    pub(super) fn p2p_block_proofs_by_hash(
        &self,
        roots: &[BlockHash],
    ) -> Result<BlockProofByHashResponse, SyncBackendError> {
        check_count(roots.len(), rpc::MAX_BLOCK_PROOFS_PER_RESPONSE)?;
        self.with_engine(|engine| {
            let proofs = roots
                .iter()
                .map(|hash| {
                    let proof = engine
                        .store()
                        .get_block_proof(hash)
                        .map_err(storage_error)?
                        .ok_or_else(|| missing("block proof is unavailable"))?;
                    if proof.block_hash != *hash {
                        return Err(storage_error("block proof hash is inconsistent"));
                    }
                    Ok(proof)
                })
                .collect::<Result<_, _>>()?;
            bounded(BlockProofByHashResponse { proofs })
        })
    }

    pub(super) fn p2p_block_proofs_by_height(
        &self,
        start: Height,
        count: u64,
        anchor: BlockHash,
    ) -> Result<BlockProofByHeightResponse, SyncBackendError> {
        self.with_engine(|engine| {
            let hashes = branch_hashes(
                engine,
                anchor,
                start,
                count.min(rpc::MAX_BLOCK_PROOFS_PER_RESPONSE),
                1,
            )?;
            let mut proofs = Vec::new();
            for (height, hash) in hashes {
                let Some(proof) = engine
                    .store()
                    .get_block_proof(&hash)
                    .map_err(storage_error)?
                else {
                    if proofs.is_empty() {
                        return Err(missing("block proof is unavailable"));
                    }
                    break;
                };
                if proof.height != height || proof.block_hash != hash {
                    return Err(storage_error("branch block proof is inconsistent"));
                }
                proofs.push(proof);
            }
            bounded(BlockProofByHeightResponse { proofs })
        })
    }

    pub(super) fn p2p_chunk_proofs_by_id(
        &self,
        ids: &[ChunkId],
    ) -> Result<ChunkProofByIdResponse, SyncBackendError> {
        check_count(ids.len(), rpc::MAX_CHUNK_PROOFS_PER_RESPONSE)?;
        self.with_engine(|engine| {
            let proofs = ids
                .iter()
                .map(|id| {
                    let proof = engine
                        .store()
                        .get_chunk_proof(*id)
                        .map_err(storage_error)?
                        .ok_or_else(|| missing("chunk proof is unavailable"))?;
                    let chunk = engine
                        .store()
                        .get_chunk(*id)
                        .map_err(storage_error)?
                        .ok_or_else(|| storage_error("chunk proof has no stored chunk"))?;
                    if proof.chunk_id != *id
                        || proof.public_inputs.chunk_id != *id
                        || proof.chunk_hash != chunk.hash()
                        || proof.finality_cert.chunk_id != *id
                        || proof.finality_cert.chunk_hash != proof.chunk_hash
                    {
                        return Err(storage_error("chunk proof envelope is inconsistent"));
                    }
                    Ok(proof)
                })
                .collect::<Result<_, _>>()?;
            bounded(ChunkProofByIdResponse { proofs })
        })
    }

    pub(super) fn p2p_recursive_proofs_by_index(
        &self,
        start: CheckpointIndex,
        count: u64,
    ) -> Result<RecursiveProofByIndexResponse, SyncBackendError> {
        self.with_engine(|engine| {
            let mut items = Vec::new();
            for offset in 0..count.min(rpc::MAX_RECURSIVE_PROOFS_PER_RESPONSE) {
                let Some(index) = start.checked_add(offset) else {
                    break;
                };
                let checkpoint = engine
                    .store()
                    .get_checkpoint(index)
                    .map_err(storage_error)?
                    .ok_or_else(|| missing("checkpoint is unavailable"))?;
                let proof = engine
                    .store()
                    .get_recursive_proof(index)
                    .map_err(storage_error)?
                    .ok_or_else(|| missing("recursive proof is unavailable"))?;
                if checkpoint.index != index
                    || proof.checkpoint_index != index
                    || proof.public_inputs != checkpoint
                    || proof.checkpoint_hash != checkpoint.hash()
                {
                    return Err(storage_error(
                        "recursive checkpoint envelope is inconsistent",
                    ));
                }
                items.push((checkpoint, proof));
            }
            bounded(RecursiveProofByIndexResponse { items })
        })
    }

    pub(super) fn p2p_finality_certs_by_chunk(
        &self,
        ids: &[ChunkId],
    ) -> Result<FinalityCertByChunkResponse, SyncBackendError> {
        check_count(ids.len(), rpc::MAX_FINALITY_CERTS_PER_RESPONSE)?;
        self.with_engine(|engine| {
            let certs = ids
                .iter()
                .map(|id| {
                    let cert = engine
                        .store()
                        .get_finality_cert(*id)
                        .map_err(storage_error)?
                        .ok_or_else(|| missing("finality certificate is unavailable"))?;
                    let chunk = engine
                        .store()
                        .get_chunk(*id)
                        .map_err(storage_error)?
                        .ok_or_else(|| storage_error("certificate has no stored chunk"))?;
                    if cert.chunk_id != *id || cert.chunk_hash != chunk.hash() {
                        return Err(storage_error(
                            "finality certificate envelope is inconsistent",
                        ));
                    }
                    Ok(cert)
                })
                .collect::<Result<_, _>>()?;
            bounded(FinalityCertByChunkResponse { certs })
        })
    }

    pub(super) fn p2p_witnesses_by_block(
        &self,
        hashes: &[BlockHash],
    ) -> Result<WitnessByBlockResponse, SyncBackendError> {
        check_count(hashes.len(), rpc::MAX_WITNESSES_PER_RESPONSE)?;
        self.with_engine(|engine| {
            let witnesses = hashes
                .iter()
                .map(|hash| {
                    engine
                        .store()
                        .get_witness(hash)
                        .map_err(storage_error)?
                        .ok_or_else(|| missing("block witness is unavailable"))
                })
                .collect::<Result<_, _>>()?;
            bounded(WitnessByBlockResponse { witnesses })
        })
    }
}
