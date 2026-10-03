//! Checked, bounded P2P reads from the same materialized chain and state as RPC.

use borsh::BorshSerialize;
use neutrino_consensus_engine::Engine;
use neutrino_consensus_types::history_proof::{Checkpoint, ConsensusBoundary};
use neutrino_network::{
    rpc::{
        self, BlockProofByHashResponse, BlockProofByHeightResponse, BlocksByRangeResponse,
        BlocksByRootResponse, ChunkProofByIdResponse, FinalityCertByChunkResponse,
        HistoryProofByRangeResponse, StateByRootResponse, Status, WitnessByBlockResponse,
    },
    sync::LocalProgress,
};
use neutrino_primitives::{BlockHash, ChunkId, Hash, Height, StateRoot, ZERO_HASH};
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
        QueryError::Pruned {
            retained_from_chunk,
            retained_from_height,
        } => SyncBackendError::Pruned {
            retained_from_chunk,
            retained_from_height,
        },
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
    if count > 0 {
        rpc_queries::ensure_payload_height(engine, start).map_err(query_error)?;
    }
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
    pub(super) fn p2p_local_metadata(&self) -> rpc::Metadata {
        if self.light_checkpoint().is_some() {
            return rpc::Metadata {
                role_flags: rpc::role_flags::LIGHT_CLIENT,
                ..rpc::Metadata::default()
            };
        }
        self.with_engine(|engine| {
            let retention = rpc_queries::retention_info(engine)?;
            Ok::<_, QueryError>(rpc::Metadata {
                seq_number: retention.retained_from_chunk.unwrap_or(0),
                vote_subnet_bits: 0,
                role_flags: rpc::role_flags::FULL_NODE
                    | if retention.archive {
                        rpc::role_flags::ARCHIVE
                    } else {
                        0
                    },
                retained_from_chunk: retention.retained_from_chunk,
                retained_from_height: retention.retained_from_height,
            })
        })
        .unwrap_or_default()
    }

    fn ensure_retained_chunk(engine: &Engine<DB>, id: ChunkId) -> Result<(), SyncBackendError> {
        let retention = engine.retention_info().map_err(storage_error)?;
        if id < retention.pruned_before_chunk {
            return Err(SyncBackendError::Pruned {
                retained_from_chunk: retention.pruned_before_chunk,
                retained_from_height: retention.first_retained_height,
            });
        }
        Ok(())
    }

    fn p2p_status_snapshot(
        engine: &Engine<DB>,
    ) -> Result<(Status, ConsensusBoundary), SyncBackendError> {
        let covered = engine.recursive_covered_chunks();
        let boundary = engine.canonical_boundary(covered).map_err(storage_error)?;
        let checkpoint_hash = engine
            .store()
            .history_domain()
            .map_err(storage_error)?
            .map_or(ZERO_HASH, |domain| Checkpoint { domain, boundary }.hash());
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
                recursive_covered_chunks: covered,
                checkpoint_hash,
                head_block_hash: engine.head_hash(),
                head_slot,
                head_height: engine.head_height(),
            },
            boundary,
        ))
    }

    pub(super) fn p2p_local_status(&self) -> Result<Status, SyncBackendError> {
        if let Some(checkpoint) = self.light_checkpoint() {
            return Ok(Status {
                chain_id: checkpoint.domain.chain.chain_id,
                chain_spec_hash: checkpoint.domain.chain.chain_spec_hash,
                finalized_chunk_id: None,
                finalized_chunk_hash: ZERO_HASH,
                recursive_covered_chunks: checkpoint.boundary.next_chunk_id,
                checkpoint_hash: checkpoint.hash(),
                head_block_hash: checkpoint.boundary.block_hash,
                head_slot: checkpoint.boundary.slot,
                head_height: checkpoint.boundary.height,
            });
        }
        self.with_engine(|engine| Self::p2p_status_snapshot(engine).map(|(status, _)| status))
    }

    pub(super) fn p2p_local_progress(&self) -> Result<LocalProgress, SyncBackendError> {
        if let Some(checkpoint) = self.light_checkpoint() {
            let boundary = checkpoint.boundary;
            return Ok(LocalProgress {
                chain_id: checkpoint.domain.chain.chain_id,
                chain_spec_hash: checkpoint.domain.chain.chain_spec_hash,
                finalized_chunk_id: None,
                finalized_chunk_hash: ZERO_HASH,
                recursive_covered_chunks: boundary.next_chunk_id,
                checkpoint_hash: checkpoint.hash(),
                finalized_state_root: boundary.state_root,
                finalized_block_hash: boundary.block_hash,
                finalized_height: boundary.height,
                head_height: boundary.height,
                head_block_hash: boundary.block_hash,
                head_slot: boundary.slot,
                proven_height: 0,
                body_height: 0,
            });
        }
        self.with_engine(|engine| {
            let (status, checkpoint) = Self::p2p_status_snapshot(engine)?;
            Ok(LocalProgress {
                chain_id: status.chain_id,
                chain_spec_hash: status.chain_spec_hash,
                finalized_chunk_id: status.finalized_chunk_id,
                finalized_chunk_hash: status.finalized_chunk_hash,
                recursive_covered_chunks: status.recursive_covered_chunks,
                checkpoint_hash: status.checkpoint_hash,
                finalized_state_root: checkpoint.state_root,
                finalized_block_hash: checkpoint.block_hash,
                finalized_height: checkpoint.height,
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
        items: &[neutrino_consensus_types::bootstrap::StateItem],
    ) -> Result<StateByRootResponse, SyncBackendError> {
        use neutrino_consensus_types::bootstrap::{
            MAX_STATE_FRAGMENT_BYTES, MAX_STATE_ITEMS, StateEntries, StateEntry, StateItemKind,
        };
        use neutrino_storage::Column;
        use neutrino_trie::{Hasher, Node, Poseidon2Hasher};
        check_count(
            items.len(),
            u64::try_from(MAX_STATE_ITEMS).expect("bounded item count"),
        )?;
        self.with_engine_mut(|engine| {
            // The retained root must exist and authenticate its own node. Object
            // reachability is established by the receiver while following child
            // hashes; serving each fragment does not traverse the complete tree.
            if root != ZERO_HASH {
                let bytes = engine
                    .store()
                    .db()
                    .get(Column::TrieNodes, &root)
                    .map_err(storage_error)?
                    .ok_or_else(|| missing("requested state root is unavailable"))?;
                if Poseidon2Hasher::hash_node(&bytes) != root {
                    return Err(storage_error("persisted state root content hash mismatch"));
                }
                Node::decode(&bytes).map_err(storage_error)?;
            }
            let entries = items
                .iter()
                .map(|item| {
                    let column = match item.kind {
                        StateItemKind::Node => Column::TrieNodes,
                        StateItemKind::Value => Column::StateValues,
                    };
                    let bytes = engine
                        .store()
                        .db()
                        .get(column, &item.hash)
                        .map_err(storage_error)?
                        .ok_or_else(|| missing("state object unavailable"))?;
                    let hash = match item.kind {
                        StateItemKind::Node => Poseidon2Hasher::hash_node(&bytes),
                        StateItemKind::Value => Poseidon2Hasher::hash_value(&bytes),
                    };
                    if hash != item.hash {
                        return Err(storage_error("persisted state content hash mismatch"));
                    }
                    let offset = usize::try_from(item.offset).map_err(storage_error)?;
                    if offset > bytes.len() || (offset == bytes.len() && offset != 0) {
                        return Err(SyncBackendError::InvalidRequest(
                            "state offset exceeds object".into(),
                        ));
                    }
                    let end = offset
                        .saturating_add(MAX_STATE_FRAGMENT_BYTES)
                        .min(bytes.len());
                    Ok(StateEntry {
                        item: *item,
                        total_len: u64::try_from(bytes.len()).map_err(storage_error)?,
                        bytes: neutrino_primitives::BoundedBytes::new(bytes[offset..end].to_vec())
                            .map_err(storage_error)?,
                    })
                })
                .collect::<Result<Vec<_>, SyncBackendError>>()?;
            let response = bounded(StateByRootResponse {
                entries: StateEntries::new(entries).map_err(storage_error)?,
            })?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(storage_error)?
                .as_secs();
            engine
                .store_mut()
                .refresh_state_snapshot(root, now)
                .map_err(|error| SyncBackendError::NotAvailable(error.to_string()))?;
            Ok(response)
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
                    if let Some(header) =
                        rpc_queries::checked_header(engine, *hash).map_err(query_error)?
                    {
                        rpc_queries::ensure_payload_height(engine, header.height)
                            .map_err(query_error)?;
                    }
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
                    Self::ensure_retained_chunk(engine, *id)?;
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

    pub(super) fn p2p_history_proof_by_range(
        &self,
        start: Hash,
        end: Hash,
    ) -> Result<HistoryProofByRangeResponse, SyncBackendError> {
        if self.light_checkpoint().is_some() {
            let proof = self
                .light_latest_proof()
                .map_err(storage_error)?
                .filter(|proof| {
                    proof.statement.start_checkpoint().hash() == start
                        && proof.statement.end_checkpoint().hash() == end
                })
                .ok_or_else(|| {
                    SyncBackendError::NotAvailable("history range not retained".into())
                })?;
            return Ok(HistoryProofByRangeResponse {
                proof,
                bootstrap: None,
            });
        }
        let proof = self
            .with_engine(|engine| rpc_queries::read_history_proof(engine, start, end))
            .map_err(query_error)?;
        if let Some(proof) = proof {
            return bounded(HistoryProofByRangeResponse {
                proof,
                bootstrap: None,
            });
        }
        self.request_history(start, end).map_err(query_error)?;
        Err(missing(
            "history range is queued; await its completion announcement",
        ))
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
                    Self::ensure_retained_chunk(engine, *id)?;
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
                    if let Some(header) =
                        rpc_queries::checked_header(engine, *hash).map_err(query_error)?
                    {
                        rpc_queries::ensure_payload_height(engine, header.height)
                            .map_err(query_error)?;
                    }
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
