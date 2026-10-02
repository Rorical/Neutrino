//! Complete consensus chunk preparation and atomic, proof-gated finalization.

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::{AggregatedVote, ChunkProof, FinalityCert};
use neutrino_primitives::{ChunkId, Hash};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_prover_chunk::{
    body::ConsensusBody,
    consensus::{
        ConsensusStatement, ConsensusWitness, as_chunk, validate_candidate, validate_consensus,
    },
    execution::{ExecutionContext, ProvenBlock, commitment},
    history::{HistoricalChunk, HistoryWitness},
};
use neutrino_runtime_abi::{StateWitness, TrieNodeBytes, TrieValueBytes};
use neutrino_storage::Database;
use neutrino_trie::Trie;

use crate::{BlockState, Engine, FinalizeError, FinalizeOutcome, ProposerKey};

/// Durable context for the next chunk; committed atomically with finalization.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusState {
    /// Last verified complete statement.
    pub statement: ConsensusStatement,
    /// Openings of the statement's outgoing historical/replay commitments.
    pub history: HistoryWitness,
}

/// Immutable snapshot carried outside the engine lock for expensive proving.
pub struct PreparedConsensusChunk<P: ProofSystem> {
    /// Fully bound candidate, with certificate filled before proving.
    pub witness: ConsensusWitness,
    /// Inner proofs in exact canonical height order.
    pub proofs: Vec<P::BlockProof>,
}

impl<DB: Database> Engine<DB> {
    /// Pin both accepted programs from the configured proof backend. These are
    /// process configuration, never chosen by a peer or evidence reporter.
    pub const fn set_evidence_programs(&mut self, block: [u32; 8], evidence: [u32; 8]) {
        self.evidence_programs = Some((block, evidence));
    }

    /// Build the trusted incoming anchor for ordinary or replay execution.
    pub fn evidence_anchor(
        &self,
        height: u64,
    ) -> Result<neutrino_consensus_types::evidence::EvidenceAnchor, alloc::string::String> {
        let Some((block_guest_vk_digest, evidence_guest_vk_digest)) = self.evidence_programs else {
            return Ok(neutrino_consensus_types::evidence::EvidenceAnchor::default());
        };
        let spec = self.chain_spec();
        let chunk_id = height
            .checked_sub(1)
            .and_then(|h| h.checked_div(spec.consensus.chunk_size))
            .ok_or_else(|| alloc::string::String::from("invalid evidence anchor height"))?;
        let history = if chunk_id == 0 {
            Vec::new()
        } else {
            let state = self
                .store()
                .get_consensus_state()
                .map_err(|_| alloc::string::String::from("history read failed"))?
                .ok_or_else(|| alloc::string::String::from("missing finalized history"))?;
            state
                .history
                .chunks
                .get(
                    ..usize::try_from(chunk_id)
                        .map_err(|_| alloc::string::String::from("history length"))?,
                )
                .ok_or_else(|| alloc::string::String::from("unfinalized evidence anchor"))?
                .to_vec()
        };
        Ok(neutrino_consensus_types::evidence::EvidenceAnchor {
            chain_spec_hash: spec.hash(),
            chunk_id,
            history_root: neutrino_prover_chunk::history::history_commitment(&history),
            block_guest_vk_digest,
            evidence_guest_vk_digest,
            policy: spec.runtime,
        })
    }

    /// Snapshot a self-contained offence for proving outside the engine lock.
    pub fn evidence_witness(
        &self,
        evidence: &neutrino_consensus_types::SlashingEvidence,
    ) -> Result<neutrino_prover_chunk::evidence::EvidenceWitness, FinalizeError<DB::Error>> {
        let (block_guest_vk_digest, _) = self.evidence_programs.ok_or(ProofError::Unsupported)?;
        let id = neutrino_prover_chunk::history::evidence_chunk_id(self.chain_spec(), evidence)
            .map_err(|_| ProofError::InvalidWitness)?;
        let state = self
            .store()
            .get_consensus_state()?
            .ok_or(ProofError::InvalidWitness)?;
        let source = state
            .history
            .record(id)
            .map_err(|_| ProofError::InvalidWitness)?
            .clone();
        Ok(neutrino_prover_chunk::evidence::EvidenceWitness {
            chain_spec: self.chain_spec().clone(),
            source,
            claim: neutrino_prover_chunk::evidence::EvidenceClaim::Slash(evidence.clone()),
            block_guest_vk_digest,
        })
    }

    /// Rebind a reusable receipt to the current canonical historical root.
    pub fn evidence_submission(
        &self,
        statement: neutrino_consensus_types::evidence::EvidenceStatement,
    ) -> Result<neutrino_consensus_types::evidence::EvidenceSubmission, FinalizeError<DB::Error>>
    {
        let state = self
            .store()
            .get_consensus_state()?
            .ok_or(ProofError::InvalidWitness)?;
        let leaves = state
            .history
            .chunks
            .iter()
            .map(|r| commitment(&r.evidence_context()))
            .collect::<Vec<_>>();
        let index =
            usize::try_from(statement.context.chunk_id).map_err(|_| ProofError::InvalidWitness)?;
        if leaves.get(index) != Some(&commitment(&statement.context)) {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let history = neutrino_consensus_types::evidence::HistoryOpening::build(&leaves, index)
            .ok_or(ProofError::InvalidWitness)?;
        Ok(neutrino_consensus_types::evidence::EvidenceSubmission { statement, history })
    }

    /// Bind a candidate to its finalized boundary and complete parent ancestry.
    /// The runtime authenticates receipts and protects replay in the branch state.
    pub fn authorize_consensus_body(
        &self,
        height: u64,
        parent_hash: Hash,
        body: &neutrino_consensus_types::Body,
        gas_limit: u64,
        block_key: &[u32; 8],
    ) -> Result<(), FinalizeError<DB::Error>> {
        let chunk_id = height
            .checked_sub(1)
            .and_then(|h| h.checked_div(self.chain_spec().consensus.chunk_size))
            .ok_or(ProofError::InvalidWitness)?;
        let (context, _, _) = self.consensus_boundary(chunk_id)?;
        let boundary_height = chunk_id
            .checked_mul(self.chain_spec().consensus.chunk_size)
            .ok_or(ProofError::InvalidWitness)?;
        let mut ancestor = parent_hash;
        for expected_height in (boundary_height + 1..height).rev() {
            let header = self
                .store()
                .get_header(&ancestor)?
                .ok_or(ProofError::InvalidWitness)?;
            if header.height != expected_height
                || header.hash() != ancestor
                || self.store().get_body(&ancestor)?.is_none()
            {
                return Err(ProofError::InvalidWitness.into());
            }
            ancestor = header.parent_hash;
        }
        if ancestor != context.parent_block_hash
            || self
                .evidence_programs
                .is_some_and(|(key, _)| &key != block_key)
        {
            return Err(ProofError::InvalidWitness.into());
        }
        let anchor = self
            .evidence_anchor(height)
            .map_err(|_| ProofError::InvalidWitness)?;
        let input = neutrino_default_runtime_core::StfInput {
            evidence_anchor: anchor,
            chain_id: self.chain_spec().chain_id,
            block_height: height,
            block_gas_limit: gas_limit,
            gas_price: self.chain_spec().runtime.gas_price,
            proposer_address: [0; 32],
            transactions: body
                .transactions
                .iter()
                .map(|raw| borsh::from_slice(raw))
                .collect::<Result<Vec<_>, _>>()?,
        };
        std::panic::catch_unwind(|| {
            let _checked = neutrino_default_runtime_core::accountability::validate_input(&input);
        })
        .map_err(|_| ProofError::InvalidWitness)?;
        let mut attachments = body.evidence_proofs.iter();
        for transaction in &input.transactions {
            if let neutrino_default_runtime_core::Transaction::SubmitEvidence(submission) =
                transaction
            {
                let attachment = attachments.next().ok_or(ProofError::InvalidWitness)?;
                if !attachment.binds(&submission.statement, &anchor.evidence_guest_vk_digest) {
                    return Err(ProofError::InvalidWitness.into());
                }
            }
        }
        if attachments.next().is_some() {
            return Err(ProofError::InvalidWitness.into());
        }
        Ok(())
    }

    /// Validate a raw report against historical membership before pooling it.
    /// Only a separately verified EvidenceProof can authorize runtime deductions.
    pub fn verify_historical_slashing_evidence(
        &self,
        evidence: &neutrino_consensus_types::SlashingEvidence,
        key: &[u32; 8],
    ) -> Result<(), FinalizeError<DB::Error>> {
        let next = self
            .latest_finalized_chunk_id()
            .map_or(Some(0), |id| id.checked_add(1))
            .ok_or(ProofError::InvalidWitness)?;
        let (_, _, history) = self.consensus_boundary(next)?;
        let (_, id) = neutrino_prover_chunk::history::authorize_evidence(
            self.chain_spec(),
            &history,
            evidence,
            key,
        )
        .map_err(|_| ProofError::InvalidWitness)?;
        if history.penalties.binary_search(&id).is_ok() {
            return Err(ProofError::InvalidWitness.into());
        }
        Ok(())
    }

    /// Load the trusted incoming consensus boundary; no peer input selects it.
    pub fn consensus_boundary(
        &self,
        chunk_id: ChunkId,
    ) -> Result<(ExecutionContext, Hash, HistoryWitness), FinalizeError<DB::Error>> {
        self.validate_chunk_id_sequence(chunk_id)?;
        let spec = self.chain_spec();
        if chunk_id == 0 {
            return Ok((
                ExecutionContext {
                    chain_id: spec.chain_id,
                    chain_spec_hash: spec.hash(),
                    chunk_id,
                    chunk_size: spec.consensus.chunk_size,
                    parent_block_hash: spec.genesis_block_hash,
                    pre_state_root: spec.genesis_state_root,
                    parent_slot: 0,
                    vm_code_hash: spec.runtime_code_hash,
                    gas_price: spec.runtime.gas_price,
                    active_validators: spec.initial_validators.clone(),
                    history_root: neutrino_prover_chunk::history::history_commitment(&[]),
                    penalty_root: commitment(&Vec::<Hash>::new()),
                },
                spec.genesis_seed,
                HistoryWitness::default(),
            ));
        }
        let previous = self
            .store()
            .get_consensus_state()?
            .ok_or(ProofError::InvalidWitness)?;
        if previous.statement.next_context.chunk_id != chunk_id {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok((
            previous.statement.next_context,
            previous.statement.next_seed,
            previous.history,
        ))
    }

    /// Assemble the complete witness from canonical blocks and the exact
    /// chunk-end trie root, even when the live runtime has advanced further.
    pub fn prepare_consensus_chunk<P: ProofSystem>(
        &self,
        chunk_id: ChunkId,
        proof_system: &P,
    ) -> Result<PreparedConsensusChunk<P>, FinalizeError<DB::Error>> {
        let end = chunk_id
            .checked_add(1)
            .and_then(|id| id.checked_mul(self.chain_spec().consensus.chunk_size))
            .ok_or(FinalizeError::HeightRangeOverflow)?;
        let end_hash = self
            .store()
            .get_block_hash_by_height(end)?
            .ok_or(FinalizeError::MissingBlock { height: end })?;
        self.prepare_consensus_chunk_on_branch(chunk_id, end_hash, proof_system)
    }

    pub(crate) fn prepare_consensus_chunk_on_branch<P: ProofSystem>(
        &self,
        chunk_id: ChunkId,
        end_hash: Hash,
        proof_system: &P,
    ) -> Result<PreparedConsensusChunk<P>, FinalizeError<DB::Error>> {
        let key = proof_system
            .consensus_block_key()
            .ok_or(ProofError::Unsupported)?;
        let (context, seed, history) = self.consensus_boundary(chunk_id)?;
        let start = chunk_id
            .checked_mul(context.chunk_size)
            .and_then(|height| height.checked_add(1))
            .ok_or(FinalizeError::HeightRangeOverflow)?;
        let end = start
            .checked_add(
                context
                    .chunk_size
                    .checked_sub(1)
                    .ok_or(FinalizeError::HeightRangeOverflow)?,
            )
            .ok_or(FinalizeError::HeightRangeOverflow)?;
        let mut blocks = Vec::new();
        let mut bodies = Vec::new();
        let mut proofs = Vec::new();
        let mut headers = Vec::new();
        let mut cursor = end_hash;
        for height in (start..=end).rev() {
            let header = self
                .store()
                .get_header(&cursor)?
                .ok_or(FinalizeError::MissingBlock { height })?;
            if header.height != height || header.hash() != cursor {
                return Err(ProofError::PublicInputMismatch.into());
            }
            cursor = header.parent_hash;
            headers.push(header);
        }
        headers.reverse();
        for header in headers {
            let height = header.height;
            let hash = header.hash();
            let state = self
                .store()
                .get_block_state(&hash)?
                .unwrap_or(BlockState::BlockProduced);
            if !matches!(state, BlockState::Proven) {
                return Err(FinalizeError::BlockNotProven { hash, state });
            }
            let wire = self
                .store()
                .get_block_proof(&hash)?
                .ok_or(FinalizeError::MissingBlockProof { hash })?;
            if wire.height != height || wire.block_hash != hash {
                return Err(ProofError::PublicInputMismatch.into());
            }
            let proof = borsh::from_slice(&wire.proof_bytes)?;
            proof_system.verify_block(&proof, &wire.public_inputs)?;
            let output = proof_system.block_statement(&proof)?;
            let body = self
                .store()
                .get_body(&hash)?
                .ok_or(ProofError::InvalidWitness)?;
            blocks.push(ProvenBlock {
                header,
                public_inputs: wire.public_inputs,
                output,
            });
            bodies.push(ConsensusBody::from_body(&body).map_err(|_| ProofError::InvalidWitness)?);
            proofs.push(proof);
        }
        let post_root = blocks
            .last()
            .ok_or(ProofError::InvalidWitness)?
            .header
            .state_root;
        let post_state = self.consensus_rotation_witness(post_root, &context.active_validators)?;
        let aggregate = AggregatedVote {
            aggregation_bits: neutrino_primitives::BitVec::default(),
            signature: [0; 96],
        };
        let witness = ConsensusWitness {
            evidence_guest_vk_digest: proof_system.evidence_key().ok_or(ProofError::Unsupported)?,
            chain_spec: self.chain_spec().clone(),
            context,
            seed,
            blocks,
            bodies,
            post_state,
            history,
            finality_cert: FinalityCert {
                attestations: Vec::new(),
                chunk_id,
                round: 0,
                chunk_hash: [0; 32],
                prevote: aggregate.clone(),
                precommit: aggregate,
                active_validator_set_root: [0; 32],
            },
            block_guest_vk_digest: key,
        };
        validate_candidate(&witness).map_err(|_| ProofError::InvalidWitness)?;
        Ok(PreparedConsensusChunk { witness, proofs })
    }

    fn consensus_rotation_witness(
        &self,
        root: Hash,
        validators: &[neutrino_primitives::Validator],
    ) -> Result<StateWitness, FinalizeError<DB::Error>> {
        let trie: Trie = Trie::from_persisted(
            root,
            self.store().iter_trie_nodes()?,
            self.store().iter_state_values()?,
        );
        let keys = neutrino_prover_chunk::rotation::witness_keys(validators);
        let mut nodes = BTreeMap::new();
        let mut values = BTreeMap::new();
        for key in &keys {
            trie.collect_path_nodes(key, &mut nodes, &mut values);
        }
        Ok(StateWitness {
            pre_state_root: root,
            nodes: nodes
                .into_iter()
                .map(|(hash, bytes)| TrieNodeBytes { hash, bytes })
                .collect(),
            values: values
                .into_iter()
                .map(|(hash, bytes)| TrieValueBytes { hash, bytes })
                .collect(),
            witnessed_keys: keys,
        })
    }

    /// Obtain the finality certificate before asking a prover to attest to it.
    /// A failed proof attempt leaves the BFT session available for retry.
    pub fn certify_consensus_chunk<P: ProofSystem>(
        &self,
        prepared: &mut PreparedConsensusChunk<P>,
        voter: &ProposerKey,
    ) -> Result<(), FinalizeError<DB::Error>> {
        let candidate =
            validate_candidate(&prepared.witness).map_err(|_| ProofError::InvalidWitness)?;
        let chunk = as_chunk(&candidate.execution);
        prepared.witness.finality_cert =
            self.run_chunk_bft(&chunk, chunk.hash(), voter, chunk.active_validator_set_root)?;
        validate_consensus(&prepared.witness).map_err(|_| ProofError::InvalidWitness)?;
        Ok(())
    }

    /// Verify a complete proof, recheck its still-current anchor and persist
    /// finality, proof, history, penalties, seed and rotation in one DB batch.
    pub fn commit_consensus_chunk<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        self.commit_consensus_chunk_inner(witness, proof, proof_system, false, None)
    }

    pub(crate) fn commit_imported_consensus_chunk<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
        executor: Option<&dyn neutrino_proof_system::ErasedBlockExecutor>,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        self.commit_consensus_chunk_inner(witness, proof, proof_system, true, executor)
    }

    fn commit_consensus_chunk_inner<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
        imported: bool,
        executor: Option<&dyn neutrino_proof_system::ErasedBlockExecutor>,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        let (context, seed, _) = self.consensus_boundary(witness.context.chunk_id)?;
        if witness.context != context
            || witness.seed != seed
            || witness.chain_spec != *self.chain_spec()
            || proof_system.consensus_block_key() != Some(witness.block_guest_vk_digest)
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        for block in &witness.blocks {
            let stored = if imported {
                self.store().get_header(&block.header.hash())?
            } else {
                self.store().get_header_by_height(block.header.height)?
            };
            if stored.as_ref() != Some(&block.header) {
                return Err(ProofError::PublicInputMismatch.into());
            }
        }
        let statement = validate_consensus(witness).map_err(|_| ProofError::InvalidWitness)?;
        proof_system.verify_consensus_chunk(proof, &statement)?;
        let chunk = as_chunk(&statement.execution);
        let wire = ChunkProof {
            finality_cert: witness.finality_cert.clone(),
            chunk_id: chunk.chunk_id,
            chunk_hash: chunk.hash(),
            public_inputs: statement.execution.chunk.clone(),
            proof_bytes: borsh::to_vec(proof)?,
        };
        let mut history = witness.history.clone();
        history.penalties = validate_candidate(witness)
            .map_err(|_| ProofError::InvalidWitness)?
            .penalties;
        history.chunks.push(HistoricalChunk {
            chunk: chunk.clone(),
            validators: context.active_validators,
            seed,
            finality: witness.finality_cert.clone(),
        });
        let state = ConsensusState { statement, history };
        let batch =
            crate::store::ChainStore::<DB>::consensus_finalization_batch(witness, &wire, &state)?;
        if self.store().get_block_hash_by_height(chunk.end_height)? == Some(chunk.end_block_hash) {
            self.store_mut()
                .db_mut()
                .write_batch(batch)
                .map_err(crate::store::StoreError::Database)?;
        } else {
            let executor = executor.ok_or(ProofError::Unsupported)?;
            // Proof verification precedes replay; a failed replay or DB batch
            // cannot change either finality or the selected chain/state.
            let replayed = self
                .replay_to_head(chunk.end_block_hash, executor)
                .map_err(FinalizeError::Replay)?;
            self.commit_materialized_head_with_batch(
                replayed.height,
                replayed.hash,
                replayed.state_root,
                Some(replayed.state),
                batch,
            )?;
        }

        self.install_consensus_state(&state);
        self.bft_sessions.remove(&chunk.chunk_id);
        let _ = self
            .fork_choice
            .add_finalized_chunk(&chunk, &witness.finality_cert);
        Ok(FinalizeOutcome {
            chunk_hash: chunk.hash(),
            chunk,
            chunk_proof: wire,
            public_inputs: state.statement.execution.chunk,
            finality_cert: witness.finality_cert.clone(),
        })
    }
}
