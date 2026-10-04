//! Complete consensus chunk preparation and atomic, proof-gated finalization.

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::history::is_recent_history_index;
use neutrino_consensus_types::{AggregatedVote, Chunk, ChunkProof, FinalityCert};
use neutrino_primitives::{ChunkId, Hash};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_prover_chunk::{
    body::ConsensusBody,
    consensus::{
        ConsensusWitness, as_chunk, context_boundary, genesis_context, validate_candidate,
        validate_consensus, validate_consensus_with_context,
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
    /// Authenticated outgoing boundary, established by a Chunk or History receipt.
    pub boundary: neutrino_consensus_types::history_proof::ConsensusBoundary,
    /// Full context retained for ordinary execution, checked against the compact output.
    pub next_context: ExecutionContext,
    /// Randomness for the following chunk.
    pub next_seed: Hash,
    /// Bounded append frontier; historical records live in the archive.
    pub frontier: neutrino_consensus_types::history::HistoryFrontier,
}

/// Immutable snapshot carried outside the engine lock for expensive proving.
pub struct PreparedConsensusChunk<P: ProofSystem> {
    /// Fully bound candidate, with certificate filled before proving.
    pub witness: ConsensusWitness,
    /// Inner proofs in exact canonical height order.
    pub proofs: Vec<P::BlockProof>,
}

impl<DB: Database> Engine<DB> {
    /// Pin all three accepted programs from the configured proof backend. These are
    /// process configuration, never chosen by a peer or evidence reporter.
    pub const fn set_evidence_programs(
        &mut self,
        block: [u32; 8],
        evidence: [u32; 8],
        facts: [u32; 8],
    ) {
        self.evidence_programs = Some((block, evidence, facts));
    }

    /// Build the trusted incoming anchor for ordinary or replay execution.
    pub fn evidence_anchor(
        &self,
        height: u64,
    ) -> Result<neutrino_consensus_types::evidence::EvidenceAnchor, alloc::string::String> {
        let Some((block_guest_vk_digest, evidence_guest_vk_digest, fact_guest_vk_digest)) =
            self.evidence_programs
        else {
            return Ok(neutrino_consensus_types::evidence::EvidenceAnchor::default());
        };
        let spec = self.chain_spec();
        let chunk_id = height
            .checked_sub(1)
            .and_then(|h| h.checked_div(spec.consensus.chunk_size))
            .ok_or_else(|| alloc::string::String::from("invalid evidence anchor height"))?;
        let frontier = self
            .store()
            .history_frontier(chunk_id)
            .map_err(|_| alloc::string::String::from("unavailable historical boundary"))?;
        Ok(neutrino_consensus_types::evidence::EvidenceAnchor {
            chain_spec_hash: spec.hash(),
            chunk_id,
            history_root: frontier
                .root()
                .ok_or_else(|| alloc::string::String::from("invalid historical boundary"))?,
            block_guest_vk_digest,
            evidence_guest_vk_digest,
            fact_guest_vk_digest,
            policy: spec.runtime,
        })
    }

    /// Snapshot a self-contained offence for proving outside the engine lock.
    pub fn evidence_witness(
        &self,
        evidence: &neutrino_consensus_types::SlashingEvidence,
    ) -> Result<neutrino_prover_chunk::evidence::EvidenceWitness, FinalizeError<DB::Error>> {
        let (block_guest_vk_digest, _, _) =
            self.evidence_programs.ok_or(ProofError::Unsupported)?;
        let id = neutrino_prover_chunk::history::evidence_chunk_id(self.chain_spec(), evidence)
            .map_err(|_| ProofError::InvalidWitness)?;
        if !is_recent_history_index(id, self.finalized_next_chunk_id()) {
            return Err(ProofError::InvalidWitness.into());
        }
        let source = self
            .store()
            .historical_chunk(id)?
            .ok_or(ProofError::InvalidWitness)?;
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
        let count = self.finalized_next_chunk_id();
        if !is_recent_history_index(statement.context.chunk_id, count) {
            return Err(ProofError::InvalidWitness.into());
        }
        let opening = self
            .store()
            .historical_opening(statement.context.chunk_id, count)?;
        if opening.record.evidence_context() != statement.context {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let history = opening.path;
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
        if body
            .finality_votes
            .iter()
            .any(|vote| !is_recent_history_index(vote.data.chunk_id, chunk_id))
        {
            return Err(ProofError::InvalidWitness.into());
        }
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
                .is_some_and(|(key, _, _)| &key != block_key)
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
                if !attachment.binds(
                    &submission.statement,
                    &anchor.evidence_guest_vk_digest,
                    &anchor.fact_guest_vk_digest,
                ) {
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
        let source_id =
            neutrino_prover_chunk::history::evidence_chunk_id(self.chain_spec(), evidence)
                .map_err(|_| ProofError::InvalidWitness)?;
        if !is_recent_history_index(source_id, self.finalized_next_chunk_id()) {
            return Err(ProofError::InvalidWitness.into());
        }
        let source = self
            .store()
            .historical_chunk(source_id)?
            .ok_or(ProofError::InvalidWitness)?;
        let (_, id) = neutrino_prover_chunk::history::authorize_evidence_at_record(
            self.chain_spec(),
            &source,
            evidence,
            key,
        )
        .map_err(|_| ProofError::InvalidWitness)?;
        if self.store().is_offence_finalized(&id)? {
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
                genesis_context(spec),
                spec.genesis_seed,
                HistoryWitness::default(),
            ));
        }
        let previous = self
            .store()
            .get_consensus_state()?
            .ok_or(ProofError::InvalidWitness)?;
        if previous.next_context.chunk_id != chunk_id
            || context_boundary(&previous.next_context, previous.next_seed)
                .map_err(|_| ProofError::InvalidWitness)?
                != previous.boundary
            || previous.frontier.root() != Some(previous.boundary.history_root)
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok((
            previous.next_context,
            previous.next_seed,
            HistoryWitness {
                frontier: previous.frontier,
                records: Vec::new(),
            },
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

    /// Prepare the fixed, previously signed BFT branch under the current proof
    /// backend, even if fork choice currently selects a competing branch.
    /// Without a session, prepare the current canonical candidate.
    pub fn prepare_bft_consensus_chunk<P: ProofSystem>(
        &self,
        chunk_id: ChunkId,
        proof_system: &P,
    ) -> Result<PreparedConsensusChunk<P>, FinalizeError<DB::Error>> {
        let Some(session) = self.bft_session(chunk_id) else {
            return self.prepare_consensus_chunk(chunk_id, proof_system);
        };
        let prepared = self.prepare_consensus_chunk_on_branch(
            chunk_id,
            session.end_block_hash(),
            proof_system,
        )?;
        let candidate =
            validate_candidate(&prepared.witness).map_err(|_| ProofError::InvalidWitness)?;
        if as_chunk(&candidate.execution.chunk).hash() != session.chunk_hash() {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok(prepared)
    }

    /// Prepare a complete candidate on an explicitly selected branch. Every
    /// receipt and consensus field is authenticated under the current backend.
    ///
    /// # Errors
    /// Returns unavailable ancestry, invalid receipts or consensus bindings.
    #[allow(clippy::too_many_lines)] // Snapshot all authenticated inputs before leaving the engine lock.
    pub fn prepare_consensus_chunk_on_branch<P: ProofSystem>(
        &self,
        chunk_id: ChunkId,
        end_hash: Hash,
        proof_system: &P,
    ) -> Result<PreparedConsensusChunk<P>, FinalizeError<DB::Error>> {
        let key = proof_system
            .consensus_block_key()
            .ok_or(ProofError::Unsupported)?;
        let (context, seed, _) = self.consensus_boundary(chunk_id)?;
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
            let output = proof_system.verify_block_statement(&proof, &wire.public_inputs)?;
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
        let history = self.store().history_witness(
            chunk_id,
            bodies
                .iter()
                .flat_map(|body| body.finality_votes.iter().map(|vote| vote.data.chunk_id)),
        )?;
        let witness = ConsensusWitness {
            fact_guest_vk_digest: proof_system.fact_key().ok_or(ProofError::Unsupported)?,
            evidence_guest_vk_digest: proof_system.evidence_key().ok_or(ProofError::Unsupported)?,
            chain_spec: self.chain_spec().clone(),
            context,
            seed,
            blocks,
            bodies,
            post_state,
            history,
            finality_cert: FinalityCert {
                // Candidate validation does not inspect finality. The prepared
                // input receives the authenticated live certificate before proving.
                proposal: neutrino_consensus_types::BftProposal {
                    chunk: Chunk {
                        chunk_id,
                        start_height: 0,
                        end_height: 0,
                        start_state_root: [0; 32],
                        end_state_root: [0; 32],
                        start_block_hash: [0; 32],
                        end_block_hash: [0; 32],
                        block_hash_root: [0; 32],
                        block_proof_root: [0; 32],
                        vrf_proof_root: [0; 32],
                        active_validator_set_root: [0; 32],
                        next_validator_set_root: [0; 32],
                        da_root: [0; 32],
                    },
                    round: 0,
                    proposer_index: 0,
                    valid_quorum: None,
                    round_change_certificate: None,
                    signature: [0; 96],
                },
                prevote_attestations: Vec::new(),
                precommit_attestations: Vec::new(),
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
        &mut self,
        prepared: &mut PreparedConsensusChunk<P>,
        voter: &ProposerKey,
    ) -> Result<(), FinalizeError<DB::Error>> {
        let candidate =
            validate_candidate(&prepared.witness).map_err(|_| ProofError::InvalidWitness)?;
        let chunk = as_chunk(&candidate.execution.chunk);
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

    /// Commit complete consensus for the saved BFT target. When that target
    /// differs from fork choice, replay its already-proven branch with the
    /// installed executor before atomically publishing finality and live state.
    pub fn commit_bft_consensus_chunk<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
        executor: Option<&dyn neutrino_proof_system::ErasedBlockExecutor>,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        let session = self
            .bft_session(witness.context.chunk_id)
            .ok_or(FinalizeError::FinalizationStalled)?;
        let candidate = validate_candidate(witness).map_err(|_| ProofError::InvalidWitness)?;
        if as_chunk(&candidate.execution.chunk).hash() != session.chunk_hash() {
            return Err(ProofError::PublicInputMismatch.into());
        }
        if self.bft_quorum_identity(witness.context.chunk_id)
            != Some(crate::BftQuorumIdentity::from_certificate(
                &witness.finality_cert,
            ))
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
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
        let validated =
            validate_consensus_with_context(witness).map_err(|_| ProofError::InvalidWitness)?;
        let statement = validated.statement;
        proof_system.verify_consensus_chunk(proof, &statement)?;
        let chunk = as_chunk(&statement.chunk);
        let wire = ChunkProof {
            finality_cert: witness.finality_cert.clone(),
            chunk_id: chunk.chunk_id,
            chunk_hash: chunk.hash(),
            public_inputs: statement.chunk.clone(),
            proof_bytes: borsh::to_vec(proof)?,
        };
        let record = HistoricalChunk {
            chunk: chunk.clone(),
            validators: context.active_validators,
            seed,
            finality: witness.finality_cert.clone(),
        };
        let mut frontier = witness.history.frontier.clone();
        let history_root = frontier
            .append(commitment(&record.evidence_context()))
            .ok_or(ProofError::InvalidWitness)?;
        if history_root != statement.end.history_root
            || context_boundary(&validated.next_context, statement.end.seed)
                .map_err(|_| ProofError::InvalidWitness)?
                != statement.end
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let next_seed = statement.end.seed;
        let state = ConsensusState {
            boundary: statement.end,
            next_context: validated.next_context,
            next_seed,
            frontier,
        };
        let batch = self
            .store()
            .consensus_finalization_batch(witness, &wire, &statement, &state)?;
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
            public_inputs: statement.chunk,
            finality_cert: witness.finality_cert.clone(),
        })
    }
}
