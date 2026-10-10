//! Complete consensus chunk preparation and atomic, proof-gated finalization.

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::evidence::{EvidenceAnchor, EvidenceArtifact};
use neutrino_consensus_types::history::is_recent_history_index;
use neutrino_consensus_types::history_proof::{ChainBinding, ConsensusPrograms};
use neutrino_consensus_types::{AggregatedVote, Chunk, ChunkProof, FinalityCert};
use neutrino_default_runtime_core::{Transaction, accountability};
use neutrino_primitives::{ChunkId, Hash};
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_prover_chunk::{
    body::ConsensusBody,
    consensus::{
        ConsensusWitness, ValidatedCandidate, ValidatedConsensus, as_chunk, context_boundary,
        genesis_context, validate_candidate, validate_consensus_with_context,
    },
    execution::{ExecutionContext, ProvenBlock, commitment},
    history::{HistoricalChunk, HistoryWitness},
};
use neutrino_runtime_abi::{StateWitness, TrieNodeBytes, TrieValueBytes};
use neutrino_storage::{Column, Database};

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
    /// Candidate validation of `witness` at preparation. Candidate validation
    /// never reads the certificate, the only field filled afterwards.
    pub candidate: ValidatedCandidate,
    /// Inner proofs in exact canonical height order.
    pub proofs: Vec<P::BlockProof>,
}

impl<DB: Database> Engine<DB> {
    /// Pin the Guest identities of the configured proof backend. This is
    /// process configuration, never chosen by a peer or evidence reporter. Bound
    /// to the chain specification's runtime artifact, it names the genesis
    /// boundary's program set and the evidence anchor digests.
    pub const fn set_programs(
        &mut self,
        guests: neutrino_consensus_types::history_proof::GuestPrograms,
    ) {
        self.programs = Some(guests.with_runtime(self.chain_spec().runtime_code_hash));
        self.consensus_programs = Some(guests.consensus);
    }

    /// The immutable chain binding: the specification plus the consensus
    /// Guests pinned by [`Self::set_programs`]. Without a proof backend the
    /// Guests are zero and no statement can verify.
    #[must_use]
    pub fn chain_binding(&self) -> ChainBinding {
        let consensus = self.consensus_programs.unwrap_or(ConsensusPrograms {
            chunk: [0; 8],
            checkpoint: [0; 8],
        });
        self.chain_binding_with(consensus)
    }

    /// This specification bound to `consensus`, using the cached spec hash.
    pub(crate) const fn chain_binding_with(&self, consensus: ConsensusPrograms) -> ChainBinding {
        ChainBinding {
            chain_id: self.chain_spec().chain_id,
            chain_spec_hash: self.chain_spec_hash(),
            chunk_size: self.chunk_size(),
            consensus,
        }
    }

    /// The certified participation report every block of `height`'s chunk
    /// hands to the runtime: the precommit signers of the previous chunk,
    /// resolved from its finalized certificate. Chunk zero has none.
    ///
    /// # Errors
    /// Returns [`crate::import::PARTICIPATION_UNAVAILABLE`] while the previous
    /// chunk is not finalized locally; production waits and import defers,
    /// exactly as for the evidence anchor's history root.
    pub fn participation_for_height(
        &self,
        height: u64,
    ) -> Result<
        Option<neutrino_consensus_types::participation::ParticipationReport>,
        alloc::string::String,
    > {
        if self.programs.is_none() {
            return Ok(None);
        }
        let chunk_id = self
            .chunk_of_height(height)
            .ok_or_else(|| alloc::string::String::from("invalid participation height"))?;
        let Some(previous) = chunk_id.checked_sub(1) else {
            return Ok(None);
        };
        let unavailable = || alloc::string::String::from(crate::import::PARTICIPATION_UNAVAILABLE);
        let record = self
            .store()
            .historical_chunk(previous)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        neutrino_consensus_types::participation::ParticipationReport::from_certificate(
            previous,
            &record.validators,
            &record.finality.precommit.aggregation_bits,
        )
        .map(Some)
        .ok_or_else(|| alloc::string::String::from("finalized certificate bitmap is malformed"))
    }

    /// The genesis boundary's program set: the pinned Guests bound to the
    /// specification's runtime. Without a proof backend the Guests are zero;
    /// such a node can serve and import blocks but never proves, verifies or
    /// agrees on a chunk statement, because incomplete sets fail validation.
    pub fn genesis_programs(&self) -> neutrino_consensus_types::history_proof::ProgramSet {
        self.programs.unwrap_or_else(|| {
            neutrino_consensus_types::history_proof::GuestPrograms {
                execution: neutrino_consensus_types::history_proof::ExecutionPrograms {
                    fact: [0; 8],
                    evidence: [0; 8],
                    block: [0; 8],
                },
                consensus: neutrino_consensus_types::history_proof::ConsensusPrograms {
                    chunk: [0; 8],
                    checkpoint: [0; 8],
                },
            }
            .with_runtime(self.chain_spec().runtime_code_hash)
        })
    }

    /// Build the trusted incoming anchor for ordinary or replay execution.
    pub fn evidence_anchor(
        &self,
        height: u64,
    ) -> Result<neutrino_consensus_types::evidence::EvidenceAnchor, alloc::string::String> {
        if self.programs.is_none() {
            return Ok(neutrino_consensus_types::evidence::EvidenceAnchor::default());
        }
        let programs = self
            .programs_for_height(height)
            .map_err(|_| alloc::string::String::from(crate::import::PROGRAMS_UNAVAILABLE))?;
        let spec = self.chain_spec();
        let chunk_id = self
            .chunk_of_height(height)
            .ok_or_else(|| alloc::string::String::from("invalid evidence anchor height"))?;
        let history_root = if chunk_id == 0 {
            neutrino_consensus_types::history::empty_history_root()
        } else {
            self.store()
                .consensus_boundary(chunk_id)
                .map_err(|_| alloc::string::String::from(crate::import::HISTORY_UNAVAILABLE))?
                .ok_or_else(|| alloc::string::String::from(crate::import::HISTORY_UNAVAILABLE))?
                .history_root
        };
        Ok(neutrino_consensus_types::evidence::EvidenceAnchor {
            chain_spec_hash: self.chain_spec_hash(),
            chunk_id,
            history_root,
            block_guest_vk_digest: programs.execution.block,
            evidence_guest_vk_digest: programs.execution.evidence,
            fact_guest_vk_digest: programs.execution.fact,
            unbonding_delay_blocks: spec.runtime.unbonding_delay_blocks,
            chunk_size: spec.consensus.chunk_size,
        })
    }

    /// Preceding finalized chunks whose complete historical records (validator
    /// vector, seed, certificate) this node keeps so safety evidence can still
    /// be constructed and raw reports verified locally: one unbonding delay,
    /// never less than the eight-chunk liveness window.
    #[must_use]
    pub const fn history_record_window_chunks(&self) -> u64 {
        let spec = self.chain_spec();
        neutrino_consensus_types::history::history_record_window_chunks(
            spec.runtime.unbonding_delay_blocks,
            spec.consensus.chunk_size,
        )
    }

    /// Whether this node still keeps the complete historical record of a
    /// finalized chunk. Receipts about older chunks stay admissible when a
    /// reporter supplies an opening authenticated at a recent boundary.
    #[must_use]
    pub fn in_history_record_window(&self, chunk_id: u64) -> bool {
        neutrino_consensus_types::history::is_history_index_within(
            chunk_id,
            self.finalized_next_chunk_id(),
            self.history_record_window_chunks(),
        )
    }

    /// The governable runtime policy in force at the head state. Genesis
    /// seeds it from the chain specification; governance replaces it.
    #[must_use]
    pub fn runtime_policy(&self) -> neutrino_default_runtime_core::RuntimePolicy {
        self.state()
            .get(neutrino_default_runtime_core::RUNTIME_POLICY_KEY)
            .and_then(|bytes| borsh::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// The governed runtime policy in the latest finalized state, read from
    /// persisted trie nodes along one key path. Evidence pruning uses it so
    /// nothing is dropped on unfinalized head state.
    ///
    /// # Errors
    /// Reports storage failures and a finalized state missing its nodes.
    pub fn finalized_runtime_policy(
        &self,
    ) -> Result<neutrino_default_runtime_core::RuntimePolicy, FinalizeError<DB::Error>> {
        let root = self
            .canonical_boundary(self.finalized_next_chunk_id())?
            .state_root;
        let db = self.store().db();
        let bytes = neutrino_trie::lookup_persisted(
            root,
            neutrino_default_runtime_core::RUNTIME_POLICY_KEY,
            |hash| db.get(Column::TrieNodes, hash).ok().flatten(),
            |hash| db.get(Column::StateValues, hash).ok().flatten(),
        )
        .map_err(|_| crate::StoreError::Corrupt("finalized runtime policy state"))?;
        Ok(bytes
            .and_then(|bytes| borsh::from_slice(&bytes).ok())
            .unwrap_or_default())
    }

    /// Snapshot a self-contained offence for proving outside the engine lock.
    pub fn evidence_witness(
        &self,
        evidence: &neutrino_consensus_types::SlashingEvidence,
    ) -> Result<neutrino_prover_chunk::evidence::EvidenceWitness, FinalizeError<DB::Error>> {
        let block_guest_vk_digest = self
            .programs
            .ok_or(ProofError::Unsupported)?
            .execution
            .block;
        let id = neutrino_prover_chunk::history::evidence_chunk_id(self.chain_spec(), evidence)
            .map_err(|_| ProofError::InvalidWitness)?;
        // Proving needs the complete record; a chunk this node no longer
        // retains can be proven by an archive, never here.
        let source = self
            .store()
            .historical_chunk(id)?
            .ok_or(ProofError::InvalidWitness)?;
        Ok(neutrino_prover_chunk::evidence::EvidenceWitness {
            chain_spec: self.chain_spec().clone(),
            source,
            claim: neutrino_prover_chunk::evidence::EvidenceClaim::Slash(evidence.clone()),
            block_guest_vk_digest,
            reporter: None,
        })
    }

    /// Open a locally retained record, or an archived record, for a new report.
    pub fn evidence_submission(
        &self,
        statement: neutrino_consensus_types::evidence::EvidenceStatement,
    ) -> Result<neutrino_consensus_types::evidence::EvidenceSubmission, FinalizeError<DB::Error>>
    {
        let count = self.finalized_next_chunk_id();
        let source = statement.context.chunk_id;
        let in_window = match statement.kind {
            // Safety has no source age limit. Pruned nodes can open only their
            // finite cache; external reporters supply older openings.
            neutrino_consensus_types::evidence::SanctionKind::Slash => source < count,
            neutrino_consensus_types::evidence::SanctionKind::Inactivity => {
                is_recent_history_index(source, count)
            }
        };
        if !in_window {
            return Err(ProofError::InvalidWitness.into());
        }
        // The path is authenticated against the statement's own context, so a
        // statement about a context that never was the canonical record fails
        // here rather than in the block.
        let history = self.store().history_path(
            source,
            count,
            neutrino_consensus_types::evidence::commitment(&statement.context),
        )?;
        Ok(neutrino_consensus_types::evidence::EvidenceSubmission { statement, history })
    }

    /// Authenticate a reporter's opening and advance it over a bounded finalized suffix.
    /// Old source chunks remain admissible; only the opening's anchor must be recent.
    /// Unknown old anchors are unavailable, while forged openings at known anchors
    /// are invalid witnesses. This lets callers defer refresh requests without
    /// misclassifying an old safety offence as expired.
    pub fn evidence_submission_with_path(
        &self,
        statement: &neutrino_consensus_types::evidence::EvidenceStatement,
        path: &neutrino_consensus_types::history::HistoryPath,
    ) -> Result<neutrino_consensus_types::evidence::EvidenceSubmission, FinalizeError<DB::Error>>
    {
        let count = self.finalized_next_chunk_id();
        let source = statement.context.chunk_id;
        if path.index != source
            || source >= path.count
            || (statement.kind == neutrino_consensus_types::evidence::SanctionKind::Inactivity
                && !is_recent_history_index(source, count))
        {
            return Err(ProofError::InvalidWitness.into());
        }
        if path.count > count {
            return Err(crate::StoreError::Corrupt(
                "evidence history anchor is not finalized locally",
            )
            .into());
        }
        if path.count
            < count.saturating_sub(neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS)
        {
            return Err(
                crate::StoreError::Corrupt("evidence history anchor requires refresh").into(),
            );
        }
        let mut frontier = self.store().history_frontier(path.count)?;
        let root = frontier.root().ok_or(ProofError::InvalidWitness)?;
        let boundary =
            self.store()
                .consensus_boundary(path.count)?
                .ok_or(crate::StoreError::Corrupt(
                    "evidence history boundary is unavailable",
                ))?;
        if boundary.history_root != root {
            return Err(crate::StoreError::Corrupt(
                "evidence history frontier differs from boundary",
            )
            .into());
        }
        let leaf = neutrino_consensus_types::evidence::commitment(&statement.context);
        if !path.verify(leaf, root) {
            return Err(ProofError::InvalidWitness.into());
        }
        let mut history = path.clone();
        for index in path.count..count {
            let record =
                self.store()
                    .historical_chunk(index)?
                    .ok_or(crate::StoreError::Corrupt(
                        "evidence history append is unavailable",
                    ))?;
            let appended_leaf = commitment(&record.evidence_context());
            history
                .advance(leaf, &frontier, appended_leaf)
                .ok_or(ProofError::InvalidWitness)?;
            frontier
                .append(appended_leaf)
                .ok_or(ProofError::InvalidWitness)?;
        }
        if frontier != self.store().history_frontier(count)? {
            return Err(ProofError::InvalidWitness.into());
        }
        Ok(neutrino_consensus_types::evidence::EvidenceSubmission {
            statement: statement.clone(),
            history,
        })
    }

    /// Bind a candidate to its finalized boundary and complete parent ancestry.
    /// The runtime authenticates receipts and protects replay in the branch state.
    ///
    /// Evidence admissions are checked by `admissions_are_well_formed`, which
    /// rejects without unwinding: this runs natively on peer bodies, and the
    /// release profile aborts on panic. The block gas limit does not affect
    /// admission shape; it is accepted so callers pass the header as is.
    pub fn authorize_consensus_body(
        &self,
        height: u64,
        parent_hash: Hash,
        body: &neutrino_consensus_types::Body,
        _gas_limit: u64,
        block_key: &[u32; 8],
    ) -> Result<(), FinalizeError<DB::Error>> {
        let chunk_id = self
            .chunk_of_height(height)
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
            .checked_mul(self.chunk_size())
            .ok_or(ProofError::InvalidWitness)?;
        let mut ancestor = parent_hash;
        for expected_height in (boundary_height + 1..height).rev() {
            let header = self
                .store()
                .get_header(&ancestor)?
                .ok_or(ProofError::InvalidWitness)?;
            if header.height != expected_height
                || header.hash() != ancestor
                || !self.has_body(&ancestor)?
            {
                return Err(ProofError::InvalidWitness.into());
            }
            ancestor = header.parent_hash;
        }
        if ancestor != context.parent_block_hash
            || self
                .programs
                .is_some_and(|programs| &programs.execution.block != block_key)
        {
            return Err(ProofError::InvalidWitness.into());
        }
        let anchor = self
            .evidence_anchor(height)
            .map_err(|_| ProofError::InvalidWitness)?;
        let transactions = body
            .transactions
            .iter()
            .map(|raw| borsh::from_slice(raw))
            .collect::<Result<Vec<Transaction>, _>>()?;
        if !admissions_are_well_formed(
            self.chain_spec().chain_id,
            height,
            &anchor,
            &transactions,
            &body.evidence_proofs,
        ) {
            return Err(ProofError::InvalidWitness.into());
        }
        Ok(())
    }

    /// Whether a block body is archived under `hash`, read without decoding it.
    fn has_body(&self, hash: &Hash) -> Result<bool, crate::StoreError<DB::Error>> {
        let body = self
            .store()
            .db()
            .get(Column::Blocks, &crate::store::keys::hash_key(hash))
            .map_err(crate::StoreError::Database)?;
        Ok(body.is_some())
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
            let programs = self.genesis_programs();
            return Ok((
                genesis_context(spec, programs),
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
        let (_, end) = self
            .chunk_heights(chunk_id)
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
        if as_chunk(&prepared.candidate.execution.chunk).hash() != session.chunk_hash() {
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
        let guests = proof_system.programs().ok_or(ProofError::Unsupported)?;
        let programs = guests.with_runtime(self.chain_spec().runtime_code_hash);
        let key = programs.execution.block;
        let (context, seed, _) = self.consensus_boundary(chunk_id)?;
        // A node can only prove chunks whose program set its backend holds;
        // otherwise it follows by verification until the programs arrive. The
        // consensus Guests are pinned: the backend must embed this chain's.
        if self
            .consensus_programs
            .is_some_and(|pinned| pinned != guests.consensus)
            || !proof_system.can_prove(&neutrino_consensus_types::history_proof::GuestPrograms {
                execution: context.programs.execution,
                consensus: guests.consensus,
            })
        {
            return Err(ProofError::Unsupported.into());
        }
        // The trusted context's chunk size is the specification's.
        let (start, end) = self
            .chunk_heights(chunk_id)
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
        let post_state = self.consensus_rotation_witness(post_root)?;
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
            fact_guest_vk_digest: programs.execution.fact,
            evidence_guest_vk_digest: programs.execution.evidence,
            consensus_programs: guests.consensus,
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
            facts: Vec::new(),
        };
        let candidate = validate_candidate(&witness).map_err(|_| ProofError::InvalidWitness)?;
        Ok(PreparedConsensusChunk {
            witness,
            candidate,
            proofs,
        })
    }

    fn consensus_rotation_witness(
        &self,
        root: Hash,
    ) -> Result<StateWitness, FinalizeError<DB::Error>> {
        let trie = self.persisted_trie(root)?;
        let keys = neutrino_prover_chunk::rotation::witness_keys();
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
        self.certify_validated_consensus_chunk(prepared, voter)
            .map(|_| ())
    }

    /// Certify `prepared` and return the complete consensus validation of the
    /// certified witness.
    pub(crate) fn certify_validated_consensus_chunk<P: ProofSystem>(
        &mut self,
        prepared: &mut PreparedConsensusChunk<P>,
        voter: &ProposerKey,
    ) -> Result<ValidatedConsensus, FinalizeError<DB::Error>> {
        let chunk = as_chunk(&prepared.candidate.execution.chunk);
        prepared.witness.finality_cert =
            self.run_chunk_bft(&chunk, chunk.hash(), voter, chunk.active_validator_set_root)?;
        validate_consensus_with_context(&prepared.witness)
            .map_err(|_| ProofError::InvalidWitness.into())
    }

    /// Verify a complete proof, recheck its still-current anchor and persist
    /// finality, proof, history, penalties, seed and rotation in one DB batch.
    pub fn commit_consensus_chunk<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        self.commit_consensus_chunk_inner(witness, proof, proof_system, false, None, None)
    }

    /// [`Self::commit_consensus_chunk`] for a witness whose complete
    /// consensus validation the caller already holds.
    pub(crate) fn commit_validated_consensus_chunk<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
        validated: ValidatedConsensus,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        self.commit_consensus_chunk_inner(
            witness,
            proof,
            proof_system,
            false,
            None,
            Some(validated),
        )
    }

    pub(crate) fn commit_imported_consensus_chunk<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
        executor: Option<&dyn neutrino_proof_system::ErasedBlockExecutor>,
        validated: ValidatedConsensus,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        self.commit_consensus_chunk_inner(
            witness,
            proof,
            proof_system,
            true,
            executor,
            Some(validated),
        )
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
        self.commit_consensus_chunk_inner(witness, proof, proof_system, true, executor, None)
    }

    /// `validated`, when present, is the complete consensus validation of this
    /// exact `witness`; it replaces the otherwise identical revalidation.
    fn commit_consensus_chunk_inner<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
        imported: bool,
        executor: Option<&dyn neutrino_proof_system::ErasedBlockExecutor>,
        validated: Option<ValidatedConsensus>,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        let (context, seed, _) = self.consensus_boundary(witness.context.chunk_id)?;
        if witness.context != context
            || witness.seed != seed
            || witness.chain_spec != *self.chain_spec()
            || proof_system
                .programs()
                .map(|programs| programs.execution.block)
                != Some(witness.block_guest_vk_digest)
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
        let validated = if let Some(validated) = validated {
            validated
        } else {
            validate_consensus_with_context(witness).map_err(|_| ProofError::InvalidWitness)?
        };
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
            runtime_code_hash: context.programs.runtime_code_hash,
            block_guest_vk_digest: context.programs.execution.block,
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
            self.store_mut().write_observed_batch(batch, false)?;
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

/// Whether a body's evidence admissions satisfy the runtime's input rules
/// ([`accountability::check_admissions`]) and exactly one attachment per
/// submission binds its statement to the anchor's evidence and fact programs,
/// in order. Peer bodies reach this check in native code, where the release
/// profile aborts on panic, so the non-panicking runtime check is used.
fn admissions_are_well_formed(
    chain_id: u64,
    height: u64,
    anchor: &EvidenceAnchor,
    transactions: &[Transaction],
    attachments: &[EvidenceArtifact],
) -> bool {
    if accountability::check_admissions(chain_id, height, anchor, transactions).is_err() {
        return false;
    }
    let admissions = transactions
        .iter()
        .filter_map(|transaction| match transaction {
            Transaction::SubmitEvidence(submission) => Some(submission),
            _ => None,
        });
    admissions.clone().count() == attachments.len()
        && admissions.zip(attachments).all(|(submission, attachment)| {
            attachment.binds(
                &submission.statement,
                &anchor.evidence_guest_vk_digest,
                &anchor.fact_guest_vk_digest,
            )
        })
}
