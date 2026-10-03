//! Proof-gated archival history coverage, independent of live chunk finality.

use crate::{Engine, FinalizeError};
use neutrino_consensus_types::history_proof::{
    ChainBinding, Checkpoint, ConsensusBoundary, ConsensusStatement, MAX_FOLD_CHUNKS, ProofDomain,
};
use neutrino_consensus_types::{ChunkProof, HistoryProof};
use neutrino_primitives::Hash;
use neutrino_proof_system::{ProofError, ProofSystem, VerifiedHistory, verify_history_proof};
use neutrino_storage::Database;

/// Immutable receipts loaded before handing a fold to a background prover.
#[derive(Clone, Debug)]
pub struct PreparedHistoryFold {
    /// Exact canonical wire receipts, in increasing chunk order.
    pub chunks: Vec<ChunkProof>,
    /// Verified public outputs retained with those finalizations.
    pub statements: Vec<ConsensusStatement>,
}

/// Outcome of archiving a genuinely verified canonical range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryImportOutcome {
    /// Archived conditional range identity.
    pub range_id: Hash,
    /// Canonical endpoint identity.
    pub checkpoint_hash: Hash,
    /// Current published genesis-prefix coverage, which may exceed this endpoint.
    pub recursive_covered_chunks: u64,
}

impl<DB: Database> Engine<DB> {
    /// Number of complete chunks finalized locally.
    #[must_use]
    pub fn finalized_next_chunk_id(&self) -> u64 {
        self.latest_finalized_chunk_id().map_or(0, |id| {
            id.checked_add(1)
                .expect("finalized chunk count was validated")
        })
    }

    /// Canonical finality boundary, never inferred from peer metadata.
    pub fn canonical_boundary(
        &self,
        count: u64,
    ) -> Result<ConsensusBoundary, FinalizeError<DB::Error>> {
        if count > self.finalized_next_chunk_id() {
            return Err(ProofError::InvalidWitness.into());
        }
        if count == 0 {
            return Ok(ConsensusBoundary::genesis(self.chain_spec()));
        }
        let boundary = self
            .store()
            .consensus_boundary(count)?
            .ok_or(ProofError::InvalidWitness)?;
        if !boundary.is_well_formed(&ChainBinding::from_spec(self.chain_spec())) {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok(boundary)
    }

    /// Pin the active history program profile and index retained canonical endpoints.
    /// Called once after the configured proof backend derives its trusted keys.
    pub fn set_history_domain(
        &mut self,
        domain: ProofDomain,
    ) -> Result<(), FinalizeError<DB::Error>> {
        if domain.chain != ChainBinding::from_spec(self.chain_spec()) {
            return Err(ProofError::PublicInputMismatch.into());
        }
        if self
            .evidence_programs
            .is_some_and(|(block, evidence, facts)| {
                (block, evidence, facts)
                    != (
                        domain.execution.block,
                        domain.execution.evidence,
                        domain.execution.fact,
                    )
            })
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let genesis = ConsensusBoundary::genesis(self.chain_spec());
        self.store_mut().set_history_domain(&domain, &genesis)?;
        Ok(())
    }

    /// Prepare at most sixteen already-finalized child receipts without proving.
    pub fn prepare_history_fold(
        &self,
        start: u64,
        end: u64,
    ) -> Result<PreparedHistoryFold, FinalizeError<DB::Error>> {
        let count = end
            .checked_sub(start)
            .filter(|count| *count > 0 && *count <= MAX_FOLD_CHUNKS as u64)
            .ok_or(ProofError::InvalidWitness)?;
        let mut boundary = self.canonical_boundary(start)?;
        let target = self.canonical_boundary(end)?;
        let capacity = usize::try_from(count).map_err(|_| ProofError::InvalidWitness)?;
        let mut chunks = Vec::with_capacity(capacity);
        let mut statements = Vec::with_capacity(capacity);
        for id in start..end {
            let statement = self
                .store()
                .chunk_statement(id)?
                .ok_or(ProofError::InvalidWitness)?;
            let proof = self
                .store()
                .get_chunk_proof(id)?
                .ok_or(ProofError::InvalidWitness)?;
            if statement.start != boundary
                || statement.chunk != proof.public_inputs
                || statement.chunk.chunk_id != proof.chunk_id
                || neutrino_prover_chunk::consensus::as_chunk(&statement.chunk).hash()
                    != proof.chunk_hash
                || neutrino_prover_chunk::execution::commitment(&proof.finality_cert)
                    != statement.finality_cert_hash
            {
                return Err(ProofError::PublicInputMismatch.into());
            }
            boundary = statement.end;
            chunks.push(proof);
            statements.push(statement);
        }
        if boundary != target {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok(PreparedHistoryFold { chunks, statements })
    }

    /// Commit a token produced only by the real configured history verifier.
    /// Canonical endpoints are rechecked after any asynchronous proving/verification.
    pub fn commit_verified_history(
        &mut self,
        verified: VerifiedHistory,
    ) -> Result<HistoryImportOutcome, FinalizeError<DB::Error>> {
        let domain = *verified.domain();
        let proof = verified.into_proof();
        let statement = &proof.statement;
        if statement.domain != domain
            || statement.domain.chain != ChainBinding::from_spec(self.chain_spec())
            || self.store().history_domain()? != Some(statement.domain)
            || statement.covered_chunks().is_none()
            || self.canonical_boundary(statement.start.next_chunk_id)? != statement.start
            || self.canonical_boundary(statement.end.next_chunk_id)? != statement.end
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let advance = statement.start.next_chunk_id == 0
            && statement.end.next_chunk_id > self.recursive_covered_chunks();
        self.store_mut().commit_history_artifact(&proof, advance)?;
        if advance {
            self.install_recursive_coverage(statement.end.next_chunk_id);
        }
        Ok(HistoryImportOutcome {
            range_id: statement.range_id(),
            checkpoint_hash: statement.end_checkpoint().hash(),
            recursive_covered_chunks: self.recursive_covered_chunks(),
        })
    }

    /// Convenience synchronous import; node callers verify outside their engine lock.
    pub fn import_history_proof<P: ProofSystem>(
        &mut self,
        proof: &HistoryProof,
        prover: &P,
    ) -> Result<HistoryImportOutcome, FinalizeError<DB::Error>> {
        let verified = verify_history_proof(prover, self.chain_spec(), proof.clone())?;
        self.commit_verified_history(verified)
    }

    /// Latest verified genesis-prefix artifact, absent before the first proof.
    pub fn latest_history_proof(&self) -> Result<Option<HistoryProof>, FinalizeError<DB::Error>> {
        let count = self.recursive_covered_chunks();
        if count == 0 {
            return Ok(None);
        }
        self.store()
            .history_proof_for_range(0, count)?
            .ok_or(ProofError::InvalidWitness)
            .map(Some)
            .map_err(Into::into)
    }

    /// Resolve a fixed endpoint request without a scan or an untrusted count hint.
    pub fn history_endpoints(
        &self,
        start_hash: Hash,
        end_hash: Hash,
    ) -> Result<(Checkpoint, Checkpoint), FinalizeError<DB::Error>> {
        let start = self
            .store()
            .checkpoint_by_hash(&start_hash)?
            .ok_or(ProofError::InvalidWitness)?;
        let end = self
            .store()
            .checkpoint_by_hash(&end_hash)?
            .ok_or(ProofError::InvalidWitness)?;
        if start.domain != end.domain
            || self.store().history_domain()? != Some(start.domain)
            || start.boundary.next_chunk_id >= end.boundary.next_chunk_id
            || self.canonical_boundary(start.boundary.next_chunk_id)? != start.boundary
            || self.canonical_boundary(end.boundary.next_chunk_id)? != end.boundary
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok((start, end))
    }

    /// Read an exact retained range; absence never weakens the requested anchor.
    pub fn history_proof_by_endpoints(
        &self,
        start: Hash,
        end: Hash,
    ) -> Result<Option<HistoryProof>, FinalizeError<DB::Error>> {
        let (start, end) = self.history_endpoints(start, end)?;
        self.store()
            .history_proof_for_range(start.boundary.next_chunk_id, end.boundary.next_chunk_id)
            .map_err(Into::into)
    }
}
