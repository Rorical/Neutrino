//! Authentication, durable publication and order-independent source replay.

use crate::{Engine, StoreError};
use neutrino_consensus_types::signed_artifacts::SignedArtifact;
use neutrino_consensus_types::{BlockProof, FinalityVote, QuorumCertificate, SlashingEvidence};
use neutrino_primitives::Hash;
use neutrino_prover_chunk::bls::Verifier as _;
use neutrino_storage::Database;

impl<DB: Database> Engine<DB> {
    pub(crate) fn verify_bft_nil_conflict(
        &self,
        index: u32,
        value: &neutrino_consensus_types::IndexedVote,
        nil: &neutrino_consensus_types::IndexedNilVote,
    ) -> Result<(), crate::SlashingError> {
        neutrino_prover_chunk::slashing::verify_conflicting_nil_vote_using(
            self.chain_spec().consensus_domain(),
            &self.accountability_validators(value.data.chunk_id)?,
            index,
            value,
            nil,
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| crate::SlashingError::EvidenceFieldsInconsistent)
    }

    pub(crate) fn verify_bft_leader_conflict(
        &self,
        index: u32,
        first: &neutrino_consensus_types::BftProposal,
        second: &neutrino_consensus_types::BftProposal,
    ) -> Result<(), crate::SlashingError> {
        neutrino_prover_chunk::slashing::verify_double_bft_proposal_using(
            self.chain_spec().consensus_domain(),
            &self.accountability_validators(first.chunk.chunk_id)?,
            index,
            first,
            second,
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| crate::SlashingError::EvidenceFieldsInconsistent)
    }

    /// Authenticate every vote/attestation equation and persist the exact envelope.
    /// Invalid unlock declarations remain available for objective attribution.
    pub fn retain_signed_vote(
        &mut self,
        vote: &FinalityVote,
    ) -> Result<Hash, StoreError<DB::Error>> {
        self.authenticate_artifact_vote(vote)?;
        self.prune_availability_sources()?;
        self.store_mut()
            .put_signed_artifact(vote.data.chunk_id, &SignedArtifact::Vote(vote.clone()))
    }

    /// Persist the local completed vote in capacity reserved from peer artifacts.
    pub fn retain_local_signed_vote(
        &mut self,
        vote: &FinalityVote,
    ) -> Result<Hash, StoreError<DB::Error>> {
        self.authenticate_artifact_vote(vote)?;
        self.prune_availability_sources()?;
        self.retain_signed_artifact(&SignedArtifact::Vote(vote.clone()), true)
    }

    fn authenticate_artifact_vote(&self, vote: &FinalityVote) -> Result<(), StoreError<DB::Error>> {
        let validators = self
            .accountability_validators(vote.data.chunk_id)
            .map_err(|_| StoreError::Corrupt("artifact source outside authenticated context"))?;
        neutrino_prover_chunk::finality::verify_vote_signatures_using(
            self.chain_spec().consensus_domain(),
            &validators,
            vote,
            &self.chain_spec().consensus,
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| StoreError::Corrupt("artifact vote authentication"))
    }

    /// Persist an independently verified lock quorum under the authenticated source set.
    pub fn retain_signed_quorum(
        &mut self,
        quorum: &QuorumCertificate,
    ) -> Result<Hash, StoreError<DB::Error>> {
        self.authenticate_artifact_quorum(quorum)?;
        self.prune_availability_sources()?;
        self.store_mut().put_signed_artifact(
            quorum.data.chunk_id,
            &SignedArtifact::Quorum(quorum.clone()),
        )
    }

    fn authenticate_artifact_quorum(
        &self,
        quorum: &QuorumCertificate,
    ) -> Result<(), StoreError<DB::Error>> {
        let validators = self
            .accountability_validators(quorum.data.chunk_id)
            .map_err(|_| StoreError::Corrupt("quorum source outside authenticated context"))?;
        let params = &self.chain_spec().consensus;
        neutrino_prover_chunk::slashing::verify_quorum_using(
            self.chain_spec().consensus_domain(),
            &validators,
            quorum,
            (
                params.bft_prevote_quorum_numerator,
                params.bft_prevote_quorum_denominator,
            ),
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| StoreError::Corrupt("artifact quorum authentication"))
    }

    /// Persist exact proof bytes only after binding every public input to a locally
    /// authenticated header and historical membership. The caller separately
    /// classifies proof validity; a stored source is not a proof acceptance token.
    pub fn retain_signed_proof(
        &mut self,
        proof: &BlockProof,
    ) -> Result<Hash, StoreError<DB::Error>> {
        let source = self.authenticate_artifact_proof(proof)?;
        let artifact = SignedArtifact::BlockProof(proof.clone());
        self.prune_availability_sources()?;
        self.store_mut().put_signed_artifact(source, &artifact)
    }

    /// Recheck source context and signatures before admitting an availability hint.
    /// A block source is bound to authenticated inputs, without accepting its proof.
    pub fn validate_signed_artifact(&self, artifact: &SignedArtifact) -> bool {
        match artifact {
            SignedArtifact::Vote(vote) => self.authenticate_artifact_vote(vote).is_ok(),
            SignedArtifact::Quorum(quorum) => self.authenticate_artifact_quorum(quorum).is_ok(),
            SignedArtifact::BlockProof(proof) => self.authenticate_artifact_proof(proof).is_ok(),
            other => self.authenticate_bft_source(other),
        }
    }

    /// Verify and persist a current signed source; local publication has reserved capacity.
    pub fn retain_signed_artifact(
        &mut self,
        artifact: &SignedArtifact,
        local: bool,
    ) -> Result<Hash, StoreError<DB::Error>> {
        if !self.validate_signed_artifact(artifact) {
            return Err(StoreError::Corrupt("signed source authentication"));
        }
        let chunk = artifact
            .chunk_id(self.chain_spec().consensus.chunk_size)
            .ok_or(StoreError::Corrupt("signed source range"))?;
        self.prune_availability_sources()?;
        if local {
            let mut protected = self.protected_local_artifacts(chunk)?;
            if let SignedArtifact::Vote(value) = artifact {
                for claim in &value.attestations {
                    if let Some(quorum) = &claim.unlock_quorum
                        && self.authenticate_artifact_quorum(quorum).is_ok()
                    {
                        let dependency = SignedArtifact::Quorum(quorum.clone());
                        self.store_mut().put_local_signed_artifact_protected(
                            chunk,
                            &dependency,
                            &protected,
                        )?;
                        protected.push(dependency.id());
                    }
                }
            }
            self.store_mut()
                .put_local_signed_artifact_protected(chunk, artifact, &protected)
        } else {
            self.store_mut().put_signed_artifact(chunk, artifact)
        }
    }

    fn protected_local_artifacts(&self, chunk: u64) -> Result<Vec<Hash>, StoreError<DB::Error>> {
        let Some(session) = self.bft_session(chunk) else {
            return Ok(Vec::new());
        };
        let lock = session.highest_lock_quorum();
        let valid = session.highest_valid_quorum();
        let mut ids: Vec<_> = lock
            .into_iter()
            .chain(valid)
            .map(|quorum| SignedArtifact::Quorum(quorum.clone()).id())
            .collect();
        if let Some(lock) = lock {
            for item in self.store().signed_artifact_metadata_for_chunk(chunk)? {
                if item.chunk_id == chunk
                    && item.local
                    && item.kind
                        == neutrino_consensus_types::signed_artifacts::SignedArtifactKind::Vote
                    && item.phase == Some(neutrino_consensus_types::FinalityVotePhase::Precommit)
                    && item.round == Some(lock.data.round)
                    && item.target == Some(lock.data.chunk_hash)
                {
                    ids.push(item.id);
                }
            }
        }
        Ok(ids)
    }

    fn authenticate_bft_source(&self, artifact: &SignedArtifact) -> bool {
        let Some(chunk) = artifact.chunk_id(self.chain_spec().consensus.chunk_size) else {
            return false;
        };
        let Ok(validators) = self.accountability_validators(chunk) else {
            return false;
        };
        let params = &self.chain_spec().consensus;
        let fraction = (
            params.bft_prevote_quorum_numerator,
            params.bft_prevote_quorum_denominator,
        );
        let mut verifier = self.bls_verifier.borrow_mut();
        let domain = self.chain_spec().consensus_domain();
        match artifact {
            SignedArtifact::Proposal(value) => {
                neutrino_consensus_types::bft_leader(
                    domain.chain_id,
                    chunk,
                    value.round,
                    &validators,
                ) == Some(value.proposer_index)
                    && value.chunk.active_validator_set_root
                        == neutrino_prover_chunk::execution::commitment(&validators)
                    && validators
                        .get(value.proposer_index as usize)
                        .is_some_and(|validator| {
                            verifier.verify(
                                &validator.pubkey,
                                &value.signing_message(domain),
                                &value.signature,
                            )
                        })
            }
            SignedArtifact::NilVote(value) => neutrino_prover_chunk::bft::verify_nil_vote_using(
                domain,
                &validators,
                value,
                &mut *verifier,
            )
            .is_ok(),
            SignedArtifact::RoundChange(value) => {
                neutrino_prover_chunk::bft::verify_round_change_using(
                    domain,
                    &validators,
                    value,
                    fraction,
                    &mut *verifier,
                )
                .is_ok()
            }
            SignedArtifact::RoundChangeCertificate(value) => {
                neutrino_prover_chunk::bft::verify_round_change_certificate_using(
                    domain,
                    &validators,
                    value,
                    fraction,
                    &mut *verifier,
                )
                .is_ok()
            }
            _ => false,
        }
    }

    fn authenticate_artifact_proof(
        &self,
        proof: &BlockProof,
    ) -> Result<u64, StoreError<DB::Error>> {
        let artifact = SignedArtifact::BlockProof(proof.clone());
        let source = artifact
            .chunk_id(self.chain_spec().consensus.chunk_size)
            .ok_or(StoreError::Corrupt("artifact proof range"))?;
        let validators = self
            .accountability_validators(source)
            .map_err(|_| StoreError::Corrupt("artifact proof source"))?;
        let header = self
            .store()
            .get_header(&proof.block_hash)?
            .ok_or(StoreError::Corrupt("artifact proof header unavailable"))?;
        if header.height != proof.height || header.hash() != proof.block_hash {
            return Err(StoreError::Corrupt("artifact proof header mismatch"));
        }
        let before = if header.parent_hash == self.chain_spec().genesis_block_hash {
            self.chain_spec().genesis_state_root
        } else {
            self.store()
                .get_header(&header.parent_hash)?
                .ok_or(StoreError::Corrupt("artifact proof parent unavailable"))?
                .state_root
        };
        let mut expected = self.block_proof_public_inputs(&header, before, proof.block_hash);
        expected.proposer_address = validators
            .get(header.proposer_index as usize)
            .ok_or(StoreError::Corrupt("artifact proof proposer"))?
            .withdrawal_credentials;
        if proof.public_inputs != expected {
            return Err(StoreError::Corrupt("artifact proof public inputs mismatch"));
        }
        Ok(source)
    }

    /// Observe authenticated sources; only related same-chunk future votes are
    /// revisited when a delayed prior precommit or locking quorum arrives.
    pub fn observe_signed_artifact(
        &mut self,
        artifact: &SignedArtifact,
    ) -> Result<Vec<SlashingEvidence>, StoreError<DB::Error>> {
        if !self.validate_signed_artifact(artifact) {
            return Err(StoreError::Corrupt("signed source replay authentication"));
        }
        let restore_precommit = self.introduces_quorum(artifact);
        let mut evidence = self.observe_source(artifact);
        let Some((chunk, round, signers)) = Self::replay_dependency(artifact) else {
            return Ok(evidence);
        };
        let id = artifact.id();
        let mut metadata = self.store().signed_artifact_metadata_for_chunk(chunk)?;
        metadata.sort_by_key(|item| (item.round, item.phase));
        for item in metadata.into_iter().filter(|item| {
            item.kind == neutrino_consensus_types::signed_artifacts::SignedArtifactKind::Vote
                && item.id != id
                && item.round.is_some_and(|later| {
                    later > round
                        || (restore_precommit
                            && later == round
                            && item.phase
                                == Some(neutrino_consensus_types::FinalityVotePhase::Precommit))
                })
                && (signers.is_empty()
                    || item.signers.iter().any(|signer| signers.contains(signer)))
        }) {
            if let Some((_, related)) = self.store().signed_artifact(&item.id)?
                && self.validate_signed_artifact(&related)
            {
                evidence.extend(self.observe_source(&related));
            }
        }
        Ok(evidence)
    }

    fn introduces_quorum(&self, artifact: &SignedArtifact) -> bool {
        match artifact {
            SignedArtifact::Vote(value) => value
                .attestations
                .iter()
                .filter_map(|claim| claim.unlock_quorum.as_ref())
                .any(|quorum| !self.slashing_monitor.prevote_quorum_is_observed(quorum)),
            SignedArtifact::Quorum(value) => {
                !self.slashing_monitor.prevote_quorum_is_observed(value)
            }
            SignedArtifact::Proposal(value) => value
                .valid_quorum
                .as_ref()
                .is_some_and(|quorum| !self.slashing_monitor.prevote_quorum_is_observed(quorum)),
            SignedArtifact::RoundChange(value) => value
                .highest_quorum
                .as_ref()
                .is_some_and(|quorum| !self.slashing_monitor.prevote_quorum_is_observed(quorum)),
            SignedArtifact::RoundChangeCertificate(value) => value
                .reports
                .iter()
                .filter_map(|report| report.highest_quorum.as_ref())
                .any(|quorum| !self.slashing_monitor.prevote_quorum_is_observed(quorum)),
            _ => false,
        }
    }

    fn replay_dependency(artifact: &SignedArtifact) -> Option<(u64, u32, Vec<u32>)> {
        Some(match artifact {
            SignedArtifact::Vote(value) => {
                let carried = value
                    .attestations
                    .iter()
                    .filter_map(|claim| {
                        claim.unlock_quorum.as_ref().map(|quorum| quorum.data.round)
                    })
                    .min();
                if value.data.phase == neutrino_consensus_types::FinalityVotePhase::Prevote
                    && carried.is_none()
                {
                    return None;
                }
                let round = carried.map_or(value.data.round, |round| round.min(value.data.round));
                (
                    value.data.chunk_id,
                    round,
                    if carried.is_some() {
                        Vec::new()
                    } else {
                        value
                            .attestations
                            .iter()
                            .map(|claim| claim.validator_index)
                            .collect()
                    },
                )
            }
            SignedArtifact::Quorum(value) => (value.data.chunk_id, value.data.round, Vec::new()),
            SignedArtifact::RoundChange(value) => (
                value.chunk_id,
                value.highest_quorum.as_ref()?.data.round,
                Vec::new(),
            ),
            SignedArtifact::RoundChangeCertificate(value) => {
                let round = value
                    .reports
                    .iter()
                    .filter_map(|report| {
                        report
                            .highest_quorum
                            .as_ref()
                            .map(|quorum| quorum.data.round)
                    })
                    .min()?;
                (value.chunk_id, round, Vec::new())
            }
            SignedArtifact::Proposal(value) => (
                value.chunk.chunk_id,
                value.valid_quorum.as_ref()?.data.round,
                Vec::new(),
            ),
            _ => return None,
        })
    }

    fn observe_source(&mut self, artifact: &SignedArtifact) -> Vec<SlashingEvidence> {
        match artifact {
            SignedArtifact::Vote(value) => {
                for claim in &value.attestations {
                    if let Some(quorum) = &claim.unlock_quorum
                        && self.authenticate_artifact_quorum(quorum).is_ok()
                    {
                        self.slashing_monitor.record_prevote_quorum(quorum.clone());
                    }
                }
                self.observe_votes_for_slashing(value).unwrap_or_default()
            }
            SignedArtifact::Quorum(value) => {
                self.slashing_monitor.record_prevote_quorum(value.clone());
                Vec::new()
            }
            SignedArtifact::NilVote(value) => self.slashing_monitor.record_nil_vote(value),
            SignedArtifact::Proposal(value) => {
                if let Some(quorum) = &value.valid_quorum
                    && self.authenticate_artifact_quorum(quorum).is_ok()
                {
                    self.slashing_monitor.record_prevote_quorum(quorum.clone());
                }
                self.slashing_monitor
                    .record_bft_proposal(value)
                    .into_iter()
                    .collect()
            }
            SignedArtifact::RoundChange(value) => {
                if let Some(quorum) = &value.highest_quorum {
                    self.slashing_monitor.record_prevote_quorum(quorum.clone());
                }
                Vec::new()
            }
            SignedArtifact::RoundChangeCertificate(value) => {
                for report in &value.reports {
                    if let Some(quorum) = &report.highest_quorum {
                        self.slashing_monitor.record_prevote_quorum(quorum.clone());
                    }
                }
                Vec::new()
            }
            SignedArtifact::BlockProof(_) => Vec::new(),
        }
    }

    /// Native authenticated nil attribution before consensus target/round filtering.
    pub fn observe_nil_votes_for_slashing(
        &mut self,
        vote: &neutrino_consensus_types::NilVote,
    ) -> Result<Vec<SlashingEvidence>, crate::SlashingError> {
        let artifact = SignedArtifact::NilVote(vote.clone());
        if !self.validate_signed_artifact(&artifact) {
            return Err(crate::SlashingError::BadSignature);
        }
        Ok(self.observe_source(&artifact))
    }

    /// Authenticate leader signatures without allowing an invalid carried QC to hide
    /// a same-round independently signed conflicting proposal.
    pub fn observe_bft_proposal_for_slashing(
        &mut self,
        proposal: &neutrino_consensus_types::BftProposal,
    ) -> Result<Vec<SlashingEvidence>, crate::SlashingError> {
        let artifact = SignedArtifact::Proposal(Box::new(proposal.clone()));
        if !self.validate_signed_artifact(&artifact) {
            return Err(crate::SlashingError::BadSignature);
        }
        Ok(self.observe_source(&artifact))
    }

    /// One restart replay restores quorum dependencies before round-ordered signed
    /// votes; no cached verdict bypasses current historical membership checks.
    pub fn replay_signed_artifacts(
        &mut self,
    ) -> Result<Vec<SlashingEvidence>, StoreError<DB::Error>> {
        let mut metadata = self.store().active_signed_artifact_metadata()?;
        metadata.sort_by_key(|item| {
            (
                item.kind != neutrino_consensus_types::signed_artifacts::SignedArtifactKind::Quorum,
                item.chunk_id,
                item.round,
            )
        });
        let mut evidence = Vec::new();
        for item in metadata {
            if item.kind
                == neutrino_consensus_types::signed_artifacts::SignedArtifactKind::BlockProof
            {
                continue;
            }
            if let Some((_, artifact)) = self.store().signed_artifact(&item.id)?
                && self.validate_signed_artifact(&artifact)
            {
                evidence.extend(self.observe_source(&artifact));
            }
        }
        Ok(evidence)
    }

    /// Prune only from local finality and persisted recursive coverage; archive nodes
    /// retain source data. Saturation returns an explicit publication error.
    pub fn prune_availability_sources(&mut self) -> Result<(), StoreError<DB::Error>> {
        let floor = self
            .finalized_next_chunk_id()
            .saturating_sub(neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS)
            .min(self.recursive_covered_chunks());
        self.store_mut().prune_signed_artifacts(floor)
    }
}
