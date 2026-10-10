//! Selective, durable forensic discovery without widening live BFT history admission.

use crate::availability::carried_quorums;
use crate::{Engine, RetentionPolicy, SlashingError, SlashingMonitor, StoreError};
use neutrino_consensus_types::signed_artifacts::SignedArtifact;
use neutrino_consensus_types::{
    FinalityVotePhase, Header, IndexedVote, QuorumCertificate, SlashingEvidence,
};
use neutrino_primitives::{BlsPublicKey, Seed, Validator};
use neutrino_storage::Database;

/// Historical BLS identity and the withdrawal address whose slashable balance is queried.
pub type ReporterIdentity = (BlsPublicKey, [u8; 32]);

impl<DB: Database> Engine<DB> {
    /// Conservatively add authenticated active memberships before an economic query can fail.
    pub fn seed_reporter_tracking(&mut self) -> Result<(), StoreError<DB::Error>> {
        let identities: Vec<_> = self
            .active_validator_set()
            .iter()
            .filter(|v| !v.slashed && v.effective_stake > 0)
            .map(|v| (v.pubkey, v.withdrawal_credentials))
            .collect();
        self.store_mut().seed_reporter_tracking(&identities)
    }

    /// Durable watched identities plus current active memberships awaiting economic classification.
    pub fn reporter_tracked_validators(
        &self,
    ) -> Result<Vec<ReporterIdentity>, StoreError<DB::Error>> {
        let mut result = self.store().reporter_tracked_validators()?;
        result.extend(
            self.active_validator_set()
                .iter()
                .filter(|v| !v.slashed && v.effective_stake > 0)
                .map(|v| (v.pubkey, v.withdrawal_credentials)),
        );
        result.sort_unstable();
        result.dedup();
        Ok(result)
    }

    /// Update material ownership using only the caller's finalized runtime economic query.
    pub fn set_reporter_eligible(
        &mut self,
        identities: &[(BlsPublicKey, [u8; 32])],
    ) -> Result<Vec<neutrino_primitives::Hash>, StoreError<DB::Error>> {
        self.store_mut().set_reporter_eligible(identities)
    }

    /// A reporter with saved evidence must synchronize continuously rather than skip append data.
    pub fn reporter_has_history(&self) -> Result<bool, StoreError<DB::Error>> {
        self.store().reporter_has_history()
    }

    pub(crate) fn forensic_context(
        &self,
        chunk: u64,
    ) -> Result<(Vec<Validator>, Seed), SlashingError> {
        if let Ok(context) = self.accountability_context(chunk) {
            return Ok(context);
        }
        if self
            .retention_info()
            .map_err(|_| SlashingError::NotYetFinalizedLocally)?
            .policy
            != RetentionPolicy::Reporter
        {
            return Err(SlashingError::SourceOutsideAccountabilityWindow);
        }
        let opening = self
            .store()
            .reporter_opening(chunk)
            .map_err(|_| SlashingError::NotYetFinalizedLocally)?
            .or_else(|| {
                self.store()
                    .historical_opening(chunk, self.finalized_next_chunk_id())
                    .ok()
            })
            .ok_or(SlashingError::SourceOutsideAccountabilityWindow)?;
        Ok((opening.record.validators, opening.record.seed))
    }

    pub(crate) fn forensic_validators(&self, chunk: u64) -> Result<Vec<Validator>, SlashingError> {
        self.forensic_context(chunk)
            .map(|(validators, _)| validators)
    }

    pub(crate) fn forensic_header_context(
        &self,
        header: &Header,
    ) -> Result<(Vec<Validator>, Seed), SlashingError> {
        let chunk = self
            .chunk_of_height(header.height)
            .ok_or(SlashingError::EvidenceFieldsInconsistent)?;
        let context = self.forensic_context(chunk)?;
        let validator = context
            .0
            .get(header.proposer_index as usize)
            .ok_or(SlashingError::EvidenceFieldsInconsistent)?;
        if validator.slashed || validator.effective_stake == 0 {
            return Err(SlashingError::EvidenceFieldsInconsistent);
        }
        Ok(context)
    }

    /// Rebuild a watched chunk from durable sources, restoring all quorum dependencies first.
    pub(crate) fn observe_reporter_artifact(
        &self,
        chunk: u64,
        extra: Option<&SignedArtifact>,
    ) -> Result<Vec<SlashingEvidence>, StoreError<DB::Error>> {
        let mut sources = self.store().reporter_sources_for_chunk(chunk)?;
        if let Some(record) = self.store().historical_chunk(chunk)? {
            sources.push(SignedArtifact::Proposal(Box::new(
                record.finality.proposal.clone(),
            )));
            sources.push(SignedArtifact::Vote(record.finality.prevote_vote()));
            sources.push(SignedArtifact::Vote(record.finality.precommit_vote()));
        }
        if let Some(artifact) = extra {
            sources.push(artifact.clone());
        }
        sources.retain(|artifact| self.validate_signed_artifact(artifact));
        sources.sort_by_key(|source| match source {
            SignedArtifact::Vote(vote) => (vote.data.round, 1u8),
            SignedArtifact::NilVote(vote) => (vote.data.round, 2),
            SignedArtifact::Proposal(value) => (value.round, 3),
            _ => (0, 0),
        });
        let mut monitor = SlashingMonitor::for_reporter();
        for source in &sources {
            self.reporter_quorums(&mut monitor, source);
        }
        let mut evidence = Vec::new();
        for source in &sources {
            match source {
                SignedArtifact::Vote(vote) => {
                    for claim in &vote.attestations {
                        monitor.record_attestation(claim.clone());
                        let indexed = IndexedVote {
                            data: claim.vote.clone(),
                            signature: claim.vote_signature,
                        };
                        evidence
                            .extend(monitor.record_indexed_vote(claim.validator_index, &indexed));
                    }
                }
                SignedArtifact::NilVote(vote) => evidence.extend(monitor.record_nil_vote(vote)),
                SignedArtifact::Proposal(value) => {
                    evidence.extend(monitor.record_bft_proposal(value));
                }
                _ => {}
            }
        }
        let mut headers = self.store().reporter_headers_for_chunk(chunk)?;
        headers.sort_by_key(|header| (header.slot, header.hash()));
        for header in headers {
            if self.chunk_of_height(header.height) != Some(chunk) {
                continue;
            }
            if let Ok((validators, seed)) = self.forensic_header_context(&header)
                && crate::signature::verify_header_signature(
                    &header,
                    &validators,
                    self.consensus_domain(),
                )
                .is_ok()
            {
                evidence.extend(monitor.record_header(chunk, &header));
                if let Err(error) = neutrino_consensus_vrf::verify_header_proposer(
                    &header,
                    &validators,
                    self.consensus_domain(),
                    &seed,
                    self.chain_spec().consensus.expected_proposers_per_slot,
                ) && let Some(reason) = crate::vrf_rejection_reason(&error)
                {
                    evidence.push(self.invalid_vrf_evidence(&header, reason));
                }
            }
        }
        let validators = self
            .forensic_validators(chunk)
            .map_err(|_| StoreError::Corrupt("reporter source context"))?;
        let eligible: Vec<_> = self
            .store()
            .reporter_tracked_validators()?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        evidence.retain(|claim| {
            validators
                .get(claim.offender_index() as usize)
                .is_some_and(|v| eligible.contains(&v.pubkey))
                && self.verify_slashing_evidence(claim).is_ok()
        });
        Ok(evidence)
    }

    fn reporter_quorums(&self, monitor: &mut SlashingMonitor, artifact: &SignedArtifact) {
        let mut record = |quorum: &QuorumCertificate| {
            let validators = self
                .forensic_validators(quorum.data.chunk_id)
                .unwrap_or_default();
            let params = &self.chain_spec().consensus;
            if neutrino_prover_chunk::slashing::verify_quorum_using(
                self.consensus_domain(),
                &validators,
                quorum,
                (
                    params.bft_prevote_quorum_numerator,
                    params.bft_prevote_quorum_denominator,
                ),
                &mut *self.bls_verifier.borrow_mut(),
            )
            .is_ok()
            {
                monitor.record_prevote_quorum(quorum.clone());
            }
        };
        for quorum in carried_quorums(artifact) {
            record(quorum);
        }
        if let SignedArtifact::Vote(vote) = artifact
            && vote.data.phase == FinalityVotePhase::Prevote
        {
            // An aggregate is usable as a lock only if it independently meets quorum weight.
            let quorum = QuorumCertificate {
                data: vote.data.clone(),
                aggregate: neutrino_consensus_types::AggregatedVote {
                    aggregation_bits: vote.aggregation_bits.clone(),
                    signature: vote.signature,
                },
            };
            record(&quorum);
        }
    }

    /// Restore long-lived sources after restart without relying on the bounded live monitor.
    pub(crate) fn replay_reporter_sources(
        &self,
    ) -> Result<Vec<SlashingEvidence>, StoreError<DB::Error>> {
        let mut evidence = Vec::new();
        for chunk in self.store().reporter_history_chunks()? {
            evidence.extend(self.observe_reporter_artifact(chunk, None)?);
        }
        Ok(evidence)
    }
}
