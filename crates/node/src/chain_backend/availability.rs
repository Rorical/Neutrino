//! Original signed source availability and delayed offence detection.

use super::ChainBackend;
use neutrino_consensus_types::signed_artifacts::{
    SignedArtifact, SignedArtifactInventory, SignedArtifactKind, SignedArtifactRef,
};
use neutrino_consensus_types::{FinalityVote, SlashingEvidence};
use neutrino_network::{
    Topic,
    rpc::{SignedArtifactByIdResponse, SignedArtifactInventoryByChunkResponse},
    service::NetworkCommand,
};
use neutrino_primitives::{ChunkId, Hash};
use neutrino_proof_system::ProofSystem;
use neutrino_storage::Database;
use neutrino_sync::{EvidenceProofAcceptance, SyncBackendError};

type Rejection = neutrino_consensus_types::ProofRejectionReason;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::redundant_pub_crate)] // The parent evidence gate consumes exact verdicts.
pub(super) enum ProofVerdict {
    Valid,
    Rejected(Rejection),
}

impl From<Option<Rejection>> for ProofVerdict {
    fn from(reason: Option<Rejection>) -> Self {
        reason.map_or(Self::Valid, Self::Rejected)
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct VerdictKey {
    program: [u32; 8],
    chain_spec: Hash,
    source: Hash,
}

#[derive(Clone, Copy)]
#[allow(clippy::redundant_pub_crate)] // Shared with the parent import/bootstrap modules.
pub(super) struct VerdictToken {
    program: Option<[u32; 8]>,
    chain_spec: Hash,
    source: Hash,
    generation: u64,
}

#[derive(Default)]
#[allow(clippy::redundant_pub_crate)] // Stored by the parent backend, used by sibling modules.
pub(super) struct VerdictCache {
    generation: u64,
    entries: std::collections::BTreeMap<VerdictKey, ProofVerdict>,
}

impl VerdictCache {
    fn get(
        &self,
        token: VerdictToken,
        program: Option<[u32; 8]>,
        chain_spec: Hash,
    ) -> Option<ProofVerdict> {
        if !self.token_is_current(token, program, chain_spec) {
            return None;
        }
        self.entries
            .get(&VerdictKey {
                program: token.program?,
                chain_spec: token.chain_spec,
                source: token.source,
            })
            .copied()
    }

    fn remember(
        &mut self,
        token: VerdictToken,
        program: Option<[u32; 8]>,
        chain_spec: Hash,
        verdict: ProofVerdict,
    ) -> bool {
        if !self.token_is_current(token, program, chain_spec) {
            return false;
        }
        let Some(program) = token.program else {
            return true;
        };
        let key = VerdictKey {
            program,
            chain_spec,
            source: token.source,
        };
        if self.entries.len() >= 4096
            && let Some(oldest) = self.entries.keys().next().copied()
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(key, verdict);
        true
    }

    fn token_is_current(
        &self,
        token: VerdictToken,
        program: Option<[u32; 8]>,
        chain_spec: Hash,
    ) -> bool {
        token.generation == self.generation
            && token.program == program
            && token.chain_spec == chain_spec
    }

    fn reset(&mut self) {
        self.generation = self
            .generation
            .checked_add(1)
            .expect("proof verdict cache generation overflow");
        self.entries.clear();
    }
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(super) fn begin_block_verdict(&self, source: Hash) -> VerdictToken {
        let program = self.proof_system.consensus_block_key();
        let chain_spec = self.with_engine(|engine| engine.chain_spec().hash());
        let generation = self
            .availability_verdicts
            .lock()
            .expect("availability verdict cache")
            .generation;
        VerdictToken {
            program,
            chain_spec,
            source,
            generation,
        }
    }

    pub(super) fn cached_block_verdict(&self, source: Hash) -> Option<ProofVerdict> {
        let token = self.begin_block_verdict(source);
        self.cached_block_verdict_at(token)
    }

    pub(super) fn cached_block_verdict_at(&self, token: VerdictToken) -> Option<ProofVerdict> {
        let program = self.proof_system.consensus_block_key();
        let chain_spec = self.with_engine(|engine| engine.chain_spec().hash());
        // Scope reads release the Engine lock before taking the cache lock.
        // Bootstrap holds Engine while invalidating this generation, so a reset
        // between these reads and lookup cannot return a prior trust verdict.
        self.availability_verdicts
            .lock()
            .expect("availability verdict cache")
            .get(token, program, chain_spec)
    }

    pub(super) fn remember_block_verdict(
        &self,
        token: VerdictToken,
        verdict: ProofVerdict,
    ) -> bool {
        let program = self.proof_system.consensus_block_key();
        let chain_spec = self.with_engine(|engine| engine.chain_spec().hash());
        self.availability_verdicts
            .lock()
            .expect("availability verdict cache")
            .remember(token, program, chain_spec, verdict)
    }

    pub(super) fn reset_block_verdicts(&self) {
        self.availability_verdicts
            .lock()
            .expect("availability verdict cache")
            .reset();
    }

    /// Source inventories never extend local history or move its pruning boundary.
    pub(super) fn availability_source_known(&self, chunk_id: ChunkId) -> bool {
        self.with_engine(|engine| {
            let next = engine.finalized_next_chunk_id();
            chunk_id == next
                || (neutrino_consensus_types::history::is_recent_history_index(chunk_id, next)
                    && engine
                        .store()
                        .historical_chunk(chunk_id)
                        .ok()
                        .flatten()
                        .is_some())
        })
    }

    /// Read one durable exact source, including bytes of rejected alternative proofs.
    pub(super) fn query_signed_artifact(
        &self,
        id: Hash,
    ) -> Result<SignedArtifactByIdResponse, SyncBackendError> {
        self.with_engine(|engine| {
            engine
                .store()
                .signed_artifact(&id)
                .map_err(|error| SyncBackendError::Storage(error.to_string()))?
                .map(|(_, artifact)| SignedArtifactByIdResponse { artifact })
                .ok_or_else(|| SyncBackendError::NotAvailable("signed source unavailable".into()))
        })
    }

    /// Stable bounded inventory; archive providers can also serve older source rows.
    pub(super) fn query_signed_inventory(
        &self,
        chunk_id: ChunkId,
        after: Option<Hash>,
    ) -> Result<SignedArtifactInventoryByChunkResponse, SyncBackendError> {
        self.with_engine(|engine| {
            engine
                .store()
                .signed_artifact_inventory(chunk_id, after)
                .map_err(|error| SyncBackendError::Storage(error.to_string()))
        })
    }

    /// Persist before publishing and then replay delayed prior-lock dependencies.
    pub(super) async fn retain_availability_vote(&self, vote: &FinalityVote) -> bool {
        self.accept_signed_source(SignedArtifact::Vote(vote.clone()))
            .await
            == EvidenceProofAcceptance::Accepted
    }

    /// Authenticate fetched sources through the same signing and evidence boundaries.
    /// Storage exhaustion defers sources; it cannot make an invalid proof valid.
    pub(super) async fn accept_signed_source(
        &self,
        artifact: SignedArtifact,
    ) -> EvidenceProofAcceptance {
        use EvidenceProofAcceptance::{Accepted, Deferred, Rejected};
        if self.light_checkpoint().is_some() || self.bootstrap_pending() {
            return Deferred;
        }
        let Some(source) =
            self.with_engine(|engine| artifact.chunk_id(engine.chain_spec().consensus.chunk_size))
        else {
            return Rejected;
        };
        if !self.availability_source_known(source) {
            return Deferred;
        }
        if self
            .with_engine(|engine| {
                engine
                    .store()
                    .signed_artifact_metadata_by_id(&artifact.id())
            })
            .ok()
            .flatten()
            .is_some()
        {
            return Accepted;
        }
        if !self.with_engine(|engine| engine.validate_signed_artifact(&artifact)) {
            return Rejected;
        }
        if let SignedArtifact::BlockProof(proof) = &artifact
            && self.signed_proof_verdict(proof).await.is_none()
        {
            return Deferred;
        }
        let chunk =
            self.with_engine(|engine| artifact.chunk_id(engine.chain_spec().consensus.chunk_size));
        let Some(chunk_id) = chunk else {
            return Rejected;
        };
        let retained = self.with_engine_mut(|engine| match &artifact {
            SignedArtifact::Vote(vote) => engine.retain_signed_vote(vote),
            SignedArtifact::Quorum(quorum) => engine.retain_signed_quorum(quorum),
            SignedArtifact::BlockProof(proof) => engine.retain_signed_proof(proof),
            other => engine.retain_signed_artifact(other, false),
        });
        if retained.is_err() {
            return Deferred;
        }
        if let SignedArtifact::Vote(vote) = &artifact {
            for claim in &vote.attestations {
                if let Some(quorum) = &claim.unlock_quorum {
                    let _ = self.with_engine_mut(|engine| engine.retain_signed_quorum(quorum));
                }
            }
        }
        self.observe_signed_source_accountability(&artifact).await;
        self.publish_signed_inventory(chunk_id, vec![artifact.reference()])
            .await;
        Accepted
    }

    /// Retain the exact first accepted receipts before publishing this node's own
    /// proof-acceptance declaration. Availability does not delay received votes.
    pub(super) fn ensure_publishable_vote_sources(&self, vote: &FinalityVote) -> bool {
        if vote.data.phase != neutrino_consensus_types::FinalityVotePhase::Precommit {
            return true;
        }
        let own = self.local_voter().map(|key| key.validator_index());
        self.with_engine_mut(|engine| {
            let branch = Self::publication_candidate_hashes(engine, vote);
            for claim in vote
                .attestations
                .iter()
                .filter(|claim| Some(claim.validator_index) == own)
            {
                for (offset, expected) in claim.proof_hashes.iter().enumerate() {
                    if let Some((_, source)) =
                        engine.store().signed_artifact(expected).ok().flatten()
                    {
                        if engine.retain_signed_artifact(&source, true).is_err() {
                            return false;
                        }
                        continue;
                    }
                    let Some(height) = vote
                        .data
                        .chunk_id
                        .checked_mul(engine.chain_spec().consensus.chunk_size)
                        .and_then(|start| start.checked_add(u64::try_from(offset).ok()?))
                        .and_then(|height| height.checked_add(1))
                    else {
                        return false;
                    };
                    let Some(hash) = branch
                        .as_ref()
                        .and_then(|hashes| hashes.get(&height))
                        .copied()
                        .or_else(|| {
                            engine
                                .store()
                                .get_block_hash_by_height(height)
                                .ok()
                                .flatten()
                        })
                    else {
                        return false;
                    };
                    let Some(proof) = engine.store().get_block_proof(&hash).ok().flatten() else {
                        return false;
                    };
                    let source = SignedArtifact::BlockProof(proof);
                    if source.id() != *expected
                        || engine.retain_signed_artifact(&source, true).is_err()
                    {
                        return false;
                    }
                }
            }
            true
        })
    }

    fn publication_candidate_hashes(
        engine: &neutrino_consensus_engine::Engine<DB>,
        vote: &FinalityVote,
    ) -> Option<std::collections::BTreeMap<u64, Hash>> {
        let chunk = engine
            .bft_session(vote.data.chunk_id)?
            .candidate_by_hash(&vote.data.chunk_hash)?;
        let mut hash = chunk.end_block_hash;
        let mut hashes = std::collections::BTreeMap::new();
        for offset in 0..engine.chain_spec().consensus.chunk_size {
            let header = engine.store().get_header(&hash).ok().flatten()?;
            if header.height != chunk.end_height.checked_sub(offset)? {
                return None;
            }
            hashes.insert(header.height, hash);
            if header.height == chunk.start_height {
                return Some(hashes);
            }
            hash = header.parent_hash;
        }
        None
    }

    /// Retain signed pacemaker, proposal and nil artifacts before their publication.
    pub(super) async fn retain_availability_bft_message(
        &self,
        message: &neutrino_consensus_types::BftMessage,
        local: bool,
    ) -> bool {
        use neutrino_consensus_types::{BftMessage, BftVote};
        let artifact = match message {
            BftMessage::Proposal(value) => SignedArtifact::Proposal(value.clone()),
            BftMessage::Vote(BftVote::Value(value)) => SignedArtifact::Vote(value.clone()),
            BftMessage::Vote(BftVote::Nil(value)) => SignedArtifact::NilVote(value.clone()),
            BftMessage::RoundChange(value) => SignedArtifact::RoundChange(value.clone()),
            BftMessage::RoundChangeCertificate(value) => {
                SignedArtifact::RoundChangeCertificate(value.clone())
            }
        };
        if local {
            let chunk = self
                .with_engine(|engine| artifact.chunk_id(engine.chain_spec().consensus.chunk_size));
            if self
                .with_engine_mut(|engine| engine.retain_signed_artifact(&artifact, true))
                .is_err()
            {
                return false;
            }
            self.observe_signed_source_accountability(&artifact).await;
            if let Some(chunk) = chunk {
                self.publish_signed_inventory(chunk, vec![artifact.reference()])
                    .await;
            }
            true
        } else {
            self.accept_signed_source(artifact).await == EvidenceProofAcceptance::Accepted
        }
    }

    /// Cache only exact current-backend proof verdicts. Restart starts with an
    /// empty cache; operational failures never become rejection evidence.
    async fn signed_proof_verdict(
        &self,
        proof: &neutrino_consensus_types::BlockProof,
    ) -> Option<ProofVerdict> {
        let id = SignedArtifact::BlockProof(proof.clone()).id();
        let token = self.begin_block_verdict(id);
        if let Some(verdict) = self.cached_block_verdict_at(token) {
            return Some(verdict);
        }
        let prover = std::sync::Arc::clone(&self.proof_system);
        let proof = proof.clone();
        let verdict =
            tokio::task::spawn_blocking(move || match prover.classify_block_rejection(&proof) {
                Ok(verdict) => Some(ProofVerdict::from(verdict)),
                Err(_) => borsh::from_slice::<P::BlockProof>(&proof.proof_bytes)
                    .ok()
                    .filter(|decoded| prover.verify_block(decoded, &proof.public_inputs).is_ok())
                    .map(|_| ProofVerdict::Valid),
            })
            .await
            .ok()
            .flatten()?;
        self.remember_block_verdict(token, verdict)
            .then_some(verdict)
    }

    async fn detect_signed_proof_offences(
        &self,
        votes: Vec<FinalityVote>,
    ) -> Vec<SlashingEvidence> {
        let mut evidence = Vec::new();
        for vote in votes {
            for claim in &vote.attestations {
                for hash in &claim.proof_hashes {
                    if self.cached_block_verdict(*hash) == Some(ProofVerdict::Valid) {
                        continue;
                    }
                    let Some((_, SignedArtifact::BlockProof(proof))) = self
                        .with_engine(|engine| engine.store().signed_artifact(hash))
                        .ok()
                        .flatten()
                    else {
                        continue;
                    };
                    let Some(ProofVerdict::Rejected(reason)) =
                        self.signed_proof_verdict(&proof).await
                    else {
                        continue;
                    };
                    let indexed = neutrino_consensus_types::IndexedVote {
                        data: claim.vote.clone(),
                        signature: claim.vote_signature,
                    };
                    let item = SlashingEvidence::InvalidProofSigning {
                        validator_index: claim.validator_index,
                        vote: indexed,
                        attestation: claim.clone(),
                        rejected_proof: proof,
                        reason,
                    };
                    if self
                        .with_engine(|engine| engine.verify_slashing_evidence(&item))
                        .is_ok()
                    {
                        evidence.push(item);
                    }
                }
            }
        }
        evidence
    }

    async fn observe_signed_source_accountability(&self, artifact: &SignedArtifact) {
        let mut evidence = self
            .with_engine_mut(|engine| engine.observe_signed_artifact(artifact))
            .unwrap_or_default();
        let votes = match artifact {
            SignedArtifact::Vote(vote) => vec![vote.clone()],
            SignedArtifact::BlockProof(_) => {
                let id = artifact.id();
                let metadata = self
                    .with_engine(|engine| {
                        let chunk = artifact
                            .chunk_id(engine.chain_spec().consensus.chunk_size)
                            .ok_or(neutrino_consensus_engine::StoreError::Corrupt(
                                "proof source range",
                            ))?;
                        engine.store().signed_artifact_metadata_for_chunk(chunk)
                    })
                    .unwrap_or_default();
                let mut votes = Vec::new();
                for item in metadata.into_iter().filter(|item| {
                    item.kind == SignedArtifactKind::Vote && item.proof_hashes.contains(&id)
                }) {
                    if let Some((_, SignedArtifact::Vote(vote))) = self
                        .with_engine(|engine| engine.store().signed_artifact(&item.id))
                        .ok()
                        .flatten()
                    {
                        votes.push(vote);
                    }
                }
                votes
            }
            _ => Vec::new(),
        };
        evidence.extend(self.detect_signed_proof_offences(votes).await);
        for item in evidence {
            self.pool_and_gossip_slashing(item).await;
        }
    }

    /// One startup replay restores authenticated observations and reports every
    /// retained dependency-complete offence through ordinary pool verification.
    pub(super) async fn replay_signed_artifact_accountability(&self) {
        let mut evidence = self
            .with_engine_mut(neutrino_consensus_engine::Engine::replay_signed_artifacts)
            .unwrap_or_default();
        let metadata = self
            .with_engine(|engine| engine.store().active_signed_artifact_metadata())
            .unwrap_or_default();
        let mut votes = Vec::new();
        for item in metadata
            .into_iter()
            .filter(|item| item.kind == SignedArtifactKind::Vote)
        {
            if let Some((_, SignedArtifact::Vote(vote))) = self
                .with_engine(|engine| engine.store().signed_artifact(&item.id))
                .ok()
                .flatten()
            {
                votes.push(vote);
            }
        }
        evidence.extend(self.detect_signed_proof_offences(votes).await);
        for item in evidence {
            self.pool_and_gossip_slashing(item).await;
        }
    }

    /// Consume the ordinary import verdict without verifying accepted receipts twice.
    /// Invalid imports still need the backend's exact objective rejection classifier.
    pub(super) async fn retain_imported_proof_source(
        &self,
        proof: &neutrino_consensus_types::BlockProof,
        accepted: bool,
        token: VerdictToken,
    ) {
        let id = SignedArtifact::BlockProof(proof.clone()).id();
        if token.source != id
            || (accepted && !self.remember_block_verdict(token, ProofVerdict::Valid))
        {
            return;
        }
        let _ = self
            .accept_signed_source(SignedArtifact::BlockProof(proof.clone()))
            .await;
        if accepted {
            self.compact_available_proof(proof);
        }
    }

    /// Exact pointer replacement after accepted receipt import avoids duplicating
    /// valid compressed proofs in the detached accountability source store.
    pub(super) fn compact_available_proof(&self, proof: &neutrino_consensus_types::BlockProof) {
        let _ = self.with_engine_mut(|engine| engine.store_mut().compact_accepted_artifact(proof));
    }

    /// Exact missing proof identities from authenticated declarations, bounded before
    /// driver admission. Earlier vote/lock sources are discovered by chunk inventory.
    pub(super) fn missing_signed_artifacts(&self, vote: &FinalityVote) -> Vec<SignedArtifactRef> {
        if !self.with_engine(|engine| {
            engine.validate_signed_artifact(&SignedArtifact::Vote(vote.clone()))
        }) {
            return Vec::new();
        }
        let mut missing = Vec::new();
        for claim in &vote.attestations {
            for id in &claim.proof_hashes {
                if missing.len() >= 128 {
                    return missing;
                }
                if !missing
                    .iter()
                    .any(|reference: &SignedArtifactRef| reference.id == *id)
                    && self
                        .with_engine(|engine| engine.store().signed_artifact_metadata_by_id(id))
                        .ok()
                        .flatten()
                        .is_none()
                {
                    missing.push(SignedArtifactRef {
                        id: *id,
                        kind: SignedArtifactKind::BlockProof,
                    });
                }
            }
        }
        missing
    }

    async fn publish_signed_inventory(
        &self,
        chunk_id: ChunkId,
        mut entries: Vec<SignedArtifactRef>,
    ) {
        entries.sort_by_key(|entry| entry.id);
        entries.dedup_by_key(|entry| entry.id);
        entries.truncate(neutrino_consensus_types::signed_artifacts::MAX_ARTIFACT_INVENTORY);
        let Some(publisher) = self.publisher_snapshot() else {
            return;
        };
        let Ok(data) = borsh::to_vec(&SignedArtifactInventory {
            chunk_id,
            entries,
            next: None,
        }) else {
            return;
        };
        let _ = publisher
            .send(NetworkCommand::Publish {
                topic: Topic::SignedArtifacts,
                data,
            })
            .await;
    }
}

#[cfg(test)]
mod verdict_cache_tests {
    use super::{ProofVerdict, Rejection, VerdictCache, VerdictToken};

    const fn token(program: Option<[u32; 8]>) -> VerdictToken {
        VerdictToken {
            program,
            chain_spec: [3; 32],
            source: [7; 32],
            generation: 0,
        }
    }

    #[test]
    fn verdict_cache_binds_program_and_exact_source() {
        let mut cache = VerdictCache::default();
        let original = token(Some([1; 8]));
        assert!(cache.remember(
            original,
            original.program,
            original.chain_spec,
            ProofVerdict::Valid
        ));
        assert_eq!(
            cache.get(original, original.program, original.chain_spec),
            Some(ProofVerdict::Valid)
        );

        let other_program = VerdictToken {
            program: Some([2; 8]),
            ..original
        };
        assert_eq!(
            cache.get(
                other_program,
                other_program.program,
                other_program.chain_spec
            ),
            None
        );
        assert_eq!(
            cache.get(original, other_program.program, original.chain_spec),
            None
        );
        assert!(!cache.remember(
            original,
            other_program.program,
            original.chain_spec,
            ProofVerdict::Valid
        ));
        let other_source = VerdictToken {
            source: [8; 32],
            ..original
        };
        assert_eq!(
            cache.get(other_source, other_source.program, other_source.chain_spec),
            None
        );
    }

    #[test]
    fn verdict_cache_binds_chain_spec() {
        let mut cache = VerdictCache::default();
        let original = token(Some([1; 8]));
        let rejection = ProofVerdict::Rejected(Rejection::VerifierRejected);
        assert!(cache.remember(original, original.program, original.chain_spec, rejection));
        let changed = VerdictToken {
            chain_spec: [4; 32],
            ..original
        };
        assert_eq!(
            cache.get(changed, changed.program, changed.chain_spec),
            None
        );
        assert_eq!(
            cache.get(original, original.program, changed.chain_spec),
            None
        );
        assert!(!cache.remember(original, original.program, changed.chain_spec, rejection));
    }

    #[test]
    fn bootstrap_generation_fences_late_verdicts() {
        let mut cache = VerdictCache::default();
        let original = token(Some([1; 8]));
        assert!(cache.remember(
            original,
            original.program,
            original.chain_spec,
            ProofVerdict::Valid
        ));
        cache.reset();
        assert_eq!(
            cache.get(original, original.program, original.chain_spec),
            None
        );
        for late in [
            ProofVerdict::Valid,
            ProofVerdict::Rejected(Rejection::VerifierRejected),
        ] {
            assert!(!cache.remember(original, original.program, original.chain_spec, late));
        }
        let current = VerdictToken {
            generation: cache.generation,
            ..original
        };
        assert!(cache.remember(
            current,
            current.program,
            current.chain_spec,
            ProofVerdict::Valid
        ));
        assert_eq!(
            cache.get(original, original.program, original.chain_spec),
            None
        );
        assert_eq!(
            cache.get(current, current.program, current.chain_spec),
            Some(ProofVerdict::Valid)
        );
    }

    #[test]
    fn unkeyed_backend_verdicts_are_never_reused() {
        let mut cache = VerdictCache::default();
        let unkeyed = token(None);
        assert!(cache.remember(unkeyed, None, unkeyed.chain_spec, ProofVerdict::Valid));
        assert!(cache.remember(
            unkeyed,
            None,
            unkeyed.chain_spec,
            ProofVerdict::Rejected(Rejection::VerifierRejected)
        ));
        assert_eq!(cache.get(unkeyed, None, unkeyed.chain_spec), None);
        assert_eq!(cache.entries.len(), 0);
        let keyed = VerdictToken {
            program: Some([1; 8]),
            ..unkeyed
        };
        assert_eq!(cache.get(keyed, keyed.program, keyed.chain_spec), None);
    }
}
