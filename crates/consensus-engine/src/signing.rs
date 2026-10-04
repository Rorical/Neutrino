//! Durable local signing reservations and monotonic anti-equivocation watermarks.
//!
//! A reservation is synchronized before accessing the secret key. Repeating the
//! exact reservation is safe because BLS signatures are deterministic. Conflicting
//! messages, earlier rounds and already-finalized chunks are rejected. Entries use
//! the public key rather than its mutable validator-set position as identity.
//! Every signature also binds the complete chain-spec hash in its 56-byte
//! consensus prefix; raw proposal/report reservations accept only that exact
//! current domain during recovery.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use neutrino_consensus_types::{
    BftProposal, FinalityVote, FinalityVoteData, FinalityVotePhase, NilVote, NilVoteAttestation,
    NilVoteData, QuorumCertificate, RoundChange,
};
use neutrino_primitives::{BitVec, BlsPublicKey, BlsSignature, Hash, Slot};
use neutrino_storage::{Batch, Column, Database};

use crate::{Engine, EngineError, ProposerKey, StoreError};

extern crate alloc;

/// A requested signature would violate local signing safety.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningViolation {
    /// Another message was reserved at this signing position.
    Conflict,
    /// A newer round or proposer slot was already reserved.
    Regression,
    /// Finalized history must never be signed again.
    FinalizedChunk,
    /// The signing key does not match its authenticated validator-set position.
    KeyNotActive,
}

impl fmt::Display for SigningViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Conflict => "conflicting local signing reservation",
            Self::Regression => "local signing position regressed",
            Self::FinalizedChunk => "refusing to sign finalized history",
            Self::KeyNotActive => "local signing key is not an active validator",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
struct VoteIntent {
    data: FinalityVoteData,
    validator_index: u32,
    proof_hashes: Vec<Hash>,
    unlock_quorum: Option<QuorumCertificate>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct VoteWatermark {
    spec: Hash,
    identity: BlsPublicKey,
    chunk_id: u64,
    round: u32,
    prevote: Option<VoteIntent>,
    precommit: Option<VoteIntent>,
    locked: Option<QuorumCertificate>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct ProposalWatermark {
    spec: Hash,
    identity: BlsPublicKey,
    slot: Slot,
    hash: Hash,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct NilIntent {
    spec: Hash,
    identity: BlsPublicKey,
    data: NilVoteData,
    validator_index: u32,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct MessageIntent {
    spec: Hash,
    identity: BlsPublicKey,
    message: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct MessageWatermark {
    spec: Hash,
    identity: BlsPublicKey,
    chunk_id: u64,
    round: u32,
}

fn nil_key(identity: &BlsPublicKey, data: &NilVoteData) -> Vec<u8> {
    let mut key = vote_key(identity, data.chunk_id);
    key[0] = 3;
    key.extend_from_slice(&data.round.to_be_bytes());
    key.push(u8::from(data.phase == FinalityVotePhase::Precommit));
    key
}

fn round_message_key(tag: u8, identity: &BlsPublicKey, chunk_id: u64, round: u32) -> Vec<u8> {
    let mut key = vote_key(identity, chunk_id);
    key[0] = tag;
    key.extend_from_slice(&round.to_be_bytes());
    key
}

fn message_watermark_key(tag: u8, identity: &BlsPublicKey, chunk_id: u64) -> Vec<u8> {
    let mut key = vote_key(identity, chunk_id);
    key[0] = tag + 2;
    key
}

/// Durable position used to identify an interrupted local signing operation.
pub(crate) struct SigningProgress {
    /// Highest round reserved for this chunk and identity.
    pub round: u32,
    /// A prevote intent is present at the highest round.
    pub prevoted: bool,
    /// A complete precommit attestation intent is present at that round.
    pub precommitted: bool,
}

fn vote_key(identity: &BlsPublicKey, chunk_id: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(57);
    key.push(0);
    key.extend_from_slice(identity);
    key.extend_from_slice(&chunk_id.to_be_bytes());
    key
}

fn proposal_key(identity: &BlsPublicKey) -> Vec<u8> {
    let mut key = Vec::with_capacity(49);
    key.push(1);
    key.extend_from_slice(identity);
    key
}

fn intent_key(identity: &BlsPublicKey, data: &FinalityVoteData) -> Vec<u8> {
    let mut key = vote_key(identity, data.chunk_id);
    key[0] = 2;
    key.extend_from_slice(&data.round.to_be_bytes());
    key.push(u8::from(data.phase == FinalityVotePhase::Precommit));
    key
}

/// Remove only positions rendered unsignable by the same atomic watermark
/// update. The retained lock's original precommit intent remains recoverable.
fn compact_round_intents(
    batch: &mut Batch,
    identity: &BlsPublicKey,
    chunk_id: u64,
    old_round: u32,
    new_round: u32,
    lock: Option<&QuorumCertificate>,
) {
    if new_round <= old_round {
        return;
    }
    for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
        let data = FinalityVoteData {
            chunk_id,
            round: old_round,
            phase,
            chunk_hash: [0; 32],
        };
        if phase != FinalityVotePhase::Precommit
            || lock.is_none_or(|lock| lock.data.round != old_round)
        {
            batch.delete(Column::SigningJournal, intent_key(identity, &data));
        }
        batch.delete(
            Column::SigningJournal,
            nil_key(
                identity,
                &NilVoteData {
                    chunk_id,
                    round: old_round,
                    phase,
                },
            ),
        );
    }
    batch.delete(
        Column::SigningJournal,
        round_message_key(4, identity, chunk_id, old_round),
    );
    batch.delete(
        Column::SigningJournal,
        round_message_key(5, identity, chunk_id, old_round),
    );
    if let Some(reported) = old_round.checked_add(1).filter(|round| *round < new_round) {
        batch.delete(
            Column::SigningJournal,
            round_message_key(5, identity, chunk_id, reported),
        );
    }
}

impl<DB: Database> Engine<DB> {
    fn validate_vote_watermark(
        &self,
        watermark: &VoteWatermark,
    ) -> Result<(), EngineError<DB::Error>> {
        if watermark.spec != self.chain_spec().hash() {
            return Err(StoreError::Corrupt("invalid signing watermark context").into());
        }
        for (phase, intent) in [
            (FinalityVotePhase::Prevote, &watermark.prevote),
            (FinalityVotePhase::Precommit, &watermark.precommit),
        ] {
            let Some(intent) = intent else {
                continue;
            };
            if intent.data.chunk_id != watermark.chunk_id
                || intent.data.round != watermark.round
                || intent.data.phase != phase
            {
                return Err(StoreError::Corrupt("signing watermark intent target mismatch").into());
            }
            let bytes = self
                .store()
                .db()
                .get(
                    Column::SigningJournal,
                    &intent_key(&watermark.identity, &intent.data),
                )
                .map_err(StoreError::Database)?
                .ok_or(StoreError::Corrupt("signing watermark intent missing"))?;
            if borsh::from_slice::<VoteIntent>(&bytes)? != *intent {
                return Err(StoreError::Corrupt("signing watermark intent changed").into());
            }
        }
        if let Some(lock) = &watermark.locked {
            let precommit = FinalityVoteData {
                phase: FinalityVotePhase::Precommit,
                ..lock.data.clone()
            };
            let bytes = self
                .store()
                .db()
                .get(
                    Column::SigningJournal,
                    &intent_key(&watermark.identity, &precommit),
                )
                .map_err(StoreError::Database)?
                .ok_or(StoreError::Corrupt("journal lock has no signed precommit"))?;
            let intent: VoteIntent = borsh::from_slice(&bytes)?;
            if intent.data != precommit
                || intent.unlock_quorum.as_ref() != Some(lock)
                || lock.data.round > watermark.round
                || self
                    .verify_bft_unlock_quorum(self.active_validator_set(), &precommit, lock)
                    .is_err()
            {
                return Err(StoreError::Corrupt("invalid durable signing lock").into());
            }
        }
        if watermark
            .precommit
            .as_ref()
            .is_some_and(|intent| intent.unlock_quorum != watermark.locked)
        {
            return Err(StoreError::Corrupt("journal precommit lock mismatch").into());
        }
        Ok(())
    }
    fn validate_signing_key(&self, voter: &ProposerKey) -> Result<(), EngineError<DB::Error>> {
        let index = usize::try_from(voter.validator_index()).expect("u32 fits usize");
        if !self
            .active_validator_set()
            .get(index)
            .is_some_and(|validator| {
                validator.pubkey == *voter.public_key_bytes()
                    && !validator.slashed
                    && validator.effective_stake > 0
            })
        {
            return Err(EngineError::Signing(SigningViolation::KeyNotActive));
        }
        Ok(())
    }

    fn load_vote_watermark(
        &self,
        voter: &ProposerKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<VoteWatermark, EngineError<DB::Error>> {
        let watermark = self
            .store()
            .db()
            .get(
                Column::SigningJournal,
                &vote_key(voter.public_key_bytes(), chunk_id),
            )
            .map_err(StoreError::Database)?
            .map(|bytes| borsh::from_slice::<VoteWatermark>(&bytes))
            .transpose()?
            .unwrap_or_else(|| VoteWatermark {
                spec: self.chain_spec().hash(),
                identity: *voter.public_key_bytes(),
                chunk_id,
                round,
                prevote: None,
                precommit: None,
                locked: None,
            });
        if watermark.identity != *voter.public_key_bytes() || watermark.chunk_id != chunk_id {
            return Err(StoreError::Corrupt("signing journal identity mismatch").into());
        }
        self.validate_vote_watermark(&watermark)?;
        Ok(watermark)
    }

    /// Reserve an exact vote and attestation before producing either signature.
    pub(crate) fn sign_vote_durable(
        &mut self,
        voter: &ProposerKey,
        data: FinalityVoteData,
        proof_hashes: Vec<Hash>,
        unlock_quorum: Option<QuorumCertificate>,
    ) -> Result<FinalityVote, EngineError<DB::Error>> {
        self.validate_signing_key(voter)?;
        if data.chunk_id < self.signing_finalized_floor()? {
            return Err(EngineError::Signing(SigningViolation::FinalizedChunk));
        }
        if self
            .store()
            .db()
            .get(
                Column::SigningJournal,
                &nil_key(
                    voter.public_key_bytes(),
                    &NilVoteData {
                        chunk_id: data.chunk_id,
                        round: data.round,
                        phase: data.phase,
                    },
                ),
            )
            .map_err(StoreError::Database)?
            .is_some()
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        let intent = VoteIntent {
            data: data.clone(),
            validator_index: voter.validator_index(),
            proof_hashes,
            unlock_quorum,
        };
        let key = vote_key(voter.public_key_bytes(), data.chunk_id);
        let mut watermark = self.load_vote_watermark(voter, data.chunk_id, data.round)?;
        let prior_round = watermark.round;
        let prior_lock = watermark.locked.clone();
        self.validate_vote_unlock(&intent, watermark.locked.as_ref())?;
        if data.round < watermark.round {
            return Err(EngineError::Signing(SigningViolation::Regression));
        }
        if data.round > watermark.round {
            watermark.round = data.round;
            watermark.prevote = None;
            watermark.precommit = None;
        }
        let entry = match data.phase {
            FinalityVotePhase::Prevote => &mut watermark.prevote,
            FinalityVotePhase::Precommit => &mut watermark.precommit,
        };
        if entry.as_ref().is_some_and(|prior| *prior != intent) {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        *entry = Some(intent.clone());
        if data.phase == FinalityVotePhase::Precommit {
            watermark.locked.clone_from(&intent.unlock_quorum);
        }
        let mut batch = Batch::new();
        compact_round_intents(
            &mut batch,
            voter.public_key_bytes(),
            data.chunk_id,
            prior_round,
            data.round,
            prior_lock.as_ref(),
        );
        if data.phase == FinalityVotePhase::Precommit
            && let Some(lock) = prior_lock
                .as_ref()
                .filter(|lock| lock.data.round < data.round)
        {
            let locked_precommit = FinalityVoteData {
                phase: FinalityVotePhase::Precommit,
                ..lock.data.clone()
            };
            batch.delete(
                Column::SigningJournal,
                intent_key(voter.public_key_bytes(), &locked_precommit),
            );
        }
        batch.put(Column::SigningJournal, key, borsh::to_vec(&watermark)?);
        batch.put(
            Column::SigningJournal,
            intent_key(voter.public_key_bytes(), &data),
            borsh::to_vec(&intent)?,
        );
        self.store_mut()
            .db_mut()
            .write_batch_durable(batch)
            .map_err(StoreError::Database)?;

        let vote = self.sign_reserved_value_vote(voter, data, intent);
        self.retain_local_signed_vote(&vote)?;
        Ok(vote)
    }

    fn sign_reserved_value_vote(
        &self,
        voter: &ProposerKey,
        data: FinalityVoteData,
        intent: VoteIntent,
    ) -> FinalityVote {
        let mut bits = BitVec::default();
        for index in 0..self.active_validator_set().len() {
            bits.push(index == usize::try_from(voter.validator_index()).expect("u32 fits usize"));
        }
        let mut vote = FinalityVote {
            aggregation_bits: bits,
            signature: voter.sign_finality_vote(self.chain_spec().consensus_domain(), &data),
            data,
            attestations: Vec::new(),
        };
        vote.attestations.push(voter.attest_vote(
            self.chain_spec().consensus_domain(),
            vote.data.clone(),
            intent.proof_hashes,
            intent.unlock_quorum,
        ));
        vote
    }

    fn validate_vote_unlock(
        &self,
        intent: &VoteIntent,
        locked: Option<&QuorumCertificate>,
    ) -> Result<(), EngineError<DB::Error>> {
        if intent.data.phase == FinalityVotePhase::Prevote && !intent.proof_hashes.is_empty() {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        if let Some(unlock) = &intent.unlock_quorum
            && self
                .verify_bft_unlock_quorum(self.active_validator_set(), &intent.data, unlock)
                .is_err()
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        if let Some(lock) = locked
            && intent.data.chunk_hash != lock.data.chunk_hash
            && intent
                .unlock_quorum
                .as_ref()
                .is_none_or(|unlock| unlock.data.round <= lock.data.round)
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        // Live precommits are emitted only after the current-round prevote QC.
        // Retaining that exact QC in the journal makes a lock survive even if
        // the subsequent session write is interrupted.
        if intent.data.phase == FinalityVotePhase::Precommit
            && intent
                .unlock_quorum
                .as_ref()
                .is_none_or(|unlock| unlock.data.round != intent.data.round)
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        Ok(())
    }

    pub(crate) fn signing_round_for(
        &self,
        identity: &BlsPublicKey,
        chunk_id: u64,
    ) -> Result<Option<u32>, EngineError<DB::Error>> {
        let bytes = self
            .store()
            .db()
            .get(Column::SigningJournal, &vote_key(identity, chunk_id))
            .map_err(StoreError::Database)?;
        bytes
            .map(|bytes| {
                let watermark: VoteWatermark = borsh::from_slice(&bytes)?;
                if watermark.spec != self.chain_spec().hash()
                    || watermark.identity != *identity
                    || watermark.chunk_id != chunk_id
                {
                    return Err(StoreError::Corrupt("signing watermark identity mismatch").into());
                }
                self.validate_vote_watermark(&watermark)?;
                Ok(watermark.round)
            })
            .transpose()
    }

    /// Finish interrupted reservations using their original authenticated inputs.
    pub(crate) fn reserved_local_votes(
        &mut self,
        voter: &ProposerKey,
        chunk_id: u64,
    ) -> Result<Vec<FinalityVote>, EngineError<DB::Error>> {
        let bytes = self
            .store()
            .db()
            .get(
                Column::SigningJournal,
                &vote_key(voter.public_key_bytes(), chunk_id),
            )
            .map_err(StoreError::Database)?;
        let Some(bytes) = bytes else {
            return Ok(Vec::new());
        };
        let watermark: VoteWatermark = borsh::from_slice(&bytes)?;
        self.validate_vote_watermark(&watermark)?;
        let mut messages = Vec::new();
        for intent in [watermark.prevote, watermark.precommit]
            .into_iter()
            .flatten()
        {
            messages.push(self.sign_vote_durable(
                voter,
                intent.data,
                intent.proof_hashes,
                intent.unlock_quorum,
            )?);
        }
        Ok(messages)
    }

    pub(crate) fn reserved_signing_progress(
        &self,
        voter: &ProposerKey,
        chunk_id: u64,
    ) -> Result<Option<SigningProgress>, EngineError<DB::Error>> {
        let bytes = self
            .store()
            .db()
            .get(
                Column::SigningJournal,
                &vote_key(voter.public_key_bytes(), chunk_id),
            )
            .map_err(StoreError::Database)?;
        bytes
            .map(|bytes| {
                let watermark: VoteWatermark = borsh::from_slice(&bytes)?;
                if watermark.spec != self.chain_spec().hash()
                    || watermark.identity != *voter.public_key_bytes()
                    || watermark.chunk_id != chunk_id
                {
                    return Err(StoreError::Corrupt("signing progress identity mismatch").into());
                }
                self.validate_vote_watermark(&watermark)?;
                Ok(SigningProgress {
                    round: watermark.round,
                    prevoted: watermark.prevote.is_some()
                        || self
                            .reserved_nil_intent(
                                voter,
                                chunk_id,
                                watermark.round,
                                FinalityVotePhase::Prevote,
                            )?
                            .is_some(),
                    precommitted: watermark.precommit.is_some()
                        || self
                            .reserved_nil_intent(
                                voter,
                                chunk_id,
                                watermark.round,
                                FinalityVotePhase::Precommit,
                            )?
                            .is_some(),
                })
            })
            .transpose()
    }

    pub(crate) fn reserved_signing_lock(
        &self,
        voter: &ProposerKey,
        chunk_id: u64,
    ) -> Result<Option<QuorumCertificate>, EngineError<DB::Error>> {
        let bytes = self
            .store()
            .db()
            .get(
                Column::SigningJournal,
                &vote_key(voter.public_key_bytes(), chunk_id),
            )
            .map_err(StoreError::Database)?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let watermark: VoteWatermark = borsh::from_slice(&bytes)?;
        if watermark.identity != *voter.public_key_bytes() || watermark.chunk_id != chunk_id {
            return Err(StoreError::Corrupt("signing lock identity mismatch").into());
        }
        self.validate_vote_watermark(&watermark)?;
        Ok(watermark.locked)
    }

    pub(crate) fn verify_saved_local_vote(
        &self,
        identity: BlsPublicKey,
        vote: &FinalityVote,
    ) -> Result<(), EngineError<DB::Error>> {
        let Some((index, _)) =
            crate::slashing::extract_single_signer(vote, self.active_validator_set().len())
        else {
            return Err(StoreError::Corrupt("saved local vote is not individual").into());
        };
        if self
            .active_validator_set()
            .get(usize::try_from(index).expect("u32 fits usize"))
            .is_none_or(|validator| validator.pubkey != identity)
        {
            return Err(StoreError::Corrupt("saved local vote identity mismatch").into());
        }
        let [claim] = vote.attestations.as_slice() else {
            return Err(StoreError::Corrupt("saved local attestation coverage changed").into());
        };
        let (proof_hashes, unlock_quorum) =
            (claim.proof_hashes.clone(), claim.unlock_quorum.clone());
        let expected = VoteIntent {
            data: vote.data.clone(),
            validator_index: index,
            proof_hashes,
            unlock_quorum,
        };
        let bytes = self
            .store()
            .db()
            .get(Column::SigningJournal, &intent_key(&identity, &vote.data))
            .map_err(StoreError::Database)?
            .ok_or(StoreError::Corrupt("saved local vote reservation missing"))?;
        if borsh::from_slice::<VoteIntent>(&bytes)? != expected {
            return Err(StoreError::Corrupt("saved local vote reservation mismatch").into());
        }
        Ok(())
    }

    /// Finality itself forbids old signing, so completed journals can be removed
    /// while retaining proposer slot watermarks and every unfinalized reservation.
    pub(crate) fn expired_signing_entries(
        &self,
        batch: &mut Batch,
    ) -> Result<(), EngineError<DB::Error>> {
        let floor = self.signing_finalized_floor()?;
        for (key, _) in self
            .store()
            .db()
            .iter_column(Column::BftSessions)
            .map_err(StoreError::Database)?
        {
            let id = u64::from_be_bytes(
                key.as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("invalid saved session key"))?,
            );
            if id < floor {
                batch.delete(Column::BftSessions, key);
            }
        }
        for (key, _) in self
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .map_err(StoreError::Database)?
        {
            if key.first() == Some(&1) {
                continue;
            }
            if key.len() < 57 || !matches!(key[0], 0 | 2..=7) {
                return Err(StoreError::Corrupt("invalid signing journal key").into());
            }
            let id = u64::from_be_bytes(key[49..57].try_into().expect("eight bytes"));
            if id < floor {
                batch.delete(Column::SigningJournal, key);
            }
        }
        Ok(())
    }

    fn signing_finalized_floor(&self) -> Result<u64, EngineError<DB::Error>> {
        let persisted = self
            .store()
            .get_latest_finalized_chunk_id()?
            .map(|id| {
                id.checked_add(1)
                    .ok_or(StoreError::Corrupt("signing finality floor overflow"))
            })
            .transpose()?
            .unwrap_or(0);
        Ok(persisted.max(self.finalized_next_chunk_id()))
    }

    /// Reserve explicit nil in the same anti-equivocation position as a value.
    /// Nil precommits preserve the durable lock from every earlier value.
    pub(crate) fn sign_nil_vote_durable(
        &mut self,
        voter: &ProposerKey,
        data: NilVoteData,
    ) -> Result<NilVote, EngineError<DB::Error>> {
        self.validate_signing_key(voter)?;
        if data.chunk_id < self.signing_finalized_floor()? {
            return Err(EngineError::Signing(SigningViolation::FinalizedChunk));
        }
        let value_data = FinalityVoteData {
            chunk_id: data.chunk_id,
            round: data.round,
            phase: data.phase,
            chunk_hash: [0; 32],
        };
        if self
            .store()
            .db()
            .get(
                Column::SigningJournal,
                &intent_key(voter.public_key_bytes(), &value_data),
            )
            .map_err(StoreError::Database)?
            .is_some()
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        let key = vote_key(voter.public_key_bytes(), data.chunk_id);
        let mut watermark = self.load_vote_watermark(voter, data.chunk_id, data.round)?;
        let prior_round = watermark.round;
        if data.round < watermark.round {
            return Err(EngineError::Signing(SigningViolation::Regression));
        }
        if data.round > watermark.round {
            watermark.round = data.round;
            watermark.prevote = None;
            watermark.precommit = None;
        }
        let intent = NilIntent {
            spec: self.chain_spec().hash(),
            identity: *voter.public_key_bytes(),
            data: data.clone(),
            validator_index: voter.validator_index(),
        };
        let nil_key = nil_key(voter.public_key_bytes(), &data);
        let bytes = borsh::to_vec(&intent)?;
        if self
            .store()
            .db()
            .get(Column::SigningJournal, &nil_key)
            .map_err(StoreError::Database)?
            .is_some_and(|prior| prior != bytes)
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        let mut batch = Batch::new();
        compact_round_intents(
            &mut batch,
            voter.public_key_bytes(),
            data.chunk_id,
            prior_round,
            data.round,
            watermark.locked.as_ref(),
        );
        batch.put(Column::SigningJournal, key, borsh::to_vec(&watermark)?);
        batch.put(Column::SigningJournal, nil_key, bytes);
        self.store_mut()
            .db_mut()
            .write_batch_durable(batch)
            .map_err(StoreError::Database)?;
        let signature = voter
            .sign_raw(&data.signing_message(self.chain_spec().consensus_domain()))
            .to_bytes();
        let mut claim = NilVoteAttestation {
            validator_index: voter.validator_index(),
            vote: data.clone(),
            vote_signature: signature,
            signature: [0; 96],
        };
        claim.signature = voter
            .sign_raw(&claim.signing_message(self.chain_spec().consensus_domain()))
            .to_bytes();
        let mut aggregation_bits = BitVec::default();
        for index in 0..self.active_validator_set().len() {
            aggregation_bits
                .push(index == usize::try_from(voter.validator_index()).expect("u32 fits usize"));
        }
        let vote = NilVote {
            data,
            aggregation_bits,
            signature,
            attestations: vec![claim],
        };
        self.retain_signed_artifact(
            &neutrino_consensus_types::signed_artifacts::SignedArtifact::NilVote(vote.clone()),
            true,
        )?;
        Ok(vote)
    }

    fn reserved_nil_intent(
        &self,
        voter: &ProposerKey,
        chunk_id: u64,
        round: u32,
        phase: FinalityVotePhase,
    ) -> Result<Option<NilIntent>, EngineError<DB::Error>> {
        let data = NilVoteData {
            chunk_id,
            round,
            phase,
        };
        self.store()
            .db()
            .get(
                Column::SigningJournal,
                &nil_key(voter.public_key_bytes(), &data),
            )
            .map_err(StoreError::Database)?
            .map(|bytes| {
                let intent: NilIntent = borsh::from_slice(&bytes)?;
                if intent.spec != self.chain_spec().hash()
                    || intent.identity != *voter.public_key_bytes()
                    || intent.data != data
                    || intent.validator_index != voter.validator_index()
                {
                    return Err(StoreError::Corrupt("nil signing reservation changed").into());
                }
                Ok(intent)
            })
            .transpose()
    }

    pub(crate) fn reserved_local_nil_votes(
        &mut self,
        voter: &ProposerKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<Vec<NilVote>, EngineError<DB::Error>> {
        let mut recovered = Vec::new();
        for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
            if let Some(intent) = self.reserved_nil_intent(voter, chunk_id, round, phase)? {
                recovered.push(self.sign_nil_vote_durable(voter, intent.data)?);
            }
        }
        Ok(recovered)
    }

    pub(crate) fn verify_saved_nil_vote(
        &self,
        identity: BlsPublicKey,
        vote: &NilVote,
    ) -> Result<(), EngineError<DB::Error>> {
        let [claim] = vote.attestations.as_slice() else {
            return Err(StoreError::Corrupt("saved local nil coverage changed").into());
        };
        if self
            .active_validator_set()
            .get(usize::try_from(claim.validator_index).expect("u32 fits usize"))
            .is_none_or(|validator| validator.pubkey != identity)
        {
            return Err(StoreError::Corrupt("saved nil identity mismatch").into());
        }
        let bytes = self
            .store()
            .db()
            .get(Column::SigningJournal, &nil_key(&identity, &vote.data))
            .map_err(StoreError::Database)?
            .ok_or(StoreError::Corrupt("saved nil reservation missing"))?;
        let intent: NilIntent = borsh::from_slice(&bytes)?;
        if intent.spec != self.chain_spec().hash()
            || intent.identity != identity
            || intent.data != vote.data
            || intent.validator_index != claim.validator_index
        {
            return Err(StoreError::Corrupt("saved nil reservation mismatch").into());
        }
        Ok(())
    }

    fn reserve_round_message(
        &mut self,
        voter: &ProposerKey,
        tag: u8,
        chunk_id: u64,
        round: u32,
        message: &[u8],
    ) -> Result<BlsSignature, EngineError<DB::Error>> {
        self.validate_signing_key(voter)?;
        if chunk_id < self.signing_finalized_floor()? {
            return Err(EngineError::Signing(SigningViolation::FinalizedChunk));
        }
        if self
            .signing_round_for(voter.public_key_bytes(), chunk_id)?
            .is_some_and(|signed_round| signed_round > round)
        {
            return Err(EngineError::Signing(SigningViolation::Regression));
        }
        let key = round_message_key(tag, voter.public_key_bytes(), chunk_id, round);
        let intent = MessageIntent {
            spec: self.chain_spec().hash(),
            identity: *voter.public_key_bytes(),
            message: message.to_vec(),
        };
        let bytes = borsh::to_vec(&intent)?;
        if self
            .store()
            .db()
            .get(Column::SigningJournal, &key)
            .map_err(StoreError::Database)?
            .is_some_and(|prior| prior != bytes)
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        let mut batch = Batch::new();
        self.compact_message_intents(&mut batch, tag, voter.public_key_bytes(), chunk_id, round)?;
        batch.put(Column::SigningJournal, key, bytes);
        self.store_mut()
            .db_mut()
            .write_batch_durable(batch)
            .map_err(StoreError::Database)?;
        Ok(voter.sign_raw(message).to_bytes())
    }

    /// Message-only rounds can be abandoned before reserving a vote. Track each
    /// message kind independently so those positions remain bounded as well.
    fn compact_message_intents(
        &self,
        batch: &mut Batch,
        tag: u8,
        identity: &BlsPublicKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<(), EngineError<DB::Error>> {
        let key = message_watermark_key(tag, identity, chunk_id);
        if let Some(bytes) = self
            .store()
            .db()
            .get(Column::SigningJournal, &key)
            .map_err(StoreError::Database)?
        {
            let prior: MessageWatermark = borsh::from_slice(&bytes)?;
            if prior.spec != self.chain_spec().hash()
                || prior.identity != *identity
                || prior.chunk_id != chunk_id
            {
                return Err(
                    StoreError::Corrupt("message signing watermark identity mismatch").into(),
                );
            }
            if round < prior.round {
                return Err(EngineError::Signing(SigningViolation::Regression));
            }
            if round > prior.round {
                batch.delete(
                    Column::SigningJournal,
                    round_message_key(tag, identity, chunk_id, prior.round),
                );
            }
        }
        batch.put(
            Column::SigningJournal,
            key,
            borsh::to_vec(&MessageWatermark {
                spec: self.chain_spec().hash(),
                identity: *identity,
                chunk_id,
                round,
            })?,
        );
        Ok(())
    }

    fn reserved_round_message(
        &self,
        tag: u8,
        identity: &BlsPublicKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<Option<Vec<u8>>, EngineError<DB::Error>> {
        self.store()
            .db()
            .get(
                Column::SigningJournal,
                &round_message_key(tag, identity, chunk_id, round),
            )
            .map_err(StoreError::Database)?
            .map(|bytes| {
                let intent: MessageIntent = borsh::from_slice(&bytes)?;
                if intent.spec != self.chain_spec().hash()
                    || intent.identity != *identity
                    || intent.message.len() < 56
                    || intent.message[16..24] != self.chain_spec().chain_id.to_le_bytes()
                    || intent.message[24..56] != self.chain_spec().hash()
                {
                    return Err(StoreError::Corrupt("round message reservation changed").into());
                }
                Ok(intent.message)
            })
            .transpose()
    }

    pub(crate) fn reserved_bft_proposal(
        &mut self,
        voter: &ProposerKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<Option<BftProposal>, EngineError<DB::Error>> {
        let Some(message) =
            self.reserved_round_message(4, voter.public_key_bytes(), chunk_id, round)?
        else {
            return Ok(None);
        };
        let (chunk, reserved_round, proposer_index, valid_quorum, round_change_certificate): (
            neutrino_consensus_types::Chunk,
            u32,
            u32,
            Option<QuorumCertificate>,
            Option<neutrino_consensus_types::RoundChangeCertificate>,
        ) = borsh::from_slice(&message[56..])?;
        let proposal = BftProposal {
            chunk,
            round: reserved_round,
            proposer_index,
            valid_quorum,
            round_change_certificate,
            signature: [0; 96],
        };
        if proposal.chunk.chunk_id != chunk_id
            || proposal.round != round
            || proposal.proposer_index != voter.validator_index()
            || proposal.signing_message(self.chain_spec().consensus_domain()) != message
        {
            return Err(StoreError::Corrupt("reserved proposal tuple changed").into());
        }
        self.sign_bft_proposal_durable(voter, proposal).map(Some)
    }

    pub(crate) fn reserved_round_change(
        &mut self,
        voter: &ProposerKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<Option<RoundChange>, EngineError<DB::Error>> {
        let Some(message) =
            self.reserved_round_message(5, voter.public_key_bytes(), chunk_id, round)?
        else {
            return Ok(None);
        };
        let (reserved_chunk, reserved_round, validator_index, highest_quorum): (
            u64,
            u32,
            u32,
            Option<QuorumCertificate>,
        ) = borsh::from_slice(&message[56..])?;
        let report = RoundChange {
            chunk_id: reserved_chunk,
            round: reserved_round,
            validator_index,
            highest_quorum,
            signature: [0; 96],
        };
        if report.chunk_id != chunk_id
            || report.round != round
            || report.validator_index != voter.validator_index()
            || report.signing_message(self.chain_spec().consensus_domain()) != message
        {
            return Err(StoreError::Corrupt("reserved round report tuple changed").into());
        }
        self.sign_round_change_durable(voter, report).map(Some)
    }

    pub(crate) fn verify_saved_round_report(
        &self,
        identity: BlsPublicKey,
        report: &RoundChange,
    ) -> Result<(), EngineError<DB::Error>> {
        if self.reserved_round_message(5, &identity, report.chunk_id, report.round)?
            != Some(report.signing_message(self.chain_spec().consensus_domain()))
        {
            return Err(StoreError::Corrupt("saved round report reservation missing").into());
        }
        Ok(())
    }

    pub(crate) fn sign_bft_proposal_durable(
        &mut self,
        voter: &ProposerKey,
        mut proposal: BftProposal,
    ) -> Result<BftProposal, EngineError<DB::Error>> {
        proposal.signature = self.reserve_round_message(
            voter,
            4,
            proposal.chunk.chunk_id,
            proposal.round,
            &proposal.signing_message(self.chain_spec().consensus_domain()),
        )?;
        self.retain_signed_artifact(
            &neutrino_consensus_types::signed_artifacts::SignedArtifact::Proposal(Box::new(
                proposal.clone(),
            )),
            true,
        )?;
        Ok(proposal)
    }

    pub(crate) fn sign_round_change_durable(
        &mut self,
        voter: &ProposerKey,
        mut report: RoundChange,
    ) -> Result<RoundChange, EngineError<DB::Error>> {
        report.signature = self.reserve_round_message(
            voter,
            5,
            report.chunk_id,
            report.round,
            &report.signing_message(self.chain_spec().consensus_domain()),
        )?;
        self.retain_signed_artifact(
            &neutrino_consensus_types::signed_artifacts::SignedArtifact::RoundChange(
                report.clone(),
            ),
            true,
        )?;
        Ok(report)
    }

    /// Reserve the proposer slot and complete header hash before signing.
    pub(crate) fn sign_proposal_durable(
        &mut self,
        voter: &ProposerKey,
        slot: Slot,
        hash: Hash,
    ) -> Result<BlsSignature, EngineError<DB::Error>> {
        self.validate_signing_key(voter)?;
        let key = proposal_key(voter.public_key_bytes());
        if let Some(bytes) = self
            .store()
            .db()
            .get(Column::SigningJournal, &key)
            .map_err(StoreError::Database)?
        {
            let prior: ProposalWatermark = borsh::from_slice(&bytes)?;
            if prior.spec != self.chain_spec().hash() || prior.identity != *voter.public_key_bytes()
            {
                return Err(StoreError::Corrupt("proposal journal identity mismatch").into());
            }
            if slot < prior.slot {
                return Err(EngineError::Signing(SigningViolation::Regression));
            }
            if slot == prior.slot && hash != prior.hash {
                return Err(EngineError::Signing(SigningViolation::Conflict));
            }
        }
        let mut batch = Batch::new();
        batch.put(
            Column::SigningJournal,
            key,
            borsh::to_vec(&ProposalWatermark {
                spec: self.chain_spec().hash(),
                identity: *voter.public_key_bytes(),
                slot,
                hash,
            })?,
        );
        self.store_mut()
            .db_mut()
            .write_batch_durable(batch)
            .map_err(StoreError::Database)?;
        Ok(voter.sign_proposer_message(self.chain_spec().consensus_domain(), &hash))
    }
}

impl<E> From<borsh::io::Error> for EngineError<E> {
    fn from(error: borsh::io::Error) -> Self {
        Self::Store(StoreError::Codec(error))
    }
}

#[cfg(test)]
#[path = "signing_tests.rs"]
mod tests;
