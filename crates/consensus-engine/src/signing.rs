//! Durable local signing reservations and monotonic anti-equivocation watermarks.
//!
//! A reservation is synchronized before accessing the secret key. Repeating the
//! exact reservation is safe because BLS signatures are deterministic. Conflicting
//! messages, earlier rounds and already-finalized chunks are rejected. Entries use
//! the public key rather than its mutable validator-set position as identity.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use neutrino_consensus_types::{
    FinalityVote, FinalityVoteData, FinalityVotePhase, QuorumCertificate,
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
}

#[derive(BorshSerialize, BorshDeserialize)]
struct ProposalWatermark {
    spec: Hash,
    identity: BlsPublicKey,
    slot: Slot,
    hash: Hash,
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

impl<DB: Database> Engine<DB> {
    fn validate_vote_watermark(
        &self,
        watermark: &VoteWatermark,
    ) -> Result<(), EngineError<DB::Error>> {
        if watermark.spec != self.chain_spec().hash()
            || watermark.round > self.chain_spec().consensus.bft_max_round
        {
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
        let intent = VoteIntent {
            data: data.clone(),
            validator_index: voter.validator_index(),
            proof_hashes,
            unlock_quorum,
        };
        let key = vote_key(voter.public_key_bytes(), data.chunk_id);
        let stored = self
            .store()
            .db()
            .get(Column::SigningJournal, &key)
            .map_err(StoreError::Database)?;
        let mut watermark = match stored {
            Some(bytes) => borsh::from_slice::<VoteWatermark>(&bytes)?,
            None => VoteWatermark {
                spec: self.chain_spec().hash(),
                identity: *voter.public_key_bytes(),
                chunk_id: data.chunk_id,
                round: data.round,
                prevote: None,
                precommit: None,
            },
        };
        if watermark.spec != self.chain_spec().hash()
            || watermark.identity != *voter.public_key_bytes()
            || watermark.chunk_id != data.chunk_id
        {
            return Err(StoreError::Corrupt("signing journal identity mismatch").into());
        }
        self.validate_vote_watermark(&watermark)?;
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
        let mut batch = Batch::new();
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

        let mut bits = BitVec::default();
        for index in 0..self.active_validator_set().len() {
            bits.push(index == usize::try_from(voter.validator_index()).expect("u32 fits usize"));
        }
        let mut vote = FinalityVote {
            aggregation_bits: bits,
            signature: voter.sign_finality_vote(self.chain_spec().chain_id, &data),
            data,
            attestations: Vec::new(),
        };
        if vote.data.phase == FinalityVotePhase::Precommit {
            vote.attestations.push(voter.attest_precommit(
                self.chain_spec().chain_id,
                vote.data.clone(),
                intent.proof_hashes,
                intent.unlock_quorum,
            ));
        }
        Ok(vote)
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
                    prevoted: watermark.prevote.is_some(),
                    precommitted: watermark.precommit.is_some(),
                })
            })
            .transpose()
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
        let (proof_hashes, unlock_quorum) = if vote.data.phase == FinalityVotePhase::Precommit {
            let claim = vote
                .attestations
                .first()
                .ok_or(StoreError::Corrupt("saved local attestation missing"))?;
            (claim.proof_hashes.clone(), claim.unlock_quorum.clone())
        } else {
            (Vec::new(), None)
        };
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
            if key.len() < 57 || !matches!(key[0], 0 | 2) {
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
        Ok(voter.sign_proposer_message(self.chain_spec().chain_id, &hash))
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
