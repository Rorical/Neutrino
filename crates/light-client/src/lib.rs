#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Proof-only light-client trust and freshness policy.
//!
//! The supplied verifier must authenticate a real compressed receipt under its
//! independently configured program keys. Native statement checks alone never
//! establish proof validity. Persistent applications atomically store this state
//! and the accepted artifact after a successful update.

#[cfg(test)]
extern crate alloc;

use neutrino_consensus_types::history_proof::{
    ChainBinding, Checkpoint, HistoryProof, ProofDomain,
};
use neutrino_primitives::{ChainSpec, Hash};

/// Cryptographic receipt verifier, implemented by the trusted proof backend.
///
/// Implementations must reject non-Compressed, malformed, wrong-program and
/// non-success receipts, bind the exact statement bytes, and compare the whole
/// domain with independently configured chain and program keys.
pub trait HistoryVerifier {
    /// Backend verification failure.
    type Error;
    /// Authenticate the exact conditional range and expected program domain.
    fn verify_history(
        &self,
        proof: &HistoryProof,
        trusted: &ProofDomain,
    ) -> Result<(), Self::Error>;
}

/// Result of accepting a valid history artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateOutcome {
    /// Advanced the exact local anchor to the requested endpoint.
    Advanced,
    /// Reverified an identical endpoint without changing trust or freshness state.
    AlreadyCurrent,
}

/// Cryptographic or local trust-policy rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LightClientError {
    /// The supplied anchor/spec/profile is inconsistent.
    InvalidAnchor,
    /// Receipt and trusted chain/program identities differ.
    Domain,
    /// The current weak-subjectivity trust window has expired.
    Expired,
    /// A verified endpoint conflicts with the local endpoint at the same height.
    Conflict,
    /// The range does not begin exactly at the current authenticated boundary.
    NotExtension,
    /// The endpoint does not match the locally requested endpoint identity.
    UnexpectedTarget,
    /// The endpoint claims a slot too far into the future.
    Future,
    /// The advancing endpoint is too old for the local freshness policy.
    Stale,
    /// Time arithmetic overflowed or a malformed range was supplied.
    Range,
    /// The cryptographic verifier rejected the receipt.
    Verification,
}
impl core::fmt::Display for LightClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "light-client update rejected: {self:?}")
    }
}
impl core::error::Error for LightClientError {}

/// Durable local trust state. Restoring never assigns a new trust timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct LightClientSnapshot {
    /// Exact locally authenticated endpoint.
    pub checkpoint: Checkpoint,
    /// Existing absolute weak-subjectivity expiry, including normal proven advancement.
    pub anchor_expires_at: u64,
}

/// Current proof-only trust state and locally pinned time policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LightClient {
    checkpoint: Checkpoint,
    genesis_time: u64,
    slot_duration_secs: u64,
    weak_subjectivity_period_secs: u64,
    stale_threshold_secs: u64,
    max_future_drift_secs: u64,
    anchor_expires_at: u64,
}
impl LightClient {
    /// Install an explicit locally trusted anchor. This is an out-of-band trust
    /// operation; an arbitrary peer checkpoint is never suitable input.
    pub fn new(
        spec: &ChainSpec,
        trusted: Checkpoint,
        trusted_at: u64,
        max_future_drift_secs: u64,
    ) -> Result<Self, LightClientError> {
        spec.validate()
            .map_err(|_| LightClientError::InvalidAnchor)?;
        if (trusted.boundary.next_chunk_id == 0
            && trusted.boundary
                != neutrino_consensus_types::history_proof::ConsensusBoundary::genesis(spec))
            || trusted.domain.chain != ChainBinding::from_spec(spec)
            || !trusted.boundary.is_well_formed(&trusted.domain.chain)
            || neutrino_prover_checkpoint::validate_domain(&trusted.domain).is_err()
        {
            return Err(LightClientError::InvalidAnchor);
        }
        let anchor_expires_at = trusted_at
            .checked_add(spec.light_client.weak_subjectivity_period_secs)
            .ok_or(LightClientError::Range)?;
        Ok(Self {
            checkpoint: trusted,
            genesis_time: spec.genesis_time,
            slot_duration_secs: spec.consensus.slot_duration_secs,
            weak_subjectivity_period_secs: spec.light_client.weak_subjectivity_period_secs,
            stale_threshold_secs: spec.light_client.stale_threshold_secs,
            max_future_drift_secs,
            anchor_expires_at,
        })
    }

    /// Snapshot for atomic persistence with the accepted receipt.
    #[must_use]
    pub const fn snapshot(&self) -> LightClientSnapshot {
        LightClientSnapshot {
            checkpoint: self.checkpoint,
            anchor_expires_at: self.anchor_expires_at,
        }
    }

    /// Restore trusted local storage under independently pinned keys and current
    /// local clock policy. Never pass a peer-supplied snapshot: this operation trusts
    /// the persisted history of anchor advancement, which the latest suffix alone
    /// cannot reconstruct. Expired snapshots remain expired; no wall clock is consulted.
    pub fn restore(
        spec: &ChainSpec,
        trusted_domain: &ProofDomain,
        snapshot: &LightClientSnapshot,
        max_future_drift_secs: u64,
    ) -> Result<Self, LightClientError> {
        if snapshot.checkpoint.domain != *trusted_domain {
            return Err(LightClientError::Domain);
        }
        let trusted_at = snapshot
            .anchor_expires_at
            .checked_sub(spec.light_client.weak_subjectivity_period_secs)
            .ok_or(LightClientError::InvalidAnchor)?;
        Self::new(spec, snapshot.checkpoint, trusted_at, max_future_drift_secs)
    }

    /// Current exact authenticated endpoint.
    #[must_use]
    pub const fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// Local expiry; receipt replay cannot extend it.
    #[must_use]
    pub const fn anchor_expires_at(&self) -> u64 {
        self.anchor_expires_at
    }

    /// Verify and accept an exact requested suffix, or reverify an identical endpoint.
    /// All checks complete before any in-memory state is changed.
    pub fn accept<V: HistoryVerifier>(
        &mut self,
        proof: &HistoryProof,
        expected_endpoint: Hash,
        now: u64,
        verifier: &V,
    ) -> Result<UpdateOutcome, LightClientError> {
        if now >= self.anchor_expires_at {
            return Err(LightClientError::Expired);
        }
        let statement = &proof.statement;
        if statement.domain != self.checkpoint.domain {
            return Err(LightClientError::Domain);
        }
        neutrino_prover_checkpoint::validate_history(statement)
            .map_err(|_| LightClientError::Range)?;
        let endpoint = statement.end_checkpoint();
        if endpoint.hash() != expected_endpoint {
            return Err(LightClientError::UnexpectedTarget);
        }
        verifier
            .verify_history(proof, &self.checkpoint.domain)
            .map_err(|_| LightClientError::Verification)?;
        if endpoint == self.checkpoint {
            return Ok(UpdateOutcome::AlreadyCurrent);
        }
        if endpoint.boundary.next_chunk_id == self.checkpoint.boundary.next_chunk_id {
            return Err(LightClientError::Conflict);
        }
        if statement.start != self.checkpoint.boundary {
            return Err(LightClientError::NotExtension);
        }
        let timestamp = endpoint
            .boundary
            .slot
            .checked_mul(self.slot_duration_secs)
            .and_then(|elapsed| self.genesis_time.checked_add(elapsed))
            .ok_or(LightClientError::Range)?;
        let latest = now
            .checked_add(self.max_future_drift_secs)
            .ok_or(LightClientError::Range)?;
        if timestamp > latest {
            return Err(LightClientError::Future);
        }
        if now.saturating_sub(timestamp) > self.stale_threshold_secs {
            return Err(LightClientError::Stale);
        }
        let expiry = timestamp
            .min(now)
            .checked_add(self.weak_subjectivity_period_secs)
            .ok_or(LightClientError::Range)?;
        if expiry <= now {
            return Err(LightClientError::Expired);
        }
        self.checkpoint = endpoint;
        self.anchor_expires_at = expiry;
        Ok(UpdateOutcome::Advanced)
    }
}

#[cfg(test)]
mod tests;
