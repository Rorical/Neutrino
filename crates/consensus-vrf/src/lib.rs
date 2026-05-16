#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Consensus-level VRF integration.
//!
//! This crate sits above the low-level `neutrino-vrf` primitive. It understands
//! validator-set indexing, header proposer claims, finalized-seed folding, and
//! public chunk-aggregator selection. The cryptographic construction and
//! threshold math are implemented in `neutrino-vrf`; this crate wires those
//! primitives to the consensus wire types from docs 02 and 12.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use neutrino_consensus_types::Header;
use neutrino_crypto::{bls::PublicKey, bls::Signature, sha256};
use neutrino_primitives::{
    BlsPublicKey, BlsSignature, ChunkId, DOMAIN_AGG_PROOF, FixedU128, Hash, Seed, Slot, Validator,
    ValidatorIndex,
};
use neutrino_vrf::{VrfOutput, is_eligible, verify};

/// Number of swap-or-not rounds used for public committee shuffling.
pub const SHUFFLE_ROUND_COUNT: u8 = 90;

/// Result of a successful proposer VRF verification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProposerEligibility {
    /// Proposer index in the active validator set.
    pub validator_index: ValidatorIndex,
    /// Recomputed VRF output used for the stake-weighted threshold check.
    pub vrf_output: VrfOutput,
}

/// Public chunk-aggregator selection result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AggregatorSelection {
    /// Validator index in the active validator set.
    pub validator_index: ValidatorIndex,
    /// Public pseudo-random output used for the stake-weighted threshold check.
    pub selection_output: VrfOutput,
}

/// Inputs required to verify one proposer VRF claim.
#[derive(Clone, Copy, Debug)]
pub struct ProposerClaim<'a> {
    /// Validator BLS public key bytes.
    pub public_key: &'a BlsPublicKey,
    /// Validator effective stake.
    pub stake: u64,
    /// Total active stake for the validator set.
    pub total_stake: u64,
    /// Chain identifier bound into the VRF message.
    pub chain_id: u64,
    /// Latest finalized public seed.
    pub finalized_seed: &'a Seed,
    /// Slot being proposed for.
    pub slot: Slot,
    /// Proposer VRF proof from the header.
    pub vrf_proof: &'a BlsSignature,
    /// Expected proposer count per slot as `Q64.64`.
    pub expected_proposers_per_slot: FixedU128,
}

/// Errors returned by consensus-level VRF checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VrfError {
    /// The active validator set has no unslashed positive stake.
    ZeroTotalStake,
    /// The selected validator has zero effective stake.
    ZeroValidatorStake,
    /// The selected validator has already been slashed.
    SlashedValidator,
    /// Summing active stake overflowed `u64`.
    StakeOverflow,
    /// A validator index could not fit in the wire type.
    ValidatorIndexOverflow {
        /// Active-set length that could not be represented.
        len: usize,
    },
    /// A header referenced a validator index outside the active set.
    ValidatorIndexOutOfBounds {
        /// Referenced validator index.
        index: ValidatorIndex,
        /// Active-set length.
        len: usize,
    },
    /// The validator public key bytes were invalid.
    InvalidPublicKey,
    /// The VRF proof bytes were invalid or failed verification.
    InvalidProof,
    /// The VRF proof verified, but its output missed the stake-weighted threshold.
    NotEligible,
}

impl fmt::Display for VrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTotalStake => f.write_str("active validator set has zero total stake"),
            Self::ZeroValidatorStake => f.write_str("validator has zero effective stake"),
            Self::SlashedValidator => f.write_str("validator is slashed"),
            Self::StakeOverflow => f.write_str("active validator stake overflowed u64"),
            Self::ValidatorIndexOverflow { len } => {
                write!(f, "active validator set length {len} exceeds u32::MAX")
            }
            Self::ValidatorIndexOutOfBounds { index, len } => {
                write!(
                    f,
                    "validator index {index} is outside active set length {len}"
                )
            }
            Self::InvalidPublicKey => f.write_str("invalid validator BLS public key"),
            Self::InvalidProof => f.write_str("invalid validator VRF proof"),
            Self::NotEligible => {
                f.write_str("validator VRF output missed the eligibility threshold")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VrfError {}

/// Computes total stake for all unslashed validators with positive stake.
pub fn total_active_stake(active_set: &[Validator]) -> Result<u64, VrfError> {
    let mut total = 0_u64;
    for validator in active_set {
        if validator.slashed || validator.effective_stake == 0 {
            continue;
        }
        total = total
            .checked_add(validator.effective_stake)
            .ok_or(VrfError::StakeOverflow)?;
    }

    if total == 0 {
        return Err(VrfError::ZeroTotalStake);
    }

    Ok(total)
}

/// Verifies a raw proposer VRF claim against a public key and stake weight.
pub fn verify_proposer(claim: ProposerClaim<'_>) -> Result<VrfOutput, VrfError> {
    if claim.stake == 0 {
        return Err(VrfError::ZeroValidatorStake);
    }
    if claim.total_stake == 0 {
        return Err(VrfError::ZeroTotalStake);
    }

    let public_key = parse_public_key(claim.public_key)?;
    let proof = parse_proof(claim.vrf_proof)?;
    let output = verify(
        &public_key,
        claim.chain_id,
        claim.finalized_seed,
        claim.slot,
        &proof,
    )
    .map_err(|_| VrfError::InvalidProof)?;

    if !is_eligible(
        &output,
        claim.stake,
        claim.total_stake,
        claim.expected_proposers_per_slot,
    ) {
        return Err(VrfError::NotEligible);
    }

    Ok(output)
}

/// Verifies the proposer VRF claim carried by a block header.
pub fn verify_header_proposer(
    header: &Header,
    active_set: &[Validator],
    chain_id: u64,
    finalized_seed: &Seed,
    expected_proposers_per_slot: FixedU128,
) -> Result<ProposerEligibility, VrfError> {
    let validator = active_validator(active_set, header.proposer_index)?;
    if validator.slashed {
        return Err(VrfError::SlashedValidator);
    }

    let total_stake = total_active_stake(active_set)?;
    let vrf_output = verify_proposer(ProposerClaim {
        public_key: &validator.pubkey,
        stake: validator.effective_stake,
        total_stake,
        chain_id,
        finalized_seed,
        slot: header.slot,
        vrf_proof: &header.vrf_proof,
        expected_proposers_per_slot,
    })?;

    Ok(ProposerEligibility {
        validator_index: header.proposer_index,
        vrf_output,
    })
}

/// Computes the next public seed from finalized VRF proof bytes in height order.
pub fn next_public_seed(prev_seed: &Seed, vrf_proofs: &[BlsSignature]) -> Seed {
    neutrino_vrf::fold_seed(prev_seed, vrf_proofs)
}

/// Computes the next public seed from finalized headers in canonical height order.
pub fn next_public_seed_from_headers(prev_seed: &Seed, headers: &[Header]) -> Seed {
    let proofs: Vec<BlsSignature> = headers.iter().map(|header| header.vrf_proof).collect();
    next_public_seed(prev_seed, &proofs)
}

/// Computes the public pseudo-random output used for aggregator selection.
pub fn aggregator_selection_output(
    seed: &Seed,
    chunk_id: ChunkId,
    round: u32,
    validator_index: ValidatorIndex,
) -> VrfOutput {
    let mut message = Vec::with_capacity(DOMAIN_AGG_PROOF.len() + seed.len() + 8 + 4 + 4);
    message.extend_from_slice(&DOMAIN_AGG_PROOF);
    message.extend_from_slice(seed);
    message.extend_from_slice(&chunk_id.to_le_bytes());
    message.extend_from_slice(&round.to_le_bytes());
    message.extend_from_slice(&validator_index.to_le_bytes());
    sha256(&message)
}

/// Computes Ethereum-style swap-or-not shuffling for one validator index.
///
/// Returns `None` when `validator_count == 0` or `index >= validator_count`.
/// For valid inputs this is a permutation over `0..validator_count`, so callers
/// can iterate source positions and map them into shuffled validator indices
/// without allocating the whole shuffled list.
pub fn compute_shuffled_index(
    index: ValidatorIndex,
    validator_count: ValidatorIndex,
    seed: &Seed,
) -> Option<ValidatorIndex> {
    if validator_count == 0 || index >= validator_count {
        return None;
    }

    let mut index = u64::from(index);
    let count = u64::from(validator_count);
    for round in 0..SHUFFLE_ROUND_COUNT {
        let pivot = shuffle_pivot(seed, round) % count;
        let flip = (pivot + count - index) % count;
        let position = index.max(flip);
        let source = shuffle_source(seed, round, position / 256);
        let byte = source[usize::try_from((position % 256) / 8).expect("byte index fits usize")];
        let bit = (byte >> (position % 8)) & 1;
        if bit == 1 {
            index = flip;
        }
    }

    Some(ValidatorIndex::try_from(index).expect("shuffled index remains below u32 count"))
}

/// Selects public chunk aggregators with the same stake-weighted threshold math.
///
/// Unlike proposer election, this selection is public: the shared finalized
/// seed plus `(chunk_id, round, validator_index)` gives every node the same
/// pseudo-random output for every active validator. Slashed and zero-stake
/// validators are ignored.
pub fn aggregator_committee(
    active_set: &[Validator],
    seed: &Seed,
    chunk_id: ChunkId,
    round: u32,
    expected_aggregators_per_round: FixedU128,
) -> Result<Vec<AggregatorSelection>, VrfError> {
    let total_stake = total_active_stake(active_set)?;
    let validator_count = ValidatorIndex::try_from(active_set.len()).map_err(|_| {
        VrfError::ValidatorIndexOverflow {
            len: active_set.len(),
        }
    })?;
    let mut selected = Vec::new();

    for source_index in 0..validator_count {
        let validator_index = compute_shuffled_index(source_index, validator_count, seed)
            .expect("source index is within validator count");
        let validator = &active_set
            [usize::try_from(validator_index).expect("u32 fits usize on supported targets")];
        if validator.slashed || validator.effective_stake == 0 {
            continue;
        }
        let selection_output = aggregator_selection_output(seed, chunk_id, round, validator_index);
        if is_eligible(
            &selection_output,
            validator.effective_stake,
            total_stake,
            expected_aggregators_per_round,
        ) {
            selected.push(AggregatorSelection {
                validator_index,
                selection_output,
            });
        }
    }

    Ok(selected)
}

fn shuffle_pivot(seed: &Seed, round: u8) -> u64 {
    let digest = shuffle_digest(seed, round, None);
    u64::from_le_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 digest has at least 8 bytes"),
    )
}

fn shuffle_source(seed: &Seed, round: u8, position_window: u64) -> Hash {
    let window =
        u32::try_from(position_window).expect("validator_count is u32, so position/256 fits u32");
    shuffle_digest(seed, round, Some(window))
}

fn shuffle_digest(seed: &Seed, round: u8, position_window: Option<u32>) -> Hash {
    let mut message = Vec::with_capacity(seed.len() + 1 + 4);
    message.extend_from_slice(seed);
    message.push(round);
    if let Some(position_window) = position_window {
        message.extend_from_slice(&position_window.to_le_bytes());
    }
    sha256(&message)
}

fn active_validator(
    active_set: &[Validator],
    index: ValidatorIndex,
) -> Result<&Validator, VrfError> {
    let position = usize::try_from(index).expect("u32 fits usize on supported targets");
    active_set
        .get(position)
        .ok_or(VrfError::ValidatorIndexOutOfBounds {
            index,
            len: active_set.len(),
        })
}

fn parse_public_key(public_key: &BlsPublicKey) -> Result<PublicKey, VrfError> {
    PublicKey::from_bytes(public_key).map_err(|_| VrfError::InvalidPublicKey)
}

fn parse_proof(vrf_proof: &BlsSignature) -> Result<Signature, VrfError> {
    Signature::from_bytes(vrf_proof).map_err(|_| VrfError::InvalidProof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_crypto::bls::SecretKey;
    use neutrino_primitives::{
        DEFAULT_EXPECTED_PROPOSERS_PER_SLOT, FIXED_U128_ONE, Validator, fixed_u128_from_integer,
    };
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const CHAIN_ID: u64 = 7;
    const SEED: Seed = [0x42; 32];
    const SLOT: Slot = 11;

    fn secret_key(seed: u64) -> SecretKey {
        let mut rng = StdRng::seed_from_u64(seed);
        SecretKey::generate(&mut rng)
    }

    fn validator(pubkey: BlsPublicKey, stake: u64) -> Validator {
        Validator {
            pubkey,
            withdrawal_credentials: [0x11; 32],
            effective_stake: stake,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }
    }

    fn header(proposer_index: ValidatorIndex, proof: BlsSignature) -> Header {
        Header {
            version: 1,
            height: 1,
            slot: SLOT,
            parent_hash: [0x01; 32],
            proposer_index,
            vrf_proof: proof,
            state_root: [0x02; 32],
            transactions_root: [0x03; 32],
            votes_root: [0x04; 32],
            slashings_root: [0x05; 32],
            validator_ops_root: [0x06; 32],
            da_root: [0x07; 32],
            runtime_extra: [0x08; 32],
            gas_used: 9,
            gas_limit: 10,
            timestamp: 12,
            signature: [0x09; 96],
        }
    }

    #[test]
    fn verify_header_accepts_valid_proposer() {
        let sk = secret_key(1);
        let pk = sk.public_key().to_bytes();
        let (proof, expected_output) = neutrino_vrf::eval(&sk, CHAIN_ID, &SEED, SLOT);
        let active_set = [validator(pk, 100)];
        let header = header(0, proof.to_bytes());

        let eligibility = verify_header_proposer(
            &header,
            &active_set,
            CHAIN_ID,
            &SEED,
            DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
        )
        .expect("valid proposer verifies");

        assert_eq!(eligibility.validator_index, 0);
        assert_eq!(eligibility.vrf_output, expected_output);
    }

    #[test]
    fn verify_header_rejects_wrong_seed() {
        let sk = secret_key(2);
        let pk = sk.public_key().to_bytes();
        let (proof, _) = neutrino_vrf::eval(&sk, CHAIN_ID, &SEED, SLOT);
        let mut wrong_seed = SEED;
        wrong_seed[0] ^= 0x01;
        let active_set = [validator(pk, 100)];
        let header = header(0, proof.to_bytes());

        assert_eq!(
            verify_header_proposer(
                &header,
                &active_set,
                CHAIN_ID,
                &wrong_seed,
                DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
            ),
            Err(VrfError::InvalidProof)
        );
    }

    #[test]
    fn verify_header_rejects_ineligible_output() {
        let sk = secret_key(3);
        let pk = sk.public_key().to_bytes();
        let (proof, _) = neutrino_vrf::eval(&sk, CHAIN_ID, &SEED, SLOT);
        let active_set = [validator(pk, 100)];
        let header = header(0, proof.to_bytes());

        assert_eq!(
            verify_header_proposer(&header, &active_set, CHAIN_ID, &SEED, 0),
            Err(VrfError::NotEligible)
        );
    }

    #[test]
    fn verify_header_rejects_slashed_or_missing_validator() {
        let sk = secret_key(4);
        let pk = sk.public_key().to_bytes();
        let (proof, _) = neutrino_vrf::eval(&sk, CHAIN_ID, &SEED, SLOT);
        let mut slashed = validator(pk, 100);
        slashed.slashed = true;

        assert_eq!(
            verify_header_proposer(
                &header(0, proof.to_bytes()),
                &[slashed],
                CHAIN_ID,
                &SEED,
                DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
            ),
            Err(VrfError::SlashedValidator)
        );
        assert!(matches!(
            verify_header_proposer(
                &header(1, proof.to_bytes()),
                &[validator(pk, 100)],
                CHAIN_ID,
                &SEED,
                DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
            ),
            Err(VrfError::ValidatorIndexOutOfBounds { index: 1, len: 1 })
        ));
    }

    #[test]
    fn seed_fold_from_headers_matches_proof_order() {
        let sk_a = secret_key(5);
        let sk_b = secret_key(6);
        let (proof_a, _) = neutrino_vrf::eval(&sk_a, CHAIN_ID, &SEED, SLOT);
        let (proof_b, _) = neutrino_vrf::eval(&sk_b, CHAIN_ID, &SEED, SLOT + 1);
        let header_a = header(0, proof_a.to_bytes());
        let header_b = header(1, proof_b.to_bytes());

        let folded = next_public_seed_from_headers(&SEED, &[header_a.clone(), header_b.clone()]);
        let direct = next_public_seed(&SEED, &[header_a.vrf_proof, header_b.vrf_proof]);
        let reversed = next_public_seed_from_headers(&SEED, &[header_b, header_a]);

        assert_eq!(folded, direct);
        assert_ne!(folded, reversed);
    }

    #[test]
    fn aggregator_output_binds_chunk_round_and_index() {
        let base = aggregator_selection_output(&SEED, 1, 2, 3);

        assert_ne!(base, aggregator_selection_output(&SEED, 2, 2, 3));
        assert_ne!(base, aggregator_selection_output(&SEED, 1, 3, 3));
        assert_ne!(base, aggregator_selection_output(&SEED, 1, 2, 4));
    }

    #[test]
    fn shuffled_index_is_a_seeded_permutation() {
        let count = 16;
        let mut shuffled: Vec<_> = (0..count)
            .map(|index| compute_shuffled_index(index, count, &SEED).expect("valid index"))
            .collect();
        let identity: Vec<_> = (0..count).collect();

        assert_ne!(shuffled, identity);
        shuffled.sort_unstable();
        assert_eq!(shuffled, identity);
        assert_eq!(compute_shuffled_index(count, count, &SEED), None);
        assert_eq!(compute_shuffled_index(0, 0, &SEED), None);
    }

    #[test]
    fn aggregator_committee_is_deterministic_and_filters_inactive_stake() {
        let pk = secret_key(7).public_key().to_bytes();
        let mut slashed = validator(pk, 50);
        slashed.slashed = true;
        let active_set = [
            validator(pk, 10),
            validator(pk, 20),
            validator(pk, 0),
            slashed,
        ];

        let first = aggregator_committee(&active_set, &SEED, 9, 1, fixed_u128_from_integer(4))
            .expect("committee selected");
        let second = aggregator_committee(&active_set, &SEED, 9, 1, fixed_u128_from_integer(4))
            .expect("committee selected");

        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].validator_index, 0);
        assert_eq!(first[1].validator_index, 1);
        assert!(
            first
                .iter()
                .all(|selection| selection.selection_output != [0xFF; 32])
        );
    }

    #[test]
    fn total_active_stake_rejects_empty_and_overflow() {
        let pk = secret_key(8).public_key().to_bytes();
        assert_eq!(total_active_stake(&[]), Err(VrfError::ZeroTotalStake));
        assert_eq!(
            total_active_stake(&[validator(pk, u64::MAX), validator(pk, 1)]),
            Err(VrfError::StakeOverflow)
        );
    }

    #[test]
    fn verify_proposer_rejects_zero_stake_and_bad_key() {
        let sk = secret_key(9);
        let (proof, _) = neutrino_vrf::eval(&sk, CHAIN_ID, &SEED, SLOT);
        let bad_key: BlsPublicKey = [0x00; 48];

        assert_eq!(
            verify_proposer(ProposerClaim {
                public_key: &sk.public_key().to_bytes(),
                stake: 0,
                total_stake: 100,
                chain_id: CHAIN_ID,
                finalized_seed: &SEED,
                slot: SLOT,
                vrf_proof: &proof.to_bytes(),
                expected_proposers_per_slot: FIXED_U128_ONE,
            }),
            Err(VrfError::ZeroValidatorStake)
        );
        assert_eq!(
            verify_proposer(ProposerClaim {
                public_key: &bad_key,
                stake: 100,
                total_stake: 100,
                chain_id: CHAIN_ID,
                finalized_seed: &SEED,
                slot: SLOT,
                vrf_proof: &proof.to_bytes(),
                expected_proposers_per_slot: FIXED_U128_ONE,
            }),
            Err(VrfError::InvalidPublicKey)
        );
    }
}
