//! Fixtures shared by the crate's unit tests.

#![allow(
    clippy::redundant_pub_crate,
    reason = "Test fixtures stay explicitly crate-scoped inside this private module."
)]

use alloc::vec::Vec;

use ed25519_dalek::SigningKey;
use neutrino_runtime_core::host::{LiveTrie, TracingState};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::{
    Address, EvidenceAnchor, RUNTIME_POLICY_KEY, RuntimePolicy, StfInput, StfPublicOutput,
    Validator, apply_block, encode_validator, validator_key,
};

/// Deterministic Ed25519 account key for `seed`.
pub(crate) fn signing_key(seed: u64) -> SigningKey {
    SigningKey::generate(&mut ChaCha20Rng::seed_from_u64(seed))
}

/// Apply `input` against a tracing view of `live` and return the output with
/// the committed post-state.
pub(crate) fn apply_against(live: &LiveTrie, input: &StfInput) -> (StfPublicOutput, LiveTrie) {
    let mut tracer = TracingState::new(live);
    let out = apply_block(input, &mut tracer);
    let (post, _witness) = tracer.into_committed_and_witness();
    (out, LiveTrie::from_trie(post))
}

/// The governable policy lives in state; seed the test trie with `policy`.
pub(crate) fn seed_policy(live: &mut LiveTrie, policy: &RuntimePolicy) {
    live.insert(RUNTIME_POLICY_KEY, borsh::to_vec(policy).unwrap());
}

/// Seed a runtime validator record, active exactly when it holds stake.
pub(crate) fn seed_validator(live: &mut LiveTrie, address: &Address, stake: u128) {
    live.insert(
        &validator_key(address),
        encode_validator(&Validator {
            stake,
            active: stake > 0,
        }),
    );
}

/// Empty block at height 2 for the evidence-admission tests.
pub(crate) fn evidence_input() -> StfInput {
    StfInput {
        evidence_anchor: EvidenceAnchor::default(),
        chain_id: 7,
        block_height: 2,
        block_gas_limit: 1_000_000,
        proposer_address: [0; 32],
        participation: None,
        transactions: Vec::new(),
    }
}
