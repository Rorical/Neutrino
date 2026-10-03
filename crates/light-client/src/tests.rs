use super::*;
use neutrino_consensus_types::history_proof::{
    ConsensusBoundary, ExecutionPrograms, HistoryStatement,
};
use neutrino_primitives::BoundedBytes;

struct Verifier(bool);
impl HistoryVerifier for Verifier {
    type Error = ();
    fn verify_history(&self, _: &HistoryProof, _: &ProofDomain) -> Result<(), ()> {
        if self.0 { Ok(()) } else { Err(()) }
    }
}
fn boundary(n: u64) -> ConsensusBoundary {
    ConsensusBoundary {
        next_chunk_id: n,
        height: n,
        block_hash: [1; 32],
        state_root: [2; 32],
        slot: n,
        validators_root: [3; 32],
        seed: [4; 32],
        history_root: [5; 32],
    }
}
fn client() -> LightClient {
    LightClient {
        checkpoint: Checkpoint {
            domain: ProofDomain {
                chain: ChainBinding {
                    chain_id: 1,
                    chain_spec_hash: [1; 32],
                    chunk_size: 1,
                    runtime_code_hash: [2; 32],
                    gas_price: 0,
                },
                execution: ExecutionPrograms {
                    fact: [1; 8],
                    evidence: [2; 8],
                    block: [3; 8],
                },
                chunk: [4; 8],
                checkpoint: [5; 8],
            },
            boundary: boundary(1),
        },
        genesis_time: 100,
        slot_duration_secs: 10,
        weak_subjectivity_period_secs: 100,
        stale_threshold_secs: 30,
        max_future_drift_secs: 2,
        anchor_expires_at: 210,
    }
}
fn proof(start: u64, end: u64) -> HistoryProof {
    HistoryProof {
        statement: HistoryStatement {
            domain: client().checkpoint.domain,
            start: boundary(start),
            end: boundary(end),
        },
        receipt: BoundedBytes::new(alloc::vec![1]).unwrap(),
    }
}
#[test]
fn advancement_is_authenticated_and_replay_does_not_refresh_expiry() {
    let mut client = client();
    let receipt = proof(1, 2);
    let target = receipt.statement.end_checkpoint().hash();
    let before = client.clone();
    assert_eq!(
        client.accept(&receipt, target, 120, &Verifier(false)),
        Err(LightClientError::Verification)
    );
    assert_eq!(client, before);
    assert_eq!(
        client.accept(&receipt, target, 120, &Verifier(true)),
        Ok(UpdateOutcome::Advanced)
    );
    let after = client.clone();
    assert_eq!(
        client.accept(&receipt, target, 130, &Verifier(true)),
        Ok(UpdateOutcome::AlreadyCurrent)
    );
    assert_eq!(client, after);
    assert_eq!(
        client.accept(&receipt, target, 220, &Verifier(true)),
        Err(LightClientError::Expired)
    );
}
#[test]
fn prefix_cannot_replace_an_existing_anchor() {
    let mut client = client();
    let prefix = proof(0, 3);
    assert_eq!(
        client.accept(
            &prefix,
            prefix.statement.end_checkpoint().hash(),
            130,
            &Verifier(true)
        ),
        Err(LightClientError::NotExtension)
    );
    let mut conflict = proof(0, 1);
    conflict.statement.end.block_hash = [99; 32];
    assert_eq!(
        client.accept(
            &conflict,
            conflict.statement.end_checkpoint().hash(),
            110,
            &Verifier(true)
        ),
        Err(LightClientError::Conflict)
    );
}
#[test]
fn domain_target_clock_and_expiry_fail_without_mutation() {
    let mut client = client();
    let before = client.clone();
    let receipt = proof(1, 2);
    let target = receipt.statement.end_checkpoint().hash();
    assert_eq!(
        client.accept(&receipt, target, 110, &Verifier(true)),
        Err(LightClientError::Future)
    );
    assert_eq!(
        client.accept(&receipt, target, 160, &Verifier(true)),
        Err(LightClientError::Stale)
    );
    assert_eq!(
        client.accept(&receipt, [99; 32], 120, &Verifier(true)),
        Err(LightClientError::UnexpectedTarget)
    );
    let mut wrong = receipt;
    wrong.statement.domain.checkpoint = [8; 8];
    assert_eq!(
        client.accept(
            &wrong,
            wrong.statement.end_checkpoint().hash(),
            120,
            &Verifier(true)
        ),
        Err(LightClientError::Domain)
    );
    assert_eq!(client, before);
}

fn spec() -> neutrino_primitives::ChainSpec {
    use neutrino_primitives::{
        BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
        RuntimeParams, StateParams, Validator,
    };
    let validators = alloc::vec![Validator {
        pubkey: [1; 48],
        withdrawal_credentials: [2; 32],
        effective_stake: 1,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0
    }];
    ChainSpec {
        name: BoundedBytes::new(alloc::vec![]).unwrap(),
        chain_id: 1,
        genesis_time: 100,
        genesis_gas_limit: 1,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [2; 32],
        genesis_seed: [4; 32],
        genesis_state_root: [2; 32],
        genesis_block_hash: [1; 32],
        genesis_validator_set_root: neutrino_primitives::blake3_256(
            &borsh::to_vec(&validators).unwrap(),
        ),
        consensus: ConsensusParams {
            slot_duration_secs: 10,
            chunk_size: 1,
            ..ConsensusParams::default()
        },
        proof: ProofParams {
            slot_budget_per_chunk: 1,
            ..ProofParams::default()
        },
        state: StateParams::default(),
        light_client: LightClientParams {
            weak_subjectivity_period_secs: 100,
            anchor_interval_chunks: 1,
            stale_threshold_secs: 30,
        },
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(alloc::vec![]).unwrap(),
    }
}

#[test]
fn persistent_snapshot_does_not_renew_trust_on_restart() {
    let spec = spec();
    let mut original = client();
    original.checkpoint.domain.chain = ChainBinding::from_spec(&spec);
    let bytes = borsh::to_vec(&original.snapshot()).unwrap();
    let saved: LightClientSnapshot = borsh::from_slice(&bytes).unwrap();
    let mut restored = LightClient::restore(&spec, &original.checkpoint.domain, &saved, 2).unwrap();
    assert_eq!(restored, original);
    let receipt = proof(1, 2);
    assert_eq!(
        restored.accept(
            &receipt,
            receipt.statement.end_checkpoint().hash(),
            saved.anchor_expires_at,
            &Verifier(true)
        ),
        Err(LightClientError::Expired)
    );
    let mut wrong = saved;
    wrong.checkpoint.domain.checkpoint = [99; 8];
    assert_eq!(
        LightClient::restore(&spec, &original.checkpoint.domain, &wrong, 2),
        Err(LightClientError::Domain)
    );
}

#[test]
fn genesis_bootstrap_checks_all_boundary_lanes() {
    let spec = spec();
    let mut anchor = client().checkpoint;
    anchor.domain.chain = ChainBinding::from_spec(&spec);
    anchor.boundary = ConsensusBoundary::genesis(&spec);
    assert!(LightClient::new(&spec, anchor, spec.genesis_time, 2).is_ok());
    anchor.boundary.history_root = [99; 32];
    assert_eq!(
        LightClient::new(&spec, anchor, spec.genesis_time, 2),
        Err(LightClientError::InvalidAnchor)
    );
}
