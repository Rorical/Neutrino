//! M6-new exit criterion 3: invalid block-proof gossip does not
//! poison local fork choice.
//!
//! Single-node test that produces a real block (FSM at
//! `BlockState::BlockProduced`), then drives three classes of
//! adversarial input through `verify_and_import_block_proofs` — the
//! same backend method [`SyncDriver`](neutrino_sync::SyncDriver) calls
//! when handling a `Topic::BlockProofs` gossip message — and asserts:
//!
//! 1. Each adversarial input is rejected with `SyncBackendError::Rejected`.
//! 2. The block FSM stays at `BlockState::BlockProduced`.
//! 3. The node's `proven_height` does not advance.
//! 4. A subsequently submitted legitimate proof is accepted and
//!    advances the FSM to `BlockState::Proven` and the proven height
//!    to 1.
//!
//! Coverage matrix:
//!
//! | Class | Tamper | Engine error                          | Backend mapping |
//! | ----- | ------ | ------------------------------------- | --------------- |
//! | A     | `BlockProof.height`           | `BlockProofEnvelopeMismatch`   | `Rejected`      |
//! | B     | `public_inputs.state_root_after` | `BlockProofPublicInputsMismatch` | `Rejected` |
//! | C     | `proof_bytes`               | `InvalidBlockProof(_)`         | `Rejected`      |
//!
//! Borsh-decode failure (driver layer) is exercised by
//! `crates/sync/tests/driver_loop.rs` and is out of scope for the
//! backend-level checks here.

use std::sync::Arc;

use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{BlockState, Engine, ProposerKey};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    LightClientParams, ProofParams, RuntimeVersion, StateParams, Validator, ZERO_HASH,
    fixed_u128_from_integer,
};
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use neutrino_sync::{SyncBackend, SyncBackendError};

const CHAIN_ID: u64 = 314_159;
const GENESIS_SEED: [u8; 32] = [0xCD; 32];

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&[0xB2; 32], 0).expect("derive proposer")
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: [0; 32],
        effective_stake: 32_000_000_000,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }]
}

fn chain_spec() -> ChainSpec {
    let proof = ProofParams {
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators());
    let genesis_block_hash: BlockHash = [0xEE; 32];
    let checkpoint = Checkpoint {
        chain_id: CHAIN_ID,
        index: 0,
        start_height: 0,
        end_height: 0,
        start_block_hash: ZERO_HASH,
        end_block_hash: genesis_block_hash,
        start_state_root: ZERO_HASH,
        end_state_root: ZERO_HASH,
        end_validator_set_root: vs_root,
        history_root: ZERO_HASH,
        proof_system_version: proof.proof_system_version,
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"m6-new-bogus".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: [0xDD; 32],
        genesis_seed: GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        genesis_checkpoint: checkpoint,
        consensus,
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // Three tamper classes + recovery path are
// one test by design; splitting would lose
// the shared setup invariants.
async fn block_proof_gossip_rejects_bogus_proofs_without_poisoning_fork_choice() {
    let _ = tracing_subscriber::fmt::try_init();

    // ChainBackend with the real SP1 adapter (mock prover) and the
    // WASM executor — mirrors the production node binary.
    let backend = tokio::task::spawn_blocking(|| {
        let engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).expect("genesis");
        let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
        let backend = Arc::new(ChainBackend::new(engine, proof_system));
        let executor = WasmExecutor::default_runtime().expect("wasm runtime");
        backend.set_block_executor(executor);
        backend
    })
    .await
    .expect("spawn_blocking build backend");

    // Produce a real block at slot 1 (FSM: BlockProduced).
    let producer_backend = Arc::clone(&backend);
    let outcome = tokio::task::spawn_blocking(move || {
        producer_backend
            .try_produce_block(1, &proposer())
            .expect("try_produce_block")
            .expect("eligible")
    })
    .await
    .expect("spawn_blocking try_produce_block");
    assert_eq!(
        backend.block_state(&outcome.block_hash),
        Some(BlockState::BlockProduced),
        "block must start at BlockProduced before any proof import",
    );

    // Produce a legitimate proof to reuse as the basis for tamper
    // tests. We immediately roll back the FSM to BlockProduced after
    // generating it so each tamper class is tested from the same
    // starting state.
    let producer_backend = Arc::clone(&backend);
    let block_hash = outcome.block_hash;
    let legit_proof_outcome = tokio::task::spawn_blocking(move || {
        producer_backend
            .prove_block(&block_hash)
            .expect("prove_block")
    })
    .await
    .expect("spawn_blocking prove_block");
    let legit_proof = legit_proof_outcome.block_proof.clone();

    // After prove_block the FSM is at Proven; that's the "trusted"
    // post-state we want to compare against. For the tamper tests we
    // need the FSM back at BlockProduced so a rejected proof can be
    // observed as a non-advancement. The simplest way is to drop the
    // current store and reproduce the whole setup from scratch.
    let backend = tokio::task::spawn_blocking(|| {
        let engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).expect("genesis");
        let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
        let backend = Arc::new(ChainBackend::new(engine, proof_system));
        let executor = WasmExecutor::default_runtime().expect("wasm runtime");
        backend.set_block_executor(executor);
        backend
    })
    .await
    .expect("rebuild backend");

    let producer_backend = Arc::clone(&backend);
    let outcome = tokio::task::spawn_blocking(move || {
        producer_backend
            .try_produce_block(1, &proposer())
            .expect("try_produce_block")
            .expect("eligible")
    })
    .await
    .expect("spawn_blocking try_produce_block");
    assert_eq!(
        backend.block_state(&outcome.block_hash),
        Some(BlockState::BlockProduced),
        "rebuilt backend must start at BlockProduced",
    );
    assert_eq!(backend.local_progress().await.proven_height, 0);

    // ---- Class A: envelope tampering — wrong height -------------
    let mut bad_height = legit_proof.clone();
    bad_height.height = 42; // canonical height is 1
    let backend_clone = Arc::clone(&backend);
    let err_a = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("inner runtime");
        rt.block_on(backend_clone.verify_and_import_block_proofs(1, vec![bad_height]))
    })
    .await
    .expect("spawn_blocking import")
    .expect_err("tampered height must be rejected");
    assert!(
        matches!(err_a, SyncBackendError::Rejected(_)),
        "expected Rejected for wrong height, got {err_a:?}",
    );
    assert_eq!(
        backend.block_state(&outcome.block_hash),
        Some(BlockState::BlockProduced),
        "FSM must not advance after class A rejection",
    );
    assert_eq!(backend.local_progress().await.proven_height, 0);

    // ---- Class B: public-inputs tampering — wrong state_root_after
    let mut bad_inputs = legit_proof.clone();
    bad_inputs.public_inputs.state_root_after = [0xFF; 32];
    let backend_clone = Arc::clone(&backend);
    let err_b = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("inner runtime");
        rt.block_on(backend_clone.verify_and_import_block_proofs(1, vec![bad_inputs]))
    })
    .await
    .expect("spawn_blocking import")
    .expect_err("tampered public_inputs must be rejected");
    assert!(
        matches!(err_b, SyncBackendError::Rejected(_)),
        "expected Rejected for tampered public_inputs, got {err_b:?}",
    );
    assert_eq!(
        backend.block_state(&outcome.block_hash),
        Some(BlockState::BlockProduced),
        "FSM must not advance after class B rejection",
    );
    assert_eq!(backend.local_progress().await.proven_height, 0);

    // ---- Class C: proof-bytes tampering -------------------------
    // Flip a bit inside the opaque `proof_bytes` so the SP1 verifier
    // rejects the inner bundle. `MockProver::verify` does skip the
    // STARK check, but `Sp1ProofSystem::verify_block` still
    // `bincode`-decodes the bundle and cross-checks the committed
    // `StfPublicOutput`; corrupting the bundle bytes blows up the
    // bincode decode or the public-output cross-check.
    let mut bad_proof_bytes = legit_proof.clone();
    if let Some(first) = bad_proof_bytes.proof_bytes.first_mut() {
        *first ^= 0xFF;
    }
    let backend_clone = Arc::clone(&backend);
    let err_c = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("inner runtime");
        rt.block_on(backend_clone.verify_and_import_block_proofs(1, vec![bad_proof_bytes]))
    })
    .await
    .expect("spawn_blocking import")
    .expect_err("tampered proof_bytes must be rejected");
    assert!(
        matches!(err_c, SyncBackendError::Rejected(_)),
        "expected Rejected for tampered proof_bytes, got {err_c:?}",
    );
    assert_eq!(
        backend.block_state(&outcome.block_hash),
        Some(BlockState::BlockProduced),
        "FSM must not advance after class C rejection",
    );
    assert_eq!(backend.local_progress().await.proven_height, 0);

    // ---- Recovery: the legitimate proof still imports cleanly. ---
    // The block was never touched by the three rejections, so a
    // later honest re-publication advances the FSM and proven height
    // as if nothing happened. The block hash inside `legit_proof`
    // points at the same canonical block hash the rebuilt backend
    // re-produced, because `try_produce_block` is fully deterministic
    // for a fixed chain spec + proposer key + slot.
    assert_eq!(legit_proof.block_hash, outcome.block_hash);
    let backend_clone = Arc::clone(&backend);
    let legit = legit_proof.clone();
    let recovered = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("inner runtime");
        rt.block_on(backend_clone.verify_and_import_block_proofs(1, vec![legit]))
    })
    .await
    .expect("spawn_blocking import")
    .expect("legitimate proof must be accepted after rejections");
    assert_eq!(recovered.new_proven_height, 1);
    assert_eq!(
        backend.block_state(&outcome.block_hash),
        Some(BlockState::Proven),
        "FSM advances to Proven after the honest proof imports",
    );
    assert_eq!(backend.local_progress().await.proven_height, 1);
}
