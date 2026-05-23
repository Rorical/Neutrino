//! Pending-fix #1: cross-layer validator-set rotation.
//!
//! The default runtime tracks its own `ValidatorSet` keyed by 32-byte
//! addresses; the consensus layer tracks a `Vec<Validator>` keyed by
//! BLS pubkeys. Without an active bridge, runtime stake mutations
//! (deposits, slashes, inactivity leaks) never affect consensus
//! proposer eligibility or BFT quorum weighting.
//!
//! This test stands up a single-validator backend whose consensus
//! validator's `withdrawal_credentials` equals an Ed25519 signing
//! key's pubkey. It then drives:
//!
//! 1. Genesis: the consensus active set has the validator at the
//!    chain-spec's `effective_stake = 1_000_000_000`. The runtime's
//!    own validator set is empty (chain-spec validators are not
//!    auto-registered through the runtime).
//! 2. Block 1: a `Transaction::Stake(validator, 250_000)` signed by
//!    the validator's key registers the validator in the runtime's
//!    set with `stake = 250_000`.
//! 3. Chunk 0 finalises. `ChainBackend::handle_quorum_reached`
//!    invokes the rotation bridge, which queries the runtime's
//!    `validator_set`, joins onto the existing consensus active set,
//!    and writes the new snapshot.
//! 4. After rotation, `Engine::active_validator_set()[0].effective_stake
//!    == 250_000` — the runtime-side stake overrides the genesis
//!    chain-spec value, exactly as it would after a real validator
//!    onboarding or slash event.
//!
//! Acceptance: the BFT-quorum + VRF-eligibility calculations now
//! observe the runtime's stake distribution.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_default_runtime_core::{
    Account, Address, StakeTx, Transaction, account_key, encode_account, stake_sig_message,
};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, LightClientParams,
    ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator, ZERO_HASH,
    fixed_u128_from_integer,
};
use neutrino_rpc::RpcBackend;
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sp1_sdk::blocking::MockProver;

const CHAIN_ID: u64 = 9_191_919;
const GENESIS_STAKE: u64 = 1_000_000_000;
const RUNTIME_STAKE: u128 = 250_000;
const FUNDING: u128 = 10_000_000;

type RotationBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

fn validator_signing_key() -> SigningKey {
    let mut rng = ChaCha20Rng::seed_from_u64(0xC0_FFEE);
    SigningKey::generate(&mut rng)
}

fn validator_address(sk: &SigningKey) -> Address {
    sk.verifying_key().to_bytes()
}

fn proposer_key() -> ProposerKey {
    ProposerKey::from_ikm(&[0x77; 32], 0).expect("derive proposer")
}

fn chain_spec_validators(runtime_addr: Address) -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer_key().public_key_bytes(),
        withdrawal_credentials: runtime_addr,
        effective_stake: GENESIS_STAKE,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }]
}

fn build_chain_spec(runtime_addr: Address, genesis_state_root: [u8; 32]) -> ChainSpec {
    let validators = chain_spec_validators(runtime_addr);
    let proof = ProofParams {
        // `chunk_size = 1` lets a single produced block close chunk 0
        // immediately so the rotation bridge runs without driving
        // multiple slots.
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        // Inflated proposer-expectation keeps the single validator
        // VRF-eligible for slot 1 regardless of finalized-seed entropy.
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    let vs_root = neutrino_consensus_engine::validator_set_root(&validators);
    let genesis_block_hash = [0xCC; 32];
    let checkpoint = Checkpoint {
        chain_id: CHAIN_ID,
        index: 0,
        start_height: 0,
        end_height: 0,
        start_block_hash: ZERO_HASH,
        end_block_hash: genesis_block_hash,
        start_state_root: ZERO_HASH,
        end_state_root: genesis_state_root,
        end_validator_set_root: vs_root,
        history_root: ZERO_HASH,
        proof_system_version: proof.proof_system_version,
    };
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"rotation-test".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: ZERO_HASH,
        genesis_seed: [0xAB; 32],
        genesis_state_root,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        genesis_checkpoint: checkpoint,
        consensus,
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

fn seed_validator_account(addr: Address, balance: u128) -> LiveTrie {
    let mut live = LiveTrie::default();
    let account = Account { nonce: 0, balance };
    live.insert(&account_key(&addr), encode_account(&account));
    live
}

fn build_backend(runtime_addr: Address) -> Arc<RotationBackend> {
    let live = seed_validator_account(runtime_addr, FUNDING);
    let state_root = live.state_root();
    let spec = build_chain_spec(runtime_addr, state_root);
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    engine.replace_state_with_reconstructed(live.trie().clone());
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    backend.set_block_executor(WasmExecutor::default_runtime().expect("wasm runtime"));
    backend.set_local_voter(proposer_key());
    backend
}

/// Minimal tokio runtime for the one async helper this test needs
/// (`RpcBackend::active_validator_set`). Mirrors the pattern in
/// `full_lifecycle.rs`.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
}

fn active_set(backend: &RotationBackend) -> Vec<Validator> {
    rt().block_on(backend.active_validator_set())
}

fn sign_stake(sk: &SigningKey, amount: u128, nonce: u64) -> StakeTx {
    let mut tx = StakeTx {
        validator: validator_address(sk),
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&stake_sig_message(CHAIN_ID, &tx)).to_bytes();
    tx
}

#[test]
fn finalize_chunk_rotates_consensus_active_set_to_runtime_stake() {
    let _ = tracing_subscriber::fmt::try_init();

    let sk = validator_signing_key();
    let runtime_addr = validator_address(&sk);
    let backend = build_backend(runtime_addr);
    let proposer = proposer_key();

    // -- 1. Sanity: genesis active set carries the chain-spec stake.
    let pre_rotation = active_set(&backend);
    assert_eq!(
        pre_rotation[0].effective_stake, GENESIS_STAKE,
        "genesis active set must carry the chain-spec effective_stake",
    );

    // -- 2. Block 1: a runtime Stake transaction registers the
    //       validator in the runtime's validator-set storage with
    //       `stake = RUNTIME_STAKE` (well below the genesis value, so
    //       a successful rotation visibly *decreases* the consensus
    //       effective_stake — the easiest signal to distinguish from
    //       "rotation never ran").
    let stake_tx = Transaction::Stake(sign_stake(&sk, RUNTIME_STAKE, 0));
    let stake_bytes = borsh::to_vec(&stake_tx).expect("encode stake");
    backend
        .submit_transaction(stake_bytes)
        .expect("admission accepts stake");

    let outcome = backend
        .try_produce_block(1, &proposer)
        .expect("produce")
        .expect("validator eligible for slot 1");
    let _proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove block 1");
    // The block touches the validator-set storage so its
    // runtime-emitted root differs from the parent's — the import-side
    // `runtime_extra` check exempts non-empty bodies for exactly this
    // reason.
    assert_ne!(
        outcome.block.header.runtime_extra, ZERO_HASH,
        "stake tx mutates the runtime validator_set root",
    );

    // -- 3. Close chunk 0 and run the rotation bridge. This mirrors
    //       what `producer::close_due_chunks` does in the live node
    //       binary after every chunk-finalize success.
    let _finalize = backend
        .finalize_chunk(0, &proposer)
        .expect("finalize chunk 0");
    backend
        .rotate_active_validator_set_for_chunk(0)
        .expect("rotation succeeds");

    // -- 4. Acceptance: the consensus active set now reflects the
    //       runtime's stake. A node querying VRF eligibility or the
    //       BFT quorum threshold for chunk 1 will observe the new
    //       stake distribution.
    let post_rotation = active_set(&backend);
    assert_eq!(
        post_rotation[0].effective_stake,
        u64::try_from(RUNTIME_STAKE).expect("RUNTIME_STAKE fits u64"),
        "rotation must copy the runtime's stake into the consensus active set",
    );
    assert_eq!(
        post_rotation[0].last_active_chunk, 1,
        "rotation must bump last_active_chunk to chunk_id + 1",
    );
    assert_eq!(
        post_rotation[0].pubkey,
        *proposer_key().public_key_bytes(),
        "rotation must preserve the consensus BLS pubkey",
    );
}

#[test]
fn rotation_is_a_noop_when_runtime_set_is_empty() {
    // A chain that has not yet seen any runtime staking activity
    // should leave the consensus active set untouched. The bridge
    // joins on `withdrawal_credentials`; an empty runtime set
    // produces no matches, so every consensus validator keeps its
    // genesis `effective_stake`.
    let _ = tracing_subscriber::fmt::try_init();

    let sk = validator_signing_key();
    let runtime_addr = validator_address(&sk);
    let backend = build_backend(runtime_addr);
    let proposer = proposer_key();

    // Produce an empty block. With chunk_size = 1 it closes chunk 0
    // immediately. The runtime has no validator_set entries because
    // no Stake / Deposit transaction has been included.
    let outcome = backend
        .try_produce_block(1, &proposer)
        .expect("produce")
        .expect("validator eligible for slot 1");
    let _proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove empty block");
    let _finalize = backend
        .finalize_chunk(0, &proposer)
        .expect("finalize chunk 0");
    backend
        .rotate_active_validator_set_for_chunk(0)
        .expect("rotation succeeds");

    let set = active_set(&backend);
    assert_eq!(
        set[0].effective_stake, GENESIS_STAKE,
        "empty runtime set must leave the chain-spec stake untouched",
    );
}
