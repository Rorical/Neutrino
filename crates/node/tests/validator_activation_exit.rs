//! Pending-fix #8: validator activation / exit epoch FSM.
//!
//! Drives the full lifecycle of a runtime-registered validator
//! through the rotation bridge:
//!
//! 1. **Registration.** A funded depositor submits a
//!    `Transaction::RegisterValidator` carrying the new validator's
//!    BLS pubkey + proof-of-possession. The runtime stores the
//!    registration; the bridge picks it up at the next chunk close.
//!
//! 2. **Activation FSM.** Newly-registered validators enter the
//!    consensus active set with `activation_epoch = current_epoch +
//!    activation_delay_epochs` and `effective_stake = 0` — every
//!    existing eligibility filter (`slashed || effective_stake ==
//!    0`) excludes them naturally. After `activation_delay_epochs`
//!    chunks (with `epoch_length_in_chunks = 1`), the bridge
//!    promotes them to their runtime stake.
//!
//! 3. **Exit FSM.** When a runtime-registered validator's stake
//!    drops to zero (via `Unstake` / `VoluntaryExit`), the bridge
//!    sets `exit_epoch = current_epoch + exit_delay_epochs` once.
//!    After the exit delay elapses, the same
//!    `effective_stake == 0` filter excludes them permanently.
//!
//! 4. **Bad-POP filtering.** Registrations whose BLS POP fails
//!    host-side verification never enter the consensus active set.
//!    The runtime accepts them (it has no BLS code path) but the
//!    bridge filters them at lift time.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_default_runtime_core::{
    Account, Address, RegisterValidatorTx, Transaction, UnstakeTx, ValidatorRegistrations,
    ValidatorSet, account_key, encode_account, register_validator_sig_message, unstake_sig_message,
};
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, LightClientParams,
    ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator, ZERO_HASH,
    fixed_u128_from_integer,
};
use neutrino_rpc::{BlockId, RpcBackend};
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sp1_sdk::blocking::MockProver;

const CHAIN_ID: u64 = 0xACE_BEEF;
const GENESIS_STAKE: u64 = 1_000_000_000;
const DEPOSIT_AMOUNT: u128 = 500_000;
const DEPOSITOR_FUNDING: u128 = 100_000_000;
const ACTIVATION_DELAY_EPOCHS: u64 = 2;
const EXIT_DELAY_EPOCHS: u64 = 2;
const EPOCH_LENGTH_IN_CHUNKS: u64 = 1;

type ActivationBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

fn ed25519_key(seed: u64) -> SigningKey {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    SigningKey::generate(&mut rng)
}

fn address_of(sk: &SigningKey) -> Address {
    sk.verifying_key().to_bytes()
}

fn proposer_key() -> ProposerKey {
    ProposerKey::from_ikm(&[0xA7; 32], 0).expect("derive proposer key")
}

/// Build a `ProposerKey` representing the BLS identity for a
/// runtime-registered validator. The IKM seed lets each test slot
/// the registered validator on a deterministic BLS key.
fn registered_bls_key(seed: u8) -> ProposerKey {
    // `validator_index` is meaningless for a not-yet-active
    // validator; the bridge assigns the real index when the
    // validator is lifted into the active set. Use `1` so it
    // differs from the chain-spec proposer's index of `0`.
    ProposerKey::from_ikm(&[seed; 32], 1).expect("derive registered BLS key")
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
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        // Single chain-spec validator stays VRF-eligible every slot
        // — keeps proposer rotation out of the test's concern.
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        epoch_length_in_chunks: EPOCH_LENGTH_IN_CHUNKS,
        activation_delay_epochs: ACTIVATION_DELAY_EPOCHS,
        exit_delay_epochs: EXIT_DELAY_EPOCHS,
        ..ConsensusParams::default()
    };
    let vs_root = neutrino_consensus_engine::validator_set_root(&validators);
    let genesis_block_hash = [0xCD; 32];
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
        name: BoundedBytes::new(b"act-exit".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: ZERO_HASH,
        genesis_seed: [0x4E; 32],
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

/// Seed the genesis trie with one funded account per `(addr,
/// balance)` pair. Used for the chain-spec validator (so it can
/// receive proposer fees) and the depositor.
fn seed_accounts(accounts: &[(Address, u128)]) -> LiveTrie {
    let mut live = LiveTrie::default();
    for (addr, balance) in accounts {
        let acct = Account {
            nonce: 0,
            balance: *balance,
        };
        live.insert(&account_key(addr), encode_account(&acct));
    }
    live
}

fn build_backend(accounts: &[(Address, u128)], proposer_addr: Address) -> Arc<ActivationBackend> {
    let live = seed_accounts(accounts);
    let state_root = live.state_root();
    let spec = build_chain_spec(proposer_addr, state_root);
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    engine.replace_state_with_reconstructed(live.trie().clone());
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    backend.set_block_executor(WasmExecutor::default_runtime().expect("wasm runtime"));
    backend.set_local_voter(proposer_key());
    backend
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
}

fn active_set(backend: &ActivationBackend) -> Vec<Validator> {
    rt().block_on(backend.active_validator_set())
}

fn query_validator_set(backend: &ActivationBackend) -> ValidatorSet {
    let resp = rt().block_on(async {
        backend
            .runtime_call("validator_set".to_string(), Vec::new(), &BlockId::Latest)
            .await
            .expect("runtime_call validator_set")
    });
    borsh::from_slice(&resp.payload).expect("decode ValidatorSet")
}

fn query_validator_registrations(backend: &ActivationBackend) -> ValidatorRegistrations {
    let resp = rt().block_on(async {
        backend
            .runtime_call(
                "validator_registrations".to_string(),
                Vec::new(),
                &BlockId::Latest,
            )
            .await
            .expect("runtime_call validator_registrations")
    });
    borsh::from_slice(&resp.payload).expect("decode ValidatorRegistrations")
}

/// Build a signed `RegisterValidator` tx funded by `depositor`,
/// binding the BLS pubkey + POP carried by `bls`.
fn signed_register_validator(
    depositor: &SigningKey,
    validator: Address,
    bls: &ProposerKey,
    deposit_amount: u128,
    nonce: u64,
) -> RegisterValidatorTx {
    let mut tx = RegisterValidatorTx {
        depositor: address_of(depositor),
        validator,
        bls_pubkey: *bls.public_key_bytes(),
        pop_signature: bls.prove_possession().to_bytes(),
        deposit_amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = depositor
        .sign(&register_validator_sig_message(CHAIN_ID, &tx))
        .to_bytes();
    tx
}

fn signed_unstake(sk: &SigningKey, amount: u128, nonce: u64) -> UnstakeTx {
    let mut tx = UnstakeTx {
        validator: address_of(sk),
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&unstake_sig_message(CHAIN_ID, &tx)).to_bytes();
    tx
}

/// Produce one block at `slot`, prove it, finalise its single-block
/// chunk (`chunk_size = 1`) and run the rotation bridge.
fn produce_prove_finalize_rotate(
    backend: &ActivationBackend,
    proposer: &ProposerKey,
    slot: u64,
    chunk_id: u64,
) {
    let outcome = backend
        .try_produce_block(slot, proposer)
        .expect("try_produce_block")
        .expect("validator eligible");
    backend
        .prove_block(&outcome.block_hash)
        .expect("prove_block");
    backend
        .finalize_chunk(chunk_id, proposer)
        .expect("finalize_chunk");
    backend
        .rotate_active_validator_set_for_chunk(chunk_id)
        .expect("rotation succeeds");
}

/// Find the entry in `active_set` whose `withdrawal_credentials`
/// equal `addr`. Panics if not found — the calling test pinned the
/// expectation.
fn find_by_addr(active_set: &[Validator], addr: Address) -> &Validator {
    active_set
        .iter()
        .find(|v| v.withdrawal_credentials == addr)
        .expect("validator address present in active set")
}

/// Shared scenario fixture: a chain with one chain-spec validator,
/// a funded depositor, and a runtime-registered validator that has
/// reached its `activation_epoch` and is producing effective stake.
/// Returns the backend after block 3 has been finalised so the new
/// validator is active.
fn build_activated_scenario(
    proposer: &ProposerKey,
    chain_spec_sk: &SigningKey,
    depositor: &SigningKey,
    new_validator: &SigningKey,
    new_bls: &ProposerKey,
) -> Arc<ActivationBackend> {
    let backend = build_backend(
        &[
            (address_of(chain_spec_sk), 0),
            (address_of(depositor), DEPOSITOR_FUNDING),
            // Pre-fund the new validator account so it can later
            // sign its own `Unstake` for the exit-FSM test.
            (address_of(new_validator), 1_000_000),
        ],
        address_of(chain_spec_sk),
    );

    // Block 1: submit + apply `RegisterValidator`.
    let register = Transaction::RegisterValidator(signed_register_validator(
        depositor,
        address_of(new_validator),
        new_bls,
        DEPOSIT_AMOUNT,
        0,
    ));
    backend
        .submit_transaction(borsh::to_vec(&register).expect("encode register"))
        .expect("admission accepts RegisterValidator");
    produce_prove_finalize_rotate(&backend, proposer, 1, 0);

    // Blocks 2 + 3: empty blocks; cross the activation epoch.
    produce_prove_finalize_rotate(&backend, proposer, 2, 1);
    produce_prove_finalize_rotate(&backend, proposer, 3, 2);

    backend
}

#[test]
fn register_validator_activates_after_delay() {
    let _ = tracing_subscriber::fmt::try_init();

    let chain_spec_sk = ed25519_key(0xA11);
    let depositor = ed25519_key(0xB22);
    let new_validator = ed25519_key(0xC33);
    let new_bls = registered_bls_key(0xC3);
    let proposer = proposer_key();

    let backend = build_backend(
        &[
            (address_of(&chain_spec_sk), 0),
            (address_of(&depositor), DEPOSITOR_FUNDING),
            (address_of(&new_validator), 1_000_000),
        ],
        address_of(&chain_spec_sk),
    );

    // Sanity: genesis active set carries just the chain-spec
    // validator at full stake.
    let active = active_set(&backend);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].withdrawal_credentials, address_of(&chain_spec_sk));
    assert_eq!(active[0].effective_stake, GENESIS_STAKE);
    assert_eq!(active[0].activation_epoch, 0);
    assert_eq!(active[0].exit_epoch, u64::MAX);

    // Block 1: submit RegisterValidator.
    let register = Transaction::RegisterValidator(signed_register_validator(
        &depositor,
        address_of(&new_validator),
        &new_bls,
        DEPOSIT_AMOUNT,
        0,
    ));
    backend
        .submit_transaction(borsh::to_vec(&register).expect("encode register"))
        .expect("admission accepts RegisterValidator");
    produce_prove_finalize_rotate(&backend, &proposer, 1, 0);

    // Runtime accepted the registration:
    let rt_set = query_validator_set(&backend);
    assert!(
        rt_set
            .entries
            .iter()
            .any(|e| e.address == address_of(&new_validator) && e.stake == DEPOSIT_AMOUNT),
        "runtime validator_set must contain the new validator at the deposited stake",
    );
    let registrations = query_validator_registrations(&backend);
    assert_eq!(registrations.entries.len(), 1);
    assert_eq!(
        registrations.entries[0].bls_pubkey,
        *new_bls.public_key_bytes()
    );

    // Bridge ran. Current epoch after chunk 0 = (0+1)/1 = 1.
    // New validator: activation_epoch = 1 + 2 = 3, effective_stake = 0.
    let active = active_set(&backend);
    assert_eq!(active.len(), 2, "rotation must add the new validator");
    let new_entry = find_by_addr(&active, address_of(&new_validator));
    assert_eq!(new_entry.activation_epoch, 3);
    assert_eq!(new_entry.exit_epoch, u64::MAX);
    assert_eq!(
        new_entry.effective_stake, 0,
        "pre-activation effective_stake must be zero"
    );
    assert_eq!(new_entry.pubkey, *new_bls.public_key_bytes());

    // Block 2: still pre-activation (current_epoch = 2 < 3).
    produce_prove_finalize_rotate(&backend, &proposer, 2, 1);
    let active = active_set(&backend);
    assert_eq!(
        find_by_addr(&active, address_of(&new_validator)).effective_stake,
        0,
    );

    // Block 3: crosses activation epoch (current_epoch = 3).
    produce_prove_finalize_rotate(&backend, &proposer, 3, 2);
    let active = active_set(&backend);
    let new_entry = find_by_addr(&active, address_of(&new_validator));
    assert_eq!(
        new_entry.effective_stake,
        u64::try_from(DEPOSIT_AMOUNT).unwrap(),
        "current_epoch >= activation_epoch → effective_stake = runtime stake",
    );
    assert_eq!(new_entry.exit_epoch, u64::MAX, "no exit scheduled");
}

#[test]
fn registered_validator_exits_after_unstake() {
    let _ = tracing_subscriber::fmt::try_init();

    let chain_spec_sk = ed25519_key(0xA12);
    let depositor = ed25519_key(0xB23);
    let new_validator = ed25519_key(0xC34);
    let new_bls = registered_bls_key(0xC4);
    let proposer = proposer_key();

    let backend = build_activated_scenario(
        &proposer,
        &chain_spec_sk,
        &depositor,
        &new_validator,
        &new_bls,
    );

    // Block 4: validator drains their full deposit. Runtime removes
    // them from the set; bridge's pass-1 exit FSM engages.
    let unstake = Transaction::Unstake(signed_unstake(&new_validator, DEPOSIT_AMOUNT, 0));
    backend
        .submit_transaction(borsh::to_vec(&unstake).expect("encode unstake"))
        .expect("admission accepts unstake");
    produce_prove_finalize_rotate(&backend, &proposer, 4, 3);

    // Runtime confirms the validator is gone.
    let rt_set = query_validator_set(&backend);
    assert!(
        rt_set
            .entries
            .iter()
            .all(|e| e.address != address_of(&new_validator)),
        "runtime validator_set drops zero-stake validators",
    );

    // Bridge: current_epoch = 4, exit_epoch = 4 + 2 = 6,
    // effective_stake immediately 0 (stake disappears, exit_epoch
    // is for record-keeping only).
    let active = active_set(&backend);
    let new_entry = find_by_addr(&active, address_of(&new_validator));
    assert_eq!(new_entry.exit_epoch, 6, "exit_epoch = current + delay");
    assert_eq!(
        new_entry.effective_stake, 0,
        "runtime_stake == 0 → effective_stake = 0 immediately",
    );

    // Block 5: exit is one-shot — second rotation must not rewrite.
    produce_prove_finalize_rotate(&backend, &proposer, 5, 4);
    let active = active_set(&backend);
    let new_entry = find_by_addr(&active, address_of(&new_validator));
    assert_eq!(new_entry.exit_epoch, 6, "exit_epoch must be one-shot");

    // Block 6: crosses exit_epoch (current_epoch = 6 = exit_epoch).
    produce_prove_finalize_rotate(&backend, &proposer, 6, 5);
    let active = active_set(&backend);
    let new_entry = find_by_addr(&active, address_of(&new_validator));
    assert_eq!(new_entry.exit_epoch, 6, "exit_epoch stable");
    assert_eq!(
        new_entry.effective_stake, 0,
        "current_epoch >= exit_epoch → permanently filtered",
    );

    // Chain-spec validator must be untouched by the FSM throughout
    // (they never enter the auto-exit path because activation_epoch
    // == 0 is the discriminator).
    let chain_entry = find_by_addr(&active, address_of(&chain_spec_sk));
    assert_eq!(chain_entry.activation_epoch, 0);
    assert_eq!(chain_entry.exit_epoch, u64::MAX);
    assert_eq!(chain_entry.effective_stake, GENESIS_STAKE);
}

#[test]
fn register_validator_with_invalid_pop_is_filtered_at_bridge() {
    let _ = tracing_subscriber::fmt::try_init();

    let chain_spec_signer = ed25519_key(0xD11);
    let chain_spec_addr = address_of(&chain_spec_signer);
    let depositor = ed25519_key(0xE22);
    let depositor_addr = address_of(&depositor);
    let bad_validator = ed25519_key(0xF33);
    let bad_validator_addr = address_of(&bad_validator);
    let valid_bls = registered_bls_key(0xF3);
    let attacker_bls = registered_bls_key(0xAA);

    let backend = build_backend(
        &[(chain_spec_addr, 0), (depositor_addr, DEPOSITOR_FUNDING)],
        chain_spec_addr,
    );
    let proposer = proposer_key();

    // Build a `RegisterValidator` whose POP is forged: the POP
    // signature is generated by `attacker_bls` but bound to
    // `valid_bls.public_key_bytes()`. `PublicKey::verify_pop` will
    // reject this — the signed payload doesn't match the claimed
    // pubkey.
    let valid_pubkey = *valid_bls.public_key_bytes();
    let attacker_pop = attacker_bls.prove_possession().to_bytes();
    let mut tx = RegisterValidatorTx {
        depositor: depositor_addr,
        validator: bad_validator_addr,
        bls_pubkey: valid_pubkey,
        pop_signature: attacker_pop,
        deposit_amount: DEPOSIT_AMOUNT,
        nonce: 0,
        signature: [0u8; 64],
    };
    tx.signature = depositor
        .sign(&register_validator_sig_message(CHAIN_ID, &tx))
        .to_bytes();
    let register = Transaction::RegisterValidator(tx);
    let bytes = borsh::to_vec(&register).expect("encode register");

    backend
        .submit_transaction(bytes)
        .expect("admission accepts (runtime doesn't verify POP)");

    produce_prove_finalize_rotate(&backend, &proposer, 1, 0);

    // The runtime stored the registration:
    let registrations = query_validator_registrations(&backend);
    assert_eq!(
        registrations.entries.len(),
        1,
        "runtime accepts the registration regardless of POP validity"
    );

    // …but the consensus active set must NOT contain this
    // validator. The bridge verified the POP and dropped them.
    let active = active_set(&backend);
    assert_eq!(
        active.len(),
        1,
        "bridge must filter bad-POP registrations from the active set"
    );
    assert_eq!(active[0].withdrawal_credentials, chain_spec_addr);
    assert!(
        active.iter().all(|v| v.pubkey != valid_pubkey),
        "the claimed BLS pubkey must not appear in the active set",
    );
}
