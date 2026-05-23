//! Mempool admission + gas accounting end-to-end coverage.
//!
//! Exercises the WASM `_neutrino_validate_tx` path through
//! [`ChainBackend::submit_transaction`], then drives the producer's
//! drain → execute → `header.gas_used` loop to confirm the runtime's
//! gas figure flows into the consensus header (and from there into
//! the SP1 proof's public inputs).

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_default_runtime_core::{
    Account, Address, GAS_TRANSFER, SlashTx, Transaction, TransferTx, account_key, encode_account,
    transfer_sig_message,
};
use neutrino_mempool::InsertError;
use neutrino_node::ChainBackend;
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, LightClientParams,
    ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator, ZERO_HASH,
    fixed_u128_from_integer,
};
use neutrino_runtime_core::host::LiveTrie;
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrino_storage::MemoryDatabase;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const CHAIN_ID: u64 = 99;

fn signing_key(seed: u64) -> SigningKey {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    SigningKey::generate(&mut rng)
}

fn address_of(sk: &SigningKey) -> Address {
    sk.verifying_key().to_bytes()
}

fn signed_transfer(
    sk: &SigningKey,
    to: Address,
    amount: u128,
    nonce: u64,
    chain_id: u64,
) -> TransferTx {
    let mut tx = TransferTx {
        from: address_of(sk),
        to,
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&transfer_sig_message(chain_id, &tx)).to_bytes();
    tx
}

fn proposer_key() -> ProposerKey {
    ProposerKey::from_ikm(&[0xA1; 32], 0).expect("derive proposer")
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer_key().public_key_bytes(),
        withdrawal_credentials: [0; 32],
        effective_stake: 32_000_000_000,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }]
}

/// Build a chain spec whose `genesis_state_root` matches a trie that
/// already carries `alice`'s pre-funded account, so the integration
/// test can submit a valid transfer immediately at slot 1.
fn seeded_chain_spec_and_trie(alice_addr: Address, balance: u128) -> (ChainSpec, LiveTrie) {
    let mut live = LiveTrie::default();
    live.insert(
        &account_key(&alice_addr),
        encode_account(&Account { nonce: 0, balance }),
    );
    let state_root = live.state_root();

    let vs_root = neutrino_consensus_engine::validator_set_root(&validators());
    let genesis_block_hash = [0xCC; 32];
    let proof = ProofParams {
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    // The canonical genesis checkpoint mandates `start_state_root =
    // ZERO_HASH` and `end_state_root = genesis_state_root`. The
    // engine's `replace_state_with_reconstructed` only checks that
    // the supplied trie's root equals `head_state_root` (which the
    // engine seeds from `genesis_state_root`), so the genesis
    // checkpoint stays canonical even as we install Alice's
    // pre-funded account.
    let checkpoint = Checkpoint {
        chain_id: CHAIN_ID,
        index: 0,
        start_height: 0,
        end_height: 0,
        start_block_hash: ZERO_HASH,
        end_block_hash: genesis_block_hash,
        start_state_root: ZERO_HASH,
        end_state_root: state_root,
        end_validator_set_root: vs_root,
        history_root: ZERO_HASH,
        proof_system_version: proof.proof_system_version,
    };
    let spec = ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"mempool-admission".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: [0xDD; 32],
        genesis_seed: [0xAB; 32],
        genesis_state_root: state_root,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        genesis_checkpoint: checkpoint,
        consensus,
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    };
    (spec, live)
}

fn seeded_backend(
    alice_addr: Address,
    balance: u128,
) -> Arc<ChainBackend<MemoryDatabase, Sp1ProofSystem<sp1_sdk::blocking::MockProver>>> {
    let (spec, live) = seeded_chain_spec_and_trie(alice_addr, balance);
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    // Snap-sync style hydration: drop the pre-built trie into the
    // engine so the production path sees Alice's funded account.
    engine.replace_state_with_reconstructed(live.trie().clone());
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    backend.set_block_executor(WasmExecutor::default_runtime().expect("wasm runtime"));
    backend
}

#[test]
fn submit_transaction_rejects_malformed_payload() {
    let alice = signing_key(1);
    let backend = seeded_backend(address_of(&alice), 100);
    // Random bytes that aren't a borsh-encoded Transaction.
    let err = backend
        .submit_transaction(vec![0xFF, 0xFF, 0xFF])
        .expect_err("malformed bytes must be rejected");
    assert_eq!(err, InsertError::RejectedByValidator);
    assert_eq!(backend.mempool_len(), 0);
}

#[test]
fn submit_transaction_rejects_consensus_driven_slash() {
    let alice = signing_key(2);
    let backend = seeded_backend(address_of(&alice), 100);
    // Slash transactions are consensus-driven; admission must refuse
    // them with the Unauthorized rejection code so a malicious peer
    // cannot inject one through gossip or RPC.
    let slash = Transaction::Slash(SlashTx {
        validator: [0xFF; 32],
        amount: 10,
    });
    let bytes = borsh::to_vec(&slash).expect("encode tx");
    let err = backend
        .submit_transaction(bytes)
        .expect_err("Slash must be rejected by admission");
    assert_eq!(err, InsertError::RejectedByValidator);
    assert_eq!(backend.mempool_len(), 0);
}

#[test]
fn submit_transaction_rejects_insufficient_balance() {
    let alice = signing_key(3);
    let backend = seeded_backend(address_of(&alice), 10); // only 10 units
    let tx = Transaction::Transfer(signed_transfer(
        &alice, [0xAB; 32], 50, // more than balance
        0, CHAIN_ID,
    ));
    let bytes = borsh::to_vec(&tx).expect("encode tx");
    let err = backend
        .submit_transaction(bytes)
        .expect_err("insufficient balance must be rejected");
    assert_eq!(err, InsertError::RejectedByValidator);
    assert_eq!(backend.mempool_len(), 0);
}

#[test]
fn submit_transaction_admits_valid_transfer_and_block_charges_gas() {
    let alice = signing_key(4);
    let alice_addr = address_of(&alice);
    let bob_addr = [0xBB; 32];
    let backend = seeded_backend(alice_addr, 100);

    // Admit a valid transfer.
    let tx = Transaction::Transfer(signed_transfer(&alice, bob_addr, 30, 0, CHAIN_ID));
    let bytes = borsh::to_vec(&tx).expect("encode tx");
    backend
        .submit_transaction(bytes.clone())
        .expect("valid transfer admits");
    assert_eq!(
        backend.mempool_len(),
        1,
        "admitted tx must land in the mempool",
    );

    // Duplicate admission is rejected at the pool layer, not the
    // runtime layer.
    let err = backend
        .submit_transaction(bytes)
        .expect_err("duplicate must be rejected");
    assert_eq!(err, InsertError::Duplicate);

    // Produce slot 1: the mempool drains and the tx lands in the body.
    let outcome = backend
        .try_produce_block(1, &proposer_key())
        .expect("try_produce_block")
        .expect("validator is eligible");
    assert_eq!(outcome.block.header.height, 1);
    assert_eq!(
        outcome.block.body.transactions.len(),
        1,
        "the admitted transfer must be drained into the body",
    );
    assert_eq!(
        outcome.block.header.gas_used, GAS_TRANSFER,
        "header.gas_used must reflect the runtime's reported consumption",
    );
    assert_eq!(
        outcome.gas_used, GAS_TRANSFER,
        "production outcome's gas_used must match",
    );
    assert!(
        outcome.block.header.gas_used <= outcome.block.header.gas_limit,
        "gas_used must respect gas_limit",
    );
    assert_eq!(
        backend.mempool_len(),
        0,
        "mempool must drain after successful production",
    );

    // Prove the block and ensure the SP1 path is happy. The
    // `Sp1ProofSystem::prove_block` adapter cross-checks
    // `StfPublicOutput.gas_used` against
    // `BlockProofPublicInputs.gas_used`, so a successful prove
    // confirms the gas figure was propagated end-to-end.
    let proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove_block on the freshly produced block");
    assert_eq!(
        proven.public_inputs.gas_used, GAS_TRANSFER,
        "block proof public inputs commit to the same gas_used",
    );
    assert_eq!(
        proven.public_inputs.gas_limit, outcome.block.header.gas_limit,
        "block proof public inputs commit to the header's gas_limit",
    );
}
