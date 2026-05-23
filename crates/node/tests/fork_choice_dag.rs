//! Pending-fix #2: fork choice wiring.
//!
//! Before this fix, `Engine::import_block` enforced strict linear
//! continuity: any block whose parent was not the local head was
//! rejected. Two validators winning the same slot (the canonical
//! BLS-VRF behaviour at moderate stake distributions) would
//! permanently fork the network.
//!
//! After the fix the engine maintains a fork-choice DAG: every
//! imported block whose parent is in the local store (or the
//! genesis hash) is accepted. The materialised head still follows
//! the linearly-applied chain (full reorg materialisation is
//! pending-fix #7), but the DAG records competing branches so
//! `Engine::fork_choice_head` can return the heaviest-proven-chain
//! winner once votes accumulate.
//!
//! Acceptance cases:
//!
//! 1. Two slot-1 siblings on the same genesis parent both import.
//!    The materialised head is the first one applied; the second
//!    lands in the DAG and the store but does not advance head.
//! 2. The fork-choice `head()` initially returns the materialised
//!    block (no votes), but once a stake-weighted chunk vote on
//!    the competing branch surfaces, `fork_choice_head()` switches
//!    to the heavier branch even though `head_hash()` does not.
//! 3. An invalid block proof on the materialised branch demotes
//!    that branch to `Invalid` in the DAG. The fork-choice head
//!    follows up by picking the competing branch (which is still
//!    `PendingProof` but extends the finalized anchor).
//!
//! Together these demonstrate the chain no longer self-bifurcates
//! on multi-winner slots.

use neutrino_consensus_engine::body::compute_body_roots;
use neutrino_consensus_engine::validator_set::validator_set_root;
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_fork_choice::{ChunkVote, ProofStatus};
use neutrino_consensus_types::{Block, Body, FinalityVoteData, FinalityVotePhase, Header};
use neutrino_primitives::{
    BlockHash, BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams,
    HEADER_VERSION, Height, LightClientParams, ProofParams, RuntimeParams, RuntimeVersion,
    StateParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrino_storage::MemoryDatabase;

const CHAIN_ID: u64 = 7_654_321;
const GENESIS_SEED: [u8; 32] = [0xD0; 32];

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: [0x88; 32],
            effective_stake: 32_000_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        })
        .collect()
}

fn chain_spec(count: u8) -> ChainSpec {
    let validators = validators(count);
    let proof = ProofParams {
        slot_budget_per_chunk: 1,
        ..ProofParams::default()
    };
    // Inflate `expected_proposers_per_slot` so multiple validators
    // can be VRF-eligible for the same slot — the very condition
    // fork choice is meant to handle.
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 8),
        ..ConsensusParams::default()
    };
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xAA; 32];
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
    ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(b"fork-choice-test".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: ZERO_HASH,
        genesis_seed: GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
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

/// Build a signed empty-body block at `(slot=1, parent=genesis)`
/// signed by `signer`. `state_root_byte` differentiates the two
/// sibling blocks so they hash differently.
fn signed_block(
    slot: u64,
    parent: BlockHash,
    height: Height,
    signer: &ProposerKey,
    state_root_byte: u8,
) -> Block {
    let body = Body::default();
    let roots = compute_body_roots(&body, &[]);
    let vrf_proof = signer.vrf_eval(CHAIN_ID, &GENESIS_SEED, slot);
    let mut header = Header {
        version: HEADER_VERSION,
        height,
        slot,
        parent_hash: parent,
        proposer_index: signer.validator_index(),
        vrf_proof,
        state_root: [state_root_byte; 32],
        transactions_root: roots.transactions_root,
        votes_root: roots.votes_root,
        slashings_root: roots.slashings_root,
        validator_ops_root: roots.validator_ops_root,
        da_root: roots.da_root,
        runtime_extra: ZERO_HASH,
        receipts_root: ZERO_HASH,
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: 1_700_000_000 + slot * 4,
        signature: [0; 96],
    };
    let header_hash = header.hash();
    header.signature = signer.sign_proposer_message(CHAIN_ID, &header_hash);
    Block { header, body }
}

#[test]
fn multi_winner_slot_does_not_reject_either_sibling() {
    let _ = tracing_subscriber::fmt::try_init();
    let mut engine = Engine::genesis(chain_spec(2), MemoryDatabase::new()).expect("genesis");
    let genesis_hash = engine.head_hash();

    let v0 = proposer(0);
    let v1 = proposer(1);

    // Both validators are VRF-eligible for slot 1 (expected
    // proposers per slot is inflated to ~10). Each signs their own
    // sibling block on top of genesis.
    let block_a = signed_block(1, genesis_hash, 1, &v0, 0x11);
    let block_b = signed_block(1, genesis_hash, 1, &v1, 0x22);
    assert_ne!(
        block_a.hash(),
        block_b.hash(),
        "sibling blocks must have distinct hashes for the test to be meaningful",
    );

    // First import lands as the materialised head.
    let out_a = engine.import_block(&block_a).expect("import first sibling");
    assert_eq!(out_a.block_hash, block_a.hash());
    assert_eq!(
        engine.head_hash(),
        block_a.hash(),
        "first sibling becomes head"
    );

    // Second sibling: previously rejected with ParentMismatch
    // (parent == genesis matches head == genesis but height check
    // would still fail because head_height is now 1). After fix #2
    // it's accepted into the DAG even though the materialised head
    // doesn't advance.
    engine
        .import_block(&block_b)
        .expect("import second sibling");

    // Materialised head is unchanged (still block A).
    assert_eq!(
        engine.head_hash(),
        block_a.hash(),
        "materialised head stays on the first sibling",
    );
    // Both siblings are in the DAG.
    assert!(
        engine.fork_choice().block(&block_a.hash()).is_some(),
        "block A in DAG",
    );
    assert!(
        engine.fork_choice().block(&block_b.hash()).is_some(),
        "block B in DAG",
    );
    // Body + header for both blocks survived persistence.
    assert!(
        engine
            .store()
            .get_header(&block_a.hash())
            .expect("read A")
            .is_some()
    );
    assert!(
        engine
            .store()
            .get_header(&block_b.hash())
            .expect("read B")
            .is_some()
    );
}

#[test]
fn heavier_branch_wins_fork_choice_head_even_when_materialised_head_lags() {
    let _ = tracing_subscriber::fmt::try_init();
    let mut engine = Engine::genesis(chain_spec(2), MemoryDatabase::new()).expect("genesis");
    let genesis_hash = engine.head_hash();
    let v0 = proposer(0);
    let v1 = proposer(1);

    let block_a = signed_block(1, genesis_hash, 1, &v0, 0x11);
    let block_b = signed_block(1, genesis_hash, 1, &v1, 0x22);
    engine.import_block(&block_a).expect("import A");
    engine.import_block(&block_b).expect("import B");

    // Both still PendingProof. fork_choice.head() returns whichever
    // wins the deterministic tie-break; both are valid tentative
    // heads. Promote both to Proven via the test hook so we can
    // test vote-based selection cleanly.
    let fc = engine.fork_choice_mut_for_test();
    fc.on_block_proof(block_a.hash(), ProofStatus::Proven)
        .expect("promote A to Proven");
    fc.on_block_proof(block_b.hash(), ProofStatus::Proven)
        .expect("promote B to Proven");

    // Register dummy chunks anchored at each sibling so the
    // vote-applies-to-candidate join has a chunk to hit.
    let chunk_a = dummy_chunk(block_a.hash(), 1);
    let chunk_b = dummy_chunk(block_b.hash(), 2);
    let _chunk_a_hash = fc.add_chunk(&chunk_a);
    let chunk_b_hash = fc.add_chunk(&chunk_b);

    // Big stake-weighted vote on chunk_b: validator 0's vote
    // dominates the tie-break with 100 units of weight.
    fc.add_vote(
        0,
        ChunkVote {
            data: FinalityVoteData {
                chunk_id: 2,
                round: 0,
                chunk_hash: chunk_b_hash,
                phase: FinalityVotePhase::Prevote,
            },
            weight: 100,
        },
    );

    // Materialised head is still A (no reorg materialisation; that's
    // pending-fix #7). The fork-choice head, however, picks B because
    // of the heavier vote weight.
    assert_eq!(engine.head_hash(), block_a.hash());
    assert_eq!(
        engine.fork_choice_head(),
        block_b.hash(),
        "fork choice picks heavier-voted branch",
    );
}

#[test]
fn invalid_proof_demotes_branch_in_fork_choice() {
    let _ = tracing_subscriber::fmt::try_init();
    let mut engine = Engine::genesis(chain_spec(2), MemoryDatabase::new()).expect("genesis");
    let genesis_hash = engine.head_hash();
    let v0 = proposer(0);
    let v1 = proposer(1);

    let block_a = signed_block(1, genesis_hash, 1, &v0, 0x11);
    let block_b = signed_block(1, genesis_hash, 1, &v1, 0x22);
    engine.import_block(&block_a).expect("import A");
    engine.import_block(&block_b).expect("import B");

    // Mark A as Invalid in fork choice. The DAG must then exclude A
    // (and any descendants) from `head()` candidates.
    engine
        .fork_choice_mut_for_test()
        .on_block_proof(block_a.hash(), ProofStatus::Invalid)
        .expect("mark A invalid");

    // Fork choice picks B because A is excluded; no votes needed.
    assert_eq!(
        engine.fork_choice_head(),
        block_b.hash(),
        "fork choice excludes Invalid branch",
    );
}

const fn dummy_chunk(end_block_hash: BlockHash, chunk_id: u64) -> neutrino_consensus_types::Chunk {
    neutrino_consensus_types::Chunk {
        chunk_id,
        start_height: 1,
        end_height: 1,
        start_state_root: ZERO_HASH,
        end_state_root: ZERO_HASH,
        start_block_hash: end_block_hash,
        end_block_hash,
        block_hash_root: ZERO_HASH,
        block_proof_root: ZERO_HASH,
        vrf_proof_root: ZERO_HASH,
        active_validator_set_root: ZERO_HASH,
        next_validator_set_root: ZERO_HASH,
        da_root: ZERO_HASH,
    }
}
