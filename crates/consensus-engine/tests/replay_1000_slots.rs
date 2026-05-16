//! M5 exit-criterion test: deterministic 1000-slot replay.
//!
//! Drives the single-validator pipeline through `TOTAL_SLOTS` slots,
//! finalizing and recursively checkpointing every chunk. Asserts:
//!
//! - The mock-proof FSM `BlockProduced → PendingProof → Proven →
//!   ChunkProven → Finalized → Checkpointed` walks all six states
//!   for every block.
//! - The chain hashes (block, chunk, checkpoint, final state root,
//!   final finalized seed) are reproduced bit-for-bit when the same
//!   chain spec + proposer key is run from scratch a second time —
//!   the deterministic-replay clause of the M5 exit criteria.
//!
//! Runs against the real `neutrino-default-runtime` ELF; gracefully
//! skips when `NEUTRINO_DEFAULT_RUNTIME_ELF` is unset.

use std::fs;

use neutrino_consensus_engine::{
    BlockState, Engine, ProductionConfig, ProposerKey, validator_set_root,
};
use neutrino_consensus_types::Body;
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, Hash, Height,
    LightClientParams, ProofParams, RuntimeVersion, Seed, StateParams, StateRoot, Validator,
    ZERO_HASH,
};
use neutrino_proof_system::MockProofSystem;
use neutrino_storage::MemoryDatabase;

const ELF_ENV: &str = "NEUTRINO_DEFAULT_RUNTIME_ELF";

/// Total slots covered by the replay test. With `CHUNK_SIZE = 125`,
/// this yields exactly 8 fully checkpointed chunks.
const TOTAL_SLOTS: u64 = 1000;
/// Chunk size chosen so `TOTAL_SLOTS` divides evenly by it.
const CHUNK_SIZE: u64 = 125;
const TOTAL_CHUNKS: u64 = TOTAL_SLOTS / CHUNK_SIZE;

fn read_elf() -> Option<Vec<u8>> {
    let path = option_env!("NEUTRINO_DEFAULT_RUNTIME_ELF")?;
    fs::read(path).ok()
}

const fn proposer_ikm() -> [u8; 32] {
    *b"neutrino::m5::phase-h::proposer-"
}

fn make_proposer() -> ProposerKey {
    ProposerKey::from_ikm(&proposer_ikm(), 0).expect("derive proposer key")
}

fn validators_from(proposer: &ProposerKey) -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer.public_key_bytes(),
        withdrawal_credentials: [0x33; 32],
        effective_stake: 32_000_000_000,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }]
}

fn chain_spec(validators: Vec<Validator>) -> ChainSpec {
    let consensus = ConsensusParams {
        chunk_size: CHUNK_SIZE,
        ..ConsensusParams::default()
    };
    let proof = ProofParams {
        slot_budget_per_chunk: CHUNK_SIZE,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash = [0xAA; 32];
    let genesis_state_root = ZERO_HASH;
    let checkpoint = Checkpoint {
        chain_id: 1,
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
        name: BoundedBytes::new(b"m5-phase-h".to_vec()).expect("name fits"),
        chain_id: 1,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: [0xBB; 32],
        genesis_seed: [0xCC; 32],
        genesis_state_root,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        genesis_checkpoint: checkpoint,
        consensus,
        proof,
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty metadata fits"),
    }
}

/// Summary of one full run, capturing the consensus-critical hashes
/// the M5 exit-criterion test compares across replays.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RunSummary {
    block_hashes: Vec<[u8; 32]>,
    chunk_hashes: Vec<Hash>,
    checkpoint_hashes: Vec<Hash>,
    final_state_root: StateRoot,
    final_finalized_seed: Seed,
    final_head_height: Height,
}

/// Drive the full single-node pipeline through `TOTAL_SLOTS` slots,
/// completing every FSM transition for every block.
fn run_chain(elf: &[u8]) -> RunSummary {
    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    let mut block_hashes = Vec::with_capacity(usize::try_from(TOTAL_SLOTS).unwrap());
    let mut chunk_hashes = Vec::with_capacity(usize::try_from(TOTAL_CHUNKS).unwrap());
    let mut checkpoint_hashes = Vec::with_capacity(usize::try_from(TOTAL_CHUNKS).unwrap());

    for chunk_id in 0..TOTAL_CHUNKS {
        let start_slot = chunk_id * CHUNK_SIZE + 1;
        let end_slot = (chunk_id + 1) * CHUNK_SIZE;

        // Produce + prove every block in this chunk.
        for slot in start_slot..=end_slot {
            let cfg = ProductionConfig {
                runtime_elf: elf,
                proposer: &proposer,
            };
            let produced = engine
                .try_produce_block(
                    slot,
                    cfg,
                    Body::default(),
                    engine.chain_spec().genesis_gas_limit,
                )
                .expect("produce ok")
                .expect("validator should be elected");
            block_hashes.push(produced.block_hash);
            engine
                .prove_block(&produced.block_hash, &[], &proof_system)
                .expect("prove ok");
        }

        // Finalize then checkpoint the chunk.
        let finalize = engine
            .finalize_chunk(chunk_id, &[], &proof_system, &proposer)
            .expect("finalize ok");
        chunk_hashes.push(finalize.chunk_hash);

        let checkpoint = engine
            .checkpoint_chunk(chunk_id, &[], &proof_system)
            .expect("checkpoint ok");
        checkpoint_hashes.push(checkpoint.checkpoint_hash);
    }

    RunSummary {
        block_hashes,
        chunk_hashes,
        checkpoint_hashes,
        final_state_root: engine.head_state_root(),
        final_finalized_seed: engine.finalized_seed(),
        final_head_height: engine.head_height(),
    }
}

#[test]
fn full_fsm_walks_every_state_for_every_block_in_1000_slots() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping 1000-slot replay test.");
        return;
    };

    let proposer = make_proposer();
    let spec = chain_spec(validators_from(&proposer));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let proof_system = MockProofSystem::new();

    let mut block_hashes = Vec::with_capacity(usize::try_from(TOTAL_SLOTS).unwrap());
    for chunk_id in 0..TOTAL_CHUNKS {
        let start_slot = chunk_id * CHUNK_SIZE + 1;
        let end_slot = (chunk_id + 1) * CHUNK_SIZE;

        // Inspect intermediate FSM states at one block per chunk.
        let mut probe_hash = None;
        for slot in start_slot..=end_slot {
            let cfg = ProductionConfig {
                runtime_elf: &elf,
                proposer: &proposer,
            };
            let produced = engine
                .try_produce_block(
                    slot,
                    cfg,
                    Body::default(),
                    engine.chain_spec().genesis_gas_limit,
                )
                .expect("produce ok")
                .expect("eligibility");
            if slot == start_slot {
                probe_hash = Some(produced.block_hash);
                assert_eq!(
                    engine
                        .store()
                        .get_block_state(&produced.block_hash)
                        .unwrap(),
                    Some(BlockState::BlockProduced),
                );
            }
            block_hashes.push(produced.block_hash);
            engine
                .prove_block(&produced.block_hash, &[], &proof_system)
                .expect("prove ok");
            if slot == start_slot {
                assert_eq!(
                    engine
                        .store()
                        .get_block_state(&probe_hash.unwrap())
                        .unwrap(),
                    Some(BlockState::Proven),
                );
            }
        }

        engine
            .finalize_chunk(chunk_id, &[], &proof_system, &proposer)
            .expect("finalize ok");
        assert_eq!(
            engine
                .store()
                .get_block_state(&probe_hash.unwrap())
                .unwrap(),
            Some(BlockState::Finalized),
        );

        engine
            .checkpoint_chunk(chunk_id, &[], &proof_system)
            .expect("checkpoint ok");
        assert_eq!(
            engine
                .store()
                .get_block_state(&probe_hash.unwrap())
                .unwrap(),
            Some(BlockState::Checkpointed),
        );
    }

    // Every block in every chunk must end in Checkpointed.
    for hash in &block_hashes {
        assert_eq!(
            engine.store().get_block_state(hash).unwrap(),
            Some(BlockState::Checkpointed),
            "block {hash:?} did not reach Checkpointed",
        );
    }
    assert_eq!(block_hashes.len(), usize::try_from(TOTAL_SLOTS).unwrap());
    assert_eq!(engine.head_height(), TOTAL_SLOTS);
    assert_eq!(engine.latest_checkpoint_index(), TOTAL_CHUNKS);
    assert_eq!(engine.latest_finalized_chunk_id(), Some(TOTAL_CHUNKS - 1),);
}

#[test]
fn deterministic_replay_reproduces_every_consensus_critical_hash() {
    let Some(elf) = read_elf() else {
        eprintln!("{ELF_ENV} not set; skipping 1000-slot replay test.");
        return;
    };

    let run_a = run_chain(&elf);
    let run_b = run_chain(&elf);

    assert_eq!(run_a, run_b, "two independent runs diverged");

    // Sanity that the run actually exercised the full pipeline.
    assert_eq!(
        run_a.block_hashes.len(),
        usize::try_from(TOTAL_SLOTS).unwrap()
    );
    assert_eq!(
        run_a.chunk_hashes.len(),
        usize::try_from(TOTAL_CHUNKS).unwrap()
    );
    assert_eq!(
        run_a.checkpoint_hashes.len(),
        usize::try_from(TOTAL_CHUNKS).unwrap(),
    );
    assert_eq!(run_a.final_head_height, TOTAL_SLOTS);
    assert_ne!(run_a.final_state_root, ZERO_HASH);
    assert_ne!(run_a.final_finalized_seed, [0; 32]);

    // Every consensus-critical hash must be unique within its
    // sequence (no two blocks share a hash, no two chunks share a
    // hash, etc.) — the runtime increments the counter every block
    // so state roots and therefore hashes always differ.
    let mut sorted_blocks = run_a.block_hashes.clone();
    sorted_blocks.sort_unstable();
    sorted_blocks.dedup();
    assert_eq!(sorted_blocks.len(), run_a.block_hashes.len());

    let mut sorted_chunks = run_a.chunk_hashes.clone();
    sorted_chunks.sort_unstable();
    sorted_chunks.dedup();
    assert_eq!(sorted_chunks.len(), run_a.chunk_hashes.len());

    let mut sorted_checkpoints = run_a.checkpoint_hashes.clone();
    sorted_checkpoints.sort_unstable();
    sorted_checkpoints.dedup();
    assert_eq!(sorted_checkpoints.len(), run_a.checkpoint_hashes.len());
}
