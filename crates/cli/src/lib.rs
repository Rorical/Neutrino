#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Command-line support for local Neutrino development nodes.

use core::fmt;

use neutrino_consensus_engine::{Engine, ProductionConfig, ProposerKey, validator_set_root};
use neutrino_consensus_types::Body;
use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, Checkpoint, ConsensusParams, Hash, Height,
    LightClientParams, ProofParams, RuntimeVersion, Seed, StateParams, StateRoot, Validator,
    ZERO_HASH, blake3_256,
};
use neutrino_proof_system::MockProofSystem;
use neutrino_storage::MemoryDatabase;

/// Supported top-level CLI commands.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Command {
    /// Run a node.
    Node,
    /// Generate keys.
    Keygen,
    /// Import a block.
    ImportBlock,
    /// Prove a block.
    ProveBlock,
    /// Verify a checkpoint.
    VerifyCheckpoint,
}

/// Configuration for a deterministic single-validator local run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SingleValidatorRunConfig<'a> {
    /// Chain name committed into the generated chain spec.
    pub chain_name: &'a [u8],
    /// Chain id committed into headers and proof public inputs.
    pub chain_id: u64,
    /// Genesis timestamp in seconds since UNIX epoch.
    pub genesis_time: u64,
    /// Gas limit assigned to every produced block.
    pub genesis_gas_limit: u64,
    /// Number of slots to produce. Must be a multiple of `chunk_size`.
    pub slots: u64,
    /// Number of canonical block heights per chunk.
    pub chunk_size: u64,
    /// Runtime ELF bytes executed for every block.
    pub runtime_elf: &'a [u8],
    /// BLS IKM for the single validator/proposer key.
    pub proposer_ikm: [u8; 32],
}

impl<'a> SingleValidatorRunConfig<'a> {
    /// Build a config with M5-friendly defaults and caller-provided ELF bytes.
    #[must_use]
    pub const fn default_for_runtime(runtime_elf: &'a [u8]) -> Self {
        Self {
            chain_name: b"m5-cli-local",
            chain_id: 1,
            genesis_time: 1_700_000_000,
            genesis_gas_limit: 30_000_000,
            slots: 1_000,
            chunk_size: 125,
            runtime_elf,
            proposer_ikm: [0x42; 32],
        }
    }
}

/// One block line in a local chain dump.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockDump {
    /// Canonical block height.
    pub height: Height,
    /// Slot at which the block was produced.
    pub slot: u64,
    /// Canonical block hash.
    pub hash: Hash,
    /// State root after this block executed.
    pub state_root: StateRoot,
}

/// One chunk line in a local chain dump.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkDump {
    /// Chunk id.
    pub chunk_id: u64,
    /// Canonical chunk hash.
    pub hash: Hash,
}

/// One checkpoint line in a local chain dump.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointDump {
    /// Recursive checkpoint index.
    pub index: u64,
    /// Canonical checkpoint hash.
    pub hash: Hash,
}

/// Deterministic dump returned by a single-validator local run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainDump {
    /// Blocks produced in height order.
    pub blocks: Vec<BlockDump>,
    /// Chunks finalized in chunk-id order.
    pub chunks: Vec<ChunkDump>,
    /// Checkpoints produced in checkpoint-index order.
    pub checkpoints: Vec<CheckpointDump>,
    /// Final canonical head height.
    pub final_head_height: Height,
    /// Final canonical head hash.
    pub final_head_hash: Hash,
    /// Final post-head state root.
    pub final_state_root: StateRoot,
    /// Finalized seed after all checkpointed chunks fold their VRF proofs.
    pub final_finalized_seed: Seed,
}

/// Errors returned by the local CLI runner.
#[derive(Debug, Eq, PartialEq)]
pub enum CliError {
    /// Run config is internally inconsistent.
    InvalidConfig(&'static str),
    /// Proposer key derivation failed.
    ProposerKey(String),
    /// Engine genesis failed.
    Engine(String),
    /// Block production failed.
    Production(String),
    /// Block proving failed.
    Prove(String),
    /// Chunk finalization failed.
    Finalize(String),
    /// Recursive checkpointing failed.
    Checkpoint(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid run config: {msg}"),
            Self::ProposerKey(err) => write!(f, "proposer key error: {err}"),
            Self::Engine(err) => write!(f, "engine error: {err}"),
            Self::Production(err) => write!(f, "production error: {err}"),
            Self::Prove(err) => write!(f, "prove error: {err}"),
            Self::Finalize(err) => write!(f, "finalize error: {err}"),
            Self::Checkpoint(err) => write!(f, "checkpoint error: {err}"),
        }
    }
}

impl std::error::Error for CliError {}

/// Run a deterministic single-validator node and return a chain dump.
pub fn run_single_validator_node(
    config: SingleValidatorRunConfig<'_>,
) -> Result<ChainDump, CliError> {
    validate_run_config(&config)?;

    let proposer = ProposerKey::from_ikm(&config.proposer_ikm, 0)
        .map_err(|err| CliError::ProposerKey(err.to_string()))?;
    let spec = chain_spec(&config, &proposer)?;
    let mut engine = Engine::genesis(spec, MemoryDatabase::new())
        .map_err(|err| CliError::Engine(err.to_string()))?;
    let proof_system = MockProofSystem::new();

    let chunk_count = config.slots / config.chunk_size;
    let mut blocks = Vec::with_capacity(usize::try_from(config.slots).expect("slots fit usize"));
    let mut chunks = Vec::with_capacity(usize::try_from(chunk_count).expect("chunks fit usize"));
    let mut checkpoints = Vec::with_capacity(chunks.capacity());

    for chunk_id in 0..chunk_count {
        let start_slot = chunk_id * config.chunk_size + 1;
        let end_slot = (chunk_id + 1) * config.chunk_size;
        for slot in start_slot..=end_slot {
            let produced = produce_and_prove(
                &mut engine,
                config.runtime_elf,
                &proposer,
                proof_system,
                slot,
                config.genesis_gas_limit,
            )?;
            blocks.push(produced);
        }

        let finalized = engine
            .finalize_chunk(chunk_id, &[], &proof_system, &proposer)
            .map_err(|err| CliError::Finalize(err.to_string()))?;
        chunks.push(ChunkDump {
            chunk_id,
            hash: finalized.chunk_hash,
        });

        let checkpoint = engine
            .checkpoint_chunk(chunk_id, &[], &proof_system)
            .map_err(|err| CliError::Checkpoint(err.to_string()))?;
        checkpoints.push(CheckpointDump {
            index: checkpoint.checkpoint.index,
            hash: checkpoint.checkpoint_hash,
        });
    }

    Ok(ChainDump {
        blocks,
        chunks,
        checkpoints,
        final_head_height: engine.head_height(),
        final_head_hash: engine.head_hash(),
        final_state_root: engine.head_state_root(),
        final_finalized_seed: engine.finalized_seed(),
    })
}

const fn validate_run_config(config: &SingleValidatorRunConfig<'_>) -> Result<(), CliError> {
    if config.chain_name.is_empty() {
        return Err(CliError::InvalidConfig("chain name must be non-empty"));
    }
    if config.chain_id == 0 {
        return Err(CliError::InvalidConfig("chain id must be non-zero"));
    }
    if config.genesis_gas_limit == 0 {
        return Err(CliError::InvalidConfig("gas limit must be non-zero"));
    }
    if config.runtime_elf.is_empty() {
        return Err(CliError::InvalidConfig("runtime ELF must be non-empty"));
    }
    if config.slots == 0 || config.chunk_size == 0 {
        return Err(CliError::InvalidConfig(
            "slots and chunk size must be non-zero",
        ));
    }
    if config.slots % config.chunk_size != 0 {
        return Err(CliError::InvalidConfig(
            "slots must be an exact multiple of chunk size",
        ));
    }
    Ok(())
}

fn chain_spec(
    config: &SingleValidatorRunConfig<'_>,
    proposer: &ProposerKey,
) -> Result<ChainSpec, CliError> {
    let validators = vec![Validator {
        pubkey: *proposer.public_key_bytes(),
        withdrawal_credentials: [0x33; 32],
        effective_stake: 32_000_000_000,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }];
    let consensus = ConsensusParams {
        chunk_size: config.chunk_size,
        ..ConsensusParams::default()
    };
    let proof = ProofParams {
        slot_budget_per_chunk: config.chunk_size,
        ..ProofParams::default()
    };
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash = [0xAA; 32];
    let genesis_state_root = ZERO_HASH;
    let checkpoint = Checkpoint {
        chain_id: config.chain_id,
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
    Ok(ChainSpec {
        spec_version: CHAIN_SPEC_VERSION,
        name: BoundedBytes::new(config.chain_name.to_vec())
            .map_err(|_| CliError::InvalidConfig("chain name is too long"))?,
        chain_id: config.chain_id,
        genesis_time: config.genesis_time,
        genesis_gas_limit: config.genesis_gas_limit,
        runtime_version: RuntimeVersion::default(),
        runtime_code_hash: blake3_256(config.runtime_elf),
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
    })
}

fn produce_and_prove(
    engine: &mut Engine<MemoryDatabase>,
    runtime_elf: &[u8],
    proposer: &ProposerKey,
    proof_system: MockProofSystem,
    slot: u64,
    gas_limit: u64,
) -> Result<BlockDump, CliError> {
    let cfg = ProductionConfig {
        runtime_elf,
        proposer,
    };
    let produced = engine
        .try_produce_block(slot, cfg, Body::default(), gas_limit)
        .map_err(|err| CliError::Production(err.to_string()))?
        .ok_or(CliError::InvalidConfig(
            "single validator was not eligible for a slot",
        ))?;
    engine
        .prove_block(&produced.block_hash, &proof_system)
        .map_err(|err| CliError::Prove(err.to_string()))?;
    Ok(BlockDump {
        height: produced.block.header.height,
        slot,
        hash: produced.block_hash,
        state_root: produced.state_root_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_runtime() -> Option<Vec<u8>> {
        let path = option_env!("NEUTRINO_DEFAULT_RUNTIME_ELF")?;
        std::fs::read(path).ok()
    }

    #[test]
    fn rejects_non_complete_chunk_run() {
        let Some(runtime) = tiny_runtime() else {
            eprintln!("NEUTRINO_DEFAULT_RUNTIME_ELF not set; skipping CLI runner test.");
            return;
        };
        let mut cfg = SingleValidatorRunConfig::default_for_runtime(&runtime);
        cfg.slots = 7;
        cfg.chunk_size = 4;

        let err = run_single_validator_node(cfg).expect_err("incomplete chunk rejected");
        assert!(matches!(err, CliError::InvalidConfig(_)));
    }

    #[test]
    fn single_validator_runner_produces_finalized_dump() {
        let Some(runtime) = tiny_runtime() else {
            eprintln!("NEUTRINO_DEFAULT_RUNTIME_ELF not set; skipping CLI runner test.");
            return;
        };
        let mut cfg = SingleValidatorRunConfig::default_for_runtime(&runtime);
        cfg.slots = 8;
        cfg.chunk_size = 4;

        let dump = run_single_validator_node(cfg).expect("run local node");
        assert_eq!(dump.blocks.len(), 8);
        assert_eq!(dump.chunks.len(), 2);
        assert_eq!(dump.checkpoints.len(), 2);
        assert_eq!(dump.final_head_height, 8);
        assert_eq!(
            dump.blocks.last().expect("block").hash,
            dump.final_head_hash
        );
        assert_ne!(dump.final_state_root, ZERO_HASH);
    }
}
