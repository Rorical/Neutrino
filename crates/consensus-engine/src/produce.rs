//! Per-slot block production: VRF eligibility, runtime execution,
//! header sealing, and persistence.
//!
//! Phase D drives the engine state forward block-by-block. Phase E
//! attaches the mock block proof on top of the [`Block`] produced
//! here.

use core::fmt;
use core::mem;

use neutrino_consensus_types::{Block, Body, Header};
use neutrino_consensus_vrf::{VrfError, total_active_stake};
use neutrino_primitives::{
    BlockHash, BlsSignature, Hash, Height, Slot, StateRoot, ZERO_HASH, blake3_256,
};
use neutrino_runtime_abi::BlockContext;
use neutrino_runtime_host::{BlockError, BlockOutcome, Overlay, run_block};
use neutrino_storage::Database;
use neutrino_vrf::eval;

use crate::block_state::BlockState;
use crate::body::{
    BodyEncodeError, BodyRoots, apply_body_roots, compute_body_roots,
    encode_runtime_body_with_validators,
};
use crate::engine::Engine;
use crate::error::EngineError;
use crate::proposer::ProposerKey;
use crate::store::StoreError;

/// Failures while producing a single block.
#[derive(Debug)]
pub enum ProductionError<E> {
    /// Engine bookkeeping or storage failure.
    Engine(EngineError<E>),
    /// Validator key cannot propose: missing index, slashed, etc.
    NotEligible(VrfError),
    /// Local validator index is not present in the active set.
    UnknownProposer {
        /// Validator index the proposer key declared.
        index: u32,
        /// Length of the active set.
        active_set_len: usize,
    },
    /// Block height counter would overflow `u64`.
    HeightOverflow,
    /// Body encoding rejected the supplied transactions.
    BodyEncode(BodyEncodeError),
    /// Runtime execution failed.
    Runtime(BlockError),
    /// The supplied runtime ELF does not match the chain-spec runtime code hash.
    RuntimeCodeHashMismatch {
        /// Runtime hash committed by the chain spec.
        expected: Hash,
        /// Runtime hash computed from the supplied ELF bytes.
        actual: Hash,
    },
    /// The proposer key does not match the validator pubkey at its declared index.
    ProposerKeyMismatch {
        /// Validator index the proposer key declared.
        index: u32,
    },
    /// The requested slot does not advance past the current head slot.
    NonMonotonicSlot {
        /// Slot of the current head block, or genesis slot 0.
        parent_slot: Slot,
        /// Slot requested for the new block.
        requested: Slot,
    },
}

impl<E: fmt::Display + fmt::Debug> fmt::Display for ProductionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(e) => write!(f, "engine error: {e}"),
            Self::NotEligible(e) => write!(f, "validator cannot propose: {e}"),
            Self::UnknownProposer {
                index,
                active_set_len,
            } => write!(
                f,
                "proposer index {index} is outside active set of length {active_set_len}"
            ),
            Self::HeightOverflow => f.write_str("block height counter overflowed"),
            Self::BodyEncode(e) => write!(f, "body encode failed: {e}"),
            Self::Runtime(e) => write!(f, "runtime execution failed: {e:?}"),
            Self::RuntimeCodeHashMismatch { expected, actual } => write!(
                f,
                "runtime ELF hash mismatch: expected {expected:?}, computed {actual:?}"
            ),
            Self::ProposerKeyMismatch { index } => {
                write!(f, "proposer key does not match validator at index {index}")
            }
            Self::NonMonotonicSlot {
                parent_slot,
                requested,
            } => write!(
                f,
                "slot {requested} must be greater than current head slot {parent_slot}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for ProductionError<E> {}

impl<E> From<EngineError<E>> for ProductionError<E> {
    fn from(value: EngineError<E>) -> Self {
        Self::Engine(value)
    }
}

impl<E> From<StoreError<E>> for ProductionError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Engine(EngineError::Store(value))
    }
}

impl<E> From<BodyEncodeError> for ProductionError<E> {
    fn from(value: BodyEncodeError) -> Self {
        Self::BodyEncode(value)
    }
}

impl<E> From<BlockError> for ProductionError<E> {
    fn from(value: BlockError) -> Self {
        Self::Runtime(value)
    }
}

/// Runtime + proposer binding for [`Engine::try_produce_block`].
#[derive(Clone, Copy, Debug)]
pub struct ProductionConfig<'a> {
    /// Runtime ELF bytes the engine will execute.
    pub runtime_elf: &'a [u8],
    /// Proposer secret-key wrapper.
    pub proposer: &'a ProposerKey,
}

/// Successful block-production outcome with detail about the
/// engine-side side effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionOutcome {
    /// The signed block.
    pub block: Block,
    /// Canonical block hash (also equal to `block.hash()`).
    pub block_hash: BlockHash,
    /// Post-execution state root (also recorded in the header).
    pub state_root_after: StateRoot,
    /// Gas the runtime actually consumed.
    pub gas_used: u64,
    /// Validator-set root the runtime committed for the next chunk,
    /// if any. Forwarded into `header.runtime_extra` and surfaced
    /// here for chunk-level consumers in later phases.
    pub next_validator_set_root: Option<StateRoot>,
}

impl<DB: Database> Engine<DB> {
    /// Attempt to produce a block at `slot`.
    ///
    /// Returns `Ok(Some(outcome))` when the local validator is
    /// eligible to propose, advancing the engine head; `Ok(None)`
    /// otherwise, leaving the engine state unchanged.
    pub fn try_produce_block(
        &mut self,
        slot: Slot,
        cfg: ProductionConfig<'_>,
        body: Body,
        gas_limit: u64,
    ) -> Result<Option<ProductionOutcome>, ProductionError<DB::Error>> {
        let actual_runtime_hash = blake3_256(cfg.runtime_elf);
        let expected_runtime_hash = self.chain_spec().runtime_code_hash;
        if actual_runtime_hash != expected_runtime_hash {
            return Err(ProductionError::RuntimeCodeHashMismatch {
                expected: expected_runtime_hash,
                actual: actual_runtime_hash,
            });
        }

        let parent_hash = self.head_hash();
        let parent_slot = self.head_slot(parent_hash)?;
        if slot <= parent_slot {
            return Err(ProductionError::NonMonotonicSlot {
                parent_slot,
                requested: slot,
            });
        }

        let Some(eligibility) = self.evaluate_eligibility(slot, cfg.proposer)? else {
            return Ok(None);
        };

        let height = self
            .head_height()
            .checked_add(1)
            .ok_or(ProductionError::HeightOverflow)?;
        let parent_state_root = self.head_state_root();

        let encoded_body =
            encode_runtime_body_with_validators(&body, &self.chain_spec().initial_validators)?;
        let ctx = BlockContext {
            slot,
            height,
            seed: self.finalized_seed(),
            parent_hash,
            parent_state_root,
            gas_limit,
            proposer_index: cfg.proposer.validator_index(),
            vrf_proof: eligibility.vrf_proof,
        };

        let trie = mem::take(self.state_mut_internal());
        let mut overlay = Overlay::new(trie);
        let outcome = match run_block(
            cfg.runtime_elf,
            &ctx,
            encoded_body.clone(),
            &mut overlay,
            gas_limit,
        ) {
            Ok(outcome) => outcome,
            Err(err) => {
                *self.state_mut_internal() = overlay.into_base();
                return Err(ProductionError::Runtime(err));
            }
        };
        *self.state_mut_internal() = overlay.into_base();

        let roots = compute_body_roots(&body, &encoded_body);
        let timestamp = self.clock().timestamp_for(slot);
        let header = seal_header(
            self.chain_spec().chain_id,
            cfg.proposer,
            slot,
            height,
            parent_hash,
            eligibility.vrf_proof,
            &outcome,
            &roots,
            timestamp,
            gas_limit,
        );

        let block = Block { header, body };
        let block_hash = block.hash();

        self.store_mut().put_header(&block.header)?;
        self.store_mut().put_body(&block_hash, &block.body)?;
        self.store_mut()
            .put_block_state(&block_hash, BlockState::BlockProduced)?;
        self.store_mut().put_tip(block_hash)?;

        self.update_head_internal(height, block_hash, outcome.state_root_after);
        // Producers own the canonical state trie; persist whatever
        // nodes/values the runtime just emitted so a restart resumes
        // at the same trie root the new head commits to.
        self.flush_trie_to_store()?;

        Ok(Some(ProductionOutcome {
            block,
            block_hash,
            state_root_after: outcome.state_root_after,
            gas_used: outcome.gas_used,
            next_validator_set_root: outcome.next_validator_set_root,
        }))
    }

    fn evaluate_eligibility(
        &self,
        slot: Slot,
        proposer: &ProposerKey,
    ) -> Result<Option<ProposerEligibility>, ProductionError<DB::Error>> {
        let active_set = &self.chain_spec().initial_validators;
        let index = proposer.validator_index();
        let position = usize::try_from(index).expect("u32 fits usize on supported targets");
        let validator = active_set
            .get(position)
            .ok_or(ProductionError::UnknownProposer {
                index,
                active_set_len: active_set.len(),
            })?;
        if validator.slashed {
            return Err(ProductionError::NotEligible(VrfError::SlashedValidator));
        }
        let total_stake = total_active_stake(active_set).map_err(ProductionError::NotEligible)?;
        if validator.pubkey != *proposer.public_key_bytes() {
            return Err(ProductionError::ProposerKeyMismatch { index });
        }

        let seed = self.finalized_seed();
        let chain_id = self.chain_spec().chain_id;
        let expected = self.chain_spec().consensus.expected_proposers_per_slot;

        let (vrf_proof, vrf_output) = eval(proposer.secret_key(), chain_id, &seed, slot);
        if !neutrino_vrf::is_eligible(
            &vrf_output,
            validator.effective_stake,
            total_stake,
            expected,
        ) {
            return Ok(None);
        }
        Ok(Some(ProposerEligibility {
            vrf_proof: vrf_proof.to_bytes(),
        }))
    }

    fn head_slot(&self, head_hash: BlockHash) -> Result<Slot, ProductionError<DB::Error>> {
        if head_hash == self.chain_spec().genesis_block_hash {
            return Ok(0);
        }
        let header = self
            .store()
            .get_header(&head_hash)?
            .ok_or(EngineError::NotInitialised)?;
        Ok(header.slot)
    }
}

#[allow(clippy::too_many_arguments)]
fn seal_header(
    chain_id: u64,
    proposer: &ProposerKey,
    slot: Slot,
    height: Height,
    parent_hash: BlockHash,
    vrf_proof: BlsSignature,
    outcome: &BlockOutcome,
    roots: &BodyRoots,
    timestamp: u64,
    gas_limit: u64,
) -> Header {
    let mut header = Header {
        version: 1,
        height,
        slot,
        parent_hash,
        proposer_index: proposer.validator_index(),
        vrf_proof,
        state_root: outcome.state_root_after,
        transactions_root: ZERO_HASH,
        votes_root: ZERO_HASH,
        slashings_root: ZERO_HASH,
        validator_ops_root: ZERO_HASH,
        da_root: ZERO_HASH,
        runtime_extra: outcome.next_validator_set_root.unwrap_or(ZERO_HASH),
        gas_used: outcome.gas_used,
        gas_limit,
        timestamp,
        signature: [0; 96],
    };
    apply_body_roots(&mut header, roots);
    let header_hash = header.hash();
    header.signature = proposer.sign_proposer_message(chain_id, &header_hash);
    header
}

#[derive(Clone, Copy, Debug)]
struct ProposerEligibility {
    vrf_proof: BlsSignature,
}
