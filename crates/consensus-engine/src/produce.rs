//! Per-slot block production shell.
//!
//! The legacy RV32IM runtime-host implementation was removed by the
//! SP1/WASM rewrite. Block production will be reintroduced through the
//! new WASM dry-run plus SP1 proving path described in
//! `docs/design/13-sp1-runtime-proof-rewrite.md`.

use core::fmt;

use neutrino_consensus_types::{Block, Body};
use neutrino_consensus_vrf::{VrfError, total_active_stake};
use neutrino_primitives::{BlockHash, BlsSignature, Slot, StateRoot, Validator};
use neutrino_storage::Database;
use neutrino_vrf::eval;

use crate::body::BodyEncodeError;
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
    /// Block production requires the new WASM/SP1 runtime path.
    RuntimeUnavailable,
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
            Self::RuntimeUnavailable => {
                f.write_str("block production awaits the WASM/SP1 runtime rewrite")
            }
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

/// Runtime + proposer binding for [`Engine::try_produce_block`].
#[derive(Clone, Copy, Debug)]
pub struct ProductionConfig<'a> {
    /// Proposer secret-key wrapper.
    pub proposer: &'a ProposerKey,
}

/// Successful block-production outcome.
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
    /// Validator-set root the runtime committed for the next chunk, if any.
    pub next_validator_set_root: Option<StateRoot>,
    /// Full active validator set when the runtime changed it in this block.
    pub next_validator_set: Option<Vec<Validator>>,
}

impl<DB: Database> Engine<DB> {
    /// Attempt to produce a block at `slot`.
    ///
    /// The legacy runtime executor has been removed. This method still performs
    /// proposer eligibility checks so validator configuration errors surface in
    /// the same place, then returns [`ProductionError::RuntimeUnavailable`]
    /// until the WASM/SP1 production path lands.
    pub fn try_produce_block(
        &mut self,
        slot: Slot,
        cfg: ProductionConfig<'_>,
        _body: Body,
        _gas_limit: u64,
    ) -> Result<Option<ProductionOutcome>, ProductionError<DB::Error>> {
        let parent_hash = self.head_hash();
        let parent_slot = self.head_slot(parent_hash)?;
        if slot <= parent_slot {
            return Err(ProductionError::NonMonotonicSlot {
                parent_slot,
                requested: slot,
            });
        }

        let Some(_eligibility) = self.evaluate_eligibility(slot, cfg.proposer)? else {
            return Ok(None);
        };

        let _height = self
            .head_height()
            .checked_add(1)
            .ok_or(ProductionError::HeightOverflow)?;

        Err(ProductionError::RuntimeUnavailable)
    }

    fn evaluate_eligibility(
        &self,
        slot: Slot,
        proposer: &ProposerKey,
    ) -> Result<Option<ProposerEligibility>, ProductionError<DB::Error>> {
        let active_set = self.active_validator_set();
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

#[derive(Clone, Copy, Debug)]
struct ProposerEligibility {
    #[allow(dead_code)]
    vrf_proof: BlsSignature,
}
