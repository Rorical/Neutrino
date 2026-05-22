//! Per-slot block production.
//!
//! The accepted SP1 rewrite (see
//! `docs/design/13-sp1-runtime-proof-rewrite.md` and
//! `docs/design/14-sp1-rewrite-roadmap.md`) splits block production
//! into three concerns:
//!
//! 1. **VRF eligibility.** Owned by this module; consults the active
//!    validator set, finalized seed, and chain spec.
//! 2. **Dynamic execution.** Delegated to a
//!    [`BlockExecutor`](neutrino_proof_system::BlockExecutor) — the
//!    node binary wires in `WasmExecutor` from `runtime-host`, but
//!    the trait keeps the engine decoupled from wasmtime and the
//!    default-runtime types.
//! 3. **Header sealing.** Owned by this module; constructs the
//!    canonical [`Header`], signs it with the proposer key, persists
//!    the header / body / witness / FSM state, and advances the
//!    engine's in-memory head pointers.
//!
//! Per-block SP1 proving is a separate FSM step
//! ([`Engine::prove_block`](crate::Engine::prove_block)). It re-reads
//! the witness this path persists and produces the
//! `BlockProof` consensus stores alongside the block.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use neutrino_consensus_types::{Block, Body, Header};
use neutrino_consensus_vrf::{VrfError, total_active_stake};
use neutrino_primitives::{
    BlockHash, BlsSignature, HEADER_VERSION, Slot, StateRoot, Validator, ZERO_HASH,
};
use neutrino_proof_system::{ErasedBlockExecutor, ExecutionOutcome};
use neutrino_storage::Database;
use neutrino_vrf::eval;

use crate::block_state::BlockState;
use crate::body::{apply_body_roots, compute_body_roots};
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
    /// The dynamic runtime ([`BlockExecutor`]) failed during the
    /// dry-run path.
    Executor(String),
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
            Self::Executor(msg) => write!(f, "block executor failed: {msg}"),
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
    /// Flow:
    ///
    /// 1. Validate the requested slot is monotonic relative to the
    ///    local head (cheap, no eligibility cost on stale slots).
    /// 2. Evaluate VRF eligibility against the active validator set
    ///    and the finalized seed. Returns `Ok(None)` if the local
    ///    validator is not eligible for this slot.
    /// 3. Snapshot the engine's authoritative state trie, flush
    ///    pending nodes/values to RocksDB so the snapshot is
    ///    drain-complete, then hand the snapshot + body to the
    ///    [`BlockExecutor`].
    /// 4. The executor returns `(state_root_after, runtime_extra,
    ///    gas_used, witness_bytes)` and mutates the supplied trie
    ///    in place with the block's writes.
    /// 5. Compute the body Merkle roots, build the canonical
    ///    [`Header`] (wiring `runtime_extra` from the executor's
    ///    `validator_set_root` commitment), sign it with the
    ///    proposer key, and persist the header / body / FSM state /
    ///    witness / tip pointer in one ordered batch.
    /// 6. Advance the engine's in-memory head pointers and flush
    ///    the new trie deltas to RocksDB.
    /// 7. Return the [`ProductionOutcome`] so the chain backend can
    ///    gossip the block and the producer loop can hand it to the
    ///    SP1 prover ([`Engine::prove_block`](crate::Engine::prove_block)).
    ///
    /// # Errors
    ///
    /// - [`ProductionError::NonMonotonicSlot`] if `slot` does not
    ///   strictly advance the local head's slot.
    /// - [`ProductionError::UnknownProposer`] /
    ///   [`ProductionError::ProposerKeyMismatch`] /
    ///   [`ProductionError::NotEligible`] for proposer eligibility
    ///   failures.
    /// - [`ProductionError::HeightOverflow`] if the block height
    ///   counter would overflow `u64`.
    /// - [`ProductionError::Executor`] if the dynamic runtime fails.
    /// - [`ProductionError::Engine`] on persistence failures.
    pub fn try_produce_block(
        &mut self,
        slot: Slot,
        cfg: ProductionConfig<'_>,
        body: Body,
        gas_limit: u64,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<Option<ProductionOutcome>, ProductionError<DB::Error>> {
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

        // Flush any pending trie writes so the snapshot we pass to
        // the executor is in lock-step with the persisted state.
        // Defensive: in the steady-state path the engine flushes
        // after every successful production / import, but a producer
        // that just restarted may have unwritten nodes / values from
        // its rehydrated trie (though `Engine::open` rebuilds an
        // empty pending list, so this is a no-op today).
        self.flush_trie_to_store()?;

        // Snapshot the authoritative trie and hand it to the
        // executor. On success the trie has been advanced in place
        // with the block's writes; on failure we leave it untouched
        // and bubble the error.
        //
        // Cloning the trie is a BTreeMap clone — cheap and
        // deterministic. Future optimisation can swap to a
        // copy-on-write snapshot if blocks grow large.
        let chain_id = self.chain_spec().chain_id;
        let mut next_state = self.state().clone();
        next_state.drain_pending_nodes();
        next_state.drain_pending_values();
        let ExecutionOutcome {
            state_root_after,
            runtime_extra,
            receipts_root,
            gas_used,
            witness_bytes,
        } = executor
            .execute_block(chain_id, &body, height, gas_limit, &mut next_state)
            .map_err(ProductionError::Executor)?;

        // Compute body roots from the supplied body. The executor
        // emits `state_root_after` and `runtime_extra` directly; the
        // body Merkle roots are still derived host-side because the
        // header lanes are consensus-level commitments, not runtime
        // ones.
        let body_roots = compute_body_roots(&body, &[]);

        // Assemble the unsigned header. Slot timing follows the
        // chain spec's `genesis_time + slot * slot_duration_secs`
        // schedule so peers can reject headers whose timestamps lie
        // outside the slot's bounds.
        let chain_spec = self.chain_spec();
        let timestamp = chain_spec
            .genesis_time
            .saturating_add(slot.saturating_mul(chain_spec.consensus.slot_duration_secs));
        let mut header = Header {
            version: HEADER_VERSION,
            height,
            slot,
            parent_hash,
            proposer_index: cfg.proposer.validator_index(),
            vrf_proof: eligibility.vrf_proof,
            state_root: state_root_after,
            transactions_root: ZERO_HASH,
            votes_root: ZERO_HASH,
            slashings_root: ZERO_HASH,
            validator_ops_root: ZERO_HASH,
            da_root: ZERO_HASH,
            // Wire the validator-set commitment the runtime emitted
            // into `runtime_extra` so the chunk BFT and consensus
            // layer see the post-block stake distribution.
            runtime_extra,
            // Wire the runtime's per-block receipts commitment into
            // `header.receipts_root`. Verifiers cross-check this
            // against the SP1 proof's committed receipts_root.
            receipts_root,
            gas_used,
            gas_limit,
            timestamp,
            signature: [0u8; 96],
        };
        apply_body_roots(&mut header, &body_roots);

        // Sign and seal.
        let header_hash = header.hash();
        header.signature = cfg
            .proposer
            .sign_proposer_message(chain_spec.chain_id, &header_hash);
        let block_hash = header.hash();
        let block = Block { header, body };

        // Persist: header, body, FSM state, witness, tip pointer.
        // Ordering mirrors `import_block` so a partial write is
        // recoverable on restart (header → body → state → tip).
        self.store_mut().put_header(&block.header)?;
        self.store_mut().put_body(&block_hash, &block.body)?;
        self.store_mut()
            .put_block_state(&block_hash, BlockState::BlockProduced)?;
        self.store_mut().put_witness(&block_hash, &witness_bytes)?;
        self.store_mut().put_tip(block_hash)?;

        // Swap the executor's mutated trie into the engine's
        // authoritative state and flush the diff to RocksDB.
        self.replace_state_internal(next_state);
        self.update_head_internal(height, block_hash, state_root_after);
        self.flush_trie_to_store()?;

        Ok(Some(ProductionOutcome {
            block,
            block_hash,
            state_root_after,
            gas_used,
            next_validator_set_root: Some(runtime_extra),
            next_validator_set: None,
        }))
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
    vrf_proof: BlsSignature,
}
