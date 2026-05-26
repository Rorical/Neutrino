//! Accept blocks and recursive checkpoint proofs sourced from peers.
//!
//! The single-node M5 engine only knows how to **produce** blocks. M6
//! gossip and the sync FSM need the inverse path: a peer hands us a
//! signed block (or a recursive checkpoint proof) and we extend the local
//! chain after validating what we can.
//!
//! Validation is intentionally limited at this milestone. The M5 mock
//! proof system is still in use (real cryptographic verification arrives
//! in M8+, see `docs/design/09-roadmap.md`). For now we check:
//!
//! - Header chain continuity (`parent_hash` matches the local head,
//!   `height` is exactly `head + 1`).
//! - That body Merkle roots match the header commitments.
//! - Recursive checkpoint proofs verify under the supplied
//!   [`ProofSystem`].
//!
//! Re-executing the runtime to verify the block's `state_root` is
//! deferred to M8 along with real proof backends. Until then the engine
//! caches the peer-reported `state_root` so subsequent block imports
//! still see the right parent state root.

use core::fmt;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use neutrino_consensus_fork_choice::{ForkChoiceError, ProofStatus};
use neutrino_consensus_types::{
    Block, BlockProof, BlockProofPublicInputs, ChunkProof, RecursiveCheckpointProof,
    RecursiveProofPublicInputs,
};
use neutrino_consensus_vrf::{self as consensus_vrf, VrfError};
use neutrino_primitives::{
    BlockHash, Checkpoint, CheckpointIndex, ChunkHash, ChunkId, Height, Slot, StateRoot,
};
use neutrino_proof_system::{
    BlockExecutionContext, ErasedBlockExecutor, ExecutionOutcome, ProofError, ProofSystem,
};

use neutrino_storage::Database;
use neutrino_trie::Trie;

extern crate alloc;

use crate::block_state::BlockState;
use crate::body::{BodyRoots, compute_body_roots};
use crate::engine::Engine;
use crate::signature::{SignatureError, verify_header_signature};
use crate::store::StoreError;

/// Maximum allowed drift between a header's `timestamp` and the
/// slot-clock's expectation for `header.slot`, in seconds.
///
/// Sized generously enough to swallow modest NTP drift between
/// honest operators (~12s) plus a few seconds of network jitter,
/// while still rejecting a proposer that tries to fake liveness for
/// a future slot or back-date a header by hours. The local node's
/// clock is consulted indirectly via the [`crate::clock::SlotClock`]
/// anchor (genesis time + slot duration), so a clock drift of `Δ`
/// seconds shows up as `Δ` of error in this comparison.
pub const MAX_HEADER_TIMESTAMP_DRIFT_SECS: u64 = 60;

/// Successful outcome of [`Engine::import_block`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportBlockOutcome {
    /// Hash of the imported block.
    pub block_hash: BlockHash,
    /// New local head height.
    pub new_head_height: Height,
    /// New local head slot.
    pub new_head_slot: Slot,
}

/// Successful outcome of [`Engine::import_recursive_proof`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportRecursiveProofOutcome {
    /// Index of the imported checkpoint.
    pub checkpoint_index: CheckpointIndex,
    /// Hash of the imported checkpoint.
    pub checkpoint_hash: BlockHash,
}

/// Successful outcome of [`Engine::import_block_proof`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportBlockProofOutcome {
    /// Hash of the proven block.
    pub block_hash: BlockHash,
    /// Height of the proven block.
    pub height: Height,
}

/// Successful outcome of [`Engine::import_chunk_proof`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportChunkProofOutcome {
    /// Chunk id covered by the imported proof.
    pub chunk_id: ChunkId,
    /// Last block height covered by the chunk.
    pub end_height: Height,
    /// Hash of the imported chunk envelope.
    pub chunk_hash: ChunkHash,
}

/// Failures while importing a peer-supplied block or recursive proof.
#[derive(Debug)]
pub enum ImportError<E> {
    /// Header height is not `head + 1`.
    HeightMismatch {
        /// Expected height (local head + 1).
        expected: Height,
        /// Actual height in the imported header.
        actual: Height,
    },
    /// Header's `parent_hash` does not match the local head.
    ParentMismatch {
        /// Local head hash.
        expected: BlockHash,
        /// Parent hash in the imported header.
        actual: BlockHash,
    },
    /// Header proposer BLS signature failed to verify.
    HeaderSignature(SignatureError),
    /// Header proposer VRF claim failed to verify.
    HeaderVrf(VrfError),
    /// Header `timestamp` is implausibly far from the slot's clock
    /// expectation (covers both severe clock skew and a malicious
    /// proposer trying to backdate or postdate a block).
    HeaderTimestampOutOfRange {
        /// Timestamp on the imported header.
        actual: u64,
        /// Expected slot timestamp from the local slot clock.
        expected: u64,
        /// Tolerance window in seconds applied to the comparison.
        tolerance_secs: u64,
    },
    /// Header `runtime_extra` does not match the runtime's committed
    /// validator-set root for the parent's active set (the only field
    /// the engine knows how to predict pre-execution). The mismatch
    /// is caught before SP1 proof arrival so a proposer cannot
    /// silently advance the head against a forged runtime commitment.
    HeaderRuntimeExtraMismatch {
        /// Expected `runtime_extra` derived from the engine's
        /// authoritative active validator set.
        expected: [u8; 32],
        /// Value carried by the imported header.
        actual: [u8; 32],
    },
    /// Re-executing the block against the parent's state trie
    /// produced a different post-state root than the header claims.
    /// Surfaced by the optional dry-run hook of
    /// [`Engine::import_block_with_dry_run`]; pending-fix #7
    /// (doc 17): catches a malicious proposer that publishes a
    /// header with a forged `state_root` before its SP1 proof
    /// arrives.
    StateRootMismatch {
        /// Value carried by the imported header.
        expected: StateRoot,
        /// Value the local executor produced re-running the body.
        computed: StateRoot,
    },
    /// Re-executing the block produced a different `receipts_root`
    /// than the header claims. Companion to
    /// [`Self::StateRootMismatch`].
    ReceiptsRootMismatch {
        /// Value carried by the imported header.
        expected: [u8; 32],
        /// Value the local executor produced re-running the body.
        computed: [u8; 32],
    },
    /// Re-executing the block produced a different `gas_used` than
    /// the header claims. Companion to [`Self::StateRootMismatch`].
    GasUsedMismatch {
        /// Value carried by the imported header.
        expected: u64,
        /// Value the local executor produced re-running the body.
        computed: u64,
    },
    /// The dry-run executor itself failed (trap, codec error, etc.).
    /// The block is rejected because the local node could not
    /// independently verify the proposer's claim; the SP1 proof
    /// path is the canonical authority but we refuse to advance
    /// the head against an unverifiable claim.
    DryRunFailed(String),
    /// Reorg materialisation refused because the lowest common
    /// ancestor of the current head and the new fork-choice head
    /// is below the finalised height. Pending-fix #12: the
    /// engine never retracts finalised history, so a fork-choice
    /// head that would require crossing the finalised line is
    /// rejected and the materialised head stays put.
    ReorgPastFinalized {
        /// Height of the lowest common ancestor we would have
        /// reorged back to.
        lca_height: Height,
        /// First height that is now finalised (and therefore
        /// immutable). The LCA must be `>=` this value.
        finalized_height: Height,
    },
    /// Block proof references a block header that is not stored locally.
    UnknownBlock(BlockHash),
    /// Body lane roots derived from the supplied body do not match the header.
    BodyRootsMismatch {
        /// Roots committed in the header.
        header: Box<BodyRoots>,
        /// Roots re-derived from the body.
        computed: Box<BodyRoots>,
    },
    /// Stored header's parent is required to reconstruct proof public inputs.
    MissingParentHeader {
        /// Parent hash that should have been present.
        parent_hash: BlockHash,
    },
    /// Block proof envelope does not match the stored canonical header.
    BlockProofEnvelopeMismatch {
        /// Hash the proof should have covered.
        expected_hash: BlockHash,
        /// Hash carried by the proof envelope.
        actual_hash: BlockHash,
        /// Height the proof should have covered.
        expected_height: Height,
        /// Height carried by the proof envelope.
        actual_height: Height,
    },
    /// Block proof's public inputs do not match the stored canonical header.
    BlockProofPublicInputsMismatch {
        /// Block hash whose proof inputs were inconsistent.
        hash: BlockHash,
    },
    /// Imported recursive proof carries the wrong chain id.
    ChainIdMismatch {
        /// Local chain id from the chain spec.
        expected: u64,
        /// Chain id embedded in the imported checkpoint.
        actual: u64,
    },
    /// Recursive proof's checkpoint index does not extend by one.
    NonContiguousCheckpointIndex {
        /// Expected index (local latest + 1).
        expected: CheckpointIndex,
        /// Actual index supplied by the peer.
        actual: CheckpointIndex,
    },
    /// Recursive proof's checkpoint index does not match its embedded
    /// `public_inputs.index`.
    CheckpointIndexInconsistent {
        /// Index on the wire envelope.
        envelope: CheckpointIndex,
        /// Index in the embedded checkpoint public inputs.
        public_inputs: CheckpointIndex,
    },
    /// Recursive proof's checkpoint hash does not match the embedded
    /// public inputs.
    CheckpointHashInconsistent {
        /// Hash on the wire envelope.
        envelope: BlockHash,
        /// Re-derived hash from the embedded checkpoint.
        public_inputs: BlockHash,
    },
    /// Backend proof bytes failed to decode under the active backend.
    Codec(borsh::io::Error),
    /// Block proof verification rejected the proof.
    InvalidBlockProof(ProofError),
    /// Chunk proof verification rejected the proof.
    InvalidChunkProof(ProofError),
    /// Chunk proof envelope's `chunk_id` does not match its public inputs.
    ChunkProofIdInconsistent {
        /// Chunk id in the wire envelope.
        envelope: ChunkId,
        /// Chunk id in the embedded public inputs.
        public_inputs: ChunkId,
    },
    /// Recursive proof verification rejected the proof.
    InvalidRecursiveProof(ProofError),
    /// Underlying chain store / database error.
    Store(StoreError<E>),
}

impl<E> From<StoreError<E>> for ImportError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Store(value)
    }
}

impl<E: fmt::Debug + fmt::Display> fmt::Display for ImportError<E> {
    #[allow(clippy::too_many_lines)] // One arm per variant; the table is intentionally flat.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeightMismatch { expected, actual } => {
                write!(
                    f,
                    "header height {actual} does not extend local head + 1 = {expected}"
                )
            }
            Self::ParentMismatch { expected, actual } => {
                write!(
                    f,
                    "header parent_hash {actual:?} does not match local head hash {expected:?}"
                )
            }
            Self::HeaderSignature(err) => write!(f, "header signature rejected: {err}"),
            Self::HeaderVrf(err) => write!(f, "header VRF claim rejected: {err}"),
            Self::HeaderTimestampOutOfRange {
                actual,
                expected,
                tolerance_secs,
            } => write!(
                f,
                "header timestamp {actual} is outside ±{tolerance_secs}s of expected slot timestamp {expected}"
            ),
            Self::HeaderRuntimeExtraMismatch { expected, actual } => write!(
                f,
                "header runtime_extra {actual:?} does not match expected {expected:?} \
                 (validator-set root for the parent active set)"
            ),
            Self::StateRootMismatch { expected, computed } => write!(
                f,
                "dry-run state_root {computed:?} does not match header state_root {expected:?}",
            ),
            Self::ReceiptsRootMismatch { expected, computed } => write!(
                f,
                "dry-run receipts_root {computed:?} does not match header receipts_root {expected:?}",
            ),
            Self::GasUsedMismatch { expected, computed } => write!(
                f,
                "dry-run gas_used {computed} does not match header gas_used {expected}",
            ),
            Self::DryRunFailed(msg) => write!(f, "dry-run executor failed: {msg}"),
            Self::ReorgPastFinalized {
                lca_height,
                finalized_height,
            } => write!(
                f,
                "reorg refused: lowest common ancestor at height {lca_height} \
                 is below finalised height {finalized_height}",
            ),
            Self::UnknownBlock(hash) => write!(f, "block proof targets unknown block {hash:?}"),
            Self::BodyRootsMismatch { header, computed } => write!(
                f,
                "block body roots mismatch: header {header:?}, computed {computed:?}"
            ),
            Self::MissingParentHeader { parent_hash } => {
                write!(f, "parent header {parent_hash:?} is missing")
            }
            Self::BlockProofEnvelopeMismatch {
                expected_hash,
                actual_hash,
                expected_height,
                actual_height,
            } => write!(
                f,
                "block proof envelope ({actual_height}, {actual_hash:?}) does not match canonical ({expected_height}, {expected_hash:?})"
            ),
            Self::BlockProofPublicInputsMismatch { hash } => {
                write!(
                    f,
                    "block proof for {hash:?} does not match canonical public inputs"
                )
            }
            Self::ChainIdMismatch { expected, actual } => {
                write!(f, "chain id mismatch: local {expected}, peer {actual}")
            }
            Self::NonContiguousCheckpointIndex { expected, actual } => write!(
                f,
                "recursive checkpoint index {actual} is non-contiguous; expected {expected}"
            ),
            Self::CheckpointIndexInconsistent {
                envelope,
                public_inputs,
            } => write!(
                f,
                "recursive proof envelope index {envelope} does not match public inputs index {public_inputs}"
            ),
            Self::CheckpointHashInconsistent {
                envelope,
                public_inputs,
            } => write!(
                f,
                "recursive proof envelope hash {envelope:?} does not match re-derived hash {public_inputs:?}"
            ),
            Self::Codec(err) => write!(f, "borsh decode of backend proof failed: {err}"),
            Self::InvalidBlockProof(err) => {
                write!(f, "block proof verification rejected: {err:?}")
            }
            Self::InvalidChunkProof(err) => {
                write!(f, "chunk proof verification rejected: {err:?}")
            }
            Self::ChunkProofIdInconsistent {
                envelope,
                public_inputs,
            } => write!(
                f,
                "chunk proof envelope id {envelope} does not match public inputs id {public_inputs}"
            ),
            Self::InvalidRecursiveProof(err) => {
                write!(f, "recursive proof verification rejected: {err:?}")
            }
            Self::Store(err) => write!(f, "store error: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for ImportError<E> {}

impl<DB: Database> Engine<DB> {
    /// Import a peer-supplied [`Block`].
    ///
    /// Acceptance criteria:
    ///
    /// 1. The block's parent is either the genesis-block hash or
    ///    already in the local store. Non-extending blocks (siblings
    ///    of the local head, late arrivals on a competing branch) are
    ///    now accepted into the fork-choice DAG; the previous strict
    ///    "must extend the head" rule was a multi-winner-slot
    ///    foot-gun and is removed.
    /// 2. The header's slot timestamp is within
    ///    [`MAX_HEADER_TIMESTAMP_DRIFT_SECS`] of the slot clock's
    ///    expectation.
    /// 3. Header signature + VRF eligibility verify against the
    ///    active validator set.
    /// 4. Body roots match the header's commitments.
    /// 5. Empty-body blocks on a non-genesis parent have
    ///    `runtime_extra == parent.runtime_extra` (defense-in-depth
    ///    against forged validator-set roots; mutating bodies cannot
    ///    be predicted without re-execution and rely on the SP1
    ///    proof's cross-check).
    ///
    /// The block is persisted in [`BlockState::BlockProduced`].
    /// Local head pointers (`head_hash`, `head_height`,
    /// `head_state_root`) only advance when the block extends the
    /// current materialized head — full reorg materialisation across
    /// branches is pending-fix #7. The fork-choice DAG always
    /// records the block so vote-driven head selection and BFT chunk
    /// finalisation can target either branch.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError::ParentMismatch`] when the parent is
    /// unknown, [`ImportError::HeightMismatch`] when the block's
    /// height is not `parent.height + 1`,
    /// [`ImportError::HeaderTimestampOutOfRange`] /
    /// [`ImportError::HeaderRuntimeExtraMismatch`] /
    /// [`ImportError::HeaderSignature`] /
    /// [`ImportError::HeaderVrf`] /
    /// [`ImportError::BodyRootsMismatch`] on individual validation
    /// failures, or [`ImportError::Store`] on persistence failure.
    /// Import a peer-supplied [`Block`] without re-executing it.
    /// Equivalent to
    /// `import_block_with_dry_run(block, None)`. Followers running
    /// without a configured `ErasedBlockExecutor` use this entry
    /// point.
    pub fn import_block(
        &mut self,
        block: &Block,
    ) -> Result<ImportBlockOutcome, ImportError<DB::Error>> {
        self.import_block_inner(block, None)
    }

    /// Import a peer-supplied [`Block`] and, when the block extends
    /// the locally materialised head and the state trie is in sync
    /// with `head_state_root`, re-execute the block against the
    /// parent's state and cross-check the header's
    /// `state_root` / `runtime_extra` / `receipts_root` / `gas_used`
    /// commitments. Pending-fix #7 (doc 17): catches a malicious
    /// proposer that publishes a header with forged commitments
    /// before its SP1 proof arrives, so RPC clients never see
    /// state from a block that will be retroactively dropped on
    /// proof-arrival.
    ///
    /// Two import shapes call the dry-run:
    ///
    /// - **Extending block** (parent == materialised head): runs
    ///   [`Self::dry_run_block_against_head`], which re-executes
    ///   the body against the live state trie and returns the
    ///   post-execution trie. The caller commits it via
    ///   [`Self::replace_state_internal`] in lockstep with the
    ///   head pointer update so the invariant
    ///   `self.state.root() == self.head_state_root()` survives
    ///   the import.
    /// - **Sibling block** (parent != materialised head, e.g.
    ///   multi-winner slot or late arrival on a competing branch):
    ///   runs [`Self::dry_run_block_against_parent`], which
    ///   reconstructs the parent's state trie via
    ///   [`Trie::from_persisted`] and re-executes against that.
    ///   The post-state is verified against the header but
    ///   discarded — siblings do not move the materialised head
    ///   until fork choice flips, at which point
    ///   [`Self::materialise_to_fork_choice_head`] replays the
    ///   branch with the same checks.
    ///
    /// The dry-run is only skipped when the caller passes
    /// `executor = None` (i.e. backends that intentionally don't
    /// install a dynamic-runtime executor — exotic test harnesses
    /// only).  In that mode the block still passes every other
    /// validation step that [`Self::import_block`] performs.
    ///
    /// # Errors
    ///
    /// Returns every error variant [`Self::import_block`] does, plus
    /// [`ImportError::StateRootMismatch`],
    /// [`ImportError::ReceiptsRootMismatch`],
    /// [`ImportError::GasUsedMismatch`],
    /// [`ImportError::HeaderRuntimeExtraMismatch`] (for non-empty
    /// bodies — the empty-body fast path already runs in
    /// [`Self::import_block`]), and [`ImportError::DryRunFailed`]
    /// when the executor itself surfaces an error.
    pub fn import_block_with_dry_run(
        &mut self,
        block: &Block,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<ImportBlockOutcome, ImportError<DB::Error>> {
        self.import_block_inner(block, Some(executor))
    }

    /// Shared body of [`Self::import_block`] and
    /// [`Self::import_block_with_dry_run`].
    #[allow(clippy::too_many_lines)] // Validation pipeline is intentionally inlined.
    fn import_block_inner(
        &mut self,
        block: &Block,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<ImportBlockOutcome, ImportError<DB::Error>> {
        // Look up the parent header so we can check height-vs-parent
        // and (later) runtime_extra-vs-parent. The genesis block
        // hash is synthetic — there is no header for it — so it is
        // handled as a special case below.
        let parent_hash = block.header.parent_hash;
        let parent_is_genesis = parent_hash == self.chain_spec().genesis_block_hash;
        let parent_header = if parent_is_genesis {
            None
        } else {
            let h = self.store().get_header(&parent_hash)?;
            if h.is_none() {
                return Err(ImportError::ParentMismatch {
                    expected: self.head_hash(),
                    actual: parent_hash,
                });
            }
            h
        };
        let parent_height = parent_header.as_ref().map_or(0, |h| h.height);
        let expected_height = parent_height.saturating_add(1);
        if block.header.height != expected_height {
            return Err(ImportError::HeightMismatch {
                expected: expected_height,
                actual: block.header.height,
            });
        }

        // Bound the header's timestamp against the slot clock's
        // expectation for its declared slot. Tolerance is large
        // enough to swallow modest cross-host drift (and any
        // bring-up clock skew between operators) while still
        // rejecting headers that are obviously back- or post-dated.
        // A malicious proposer cannot fake liveness for a slot they
        // didn't actually win because the VRF check immediately
        // below binds (proposer_index, slot, finalized_seed).
        let expected_timestamp = self.clock().timestamp_for(block.header.slot);
        let drift = block.header.timestamp.abs_diff(expected_timestamp);
        if drift > MAX_HEADER_TIMESTAMP_DRIFT_SECS {
            return Err(ImportError::HeaderTimestampOutOfRange {
                actual: block.header.timestamp,
                expected: expected_timestamp,
                tolerance_secs: MAX_HEADER_TIMESTAMP_DRIFT_SECS,
            });
        }

        // Cross-check the header's `runtime_extra` for the empty-body
        // case on every non-genesis parent: the default runtime
        // publishes its post-block `validator_set_root` here, an
        // empty body cannot rotate the active set, so `runtime_extra`
        // must equal the parent's. We deliberately skip block 1
        // (parent = genesis) because the engine's
        // `genesis_validator_set_root` (a hash over the chain-spec
        // initial validators) and the runtime's empty-state
        // `ValidatorSet::root()` (a commitment to count 0) are
        // intentionally different commitments — the runtime treats
        // those validators as pre-existing consensus identities, not
        // as runtime-staked accounts. Bodies that touch state
        // cannot be predicted without re-execution; the SP1 proof
        // binds the real value via `BlockProofPublicInputs` so a
        // proposer cannot lie in the long run.
        let body_is_empty = block.body.transactions.is_empty()
            && block.body.slashings.is_empty()
            && block.body.finality_votes.is_empty();
        if !parent_is_genesis && body_is_empty {
            let parent_extra = parent_header
                .as_ref()
                .map_or(neutrino_primitives::ZERO_HASH, |h| h.runtime_extra);
            // ZERO_HASH stays accepted as the runtime's "no
            // commitment" marker still used by tests and pre-runtime
            // bring-up fixtures.
            if block.header.runtime_extra != neutrino_primitives::ZERO_HASH
                && block.header.runtime_extra != parent_extra
            {
                return Err(ImportError::HeaderRuntimeExtraMismatch {
                    expected: parent_extra,
                    actual: block.header.runtime_extra,
                });
            }
        }

        // Authenticate the header before doing any further work: a
        // mis-signed or non-eligible header is rejected before its
        // body is inspected or persisted. Both checks consult the
        // engine's live active validator set and the latest finalized
        // seed.
        verify_header_signature(
            &block.header,
            self.active_validator_set(),
            self.chain_spec().chain_id,
        )
        .map_err(ImportError::HeaderSignature)?;
        consensus_vrf::verify_header_proposer(
            &block.header,
            self.active_validator_set(),
            self.chain_spec().chain_id,
            &self.finalized_seed(),
            self.chain_spec().consensus.expected_proposers_per_slot,
        )
        .map_err(ImportError::HeaderVrf)?;

        let header_roots = BodyRoots {
            transactions_root: block.header.transactions_root,
            votes_root: block.header.votes_root,
            slashings_root: block.header.slashings_root,
            validator_ops_root: block.header.validator_ops_root,
            da_root: block.header.da_root,
        };
        let computed_roots = compute_body_roots(&block.body, &[]);
        if header_roots != computed_roots {
            return Err(ImportError::BodyRootsMismatch {
                header: Box::new(header_roots),
                computed: Box::new(computed_roots),
            });
        }

        // Pending-fix #7 (dry-run cross-check) + pending-fix #11
        // (follower state replay): when an executor is supplied and
        // the block extends the materialised head, re-execute the
        // body against the parent's state trie. The executor's
        // post-state trie is captured here and committed in the
        // head-update branch below via `replace_state_internal`, so
        // the invariant `self.state.root() == self.head_state_root()`
        // is maintained across imports (the producer path already
        // maintains it via the same dance in `try_produce_block`).
        //
        // On any mismatch the cross-checks surface as
        // `StateRootMismatch` / `ReceiptsRootMismatch` /
        // `GasUsedMismatch` / `HeaderRuntimeExtraMismatch`; on an
        // executor-side trap as `DryRunFailed`. The check runs
        // before fork-choice registration so a rejected block
        // leaves no DAG / store residue.
        //
        // DAG siblings (parent != materialised head) skip the
        // re-execution — they cannot be replayed without parent
        // state reconstruction, which is the reorg materialisation
        // sub-task.
        let extends_materialised_head = parent_hash == self.head_hash();
        let post_state: Option<Trie> = match (executor, extends_materialised_head) {
            (Some(executor), true) => {
                debug_assert_eq!(
                    self.state().root(),
                    self.head_state_root(),
                    "engine state trie must match head_state_root on every executor-equipped import",
                );
                Some(self.dry_run_block_against_head(executor, block)?)
            }
            (Some(executor), false) => {
                // Sibling import. Reconstruct the parent's state
                // trie from persisted nodes/values and re-execute
                // against it; this catches a malicious proposer
                // who publishes a forged commitment for a block
                // that does not extend our materialised head
                // (e.g. a multi-winner slot). The post-state is
                // verified but discarded — the materialised head
                // stays put until fork choice picks this branch
                // and `materialise_to_fork_choice_head` replays
                // forward with the same checks.
                let parent_state_root = parent_header
                    .as_ref()
                    .map_or_else(|| self.chain_spec().genesis_state_root, |h| h.state_root);
                self.dry_run_block_against_parent(executor, block, parent_state_root)?;
                None
            }
            (None, _) => None,
        };

        let hash = block.hash();

        // Register in the fork-choice DAG. Any non-extending sibling
        // imported in a multi-winner slot lands here so vote
        // weighting can later pick the heaviest branch. Persist the
        // header + body unconditionally; the FSM advances to
        // `BlockProduced` regardless of whether this block extends
        // the local materialised head.
        self.fork_choice
            .add_block(&block.header)
            .map_err(|err| match err {
                ForkChoiceError::UnknownParent(parent) => ImportError::ParentMismatch {
                    expected: self.head_hash(),
                    actual: parent,
                },
                _ => ImportError::ParentMismatch {
                    expected: self.head_hash(),
                    actual: parent_hash,
                },
            })?;
        self.store_mut().put_header(&block.header)?;
        self.store_mut().put_body(&hash, &block.body)?;
        self.store_mut()
            .put_block_state(&hash, BlockState::BlockProduced)?;

        // Linear materialisation: advance the local head only when
        // this block extends the current materialised tip. Branches
        // that fork off an earlier ancestor stay in the DAG and the
        // store but the in-memory state trie keeps following the
        // linearly-applied chain. Reorg materialisation across the
        // DAG (when `fork_choice_head()` outruns the linear head)
        // is the remaining sub-task; today, an attempt to produce
        // on top of a stale head would extend the existing chain —
        // peers running the same fork-choice rule converge through
        // gossip + vote weighting.
        if extends_materialised_head {
            self.store_mut().put_tip(hash)?;
            // Commit the dry-run's post-state in lockstep with the
            // head pointer update. After this step
            // `self.state.root() == self.head_state_root()` holds,
            // which is the invariant `dry_run_block_against_head`
            // relies on for the *next* incoming block. Producers /
            // executor-less imports skip the swap; in the
            // executor-less case the trie remains a stale view of
            // the chain (no production / dry-run will run against
            // it).
            if let Some(post_state) = post_state {
                self.replace_state_internal(post_state);
            }
            self.update_head_internal(block.header.height, hash, block.header.state_root);
            self.flush_trie_to_store()?;
        }

        // Pending-fix #12: the import may have shifted the
        // fork-choice head off the linearly-materialised tip
        // (e.g. a sibling that just arrived plus a vote-weight
        // shift; in the no-vote case this branch is a no-op
        // because tie-break favours the first-imported sibling).
        // Materialise to the new head if the executor can replay.
        // Errors abort the import; the head pointer + tip update
        // above happens FIRST, so a failed reorg leaves the engine
        // at the just-imported block, not at an inconsistent state.
        self.materialise_to_fork_choice_head(executor)?;

        // If this header completes the covering range of a previously
        // imported recursive proof, advance the finalized seed now
        // so subsequent VRF-eligibility checks observe the right
        // seed. The helper is idempotent and cheap when no advance
        // is possible.
        self.try_advance_finalized_seed()?;

        Ok(ImportBlockOutcome {
            block_hash: hash,
            new_head_height: self.head_height(),
            new_head_slot: block.header.slot,
        })
    }

    /// Re-execute `block` against the live state trie (which is the
    /// parent's post-state because the caller already verified that
    /// `parent_hash == self.head_hash()` and asserted the invariant
    /// `self.state.root() == self.head_state_root()`) and cross-check
    /// the resulting commitments against the header.
    ///
    /// On success returns the post-execution trie. The caller
    /// (`import_block_inner`) commits it via `replace_state_internal`
    /// in lockstep with the head pointer update so the engine's
    /// invariant survives import — pending-fix #11.
    ///
    /// Used by [`Self::import_block_with_dry_run`] (pending-fix #7).
    fn dry_run_block_against_head(
        &self,
        executor: &dyn ErasedBlockExecutor,
        block: &Block,
    ) -> Result<Trie, ImportError<DB::Error>> {
        let proposer_position = usize::try_from(block.header.proposer_index)
            .expect("u32 validator index fits usize on supported targets");
        let proposer_address = self
            .active_validator_set()
            .get(proposer_position)
            .map(|v| v.withdrawal_credentials)
            .unwrap_or_default();
        let ctx = BlockExecutionContext {
            chain_id: self.chain_spec().chain_id,
            block_height: block.header.height,
            gas_limit: block.header.gas_limit,
            gas_price: self.chain_spec().runtime.gas_price,
            proposer_address,
        };

        // Snapshot the engine's state trie into a scratch buffer.
        // The executor advances the scratch on success; on every
        // cross-check failure the scratch is dropped and the
        // engine's `self.state` is untouched. On success the
        // scratch is returned to the caller for commit via
        // `replace_state_internal`.
        let mut scratch = self.state().clone();
        scratch.drain_pending_nodes();
        scratch.drain_pending_values();

        let ExecutionOutcome {
            state_root_after,
            runtime_extra,
            receipts_root,
            gas_used,
            witness_bytes: _,
        } = executor
            .execute_block(&ctx, &block.body, &mut scratch)
            .map_err(ImportError::DryRunFailed)?;

        if state_root_after != block.header.state_root {
            return Err(ImportError::StateRootMismatch {
                expected: block.header.state_root,
                computed: state_root_after,
            });
        }
        if runtime_extra != block.header.runtime_extra {
            return Err(ImportError::HeaderRuntimeExtraMismatch {
                expected: block.header.runtime_extra,
                actual: runtime_extra,
            });
        }
        if receipts_root != block.header.receipts_root {
            return Err(ImportError::ReceiptsRootMismatch {
                expected: block.header.receipts_root,
                computed: receipts_root,
            });
        }
        if gas_used != block.header.gas_used {
            return Err(ImportError::GasUsedMismatch {
                expected: block.header.gas_used,
                computed: gas_used,
            });
        }
        Ok(scratch)
    }

    /// Re-execute `block` against a reconstruction of `parent_state_root`
    /// and cross-check the resulting commitments against the
    /// header.  Used by [`Self::import_block_inner`] for sibling
    /// imports — blocks whose parent is not the locally materialised
    /// head (e.g. multi-winner slots, late-arriving sibling on a
    /// competing branch).
    ///
    /// The reconstructed trie is dropped after the cross-check
    /// because the engine's materialised state continues to follow
    /// the linearly-applied chain. If fork choice subsequently
    /// promotes this branch, [`Self::materialise_to_fork_choice_head`]
    /// replays the whole new branch through the same executor with
    /// the same checks.
    ///
    /// Same cost shape as `materialise_to_fork_choice_head`: walking
    /// `iter_trie_nodes` / `iter_state_values` over the whole DB.
    /// Sibling imports are rare so this is acceptable; future
    /// optimisation can switch to a per-root index.
    fn dry_run_block_against_parent(
        &self,
        executor: &dyn ErasedBlockExecutor,
        block: &Block,
        parent_state_root: StateRoot,
    ) -> Result<(), ImportError<DB::Error>> {
        let proposer_position = usize::try_from(block.header.proposer_index)
            .expect("u32 validator index fits usize on supported targets");
        let proposer_address = self
            .active_validator_set()
            .get(proposer_position)
            .map(|v| v.withdrawal_credentials)
            .unwrap_or_default();
        let ctx = BlockExecutionContext {
            chain_id: self.chain_spec().chain_id,
            block_height: block.header.height,
            gas_limit: block.header.gas_limit,
            gas_price: self.chain_spec().runtime.gas_price,
            proposer_address,
        };

        // Content-addressed storage: loading every persisted node /
        // value is correct because the trie only navigates entries
        // reachable from `parent_state_root`.
        let trie_nodes = self.store().iter_trie_nodes()?;
        let state_values = self.store().iter_state_values()?;
        let mut scratch = Trie::from_persisted(parent_state_root, trie_nodes, state_values);

        let ExecutionOutcome {
            state_root_after,
            runtime_extra,
            receipts_root,
            gas_used,
            witness_bytes: _,
        } = executor
            .execute_block(&ctx, &block.body, &mut scratch)
            .map_err(ImportError::DryRunFailed)?;

        if state_root_after != block.header.state_root {
            return Err(ImportError::StateRootMismatch {
                expected: block.header.state_root,
                computed: state_root_after,
            });
        }
        if runtime_extra != block.header.runtime_extra {
            return Err(ImportError::HeaderRuntimeExtraMismatch {
                expected: block.header.runtime_extra,
                actual: runtime_extra,
            });
        }
        if receipts_root != block.header.receipts_root {
            return Err(ImportError::ReceiptsRootMismatch {
                expected: block.header.receipts_root,
                computed: receipts_root,
            });
        }
        if gas_used != block.header.gas_used {
            return Err(ImportError::GasUsedMismatch {
                expected: block.header.gas_used,
                computed: gas_used,
            });
        }
        Ok(())
    }

    /// Pending-fix #12: if the fork-choice DAG's head has diverged
    /// from the linearly-materialised head, walk back to the lowest
    /// common ancestor (LCA) of the two heads, reconstruct the
    /// LCA's state trie from persisted nodes, then replay every
    /// block on the new branch through `executor` against that
    /// trie. The resulting trie + head pointers are committed in
    /// lockstep so the engine's invariant
    /// `self.state.root() == self.head_state_root()` survives the
    /// reorg.
    ///
    /// No-op (returns `Ok(false)`) when:
    ///
    /// - `fork_choice.head() == self.head_hash()` — no divergence,
    /// - `executor.is_none()` — followers without an executor cannot
    ///   replay; the materialised head stays where it is (the
    ///   fork-choice head is observable via
    ///   [`Self::fork_choice_head`] for operators / RPC),
    /// - the LCA is below the finalised height — refusing the
    ///   reorg surfaces as `ImportError::ReorgPastFinalized`. The
    ///   safety floor protects already-finalised history from any
    ///   downstream bug in fork-choice scoring.
    ///
    /// Returns `Ok(true)` when the materialised head actually moved.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError::MissingParentHeader`] when the DAG
    /// references a header the store does not have (corruption);
    /// [`ImportError::ReorgPastFinalized`] when the LCA is below
    /// the finalised height (refused reorg);
    /// [`ImportError::DryRunFailed`] when the executor traps during
    /// replay; [`ImportError::StateRootMismatch`] /
    /// `ReceiptsRootMismatch` / `GasUsedMismatch` /
    /// `HeaderRuntimeExtraMismatch` when a stored header's
    /// commitments disagree with the local replay; or
    /// [`ImportError::Store`] on persistence failure.
    pub fn materialise_to_fork_choice_head(
        &mut self,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<bool, ImportError<DB::Error>> {
        let new_head = self.fork_choice.head();
        if new_head == self.head_hash() {
            return Ok(false);
        }
        let Some(executor) = executor else {
            return Ok(false);
        };

        let (lca_hash, new_branch) = self.find_lca_and_path_to(new_head)?;
        let (lca_state_root, lca_height) = self.lookup_block_state(lca_hash)?;

        // Safety floor: refuse to retract finalised history. Today
        // `fork_choice.add_finalized_chunk` is never called in
        // production (a separate gap noted in the doc 17 audit), so
        // the DAG's own anchor stays at genesis — meaning fork
        // choice cannot itself enforce this. The check here is the
        // engine-side belt to the DAG's missing braces.
        if let Some(finalized_chunk_id) = self.latest_finalized_chunk_id() {
            let chunk_size = self.chain_spec().consensus.chunk_size;
            let finalized_height = finalized_chunk_id
                .checked_add(1)
                .and_then(|n| n.checked_mul(chunk_size))
                .unwrap_or(Height::MAX);
            if lca_height < finalized_height {
                return Err(ImportError::ReorgPastFinalized {
                    lca_height,
                    finalized_height,
                });
            }
        }

        // Reconstruct the LCA's state trie. The
        // `iter_trie_nodes` / `iter_state_values` columns are
        // content-addressed (union over every branch), so loading
        // everything is correct — the trie only navigates nodes
        // reachable from `lca_state_root`. Bigger working set than
        // a per-root index would yield; acceptable for v1 because
        // reorgs are rare.
        let trie_nodes = self.store().iter_trie_nodes()?;
        let state_values = self.store().iter_state_values()?;
        let mut state = Trie::from_persisted(lca_state_root, trie_nodes, state_values);

        // Replay forward through `new_branch`. On any cross-check
        // mismatch we abandon the reorg — the materialised head
        // stays where it was, the stored header is left as
        // evidence, and the caller sees the variant-specific error.
        let mut current_height = lca_height;
        let mut current_hash = lca_hash;
        let mut current_state_root = lca_state_root;
        for block_hash in new_branch {
            let header =
                self.store()
                    .get_header(&block_hash)?
                    .ok_or(ImportError::MissingParentHeader {
                        parent_hash: block_hash,
                    })?;
            let body =
                self.store()
                    .get_body(&block_hash)?
                    .ok_or(ImportError::MissingParentHeader {
                        parent_hash: block_hash,
                    })?;

            let proposer_position = usize::try_from(header.proposer_index)
                .expect("u32 validator index fits usize on supported targets");
            let proposer_address = self
                .active_validator_set()
                .get(proposer_position)
                .map(|v| v.withdrawal_credentials)
                .unwrap_or_default();
            let ctx = BlockExecutionContext {
                chain_id: self.chain_spec().chain_id,
                block_height: header.height,
                gas_limit: header.gas_limit,
                gas_price: self.chain_spec().runtime.gas_price,
                proposer_address,
            };

            let ExecutionOutcome {
                state_root_after,
                runtime_extra,
                receipts_root,
                gas_used,
                witness_bytes: _,
            } = executor
                .execute_block(&ctx, &body, &mut state)
                .map_err(ImportError::DryRunFailed)?;

            if state_root_after != header.state_root {
                return Err(ImportError::StateRootMismatch {
                    expected: header.state_root,
                    computed: state_root_after,
                });
            }
            if runtime_extra != header.runtime_extra {
                return Err(ImportError::HeaderRuntimeExtraMismatch {
                    expected: header.runtime_extra,
                    actual: runtime_extra,
                });
            }
            if receipts_root != header.receipts_root {
                return Err(ImportError::ReceiptsRootMismatch {
                    expected: header.receipts_root,
                    computed: receipts_root,
                });
            }
            if gas_used != header.gas_used {
                return Err(ImportError::GasUsedMismatch {
                    expected: header.gas_used,
                    computed: gas_used,
                });
            }

            current_height = header.height;
            current_hash = block_hash;
            current_state_root = state_root_after;
        }

        // Commit. Replace state THEN advance the head pointers so
        // the invariant `self.state.root() == self.head_state_root()`
        // is maintained at every observable point.
        self.replace_state_internal(state);
        self.update_head_internal(current_height, current_hash, current_state_root);
        self.store_mut().put_tip(current_hash)?;
        self.flush_trie_to_store()?;
        Ok(true)
    }

    /// Walk back from `new_head` and the current materialised head
    /// via `parent_hash` until they meet at the lowest common
    /// ancestor (LCA). Returns `(lca_hash, branch_from_lca_to_new_head)`
    /// where the branch is ordered ancestor-first (LCA's immediate
    /// child first, `new_head` last) and excludes the LCA itself.
    ///
    /// Both walks terminate at the chain-spec genesis block. The
    /// genesis itself can be the LCA.
    fn find_lca_and_path_to(
        &self,
        new_head: BlockHash,
    ) -> Result<(BlockHash, Vec<BlockHash>), ImportError<DB::Error>> {
        let current_head = self.head_hash();
        let genesis = self.chain_spec().genesis_block_hash;

        // Collect every ancestor of current_head (inclusive) so the
        // walk from new_head can stop on first hit.
        let mut current_ancestors: BTreeSet<BlockHash> = BTreeSet::new();
        current_ancestors.insert(current_head);
        let mut cursor = current_head;
        while cursor != genesis {
            let header =
                self.store()
                    .get_header(&cursor)?
                    .ok_or(ImportError::MissingParentHeader {
                        parent_hash: cursor,
                    })?;
            cursor = header.parent_hash;
            current_ancestors.insert(cursor);
        }

        // Walk back from new_head until we hit a shared ancestor.
        let mut new_branch_reversed: Vec<BlockHash> = Vec::new();
        let mut cursor = new_head;
        loop {
            if current_ancestors.contains(&cursor) {
                let mut new_branch = new_branch_reversed;
                new_branch.reverse();
                return Ok((cursor, new_branch));
            }
            new_branch_reversed.push(cursor);
            if cursor == genesis {
                // new_head's chain does not descend from genesis —
                // should be impossible because every imported block
                // is gated on parent presence in the store / DAG.
                return Err(ImportError::MissingParentHeader {
                    parent_hash: cursor,
                });
            }
            let header =
                self.store()
                    .get_header(&cursor)?
                    .ok_or(ImportError::MissingParentHeader {
                        parent_hash: cursor,
                    })?;
            cursor = header.parent_hash;
        }
    }

    /// Look up `(state_root, height)` for a block hash, returning
    /// the genesis values when `hash` is the genesis-block hash
    /// (which has no stored header).
    fn lookup_block_state(
        &self,
        hash: BlockHash,
    ) -> Result<(StateRoot, Height), ImportError<DB::Error>> {
        if hash == self.chain_spec().genesis_block_hash {
            return Ok((self.chain_spec().genesis_state_root, 0));
        }
        let header = self
            .store()
            .get_header(&hash)?
            .ok_or(ImportError::MissingParentHeader { parent_hash: hash })?;
        Ok((header.state_root, header.height))
    }

    /// Import a peer-supplied block proof for an already-stored
    /// block. Equivalent to
    /// `import_block_proof_with_dry_run_executor(proof, proof_system, None)`.
    /// Followers / RPC-only nodes without a configured executor
    /// use this entry point; the proof verifies but no reorg
    /// materialisation runs on the (rare) case where the proof
    /// shifts the fork-choice head.
    pub fn import_block_proof<PS: ProofSystem>(
        &mut self,
        proof: &BlockProof,
        proof_system: &PS,
    ) -> Result<ImportBlockProofOutcome, ImportError<DB::Error>> {
        self.import_block_proof_inner(proof, proof_system, None)
    }

    /// Companion to [`Self::import_block_proof`] that threads a
    /// dynamic-runtime executor through to the post-proof reorg
    /// materialisation step. Used by the production
    /// [`ChainBackend`](../../../neutrino_node/struct.ChainBackend.html)
    /// import path so a `ProofStatus::Invalid` mark (or, when
    /// vote-feeding is wired up, a vote-weight shift triggered by
    /// the proof's arrival) reorgs the materialised head to the
    /// new fork-choice head automatically.
    pub fn import_block_proof_with_dry_run<PS: ProofSystem>(
        &mut self,
        proof: &BlockProof,
        proof_system: &PS,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<ImportBlockProofOutcome, ImportError<DB::Error>> {
        self.import_block_proof_inner(proof, proof_system, Some(executor))
    }

    /// Shared body of [`Self::import_block_proof`] and
    /// [`Self::import_block_proof_with_dry_run`].
    ///
    /// The proof envelope and public inputs are reconstructed against the
    /// canonical header in the local store before the active proof backend
    /// verifies the backend proof bytes. On success the proof is persisted and
    /// the block FSM advances to [`BlockState::Proven`] unless it is already
    /// past that state.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError`] when the block is unknown, the proof is not
    /// bound to the canonical header, backend proof bytes fail to decode, proof
    /// verification fails, or persistence fails.
    fn import_block_proof_inner<PS: ProofSystem>(
        &mut self,
        proof: &BlockProof,
        proof_system: &PS,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<ImportBlockProofOutcome, ImportError<DB::Error>> {
        let header = self
            .store()
            .get_header(&proof.block_hash)?
            .ok_or(ImportError::UnknownBlock(proof.block_hash))?;
        let canonical_hash = header.hash();
        if proof.block_hash != canonical_hash || proof.height != header.height {
            return Err(ImportError::BlockProofEnvelopeMismatch {
                expected_hash: canonical_hash,
                actual_hash: proof.block_hash,
                expected_height: header.height,
                actual_height: proof.height,
            });
        }

        let state_root_before = self.block_proof_state_root_before(&header)?;
        let expected_public_inputs =
            self.block_proof_public_inputs(&header, state_root_before, canonical_hash);
        if proof.public_inputs != expected_public_inputs {
            return Err(ImportError::BlockProofPublicInputsMismatch {
                hash: canonical_hash,
            });
        }

        let backend_proof: PS::BlockProof =
            borsh::from_slice(&proof.proof_bytes).map_err(ImportError::Codec)?;
        if let Err(err) = proof_system.verify_block(&backend_proof, &proof.public_inputs) {
            // Cache the rejected proof envelope so the
            // `InvalidProofSigning` detector can surface evidence
            // when a peer precommit later arrives for a chunk
            // covering this block. The cache is opt-out: legitimate
            // peers re-publish corrected proofs and the cache entry
            // is cleared on the next successful import (above).
            let reason = match err {
                neutrino_proof_system::ProofError::MalformedProof => {
                    neutrino_consensus_types::ProofRejectionReason::MalformedProof
                }
                neutrino_proof_system::ProofError::PublicInputMismatch => {
                    neutrino_consensus_types::ProofRejectionReason::PublicInputsMismatch
                }
                _ => neutrino_consensus_types::ProofRejectionReason::VerifierRejected,
            };
            self.record_rejected_proof(canonical_hash, proof.clone(), reason);
            // Notify the fork-choice DAG so the block (and every
            // descendant) is excluded from `head()` candidates. The
            // helper silently no-ops when the block hasn't been
            // registered (e.g. unit tests that never called
            // `import_block`).
            let _ = self
                .fork_choice
                .on_block_proof(canonical_hash, ProofStatus::Invalid);
            // Pending-fix #12: if our local materialised head was
            // on the now-Invalid branch, the materialise step
            // moves it off. Swallow materialise errors here so the
            // caller sees the more important `InvalidBlockProof`
            // error (the proof was bad; the materialise failure is
            // a secondary symptom and the next import will retry).
            let _ = self.materialise_to_fork_choice_head(executor);
            return Err(ImportError::InvalidBlockProof(err));
        }
        // Successful import — clear any stale rejected-proof entry
        // for this block (a peer's earlier corrupted gossip should
        // not slash any future signer once an honest proof lands).
        self.clear_rejected_proof(&canonical_hash);

        self.store_mut().put_block_proof(&canonical_hash, proof)?;
        match self.store().get_block_state(&canonical_hash)? {
            Some(BlockState::BlockProduced | BlockState::PendingProof | BlockState::Proven)
            | None => {
                self.store_mut()
                    .put_block_state(&canonical_hash, BlockState::Proven)?;
            }
            Some(BlockState::ChunkProven | BlockState::Finalized | BlockState::Checkpointed) => {}
        }
        // Promote the block from `PendingProof` to `Proven` in the
        // fork-choice DAG. Branches built on top of unproven blocks
        // are still excluded from `head()` — promotion to `Proven`
        // lets them count.
        let _ = self
            .fork_choice
            .on_block_proof(canonical_hash, ProofStatus::Proven);

        // Pending-fix #12: the proof status mutation may have
        // promoted a non-canonical sibling above the linearly-
        // materialised head in fork-choice scoring (e.g. our local
        // head was Invalid'd above; or in the future,
        // vote-weighted scoring shifts when a freshly proven
        // chunk's votes start counting). Materialise to the new
        // head if the executor can replay.
        self.materialise_to_fork_choice_head(executor)?;

        Ok(ImportBlockProofOutcome {
            block_hash: canonical_hash,
            height: header.height,
        })
    }

    /// Import a peer-supplied chunk proof.
    ///
    /// The envelope's `chunk_id` is validated against its embedded
    /// public inputs, the backend proof bytes are decoded and verified
    /// against [`ProofSystem::verify_chunk`], and the wire proof is
    /// persisted at [`crate::store::keys::chunk_id_key`]. The engine's
    /// `latest_finalized_chunk_id` pointer is **not** advanced — that
    /// transition is driven by the BFT finalization path in M7.
    /// Persisting the proof early lets followers serve
    /// `/neutrino/req/chunk_proof_by_id/1` and gives the M7 BFT slice
    /// a local artifact to bind votes against.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError::ChunkProofIdInconsistent`] when the
    /// envelope and public inputs disagree, [`ImportError::Codec`]
    /// when the backend proof bytes fail to decode,
    /// [`ImportError::InvalidChunkProof`] when verification fails,
    /// or [`ImportError::Store`] on persistence failure.
    pub fn import_chunk_proof<PS: ProofSystem>(
        &mut self,
        proof: &ChunkProof,
        proof_system: &PS,
    ) -> Result<ImportChunkProofOutcome, ImportError<DB::Error>> {
        if proof.chunk_id != proof.public_inputs.chunk_id {
            return Err(ImportError::ChunkProofIdInconsistent {
                envelope: proof.chunk_id,
                public_inputs: proof.public_inputs.chunk_id,
            });
        }
        let backend_proof: PS::ChunkProof =
            borsh::from_slice(&proof.proof_bytes).map_err(ImportError::Codec)?;
        proof_system
            .verify_chunk(&backend_proof, &proof.public_inputs)
            .map_err(ImportError::InvalidChunkProof)?;
        self.store_mut().put_chunk_proof(proof.chunk_id, proof)?;
        Ok(ImportChunkProofOutcome {
            chunk_id: proof.chunk_id,
            end_height: proof.public_inputs.end_height,
            chunk_hash: proof.chunk_hash,
        })
    }

    /// Import a peer-supplied recursive checkpoint proof.
    ///
    /// The proof's `public_inputs` carry the [`Checkpoint`] under
    /// recursion. The function verifies internal consistency (chain id,
    /// index extension, hash), borsh-decodes the backend proof, runs
    /// `proof_system.verify_recursive` on the public inputs, and then
    /// persists the checkpoint, the recursive proof, and the
    /// `latest_checkpoint_index` pointer.
    ///
    /// # Errors
    ///
    /// Returns any [`ImportError`] variant on validation, decode, or
    /// store failure.
    pub fn import_recursive_proof<PS: ProofSystem>(
        &mut self,
        proof: &RecursiveCheckpointProof,
        proof_system: &PS,
    ) -> Result<ImportRecursiveProofOutcome, ImportError<DB::Error>> {
        let checkpoint: &Checkpoint = &proof.public_inputs;

        if checkpoint.chain_id != self.chain_spec().chain_id {
            return Err(ImportError::ChainIdMismatch {
                expected: self.chain_spec().chain_id,
                actual: checkpoint.chain_id,
            });
        }

        let expected_index = self.latest_checkpoint_index().saturating_add(1);
        if proof.checkpoint_index != expected_index {
            return Err(ImportError::NonContiguousCheckpointIndex {
                expected: expected_index,
                actual: proof.checkpoint_index,
            });
        }
        if proof.checkpoint_index != checkpoint.index {
            return Err(ImportError::CheckpointIndexInconsistent {
                envelope: proof.checkpoint_index,
                public_inputs: checkpoint.index,
            });
        }

        let recomputed_hash = checkpoint.hash();
        if proof.checkpoint_hash != recomputed_hash {
            return Err(ImportError::CheckpointHashInconsistent {
                envelope: proof.checkpoint_hash,
                public_inputs: recomputed_hash,
            });
        }

        let backend_proof: PS::RecursiveProof =
            borsh::from_slice(&proof.proof_bytes).map_err(ImportError::Codec)?;
        let public_inputs: RecursiveProofPublicInputs = checkpoint.clone();
        proof_system
            .verify_recursive(&backend_proof, &public_inputs)
            .map_err(ImportError::InvalidRecursiveProof)?;

        self.store_mut().put_checkpoint(checkpoint)?;
        self.store_mut()
            .put_recursive_proof(proof.checkpoint_index, proof)?;
        self.store_mut()
            .put_latest_checkpoint_index(proof.checkpoint_index)?;
        // Update the in-memory checkpoint pointer; the seed advance
        // is two-phase and may only complete after the corresponding
        // headers are also imported.
        self.update_checkpoint_pointers(proof.checkpoint_index, self.finalized_seed());
        // Followers usually receive recursive proofs ahead of the
        // headers they cover (CheckpointBackfill → HeaderBackfill).
        // Attempt the advance now in case the headers were already
        // imported — `import_block` re-runs the helper after every
        // gossip block so a later header that completes the chunk's
        // range triggers the fold without further user action.
        self.try_advance_finalized_seed()?;

        Ok(ImportRecursiveProofOutcome {
            checkpoint_index: proof.checkpoint_index,
            checkpoint_hash: recomputed_hash,
        })
    }

    fn block_proof_state_root_before(
        &self,
        header: &neutrino_consensus_types::Header,
    ) -> Result<StateRoot, ImportError<DB::Error>> {
        if header.parent_hash == self.chain_spec().genesis_block_hash {
            return Ok(self.chain_spec().genesis_state_root);
        }
        let parent = self.store().get_header(&header.parent_hash)?.ok_or(
            ImportError::MissingParentHeader {
                parent_hash: header.parent_hash,
            },
        )?;
        Ok(parent.state_root)
    }

    fn block_proof_public_inputs(
        &self,
        header: &neutrino_consensus_types::Header,
        state_root_before: StateRoot,
        block_hash: BlockHash,
    ) -> BlockProofPublicInputs {
        BlockProofPublicInputs {
            chain_id: self.chain_spec().chain_id,
            height: header.height,
            parent_block_hash: header.parent_hash,
            block_hash,
            state_root_before,
            state_root_after: header.state_root,
            transactions_root: header.transactions_root,
            receipt_root: header.receipts_root,
            da_root: header.da_root,
            vm_code_hash: self.chain_spec().runtime_code_hash,
            abi_version: self.chain_spec().runtime_version.abi_version,
            gas_used: header.gas_used,
            gas_limit: header.gas_limit,
            gas_price: self.chain_spec().runtime.gas_price,
            proposer_address: self.proposer_runtime_address_for_import(header.proposer_index),
        }
    }

    /// Equivalent of `Engine::proposer_runtime_address` available
    /// inside the import path; kept as a method on `Engine` rather
    /// than a free function so the active validator set lookup
    /// observes the same in-memory state as the rest of import.
    fn proposer_runtime_address_for_import(
        &self,
        proposer_index: neutrino_primitives::ValidatorIndex,
    ) -> neutrino_primitives::Hash {
        usize::try_from(proposer_index)
            .ok()
            .and_then(|i| self.active_validator_set().get(i))
            .map_or(neutrino_primitives::ZERO_HASH, |v| v.withdrawal_credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProposerKey;
    use crate::validator_set::validator_set_root;
    use neutrino_consensus_types::{BlockProofPublicInputs, Body, ChunkProofPublicInputs, Header};
    use neutrino_primitives::{
        BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, ConsensusParams, HEADER_VERSION,
        LightClientParams, ProofParams, RuntimeParams, RuntimeVersion, StateParams, Validator,
        ZERO_HASH,
    };
    use neutrino_proof_system::MockProofSystem;
    use neutrino_storage::MemoryDatabase;

    const TEST_CHAIN_ID: u64 = 7;
    const TEST_GENESIS_SEED: [u8; 32] = [0xDD; 32];
    const TEST_IKM: [u8; 32] = [0xAA; 32];
    /// Anchor for the in-test slot clock. Test fixtures use this to
    /// build header timestamps the post-M5-new import validator
    /// accepts (`abs(header.ts - clock.timestamp_for(slot)) <= 60s`).
    const TEST_GENESIS_TIME: u64 = 1_700_000_000;

    fn proposer() -> ProposerKey {
        ProposerKey::from_ikm(&TEST_IKM, 0).expect("derive proposer key")
    }

    fn validators() -> Vec<Validator> {
        vec![Validator {
            pubkey: *proposer().public_key_bytes(),
            withdrawal_credentials: [2; 32],
            effective_stake: 32_000_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }]
    }

    fn spec() -> ChainSpec {
        let proof = ProofParams::default();
        let vs_root = validator_set_root(&validators());
        let genesis_block_hash: BlockHash = [0xAA; 32];
        let checkpoint = Checkpoint {
            chain_id: TEST_CHAIN_ID,
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
            name: BoundedBytes::new(b"m6-import-test".to_vec()).expect("name fits"),
            chain_id: TEST_CHAIN_ID,
            genesis_time: TEST_GENESIS_TIME,
            genesis_gas_limit: 30_000_000,
            runtime_version: RuntimeVersion::default(),
            runtime_code_hash: [0xCC; 32],
            genesis_seed: TEST_GENESIS_SEED,
            genesis_state_root: ZERO_HASH,
            genesis_block_hash,
            genesis_validator_set_root: vs_root,
            genesis_checkpoint: checkpoint,
            consensus: ConsensusParams::default(),
            proof,
            state: StateParams::default(),
            light_client: LightClientParams::default(),
            runtime: RuntimeParams::default(),
            initial_validators: validators(),
            metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
        }
    }

    /// Build a fully signed, VRF-eligible block. `proposer_override` lets
    /// individual tests use a key whose pubkey is NOT in the active set,
    /// which is how the rejection paths are exercised.
    fn signed_block(
        height: Height,
        slot: Slot,
        parent: BlockHash,
        state_root: [u8; 32],
        proposer_override: Option<&ProposerKey>,
    ) -> Block {
        let key = proposer();
        let signing_key = proposer_override.unwrap_or(&key);
        let body = Body::default();
        let roots = compute_body_roots(&body, &[]);

        let (vrf_proof, _) = neutrino_vrf::eval(
            signing_key.secret_key(),
            TEST_CHAIN_ID,
            &TEST_GENESIS_SEED,
            slot,
        );

        let mut header = Header {
            version: HEADER_VERSION,
            height,
            slot,
            parent_hash: parent,
            proposer_index: signing_key.validator_index(),
            vrf_proof: vrf_proof.to_bytes(),
            state_root,
            transactions_root: roots.transactions_root,
            votes_root: roots.votes_root,
            slashings_root: roots.slashings_root,
            validator_ops_root: roots.validator_ops_root,
            da_root: roots.da_root,
            runtime_extra: ZERO_HASH,
            receipts_root: ZERO_HASH,
            gas_used: 0,
            gas_limit: 1_000_000,
            timestamp: TEST_GENESIS_TIME + slot * 4,
            signature: [0; 96],
        };
        let header_hash = header.hash();
        header.signature = signing_key.sign_proposer_message(TEST_CHAIN_ID, &header_hash);
        Block { header, body }
    }

    /// Convenience: signed by the canonical test proposer.
    fn block(height: Height, slot: Slot, parent: BlockHash, state_root: [u8; 32]) -> Block {
        signed_block(height, slot, parent, state_root, None)
    }

    #[test]
    fn import_block_extends_local_head() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();

        let genesis_hash = engine.head_hash();
        let block1 = block(1, 1, genesis_hash, [5; 32]);

        let outcome = engine
            .import_block(&block1)
            .expect("first block extends genesis");
        assert_eq!(outcome.new_head_height, 1);
        assert_eq!(outcome.block_hash, block1.hash());
        assert_eq!(engine.head_height(), 1);
        assert_eq!(engine.head_state_root(), [5; 32]);

        // Chain into block 2.
        let block2 = block(2, 2, outcome.block_hash, [6; 32]);
        let outcome = engine.import_block(&block2).expect("second extends first");
        assert_eq!(outcome.new_head_height, 2);
        assert_eq!(engine.head_hash(), block2.hash());
    }

    #[test]
    fn import_block_rejects_wrong_parent() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let block = block(1, 1, [0; 32], [5; 32]); // wrong parent
        match engine.import_block(&block) {
            Err(ImportError::ParentMismatch { .. }) => {}
            other => panic!("expected ParentMismatch, got {other:?}"),
        }
        assert_eq!(engine.head_height(), 0);
    }

    #[test]
    fn import_block_rejects_skipped_height() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let block = block(2, 2, engine.head_hash(), [5; 32]); // skips height 1
        match engine.import_block(&block) {
            Err(ImportError::HeightMismatch { .. }) => {}
            other => panic!("expected HeightMismatch, got {other:?}"),
        }
    }

    #[test]
    fn import_block_rejects_body_root_mismatch() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let mut block = block(1, 1, engine.head_hash(), [5; 32]);
        block.body.transactions.push(vec![1, 2, 3]);

        match engine.import_block(&block) {
            Err(ImportError::BodyRootsMismatch { .. }) => {}
            other => panic!("expected BodyRootsMismatch, got {other:?}"),
        }
    }

    #[test]
    fn import_block_rejects_tampered_signature() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let mut block = block(1, 1, engine.head_hash(), [5; 32]);
        // Flip a bit in the signature so it no longer matches the
        // canonical signed message.
        block.header.signature[0] ^= 0x80;
        match engine.import_block(&block) {
            Err(ImportError::HeaderSignature(_)) => {}
            other => panic!("expected HeaderSignature error, got {other:?}"),
        }
        assert_eq!(engine.head_height(), 0);
    }

    #[test]
    fn import_block_rejects_signature_from_foreign_key() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        // Build a block whose header signature comes from a key that
        // is NOT in the active set. The proposer_index still points at
        // slot 0 (the canonical validator), so the signature is checked
        // against the wrong pubkey and must fail.
        let attacker = ProposerKey::from_ikm(&[0xBE; 32], 0).expect("derive attacker");
        let mut block = signed_block(1, 1, engine.head_hash(), [5; 32], Some(&attacker));
        // Force the proposer index back to the legitimate validator so
        // the active-set lookup picks the wrong key for verification.
        block.header.proposer_index = 0;
        let header_hash = block.header.hash();
        // Re-sign with the attacker key under the legitimate proposer
        // index so the signature decodes but verifies against the
        // wrong public key.
        block.header.signature = attacker.sign_proposer_message(TEST_CHAIN_ID, &header_hash);

        match engine.import_block(&block) {
            Err(ImportError::HeaderSignature(_)) => {}
            other => panic!("expected HeaderSignature error, got {other:?}"),
        }
    }

    #[test]
    fn import_block_rejects_tampered_vrf_proof() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let mut block = block(1, 1, engine.head_hash(), [5; 32]);
        // Replace the VRF proof with garbage that decodes as a BLS
        // signature but does not verify against the validator's key.
        let attacker = ProposerKey::from_ikm(&[0xCE; 32], 0).expect("derive attacker");
        let (bogus_vrf, _) = neutrino_vrf::eval(
            attacker.secret_key(),
            TEST_CHAIN_ID,
            &TEST_GENESIS_SEED,
            block.header.slot,
        );
        block.header.vrf_proof = bogus_vrf.to_bytes();
        // Re-sign the header so the signature check passes; only the
        // VRF claim is bogus.
        let header_hash = block.header.hash();
        block.header.signature = proposer().sign_proposer_message(TEST_CHAIN_ID, &header_hash);

        match engine.import_block(&block) {
            Err(ImportError::HeaderVrf(_)) => {}
            other => panic!("expected HeaderVrf error, got {other:?}"),
        }
    }

    #[test]
    fn import_block_rejects_proposer_index_out_of_range() {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let mut block = block(1, 1, engine.head_hash(), [5; 32]);
        // The active set has length 1, so index 5 is out of bounds.
        block.header.proposer_index = 5;
        let header_hash = block.header.hash();
        // Re-sign so signature decoding does not short-circuit; the
        // missing validator lookup must be the first failure.
        block.header.signature = proposer().sign_proposer_message(TEST_CHAIN_ID, &header_hash);

        match engine.import_block(&block) {
            Err(ImportError::HeaderSignature(SignatureError::ValidatorIndexOutOfBounds {
                index: 5,
                len: 1,
            })) => {}
            other => panic!("expected ValidatorIndexOutOfBounds, got {other:?}"),
        }
    }

    fn produce_and_verify_recursive_proof(
        chain_spec: &ChainSpec,
        index: CheckpointIndex,
        start_height: Height,
        end_height: Height,
        end_block_hash: BlockHash,
        end_state_root: [u8; 32],
    ) -> RecursiveCheckpointProof {
        let proof_system = MockProofSystem::new();
        let public_inputs = Checkpoint {
            chain_id: chain_spec.chain_id,
            index,
            start_height,
            end_height,
            start_block_hash: ZERO_HASH,
            end_block_hash,
            start_state_root: ZERO_HASH,
            end_state_root,
            end_validator_set_root: validator_set_root(&validators()),
            history_root: ZERO_HASH,
            proof_system_version: chain_spec.proof.proof_system_version,
        };

        // Mock backend produces a placeholder block + chunk proof so
        // the recursive prove call has the right inputs.
        let block_inputs = BlockProofPublicInputs {
            chain_id: chain_spec.chain_id,
            height: end_height,
            parent_block_hash: ZERO_HASH,
            block_hash: end_block_hash,
            state_root_before: ZERO_HASH,
            state_root_after: end_state_root,
            transactions_root: ZERO_HASH,
            receipt_root: ZERO_HASH,
            da_root: ZERO_HASH,
            vm_code_hash: ZERO_HASH,
            abi_version: 1,
            gas_used: 0,
            gas_limit: 1_000_000,
            gas_price: 0,
            proposer_address: [0u8; 32],
        };
        let block_proof = proof_system
            .prove_block(&[], &block_inputs)
            .expect("mock block proof");
        let chunk_inputs = ChunkProofPublicInputs {
            chunk_id: index.saturating_sub(1),
            start_height,
            end_height,
            start_state_root: ZERO_HASH,
            end_state_root,
            start_block_hash: ZERO_HASH,
            end_block_hash,
            block_hash_root: ZERO_HASH,
            block_proof_root: ZERO_HASH,
            vrf_proof_root: ZERO_HASH,
            active_validator_set_root: validator_set_root(&validators()),
            next_validator_set_root: validator_set_root(&validators()),
            da_root: ZERO_HASH,
        };
        let chunk_proof = proof_system
            .prove_chunk(&[block_proof], &chunk_inputs)
            .expect("mock chunk proof");
        let recursive = proof_system
            .prove_recursive(None, &chunk_proof, &public_inputs)
            .expect("mock recursive proof");
        let proof_bytes = borsh::to_vec(&recursive).expect("borsh encode");

        RecursiveCheckpointProof {
            checkpoint_index: index,
            checkpoint_hash: public_inputs.hash(),
            public_inputs,
            proof_bytes,
        }
    }

    #[test]
    fn import_recursive_proof_accepts_a_well_formed_proof() {
        let chain_spec = spec();
        let mut engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
        let proof_system = MockProofSystem::new();

        let proof =
            produce_and_verify_recursive_proof(&chain_spec, 1, 0, 128, [0x77; 32], [0x88; 32]);

        let outcome = engine
            .import_recursive_proof(&proof, &proof_system)
            .expect("import valid recursive proof");
        assert_eq!(outcome.checkpoint_index, 1);
        assert_eq!(engine.latest_checkpoint_index(), 1);
    }

    #[test]
    fn import_recursive_proof_rejects_wrong_chain_id() {
        let chain_spec = spec();
        let mut engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
        let proof_system = MockProofSystem::new();

        let mut bad =
            produce_and_verify_recursive_proof(&chain_spec, 1, 0, 128, [0x77; 32], [0x88; 32]);
        bad.public_inputs.chain_id = 99;
        bad.checkpoint_hash = bad.public_inputs.hash();

        match engine.import_recursive_proof(&bad, &proof_system) {
            Err(ImportError::ChainIdMismatch {
                expected: 7,
                actual: 99,
            }) => {}
            other => panic!("expected ChainIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn import_recursive_proof_rejects_skipped_index() {
        let chain_spec = spec();
        let mut engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
        let proof_system = MockProofSystem::new();

        // Index 2 cannot be imported before index 1.
        let proof =
            produce_and_verify_recursive_proof(&chain_spec, 2, 128, 256, [0x77; 32], [0x88; 32]);
        match engine.import_recursive_proof(&proof, &proof_system) {
            Err(ImportError::NonContiguousCheckpointIndex {
                expected: 1,
                actual: 2,
            }) => {}
            other => panic!("expected NonContiguousCheckpointIndex, got {other:?}"),
        }
    }

    /// Build a recursive proof whose covered range matches the given
    /// `end_height`. Mirrors `produce_and_verify_recursive_proof` but
    /// is parameterised so seed-advance tests can supply the real
    /// `end_height` after a small block sequence.
    fn recursive_proof_for_range(
        chain_spec: &ChainSpec,
        index: CheckpointIndex,
        start_height: Height,
        end_height: Height,
        end_block_hash: BlockHash,
        end_state_root: [u8; 32],
    ) -> RecursiveCheckpointProof {
        produce_and_verify_recursive_proof(
            chain_spec,
            index,
            start_height,
            end_height,
            end_block_hash,
            end_state_root,
        )
    }

    #[test]
    fn import_recursive_proof_advances_seed_when_headers_already_present() {
        // Header-first ordering: import block 1, then import the
        // recursive proof covering height 1. The seed should advance
        // immediately because the covering header is in the store.
        let chain_spec = spec();
        let mut engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
        let proof_system = MockProofSystem::new();

        let initial_seed = engine.finalized_seed();
        let b1 = block(1, 1, engine.head_hash(), [0x11; 32]);
        engine.import_block(&b1).expect("import block 1");
        // No checkpoint imported yet, so seed must not have advanced.
        assert_eq!(engine.finalized_seed(), initial_seed);

        let proof = recursive_proof_for_range(&chain_spec, 1, 0, 1, b1.hash(), [0x11; 32]);
        engine
            .import_recursive_proof(&proof, &proof_system)
            .expect("import recursive proof");
        // The header at height 1 was already present, so the seed
        // must have folded chunk 1's VRF proofs in.
        let folded = neutrino_vrf::fold_seed(&initial_seed, &[b1.header.vrf_proof]);
        assert_eq!(engine.finalized_seed(), folded);
        assert_eq!(
            engine
                .store()
                .get_seed_advanced_through_checkpoint()
                .unwrap(),
            Some(1)
        );
    }

    #[test]
    fn import_block_advances_seed_after_checkpoint_for_late_arriving_header() {
        // Checkpoint-first ordering (typical sync FSM):
        // CheckpointBackfill imports the recursive proof before
        // HeaderBackfill imports the headers. The seed must defer
        // until the last covering header arrives and then advance.
        let chain_spec = spec();
        let mut engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
        let proof_system = MockProofSystem::new();

        let initial_seed = engine.finalized_seed();

        // Build the header but do NOT import it yet so we know its
        // VRF proof for later assertion.
        let b1 = block(1, 1, engine.head_hash(), [0x11; 32]);

        // Phase 1: checkpoint arrives before the header. The seed
        // cannot advance because heights [1, 1] are missing.
        let proof = recursive_proof_for_range(&chain_spec, 1, 0, 1, b1.hash(), [0x11; 32]);
        engine
            .import_recursive_proof(&proof, &proof_system)
            .expect("import recursive proof");
        assert_eq!(engine.finalized_seed(), initial_seed);
        assert_eq!(
            engine
                .store()
                .get_seed_advanced_through_checkpoint()
                .unwrap()
                .unwrap_or(0),
            0
        );

        // Phase 2: header arrives. The block-import path retries
        // the seed advance and folds the chunk now that headers
        // are present.
        engine.import_block(&b1).expect("import block 1");
        let folded = neutrino_vrf::fold_seed(&initial_seed, &[b1.header.vrf_proof]);
        assert_eq!(engine.finalized_seed(), folded);
        assert_eq!(
            engine
                .store()
                .get_seed_advanced_through_checkpoint()
                .unwrap(),
            Some(1)
        );
    }

    #[test]
    fn import_recursive_proof_does_not_advance_seed_when_headers_missing() {
        // No headers imported. The recursive proof for height 1
        // arrives. Seed must stay put; the pointer must stay at 0.
        let chain_spec = spec();
        let mut engine = Engine::genesis(chain_spec.clone(), MemoryDatabase::new()).unwrap();
        let proof_system = MockProofSystem::new();

        let initial_seed = engine.finalized_seed();
        let proof = recursive_proof_for_range(&chain_spec, 1, 0, 1, [0x22; 32], [0x11; 32]);
        engine
            .import_recursive_proof(&proof, &proof_system)
            .expect("import recursive proof");
        assert_eq!(engine.finalized_seed(), initial_seed);
        assert_eq!(
            engine
                .store()
                .get_seed_advanced_through_checkpoint()
                .unwrap()
                .unwrap_or(0),
            0
        );
    }
}
