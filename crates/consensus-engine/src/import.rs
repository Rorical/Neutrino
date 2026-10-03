//! Verify and archive peer blocks and proofs, replay selected branches, and
//! publish complete chunk finality with its canonical head and state atomically.
//!
//! Executor-equipped production imports check runtime commitments before storage.

use core::fmt;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use neutrino_consensus_fork_choice::{ForkChoiceError, ProofStatus};
use neutrino_consensus_types::history::is_recent_history_index;
use neutrino_consensus_types::{Block, BlockProof, BlockProofPublicInputs, ChunkProof};
use neutrino_consensus_vrf::{self as consensus_vrf, VrfError};
use neutrino_primitives::{BlockHash, ChunkHash, ChunkId, Height, Slot, StateRoot};
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

/// Failures while importing a peer-supplied block or complete chunk proof.
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
    /// catches a malicious proposer that publishes a
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
    /// An embedded vote targets a chunk outside the preceding eight finalized chunks.
    HistoricalVoteOutsideWindow {
        /// Chunk containing the imported block.
        chunk_id: ChunkId,
        /// Historical chunk claimed by the embedded vote.
        referenced_chunk: ChunkId,
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
                "header runtime_extra {actual:?} does not match executed runtime commitment {expected:?}"
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
            Self::HistoricalVoteOutsideWindow {
                chunk_id,
                referenced_chunk,
            } => write!(
                f,
                "embedded vote for chunk {referenced_chunk} is outside chunk {chunk_id}'s history window"
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
            Self::Store(err) => write!(f, "store error: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for ImportError<E> {}

pub(crate) struct ReplayedHead {
    pub(crate) height: Height,
    pub(crate) hash: BlockHash,
    pub(crate) state_root: StateRoot,
    pub(crate) state: Trie,
}

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
    /// commitments. catches a malicious
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
    ///   [`Self::commit_materialized_head`] in lockstep with the
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
        // Replayed gossip must not demote Proven/Finalized back to Produced.
        // Compare the full previously authenticated artifact, including signature
        // and body, before returning the current materialized head unchanged.
        let hash = block.hash();
        if self.store().get_header(&hash)?.as_ref() == Some(&block.header)
            && self
                .store()
                .get_body(&hash)?
                .as_ref()
                .is_some_and(|body| body.same_consensus_content(&block.body))
        {
            let head_slot = self
                .store()
                .get_header(&self.head_hash())?
                .map_or(0, |header| header.slot);
            return Ok(ImportBlockOutcome {
                block_hash: self.head_hash(),
                new_head_height: self.head_height(),
                new_head_slot: head_slot,
            });
        }

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
            da_root: block.header.da_root,
        };
        let computed_roots = compute_body_roots(&block.body);
        if header_roots != computed_roots {
            return Err(ImportError::BodyRootsMismatch {
                header: Box::new(header_roots),
                computed: Box::new(computed_roots),
            });
        }
        let chunk_id =
            block.header.height.saturating_sub(1) / self.chain_spec().consensus.chunk_size;
        if let Some(vote) = block
            .body
            .finality_votes
            .iter()
            .find(|vote| !is_recent_history_index(vote.data.chunk_id, chunk_id))
        {
            return Err(ImportError::HistoricalVoteOutsideWindow {
                chunk_id,
                referenced_chunk: vote.data.chunk_id,
            });
        }

        // Pending-fix #7 (dry-run cross-check) + pending-fix #11
        // (follower state replay): when an executor is supplied and
        // the block extends the materialised head, re-execute the
        // body against the parent's state trie. The executor's
        // post-state trie is captured here and committed in the
        // head-update branch below via `commit_materialized_head`, so
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
                // that does not extend our materialised head.
                // Persist the verified post-state for subsequent sibling
                // descendants; the materialized head stays put until
                // fork choice picks this branch
                // and `materialise_to_fork_choice_head` replays
                // forward with the same checks.
                let parent_state_root = parent_header
                    .as_ref()
                    .map_or_else(|| self.chain_spec().genesis_state_root, |h| h.state_root);
                Some(self.dry_run_block_against_parent(executor, block, parent_state_root)?)
            }
            (None, _) => None,
        };

        let hash = block.hash();

        let mut next_fork_choice = self.fork_choice.clone();
        next_fork_choice
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
        let mut batch = crate::store::ChainStore::<DB>::block_archive_batch(block, None)?;
        if extends_materialised_head {
            self.commit_materialized_head_with_batch(
                block.header.height,
                hash,
                block.header.state_root,
                post_state,
                batch,
            )?;
        } else {
            if let Some(mut archived_state) = post_state {
                for (key, bytes) in archived_state.drain_pending_nodes() {
                    batch.put(neutrino_storage::Column::TrieNodes, key, bytes);
                }
                for (key, bytes) in archived_state.drain_pending_values() {
                    batch.put(neutrino_storage::Column::StateValues, key, bytes);
                }
            }
            self.store_mut()
                .db_mut()
                .write_batch(batch)
                .map_err(StoreError::Database)?;
        }
        self.fork_choice = next_fork_choice;

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
    /// (`import_block_inner`) commits it via `commit_materialized_head`
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
            evidence_anchor: self
                .evidence_anchor(block.header.height)
                .map_err(ImportError::DryRunFailed)?,
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
        // `commit_materialized_head`.
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
    /// Archive the verified post-state with the block without selecting it.
    /// Descendants can then replay against this parent root. If fork choice
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
    ) -> Result<Trie, ImportError<DB::Error>> {
        let proposer_position = usize::try_from(block.header.proposer_index)
            .expect("u32 validator index fits usize on supported targets");
        let proposer_address = self
            .active_validator_set()
            .get(proposer_position)
            .map(|v| v.withdrawal_credentials)
            .unwrap_or_default();
        let ctx = BlockExecutionContext {
            evidence_anchor: self
                .evidence_anchor(block.header.height)
                .map_err(ImportError::DryRunFailed)?,
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
        Ok(scratch)
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

        let replayed = self.replay_to_head(new_head, executor)?;
        self.commit_materialized_head(
            replayed.height,
            replayed.hash,
            replayed.state_root,
            Some(replayed.state),
        )?;
        Ok(true)
    }

    pub(crate) fn replay_to_head(
        &self,
        new_head: BlockHash,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<ReplayedHead, ImportError<DB::Error>> {
        let (lca_hash, new_branch) = self.find_lca_and_path_to(new_head)?;
        let (lca_state_root, lca_height) = self.lookup_block_state(lca_hash)?;

        // Also enforce the finalized floor while staging a proof-selected branch.
        // No state, head or height index changes until replay fully succeeds.
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
        // a per-root index would yield; accepted here because
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
                evidence_anchor: self
                    .evidence_anchor(header.height)
                    .map_err(ImportError::DryRunFailed)?,
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

        Ok(ReplayedHead {
            height: current_height,
            hash: current_hash,
            state_root: current_state_root,
            state,
        })
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
        if self.evidence_programs.is_some() {
            let expected_anchor = self.evidence_anchor(header.height).map_err(|_| {
                ImportError::InvalidBlockProof(
                    neutrino_proof_system::ProofError::PublicInputMismatch,
                )
            })?;
            let statement = proof_system
                .block_statement(&backend_proof)
                .map_err(ImportError::InvalidBlockProof)?;
            if statement.accountability.anchor != expected_anchor {
                return Err(ImportError::InvalidBlockProof(
                    neutrino_proof_system::ProofError::PublicInputMismatch,
                ));
            }
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
            Some(BlockState::Finalized) => {}
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

    /// Verify and finalize a peer-supplied complete chunk proof.
    ///
    /// Reconstructs the trusted candidate context, validates the mandatory
    /// certificate and statement, verifies the backend receipt, then atomically
    /// persists and installs the next consensus boundary.
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
        self.import_chunk_proof_inner(proof, proof_system, None)
    }

    /// Verify complete chunk finality and atomically select its branch with
    /// replayed state when the peer finalized a different unfinalized fork.
    ///
    /// # Errors
    /// Returns proof, replay or storage errors without changing finality.
    pub fn import_chunk_proof_with_dry_run<PS: ProofSystem>(
        &mut self,
        proof: &ChunkProof,
        proof_system: &PS,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<ImportChunkProofOutcome, ImportError<DB::Error>> {
        self.import_chunk_proof_inner(proof, proof_system, Some(executor))
    }

    fn import_chunk_proof_inner<PS: ProofSystem>(
        &mut self,
        proof: &ChunkProof,
        proof_system: &PS,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<ImportChunkProofOutcome, ImportError<DB::Error>> {
        if self.store().get_chunk_proof(proof.chunk_id)?.as_ref() == Some(proof) {
            return Ok(ImportChunkProofOutcome {
                chunk_id: proof.chunk_id,
                end_height: proof.public_inputs.end_height,
                chunk_hash: proof.chunk_hash,
            });
        }
        let mut prepared = self
            .prepare_consensus_chunk_on_branch(
                proof.chunk_id,
                proof.public_inputs.end_block_hash,
                proof_system,
            )
            .map_err(|_| {
                ImportError::InvalidChunkProof(neutrino_proof_system::ProofError::InvalidWitness)
            })?;
        prepared.witness.finality_cert = proof.finality_cert.clone();
        let statement = neutrino_prover_chunk::consensus::validate_consensus(&prepared.witness)
            .map_err(|_| {
                ImportError::InvalidChunkProof(neutrino_proof_system::ProofError::InvalidWitness)
            })?;
        if proof.chunk_id != statement.chunk.chunk_id
            || proof.public_inputs != statement.chunk
            || proof.chunk_hash
                != neutrino_prover_chunk::consensus::as_chunk(&statement.chunk).hash()
        {
            return Err(ImportError::InvalidChunkProof(
                neutrino_proof_system::ProofError::PublicInputMismatch,
            ));
        }
        let backend_proof = borsh::from_slice(&proof.proof_bytes).map_err(ImportError::Codec)?;
        let finalized = self
            .commit_imported_consensus_chunk(
                &prepared.witness,
                &backend_proof,
                proof_system,
                executor,
            )
            .map_err(|error| match error {
                crate::FinalizeError::Replay(error) => error,
                crate::FinalizeError::Engine(crate::EngineError::Store(error)) => {
                    ImportError::Store(error)
                }
                crate::FinalizeError::Backend(error) => ImportError::InvalidChunkProof(error),
                _ => ImportError::InvalidChunkProof(
                    neutrino_proof_system::ProofError::BackendRejected,
                ),
            })?;
        Ok(ImportChunkProofOutcome {
            chunk_id: finalized.chunk.chunk_id,
            end_height: finalized.chunk.end_height,
            chunk_hash: finalized.chunk_hash,
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
            gas_used: header.gas_used,
            gas_limit: header.gas_limit,
            gas_price: self.chain_spec().runtime.gas_price,
            proposer_address: self.proposer_runtime_address_for_import(header.proposer_index),
            runtime_extra: header.runtime_extra,
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
    use crate::{ProposerKey, validator_set_root};
    use neutrino_consensus_types::{Body, Header};
    use neutrino_primitives::{
        BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
        RuntimeParams, StateParams, Validator, ZERO_HASH,
    };
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

        ChainSpec {
            name: BoundedBytes::new(b"m6-import-test".to_vec()).expect("name fits"),
            chain_id: TEST_CHAIN_ID,
            genesis_time: TEST_GENESIS_TIME,
            genesis_gas_limit: 30_000_000,
            runtime_info: RuntimeInfo::default(),
            runtime_code_hash: [0xCC; 32],
            genesis_seed: TEST_GENESIS_SEED,
            genesis_state_root: ZERO_HASH,
            genesis_block_hash,
            genesis_validator_set_root: vs_root,
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
        let roots = compute_body_roots(&body);

        let (vrf_proof, _) = neutrino_vrf::eval(
            signing_key.secret_key(),
            TEST_CHAIN_ID,
            &TEST_GENESIS_SEED,
            slot,
        );

        let mut header = Header {
            height,
            slot,
            parent_hash: parent,
            proposer_index: signing_key.validator_index(),
            vrf_proof: vrf_proof.to_bytes(),
            state_root,
            transactions_root: roots.transactions_root,
            votes_root: roots.votes_root,
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
    fn import_block_rejects_expired_embedded_votes_before_storage() {
        use neutrino_consensus_types::{FinalityVote, FinalityVoteData, FinalityVotePhase};

        let mut spec = spec();
        spec.consensus.chunk_size = 1;
        spec.proof.slot_budget_per_chunk = 1;
        let mut engine = Engine::genesis(spec, MemoryDatabase::new()).unwrap();
        for height in 1..10 {
            let next = block(height, height, engine.head_hash(), [5; 32]);
            engine.import_block(&next).unwrap();
        }
        let mut next = block(10, 10, engine.head_hash(), [5; 32]);
        next.body.finality_votes.push(FinalityVote {
            data: FinalityVoteData {
                chunk_id: 0,
                round: 0,
                chunk_hash: [7; 32],
                phase: FinalityVotePhase::Prevote,
            },
            signature: [0; 96],
            aggregation_bits: neutrino_primitives::BitVec::from_bytes(1, vec![0]).unwrap(),
            attestations: vec![],
        });
        let roots = compute_body_roots(&next.body);
        next.header.votes_root = roots.votes_root;
        next.header.da_root = roots.da_root;
        next.header.signature = proposer().sign_proposer_message(TEST_CHAIN_ID, &next.hash());
        assert!(matches!(
            engine.import_block(&next),
            Err(ImportError::HistoricalVoteOutsideWindow {
                chunk_id: 9,
                referenced_chunk: 0,
            })
        ));
        assert_eq!(engine.head_height(), 9);
        assert!(engine.store().get_header(&next.hash()).unwrap().is_none());
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
}
