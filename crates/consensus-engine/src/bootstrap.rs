//! Install an authenticated execution snapshot at a recursively proven boundary.

use crate::{Engine, FinalizeError, RetentionPolicy, StoreError};
use neutrino_consensus_types::history::{HISTORY_RETENTION_CHUNKS, HistoryFrontier};
use neutrino_consensus_types::history_proof::ConsensusBoundary;
use neutrino_consensus_types::{Checkpoint, Header};
use neutrino_primitives::{ChainSpec, Validator};
use neutrino_proof_system::{ProofError, VerifiedHistory};
use neutrino_prover_chunk::{
    consensus::{context_boundary, genesis_context},
    execution::commitment,
    history::{HistoricalOpening, HistoryWitness},
};
use neutrino_storage::Database;
use neutrino_trie::Trie;

impl<DB: Database> Engine<DB> {
    /// Install a full-node bootstrap only after receipt and trust-policy verification.
    ///
    /// `trusted_start` comes from local trust configuration, or the existing local
    /// finalized boundary. The caller applies weak-subjectivity and freshness policy
    /// before invoking this method. Neither proof alone authorizes changing that anchor.
    /// Both receipts must end at the same boundary; the genesis prefix permits future
    /// proof-backed pruning, while the bridge protects an existing non-genesis anchor.
    #[allow(clippy::too_many_arguments)]
    pub fn install_bootstrap(
        &mut self,
        prefix: VerifiedHistory,
        bridge: Option<VerifiedHistory>,
        trusted_start: Checkpoint,
        header: &Header,
        validators: &[Validator],
        frontier: &HistoryFrontier,
        recent: &[HistoricalOpening],
        mut state: Trie,
    ) -> Result<(), FinalizeError<DB::Error>> {
        let spec = self.chain_spec();
        let statement = &prefix.proof().statement;
        let end = statement.end;
        let count = end.next_chunk_id;
        let local_count = self.finalized_next_chunk_id();
        if self.retention_info()?.policy == RetentionPolicy::Archive
            || count == 0
            || count < local_count
            || self.head_height() > end.height
            || statement.domain != *prefix.domain()
            || Some(statement.domain) != self.store().history_domain()?
            || statement.start
                != neutrino_consensus_types::history_proof::ConsensusBoundary::genesis(spec)
            || statement.domain.chain
                != neutrino_consensus_types::history_proof::ChainBinding::from_spec(spec)
            || !end.is_well_formed(&statement.domain.chain)
            || bridge.map_or_else(
                || trusted_start != statement.end_checkpoint(),
                |bridge| {
                    *bridge.domain() != *prefix.domain()
                        || bridge.proof().statement.start_checkpoint() != trusted_start
                        || bridge.proof().statement.end != end
                },
            )
            || (local_count != 0
                && trusted_start.boundary != self.canonical_boundary(local_count)?)
            || header.hash() != end.block_hash
            || header.height != end.height
            || header.state_root != end.state_root
            || header.slot != end.slot
            || state.root() != end.state_root
            || commitment(validators) != end.validators_root
            || recent.len()
                != usize::try_from(count.min(HISTORY_RETENTION_CHUNKS))
                    .map_err(|_| ProofError::InvalidWitness)?
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        for (key, _) in self
            .store()
            .db()
            .iter_column(neutrino_storage::Column::BftSessions)
            .map_err(StoreError::Database)?
        {
            let id = u64::from_be_bytes(
                key.as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("invalid BFT session key"))?,
            );
            if id >= count {
                return Err(
                    StoreError::Corrupt("bootstrap would discard an unfinalized lock").into(),
                );
            }
        }
        if !self
            .store()
            .history_dependencies_for_bootstrap()?
            .is_empty()
        {
            return Err(StoreError::Corrupt("bootstrap has active history leases").into());
        }
        let first = count.saturating_sub(HISTORY_RETENTION_CHUNKS);
        if recent.iter().enumerate().any(|(offset, opening)| {
            u64::try_from(offset)
                .ok()
                .and_then(|offset| first.checked_add(offset))
                != Some(opening.record.chunk.chunk_id)
        }) {
            return Err(ProofError::InvalidWitness.into());
        }
        authenticate_history(spec, end, header, frontier, recent)?;
        let before = (state.node_count(), state.value_count());
        state
            .retain_roots(&[])
            .map_err(|_| ProofError::InvalidWitness)?;
        if before != (state.node_count(), state.value_count()) {
            return Err(ProofError::InvalidWitness.into());
        }
        let mut context = genesis_context(spec);
        context.chunk_id = count;
        context.parent_block_hash = end.block_hash;
        context.pre_state_root = end.state_root;
        context.parent_slot = end.slot;
        context.active_validators = validators.to_vec();
        context.history_root = end.history_root;
        if context_boundary(&context, end.seed).map_err(|_| ProofError::InvalidWitness)? != end {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let consensus = crate::full_chunk::ConsensusState {
            boundary: end,
            next_context: context,
            next_seed: end.seed,
            frontier: frontier.clone(),
        };
        let proof = prefix.into_proof();
        self.store_mut()
            .commit_bootstrap(&proof, header, &consensus, recent, &state)?;
        self.publish_bootstrap_state(&consensus, state);
        Ok(())
    }
}

fn authenticate_history(
    spec: &ChainSpec,
    end: ConsensusBoundary,
    header: &Header,
    frontier: &HistoryFrontier,
    recent: &[HistoricalOpening],
) -> Result<(), ProofError> {
    let history = HistoryWitness {
        frontier: frontier.clone(),
        records: recent.to_vec(),
    };
    history
        .authenticate(end.next_chunk_id, end.history_root)
        .map_err(|_| ProofError::InvalidWitness)?;
    for opening in recent {
        neutrino_prover_chunk::finality::verify_finality(
            spec.chain_id,
            &spec.consensus,
            &opening.record.validators,
            &opening.record.chunk,
            &opening.record.finality,
        )
        .map_err(|_| ProofError::InvalidWitness)?;
    }
    let last = recent.last().ok_or(ProofError::InvalidWitness)?;
    if last.record.chunk.end_block_hash != end.block_hash
        || last.record.chunk.end_height != end.height
        || last.record.chunk.end_state_root != end.state_root
        || last.record.chunk.next_validator_set_root != end.validators_root
    {
        return Err(ProofError::PublicInputMismatch);
    }
    crate::verify_header_signature(header, &last.record.validators, spec.chain_id)
        .map_err(|_| ProofError::InvalidWitness)?;
    Ok(())
}
