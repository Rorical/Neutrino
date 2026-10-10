//! Program sets of unfinalized chunks (design 24).
//!
//! Finalized boundaries carry their program set. For a chunk beyond the
//! finalized one the set follows from the runtime's `ScheduledUpgrade`
//! record in the post-state of the previous chunk's last canonical block,
//! exactly the rule the chunk Guest applies at that boundary. Results are
//! cached by that block's hash, so reorganisations never reuse a stale
//! answer.

extern crate alloc;

use alloc::collections::BTreeMap;

use neutrino_consensus_types::history_proof::{ProgramSet, ScheduledUpgrade};
use neutrino_primitives::Hash;
use neutrino_proof_system::ProofError;
use neutrino_storage::Database;

use crate::{Engine, FinalizeError};

/// Retained switch answers; older chunks are dropped as finality advances.
const MAX_CACHED_SWITCHES: usize = 64;

impl<DB: Database> Engine<DB> {
    /// Program set the block at `height` executes under.
    pub fn programs_for_height(&self, height: u64) -> Result<ProgramSet, FinalizeError<DB::Error>> {
        self.programs_at_chunk(self.chunk_of_height(height).unwrap_or(0))
    }

    /// Program set of chunk `chunk_id`, finalized or not.
    pub fn programs_at_chunk(&self, chunk_id: u64) -> Result<ProgramSet, FinalizeError<DB::Error>> {
        let finalized = self.finalized_next_chunk_id();
        if chunk_id <= finalized {
            return Ok(self.canonical_boundary(chunk_id)?.programs);
        }
        let mut programs = self.canonical_boundary(finalized)?.programs;
        for next in finalized + 1..=chunk_id {
            let boundary_height = next
                .checked_mul(self.chunk_size())
                .ok_or(ProofError::InvalidWitness)?;
            if let Some(scheduled) = self.scheduled_switch_at(boundary_height)?
                && scheduled.activate_at_chunk == next
            {
                programs = scheduled.programs;
            }
        }
        Ok(programs)
    }

    /// The upgrade record in the post-state of the canonical block at
    /// `boundary_height`, the last block of the chunk ending there.
    fn scheduled_switch_at(
        &self,
        boundary_height: u64,
    ) -> Result<Option<ScheduledUpgrade>, FinalizeError<DB::Error>> {
        let header = self
            .store()
            .get_header_by_height(boundary_height)?
            .ok_or(ProofError::InvalidWitness)?;
        let hash = header.hash();
        if let Some(cached) = self.program_switches.borrow().get(&hash) {
            return Ok(*cached);
        }
        let scheduled = if header.state_root == self.head_state_root() {
            self.state().get(neutrino_default_runtime_core::UPGRADE_KEY)
        } else {
            self.persisted_trie(header.state_root)?
                .get(neutrino_default_runtime_core::UPGRADE_KEY)
        }
        .and_then(|bytes| borsh::from_slice::<ScheduledUpgrade>(&bytes).ok());
        let mut cache = self.program_switches.borrow_mut();
        if cache.len() >= MAX_CACHED_SWITCHES {
            cache.clear();
        }
        cache.insert(hash, scheduled);
        Ok(scheduled)
    }

    /// Runtime artifact the block at `height` must be executed with.
    pub fn runtime_code_hash_for(&self, height: u64) -> Result<Hash, FinalizeError<DB::Error>> {
        Ok(self.programs_for_height(height)?.runtime_code_hash)
    }

    pub(crate) const fn new_program_switch_cache()
    -> core::cell::RefCell<BTreeMap<Hash, Option<ScheduledUpgrade>>> {
        core::cell::RefCell::new(BTreeMap::new())
    }
}
