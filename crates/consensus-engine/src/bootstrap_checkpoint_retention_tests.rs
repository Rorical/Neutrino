//! A lagging recursive endpoint retains its bootstrap records, not older raw data.
//! These fixtures model already authenticated receipts and finalized storage.

use super::*;

fn assert_openings(engine: &Engine<MemoryDatabase>, count: u64) {
    let root = engine.canonical_boundary(count).unwrap().history_root;
    for id in count.saturating_sub(HISTORY_RETENTION_CHUNKS)..count {
        let opening = engine.store().historical_opening(id, count).unwrap();
        assert_eq!(opening.record.chunk.chunk_id, id);
        assert_eq!(opening.path.index, id);
        assert_eq!(opening.path.count, count);
        assert!(
            opening
                .path
                .verify(commitment(&opening.record.evidence_context()), root)
        );
    }
}

#[test]
fn lagging_prefix_keeps_both_bootstrap_and_current_windows_without_pinning_raw_sources() {
    let finalized = 24;
    let current_first = finalized - HISTORY_RETENTION_CHUNKS;
    for lag in [1, 5, 12] {
        let covered = finalized - lag;
        let checkpoint_first = covered - HISTORY_RETENTION_CHUNKS;
        let expected_floor = covered.min(current_first);
        let mut engine = fixture(MemoryDatabase::new(), finalized);
        artifact(&mut engine, 0, covered, true);
        let retention = engine.prune_history_covered().unwrap();
        assert_eq!(retention.pruned_before_chunk, expected_floor);
        assert_eq!(retention.first_retained_height, expected_floor + 1);
        assert_openings(&engine, covered);
        assert_openings(&engine, finalized);
        // All manifest context remains available under the retained endpoint.
        let endpoint = engine.canonical_boundary(covered).unwrap();
        assert_eq!(
            engine
                .store()
                .get_header_by_height(covered)
                .unwrap()
                .unwrap()
                .hash(),
            endpoint.block_hash
        );
        assert_eq!(
            engine
                .store()
                .get_validator_set_snapshot(covered)
                .unwrap()
                .unwrap(),
            spec().initial_validators
        );
        let frontier = engine.store().history_frontier(covered).unwrap();
        assert_eq!(frontier.count, covered);
        assert_eq!(frontier.root(), Some(endpoint.history_root));
        // Compact bootstrap contexts cannot broaden the incoming chunk's legal
        // reference window, or preserve transaction bodies and source receipts.
        for id in checkpoint_first..current_first.min(covered) {
            assert!(!neutrino_consensus_types::history::is_recent_history_index(
                id, finalized
            ));
            assert!(engine.store().historical_chunk(id).unwrap().is_some());
        }
        for id in 0..expected_floor {
            assert!(engine.store().get_chunk_proof(id).unwrap().is_none());
            assert!(engine.store().get_chunk(id).unwrap().is_none());
        }
        assert_eq!(
            engine
                .store()
                .db()
                .iter_column(Column::Blocks)
                .unwrap()
                .len(),
            usize::try_from(finalized - expected_floor).unwrap()
        );
        let mut restarted = Engine::open(spec(), engine.store().db().clone()).unwrap();
        assert_eq!(restarted.recursive_covered_chunks(), covered);
        assert_eq!(restarted.retention_info().unwrap(), retention);
        assert_openings(&restarted, covered);
        assert_openings(&restarted, finalized);
        // Once a newer prefix replaces R, only its own bootstrap window survives.
        artifact(&mut restarted, 0, finalized, true);
        assert_eq!(
            restarted
                .prune_history_covered()
                .unwrap()
                .pruned_before_chunk,
            current_first
        );
        assert_openings(&restarted, finalized);
        for id in 0..current_first {
            assert!(restarted.store().historical_chunk(id).unwrap().is_none());
        }
        assert_eq!(
            restarted
                .store()
                .db()
                .iter_column(Column::HistoricalChunks)
                .unwrap()
                .len(),
            usize::try_from(HISTORY_RETENTION_CHUNKS).unwrap()
        );
        let again = Engine::open(spec(), restarted.store().db().clone()).unwrap();
        assert_eq!(again.recursive_covered_chunks(), finalized);
        assert_openings(&again, finalized);
        for id in checkpoint_first..current_first.min(covered) {
            assert!(again.store().historical_chunk(id).unwrap().is_none());
        }
    }
}
