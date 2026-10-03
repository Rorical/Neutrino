//! Bootstrap storage tests start after receipt and trust-policy verification.
//! Fixture receipts are never passed through production cryptographic acceptance.

use super::*;
use neutrino_prover_chunk::history::HistoricalOpening;

struct Snapshot {
    prefix: HistoryProof,
    header: neutrino_consensus_types::Header,
    consensus: ConsensusState,
    recent: Vec<HistoricalOpening>,
    state: Trie,
}

fn snapshot(count: u64) -> Snapshot {
    let mut source = fixture(MemoryDatabase::new(), count);
    artifact(&mut source, 0, count, true);
    let first = count.saturating_sub(HISTORY_RETENTION_CHUNKS);
    let recent = (first..count)
        .map(|id| source.store().historical_opening(id, count).unwrap())
        .collect();
    let mut state = source.state().clone();
    state.retain_roots(&[]).unwrap();
    Snapshot {
        prefix: source.latest_history_proof().unwrap().unwrap(),
        header: source
            .store()
            .get_header(&source.head_hash())
            .unwrap()
            .unwrap(),
        consensus: source.store().get_consensus_state().unwrap().unwrap(),
        recent,
        state,
    }
}

fn commit<DB: Database>(target: &mut Engine<DB>, snapshot: &Snapshot)
where
    DB::Error: std::fmt::Debug,
{
    target
        .store_mut()
        .commit_bootstrap(
            &snapshot.prefix,
            &snapshot.header,
            &snapshot.consensus,
            &snapshot.recent,
            &snapshot.state,
        )
        .unwrap();
    target.publish_bootstrap_state(&snapshot.consensus, snapshot.state.clone());
}

#[test]
fn sparse_bootstrap_tree_reopens_and_appends_across_binary_carries() {
    for count in [1, 7, 8, 9, 16, 17, 32, 33] {
        let snapshot = snapshot(count);
        let mut target = fixture(MemoryDatabase::new(), 0);
        commit(&mut target, &snapshot);
        let mut reopened =
            Engine::open(target.chain_spec().clone(), target.store().db().clone()).unwrap();
        assert_eq!(reopened.head_hash(), snapshot.header.hash());
        assert_eq!(reopened.recursive_covered_chunks(), count);
        assert_eq!(reopened.finalized_next_chunk_id(), count);
        assert_eq!(reopened.state().root(), snapshot.state.root());
        assert_eq!(
            reopened.state().get(b"counter"),
            Some(count.to_be_bytes().to_vec())
        );
        let first = count.saturating_sub(HISTORY_RETENTION_CHUNKS);
        for expected in &snapshot.recent {
            assert_eq!(
                reopened
                    .store()
                    .historical_opening(expected.record.chunk.chunk_id, count)
                    .unwrap(),
                *expected
            );
        }
        assert_eq!(
            reopened.retention_info().unwrap().pruned_before_chunk,
            count
        );
        assert_eq!(
            reopened
                .store()
                .db()
                .iter_column(Column::Blocks)
                .unwrap()
                .len(),
            0
        );
        assert!(
            reopened
                .set_retention_policy(RetentionPolicy::Archive)
                .is_err()
        );
        reopened.prune_history_covered().unwrap();
        for id in first..count {
            reopened.store().historical_opening(id, count).unwrap();
        }
        append(&mut reopened);
        for id in count
            .saturating_add(1)
            .saturating_sub(HISTORY_RETENTION_CHUNKS)..=count
        {
            reopened.store().historical_opening(id, count + 1).unwrap();
        }
        reopened.prune_history_covered().unwrap();
        assert_eq!(
            reopened.retention_info().unwrap().pruned_before_chunk,
            count
        );
        assert!(
            reopened
                .store()
                .db()
                .get(Column::Blocks, &reopened.head_hash())
                .unwrap()
                .is_some()
        );
        let again =
            Engine::open(reopened.chain_spec().clone(), reopened.store().db().clone()).unwrap();
        for id in (count + 1).saturating_sub(HISTORY_RETENTION_CHUNKS)..=count {
            again.store().historical_opening(id, count + 1).unwrap();
        }
    }
}

#[test]
fn bootstrap_pruning_tracks_new_consensus_window_without_expiring_live_state() {
    let count = 17;
    let snapshot = snapshot(count);
    let mut target = fixture(MemoryDatabase::new(), 0);
    commit(&mut target, &snapshot);
    for _ in 0..10 {
        append(&mut target);
        let latest = target.finalized_next_chunk_id();
        artifact(&mut target, 0, latest, true);
        target.prune_history_covered().unwrap();
        let first = latest.saturating_sub(HISTORY_RETENTION_CHUNKS);
        let expected_floor = count.max(first);
        assert_eq!(
            target.retention_info().unwrap().pruned_before_chunk,
            expected_floor
        );
        for id in first..latest {
            target.store().historical_opening(id, latest).unwrap();
        }
        if first > 0 {
            assert!(
                target
                    .store()
                    .historical_chunk(first - 1)
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            target.state().get(b"counter"),
            Some(latest.to_be_bytes().to_vec())
        );
        let again = Engine::open(target.chain_spec().clone(), target.store().db().clone()).unwrap();
        assert_eq!(
            again.retention_info().unwrap(),
            target.retention_info().unwrap()
        );
    }
}

#[test]
fn failed_durable_bootstrap_batch_leaves_disk_and_live_pointers_unchanged() {
    let snapshot = snapshot(9);
    let mut target = fixture(FaultDb::default(), 2);
    let head = target.head_hash();
    let root = target.state().root();
    let finalized = target.finalized_next_chunk_id();
    let disk: Vec<_> = neutrino_storage::ALL_COLUMNS
        .iter()
        .map(|column| (*column, target.store().db().iter_column(*column).unwrap()))
        .collect();
    target.store_mut().db_mut().fail_batch = true;
    assert!(matches!(
        target.store_mut().commit_bootstrap(
            &snapshot.prefix,
            &snapshot.header,
            &snapshot.consensus,
            &snapshot.recent,
            &snapshot.state,
        ),
        Err(StoreError::Database(_))
    ));
    assert_eq!(target.head_hash(), head);
    assert_eq!(target.state().root(), root);
    assert_eq!(target.finalized_next_chunk_id(), finalized);
    assert_eq!(target.recursive_covered_chunks(), 0);
    assert_eq!(target.store().bootstrap_source_floor().unwrap(), 0);
    for (column, entries) in disk {
        assert_eq!(target.store().db().iter_column(column).unwrap(), entries);
    }
    target.store_mut().db_mut().fail_batch = false;
    commit(&mut target, &snapshot);
    let reopened = Engine::open(target.chain_spec().clone(), target.store().db().clone()).unwrap();
    assert_eq!(reopened.head_hash(), snapshot.header.hash());
    assert_eq!(reopened.store().bootstrap_source_floor().unwrap(), 9);
}

#[test]
fn malformed_opening_cannot_publish_a_partial_bootstrap() {
    let mut snapshot = snapshot(9);
    snapshot.recent[0].path.siblings[0][0] ^= 1;
    let mut target = fixture(MemoryDatabase::new(), 0);
    let head = target.head_hash();
    let disk = target.store().db().clone();
    assert!(
        target
            .store_mut()
            .commit_bootstrap(
                &snapshot.prefix,
                &snapshot.header,
                &snapshot.consensus,
                &snapshot.recent,
                &snapshot.state,
            )
            .is_err()
    );
    assert_eq!(target.head_hash(), head);
    for column in neutrino_storage::ALL_COLUMNS {
        assert_eq!(
            target.store().db().iter_column(column).unwrap(),
            disk.iter_column(column).unwrap()
        );
    }
}

#[test]
fn bootstrap_publication_preserves_the_local_signing_journal() {
    let snapshot = snapshot(9);
    let mut target = fixture(MemoryDatabase::new(), 0);
    // The store must preserve journal bytes independently of their signing-layer
    // schema. Decoding and enforcing their semantics belong to signing tests.
    target
        .store_mut()
        .db_mut()
        .put(Column::SigningJournal, b"persisted-key", b"signing-intent")
        .unwrap();
    commit(&mut target, &snapshot);
    assert_eq!(
        target
            .store()
            .db()
            .get(Column::SigningJournal, b"persisted-key")
            .unwrap(),
        Some(b"signing-intent".to_vec())
    );
}
