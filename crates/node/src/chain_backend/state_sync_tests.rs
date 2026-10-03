//! State download regression tests without accepting synthetic proof receipts.

use super::{ChainBackend, state_sync::MAX_ENTRY_BYTES};
use neutrino_consensus_engine::{Engine, ProposerKey, validator_set::validator_set_root};
use neutrino_consensus_types::bootstrap::{StateItem, StateItemKind};
use neutrino_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, StateParams, Validator, ZERO_HASH,
};
use neutrino_proof_system::MockProofSystem;
use neutrino_storage::{Column, Database, MemoryDatabase};
use neutrino_trie::{Hasher, Poseidon2Hasher, Trie};

type Backend = ChainBackend<MemoryDatabase, MockProofSystem>;

pub(super) fn spec() -> ChainSpec {
    let validators = vec![Validator {
        pubkey: *ProposerKey::from_ikm(&[6; 32], 0)
            .unwrap()
            .public_key_bytes(),
        withdrawal_credentials: [7; 32],
        effective_stake: 32_000_000_000,
        slashed: false,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
        last_active_chunk: 0,
    }];
    ChainSpec {
        name: BoundedBytes::new(b"state-download".to_vec()).unwrap(),
        chain_id: 41,
        genesis_time: 0,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [1; 32],
        genesis_seed: [2; 32],
        genesis_state_root: ZERO_HASH,
        genesis_block_hash: [4; 32],
        genesis_validator_set_root: validator_set_root(&validators),
        consensus: ConsensusParams::default(),
        proof: ProofParams::default(),
        state: StateParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).unwrap(),
    }
}
fn backend() -> Backend {
    ChainBackend::new(
        Engine::genesis(spec(), MemoryDatabase::new()).unwrap(),
        MockProofSystem::new(),
    )
}
fn source(value: &[u8]) -> (Backend, neutrino_primitives::Hash) {
    let server = backend();
    let mut state: Trie = Trie::new();
    state.insert(b"large", value.to_vec()).unwrap();
    let root = state.root();
    server.with_engine_mut(|engine| {
        for (hash, bytes) in state.node_entries() {
            engine
                .store_mut()
                .db_mut()
                .put(Column::TrieNodes, &hash, bytes)
                .unwrap();
        }
        for (hash, bytes) in state.value_entries() {
            engine
                .store_mut()
                .db_mut()
                .put(Column::StateValues, &hash, bytes)
                .unwrap();
        }
    });
    (server, root)
}
fn receive(
    server: &Backend,
    client: &Backend,
    root: neutrino_primitives::Hash,
) -> neutrino_sync::StateProgress {
    let items = client.state_download_items(root).unwrap();
    let response = server.p2p_state_nodes(root, &items).unwrap();
    client
        .receive_state_entries(root, &items, &response.entries)
        .unwrap()
}

#[test]
fn fragment_service_rejects_unknown_or_corrupt_roots_before_serving_retained_objects() {
    let (server, root) = source(b"authenticated value");
    let items = vec![StateItem::node(root)];
    assert!(matches!(
        server.p2p_state_nodes([9; 32], &items),
        Err(neutrino_sync::SyncBackendError::NotAvailable(_))
    ));
    let response = server.p2p_state_nodes(root, &items).unwrap();
    assert_eq!(response.entries[0].item, items[0]);
    assert_eq!(
        Poseidon2Hasher::hash_node(response.entries[0].bytes.as_slice()),
        root
    );
    assert!(
        server
            .with_engine(|engine| engine.store().db().iter_column(Column::Meta).unwrap())
            .iter()
            .all(|(key, _)| !key.starts_with(b"state_snapshot_lease/"))
    );
    let client = backend();
    while !receive(&server, &client, root).root_complete {}
    assert_eq!(
        client.reconstructed_state(root).unwrap().get(b"large"),
        Some(b"authenticated value".to_vec())
    );
    server.with_engine_mut(|engine| {
        engine
            .store_mut()
            .db_mut()
            .put(Column::TrieNodes, &root, &[255])
            .unwrap();
    });
    // The root is checked even when no object fragments were requested.
    assert!(matches!(
        server.p2p_state_nodes(root, &[]),
        Err(neutrino_sync::SyncBackendError::Storage(_))
    ));
    let malformed_root = Poseidon2Hasher::hash_node(&[255]);
    server.with_engine_mut(|engine| {
        engine
            .store_mut()
            .db_mut()
            .put(Column::TrieNodes, &malformed_root, &[255])
            .unwrap();
    });
    assert!(matches!(
        server.p2p_state_nodes(malformed_root, &[]),
        Err(neutrino_sync::SyncBackendError::Storage(_))
    ));
}

#[test]
fn large_value_fragments_resume_after_restart_and_do_not_publish_partial_state() {
    let value = vec![5; 150_000];
    let (server, root) = source(&value);
    let client = backend();
    assert!(!receive(&server, &client, root).root_complete); // Root authenticates the value hash.
    let progress = receive(&server, &client, root);
    assert_eq!(progress.next_items[0].kind, StateItemKind::Value);
    assert_eq!(progress.next_items[0].offset, 65_536);
    let db = client.with_engine(|engine| engine.store().db().clone());
    assert_eq!(
        db.iter_column(Column::TrieNodes).unwrap(),
        Vec::<(Vec<u8>, Vec<u8>)>::new()
    );
    let resumed = ChainBackend::new(Engine::open(spec(), db).unwrap(), MockProofSystem::new());
    assert_eq!(
        resumed.state_download_items(root).unwrap(),
        progress.next_items
    );
    while !receive(&server, &resumed, root).root_complete {}
    let state = resumed.reconstructed_state(root).unwrap();
    assert_eq!(state.get(b"large"), Some(value));
    assert_eq!(resumed.with_engine(Engine::head_state_root), ZERO_HASH);
    resumed.clear_state_download(root).unwrap();
    assert!(
        resumed
            .with_engine(|engine| engine.store().db().iter_column(Column::Meta).unwrap())
            .iter()
            .all(|(key, _)| !key.starts_with(b"state_download"))
    );
}

#[test]
fn corrupt_final_fragment_restarts_only_that_object_from_zero() {
    let (server, root) = source(&vec![7; 80_000]);
    let client = backend();
    receive(&server, &client, root);
    receive(&server, &client, root);
    let items = client.state_download_items(root).unwrap();
    let mut entries = server
        .p2p_state_nodes(root, &items)
        .unwrap()
        .entries
        .to_vec();
    let mut corrupt = entries[0].bytes.as_slice().to_vec();
    corrupt[0] ^= 1;
    entries[0].bytes = BoundedBytes::new(corrupt).unwrap();
    assert!(
        client
            .receive_state_entries(root, &items, &entries)
            .is_err()
    );
    let restarted = client.state_download_items(root).unwrap();
    assert_eq!(restarted[0].offset, 0);
    while !receive(&server, &client, root).root_complete {}
    assert_eq!(
        client.reconstructed_state(root).unwrap().get(b"large"),
        Some(vec![7; 80_000])
    );
}

#[test]
fn unsolicited_fragment_and_giant_declared_length_cannot_change_progress() {
    let (server, root) = source(b"value");
    let client = backend();
    let items = vec![StateItem::node(root)];
    let mut entries = server
        .p2p_state_nodes(root, &items)
        .unwrap()
        .entries
        .to_vec();
    entries[0].item.hash = [9; 32];
    assert!(
        client
            .receive_state_entries(root, &items, &entries)
            .is_err()
    );
    assert_eq!(client.state_download_items(root).unwrap(), items);
    entries[0].item = items[0];
    entries[0].total_len = MAX_ENTRY_BYTES + 1;
    assert!(
        client
            .receive_state_entries(root, &items, &entries)
            .is_err()
    );
    assert_eq!(client.state_download_items(root).unwrap(), items);
}
