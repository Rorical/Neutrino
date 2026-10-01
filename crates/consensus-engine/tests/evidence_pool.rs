//! Storage invariants; marker receipts here test persistence, not authentication.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use neutrino_consensus_engine::store::ChainStore;
use neutrino_consensus_types::evidence::{
    EvidenceArtifact, EvidenceContext, EvidenceStatement, MAX_EVIDENCE_PROOF_BYTES, SanctionKind,
};
use neutrino_storage::MemoryDatabase;

fn artifact(id: u64) -> EvidenceArtifact {
    let (witness, _, _) = support::fixture([1; 8], [4; 32]);
    let mut offence_id = [0; 32];
    offence_id[..8].copy_from_slice(&id.to_le_bytes());
    EvidenceArtifact {
        statement: EvidenceStatement {
            chain_id: 7,
            chain_spec_hash: witness.chain_spec.hash(),
            block_guest_vk_digest: [1; 8],
            context: EvidenceContext {
                chunk_id: 0,
                chunk_hash: [3; 32],
                end_height: 1,
                validators_root: witness.chain_spec.genesis_validator_set_root,
                seed: [0; 32],
            },
            offender: witness.context.active_validators[0].clone(),
            kind: SanctionKind::Slash,
            offence_id,
            facts_commitment: [5; 32],
        },
        proof_bytes: vec![1],
    }
}

#[test]
fn verified_pool_survives_restart_preserves_first_receipt_and_expires_at_finality() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let original = artifact(1);
    store.put_evidence_artifact(&original).unwrap();
    let mut alternate = original.clone();
    alternate.proof_bytes.push(2);
    store.put_evidence_artifact(&alternate).unwrap();
    let mut restarted = ChainStore::new(store.into_db());
    assert_eq!(
        restarted.evidence_artifacts().unwrap(),
        vec![original.clone()]
    );
    restarted.prune_evidence_artifacts(10, 10, &[]).unwrap();
    assert_eq!(restarted.evidence_artifacts().unwrap(), vec![original]);
    restarted.prune_evidence_artifacts(11, 10, &[]).unwrap();
    assert!(restarted.evidence_artifacts().unwrap().is_empty());
}

#[test]
fn persistent_pool_enforces_receipt_and_entry_bounds() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let mut item = artifact(0);
    item.proof_bytes = vec![0; MAX_EVIDENCE_PROOF_BYTES + 1];
    assert!(store.put_evidence_artifact(&item).is_err());
    item.proof_bytes = vec![1];
    for id in 0_u64..256 {
        item.statement.offence_id[..8].copy_from_slice(&id.to_le_bytes());
        store.put_evidence_artifact(&item).unwrap();
    }
    item.statement.offence_id[..8].copy_from_slice(&256_u64.to_le_bytes());
    assert!(store.put_evidence_artifact(&item).is_err());
    assert_eq!(store.evidence_artifacts().unwrap().len(), 256);
    store.prune_evidence_artifacts(1, 1024, &[[0; 32]]).unwrap();
    store.put_evidence_artifact(&item).unwrap();
    assert_eq!(store.evidence_artifacts().unwrap().len(), 256);
}

#[test]
fn finalization_releases_cache_capacity_without_discarding_reorg_candidates() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let original = artifact(1);
    let pending = artifact(2);
    store.put_evidence_artifact(&original).unwrap();
    store.put_evidence_artifact(&pending).unwrap();
    // The node supplies only the ledger from a proof-gated finalized boundary.
    // A receipt consumed merely on the materialized head remains recoverable.
    store
        .prune_evidence_artifacts(1, 1024, &[original.statement.offence_id])
        .unwrap();
    assert_eq!(store.evidence_artifacts().unwrap(), vec![pending]);
}
