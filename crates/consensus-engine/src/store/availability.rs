//! Durable bounded accountability sources; capacity never evicts live references.

use crate::{ChainStore, RetentionPolicy, StoreError};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::signed_artifacts::{
    MAX_ARTIFACT_INVENTORY, SignedArtifact, SignedArtifactInventory, SignedArtifactKind,
};
use neutrino_primitives::{ChunkId, Hash};
use neutrino_storage::{Batch, Column, Database};

const MAX_SIGNED_ARTIFACTS: usize = 4096;
const MAX_SIGNED_ARTIFACT_STORAGE_BYTES: usize = 512 * 1024 * 1024;
const PRUNED_FLOOR_KEY: &[u8] = b"signed_artifact_pruned_floor";

fn metadata_id_key(id: Hash) -> [u8; 33] {
    let mut key = [0; 33];
    key[1..].copy_from_slice(&id);
    key
}

fn metadata_chunk_prefix(chunk: ChunkId) -> [u8; 9] {
    let mut key = [1; 9];
    key[1..].copy_from_slice(&chunk.to_be_bytes());
    key
}

fn metadata_chunk_key(chunk: ChunkId, id: Hash) -> [u8; 41] {
    let mut key = [0; 41];
    key[..9].copy_from_slice(&metadata_chunk_prefix(chunk));
    key[9..].copy_from_slice(&id);
    key
}

fn put_metadata(batch: &mut Batch, metadata: &SignedArtifactMetadata) -> borsh::io::Result<()> {
    let bytes = borsh::to_vec(metadata)?;
    batch.put(
        Column::SignedArtifactIndex,
        metadata_id_key(metadata.id),
        bytes.as_slice(),
    );
    batch.put(
        Column::SignedArtifactIndex,
        metadata_chunk_key(metadata.chunk_id, metadata.id),
        bytes,
    );
    Ok(())
}

fn delete_metadata(batch: &mut Batch, chunk: ChunkId, id: Hash) {
    batch.delete(Column::SignedArtifactIndex, metadata_id_key(id));
    batch.delete(Column::SignedArtifactIndex, metadata_chunk_key(chunk, id));
}

#[derive(BorshSerialize, BorshDeserialize)]
struct StoredArtifact {
    chunk_id: ChunkId,
    payload: StoredPayload,
}
#[derive(BorshSerialize, BorshDeserialize)]
enum StoredPayload {
    Source(Box<SignedArtifact>),
    // Accepted receipt bytes already live in BlockProofs and are immutable.
    AcceptedBlockProof(Hash),
}

/// Small dependency metadata; raw receipts are resolved only for relevant observations.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct SignedArtifactMetadata {
    /// Authenticated source chunk.
    pub chunk_id: ChunkId,
    /// Exact immutable artifact identity.
    pub id: Hash,
    /// Signed source category.
    pub kind: SignedArtifactKind,
    /// Protocol round, absent for a block receipt.
    pub round: Option<u32>,
    /// Individual accountable signers.
    pub signers: Vec<u32>,
    /// Exact signed proof-envelope dependencies.
    pub proof_hashes: Vec<Hash>,
    /// Encoded retained source size, excluding referenced accepted receipt bytes.
    pub storage_bytes: u64,
    /// This node published the source under its durable signing journal.
    pub local: bool,
    /// Value-vote phase, needed to retain an earlier actual locked precommit.
    pub phase: Option<neutrino_consensus_types::FinalityVotePhase>,
    /// Signed value target, absent for nil and pure pacemaker declarations.
    pub target: Option<Hash>,
}

impl SignedArtifactMetadata {
    fn for_artifact(chunk_id: ChunkId, artifact: &SignedArtifact) -> Self {
        let (round, signers, mut proof_hashes) = match artifact {
            SignedArtifact::Vote(vote) => (
                Some(vote.data.round),
                vote.attestations
                    .iter()
                    .map(|claim| claim.validator_index)
                    .collect(),
                vote.attestations
                    .iter()
                    .flat_map(|claim| claim.proof_hashes.iter().copied())
                    .collect(),
            ),
            SignedArtifact::Quorum(quorum) => (Some(quorum.data.round), Vec::new(), Vec::new()),
            SignedArtifact::BlockProof(_) => (None, Vec::new(), Vec::new()),
            SignedArtifact::Proposal(value) => {
                (Some(value.round), vec![value.proposer_index], Vec::new())
            }
            SignedArtifact::NilVote(value) => (
                Some(value.data.round),
                value
                    .attestations
                    .iter()
                    .map(|claim| claim.validator_index)
                    .collect(),
                Vec::new(),
            ),
            SignedArtifact::RoundChange(value) => {
                (Some(value.round), vec![value.validator_index], Vec::new())
            }
            SignedArtifact::RoundChangeCertificate(value) => (
                Some(value.round),
                value
                    .reports
                    .iter()
                    .map(|report| report.validator_index)
                    .collect(),
                Vec::new(),
            ),
        };
        proof_hashes.sort_unstable();
        proof_hashes.dedup();
        Self {
            chunk_id,
            id: artifact.id(),
            kind: artifact.kind(),
            round,
            signers,
            proof_hashes,
            storage_bytes: 0,
            local: false,
            phase: match artifact {
                SignedArtifact::Vote(value) => Some(value.data.phase),
                SignedArtifact::NilVote(value) => Some(value.data.phase),
                _ => None,
            },
            target: match artifact {
                SignedArtifact::Vote(value) => Some(value.data.chunk_hash),
                SignedArtifact::Quorum(value) => Some(value.data.chunk_hash),
                SignedArtifact::Proposal(value) => Some(value.chunk.hash()),
                _ => None,
            },
        }
    }
}

impl<DB: Database> ChainStore<DB> {
    /// Persist a checked source before publication; peer capacity excludes local reserve.
    pub fn put_signed_artifact(
        &mut self,
        chunk_id: ChunkId,
        artifact: &SignedArtifact,
    ) -> Result<Hash, StoreError<DB::Error>> {
        self.put_signed_artifact_with_priority(chunk_id, artifact, false, &[])
    }
    /// Reserved capacity for completed local signatures and actual lock dependencies.
    pub fn put_local_signed_artifact(
        &mut self,
        chunk_id: ChunkId,
        artifact: &SignedArtifact,
    ) -> Result<Hash, StoreError<DB::Error>> {
        self.put_signed_artifact_with_priority(chunk_id, artifact, true, &[])
    }
    /// Atomically replace superseded local publication slots, preserving actual locks.
    pub fn put_local_signed_artifact_protected(
        &mut self,
        chunk_id: ChunkId,
        artifact: &SignedArtifact,
        protected: &[Hash],
    ) -> Result<Hash, StoreError<DB::Error>> {
        self.put_signed_artifact_with_priority(chunk_id, artifact, true, protected)
    }

    fn put_signed_artifact_with_priority(
        &mut self,
        chunk_id: ChunkId,
        artifact: &SignedArtifact,
        local: bool,
        protected: &[Hash],
    ) -> Result<Hash, StoreError<DB::Error>> {
        let id = artifact.id();
        if let Some((source, prior)) = self.signed_artifact(&id)? {
            if source != chunk_id || prior != *artifact {
                return Err(StoreError::Corrupt("signed artifact identity conflict"));
            }
            if local
                && let Some(mut metadata) = self.signed_artifact_metadata_by_id(&id)?
                && !metadata.local
            {
                metadata.local = true;
                let mut batch = Batch::new();
                put_metadata(&mut batch, &metadata)?;
                self.db
                    .write_batch_durable(batch)
                    .map_err(StoreError::Database)?;
            }
            return Ok(id);
        }
        let payload = if let SignedArtifact::BlockProof(proof) = artifact {
            if self.get_block_proof(&proof.block_hash)?.as_ref() == Some(proof) {
                StoredPayload::AcceptedBlockProof(proof.block_hash)
            } else {
                StoredPayload::Source(Box::new(artifact.clone()))
            }
        } else {
            StoredPayload::Source(Box::new(artifact.clone()))
        };
        let bytes = borsh::to_vec(&StoredArtifact { chunk_id, payload })?;
        let archive = self.retention_info()?.policy == RetentionPolicy::Archive;
        let incoming = SignedArtifactMetadata::for_artifact(chunk_id, artifact);
        let mut removed = Vec::new();
        let mut count = 0_usize;
        let mut size = bytes.len();
        let retained = if archive {
            self.signed_artifact_metadata_for_chunk(chunk_id)?
        } else {
            self.active_signed_artifact_metadata()?
        };
        for existing in retained {
            let superseded = local
                && !archive
                && existing.local
                && existing.chunk_id == chunk_id
                && existing.kind == incoming.kind
                && existing.phase == incoming.phase
                && existing
                    .round
                    .zip(incoming.round)
                    .is_some_and(|(old, new)| old < new)
                && !protected.contains(&existing.id);
            if superseded {
                removed.push(existing.id);
                continue;
            }
            if !archive || existing.chunk_id == chunk_id {
                count += 1;
                size = size
                    .saturating_add(usize::try_from(existing.storage_bytes).unwrap_or(usize::MAX));
            }
        }
        let count_limit = if local {
            MAX_SIGNED_ARTIFACTS
        } else {
            MAX_SIGNED_ARTIFACTS - 256
        };
        let size_limit = if local {
            MAX_SIGNED_ARTIFACT_STORAGE_BYTES
        } else {
            MAX_SIGNED_ARTIFACT_STORAGE_BYTES - 128 * 1024 * 1024
        };
        if count >= count_limit || size > size_limit {
            return Err(StoreError::Corrupt(
                "signed artifact capacity; defer publication",
            ));
        }
        let mut metadata = incoming;
        metadata.local = local;
        metadata.storage_bytes =
            u64::try_from(bytes.len()).map_err(|_| StoreError::Corrupt("source size overflow"))?;
        let mut batch = Batch::new();
        for removed_id in removed {
            batch.delete(Column::SignedArtifacts, removed_id);
            delete_metadata(&mut batch, chunk_id, removed_id);
        }
        batch.put(Column::SignedArtifacts, id, bytes);
        put_metadata(&mut batch, &metadata)?;
        self.db
            .write_batch_durable(batch)
            .map_err(StoreError::Database)?;
        Ok(id)
    }

    /// Replace duplicate bytes with an exact pointer after normal proof admission.
    pub fn compact_accepted_artifact(
        &mut self,
        proof: &neutrino_consensus_types::BlockProof,
    ) -> Result<(), StoreError<DB::Error>> {
        let artifact = SignedArtifact::BlockProof(proof.clone());
        let id = artifact.id();
        if self.get_block_proof(&proof.block_hash)?.as_ref() != Some(proof) {
            return Ok(());
        }
        let Some((source, prior)) = self.signed_artifact(&id)? else {
            return Ok(());
        };
        if prior != artifact {
            return Err(StoreError::Corrupt("accepted artifact pointer mismatch"));
        }
        let bytes = borsh::to_vec(&StoredArtifact {
            chunk_id: source,
            payload: StoredPayload::AcceptedBlockProof(proof.block_hash),
        })?;
        let mut metadata = self
            .signed_artifact_metadata_by_id(&id)?
            .ok_or(StoreError::Corrupt("source metadata missing"))?;
        metadata.storage_bytes =
            u64::try_from(bytes.len()).map_err(|_| StoreError::Corrupt("source size overflow"))?;
        let mut batch = Batch::new();
        batch.put(Column::SignedArtifacts, id, bytes);
        put_metadata(&mut batch, &metadata)?;
        self.db
            .write_batch_durable(batch)
            .map_err(StoreError::Database)
    }

    /// Exact original source; no alternate encoding can satisfy this immutable ID.
    pub fn signed_artifact(
        &self,
        id: &Hash,
    ) -> Result<Option<(ChunkId, SignedArtifact)>, StoreError<DB::Error>> {
        let Some(bytes) = self
            .db
            .get(Column::SignedArtifacts, id)
            .map_err(StoreError::Database)?
        else {
            return Ok(None);
        };
        let stored: StoredArtifact = borsh::from_slice(&bytes)?;
        let artifact = match stored.payload {
            StoredPayload::Source(artifact) => *artifact,
            StoredPayload::AcceptedBlockProof(block_hash) => SignedArtifact::BlockProof(
                self.get_block_proof(&block_hash)?
                    .ok_or(StoreError::Corrupt("accepted source receipt unavailable"))?,
            ),
        };
        if artifact.id() != *id {
            return Err(StoreError::Corrupt("signed artifact key mismatch"));
        }
        Ok(Some((stored.chunk_id, artifact)))
    }

    /// Inspect one dependency row without decoding a receipt.
    pub fn signed_artifact_metadata_by_id(
        &self,
        id: &Hash,
    ) -> Result<Option<SignedArtifactMetadata>, StoreError<DB::Error>> {
        let Some(bytes) = self
            .db
            .get(Column::SignedArtifactIndex, &metadata_id_key(*id))
            .map_err(StoreError::Database)?
        else {
            return Ok(None);
        };
        let metadata: SignedArtifactMetadata = borsh::from_slice(&bytes)?;
        if metadata.id != *id {
            return Err(StoreError::Corrupt("signed source index mismatch"));
        }
        Ok(Some(metadata))
    }

    /// Iterate bounded metadata without decoding every raw source or receipt.
    pub fn signed_artifact_metadata(
        &self,
    ) -> Result<Vec<SignedArtifactMetadata>, StoreError<DB::Error>> {
        self.db
            .iter_prefix(Column::SignedArtifactIndex, &[0])
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(key, bytes)| {
                let metadata: SignedArtifactMetadata = borsh::from_slice(&bytes)?;
                if key.as_slice() != metadata_id_key(metadata.id) {
                    return Err(StoreError::Corrupt("signed source index mismatch"));
                }
                Ok(metadata)
            })
            .collect()
    }

    /// Read one source chunk without scanning retained proof-lag backlog.
    pub fn signed_artifact_metadata_for_chunk(
        &self,
        chunk_id: ChunkId,
    ) -> Result<Vec<SignedArtifactMetadata>, StoreError<DB::Error>> {
        self.db
            .iter_prefix(
                Column::SignedArtifactIndex,
                &metadata_chunk_prefix(chunk_id),
            )
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(key, bytes)| {
                let metadata: SignedArtifactMetadata = borsh::from_slice(&bytes)?;
                if metadata.chunk_id != chunk_id
                    || key.as_slice() != metadata_chunk_key(chunk_id, metadata.id)
                {
                    return Err(StoreError::Corrupt("signed source chunk index mismatch"));
                }
                Ok(metadata)
            })
            .collect()
    }

    /// Bound live admission independently of old rows awaiting recursive coverage.
    pub fn active_signed_artifact_metadata(
        &self,
    ) -> Result<Vec<SignedArtifactMetadata>, StoreError<DB::Error>> {
        let next = self
            .get_latest_finalized_chunk_id()?
            .map_or(Some(0), |id| id.checked_add(1))
            .ok_or(StoreError::Corrupt("signed source active window overflow"))?;
        let mut metadata = Vec::new();
        for chunk in
            next.saturating_sub(neutrino_consensus_types::history::HISTORY_RETENTION_CHUNKS)..=next
        {
            metadata.extend(self.signed_artifact_metadata_for_chunk(chunk)?);
        }
        Ok(metadata)
    }

    /// Stable bounded pagination over immutable source identities.
    pub fn signed_artifact_inventory(
        &self,
        chunk_id: ChunkId,
        after: Option<Hash>,
    ) -> Result<SignedArtifactInventory, StoreError<DB::Error>> {
        let mut entries: Vec<_> = self
            .signed_artifact_metadata_for_chunk(chunk_id)?
            .into_iter()
            .filter(|metadata| {
                metadata.chunk_id == chunk_id && after.is_none_or(|cursor| metadata.id > cursor)
            })
            .map(
                |metadata| neutrino_consensus_types::signed_artifacts::SignedArtifactRef {
                    id: metadata.id,
                    kind: metadata.kind,
                },
            )
            .collect();
        entries.sort_by_key(|entry| entry.id);
        let more = entries.len() > MAX_ARTIFACT_INVENTORY;
        entries.truncate(MAX_ARTIFACT_INVENTORY);
        let next = if more {
            entries.last().map(|entry| entry.id)
        } else {
            None
        };
        Ok(SignedArtifactInventory {
            chunk_id,
            entries,
            next,
        })
    }
    /// Remove obsolete sources only below authenticated recursive coverage.
    pub fn prune_signed_artifacts(
        &mut self,
        first_chunk: ChunkId,
    ) -> Result<(), StoreError<DB::Error>> {
        if self.retention_info()?.policy == RetentionPolicy::Archive
            || first_chunk
                <= self
                    .get_decoded::<u64>(Column::Meta, PRUNED_FLOOR_KEY)?
                    .unwrap_or(0)
        {
            return Ok(());
        }
        let mut batch = Batch::new();
        for metadata in self.signed_artifact_metadata()? {
            if metadata.chunk_id < first_chunk {
                batch.delete(Column::SignedArtifacts, metadata.id);
                delete_metadata(&mut batch, metadata.chunk_id, metadata.id);
            }
        }
        batch.put(Column::Meta, PRUNED_FLOOR_KEY, borsh::to_vec(&first_chunk)?);
        self.db
            .write_batch_durable(batch)
            .map_err(StoreError::Database)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProposerKey, test_db::FaultDb};
    use neutrino_consensus_types::{
        FinalityVoteData, FinalityVotePhase, NilVote, NilVoteAttestation, NilVoteData,
    };
    use neutrino_primitives::{BitVec, ConsensusDomain};

    const DOMAIN: ConsensusDomain = ConsensusDomain {
        chain_id: 7,
        chain_spec_hash: [9; 32],
    };
    use neutrino_storage::MemoryDatabase;

    fn nil(round: u32) -> SignedArtifact {
        nil_for_chunk(0, round)
    }
    fn nil_for_chunk(chunk_id: ChunkId, round: u32) -> SignedArtifact {
        let key = ProposerKey::from_ikm(&[1; 32], 0).unwrap();
        let data = NilVoteData {
            chunk_id,
            round,
            phase: FinalityVotePhase::Prevote,
        };
        let signature = key.sign_raw(&data.signing_message(DOMAIN)).to_bytes();
        let mut claim = NilVoteAttestation {
            validator_index: 0,
            vote: data.clone(),
            vote_signature: signature,
            signature: [0; 96],
        };
        claim.signature = key.sign_raw(&claim.signing_message(DOMAIN)).to_bytes();
        SignedArtifact::NilVote(NilVote {
            data,
            aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
            signature,
            attestations: vec![claim],
        })
    }
    fn precommit(round: u32) -> SignedArtifact {
        let key = ProposerKey::from_ikm(&[1; 32], 0).unwrap();
        let data = FinalityVoteData {
            chunk_id: 0,
            round,
            phase: FinalityVotePhase::Precommit,
            chunk_hash: [u8::try_from(round).unwrap(); 32],
        };
        let claim = key.attest_vote(DOMAIN, data.clone(), vec![[9; 32]], None);
        SignedArtifact::Vote(neutrino_consensus_types::FinalityVote {
            signature: key.sign_finality_vote(DOMAIN, &data),
            data,
            aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
            attestations: vec![claim],
        })
    }

    #[test]
    fn protected_rolling_local_slots_keep_lock_and_survive_many_unfinalized_rounds() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        for round in 0..300 {
            store
                .put_local_signed_artifact_protected(0, &nil(round), &[])
                .unwrap();
        }
        assert_eq!(store.signed_artifact_metadata().unwrap().len(), 1);
        let locked = precommit(0);
        store
            .put_local_signed_artifact_protected(0, &locked, &[])
            .unwrap();
        store
            .put_local_signed_artifact_protected(0, &precommit(1), &[locked.id()])
            .unwrap();
        store
            .put_local_signed_artifact_protected(0, &precommit(2), &[locked.id()])
            .unwrap();
        assert!(store.signed_artifact(&locked.id()).unwrap().is_some());
        assert!(store.signed_artifact(&precommit(1).id()).unwrap().is_none());
        assert!(store.signed_artifact(&precommit(2).id()).unwrap().is_some());
        let reopened = ChainStore::new(store.into_db());
        assert_eq!(
            reopened.signed_artifact(&locked.id()).unwrap().unwrap().1,
            locked
        );
    }

    #[test]
    fn failed_durable_slot_replacement_preserves_old_source_and_index() {
        let mut store = ChainStore::new(FaultDb::default());
        let old = nil(0);
        store
            .put_local_signed_artifact_protected(0, &old, &[])
            .unwrap();
        store.db_mut().fail_durable_after = Some(0);
        assert!(
            store
                .put_local_signed_artifact_protected(0, &nil(1), &[])
                .is_err()
        );
        let reopened = ChainStore::new(store.into_db());
        assert_eq!(reopened.signed_artifact(&old.id()).unwrap().unwrap().1, old);
        assert!(reopened.signed_artifact(&nil(1).id()).unwrap().is_none());
        assert_eq!(
            reopened
                .signed_artifact_inventory(0, None)
                .unwrap()
                .entries
                .len(),
            1
        );
    }

    #[test]
    fn peer_record_capacity_preserves_local_publication_and_rolling_slots() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let mut batch = Batch::new();
        // Populate checked rows directly: this regression exercises admission
        // accounting without thousands of repeated full-index scans.
        for round in 0..MAX_SIGNED_ARTIFACTS - 256 {
            let artifact = nil(u32::try_from(round).unwrap());
            let id = artifact.id();
            let bytes = borsh::to_vec(&StoredArtifact {
                chunk_id: 0,
                payload: StoredPayload::Source(Box::new(artifact.clone())),
            })
            .unwrap();
            let mut metadata = SignedArtifactMetadata::for_artifact(0, &artifact);
            metadata.storage_bytes = u64::try_from(bytes.len()).unwrap();
            batch.put(Column::SignedArtifacts, id, bytes);
            put_metadata(&mut batch, &metadata).unwrap();
        }
        store.db_mut().write_batch_durable(batch).unwrap();
        let latest = nil(4000);
        assert!(store.put_signed_artifact(0, &latest).is_err());
        store
            .put_local_signed_artifact_protected(0, &latest, &[])
            .unwrap();
        let next = nil(4001);
        store
            .put_local_signed_artifact_protected(0, &next, &[])
            .unwrap();
        assert!(store.signed_artifact(&latest.id()).unwrap().is_none());
        assert_eq!(store.signed_artifact(&next.id()).unwrap().unwrap().1, next);
        assert_eq!(
            store.signed_artifact_metadata().unwrap().len(),
            MAX_SIGNED_ARTIFACTS - 256 + 1
        );
    }

    #[test]
    fn archive_preserves_superseded_local_round_sources() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        store
            .set_retention_policy(RetentionPolicy::Archive)
            .unwrap();
        for round in 0..40 {
            store
                .put_local_signed_artifact_protected(0, &nil(round), &[])
                .unwrap();
        }
        let first = store.signed_artifact_inventory(0, None).unwrap();
        assert_eq!(first.entries.len(), 32);
        let second = store.signed_artifact_inventory(0, first.next).unwrap();
        assert_eq!(second.entries.len(), 8);
        assert!(second.next.is_none());
        store.prune_signed_artifacts(u64::MAX).unwrap();
        assert_eq!(store.signed_artifact_metadata().unwrap().len(), 40);
    }

    #[test]
    fn recursive_coverage_lag_preserves_old_rows_without_gating_live_publication() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        let mut batch = Batch::new();
        for chunk in 0..30 {
            for round in 0..144 {
                let artifact = nil_for_chunk(chunk, round);
                let id = artifact.id();
                let bytes = borsh::to_vec(&StoredArtifact {
                    chunk_id: chunk,
                    payload: StoredPayload::Source(Box::new(artifact.clone())),
                })
                .unwrap();
                let mut metadata = SignedArtifactMetadata::for_artifact(chunk, &artifact);
                metadata.storage_bytes = u64::try_from(bytes.len()).unwrap();
                batch.put(Column::SignedArtifacts, id, bytes);
                put_metadata(&mut batch, &metadata).unwrap();
            }
        }
        store.db_mut().write_batch_durable(batch).unwrap();
        store.put_latest_finalized_chunk_id(29).unwrap();
        store.put_recursive_covered_chunks(0).unwrap();
        store.prune_signed_artifacts(0).unwrap();
        assert!(store.signed_artifact_metadata().unwrap().len() > MAX_SIGNED_ARTIFACTS);
        let current = nil_for_chunk(30, 0);
        store
            .put_local_signed_artifact_protected(30, &current, &[])
            .unwrap();
        assert_eq!(
            store.signed_artifact(&current.id()).unwrap().unwrap().1,
            current
        );
        assert_eq!(
            store.signed_artifact_metadata_for_chunk(0).unwrap().len(),
            144
        );
        assert_eq!(
            store.active_signed_artifact_metadata().unwrap().len(),
            8 * 144 + 1
        );
        let reopened = ChainStore::new(store.into_db());
        assert_eq!(
            reopened
                .signed_artifact_metadata_for_chunk(0)
                .unwrap()
                .len(),
            144
        );
    }
}
