//! Selective durable accountability storage, independent of ordinary source pruning.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::Header;
use neutrino_consensus_types::history::{HistoryFrontier, HistoryPath};
use neutrino_consensus_types::history_proof::ConsensusBoundary;
use neutrino_consensus_types::signed_artifacts::SignedArtifact;
use neutrino_primitives::{BlsPublicKey, Hash, Validator};
use neutrino_prover_chunk::{
    execution::commitment,
    history::{HistoricalChunk, HistoricalOpening},
};
use neutrino_storage::{Batch, Column, Database};
use std::collections::{BTreeMap, BTreeSet};

use super::{ChainStore, StoreError};
use crate::{ReporterIdentity, RetentionPolicy};

#[derive(BorshSerialize, BorshDeserialize)]
pub(super) struct Owned<T> {
    owners: Vec<BlsPublicKey>,
    pub(super) value: T,
}

struct ReporterContext {
    validators: Vec<Validator>,
    owners: Vec<BlsPublicKey>,
}

fn source_key(chunk: u64, id: Hash) -> [u8; 40] {
    let mut key = [0; 40];
    key[..8].copy_from_slice(&chunk.to_be_bytes());
    key[8..].copy_from_slice(&id);
    key
}

fn lookup_key(kind: u8, hash: &Hash) -> [u8; 33] {
    let mut key = [0; 33];
    key[0] = kind;
    key[1..].copy_from_slice(hash);
    key
}

fn inventory_key(chunk: u64, hash: Hash) -> [u8; 41] {
    let mut key = [0; 41];
    key[0] = 2;
    key[1..].copy_from_slice(&source_key(chunk, hash));
    key
}

fn chunk_lookup_key(chunk: u64) -> [u8; 9] {
    let mut key = [3; 9];
    key[1..].copy_from_slice(&chunk.to_be_bytes());
    key
}

fn validate_addresses<E>(addresses: &[[u8; 32]]) -> Result<(), StoreError<E>> {
    if addresses.is_empty() || addresses.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(StoreError::Corrupt(
            "reporter withdrawal addresses are not canonical",
        ));
    }
    Ok(())
}

impl<DB: Database> ChainStore<DB> {
    pub(crate) fn retain_reporter_source(
        &mut self,
        chunk: u64,
        artifact: &SignedArtifact,
    ) -> Result<(), StoreError<DB::Error>> {
        if self.retention_info()?.policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        let mut batch = Batch::new();
        self.retain_reporter_source_batch(&mut batch, chunk, artifact)?;
        self.write_observed_batch(batch, true)
    }

    pub(crate) fn seed_reporter_tracking(
        &mut self,
        identities: &[(BlsPublicKey, [u8; 32])],
    ) -> Result<(), StoreError<DB::Error>> {
        let mut batch = Batch::new();
        self.merge_reporter_identities_batch(&mut batch, identities)?;
        self.write_observed_batch(batch, true)
    }

    /// Identities with selectively retained material and their historical withdrawal addresses.
    pub fn reporter_tracked_validators(
        &self,
    ) -> Result<Vec<ReporterIdentity>, StoreError<DB::Error>> {
        let mut identities = Vec::new();
        for (key, bytes) in self
            .db
            .iter_column(Column::ReporterValidators)
            .map_err(StoreError::Database)?
        {
            let key = key
                .try_into()
                .map_err(|_| StoreError::Corrupt("reporter identity key"))?;
            let addresses: Vec<[u8; 32]> = borsh::from_slice(&bytes)?;
            validate_addresses::<DB::Error>(&addresses)?;
            identities.extend(addresses.into_iter().map(|address| (key, address)));
        }
        identities.sort_unstable();
        Ok(identities)
    }

    fn merge_reporter_identities_batch(
        &self,
        batch: &mut Batch,
        identities: &[ReporterIdentity],
    ) -> Result<(), StoreError<DB::Error>> {
        let mut grouped: BTreeMap<BlsPublicKey, Vec<[u8; 32]>> = BTreeMap::new();
        for (key, address) in identities {
            grouped.entry(*key).or_default().push(*address);
        }
        for (key, mut addresses) in grouped {
            if let Some(previous) =
                self.get_decoded::<Vec<[u8; 32]>>(Column::ReporterValidators, &key)?
            {
                validate_addresses::<DB::Error>(&previous)?;
                addresses.extend(previous);
            }
            addresses.sort_unstable();
            addresses.dedup();
            batch.put(Column::ReporterValidators, key, borsh::to_vec(&addresses)?);
        }
        Ok(())
    }

    /// Whether switching to a snapshot would skip append data needed by watched openings.
    pub fn reporter_has_history(&self) -> Result<bool, StoreError<DB::Error>> {
        Ok(!self
            .db
            .iter_column(Column::ReporterIndex)
            .map_err(StoreError::Database)?
            .is_empty())
    }

    /// Replace eligibility only from authenticated finalized runtime economics.
    /// Shared material is deleted only after its last slashable owner leaves.
    pub fn set_reporter_eligible(
        &mut self,
        eligible: &[(BlsPublicKey, [u8; 32])],
    ) -> Result<Vec<Hash>, StoreError<DB::Error>> {
        if self.retention_info()?.policy != RetentionPolicy::Reporter {
            return Err(StoreError::Corrupt(
                "reporter eligibility outside reporter role",
            ));
        }
        let mut keys = BTreeSet::new();
        let mut batch = Batch::new();
        let mut removed_raw = Vec::new();
        self.merge_reporter_identities_batch(&mut batch, eligible)?;
        for (key, _) in eligible {
            keys.insert(*key);
        }
        let previous = self.reporter_tracked_validators()?;
        let changed = previous.iter().any(|(key, _)| !keys.contains(key));
        for (key, _) in previous {
            if !keys.contains(&key) {
                batch.delete(Column::ReporterValidators, key);
            }
        }
        for (id, evidence) in self.iter_slashing_evidence()? {
            let chunk = match &evidence {
                neutrino_consensus_types::SlashingEvidence::DoubleProposal { header_a, .. } => {
                    self.reporter_chunk_for_height(header_a.height)?
                }
                neutrino_consensus_types::SlashingEvidence::InvalidVrfClaim { header, .. }
                | neutrino_consensus_types::SlashingEvidence::DaCommitmentFraud {
                    header, ..
                } => self.reporter_chunk_for_height(header.height)?,
                neutrino_consensus_types::SlashingEvidence::DoublePrevote { vote_a, .. }
                | neutrino_consensus_types::SlashingEvidence::DoublePrecommit { vote_a, .. }
                | neutrino_consensus_types::SlashingEvidence::LockViolation { vote_a, .. } => {
                    vote_a.data.chunk_id
                }
                neutrino_consensus_types::SlashingEvidence::InvalidProofSigning {
                    vote, ..
                }
                | neutrino_consensus_types::SlashingEvidence::LongRangeForkParticipation {
                    vote,
                    ..
                } => vote.data.chunk_id,
                neutrino_consensus_types::SlashingEvidence::ConflictingNilVote {
                    value_vote,
                    ..
                } => value_vote.data.chunk_id,
                neutrino_consensus_types::SlashingEvidence::DoubleBftProposal {
                    proposal_a,
                    ..
                } => proposal_a.chunk.chunk_id,
            };
            let validators = if let Some(record) = self.historical_chunk(chunk)? {
                record.validators
            } else if chunk
                == self
                    .get_latest_finalized_chunk_id()?
                    .map_or(0, |id| id.saturating_add(1))
            {
                self.get_validator_set_snapshot(
                    self.get_latest_validator_set_index()?.unwrap_or(0),
                )?
                .unwrap_or_default()
            } else {
                Vec::new()
            };
            let accused = validators
                .get(evidence.offender_index() as usize)
                .map(|v| v.pubkey);
            if accused.is_none_or(|key| !keys.contains(&key)) {
                batch.delete(Column::SlashingPool, id);
                removed_raw.push(id);
            }
        }
        if changed {
            self.trim_reporter_owners::<HistoricalOpening>(
                &mut batch,
                Column::ReporterHistory,
                &keys,
            )?;
            self.trim_reporter_owners::<SignedArtifact>(
                &mut batch,
                Column::ReporterSources,
                &keys,
            )?;
            self.trim_reporter_owners::<Header>(&mut batch, Column::ReporterHeaders, &keys)?;
            self.trim_reporter_owners::<ConsensusBoundary>(
                &mut batch,
                Column::ReporterBoundaries,
                &keys,
            )?;
        }
        self.write_observed_batch(batch, true)?;
        Ok(removed_raw)
    }

    fn reporter_chunk_for_height(&self, height: u64) -> Result<u64, StoreError<DB::Error>> {
        let size = self
            .history_domain()?
            .ok_or(StoreError::Corrupt("reporter raw history domain"))?
            .chain
            .chunk_size;
        height
            .checked_sub(1)
            .and_then(|h| h.checked_div(size))
            .ok_or(StoreError::Corrupt("reporter raw source height"))
    }

    fn trim_reporter_owners<T: BorshSerialize + BorshDeserialize>(
        &self,
        batch: &mut Batch,
        column: Column,
        eligible: &BTreeSet<BlsPublicKey>,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut removed_headers: BTreeMap<Hash, Vec<u64>> = BTreeMap::new();
        for (key, bytes) in self.db.iter_column(column).map_err(StoreError::Database)? {
            let mut entry: Owned<T> = borsh::from_slice(&bytes)?;
            entry.owners.retain(|owner| eligible.contains(owner));
            if entry.owners.is_empty() {
                if column == Column::ReporterHistory {
                    let chunk = super::retention::decode_count(&key)?;
                    batch.delete(Column::ReporterIndex, chunk_lookup_key(chunk));
                }
                if column == Column::ReporterSources {
                    let hash: Hash = key[8..]
                        .try_into()
                        .map_err(|_| StoreError::Corrupt("reporter source key"))?;
                    batch.delete(Column::ReporterIndex, lookup_key(0, &hash));
                    let chunk = u64::from_be_bytes(key[..8].try_into().expect("eight bytes"));
                    batch.delete(Column::ReporterIndex, inventory_key(chunk, hash));
                } else if column == Column::ReporterHeaders {
                    let hash: Hash = key[8..]
                        .try_into()
                        .map_err(|_| StoreError::Corrupt("reporter header key"))?;
                    let chunk = u64::from_be_bytes(key[..8].try_into().expect("eight bytes"));
                    removed_headers.entry(hash).or_default().push(chunk);
                }
                batch.delete(column, key);
            } else {
                batch.put(column, key, borsh::to_vec(&entry)?);
            }
        }
        for (hash, removed) in removed_headers {
            let mut chunks: Vec<u64> = self
                .get_decoded(Column::ReporterIndex, &lookup_key(1, &hash))?
                .ok_or(StoreError::Corrupt("reporter header lookup missing"))?;
            chunks.retain(|chunk| !removed.contains(chunk));
            if chunks.is_empty() {
                batch.delete(Column::ReporterIndex, lookup_key(1, &hash));
            } else {
                batch.put(
                    Column::ReporterIndex,
                    lookup_key(1, &hash),
                    borsh::to_vec(&chunks)?,
                );
            }
        }
        Ok(())
    }

    fn reporter_owners(
        &self,
        validators: &[Validator],
    ) -> Result<Vec<BlsPublicKey>, StoreError<DB::Error>> {
        let eligible: BTreeSet<_> = self
            .reporter_tracked_validators()?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        Ok(validators
            .iter()
            .filter(|v| eligible.contains(&v.pubkey))
            .map(|v| v.pubkey)
            .collect())
    }

    fn reporter_context_batch(
        &self,
        batch: &mut Batch,
        chunk: u64,
    ) -> Result<ReporterContext, StoreError<DB::Error>> {
        if let Some(opening) = self.reporter_opening(chunk)? {
            let owners = self.reporter_owners(&opening.record.validators)?;
            return Ok(ReporterContext {
                validators: opening.record.validators,
                owners,
            });
        }
        let state = self.get_consensus_state()?;
        let count = state.as_ref().map_or_else(
            || {
                self.get_latest_finalized_chunk_id()
                    .map(|id| id.map_or(0, |id| id.saturating_add(1)))
            },
            |state| Ok(state.boundary.next_chunk_id),
        )?;
        if chunk < count {
            let opening = self.historical_opening(chunk, count)?;
            let boundary = self.consensus_boundary(chunk)?;
            return self.promote_reporter_opening_batch(batch, &opening, boundary.as_ref());
        }
        if chunk != count {
            return Err(StoreError::Corrupt("reporter source is not authenticated"));
        }
        let validators = if let Some(state) = state {
            state.next_context.active_validators
        } else {
            self.get_validator_set_snapshot(self.get_latest_validator_set_index()?.unwrap_or(0))?
                .unwrap_or_default()
        };
        Ok(ReporterContext {
            owners: self.reporter_owners(&validators)?,
            validators,
        })
    }

    fn promote_reporter_opening_batch(
        &self,
        batch: &mut Batch,
        opening: &HistoricalOpening,
        boundary: Option<&ConsensusBoundary>,
    ) -> Result<ReporterContext, StoreError<DB::Error>> {
        let chunk = opening.record.chunk.chunk_id;
        let mut identities = Vec::new();
        let mut owners = self.reporter_owners(&opening.record.validators)?;
        for validator in &opening.record.validators {
            if !validator.slashed
                && validator.effective_stake > 0
                && !self.is_identity_slashed(&validator.pubkey)?
            {
                identities.push((validator.pubkey, validator.withdrawal_credentials));
                owners.push(validator.pubkey);
            }
        }
        owners.sort_unstable();
        owners.dedup();
        self.merge_reporter_identities_batch(batch, &identities)?;
        if !owners.is_empty() {
            batch.put(Column::ReporterIndex, chunk_lookup_key(chunk), [0]);
            batch.put(
                Column::ReporterHistory,
                chunk.to_be_bytes(),
                borsh::to_vec(&Owned {
                    owners: owners.clone(),
                    value: opening.clone(),
                })?,
            );
            if let Some(boundary) = boundary {
                batch.put(
                    Column::ReporterBoundaries,
                    chunk.to_be_bytes(),
                    borsh::to_vec(&Owned {
                        owners: owners.clone(),
                        value: *boundary,
                    })?,
                );
            }
        }
        Ok(ReporterContext {
            validators: opening.record.validators.clone(),
            owners,
        })
    }

    pub(super) fn retain_reporter_bootstrap_batch(
        &self,
        batch: &mut Batch,
        recent: &[HistoricalOpening],
    ) -> Result<(), StoreError<DB::Error>> {
        if self.retention_info()?.policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        let mut identities = Vec::new();
        for opening in recent {
            self.promote_reporter_opening_batch(batch, opening, None)?;
            for validator in &opening.record.validators {
                if !validator.slashed
                    && validator.effective_stake > 0
                    && !self.is_identity_slashed(&validator.pubkey)?
                {
                    identities.push((validator.pubkey, validator.withdrawal_credentials));
                }
            }
        }
        // Each opening can contain a different account for the same BLS key.
        // Publish their complete union after the individual context writes.
        self.merge_reporter_identities_batch(batch, &identities)
    }

    pub(super) fn advance_reporter_history_batch(
        &self,
        batch: &mut Batch,
        record: &HistoricalChunk,
        old: &HistoryFrontier,
        path: &HistoryPath,
    ) -> Result<(), StoreError<DB::Error>> {
        if self.retention_info()?.policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        let leaf = commitment(&record.evidence_context());
        for (key, bytes) in self
            .db
            .iter_column(Column::ReporterHistory)
            .map_err(StoreError::Database)?
        {
            let mut entry: Owned<HistoricalOpening> = borsh::from_slice(&bytes)?;
            let prior_leaf = commitment(&entry.value.record.evidence_context());
            if entry.value.path.advance(prior_leaf, old, leaf).is_none() {
                return Err(StoreError::Corrupt("reporter opening advance"));
            }
            batch.put(Column::ReporterHistory, key, borsh::to_vec(&entry)?);
        }
        // New memberships are retained immediately. The finalized runtime query
        // following this append decides whether they remain economically accountable.
        let mut owners = Vec::new();
        let mut identities = Vec::new();
        for validator in &record.validators {
            if !validator.slashed
                && validator.effective_stake > 0
                && !self.is_identity_slashed(&validator.pubkey)?
            {
                owners.push(validator.pubkey);
                identities.push((validator.pubkey, validator.withdrawal_credentials));
            }
        }
        self.merge_reporter_identities_batch(batch, &identities)?;
        if !owners.is_empty() {
            batch.put(
                Column::ReporterIndex,
                chunk_lookup_key(record.chunk.chunk_id),
                [0],
            );
            batch.put(
                Column::ReporterHistory,
                record.chunk.chunk_id.to_be_bytes(),
                borsh::to_vec(&Owned {
                    owners,
                    value: HistoricalOpening {
                        record: record.clone(),
                        path: path.clone(),
                    },
                })?,
            );
        }
        Ok(())
    }

    /// Reverify the current opening before using a selectively saved historical context.
    pub fn reporter_opening(
        &self,
        chunk: u64,
    ) -> Result<Option<HistoricalOpening>, StoreError<DB::Error>> {
        let Some(entry) = self.get_decoded::<Owned<HistoricalOpening>>(
            Column::ReporterHistory,
            &chunk.to_be_bytes(),
        )?
        else {
            return Ok(None);
        };
        let opening = entry.value;
        let frontier = self.history_frontier(opening.path.count)?;
        let root = frontier
            .root()
            .ok_or(StoreError::Corrupt("reporter frontier"))?;
        if entry.owners.is_empty()
            || opening.record.chunk.chunk_id != chunk
            || opening.path.index != chunk
            || !opening
                .path
                .verify(commitment(&opening.record.evidence_context()), root)
        {
            return Err(StoreError::Corrupt("reporter historical opening"));
        }
        Ok(Some(opening))
    }

    /// Watched finalized chunk IDs for restart and delayed dependency discovery.
    pub fn reporter_history_chunks(&self) -> Result<Vec<u64>, StoreError<DB::Error>> {
        self.db
            .iter_prefix(Column::ReporterIndex, &[3])
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(key, _)| {
                key.get(1..)
                    .ok_or(StoreError::Corrupt("reporter chunk lookup key"))
                    .and_then(super::retention::decode_count)
            })
            .collect()
    }

    /// Exact signed sources for one watched historical chunk, excluding complete block bodies.
    pub fn reporter_sources_for_chunk(
        &self,
        chunk: u64,
    ) -> Result<Vec<SignedArtifact>, StoreError<DB::Error>> {
        self.db
            .iter_prefix(Column::ReporterSources, &chunk.to_be_bytes())
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(key, bytes)| {
                let entry: Owned<SignedArtifact> = borsh::from_slice(&bytes)?;
                if key.as_slice() != source_key(chunk, entry.value.id()) {
                    return Err(StoreError::Corrupt("reporter source key"));
                }
                Ok(entry.value)
            })
            .collect()
    }

    pub(super) fn reporter_source_refs(
        &self,
        chunk: u64,
    ) -> Result<
        Vec<neutrino_consensus_types::signed_artifacts::SignedArtifactRef>,
        StoreError<DB::Error>,
    > {
        let key = inventory_key(chunk, [0; 32]);
        self.db
            .iter_prefix(Column::ReporterIndex, &key[..9])
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(key, bytes)| {
                let id = key
                    .get(9..)
                    .and_then(|id| id.try_into().ok())
                    .ok_or(StoreError::Corrupt("reporter inventory key"))?;
                Ok(
                    neutrino_consensus_types::signed_artifacts::SignedArtifactRef {
                        id,
                        kind: borsh::from_slice(&bytes)?,
                    },
                )
            })
            .collect()
    }

    pub(super) fn retain_reporter_source_batch(
        &self,
        batch: &mut Batch,
        chunk: u64,
        artifact: &SignedArtifact,
    ) -> Result<(), StoreError<DB::Error>> {
        if self.retention_info()?.policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        let ReporterContext { validators, owners } = self.reporter_context_batch(batch, chunk)?;
        let signers: Vec<u32> = match artifact {
            SignedArtifact::Vote(value) => value
                .attestations
                .iter()
                .map(|v| v.validator_index)
                .collect(),
            SignedArtifact::NilVote(value) => value
                .attestations
                .iter()
                .map(|v| v.validator_index)
                .collect(),
            SignedArtifact::Proposal(value) => vec![value.proposer_index],
            SignedArtifact::RoundChange(value) => vec![value.validator_index],
            SignedArtifact::RoundChangeCertificate(value) => {
                value.reports.iter().map(|v| v.validator_index).collect()
            }
            SignedArtifact::Quorum(_) | SignedArtifact::BlockProof(_) => Vec::new(),
        };
        let source_owners: Vec<_> = match artifact {
            SignedArtifact::Quorum(_) => owners.clone(),
            SignedArtifact::BlockProof(_) => {
                self.reporter_proof_claim_owners(chunk, artifact.id(), &validators, &owners)?
            }
            _ => signers
                .iter()
                .filter_map(|index| validators.get(*index as usize))
                .map(|v| v.pubkey)
                .filter(|key| owners.contains(key))
                .collect(),
        };
        let quorums: Vec<_> = match artifact {
            SignedArtifact::Vote(value) => value
                .attestations
                .iter()
                .filter_map(|v| v.unlock_quorum.as_ref())
                .collect(),
            SignedArtifact::Proposal(value) => value.valid_quorum.iter().collect(),
            SignedArtifact::RoundChange(value) => value.highest_quorum.iter().collect(),
            SignedArtifact::RoundChangeCertificate(value) => value
                .reports
                .iter()
                .filter_map(|v| v.highest_quorum.as_ref())
                .collect(),
            _ => Vec::new(),
        };
        if !owners.is_empty() {
            for quorum in quorums {
                let dependency = SignedArtifact::Quorum(quorum.clone());
                self.put_reporter_source_batch(batch, chunk, &dependency, &owners)?;
            }
        }
        if !source_owners.is_empty() {
            // Copy envelopes: accepted receipt references would dangle after ordinary pruning.
            // Quorums and other signers remain dependencies of a tracked signer's lock claim.
            self.put_reporter_source_batch(batch, chunk, artifact, &source_owners)?;
        }
        if let SignedArtifact::Vote(vote) = artifact {
            let mut dependencies: BTreeMap<Hash, Vec<BlsPublicKey>> = BTreeMap::new();
            for claim in &vote.attestations {
                let Some(owner) = validators
                    .get(claim.validator_index as usize)
                    .map(|v| v.pubkey)
                    .filter(|key| owners.contains(key))
                else {
                    continue;
                };
                for id in &claim.proof_hashes {
                    dependencies.entry(*id).or_default().push(owner);
                }
            }
            for (id, users) in dependencies {
                if let Some((source, dependency @ SignedArtifact::BlockProof(_))) =
                    self.signed_artifact(&id)?
                    && source == chunk
                {
                    self.put_reporter_source_batch(batch, chunk, &dependency, &users)?;
                }
            }
        }
        Ok(())
    }

    fn reporter_proof_claim_owners(
        &self,
        chunk: u64,
        id: Hash,
        validators: &[Validator],
        eligible: &[BlsPublicKey],
    ) -> Result<Vec<BlsPublicKey>, StoreError<DB::Error>> {
        let mut claims = Vec::new();
        for source in self.reporter_sources_for_chunk(chunk)? {
            if let SignedArtifact::Vote(vote) = source {
                claims.extend(vote.attestations);
            }
        }
        if let Some(record) = self.historical_chunk(chunk)? {
            claims.extend(record.finality.precommit_attestations);
        }
        let mut owners: Vec<_> = claims
            .into_iter()
            .filter(|claim| claim.proof_hashes.contains(&id))
            .filter_map(|claim| validators.get(claim.validator_index as usize))
            .map(|v| v.pubkey)
            .filter(|key| eligible.contains(key))
            .collect();
        owners.sort_unstable();
        owners.dedup();
        Ok(owners)
    }

    fn put_reporter_source_batch(
        &self,
        batch: &mut Batch,
        chunk: u64,
        artifact: &SignedArtifact,
        owners: &[BlsPublicKey],
    ) -> Result<(), StoreError<DB::Error>> {
        let key = source_key(chunk, artifact.id());
        let mut all = owners.to_vec();
        if let Some(prior) =
            self.get_decoded::<Owned<SignedArtifact>>(Column::ReporterSources, &key)?
        {
            all.extend(prior.owners);
        }
        all.sort_unstable();
        all.dedup();
        batch.put(
            Column::ReporterSources,
            key,
            borsh::to_vec(&Owned {
                owners: all.clone(),
                value: artifact.clone(),
            })?,
        );
        batch.put(
            Column::ReporterIndex,
            lookup_key(0, &artifact.id()),
            borsh::to_vec(&chunk)?,
        );
        batch.put(
            Column::ReporterIndex,
            inventory_key(chunk, artifact.id()),
            borsh::to_vec(&artifact.kind())?,
        );
        if let SignedArtifact::BlockProof(proof) = artifact
            && let Some(header) = self
                .get_header(&proof.block_hash)?
                .or(self.reporter_header(&proof.block_hash)?)
        {
            self.put_reporter_header_batch(batch, chunk, &header, &all)?;
            if let Some(parent) = self
                .get_header(&header.parent_hash)?
                .or(self.reporter_header(&header.parent_hash)?)
            {
                self.put_reporter_header_batch(batch, chunk, &parent, &all)?;
            }
        }
        Ok(())
    }

    fn put_reporter_header_batch(
        &self,
        batch: &mut Batch,
        chunk: u64,
        header: &Header,
        owners: &[BlsPublicKey],
    ) -> Result<(), StoreError<DB::Error>> {
        let key = source_key(chunk, header.hash());
        let mut all = owners.to_vec();
        if let Some(prior) = self.get_decoded::<Owned<Header>>(Column::ReporterHeaders, &key)? {
            all.extend(prior.owners);
        }
        all.sort_unstable();
        all.dedup();
        if !all.is_empty() {
            batch.put(
                Column::ReporterHeaders,
                key,
                borsh::to_vec(&Owned {
                    owners: all,
                    value: header.clone(),
                })?,
            );
            let mut chunks: Vec<u64> = self
                .get_decoded(Column::ReporterIndex, &lookup_key(1, &header.hash()))?
                .unwrap_or_default();
            chunks.push(chunk);
            chunks.sort_unstable();
            chunks.dedup();
            batch.put(
                Column::ReporterIndex,
                lookup_key(1, &header.hash()),
                borsh::to_vec(&chunks)?,
            );
        }
        Ok(())
    }

    /// Save a historical program boundary needed by retained exact proof envelopes.
    pub(super) fn retain_reporter_boundary_batch(
        &self,
        batch: &mut Batch,
        record: &HistoricalChunk,
        boundary: &ConsensusBoundary,
    ) -> Result<(), StoreError<DB::Error>> {
        if self.retention_info()?.policy == RetentionPolicy::Reporter {
            let owners: Vec<_> = record
                .validators
                .iter()
                .filter(|v| !v.slashed && v.effective_stake > 0)
                .map(|v| v.pubkey)
                .collect();
            batch.put(
                Column::ReporterBoundaries,
                boundary.next_chunk_id.to_be_bytes(),
                borsh::to_vec(&Owned {
                    owners,
                    value: *boundary,
                })?,
            );
        }
        Ok(())
    }

    /// Compact saved boundary used for forensic source verification, never live BFT admission.
    pub fn reporter_boundary(
        &self,
        count: u64,
    ) -> Result<Option<ConsensusBoundary>, StoreError<DB::Error>> {
        self.get_decoded::<Owned<ConsensusBoundary>>(
            Column::ReporterBoundaries,
            &count.to_be_bytes(),
        )
        .map(|entry| entry.map(|e| e.value))
    }

    /// Retain a signed header and its parent dependency without retaining its block body.
    pub fn retain_reporter_header(
        &mut self,
        chunk: u64,
        header: &Header,
        validators: &[Validator],
    ) -> Result<(), StoreError<DB::Error>> {
        if self.retention_info()?.policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        let count = self
            .get_latest_finalized_chunk_id()?
            .map_or(0, |id| id.saturating_add(1));
        if chunk > count {
            return Ok(());
        }
        let mut batch = Batch::new();
        let context = self.reporter_context_batch(&mut batch, chunk)?;
        if context.validators != validators {
            return Err(StoreError::Corrupt("reporter header validator context"));
        }
        let owners: Vec<_> = context
            .validators
            .get(header.proposer_index as usize)
            .map(|v| v.pubkey)
            .filter(|key| context.owners.contains(key))
            .into_iter()
            .collect();
        if owners.is_empty() {
            return Ok(());
        }
        self.put_reporter_header_batch(&mut batch, chunk, header, &owners)?;
        self.write_observed_batch(batch, true)
    }

    pub(super) fn retain_reporter_finalization_batch(
        &self,
        batch: &mut Batch,
        record: &HistoricalChunk,
        boundary: &ConsensusBoundary,
        headers: impl Iterator<Item = Header>,
    ) -> Result<(), StoreError<DB::Error>> {
        self.retain_reporter_boundary_batch(batch, record, boundary)?;
        if self.retention_info()?.policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        let mut retained: BTreeMap<Hash, (Header, Vec<BlsPublicKey>)> = BTreeMap::new();
        for header in headers {
            let owners: Vec<_> = record
                .validators
                .get(header.proposer_index as usize)
                .map(|v| v.pubkey)
                .into_iter()
                .collect();
            retained
                .entry(header.hash())
                .or_insert_with(|| (header.clone(), Vec::new()))
                .1
                .extend(owners);
            if let Some(proof) = self.get_block_proof(&header.hash())? {
                let source = SignedArtifact::BlockProof(proof);
                let users: Vec<_> = record
                    .finality
                    .precommit_attestations
                    .iter()
                    .filter(|claim| claim.proof_hashes.contains(&source.id()))
                    .filter_map(|claim| record.validators.get(claim.validator_index as usize))
                    .map(|v| v.pubkey)
                    .collect();
                if !users.is_empty() {
                    self.put_reporter_source_batch(batch, record.chunk.chunk_id, &source, &users)?;
                    retained
                        .entry(header.hash())
                        .or_insert_with(|| (header.clone(), Vec::new()))
                        .1
                        .extend_from_slice(&users);
                    if let Some(parent) = self
                        .get_header(&header.parent_hash)?
                        .or(self.reporter_header(&header.parent_hash)?)
                    {
                        retained
                            .entry(parent.hash())
                            .or_insert_with(|| (parent, Vec::new()))
                            .1
                            .extend(users);
                    }
                }
            }
        }
        for (_, (header, owners)) in retained {
            self.put_reporter_header_batch(batch, record.chunk.chunk_id, &header, &owners)?;
        }
        Ok(())
    }

    /// Saved compact header dependency for exact historical block proof authentication.
    pub fn reporter_header(&self, hash: &Hash) -> Result<Option<Header>, StoreError<DB::Error>> {
        let Some(chunks): Option<Vec<u64>> =
            self.get_decoded(Column::ReporterIndex, &lookup_key(1, hash))?
        else {
            return Ok(None);
        };
        let chunk = chunks
            .first()
            .ok_or(StoreError::Corrupt("reporter header lookup empty"))?;
        let entry: Owned<Header> = self
            .get_decoded(Column::ReporterHeaders, &source_key(*chunk, *hash))?
            .ok_or(StoreError::Corrupt("reporter header lookup dangling"))?;
        if entry.value.hash() != *hash {
            return Err(StoreError::Corrupt("reporter header key"));
        }
        Ok(Some(entry.value))
    }

    /// Saved signed headers for restoring objective proposer and VRF detection.
    pub fn reporter_headers_for_chunk(
        &self,
        chunk: u64,
    ) -> Result<Vec<Header>, StoreError<DB::Error>> {
        self.db
            .iter_prefix(Column::ReporterHeaders, &chunk.to_be_bytes())
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(_, bytes)| {
                let entry: Owned<Header> = borsh::from_slice(&bytes)?;
                Ok(entry.value)
            })
            .collect()
    }

    pub(super) fn reporter_source(
        &self,
        id: &Hash,
    ) -> Result<Option<(u64, SignedArtifact)>, StoreError<DB::Error>> {
        let Some(chunk): Option<u64> =
            self.get_decoded(Column::ReporterIndex, &lookup_key(0, id))?
        else {
            return Ok(None);
        };
        let entry: Owned<SignedArtifact> = self
            .get_decoded(Column::ReporterSources, &source_key(chunk, *id))?
            .ok_or(StoreError::Corrupt("reporter source lookup dangling"))?;
        if entry.value.id() != *id {
            return Err(StoreError::Corrupt("reporter source id"));
        }
        Ok(Some((chunk, entry.value)))
    }

    pub(super) fn validate_reporter_history(&self) -> Result<(), StoreError<DB::Error>> {
        for (key, _) in self
            .db
            .iter_column(Column::ReporterHistory)
            .map_err(StoreError::Database)?
        {
            let chunk = super::retention::decode_count(&key)?;
            self.reporter_opening(chunk)?
                .ok_or(StoreError::Corrupt("reporter context missing"))?;
        }
        for (key, bytes) in self
            .db
            .iter_column(Column::ReporterIndex)
            .map_err(StoreError::Database)?
        {
            let Some(tag) = key.first() else {
                return Err(StoreError::Corrupt("reporter index empty key"));
            };
            match tag {
                0 => {
                    let hash: Hash = key
                        .get(1..)
                        .and_then(|hash| hash.try_into().ok())
                        .ok_or(StoreError::Corrupt("reporter source lookup key"))?;
                    let chunk: u64 = borsh::from_slice(&bytes)?;
                    let (source, _) = self
                        .reporter_source(&hash)?
                        .ok_or(StoreError::Corrupt("reporter source lookup unavailable"))?;
                    if source != chunk {
                        return Err(StoreError::Corrupt("reporter source lookup count"));
                    }
                }
                1 => {
                    let hash: Hash = key
                        .get(1..)
                        .and_then(|hash| hash.try_into().ok())
                        .ok_or(StoreError::Corrupt("reporter header lookup key"))?;
                    let chunks: Vec<u64> = borsh::from_slice(&bytes)?;
                    for chunk in chunks {
                        let header: Owned<Header> = self
                            .get_decoded(Column::ReporterHeaders, &source_key(chunk, hash))?
                            .ok_or(StoreError::Corrupt("reporter header lookup dangling"))?;
                        if header.value.hash() != hash {
                            return Err(StoreError::Corrupt("reporter header lookup hash"));
                        }
                    }
                    self.reporter_header(&hash)?
                        .ok_or(StoreError::Corrupt("reporter header lookup unavailable"))?;
                }
                2 => {
                    let chunk = key
                        .get(1..9)
                        .and_then(|c| c.try_into().ok())
                        .map(u64::from_be_bytes)
                        .ok_or(StoreError::Corrupt("reporter inventory chunk key"))?;
                    let hash: Hash = key
                        .get(9..)
                        .and_then(|h| h.try_into().ok())
                        .ok_or(StoreError::Corrupt("reporter inventory hash"))?;
                    if self.get_decoded::<u64>(Column::ReporterIndex, &lookup_key(0, &hash))?
                        != Some(chunk)
                    {
                        return Err(StoreError::Corrupt("reporter inventory lookup mismatch"));
                    }
                }
                3 => {
                    let chunk = key
                        .get(1..)
                        .ok_or(StoreError::Corrupt("reporter chunk lookup key"))
                        .and_then(super::retention::decode_count)?;
                    self.reporter_opening(chunk)?
                        .ok_or(StoreError::Corrupt("reporter chunk lookup unavailable"))?;
                }
                _ => return Err(StoreError::Corrupt("reporter index kind")),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProposerKey;
    use neutrino_consensus_types::{
        BlockProof, BlockProofPublicInputs, FinalityVoteData, FinalityVotePhase,
    };
    use neutrino_primitives::ConsensusDomain;
    use neutrino_storage::MemoryDatabase;

    #[test]
    fn unobserved_multiblock_finalization_preserves_proposer_and_shared_parent_owners() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        store
            .set_retention_policy(RetentionPolicy::Reporter)
            .unwrap();
        let mut record = super::super::history::tests::record(0);
        record.validators = [1u8, 2]
            .into_iter()
            .map(|tag| Validator {
                pubkey: [tag; 48],
                withdrawal_credentials: [tag; 32],
                effective_stake: 100,
                slashed: false,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                last_active_chunk: 0,
            })
            .collect();
        let identities: Vec<_> = record
            .validators
            .iter()
            .map(|v| (v.pubkey, v.withdrawal_credentials))
            .collect();
        store.set_reporter_eligible(&identities).unwrap();
        let first = crate::test_db::header(1, 1, [0; 32], [1; 32]);
        let mut second = crate::test_db::header(2, 2, first.hash(), [2; 32]);
        second.proposer_index = 1;
        store.put_header(&first).unwrap();
        store.put_header(&second).unwrap();
        let proof = BlockProof {
            height: 2,
            block_hash: second.hash(),
            public_inputs: BlockProofPublicInputs {
                chain_id: 7,
                height: 2,
                parent_block_hash: first.hash(),
                block_hash: second.hash(),
                state_root_before: first.state_root,
                state_root_after: second.state_root,
                transactions_root: [0; 32],
                receipt_root: [0; 32],
                da_root: [0; 32],
                vm_code_hash: [0; 32],
                block_program: [0; 8],
                gas_used: 0,
                gas_limit: 1_000_000,
                proposer_address: [2; 32],
                runtime_extra: [0; 32],
            },
            proof_bytes: vec![1],
        };
        store.put_block_proof(&second.hash(), &proof).unwrap();
        let key = ProposerKey::from_ikm(&[2; 32], 1).unwrap();
        record.finality.precommit_attestations = vec![key.attest_vote(
            ConsensusDomain {
                chain_id: 7,
                chain_spec_hash: [9; 32],
            },
            FinalityVoteData {
                chunk_id: 0,
                round: 0,
                phase: FinalityVotePhase::Precommit,
                chunk_hash: record.chunk.hash(),
            },
            vec![SignedArtifact::BlockProof(proof).id()],
            None,
        )];
        let boundary = super::super::history::tests::range_artifact(0, 1)
            .statement
            .start;
        let mut batch = Batch::new();
        store.append_history_batch(&mut batch, &record).unwrap();
        store
            .retain_reporter_finalization_batch(
                &mut batch,
                &record,
                &boundary,
                [first.clone(), second.clone()].into_iter(),
            )
            .unwrap();
        store.db_mut().write_batch_durable(batch).unwrap();
        let retained = store.reporter_storage_stats().unwrap();
        assert_eq!(retained.headers.records, 2);
        assert_eq!(retained.paths.records, retained.history.records);
        assert!(retained.paths.bytes > 0);
        assert!(retained.contexts.bytes > 0);
        assert!(retained.signatures.records >= 2);
        assert_eq!(retained.signatures.bytes, retained.signatures.records * 96);
        // The second proof depends on the first header. Releasing that acceptor
        // must retain the first header's independent, still-bonded proposer.
        store.set_reporter_eligible(&identities[..1]).unwrap();
        assert_eq!(store.reporter_header(&first.hash()).unwrap(), Some(first));
        assert!(store.reporter_header(&second.hash()).unwrap().is_none());
        let cleaned = store.reporter_storage_stats().unwrap();
        assert_eq!(cleaned.headers.records, 1);
        assert!(cleaned.cleaned_records > 0);
        assert!(cleaned.cleaned_bytes > 0);
        store.validate_reporter_history().unwrap();
    }

    #[test]
    fn historical_withdrawal_addresses_survive_reseating_and_single_account_eligibility() {
        let mut store = ChainStore::new(MemoryDatabase::new());
        store
            .set_retention_policy(RetentionPolicy::Reporter)
            .unwrap();
        let key = [9; 48];
        let original = [10; 32];
        let replacement = [20; 32];
        store.set_reporter_eligible(&[(key, original)]).unwrap();
        for (id, address) in [(0, original), (1, replacement)] {
            let mut record = super::super::history::tests::record(id);
            record.validators = vec![Validator {
                pubkey: key,
                withdrawal_credentials: address,
                effective_stake: 100,
                slashed: false,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                last_active_chunk: 0,
            }];
            let mut batch = Batch::new();
            store.append_history_batch(&mut batch, &record).unwrap();
            store.db_mut().write_batch_durable(batch).unwrap();
        }
        // Old-account withdrawal followed by a new seat cannot overwrite the
        // old address: its collateral may become slashable again through Deposit.
        let all = vec![(key, original), (key, replacement)];
        assert_eq!(store.reporter_tracked_validators().unwrap(), all);
        store.set_reporter_eligible(&[(key, replacement)]).unwrap();
        assert_eq!(store.reporter_tracked_validators().unwrap(), all);
        assert!(store.reporter_opening(0).unwrap().is_some());
        let mut restarted = ChainStore::new(store.into_db());
        restarted
            .seed_reporter_tracking(&[(key, replacement), (key, original)])
            .unwrap();
        restarted.set_reporter_eligible(&[(key, original)]).unwrap();
        assert_eq!(restarted.reporter_tracked_validators().unwrap(), all);
        assert_eq!(
            restarted.reporter_opening(0).unwrap().unwrap().path.count,
            2
        );
        restarted
            .set_reporter_eligible(&[(key, replacement), (key, original), (key, replacement)])
            .unwrap();
        assert_eq!(restarted.reporter_tracked_validators().unwrap(), all);
        restarted.set_reporter_eligible(&[]).unwrap();
        assert_eq!(
            restarted.reporter_tracked_validators().unwrap(),
            [] as [crate::ReporterIdentity; 0]
        );
        assert!(!restarted.reporter_has_history().unwrap());
    }
}
