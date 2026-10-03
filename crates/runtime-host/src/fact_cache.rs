//! Bounded verified fact receipts, reusable across offences and process restarts.

// Keep cache internals explicitly scoped to the host crate.
#![allow(clippy::redundant_pub_crate)]

use neutrino_primitives::Hash;
use neutrino_prover_chunk::{facts::FactStatement, receipt_codec};
use sp1_sdk::{HashableKey, SP1ProofWithPublicValues, SP1VerifyingKey};
use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::Arc,
};

static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(super) struct FactReceipt {
    pub(super) bundle: SP1ProofWithPublicValues,
    pub(super) statement: FactStatement,
    id: Hash,
    size: usize,
}

pub(super) struct FactCache {
    entries: VecDeque<Arc<FactReceipt>>,
    bytes: usize,
    directory: PathBuf,
}

pub(super) fn verify_receipt<T: borsh::BorshSerialize>(
    bundle: &SP1ProofWithPublicValues,
    statement: &T,
    key: &SP1VerifyingKey,
) -> Result<(), neutrino_proof_system::ProofError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        neutrino_prover_chunk::proof_verification::verify_typed_receipt(
            &bundle.proof,
            bundle.public_values.as_slice(),
            &bundle.sp1_version,
            statement,
            &key.hash_u32(),
        )
    }))
    .map_err(|_| neutrino_proof_system::ProofError::BackendRejected)?
    .map_err(|_| neutrino_proof_system::ProofError::BackendRejected)
}

impl FactReceipt {
    pub(super) fn new(
        bundle: SP1ProofWithPublicValues,
        statement: FactStatement,
        key: &SP1VerifyingKey,
    ) -> Result<Self, neutrino_proof_system::ProofError> {
        verify_receipt(&bundle, &statement, key)?;
        if statement.facts.is_empty()
            || statement.facts.len() > neutrino_prover_chunk::facts::MAX_FACTS
        {
            return Err(neutrino_proof_system::ProofError::MalformedProof);
        }
        let size = receipt_codec::encode(&bundle)
            .map_err(|_| neutrino_proof_system::ProofError::MalformedProof)?
            .len();
        if size > neutrino_consensus_types::evidence::MAX_EVIDENCE_PROOF_BYTES {
            return Err(neutrino_proof_system::ProofError::MalformedProof);
        }
        let id = neutrino_prover_chunk::execution::commitment(&statement);
        Ok(Self {
            bundle,
            statement,
            id,
            size,
        })
    }
}

impl FactCache {
    pub(super) fn load(key: &SP1VerifyingKey) -> Self {
        let directory = crate::cache_dir().join(format!(
            "facts-{}-{}",
            sp1_sdk::SP1_CIRCUIT_VERSION,
            key.bytes32()
        ));
        let mut cache = Self {
            entries: VecDeque::new(),
            bytes: 0,
            directory,
        };
        let Ok(files) = std::fs::read_dir(&cache.directory) else {
            return cache;
        };
        let mut files: Vec<_> = files
            .flatten()
            .filter(|file| file.path().extension().is_some_and(|ext| ext == "bin"))
            .filter_map(|file| Some((file.metadata().ok()?.modified().ok()?, file.path())))
            .collect();
        files.sort_unstable();
        // Prune before loading so a restart never admits an unbounded directory.
        let keep_from = files.len().saturating_sub(256);
        for (_, path) in files.drain(..keep_from) {
            let _ = std::fs::remove_file(path);
        }
        for (_, path) in files {
            let receipt = (|| {
                if std::fs::metadata(&path).ok()?.len() > 2 * 1024 * 1024 {
                    return None;
                }
                let bytes = std::fs::read(&path).ok()?;
                let bundle =
                    receipt_codec::decode::<SP1ProofWithPublicValues, { 2 * 1024 * 1024 }>(&bytes)
                        .ok()?;
                let statement = borsh::from_slice(bundle.public_values.as_slice()).ok()?;
                // A persisted receipt never inherits an in-memory verified flag.
                FactReceipt::new(bundle, statement, key).ok()
            })();
            if let Some(receipt) = receipt
                && path == cache.path(receipt.id)
            {
                cache.retain(Arc::new(receipt));
            } else {
                let _ = std::fs::remove_file(path);
            }
        }
        cache
    }

    pub(super) fn verified(&self) -> BTreeMap<Hash, bool> {
        self.entries
            .iter()
            .flat_map(|receipt| {
                receipt
                    .statement
                    .facts
                    .iter()
                    .map(|fact| (fact.id, fact.valid))
            })
            .collect()
    }

    pub(super) fn covering(
        &self,
        ids: &mut std::collections::BTreeSet<Hash>,
    ) -> Vec<Arc<FactReceipt>> {
        let mut selected = Vec::new();
        for receipt in self.entries.iter().rev() {
            if receipt
                .statement
                .facts
                .iter()
                .any(|fact| ids.contains(&fact.id))
            {
                for fact in &receipt.statement.facts {
                    ids.remove(&fact.id);
                }
                selected.push(Arc::clone(receipt));
            }
        }
        selected
    }

    pub(super) fn insert(&mut self, receipt: Arc<FactReceipt>) {
        if self.entries.iter().any(|entry| entry.id == receipt.id) {
            return;
        }
        // Failure to write the optional cache does not invalidate a verified proof.
        if std::fs::create_dir_all(&self.directory).is_ok()
            && let Ok(bytes) = receipt_codec::encode(&receipt.bundle)
        {
            let path = self.path(receipt.id);
            let serial = SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let tmp = path.with_extension(format!("{}-{serial}.tmp", std::process::id()));
            if std::fs::write(&tmp, bytes).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
            let _ = std::fs::remove_file(tmp);
        }
        self.retain(receipt);
    }

    fn path(&self, id: Hash) -> PathBuf {
        self.directory
            .join(format!("{}.bin", blake3::Hash::from(id).to_hex()))
    }

    fn retain(&mut self, receipt: Arc<FactReceipt>) {
        self.bytes += receipt.size;
        self.entries.push_back(receipt);
        while self.entries.len() > 256 || self.bytes > 32 * 1024 * 1024 {
            let old = self.entries.pop_front().expect("over budget");
            self.bytes -= old.size;
            let _ = std::fs::remove_file(self.path(old.id));
        }
    }
}
