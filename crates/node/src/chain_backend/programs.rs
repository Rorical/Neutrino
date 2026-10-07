//! Installing on-chain program artifacts into the executor and proof backend.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, atomic::Ordering};

use neutrino_consensus_types::{
    ProgramPiece,
    history_proof::{ProgramArtifacts, ProgramSet, VkDigest},
};
use neutrino_primitives::Hash;
use neutrino_proof_system::ProofSystem;
use neutrino_storage::Database;
use tracing::{info, warn};

use super::ChainBackend;
use crate::programs::ArtifactKind;

/// The identity governance declared for a named artifact. An installed
/// artifact must produce exactly this identity or it is discarded.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum ExpectedIdentity {
    /// Runtime WASM whose BLAKE3 hash is the program set's runtime code hash.
    Runtime(Hash),
    /// Guest ELF whose SP1 verifying key has this digest.
    Guest(VkDigest),
}

fn expectations(
    programs: &ProgramSet,
    artifacts: &ProgramArtifacts,
) -> impl Iterator<Item = (Hash, ExpectedIdentity)> {
    [
        (
            artifacts.runtime,
            ExpectedIdentity::Runtime(programs.runtime_code_hash),
        ),
        (
            artifacts.fact,
            ExpectedIdentity::Guest(programs.execution.fact),
        ),
        (
            artifacts.evidence,
            ExpectedIdentity::Guest(programs.execution.evidence),
        ),
        (
            artifacts.block,
            ExpectedIdentity::Guest(programs.execution.block),
        ),
    ]
    .into_iter()
    .filter(|(hash, _)| *hash != [0; 32])
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Feed an imported block's program lane to the store and install
    /// anything it completed. Only artifacts governance names are assembled.
    pub(super) fn absorb_programs(&self, pieces: &[ProgramPiece]) {
        if pieces.is_empty() {
            return;
        }
        let wanted = self.wanted_artifacts();
        let names: BTreeSet<Hash> = wanted.keys().copied().collect();
        if !self.program_store().absorb(pieces, &names).is_empty() {
            self.install_wanted(&wanted);
        }
    }

    /// Artifacts the runtime's open proposal or enacted schedule names, with
    /// the identity each must produce, read through the installed runtime
    /// against the head state.
    pub(super) fn wanted_artifacts(&self) -> BTreeMap<Hash, ExpectedIdentity> {
        let Some(executor) = self.block_executor_snapshot() else {
            return BTreeMap::new();
        };
        let Some((state, runtime)) = self.with_engine(|engine| {
            engine
                .runtime_code_hash_for(engine.head_height())
                .ok()
                .map(|runtime| (engine.state().clone(), runtime))
        }) else {
            return BTreeMap::new();
        };
        let request = neutrino_runtime_abi::QueryRequest {
            method: neutrino_default_runtime_core::QUERY_METHOD_UPGRADE_STATUS.to_owned(),
            args: Vec::new(),
        };
        let Ok(response) = executor.query(&request, runtime, &state) else {
            return BTreeMap::new();
        };
        let Ok(status) =
            borsh::from_slice::<neutrino_default_runtime_core::UpgradeStatus>(&response.payload)
        else {
            return BTreeMap::new();
        };
        let mut wanted = BTreeMap::new();
        if let Some(proposal) = &status.proposal
            && let neutrino_default_runtime_core::governance::ProposalAction::Programs {
                programs,
                artifacts,
                ..
            } = &proposal.action
        {
            wanted.extend(expectations(programs, artifacts));
        }
        if let Some(scheduled) = &status.scheduled {
            wanted.extend(expectations(&scheduled.programs, &scheduled.artifacts));
        }
        *self
            .wanted_programs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = wanted.keys().copied().collect();
        wanted
    }

    /// Install complete artifacts that governance names. Cheap when nothing
    /// is complete; called on import completions and before production.
    pub(crate) fn sync_programs(&self) {
        if self.program_store().complete().is_empty() {
            return;
        }
        let wanted = self.wanted_artifacts();
        self.install_wanted(&wanted);
    }

    fn install_wanted(&self, wanted: &BTreeMap<Hash, ExpectedIdentity>) {
        for (hash, bytes) in self.program_store().complete() {
            if let Some(expected) = wanted.get(&hash) {
                self.install_artifact(hash, bytes, *expected);
            }
        }
    }

    /// Identities the chain currently names: the program set in force at the
    /// chunk being built plus everything governance has proposed or
    /// scheduled. Only these may be installed from disk.
    fn named_identities(&self) -> BTreeSet<ExpectedIdentity> {
        let mut named: BTreeSet<ExpectedIdentity> = self.wanted_artifacts().into_values().collect();
        if let Ok(programs) =
            self.with_engine(|engine| engine.programs_at_chunk(engine.finalized_next_chunk_id()))
        {
            named.insert(ExpectedIdentity::Runtime(programs.runtime_code_hash));
            for digest in [
                programs.execution.fact,
                programs.execution.evidence,
                programs.execution.block,
            ] {
                named.insert(ExpectedIdentity::Guest(digest));
            }
        }
        named
    }

    /// Reinstall artifacts persisted by an earlier session, but only those
    /// whose re-derived identity the chain still names. The directory is
    /// local trusted storage, yet nothing in it is installed on faith: a
    /// file that no longer matches a named identity is deleted.
    pub fn restore_programs(&self) {
        let named = self.named_identities();
        let store = self.program_store();
        for (hash, bytes) in store.persisted() {
            match ArtifactKind::of(&bytes) {
                ArtifactKind::Wasm => {
                    let identity =
                        ExpectedIdentity::Runtime(neutrino_primitives::blake3_256(&bytes));
                    if named.contains(&identity) {
                        self.install_artifact(hash, Arc::new(bytes), identity);
                    } else {
                        warn!(hash = %hex(&hash), "persisted runtime is no longer named; removed");
                        store.forget_persisted(&hash);
                    }
                }
                ArtifactKind::Elf => self.restore_persisted_guest(hash, Arc::new(bytes), &named),
                ArtifactKind::Unknown => store.forget_persisted(&hash),
            }
        }
    }

    fn restore_persisted_guest(
        &self,
        hash: Hash,
        bytes: Arc<Vec<u8>>,
        named: &BTreeSet<ExpectedIdentity>,
    ) {
        let prover = Arc::clone(&self.proof_system);
        let store = self.program_store();
        let named = named.clone();
        let install = move || match prover.install_guest(bytes.to_vec()) {
            Ok(digest) if named.contains(&ExpectedIdentity::Guest(digest)) => {
                info!(hash = %hex(&hash), ?digest, "guest restored");
            }
            Ok(digest) => {
                warn!(hash = %hex(&hash), ?digest, "persisted guest is no longer named; removed");
                store.forget_persisted(&hash);
            }
            Err(error) => {
                warn!(hash = %hex(&hash), %error, "persisted guest rejected; removed");
                store.forget_persisted(&hash);
            }
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::spawn_blocking(install);
        } else {
            install();
        }
    }

    fn install_artifact(&self, hash: Hash, bytes: Arc<Vec<u8>>, expected: ExpectedIdentity) {
        let store = self.program_store();
        match (ArtifactKind::of(&bytes), expected) {
            (ArtifactKind::Wasm, ExpectedIdentity::Runtime(code_hash)) => {
                // The runtime hash is checked before any bytes are compiled.
                if neutrino_primitives::blake3_256(&bytes) != code_hash {
                    warn!(hash = %hex(&hash), "runtime artifact does not match the declared code hash");
                    store.mark_installed(&hash);
                    return;
                }
                let Some(executor) = self.block_executor_snapshot() else {
                    return;
                };
                match executor.install_runtime(&bytes) {
                    Ok(_) => {
                        info!(hash = %hex(&hash), code_hash = %hex(&code_hash), "runtime installed");
                        store.persist(&hash, &bytes);
                    }
                    Err(error) => warn!(hash = %hex(&hash), %error, "runtime artifact rejected"),
                }
                store.mark_installed(&hash);
            }
            (ArtifactKind::Elf, ExpectedIdentity::Guest(digest)) => {
                if self.installing_programs.swap(true, Ordering::AcqRel) {
                    return;
                }
                let prover = Arc::clone(&self.proof_system);
                let flag = Arc::clone(&self.installing_programs);
                let install = move || {
                    let result = prover.install_guest(bytes.to_vec());
                    flag.store(false, Ordering::Release);
                    match result {
                        Ok(derived) if derived == digest => {
                            info!(hash = %hex(&hash), ?digest, "guest installed");
                            store.persist(&hash, &bytes);
                        }
                        Ok(derived) => warn!(
                            hash = %hex(&hash), ?digest, ?derived,
                            "guest artifact derives a different verifying key than governance declared"
                        ),
                        Err(error) => warn!(hash = %hex(&hash), %error, "guest artifact rejected"),
                    }
                    store.mark_installed(&hash);
                };
                // SP1 setup is slow; keep it off async workers when possible.
                if tokio::runtime::Handle::try_current().is_ok() {
                    tokio::task::spawn_blocking(install);
                } else {
                    install();
                }
            }
            (kind, expected) => {
                warn!(hash = %hex(&hash), ?kind, ?expected, "artifact kind does not match its declared identity");
                store.mark_installed(&hash);
            }
        }
    }

    /// Operator-facing program state for `programs_status`.
    pub fn programs_status(&self) -> neutrino_rpc::ProgramsStatusJson {
        use neutrino_rpc::{
            ArtifactProgressJson, HashHex, InstalledGuestJson, PersistedArtifactJson,
        };
        let status = self.program_store().status();
        let progress = |(hash, bytes, total): (Hash, u32, u32)| ArtifactProgressJson {
            content_hash: HashHex(hash),
            bytes,
            total,
        };
        neutrino_rpc::ProgramsStatusJson {
            installed_guests: self
                .proof_system
                .installed_guests()
                .into_iter()
                .map(|(digest, elf_hash)| InstalledGuestJson {
                    digest,
                    elf_hash: HashHex(elf_hash),
                })
                .collect(),
            runtimes: self
                .block_executor_snapshot()
                .map(|executor| executor.installed_runtimes())
                .unwrap_or_default()
                .into_iter()
                .map(HashHex)
                .collect(),
            wanted: self
                .wanted_programs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .copied()
                .map(HashHex)
                .collect(),
            assembling: status.assembling.into_iter().map(progress).collect(),
            complete: status.complete.into_iter().map(HashHex).collect(),
            persisted: status
                .persisted
                .into_iter()
                .map(|(hash, kind)| PersistedArtifactJson {
                    content_hash: HashHex(hash),
                    kind: match kind {
                        ArtifactKind::Wasm => "wasm",
                        ArtifactKind::Elf => "elf",
                        ArtifactKind::Unknown => "unknown",
                    }
                    .to_owned(),
                })
                .collect(),
            publishing: status.publishing.map(progress),
            publish_queue: status.publish_queue,
        }
    }
}

fn hex(hash: &Hash) -> String {
    crate::programs::hex_hash(hash)
}
