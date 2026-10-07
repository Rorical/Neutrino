//! Guest program registry (design 24, phase 3).
//!
//! Every SP1 Guest this backend can prove or fully verify under is held
//! here, keyed by verifying-key digest. The five embedded Guests are
//! installed at construction; Guests distributed on chain are installed
//! later from their ELF bytes, which runs SP1 setup once and records the
//! derived digest. Proving paths resolve keys by the digests named in
//! boundaries and anchors, never by assuming the embedded set.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use neutrino_consensus_types::history_proof::{GuestPrograms, VkDigest};
use neutrino_primitives::Hash;
use neutrino_proof_system::ProofError;
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1VerifyingKey, blocking::Prover};

use crate::{ProgramProver, Sp1HostError};

/// Keys of one installed Guest.
pub struct ProgramKeys<P: Prover> {
    /// Proving key; for CUDA this owns a server session.
    pub pk: P::ProvingKey,
    /// Verifying key.
    pub vk: SP1VerifyingKey,
    /// BLAKE3 hash of the ELF bytes.
    pub elf_hash: Hash,
}

/// Installed Guests by digest and by ELF hash.
pub struct Registry<P: Prover> {
    by_digest: HashMap<VkDigest, Arc<ProgramKeys<P>>>,
    by_elf: HashMap<Hash, VkDigest>,
}

impl<P: Prover> Default for Registry<P> {
    fn default() -> Self {
        Self {
            by_digest: HashMap::new(),
            by_elf: HashMap::new(),
        }
    }
}

impl<P: Prover> Registry<P> {
    pub(crate) fn get(&self, digest: &VkDigest) -> Option<Arc<ProgramKeys<P>>> {
        self.by_digest.get(digest).cloned()
    }

    pub(crate) fn installed(&self) -> Vec<(VkDigest, Hash)> {
        let mut all: Vec<_> = self
            .by_digest
            .iter()
            .map(|(digest, keys)| (*digest, keys.elf_hash))
            .collect();
        all.sort_unstable();
        all
    }
}

impl<P: ProgramProver> Registry<P> {
    /// Set up `elf` if its hash is new and return the Guest's digest.
    pub(crate) fn install(&mut self, prover: &P, elf: Elf) -> Result<VkDigest, Sp1HostError> {
        let elf_hash = neutrino_primitives::blake3_256(&elf);
        if let Some(digest) = self.by_elf.get(&elf_hash) {
            return Ok(*digest);
        }
        let pk = prover.setup_program(elf)?;
        let vk = pk.verifying_key().clone();
        let digest = vk.hash_u32();
        self.by_digest
            .entry(digest)
            .or_insert_with(|| Arc::new(ProgramKeys { pk, vk, elf_hash }));
        self.by_elf.insert(elf_hash, digest);
        Ok(digest)
    }
}

/// Shared handle to the registry.
pub type SharedRegistry<P> = RwLock<Registry<P>>;

/// Resolve keys for every digest of a Guest set.
pub(crate) fn can_prove<P: Prover>(registry: &SharedRegistry<P>, guests: &GuestPrograms) -> bool {
    let registry = registry
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    [
        guests.execution.fact,
        guests.execution.evidence,
        guests.execution.block,
        guests.consensus.chunk,
        guests.consensus.checkpoint,
    ]
    .iter()
    .all(|digest| registry.get(digest).is_some())
}

/// Keys for `digest`, or `Unsupported` when the Guest is not installed.
pub(crate) fn keys<P: Prover>(
    registry: &SharedRegistry<P>,
    digest: &VkDigest,
) -> Result<Arc<ProgramKeys<P>>, ProofError> {
    registry
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(digest)
        .ok_or(ProofError::Unsupported)
}
