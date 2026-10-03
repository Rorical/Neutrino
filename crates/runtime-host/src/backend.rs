//! Backend-specific program setup. CUDA session keys stay in memory; CPU ROM
//! preprocessing and the expected program identity share the disk VK cache.

use sp1_sdk::{
    Elf,
    blocking::{CpuProver, LightProver, MockProver, Prover},
};

use crate::Sp1HostError;

/// An SP1 prover with reusable, program-bound key setup.
///
/// The returned key must remain valid for this prover's lifetime and bind the
/// supplied ELF. Callers retain it for all subsequent proofs of that program.
pub trait ProgramProver: Prover {
    /// Prepare a program, reusing cached preprocessing where supported.
    ///
    /// # Errors
    /// Returns an SDK error when setup fails or the backend changes program identity.
    fn setup_program(&self, elf: Elf) -> Result<Self::ProvingKey, Sp1HostError>;
}

impl ProgramProver for CpuProver {
    fn setup_program(&self, elf: Elf) -> Result<Self::ProvingKey, Sp1HostError> {
        crate::cached_proving_key(self, elf)
    }
}

impl ProgramProver for MockProver {
    fn setup_program(&self, elf: Elf) -> Result<Self::ProvingKey, Sp1HostError> {
        crate::cached_proving_key(self, elf)
    }
}

impl ProgramProver for LightProver {
    fn setup_program(&self, elf: Elf) -> Result<Self::ProvingKey, Sp1HostError> {
        crate::cached_proving_key(self, elf)
    }
}

/// Check build and platform support without initializing a GPU or downloading
/// the SDK's GPU server. Hardware/driver availability is checked by SDK startup.
///
/// # Errors
/// CUDA requires the `cuda` Cargo feature and Linux x86-64.
pub const fn ensure_cuda_available() -> Result<(), &'static str> {
    if !cfg!(feature = "cuda") {
        return Err("CUDA requires building neutrino-node with --features cuda");
    }
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err("SP1 CUDA requires Linux x86-64 and an NVIDIA GPU; macOS/Metal is unsupported");
    }
    Ok(())
}

/// Start the local SP1 GPU server on one CUDA device. Never falls back to CPU.
///
/// Call inside a multithreaded Tokio runtime, keeping the runtime alive until
/// the prover and its session keys are dropped (the SDK schedules their cleanup).
///
/// # Errors
/// Returns a platform, runtime or SDK startup error, including SDK builder panics.
#[cfg(feature = "cuda")]
pub fn cuda_prover(device_id: u32) -> Result<sp1_sdk::blocking::CudaProver, Sp1HostError> {
    ensure_cuda_available().map_err(|error| Sp1HostError::Sdk(error.into()))?;
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| Sp1HostError::Sdk("CUDA requires a multithreaded Tokio runtime".into()))?;
    if runtime.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
        return Err(Sp1HostError::Sdk(
            "CUDA requires a multithreaded Tokio runtime".into(),
        ));
    }
    std::panic::catch_unwind(|| {
        sp1_sdk::blocking::ProverClient::builder()
            .cuda()
            .with_device_id(device_id)
            .build()
    })
    .map_err(|payload| {
        let reason = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("unknown SDK panic");
        Sp1HostError::Sdk(format!("CUDA initialization failed: {reason}"))
    })
}

#[cfg(feature = "cuda")]
impl ProgramProver for sp1_sdk::blocking::CudaProver {
    fn setup_program(&self, elf: Elf) -> Result<Self::ProvingKey, Sp1HostError> {
        use sp1_sdk::{HashableKey, ProvingKey, blocking::ProverClient};

        // The server returns its VK during setup. Authenticate it against the
        // same locally derived program identity used by CPU verification.
        let expected = match crate::load_cached_vk_for(&elf) {
            Some(vk) => vk,
            None => {
                crate::cached_proving_key(&ProverClient::builder().light().build(), elf.clone())?
                    .verifying_key()
                    .clone()
            }
        };
        let key = self.setup(elf).map_err(crate::sdk_err)?;
        if key.verifying_key().hash_u32() != expected.hash_u32() {
            return Err(Sp1HostError::Sdk(
                "CUDA program verifying key mismatch".into(),
            ));
        }
        // A CUDA key owns a server session. It cannot be reconstructed from a
        // disk VK, and must be retained until the last proof request completes.
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_sdk::{HashableKey, ProvingKey, blocking::ProverClient};

    #[test]
    fn cached_program_keys_match_local_verification_for_all_stages() {
        let prover = ProverClient::builder().mock().build();
        let verifier = ProverClient::builder().light().build();
        let mut digests = std::collections::BTreeSet::new();
        for elf in [
            crate::DEFAULT_GUEST_ELF,
            crate::DEFAULT_EVIDENCE_GUEST_ELF,
            crate::DEFAULT_FACT_GUEST_ELF,
            crate::DEFAULT_CONSENSUS_CHUNK_GUEST_ELF,
            crate::DEFAULT_CHECKPOINT_GUEST_ELF,
        ] {
            let key = prover.setup_program(elf.clone()).unwrap();
            let verifier_key = verifier.setup(elf.clone()).unwrap();
            assert_eq!(crate::elf_bytes(key.elf()), crate::elf_bytes(&elf));
            assert_eq!(
                key.verifying_key().hash_u32(),
                verifier_key.verifying_key().hash_u32()
            );
            assert!(
                digests.insert(key.verifying_key().hash_u32()),
                "program identities must be distinct"
            );
        }
    }

    #[cfg(all(
        feature = "cuda",
        not(all(target_os = "linux", target_arch = "x86_64"))
    ))]
    #[test]
    fn cuda_factory_rejects_unsupported_platform_before_sdk_startup() {
        let Err(error) = cuda_prover(0) else {
            panic!("CUDA initialized on unsupported host");
        };
        assert!(error.to_string().contains("Linux x86-64"));
    }

    #[cfg(all(feature = "cuda", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn cuda_factory_requires_runtime_before_sdk_startup() {
        let Err(error) = cuda_prover(0) else {
            panic!("CUDA initialized without Tokio runtime");
        };
        assert!(error.to_string().contains("Tokio runtime"));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let Err(error) = cuda_prover(0) else {
            panic!("CUDA initialized with current-thread runtime");
        };
        assert!(error.to_string().contains("multithreaded Tokio runtime"));
    }
}
