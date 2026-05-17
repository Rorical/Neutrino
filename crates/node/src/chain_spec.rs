//! Serde-friendly chain-spec file loader.
//!
//! The canonical [`neutrino_primitives::ChainSpec`] is borsh-encoded
//! consensus data, not a serde type. For operators we expose a thin
//! TOML/JSON-compatible [`ChainSpecFile`] wrapper that captures the
//! configurable subset and derives every other field deterministically.
//!
//! All nodes participating in a deployment **must** load an identical
//! `chain-spec.toml`; the resulting `ChainSpec::hash()` is what peers
//! compare during handshake.

use std::fs;
use std::path::Path;

use neutrino_primitives::{
    BoundedBytes, CHAIN_SPEC_VERSION, ChainSpec, ConsensusParams, Hash, LightClientParams,
    ProofParams, RuntimeVersion, StateParams, Validator, ZERO_HASH,
};
use serde::Deserialize;
use thiserror::Error;

/// Errors returned by [`ChainSpecFile::load_from_path`] and
/// [`ChainSpecFile::to_chain_spec`].
#[derive(Debug, Error)]
pub enum ChainSpecError {
    /// Reading the file from disk failed.
    #[error("failed to read chain spec `{path}`: {source}")]
    Io {
        /// Path the loader attempted.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Parsing the TOML payload failed.
    #[error("failed to parse chain spec TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// One of the hex-encoded byte fields was malformed.
    #[error("invalid hex in field `{field}`: {reason}")]
    Hex {
        /// Field name in the chain spec file.
        field: String,
        /// Operator-readable reason.
        reason: String,
    },
    /// The chain name was longer than [`neutrino_primitives::MAX_CHAIN_NAME_BYTES`].
    #[error("chain name is too long: {len} bytes")]
    NameTooLong {
        /// Observed length in bytes.
        len: usize,
    },
    /// Optional metadata exceeded [`neutrino_primitives::MAX_METADATA_BYTES`].
    #[error("metadata is too long: {len} bytes")]
    MetadataTooLong {
        /// Observed length in bytes.
        len: usize,
    },
    /// Provided fields produced an invalid canonical [`ChainSpec`].
    #[error("chain spec validation failed: {0}")]
    Validation(String),
}

/// One validator entry in the chain-spec file.
///
/// `pubkey_hex` must be exactly 96 hex characters (48 bytes).
/// `withdrawal_credentials_hex` is optional and defaults to all-zero.
#[derive(Clone, Debug, Deserialize)]
pub struct ValidatorEntry {
    /// Hex-encoded BLS public key (48 bytes, 96 hex chars).
    pub pubkey_hex: String,
    /// Optional hex-encoded withdrawal credentials (32 bytes). Defaults
    /// to all-zero.
    #[serde(default)]
    pub withdrawal_credentials_hex: Option<String>,
    /// Effective stake at genesis, in the runtime's base unit.
    pub effective_stake: u64,
}

/// TOML-deserializable chain spec file.
///
/// Fields not exposed here fall back to canonical [`ConsensusParams`],
/// [`ProofParams`], [`StateParams`], and [`LightClientParams`] defaults.
#[derive(Clone, Debug, Deserialize)]
pub struct ChainSpecFile {
    /// Human-readable chain name (must be ≤ 64 bytes).
    pub name: String,
    /// Chain identifier; must be non-zero.
    pub chain_id: u64,
    /// Genesis timestamp in seconds since UNIX epoch.
    pub genesis_time: u64,
    /// Block gas limit applied to every block at genesis.
    pub genesis_gas_limit: u64,
    /// Optional hex-encoded genesis seed (32 bytes). Defaults to all-zero.
    #[serde(default)]
    pub genesis_seed_hex: Option<String>,
    /// Optional hex-encoded genesis state root (32 bytes). Defaults to
    /// all-zero.
    #[serde(default)]
    pub genesis_state_root_hex: Option<String>,
    /// Optional hex-encoded genesis block hash (32 bytes). Defaults to
    /// all-zero.
    #[serde(default)]
    pub genesis_block_hash_hex: Option<String>,
    /// Optional hex-encoded runtime code hash (32 bytes). Defaults to
    /// all-zero — sufficient for M6 stage where the mock proof system is
    /// in use.
    #[serde(default)]
    pub runtime_code_hash_hex: Option<String>,
    /// Optional override for [`ConsensusParams::slot_duration_secs`].
    ///
    /// Used by integration tests that need shorter slots to exercise
    /// chunk-close and checkpointing within their wall-clock budget.
    #[serde(default)]
    pub slot_duration_secs: Option<u64>,
    /// Optional override for [`ConsensusParams::chunk_size`].
    ///
    /// When set, also overrides
    /// [`ProofParams::slot_budget_per_chunk`] to the same value so the
    /// canonical chain-spec validator keeps the two in lock-step.
    #[serde(default)]
    pub chunk_size: Option<u64>,
    /// Optional free-form metadata (≤ 256 bytes).
    #[serde(default)]
    pub metadata: Option<String>,
    /// Initial validator set (must be non-empty).
    pub validators: Vec<ValidatorEntry>,
}

impl ChainSpecFile {
    /// Load and parse the chain spec at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainSpecError::Io`] or [`ChainSpecError::Toml`] on
    /// read / parse failures.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ChainSpecError> {
        let path_ref = path.as_ref();
        let raw = fs::read_to_string(path_ref).map_err(|source| ChainSpecError::Io {
            path: path_ref.display().to_string(),
            source,
        })?;
        Self::from_toml_str(&raw)
    }

    /// Parse a chain spec from an in-memory TOML string.
    ///
    /// # Errors
    ///
    /// Returns [`ChainSpecError::Toml`] when the input is invalid TOML.
    pub fn from_toml_str(raw: &str) -> Result<Self, ChainSpecError> {
        toml::from_str(raw).map_err(ChainSpecError::Toml)
    }

    /// Materialise a canonical [`ChainSpec`] from this file.
    ///
    /// # Errors
    ///
    /// Returns [`ChainSpecError`] when any hex field is invalid or the
    /// resulting spec fails canonical validation.
    pub fn to_chain_spec(&self) -> Result<ChainSpec, ChainSpecError> {
        let name_bytes = self.name.as_bytes().to_vec();
        let name = BoundedBytes::new(name_bytes)
            .map_err(|err| ChainSpecError::NameTooLong { len: err.actual })?;

        let metadata_bytes = self
            .metadata
            .as_deref()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let metadata = BoundedBytes::new(metadata_bytes)
            .map_err(|err| ChainSpecError::MetadataTooLong { len: err.actual })?;

        let genesis_seed: Hash =
            decode_hash_or_zero(self.genesis_seed_hex.as_deref(), "genesis_seed_hex")?;
        let genesis_state_root: Hash = decode_hash_or_zero(
            self.genesis_state_root_hex.as_deref(),
            "genesis_state_root_hex",
        )?;
        let genesis_block_hash: Hash = decode_hash_or_zero(
            self.genesis_block_hash_hex.as_deref(),
            "genesis_block_hash_hex",
        )?;
        let runtime_code_hash: Hash = decode_hash_or_zero(
            self.runtime_code_hash_hex.as_deref(),
            "runtime_code_hash_hex",
        )?;

        let mut validators: Vec<Validator> = Vec::with_capacity(self.validators.len());
        for (idx, entry) in self.validators.iter().enumerate() {
            let pubkey = decode_bls_pubkey(&entry.pubkey_hex, idx)?;
            let withdrawal_credentials: Hash = decode_hash_or_zero(
                entry.withdrawal_credentials_hex.as_deref(),
                "validators[].withdrawal_credentials_hex",
            )?;
            validators.push(Validator {
                pubkey,
                withdrawal_credentials,
                effective_stake: entry.effective_stake,
                slashed: false,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                last_active_chunk: 0,
            });
        }

        let mut proof_params = ProofParams::default();
        let mut consensus = ConsensusParams::default();
        let state = StateParams::default();
        let light_client = LightClientParams::default();
        let runtime_version = RuntimeVersion::default();

        if let Some(slot_duration_secs) = self.slot_duration_secs {
            consensus.slot_duration_secs = slot_duration_secs;
        }
        if let Some(chunk_size) = self.chunk_size {
            consensus.chunk_size = chunk_size;
            proof_params.slot_budget_per_chunk = chunk_size;
        }

        let genesis_validator_set_root =
            neutrino_consensus_engine::validator_set::validator_set_root(&validators);

        let canonical_genesis_checkpoint = neutrino_primitives::Checkpoint {
            chain_id: self.chain_id,
            index: 0,
            start_height: 0,
            end_height: 0,
            start_block_hash: ZERO_HASH,
            end_block_hash: genesis_block_hash,
            start_state_root: ZERO_HASH,
            end_state_root: genesis_state_root,
            end_validator_set_root: genesis_validator_set_root,
            history_root: ZERO_HASH,
            proof_system_version: proof_params.proof_system_version,
        };

        let spec = ChainSpec {
            spec_version: CHAIN_SPEC_VERSION,
            name,
            chain_id: self.chain_id,
            genesis_time: self.genesis_time,
            genesis_gas_limit: self.genesis_gas_limit,
            runtime_version,
            runtime_code_hash,
            genesis_seed,
            genesis_state_root,
            genesis_block_hash,
            genesis_validator_set_root,
            genesis_checkpoint: canonical_genesis_checkpoint,
            consensus,
            proof: proof_params,
            state,
            light_client,
            initial_validators: validators,
            metadata,
        };

        spec.validate()
            .map_err(|err| ChainSpecError::Validation(err.to_string()))?;
        Ok(spec)
    }
}

// --- helpers --------------------------------------------------------------

fn decode_hash_or_zero(hex: Option<&str>, field: &str) -> Result<Hash, ChainSpecError> {
    let Some(hex) = hex else {
        return Ok(ZERO_HASH);
    };
    let bytes = decode_hex_exact::<32>(hex, field)?;
    Ok(bytes)
}

fn decode_bls_pubkey(hex: &str, validator_index: usize) -> Result<[u8; 48], ChainSpecError> {
    let field = format!("validators[{validator_index}].pubkey_hex");
    decode_hex_exact::<48>(hex, &field)
}

pub(crate) fn decode_hex_exact<const N: usize>(
    hex: &str,
    field: &str,
) -> Result<[u8; N], ChainSpecError> {
    let trimmed = hex.strip_prefix("0x").unwrap_or(hex);
    if trimmed.len() != N * 2 {
        return Err(ChainSpecError::Hex {
            field: field.to_owned(),
            reason: format!(
                "expected {expected} hex chars, got {actual}",
                expected = N * 2,
                actual = trimmed.len()
            ),
        });
    }
    let mut out = [0_u8; N];
    for (idx, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let high = parse_hex_nibble(chunk[0], field)?;
        let low = parse_hex_nibble(chunk[1], field)?;
        out[idx] = (high << 4) | low;
    }
    Ok(out)
}

fn parse_hex_nibble(byte: u8, field: &str) -> Result<u8, ChainSpecError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ChainSpecError::Hex {
            field: field.to_owned(),
            reason: format!("invalid hex digit: {:?}", char::from(byte)),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_spec_toml() -> &'static str {
        r#"
name = "neutrino-m6-test"
chain_id = 7
genesis_time = 1700000000
genesis_gas_limit = 30000000
genesis_block_hash_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[validators]]
pubkey_hex = "010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748"
effective_stake = 32000000000
"#
    }

    #[test]
    fn parses_minimal_chain_spec() {
        let file = ChainSpecFile::from_toml_str(minimal_spec_toml()).expect("parse");
        assert_eq!(file.chain_id, 7);
        assert_eq!(file.validators.len(), 1);
    }

    #[test]
    fn materialises_canonical_chain_spec() {
        let file = ChainSpecFile::from_toml_str(minimal_spec_toml()).expect("parse");
        let spec = file.to_chain_spec().expect("to_chain_spec");
        assert_eq!(spec.chain_id, 7);
        assert_eq!(spec.genesis_block_hash, [0xAA; 32]);
        assert!(spec.initial_validators[0].effective_stake > 0);
    }

    #[test]
    fn identical_spec_files_hash_identically() {
        let a = ChainSpecFile::from_toml_str(minimal_spec_toml())
            .unwrap()
            .to_chain_spec()
            .unwrap();
        let b = ChainSpecFile::from_toml_str(minimal_spec_toml())
            .unwrap()
            .to_chain_spec()
            .unwrap();
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn changing_chain_id_changes_hash() {
        let a = ChainSpecFile::from_toml_str(minimal_spec_toml())
            .unwrap()
            .to_chain_spec()
            .unwrap();
        let modified = minimal_spec_toml().replace("chain_id = 7", "chain_id = 8");
        let b = ChainSpecFile::from_toml_str(&modified)
            .unwrap()
            .to_chain_spec()
            .unwrap();
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn rejects_short_pubkey() {
        let bad = r#"
name = "x"
chain_id = 1
genesis_time = 0
genesis_gas_limit = 1

[[validators]]
pubkey_hex = "0102"
effective_stake = 1
"#;
        let file = ChainSpecFile::from_toml_str(bad).expect("parse");
        match file.to_chain_spec() {
            Err(ChainSpecError::Hex { field, .. }) => {
                assert!(field.starts_with("validators[0]"));
            }
            other => panic!("expected Hex error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversized_name() {
        let mut long_name = String::with_capacity(128);
        for _ in 0..128 {
            long_name.push('a');
        }
        let raw = format!(
            r#"
name = "{long_name}"
chain_id = 1
genesis_time = 0
genesis_gas_limit = 1

[[validators]]
pubkey_hex = "010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748"
effective_stake = 1
"#
        );
        let file = ChainSpecFile::from_toml_str(&raw).expect("parse");
        assert!(matches!(
            file.to_chain_spec(),
            Err(ChainSpecError::NameTooLong { .. })
        ));
    }
}
