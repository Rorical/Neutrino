#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Stable wire definitions for the Neutrino runtime ABI v1.
//!
//! This crate is the single source of truth for the contract between the
//! consensus node and any runtime running on the RV32IM interpreter. It
//! declares:
//!
//! - The numeric syscall identifiers, grouped by category ([`syscall`]).
//! - The stable status codes returned in `a0` ([`status::Status`]).
//! - Deterministic gas-cost helpers per syscall ([`gas`]).
//! - The borsh-encoded per-block context handed to every entrypoint
//!   ([`BlockContext`]).
//!
//! Everything in this crate is reachable by both the host (which charges
//! gas and validates buffers) and the guest SDK (which emits the
//! corresponding `ECALL` instructions). Numbers and field layouts here
//! are consensus-critical and must not be changed without bumping
//! [`ABI_VERSION`].

#[cfg(test)]
extern crate alloc;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{
    ABI_VERSION, BlockHash, BlsSignature, Height, Seed, Slot, StateRoot, ValidatorIndex,
};

pub mod gas;
pub mod status;
pub mod syscall;

pub use neutrino_primitives::RuntimeVersion;
pub use status::{Status, UnknownStatus};

/// Runtime ABI version implemented by this crate. Bumping this value is
/// a consensus-breaking change: the host refuses to load any runtime
/// whose [`RuntimeVersion::abi_version`] does not match.
pub const VERSION: u32 = ABI_VERSION;

/// Runtime symbol used by the host to run a single transaction
/// admission check.
pub const VALIDATE_TX_ENTRYPOINT: &str = "_neutrino_validate_tx";

/// Byte length of the fixed transaction-validity result returned by
/// [`VALIDATE_TX_ENTRYPOINT`].
pub const TX_VALIDITY_ENCODED_LEN: usize = 12;

/// Runtime-defined transaction validity code returned to the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxValidationCode {
    /// The transaction is valid against the supplied state root.
    Valid,
    /// The transaction bytes are malformed or truncated.
    Malformed,
    /// A transaction signature failed verification.
    BadSignature,
    /// The transaction nonce does not match account state.
    NonceMismatch,
    /// The sender or stake account lacks the required balance.
    InsufficientBalance,
    /// The transaction attempts an operation reserved to another owner.
    Unauthorized,
    /// The transaction type tag is not recognised by this runtime.
    UnknownType,
    /// Runtime state could not be read in the expected format.
    StateReadFailed,
}

impl TxValidationCode {
    /// Convert the validation code into its stable ABI integer.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Valid => 0,
            Self::Malformed => 1,
            Self::BadSignature => 2,
            Self::NonceMismatch => 3,
            Self::InsufficientBalance => 4,
            Self::Unauthorized => 5,
            Self::UnknownType => 6,
            Self::StateReadFailed => 7,
        }
    }

    /// Convert a stable ABI integer back into a validation code.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Valid),
            1 => Some(Self::Malformed),
            2 => Some(Self::BadSignature),
            3 => Some(Self::NonceMismatch),
            4 => Some(Self::InsufficientBalance),
            5 => Some(Self::Unauthorized),
            6 => Some(Self::UnknownType),
            7 => Some(Self::StateReadFailed),
            _ => None,
        }
    }

    /// `true` when this code admits the transaction into a block or mempool.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Result returned by a runtime transaction-admission entrypoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxValidity {
    /// Validity code produced by the runtime.
    pub code: TxValidationCode,
    /// Runtime-defined mempool priority. Higher values drain first.
    pub priority: u64,
}

impl TxValidity {
    /// Construct an admitted transaction result.
    #[must_use]
    pub const fn valid(priority: u64) -> Self {
        Self {
            code: TxValidationCode::Valid,
            priority,
        }
    }

    /// Construct a rejected transaction result.
    #[must_use]
    pub const fn invalid(code: TxValidationCode) -> Self {
        Self { code, priority: 0 }
    }

    /// `true` when this result admits the transaction.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.code.is_valid()
    }

    /// Encode this result as `code:u32 || priority:u64`, both little-endian.
    #[must_use]
    pub const fn encode(self) -> [u8; TX_VALIDITY_ENCODED_LEN] {
        let code = self.code.as_u32().to_le_bytes();
        let priority = self.priority.to_le_bytes();
        [
            code[0],
            code[1],
            code[2],
            code[3],
            priority[0],
            priority[1],
            priority[2],
            priority[3],
            priority[4],
            priority[5],
            priority[6],
            priority[7],
        ]
    }

    /// Decode a fixed-width runtime validity result.
    pub fn decode(bytes: &[u8]) -> Result<Self, TxValidityDecodeError> {
        if bytes.len() != TX_VALIDITY_ENCODED_LEN {
            return Err(TxValidityDecodeError::WrongLength {
                actual: bytes.len(),
            });
        }
        let code_raw = u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .expect("length checked for validation code"),
        );
        let Some(code) = TxValidationCode::from_u32(code_raw) else {
            return Err(TxValidityDecodeError::UnknownCode { code: code_raw });
        };
        let priority = u64::from_le_bytes(
            bytes[4..]
                .try_into()
                .expect("length checked for validation priority"),
        );
        Ok(Self { code, priority })
    }
}

/// Errors while decoding a transaction-validity result from the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxValidityDecodeError {
    /// The output length did not match [`TX_VALIDITY_ENCODED_LEN`].
    WrongLength {
        /// Actual number of bytes returned by the runtime.
        actual: usize,
    },
    /// The runtime returned an unknown validation code.
    UnknownCode {
        /// Raw code returned by the runtime.
        code: u32,
    },
}

/// Borsh-encoded per-block context handed to every entrypoint via the
/// [`syscall::block::CONTEXT_OUT`] syscall.
///
/// All fields are engine-supplied and consensus-critical. The
/// `parent_state_root` is the trie root the runtime is expected to
/// extend; `seed` is the folded VRF outputs of the last finalized chunk
/// (see `docs/design/12-randomness.md`); `vrf_proof` is the proposer's
/// BLS-VRF for this slot.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct BlockContext {
    /// Block slot number.
    pub slot: Slot,
    /// Candidate block height.
    pub height: Height,
    /// Latest finalized randomness seed.
    pub seed: Seed,
    /// Parent block hash.
    pub parent_hash: BlockHash,
    /// Parent state root.
    pub parent_state_root: StateRoot,
    /// Block gas limit.
    pub gas_limit: u64,
    /// Proposer validator index.
    pub proposer_index: ValidatorIndex,
    /// Proposer VRF proof.
    pub vrf_proof: BlsSignature,
}

/// Returns the [`RuntimeVersion`] this crate advertises by default. It
/// reuses the canonical version constants from [`neutrino_primitives`]
/// so the chain spec, the runtime ABI, and the SDK never drift.
#[must_use]
pub fn default_runtime_version() -> RuntimeVersion {
    RuntimeVersion::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn sample_block_context() -> BlockContext {
        BlockContext {
            slot: 42,
            height: 17,
            seed: [9; 32],
            parent_hash: [1; 32],
            parent_state_root: [2; 32],
            gas_limit: 30_000_000,
            proposer_index: 5,
            vrf_proof: [3; 96],
        }
    }

    #[test]
    fn block_context_round_trips_through_borsh() {
        let original = sample_block_context();
        let encoded: Vec<u8> = borsh::to_vec(&original).expect("borsh serialization succeeds");
        let decoded: BlockContext =
            borsh::from_slice(&encoded).expect("borsh deserialization succeeds");
        assert_eq!(decoded, original);
    }

    #[test]
    fn default_runtime_version_matches_abi_version() {
        let version = default_runtime_version();
        assert_eq!(version.abi_version, VERSION);
        assert_eq!(version.abi_version, ABI_VERSION);
    }

    #[test]
    fn transaction_validity_round_trips_fixed_encoding() {
        let validity = TxValidity::valid(42);
        let encoded = validity.encode();
        assert_eq!(encoded.len(), TX_VALIDITY_ENCODED_LEN);
        assert_eq!(TxValidity::decode(&encoded).unwrap(), validity);
    }

    #[test]
    fn transaction_validity_rejects_unknown_code() {
        let mut encoded = TxValidity::invalid(TxValidationCode::BadSignature).encode();
        encoded[..4].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            TxValidity::decode(&encoded),
            Err(TxValidityDecodeError::UnknownCode { code: 99 })
        );
    }
}
