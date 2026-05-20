#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Stable wire definitions for the Neutrino runtime ABI v1.
//!
//! This crate is the single source of truth for the contract between the
//! consensus node and any runtime (WASM dynamic runtime or SP1 guest). It
//! declares:
//!
//! - The stable status codes for runtime operations ([`status::Status`]).
//! - The borsh-encoded per-block context handed to every entrypoint
//!   ([`BlockContext`]).
//! - The borsh-encoded read-only query request and response types
//!   ([`QueryRequest`], [`QueryResponse`]).
//! - The fixed-width transaction-validity result format
//!   ([`TxValidity`], [`TxValidationCode`]).
//! - The witness envelope handed to the SP1 Guest
//!   ([`StateWitness`], [`WitnessEntry`]).
//!
//! Numbers and field layouts here are consensus-critical and must not be
//! changed without bumping [`ABI_VERSION`].

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{
    ABI_VERSION, BlockHash, BlsSignature, Hash, Height, Seed, Slot, StateRoot, ValidatorIndex,
};

pub mod status;

pub use neutrino_primitives::RuntimeVersion;
pub use status::{Status, UnknownStatus};

/// Runtime ABI version implemented by this crate. Bumping this value is
/// a consensus-breaking change: the host refuses to load any runtime
/// whose [`RuntimeVersion::abi_version`] does not match.
pub const VERSION: u32 = ABI_VERSION;

/// Runtime function name used by the host to run a single transaction
/// admission check against the WASM dynamic runtime.
pub const VALIDATE_TX_ENTRYPOINT: &str = "_neutrino_validate_tx";

/// Runtime function name used by the host to run a single read-only query
/// against the WASM dynamic runtime.
///
/// The runtime reads a [`QueryRequest`] from its input buffer and writes a
/// [`QueryResponse`] to its output buffer. State writes are forbidden; the
/// host discards the state overlay regardless of what the runtime
/// attempts. Both shapes are stable across minor ABI revisions; new query
/// methods are added by the runtime without changing the wire envelope.
pub const QUERY_ENTRYPOINT: &str = "_neutrino_query";

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

/// Borsh-encoded per-block context handed to every entrypoint by the
/// runtime host.
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

/// Borsh-encoded read-only query request passed to
/// [`QUERY_ENTRYPOINT`] through the runtime's input buffer.
///
/// The wire envelope is intentionally narrow: a runtime-defined method
/// name plus opaque bytes. The method is a UTF-8 string so an EVM-style
/// runtime can claim `eth_getBalance`, `eth_call`, etc.; non-EVM
/// runtimes are free to choose any naming scheme. The argument bytes
/// are encoded by the caller in whatever shape the chosen method
/// expects (typically borsh, but the host is agnostic).
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct QueryRequest {
    /// Runtime-defined method name (e.g. `"account_get"` or
    /// `"eth_call"`).
    pub method: String,
    /// Opaque, method-defined argument payload.
    pub args: Vec<u8>,
}

/// Borsh-encoded read-only query response written to the runtime's output
/// buffer.
///
/// A successful query carries `code = 0` and the method's serialised
/// result in `payload`. A failed query carries a non-zero runtime
/// status; the value is consensus-irrelevant (queries never produce
/// state) so runtimes are free to define their own status spaces, but
/// the values listed in [`QueryStatus`] cover the common cases.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct QueryResponse {
    /// Runtime-defined status code. `0` means success.
    pub code: u32,
    /// Method-defined result bytes on success, or an optional error
    /// payload on failure.
    pub payload: Vec<u8>,
}

impl QueryResponse {
    /// Construct a successful response with the given payload.
    #[must_use]
    pub const fn ok(payload: Vec<u8>) -> Self {
        Self {
            code: QueryStatus::Ok.as_u32(),
            payload,
        }
    }

    /// Construct an error response with the given status code and
    /// optional message bytes.
    #[must_use]
    pub fn err(status: QueryStatus, message: impl Into<Vec<u8>>) -> Self {
        Self {
            code: status.as_u32(),
            payload: message.into(),
        }
    }

    /// `true` when this response signals a successful query.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.code == QueryStatus::Ok.as_u32()
    }
}

/// Conventional status codes for [`QueryResponse::code`].
///
/// Runtimes are free to use additional codes >= `1024`; the values
/// below `1024` are reserved for the canonical envelope. The host
/// never inspects the value; it is interpreted by the RPC layer
/// (or whatever consumes the response).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryStatus {
    /// Successful query.
    Ok,
    /// Method name was not recognised by the runtime.
    UnknownMethod,
    /// Method recognised, but the argument bytes were malformed.
    InvalidArguments,
    /// The runtime returned an error specific to the method.
    MethodError,
    /// The host refused the call (e.g. write attempted during query).
    PermissionDenied,
}

impl QueryStatus {
    /// Stable wire encoding of the status.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::UnknownMethod => 1,
            Self::InvalidArguments => 2,
            Self::MethodError => 3,
            Self::PermissionDenied => 4,
        }
    }
}

/// One trie node carried in a [`StateWitness`].
///
/// `bytes` is the canonical encoded form of a `neutrino_trie::Node`
/// whose BLAKE3 hash equals `hash`. The SP1 Guest reconstructs a
/// partial `Trie` from the collected `(hash, bytes)` pairs via
/// `Trie::from_persisted`.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct TrieNodeBytes {
    /// BLAKE3 hash of `bytes`.
    pub hash: Hash,
    /// Canonical node encoding.
    pub bytes: Vec<u8>,
}

/// One trie value (leaf payload) carried in a [`StateWitness`].
///
/// `bytes` is the raw value stored at the corresponding leaf; `hash`
/// is `BLAKE3(value_bytes)` exactly as the trie computes it.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct TrieValueBytes {
    /// BLAKE3 hash of `bytes`.
    pub hash: Hash,
    /// Raw value bytes referenced by leaves in [`TrieNodeBytes`].
    pub bytes: Vec<u8>,
}

/// Witness handed to the SP1 Guest before it replays the STF.
///
/// The witness is a Merkle subtree of the state trie that covers every
/// key the STF reads or writes. The Guest builds a `Trie` via
/// `Trie::from_persisted(pre_state_root, nodes, values)`, asserts the
/// reconstructed root equals `pre_state_root`, then runs the STF
/// against that partial trie. After the STF finishes the Guest reads
/// the new root from the (now-updated) trie and commits it as the
/// `post_state_root` in `StfPublicOutput`.
///
/// Any STF read whose key is not in `witnessed_keys` panics inside the
/// Guest, which surfaces as a non-zero exit code and rejects the
/// proof. Writes implicitly witness their key.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct StateWitness {
    /// Trie root the supplied nodes / values must reconstruct.
    pub pre_state_root: StateRoot,
    /// Trie nodes (`hash -> bytes`) covering every read / write path.
    pub nodes: Vec<TrieNodeBytes>,
    /// Trie values (`hash -> bytes`) referenced by the witnessed leaves.
    pub values: Vec<TrieValueBytes>,
    /// Raw runtime keys the STF is permitted to read. The host sorts
    /// the set ascending for determinism.
    pub witnessed_keys: Vec<Vec<u8>>,
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

    #[test]
    fn query_request_round_trips_through_borsh() {
        let req = QueryRequest {
            method: "account_get".into(),
            args: vec![1, 2, 3, 4],
        };
        let bytes = borsh::to_vec(&req).expect("encode");
        let decoded: QueryRequest = borsh::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    fn query_response_round_trips_through_borsh() {
        let resp = QueryResponse::ok(vec![9, 8, 7]);
        let bytes = borsh::to_vec(&resp).expect("encode");
        let decoded: QueryResponse = borsh::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, resp);
        assert!(decoded.is_ok());
    }

    #[test]
    fn query_status_codes_are_stable() {
        assert_eq!(QueryStatus::Ok.as_u32(), 0);
        assert_eq!(QueryStatus::UnknownMethod.as_u32(), 1);
        assert_eq!(QueryStatus::InvalidArguments.as_u32(), 2);
        assert_eq!(QueryStatus::MethodError.as_u32(), 3);
        assert_eq!(QueryStatus::PermissionDenied.as_u32(), 4);
    }

    #[test]
    fn query_response_err_carries_message_payload() {
        let resp = QueryResponse::err(QueryStatus::UnknownMethod, b"no such method".to_vec());
        assert_eq!(resp.code, QueryStatus::UnknownMethod.as_u32());
        assert_eq!(resp.payload, b"no such method".to_vec());
        assert!(!resp.is_ok());
    }

    #[test]
    fn state_witness_round_trips_through_borsh() {
        let witness = StateWitness {
            pre_state_root: [7; 32],
            nodes: vec![TrieNodeBytes {
                hash: [1; 32],
                bytes: b"node-bytes".to_vec(),
            }],
            values: vec![TrieValueBytes {
                hash: [2; 32],
                bytes: b"value-bytes".to_vec(),
            }],
            witnessed_keys: vec![b"k".to_vec()],
        };
        let bytes = borsh::to_vec(&witness).expect("encode");
        let decoded: StateWitness = borsh::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, witness);
    }
}
