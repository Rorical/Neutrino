#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]

//! Shared primitive types and chain-spec constants for Neutrino.
//!
//! This crate is the canonical source of truth for consensus constants that
//! must be shared by the engine, runtime ABI, proof system, and light client.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};

/// A 32-byte cryptographic digest.
pub type Hash = [u8; 32];
/// Chain identifier, encoded little-endian in signed messages.
pub type ChainId = u64;
/// Consensus slot number.
pub type Slot = u64;
/// Staking/reward epoch number.
pub type Epoch = u64;
/// Monotonic block height.
pub type Height = u64;
/// Finality/proof chunk identifier.
pub type ChunkId = u64;
/// Recursive checkpoint index.
pub type CheckpointIndex = u64;
/// Index into the active validator set.
pub type ValidatorIndex = u32;
/// Runtime state trie root.
pub type StateRoot = Hash;
/// Block header hash.
pub type BlockHash = Hash;
/// Chunk commitment hash.
pub type ChunkHash = Hash;
/// Transaction hash.
pub type TxHash = Hash;
/// Public randomness seed.
pub type Seed = Hash;
/// Fixed-point `Q64.64` value.
pub type FixedU128 = u128;
/// BLS12-381 G1 public key, compressed.
pub type BlsPublicKey = [u8; 48];
/// BLS12-381 G2 signature, compressed.
pub type BlsSignature = [u8; 96];
/// Ed25519 public key.
pub type Ed25519PublicKey = [u8; 32];
/// Ed25519 signature.
pub type Ed25519Signature = [u8; 64];
/// Secp256k1 public key, compressed.
pub type Secp256k1PublicKey = [u8; 33];
/// Secp256k1 recoverable or compact signature bytes.
pub type Secp256k1Signature = [u8; 65];
/// Consensus domain tag. All domain tags are exactly 16 bytes.
pub type DomainTag = [u8; 16];

/// Zero hash used for empty roots and genesis placeholders.
pub const ZERO_HASH: Hash = [0; 32];
/// Current engine/header version.
pub const HEADER_VERSION: u32 = 1;
/// Current chain-spec schema version.
pub const CHAIN_SPEC_VERSION: u32 = 1;
/// Current proof-system public-input version.
pub const PROOF_SYSTEM_VERSION: u32 = 1;
/// Runtime ABI version targeted by M0.
pub const ABI_VERSION: u32 = 1;
/// Fractional bits in `FixedU128`.
pub const FIXED_U128_FRAC_BITS: u32 = 64;
/// `1.0` as `Q64.64`.
pub const FIXED_U128_ONE: FixedU128 = 1_u128 << FIXED_U128_FRAC_BITS;
/// Default slot duration in seconds.
pub const DEFAULT_SLOT_DURATION_SECS: u64 = 4;
/// Default epoch length in slots.
pub const DEFAULT_EPOCH_LENGTH: u64 = 32;
/// Default chunk size in canonical block heights.
pub const DEFAULT_CHUNK_SIZE: u64 = 128;
/// Default block-proof window in slots.
pub const DEFAULT_PROOF_WINDOW_SLOTS: u64 = 8;
/// Default timeout after the last chunk block before fallback proving starts.
pub const DEFAULT_CHUNK_TIMEOUT_SLOTS: u64 = 16;
/// Default finality-stall alert threshold after chunk timeout.
pub const DEFAULT_FINALITY_STALL_THRESHOLD_SLOTS: u64 = 64;
/// Default proposer boost fraction, `0.4` as `Q64.64`. Truncating integer
/// division yields the closest representable `Q64.64` value to `0.4`, which
/// is within 1 ULP of the mathematical fraction.
pub const DEFAULT_PROPOSER_BOOST_FRACTION: FixedU128 = (FIXED_U128_ONE * 2) / 5;
/// Default expected proposer count per slot, `1.0` as `Q64.64`.
pub const DEFAULT_EXPECTED_PROPOSERS_PER_SLOT: FixedU128 = FIXED_U128_ONE;
/// Default expected aggregator count per `(chunk, round)`, `4.0`
/// as `Q64.64`. Sized to keep aggregation work distributed across
/// roughly a quarter of a 16-validator set per round.
pub const DEFAULT_EXPECTED_AGGREGATORS_PER_ROUND: FixedU128 = FIXED_U128_ONE * 4;
/// Default fallback prover premium, `0.5` as `Q64.64`.
pub const DEFAULT_FALLBACK_PREMIUM: FixedU128 = FIXED_U128_ONE / 2;
/// Default number of finality-vote subnets.
pub const DEFAULT_VOTE_SUBNETS: u16 = 16;
/// Default number of validator vote subnets per chunk.
pub const DEFAULT_VALIDATOR_SUBNETS_PER_CHUNK: u8 = 2;
/// Default withdrawal delay and weak-subjectivity period in seconds.
pub const DEFAULT_WEAK_SUBJECTIVITY_PERIOD_SECS: u64 = 14 * 24 * 60 * 60;
/// Default number of chunks to retain lock-violation evidence.
pub const DEFAULT_LOCK_WINDOW_CHUNKS: u64 = 64;
/// Default recent-state retention in blocks.
pub const DEFAULT_KEEP_STATE_BLOCKS: u64 = DEFAULT_CHUNK_SIZE * 4;
/// Default checkpoint pruning delay.
pub const DEFAULT_PRUNING_DELAY_CHECKPOINTS: u64 = 2;
/// Default witness retention beyond the proving window.
pub const DEFAULT_WITNESS_RETENTION_BLOCKS: u64 = DEFAULT_CHUNK_SIZE;
/// Default state snapshot interval in checkpoints.
pub const DEFAULT_SNAPSHOT_INTERVAL_CHECKPOINTS: u64 = 1024;
/// Default external anchor interval in checkpoints.
pub const DEFAULT_ANCHOR_INTERVAL_CHECKPOINTS: u64 = 1024;
/// Default user-facing stale-checkpoint alert threshold in seconds.
pub const DEFAULT_LIGHT_CLIENT_STALE_THRESHOLD_SECS: u64 =
    4 * DEFAULT_CHUNK_SIZE * DEFAULT_SLOT_DURATION_SECS;
/// Maximum canonical chain name length.
pub const MAX_CHAIN_NAME_BYTES: usize = 64;
/// Maximum URL or human label length used in chain-spec metadata.
pub const MAX_METADATA_BYTES: usize = 256;

/// BLS-VRF eval/verify domain.
pub const DOMAIN_VRF: DomainTag = *b"NEUTRINO_VRF_V1\0";
/// Block header proposer-signature domain.
pub const DOMAIN_PROPOSER_SIG: DomainTag = *b"NEUTRINO_PROPOSE";
/// Finality prevote domain.
pub const DOMAIN_PREVOTE: DomainTag = *b"NEUTRINO_PREVOTE";
/// Finality precommit domain.
pub const DOMAIN_PRECOMMIT: DomainTag = *b"NEUTRINO_PRECOMM";
/// Validator deposit proof-of-possession domain.
pub const DOMAIN_DEPOSIT_POP: DomainTag = *b"NEUTRINO_DEP_POP";
/// Voluntary-exit signature domain.
pub const DOMAIN_VOLUNTARY_EXIT: DomainTag = *b"NEUTRINO_VEXIT00";
/// Future chunk-aggregator proof domain.
pub const DOMAIN_AGG_PROOF: DomainTag = *b"NEUTRINO_AGGPRF0";

/// Converts an integer into `Q64.64`.
pub const fn fixed_u128_from_integer(value: u64) -> FixedU128 {
    (value as u128) << FIXED_U128_FRAC_BITS
}

/// Converts a rational number into `Q64.64`. Returns zero for a zero denominator.
pub const fn fixed_u128_ratio(numerator: u64, denominator: u64) -> FixedU128 {
    if denominator == 0 {
        0
    } else {
        ((numerator as u128) << FIXED_U128_FRAC_BITS) / (denominator as u128)
    }
}

/// Computes a BLAKE3-256 digest.
pub fn blake3_256(input: &[u8]) -> Hash {
    *blake3::hash(input).as_bytes()
}

/// Error returned when bounded bytes exceed their configured maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundsError {
    /// Observed byte length.
    pub actual: usize,
    /// Maximum permitted byte length.
    pub max: usize,
}

impl fmt::Display for BoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bounded byte length {} exceeds maximum {}",
            self.actual, self.max
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BoundsError {}

/// Heap bytes with a type-level maximum length.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedBytes<const MAX_LEN: usize> {
    inner: Vec<u8>,
}

impl<const MAX_LEN: usize> BoundedBytes<MAX_LEN> {
    /// Creates bounded bytes after checking the maximum length.
    pub fn new(bytes: Vec<u8>) -> Result<Self, BoundsError> {
        if bytes.len() > MAX_LEN {
            return Err(BoundsError {
                actual: bytes.len(),
                max: MAX_LEN,
            });
        }

        Ok(Self { inner: bytes })
    }

    /// Returns the maximum permitted byte length.
    pub const fn max_len() -> usize {
        MAX_LEN
    }

    /// Returns the current byte length.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Borrows the contained bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Consumes the wrapper and returns the contained bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.inner
    }
}

impl<const MAX_LEN: usize> AsRef<[u8]> for BoundedBytes<MAX_LEN> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const MAX_LEN: usize> TryFrom<Vec<u8>> for BoundedBytes<MAX_LEN> {
    type Error = BoundsError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<const MAX_LEN: usize> fmt::Debug for BoundedBytes<MAX_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedBytes")
            .field("len", &self.inner.len())
            .field("max", &MAX_LEN)
            .finish()
    }
}

impl<const MAX_LEN: usize> BorshSerialize for BoundedBytes<MAX_LEN> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        self.inner.serialize(writer)
    }
}

impl<const MAX_LEN: usize> BorshDeserialize for BoundedBytes<MAX_LEN> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let bytes = Vec::<u8>::deserialize_reader(reader)?;
        Self::new(bytes).map_err(|_| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "bounded bytes exceed maximum length",
            )
        })
    }
}

/// Compact bit vector used for validator aggregation bitmaps.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct BitVec {
    bit_len: u32,
    bytes: Vec<u8>,
}

impl BitVec {
    /// Creates a bit vector from raw bytes and validates zero padding bits.
    pub fn from_bytes(bit_len: u32, bytes: Vec<u8>) -> Result<Self, BoundsError> {
        let expected = bytes_for_bits(bit_len);
        if bytes.len() != expected {
            return Err(BoundsError {
                actual: bytes.len(),
                max: expected,
            });
        }

        let bit_vec = Self { bit_len, bytes };
        if bit_vec.has_non_zero_padding() {
            return Err(BoundsError {
                actual: bit_vec.bytes.len(),
                max: expected,
            });
        }

        Ok(bit_vec)
    }

    /// Returns the number of meaningful bits.
    pub const fn bit_len(&self) -> u32 {
        self.bit_len
    }

    /// Returns the number of encoded bytes.
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if no bits are present.
    pub const fn is_empty(&self) -> bool {
        self.bit_len == 0
    }

    /// Borrows the encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reads a bit by index. Bits are encoded least-significant-bit first.
    pub fn get(&self, index: u32) -> Option<bool> {
        if index >= self.bit_len {
            return None;
        }

        let byte = self.bytes[usize::try_from(index / 8).ok()?];
        let mask = 1_u8 << (index % 8);
        Some(byte & mask != 0)
    }

    /// Appends one bit.
    pub fn push(&mut self, value: bool) {
        let index = self.bit_len;
        let next_len = index.saturating_add(1);
        let next_byte_len = bytes_for_bits(next_len);
        if self.bytes.len() < next_byte_len {
            self.bytes.push(0);
        }
        if value {
            let byte_index =
                usize::try_from(index / 8).expect("u32 fits usize on supported targets");
            self.bytes[byte_index] |= 1_u8 << (index % 8);
        }
        self.bit_len = next_len;
    }

    fn has_non_zero_padding(&self) -> bool {
        let unused_bits = self
            .bytes
            .len()
            .saturating_mul(8)
            .saturating_sub(self.bit_len as usize);
        if unused_bits == 0 || self.bytes.is_empty() {
            return false;
        }

        let used_bits_in_last = self.bit_len % 8;
        let mask = if used_bits_in_last == 0 {
            0
        } else {
            !((1_u8 << used_bits_in_last) - 1)
        };

        self.bytes.last().is_some_and(|last| last & mask != 0)
    }
}

impl fmt::Debug for BitVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitVec")
            .field("bit_len", &self.bit_len)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

impl BorshSerialize for BitVec {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        self.bit_len.serialize(writer)?;
        self.bytes.serialize(writer)
    }
}

impl BorshDeserialize for BitVec {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let bit_len = u32::deserialize_reader(reader)?;
        let bytes = Vec::<u8>::deserialize_reader(reader)?;
        Self::from_bytes(bit_len, bytes).map_err(|_| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "invalid bit-vector encoding",
            )
        })
    }
}

fn bytes_for_bits(bit_len: u32) -> usize {
    (bit_len as usize).div_ceil(8)
}

/// Supported state-trie hash algorithms.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum HashAlgorithm {
    /// BLAKE3, the M0 default and reference implementation.
    #[default]
    Blake3,
    /// SHA-256, useful for backends that prefer SHA-friendly trie
    /// commitments (e.g. an alternative `proof_system_version` swap).
    Sha256,
    /// Poseidon (Poseidon2 over BabyBear under the v1 Plonky3 backend),
    /// useful for in-circuit Merkle and Fiat-Shamir economics.
    Poseidon,
}

/// Runtime version exposed by the runtime ABI and ELF metadata.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeVersion {
    /// Fixed-width runtime name.
    pub spec_name: [u8; 16],
    /// Consensus-breaking runtime version.
    pub spec_version: u32,
    /// Implementation-only runtime version.
    pub impl_version: u32,
    /// Host ABI version expected by the runtime.
    pub abi_version: u32,
}

impl Default for RuntimeVersion {
    fn default() -> Self {
        Self {
            spec_name: *b"NEUTRINO_DEFAULT",
            spec_version: 1,
            impl_version: 1,
            abi_version: ABI_VERSION,
        }
    }
}

/// Validator identity and activation metadata from the active validator set.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Validator {
    /// BLS signing public key.
    pub pubkey: BlsPublicKey,
    /// Runtime-defined withdrawal credential commitment.
    pub withdrawal_credentials: Hash,
    /// Effective stake in the runtime's base unit.
    pub effective_stake: u64,
    /// True if the validator has been slashed.
    pub slashed: bool,
    /// Epoch at which the validator becomes active.
    pub activation_epoch: Epoch,
    /// Epoch at which the validator exits.
    pub exit_epoch: Epoch,
    /// Last chunk in which the validator was active for finality weighting.
    pub last_active_chunk: ChunkId,
}

/// Consensus timing and finality constants covered by the chain-spec hash.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConsensusParams {
    /// Slot duration in seconds.
    pub slot_duration_secs: u64,
    /// Epoch length in slots.
    pub epoch_length: u64,
    /// Chunk size in canonical block heights.
    pub chunk_size: u64,
    /// Fallback-prover timeout after the last chunk block.
    pub chunk_timeout_slots: u64,
    /// Block-proof production window.
    pub proof_window_slots: u64,
    /// Node-level finality-stall alert threshold.
    pub finality_stall_threshold_slots: u64,
    /// Proposer boost fraction as `Q64.64`.
    pub proposer_boost_fraction: FixedU128,
    /// Prevote quorum numerator.
    pub bft_prevote_quorum_numerator: u64,
    /// Prevote quorum denominator.
    pub bft_prevote_quorum_denominator: u64,
    /// Precommit quorum numerator.
    pub bft_precommit_quorum_numerator: u64,
    /// Precommit quorum denominator.
    pub bft_precommit_quorum_denominator: u64,
    /// Minimum delay before withdrawals are final from a weak-subjectivity view.
    pub min_validator_withdrawal_delay_secs: u64,
    /// Chunks retained for lock-violation slashing evidence.
    pub lock_window_chunks: u64,
    /// Expected proposer count per slot as `Q64.64`.
    pub expected_proposers_per_slot: FixedU128,
    /// Expected aggregator count per `(chunk, round)` as `Q64.64`.
    pub expected_aggregators_per_round: FixedU128,
    /// Number of finality-vote subnets.
    pub vote_subnets: u16,
    /// Validator subnets assigned per chunk.
    pub validator_subnets_per_chunk: u8,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            slot_duration_secs: DEFAULT_SLOT_DURATION_SECS,
            epoch_length: DEFAULT_EPOCH_LENGTH,
            chunk_size: DEFAULT_CHUNK_SIZE,
            chunk_timeout_slots: DEFAULT_CHUNK_TIMEOUT_SLOTS,
            proof_window_slots: DEFAULT_PROOF_WINDOW_SLOTS,
            finality_stall_threshold_slots: DEFAULT_FINALITY_STALL_THRESHOLD_SLOTS,
            proposer_boost_fraction: DEFAULT_PROPOSER_BOOST_FRACTION,
            bft_prevote_quorum_numerator: 2,
            bft_prevote_quorum_denominator: 3,
            bft_precommit_quorum_numerator: 2,
            bft_precommit_quorum_denominator: 3,
            min_validator_withdrawal_delay_secs: DEFAULT_WEAK_SUBJECTIVITY_PERIOD_SECS,
            lock_window_chunks: DEFAULT_LOCK_WINDOW_CHUNKS,
            expected_proposers_per_slot: DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
            expected_aggregators_per_round: DEFAULT_EXPECTED_AGGREGATORS_PER_ROUND,
            vote_subnets: DEFAULT_VOTE_SUBNETS,
            validator_subnets_per_chunk: DEFAULT_VALIDATOR_SUBNETS_PER_CHUNK,
        }
    }
}

/// Proof-market and proof-version constants covered by the chain-spec hash.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProofParams {
    /// Public-input proof-system version.
    pub proof_system_version: u32,
    /// Ideal no-empty-slot chunk length in slots.
    pub slot_budget_per_chunk: u64,
    /// Fallback prover bounty premium as `Q64.64`.
    pub fallback_premium: FixedU128,
}

impl Default for ProofParams {
    fn default() -> Self {
        Self {
            proof_system_version: PROOF_SYSTEM_VERSION,
            slot_budget_per_chunk: DEFAULT_CHUNK_SIZE,
            fallback_premium: DEFAULT_FALLBACK_PREMIUM,
        }
    }
}

/// Storage/pruning constants covered by the chain-spec hash.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct StateParams {
    /// Recent state retained by full/pruned nodes.
    pub keep_state_blocks: u64,
    /// Checkpoint delay before coverage-prunable data can be deleted.
    pub pruning_delay_checkpoints: u64,
    /// Witness retention after proving.
    pub witness_retention_blocks: u64,
    /// State snapshot publishing interval.
    pub snapshot_interval_checkpoints: u64,
    /// State-trie hash function.
    pub state_trie_hash: HashAlgorithm,
}

impl Default for StateParams {
    fn default() -> Self {
        Self {
            keep_state_blocks: DEFAULT_KEEP_STATE_BLOCKS,
            pruning_delay_checkpoints: DEFAULT_PRUNING_DELAY_CHECKPOINTS,
            witness_retention_blocks: DEFAULT_WITNESS_RETENTION_BLOCKS,
            snapshot_interval_checkpoints: DEFAULT_SNAPSHOT_INTERVAL_CHECKPOINTS,
            state_trie_hash: HashAlgorithm::Blake3,
        }
    }
}

/// Light-client constants covered by the chain-spec hash.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct LightClientParams {
    /// Weak-subjectivity period in seconds.
    pub weak_subjectivity_period_secs: u64,
    /// External anchor interval in checkpoints.
    pub anchor_interval_checkpoints: u64,
    /// User-facing stale-checkpoint threshold in seconds.
    pub stale_threshold_secs: u64,
    /// Expected recursive proof version.
    pub expected_proof_version: u32,
}

impl Default for LightClientParams {
    fn default() -> Self {
        Self {
            weak_subjectivity_period_secs: DEFAULT_WEAK_SUBJECTIVITY_PERIOD_SECS,
            anchor_interval_checkpoints: DEFAULT_ANCHOR_INTERVAL_CHECKPOINTS,
            stale_threshold_secs: DEFAULT_LIGHT_CLIENT_STALE_THRESHOLD_SECS,
            expected_proof_version: PROOF_SYSTEM_VERSION,
        }
    }
}

/// Recursive-checkpoint public inputs stored at genesis and after finalized chunks.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Checkpoint {
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Recursive checkpoint index.
    pub index: CheckpointIndex,
    /// Previous checkpoint boundary height. For checkpoint `n > 0`, the
    /// covered chunk starts at `start_height + 1`; genesis uses zero.
    pub start_height: Height,
    /// Last covered canonical block height.
    pub end_height: Height,
    /// Previous checkpoint boundary block hash, or zero at genesis.
    pub start_block_hash: BlockHash,
    /// Last covered block hash.
    pub end_block_hash: BlockHash,
    /// Previous checkpoint boundary state root, or zero at genesis.
    pub start_state_root: StateRoot,
    /// State root after the covered range.
    pub end_state_root: StateRoot,
    /// Active validator-set commitment after the covered range.
    pub end_validator_set_root: Hash,
    /// Authenticated history accumulator root.
    pub history_root: Hash,
    /// Proof-system version that produced this checkpoint.
    pub proof_system_version: u32,
}

impl Checkpoint {
    /// Computes `BLAKE3(borsh(self))`.
    pub fn hash(&self) -> Hash {
        blake3_256(&borsh::to_vec(self).expect("borsh serialization of Checkpoint is infallible"))
    }
}

/// Canonical chain specification used for DB metadata and peer compatibility.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChainSpec {
    /// Chain-spec schema version.
    pub spec_version: u32,
    /// Human-readable chain name.
    pub name: BoundedBytes<MAX_CHAIN_NAME_BYTES>,
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Genesis timestamp in seconds since UNIX epoch.
    pub genesis_time: u64,
    /// Genesis block gas limit.
    pub genesis_gas_limit: u64,
    /// Runtime version expected at genesis.
    pub runtime_version: RuntimeVersion,
    /// BLAKE3 hash of the canonical runtime ELF bytes stored on-chain.
    pub runtime_code_hash: Hash,
    /// Public randomness seed for the first post-genesis chunk.
    pub genesis_seed: Seed,
    /// State root returned by `runtime.init_genesis`.
    pub genesis_state_root: StateRoot,
    /// Header hash of the genesis block.
    pub genesis_block_hash: BlockHash,
    /// Validator-set root effective at genesis.
    pub genesis_validator_set_root: Hash,
    /// Genesis checkpoint accepted as recursion base case.
    pub genesis_checkpoint: Checkpoint,
    /// Consensus constants.
    pub consensus: ConsensusParams,
    /// Proof constants.
    pub proof: ProofParams,
    /// State/storage constants.
    pub state: StateParams,
    /// Light-client constants.
    pub light_client: LightClientParams,
    /// Initial validator set.
    pub initial_validators: Vec<Validator>,
    /// Optional metadata URL or label.
    pub metadata: BoundedBytes<MAX_METADATA_BYTES>,
}

impl ChainSpec {
    /// Computes `BLAKE3(borsh(self))`, the canonical chain-spec hash.
    pub fn hash(&self) -> Hash {
        blake3_256(&borsh::to_vec(self).expect("borsh serialization of ChainSpec is infallible"))
    }

    /// Computes the canonical genesis checkpoint from the chain-spec fields.
    pub fn canonical_genesis_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            chain_id: self.chain_id,
            index: 0,
            start_height: 0,
            end_height: 0,
            start_block_hash: ZERO_HASH,
            end_block_hash: self.genesis_block_hash,
            start_state_root: ZERO_HASH,
            end_state_root: self.genesis_state_root,
            end_validator_set_root: self.genesis_validator_set_root,
            history_root: ZERO_HASH,
            proof_system_version: self.proof.proof_system_version,
        }
    }

    /// Computes `BLAKE3(borsh(genesis_checkpoint))`.
    pub fn genesis_checkpoint_hash(&self) -> Hash {
        self.genesis_checkpoint.hash()
    }

    /// Validates consistency of consensus-critical chain-spec fields.
    pub fn validate(&self) -> Result<(), ChainSpecError> {
        if self.spec_version != CHAIN_SPEC_VERSION {
            return Err(ChainSpecError::UnsupportedSpecVersion(self.spec_version));
        }

        if self.chain_id == 0 {
            return Err(ChainSpecError::ZeroChainId);
        }

        if self.runtime_version.abi_version != ABI_VERSION {
            return Err(ChainSpecError::UnsupportedAbiVersion(
                self.runtime_version.abi_version,
            ));
        }

        if self.genesis_checkpoint != self.canonical_genesis_checkpoint() {
            return Err(ChainSpecError::InvalidGenesisCheckpoint);
        }

        self.consensus.validate()?;
        self.proof.validate(&self.consensus)?;
        self.state.validate()?;
        self.light_client.validate(&self.proof)?;

        if self.initial_validators.is_empty() {
            return Err(ChainSpecError::EmptyValidatorSet);
        }

        let mut total_stake = 0_u64;
        for validator in &self.initial_validators {
            if validator.effective_stake == 0 {
                return Err(ChainSpecError::ZeroValidatorStake);
            }
            total_stake = total_stake
                .checked_add(validator.effective_stake)
                .ok_or(ChainSpecError::ValidatorStakeOverflow)?;
        }

        Ok(())
    }
}

impl ConsensusParams {
    fn validate(&self) -> Result<(), ChainSpecError> {
        if self.slot_duration_secs == 0
            || self.epoch_length == 0
            || self.chunk_size == 0
            || self.chunk_timeout_slots == 0
            || self.proof_window_slots == 0
            || self.finality_stall_threshold_slots == 0
        {
            return Err(ChainSpecError::ZeroConsensusParameter);
        }

        validate_quorum(
            self.bft_prevote_quorum_numerator,
            self.bft_prevote_quorum_denominator,
        )?;
        validate_quorum(
            self.bft_precommit_quorum_numerator,
            self.bft_precommit_quorum_denominator,
        )?;

        if self.vote_subnets == 0 || self.validator_subnets_per_chunk == 0 {
            return Err(ChainSpecError::ZeroConsensusParameter);
        }

        if self.expected_proposers_per_slot == 0
            || self.expected_aggregators_per_round == 0
            || self.proposer_boost_fraction > FIXED_U128_ONE
        {
            return Err(ChainSpecError::InvalidFixedPointParameter);
        }

        Ok(())
    }
}

impl ProofParams {
    fn validate(&self, consensus: &ConsensusParams) -> Result<(), ChainSpecError> {
        if self.proof_system_version == 0 || self.slot_budget_per_chunk == 0 {
            return Err(ChainSpecError::ZeroProofParameter);
        }

        if self.slot_budget_per_chunk != consensus.chunk_size {
            return Err(ChainSpecError::SlotBudgetDoesNotMatchChunkSize);
        }

        Ok(())
    }
}

impl StateParams {
    fn validate(&self) -> Result<(), ChainSpecError> {
        if self.keep_state_blocks == 0
            || self.pruning_delay_checkpoints == 0
            || self.witness_retention_blocks == 0
            || self.snapshot_interval_checkpoints == 0
        {
            return Err(ChainSpecError::ZeroStateParameter);
        }

        Ok(())
    }
}

impl LightClientParams {
    fn validate(&self, proof: &ProofParams) -> Result<(), ChainSpecError> {
        if self.weak_subjectivity_period_secs == 0
            || self.anchor_interval_checkpoints == 0
            || self.stale_threshold_secs == 0
        {
            return Err(ChainSpecError::ZeroLightClientParameter);
        }

        if self.expected_proof_version != proof.proof_system_version {
            return Err(ChainSpecError::LightClientProofVersionMismatch);
        }

        Ok(())
    }
}

fn validate_quorum(numerator: u64, denominator: u64) -> Result<(), ChainSpecError> {
    if denominator == 0 || numerator == 0 || numerator > denominator {
        return Err(ChainSpecError::InvalidQuorum);
    }

    Ok(())
}

/// Chain-spec validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainSpecError {
    /// The schema version is not supported by this binary.
    UnsupportedSpecVersion(u32),
    /// Chain ID zero is reserved as invalid.
    ZeroChainId,
    /// The runtime ABI version does not match the host.
    UnsupportedAbiVersion(u32),
    /// The embedded genesis checkpoint is not canonical for the spec fields.
    InvalidGenesisCheckpoint,
    /// At least one consensus parameter was zero.
    ZeroConsensusParameter,
    /// A quorum numerator/denominator pair was invalid.
    InvalidQuorum,
    /// A fixed-point parameter was outside its valid range.
    InvalidFixedPointParameter,
    /// At least one proof parameter was zero.
    ZeroProofParameter,
    /// `slot_budget_per_chunk` must equal `chunk_size` in M0.
    SlotBudgetDoesNotMatchChunkSize,
    /// At least one state/storage parameter was zero.
    ZeroStateParameter,
    /// At least one light-client parameter was zero.
    ZeroLightClientParameter,
    /// Light-client expected proof version does not match proof params.
    LightClientProofVersionMismatch,
    /// The initial validator set must not be empty.
    EmptyValidatorSet,
    /// Validators must start with non-zero effective stake.
    ZeroValidatorStake,
    /// Total validator stake overflowed `u64`.
    ValidatorStakeOverflow,
}

impl fmt::Display for ChainSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSpecVersion(version) => {
                write!(f, "unsupported chain-spec version {version}")
            }
            Self::ZeroChainId => f.write_str("chain ID must be non-zero"),
            Self::UnsupportedAbiVersion(version) => write!(f, "unsupported ABI version {version}"),
            Self::InvalidGenesisCheckpoint => f.write_str("genesis checkpoint is not canonical"),
            Self::ZeroConsensusParameter => f.write_str("consensus parameters must be non-zero"),
            Self::InvalidQuorum => f.write_str("BFT quorum fraction is invalid"),
            Self::InvalidFixedPointParameter => f.write_str("fixed-point parameter is invalid"),
            Self::ZeroProofParameter => f.write_str("proof parameters must be non-zero"),
            Self::SlotBudgetDoesNotMatchChunkSize => {
                f.write_str("slot budget per chunk must match chunk size")
            }
            Self::ZeroStateParameter => f.write_str("state parameters must be non-zero"),
            Self::ZeroLightClientParameter => {
                f.write_str("light-client parameters must be non-zero")
            }
            Self::LightClientProofVersionMismatch => {
                f.write_str("light-client proof version must match proof params")
            }
            Self::EmptyValidatorSet => f.write_str("initial validator set must not be empty"),
            Self::ZeroValidatorStake => f.write_str("validator effective stake must be non-zero"),
            Self::ValidatorStakeOverflow => f.write_str("total validator stake overflowed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ChainSpecError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tags_are_exactly_sixteen_bytes() {
        let tags = [
            DOMAIN_VRF,
            DOMAIN_PROPOSER_SIG,
            DOMAIN_PREVOTE,
            DOMAIN_PRECOMMIT,
            DOMAIN_DEPOSIT_POP,
            DOMAIN_VOLUNTARY_EXIT,
            DOMAIN_AGG_PROOF,
        ];

        for tag in tags {
            assert_eq!(tag.len(), 16);
        }
    }

    #[test]
    fn bounded_bytes_rejects_oversized_input() {
        let result = BoundedBytes::<2>::new(vec![1, 2, 3]);
        assert!(matches!(result, Err(BoundsError { actual: 3, max: 2 })));
    }

    #[test]
    fn bit_vec_round_trips_and_rejects_padding() {
        let mut bits = BitVec::default();
        bits.push(true);
        bits.push(false);
        bits.push(true);

        let encoded = borsh::to_vec(&bits).expect("borsh serialization succeeds");
        let decoded = borsh::from_slice::<BitVec>(&encoded).expect("valid bit vec decodes");
        assert_eq!(decoded.get(0), Some(true));
        assert_eq!(decoded.get(1), Some(false));
        assert_eq!(decoded.get(2), Some(true));
        assert_eq!(decoded.get(3), None);

        let invalid = BitVec::from_bytes(3, vec![0b1111_1000]);
        assert!(invalid.is_err());
    }

    #[test]
    fn chain_spec_validates_canonical_genesis_checkpoint() {
        let mut spec = test_chain_spec();
        spec.genesis_checkpoint = spec.canonical_genesis_checkpoint();

        assert_eq!(spec.validate(), Ok(()));
        assert_eq!(
            spec.genesis_checkpoint_hash(),
            spec.genesis_checkpoint.hash()
        );
        assert_ne!(spec.hash(), ZERO_HASH);
    }

    #[test]
    fn chain_spec_rejects_noncanonical_genesis_checkpoint() {
        let mut spec = test_chain_spec();
        spec.genesis_checkpoint.end_height = 1;

        assert_eq!(
            spec.validate(),
            Err(ChainSpecError::InvalidGenesisCheckpoint)
        );
    }

    fn test_chain_spec() -> ChainSpec {
        let consensus = ConsensusParams::default();
        let proof = ProofParams::default();
        let checkpoint = Checkpoint {
            chain_id: 7,
            index: 0,
            start_height: 0,
            end_height: 0,
            start_block_hash: ZERO_HASH,
            end_block_hash: [1; 32],
            start_state_root: ZERO_HASH,
            end_state_root: [2; 32],
            end_validator_set_root: [3; 32],
            history_root: ZERO_HASH,
            proof_system_version: proof.proof_system_version,
        };

        ChainSpec {
            spec_version: CHAIN_SPEC_VERSION,
            name: BoundedBytes::new(b"local-testnet".to_vec()).expect("name fits"),
            chain_id: 7,
            genesis_time: 1_800_000_000,
            genesis_gas_limit: 30_000_000,
            runtime_version: RuntimeVersion::default(),
            runtime_code_hash: [4; 32],
            genesis_seed: [5; 32],
            genesis_state_root: [2; 32],
            genesis_block_hash: [1; 32],
            genesis_validator_set_root: [3; 32],
            genesis_checkpoint: checkpoint,
            consensus,
            proof,
            state: StateParams::default(),
            light_client: LightClientParams::default(),
            initial_validators: vec![Validator {
                pubkey: [6; 48],
                withdrawal_credentials: [7; 32],
                effective_stake: 32_000_000_000,
                slashed: false,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                last_active_chunk: 0,
            }],
            metadata: BoundedBytes::new(Vec::new()).expect("empty metadata fits"),
        }
    }
}
