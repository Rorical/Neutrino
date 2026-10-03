//! Stable pointer / metadata key names used in the `Finalized` and
//! `Meta` columns.

/// Latest produced block hash (heaviest tip of the local view).
pub const TIP: &[u8] = b"tip";

/// Latest finalized block hash.
pub const FINALIZED_HEAD: &[u8] = b"finalized_head";

/// Highest finalized chunk id (none until chunk 0 finalizes).
pub const LATEST_FINALIZED_CHUNK_ID: &[u8] = b"latest_chunk_id";

/// Highest checkpoint index (genesis is 0).
pub const RECURSIVE_COVERED_CHUNKS: &[u8] = b"recursive_covered_chunks";

/// Current VRF seed folded over the latest finalized chunk.
///
/// Persisted so restarts after one or more chunks have closed resume
/// against the same VRF eligibility surface they were producing under;
/// without it [`Engine::open`] would re-derive the genesis seed and
/// silently fork.
pub const FINALIZED_SEED: &[u8] = b"finalized_seed";

/// Index of the currently active validator-set snapshot.
///
/// Persisted so restarts resume with the correct active validator list
/// for proposer eligibility and BFT quorum weighting.
pub const LATEST_VALIDATOR_SET_INDEX: &[u8] = b"latest_vs_idx";

/// BLAKE3 hash of the borsh-encoded chain spec.
pub const CHAIN_SPEC_HASH: &[u8] = b"chain_spec_hash";

/// Authenticated consensus boundary and the full next execution context.
pub const CONSENSUS_STATE: &[u8] = b"full_consensus_state";

/// Authenticated manifest and trust origin of an unfinished snapshot bootstrap.
pub const BOOTSTRAP_PENDING: &[u8] = b"bootstrap_pending";
/// Durable frontier of a content-addressed execution-state download.
pub const STATE_DOWNLOAD: &[u8] = b"state_download";
/// Prefix for partial and completed objects in the download staging area.
pub const STATE_DOWNLOAD_ENTRY_PREFIX: &[u8] = b"state_download_entry/";
