//! Stable pointer / metadata key names used in the `Finalized` and
//! `Meta` columns.

/// Latest produced block hash (heaviest tip of the local view).
pub const TIP: &[u8] = b"tip";

/// Latest finalized block hash.
pub const FINALIZED_HEAD: &[u8] = b"finalized_head";

/// Highest finalized chunk id (none until chunk 0 finalizes).
pub const LATEST_FINALIZED_CHUNK_ID: &[u8] = b"latest_chunk_id";

/// Highest checkpoint index (genesis is 0).
pub const LATEST_CHECKPOINT_INDEX: &[u8] = b"latest_ckpt_index";

/// Current VRF seed folded over the latest finalized chunk.
///
/// Persisted so restarts after one or more chunks have closed resume
/// against the same VRF eligibility surface they were producing under;
/// without it [`Engine::open`] would re-derive the genesis seed and
/// silently fork.
pub const FINALIZED_SEED: &[u8] = b"finalized_seed";

/// BLAKE3 hash of the borsh-encoded chain spec.
pub const CHAIN_SPEC_HASH: &[u8] = b"chain_spec_hash";

/// Database schema version. Incremented on any breaking on-disk change.
pub const DB_SCHEMA_VERSION: &[u8] = b"db_schema_version";

/// Current on-disk schema version. Bumped whenever the layout changes.
pub const CURRENT_DB_SCHEMA_VERSION: u32 = 1;
