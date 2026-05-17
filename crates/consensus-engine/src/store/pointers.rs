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

/// Highest checkpoint index whose covering headers have already been
/// folded into [`FINALIZED_SEED`].
///
/// Followers may import a recursive checkpoint before the headers it
/// covers, so the seed advance is two-phase: the engine bumps this
/// pointer only after every header in the checkpoint's range is
/// present and folded. Producers advance both the pointer and the
/// seed inline at chunk-close. The pointer is reloaded on
/// [`Engine::open`] so restart-resume never re-folds or skips a
/// chunk.
pub const SEED_ADVANCED_THROUGH_CHECKPOINT: &[u8] = b"seed_advanced_idx";

/// Index of the currently active validator-set snapshot.
///
/// Persisted so restarts resume with the correct active validator list
/// for proposer eligibility and BFT quorum weighting.
pub const LATEST_VALIDATOR_SET_INDEX: &[u8] = b"latest_vs_idx";

/// BLAKE3 hash of the borsh-encoded chain spec.
pub const CHAIN_SPEC_HASH: &[u8] = b"chain_spec_hash";

/// Database schema version. Incremented on any breaking on-disk change.
pub const DB_SCHEMA_VERSION: &[u8] = b"db_schema_version";

/// Current on-disk schema version. Bumped whenever the layout changes.
pub const CURRENT_DB_SCHEMA_VERSION: u32 = 1;
