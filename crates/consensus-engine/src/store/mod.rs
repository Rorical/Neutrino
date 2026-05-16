//! Typed wrappers over a column-family [`Database`](neutrino_storage::Database).
//!
//! `ChainStore` borsh-encodes every value and centralises the key
//! conventions for every consensus column (headers, bodies, proofs,
//! chunks, checkpoints, validator-set snapshots, pointers, metadata).
//!
//! The encoding rule is uniform: all integer keys are stored as
//! big-endian byte arrays so iteration order matches numeric order, and
//! every value is borsh-encoded. Pointers in the `Finalized` and `Meta`
//! columns use stable ASCII names (`tip`, `finalized_head`,
//! `latest_chunk_id`, ...).

mod chain_store;
mod error;
pub mod keys;
pub mod pointers;

pub use chain_store::{ChainStore, ValidatorSetSnapshot};
pub use error::StoreError;
