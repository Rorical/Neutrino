//! Column-family names shared by all storage backends.

/// Named storage column.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Column {
    /// Authenticated trie nodes, keyed by node hash.
    TrieNodes,
    /// Content-addressed state values, keyed by value hash.
    StateValues,
    /// Block bodies, keyed by block hash.
    Blocks,
    /// Block headers, keyed by block hash.
    Headers,
    /// Canonical block hash by height, keyed by big-endian or
    /// little-endian height bytes chosen by the caller.
    HeaderByHeight,
    /// One or more block hashes by slot, keyed by caller-encoded slot.
    HeaderBySlot,
    /// Finalized chunks, keyed by chunk id.
    Chunks,
    /// Per-block proof artifacts, keyed by block hash.
    BlockProofs,
    /// Per-block consensus FSM state, keyed by block hash.
    BlockStates,
    /// Per-chunk proof artifacts, keyed by chunk id.
    ChunkProofs,
    /// Recursive checkpoints, keyed by checkpoint index.
    Checkpoints,
    /// Recursive proof bytes, keyed by checkpoint index.
    RecursiveProofs,
    /// Finality certificates, keyed by chunk id.
    FinalityCerts,
    /// Execution witnesses, keyed by block hash.
    Witnesses,
    /// Validator-set snapshots, keyed by checkpoint index.
    ValidatorSetSnapshots,
    /// Finalization pointers such as `tip`, `justified`, and `ckpt`.
    Finalized,
    /// Best-effort mempool state. Not consensus-critical.
    Mempool,
    /// Node-local persisted slashing-evidence pool. Key is BLAKE3
    /// of the borsh-encoded `SlashingEvidence`; value is the
    /// borsh-encoded evidence itself. Loaded into memory on
    /// startup so a node that crashes after detecting equivocation
    /// still emits the evidence in its next produced block.
    SlashingPool,
    /// Node-local metadata such as DB version and chain-spec hash.
    Meta,
}

/// Every storage column in deterministic order.
pub const ALL_COLUMNS: [Column; 19] = [
    Column::TrieNodes,
    Column::StateValues,
    Column::Blocks,
    Column::Headers,
    Column::HeaderByHeight,
    Column::HeaderBySlot,
    Column::Chunks,
    Column::BlockProofs,
    Column::BlockStates,
    Column::ChunkProofs,
    Column::Checkpoints,
    Column::RecursiveProofs,
    Column::FinalityCerts,
    Column::Witnesses,
    Column::ValidatorSetSnapshots,
    Column::Finalized,
    Column::Mempool,
    Column::SlashingPool,
    Column::Meta,
];

impl Column {
    /// Returns the stable RocksDB column-family name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TrieNodes => "trie_nodes",
            Self::StateValues => "state_values",
            Self::Blocks => "blocks",
            Self::Headers => "headers",
            Self::HeaderByHeight => "header_by_height",
            Self::HeaderBySlot => "header_by_slot",
            Self::Chunks => "chunks",
            Self::BlockProofs => "block_proofs",
            Self::BlockStates => "block_states",
            Self::ChunkProofs => "chunk_proofs",
            Self::Checkpoints => "checkpoints",
            Self::RecursiveProofs => "recursive_proofs",
            Self::FinalityCerts => "finality_certs",
            Self::Witnesses => "witnesses",
            Self::ValidatorSetSnapshots => "validator_set_snap",
            Self::Finalized => "finalized",
            Self::Mempool => "mempool",
            Self::SlashingPool => "slashing_pool",
            Self::Meta => "meta",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_columns_has_every_variant_once() {
        assert_eq!(ALL_COLUMNS.len(), 19);
        for (index, left) in ALL_COLUMNS.iter().enumerate() {
            for right in &ALL_COLUMNS[index + 1..] {
                assert_ne!(left, right, "duplicate column {left:?}");
            }
        }
    }

    #[test]
    fn column_names_match_design_doc() {
        let names: [&str; 19] = [
            "trie_nodes",
            "state_values",
            "blocks",
            "headers",
            "header_by_height",
            "header_by_slot",
            "chunks",
            "block_proofs",
            "block_states",
            "chunk_proofs",
            "checkpoints",
            "recursive_proofs",
            "finality_certs",
            "witnesses",
            "validator_set_snap",
            "finalized",
            "mempool",
            "slashing_pool",
            "meta",
        ];
        for (column, expected) in ALL_COLUMNS.iter().zip(names) {
            assert_eq!(column.name(), expected);
        }
    }
}
