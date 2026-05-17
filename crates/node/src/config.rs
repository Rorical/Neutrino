//! TOML configuration for [`crate::run`].

use std::path::PathBuf;

use serde::Deserialize;

/// Self-declared role for the node.
///
/// This currently only feeds the FSM's [`SyncMode`](neutrino_sync::SyncMode)
/// and a future role-flag bitmap advertised in the metadata RPC.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    /// Full validator node.
    #[default]
    Validator,
    /// Full non-validator node.
    Full,
    /// Light client.
    LightClient,
    /// Archive node.
    Archive,
}

impl NodeRole {
    /// Map the role to the FSM sync mode.
    #[must_use]
    pub const fn sync_mode(self) -> neutrino_sync::SyncMode {
        match self {
            Self::LightClient => neutrino_sync::SyncMode::LightClient,
            Self::Archive => neutrino_sync::SyncMode::Archive,
            Self::Validator | Self::Full => neutrino_sync::SyncMode::Snap,
        }
    }
}

/// Node configuration loaded from TOML.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct NodeConfig {
    /// Self-declared role (validator / full / archive / light).
    #[serde(default)]
    pub role: NodeRole,
    /// Chain id this node participates in.
    pub chain_id: u64,
    /// Bind addresses (multiaddr) the libp2p listener attaches to.
    ///
    /// Defaults to `/ip4/0.0.0.0/tcp/0` if empty.
    #[serde(default)]
    pub listen: Vec<String>,
    /// Bootnode multiaddrs to dial on startup.
    #[serde(default)]
    pub bootnodes: Vec<String>,
    /// Optional path to a `chain-spec.toml` file. When set, the node
    /// bootstraps a real [`ChainSpec`]-backed engine via
    /// [`ChainBackend`](crate::ChainBackend). When unset, the stub
    /// backend is used.
    #[serde(default)]
    pub chain_spec_path: Option<String>,
    /// Data directory for the chain database. Optional — when unset the
    /// node runs against an in-memory backend (useful for ephemeral
    /// test containers).
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    /// Optional runtime ELF path. When set, the node hashes this ELF into
    /// the loaded chain spec if the chain-spec file omits
    /// `runtime_code_hash_hex`; validators also execute it for local block
    /// production.
    #[serde(default)]
    pub runtime_elf_path: Option<PathBuf>,
    /// Optional hex-encoded BLS IKM (32 bytes) used to derive the local
    /// proposer key for validator block production.
    #[serde(default)]
    pub proposer_ikm_hex: Option<String>,
    /// Validator index paired with [`Self::proposer_ikm_hex`].
    #[serde(default)]
    pub proposer_index: Option<u32>,
    /// Gossip topics to subscribe to on startup. Defaults to all canonical
    /// topics from `docs/design/06-networking.md`.
    #[serde(default)]
    pub subscribe_topics: Option<Vec<String>>,
    /// When set, the node spawns a deterministic test-transaction
    /// generator that publishes this many synthetic deposits per slot
    /// on `/neutrino/txs/borsh/1`. Used by the integration smoke test
    /// to exercise the full mempool path (gossip in -> admission ->
    /// produced block) without a separate tx-submission RPC. Leave
    /// unset on production nodes.
    #[serde(default)]
    pub inject_test_transactions_per_slot: Option<u32>,
}

impl NodeConfig {
    /// Default listen multiaddr used when `listen` is empty.
    pub const DEFAULT_LISTEN: &'static str = "/ip4/0.0.0.0/tcp/0";

    /// Effective listen addresses.
    #[must_use]
    pub fn effective_listen(&self) -> Vec<String> {
        if self.listen.is_empty() {
            vec![Self::DEFAULT_LISTEN.to_owned()]
        } else {
            self.listen.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_validator_production_fields() {
        let cfg: NodeConfig = toml::from_str(
            r#"
chain_id = 7
role = "validator"
runtime_elf_path = "/runtime/default.elf"
proposer_ikm_hex = "4242424242424242424242424242424242424242424242424242424242424242"
proposer_index = 3
"#,
        )
        .expect("parse node config");

        assert_eq!(cfg.role, NodeRole::Validator);
        assert_eq!(
            cfg.runtime_elf_path,
            Some(PathBuf::from("/runtime/default.elf"))
        );
        assert_eq!(cfg.proposer_index, Some(3));
        assert!(cfg.proposer_ikm_hex.is_some());
    }
}
