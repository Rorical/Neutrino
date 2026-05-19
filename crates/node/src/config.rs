//! TOML configuration for [`crate::run`].

use serde::Deserialize;
use std::net::SocketAddr;

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
    /// Path to a `chain-spec.toml` file. The runner rejects configs that
    /// leave this unset.
    #[serde(default)]
    pub chain_spec_path: Option<String>,
    /// Data directory for the chain database. Optional — when unset the
    /// node runs against an in-memory backend (useful for ephemeral
    /// test containers).
    #[serde(default)]
    pub data_dir: Option<std::path::PathBuf>,
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
    /// JSON-RPC server configuration. When omitted, no RPC listener
    /// is started; the node still functions for consensus and gossip
    /// but external observers have no read API.
    #[serde(default)]
    pub rpc: Option<RpcConfigToml>,
}

/// TOML-deserialisable mirror of [`neutrino_rpc::RpcConfig`].
#[derive(Clone, Debug, Deserialize)]
pub struct RpcConfigToml {
    /// `host:port` to bind on. Examples: `"127.0.0.1:9933"` for
    /// local-only, `"0.0.0.0:9933"` to listen on every interface.
    pub listen: String,
    /// Maximum concurrent connections. Defaults to `200`.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Maximum size of a single request body in bytes. Defaults to
    /// 10 MiB.
    #[serde(default = "default_max_request_body_size")]
    pub max_request_body_size: u32,
    /// Maximum size of a single response body in bytes. Defaults to
    /// 15 MiB.
    #[serde(default = "default_max_response_body_size")]
    pub max_response_body_size: u32,
}

const fn default_max_connections() -> u32 {
    200
}
const fn default_max_request_body_size() -> u32 {
    10 * 1024 * 1024
}
const fn default_max_response_body_size() -> u32 {
    15 * 1024 * 1024
}

impl RpcConfigToml {
    /// Parse the configured `listen` address into a [`SocketAddr`] and
    /// build the runtime [`neutrino_rpc::RpcConfig`].
    pub fn to_runtime_config(&self) -> Result<neutrino_rpc::RpcConfig, std::net::AddrParseError> {
        let listen: SocketAddr = self.listen.parse()?;
        Ok(neutrino_rpc::RpcConfig {
            listen,
            max_connections: self.max_connections,
            max_request_body_size: self.max_request_body_size,
            max_response_body_size: self.max_response_body_size,
        })
    }
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
proposer_ikm_hex = "4242424242424242424242424242424242424242424242424242424242424242"
proposer_index = 3
"#,
        )
        .expect("parse node config");

        assert_eq!(cfg.role, NodeRole::Validator);
        assert_eq!(cfg.proposer_index, Some(3));
        assert!(cfg.proposer_ikm_hex.is_some());
    }

    #[test]
    fn parses_rpc_config_section() {
        let cfg: NodeConfig = toml::from_str(
            r#"
chain_id = 1

[rpc]
listen = "127.0.0.1:9933"
max_connections = 64
"#,
        )
        .expect("parse node config with rpc");

        let rpc = cfg.rpc.expect("rpc section present");
        assert_eq!(rpc.listen, "127.0.0.1:9933");
        assert_eq!(rpc.max_connections, 64);
        // Defaults filled in for unspecified fields.
        assert_eq!(rpc.max_request_body_size, 10 * 1024 * 1024);
        assert_eq!(rpc.max_response_body_size, 15 * 1024 * 1024);

        let runtime_cfg = rpc.to_runtime_config().expect("listen parses");
        assert_eq!(runtime_cfg.listen.port(), 9933);
        assert_eq!(runtime_cfg.max_connections, 64);
    }

    #[test]
    fn rpc_config_omitted_means_no_rpc_listener() {
        let cfg: NodeConfig = toml::from_str("chain_id = 1\n").expect("parse minimal config");
        assert!(cfg.rpc.is_none());
    }
}
