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
    /// Data directory for the chain database. Optional — when unset the
    /// node runs against an in-memory backend (useful for ephemeral
    /// test containers).
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    /// Gossip topics to subscribe to on startup. Defaults to all canonical
    /// topics from `docs/design/06-networking.md`.
    #[serde(default)]
    pub subscribe_topics: Option<Vec<String>>,
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
