//! TOML configuration for [`crate::run`].

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Environment variable that supplies the validator's BLS IKM as hex.
/// Takes precedence over `proposer_ikm_path` and `proposer_ikm_hex`.
pub const PROPOSER_IKM_ENV: &str = "NEUTRINO_PROPOSER_IKM_HEX";

/// Self-declared role for the node.
///
/// Selects full execution or proof-only synchronization and storage.
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
    /// Archive nodes keep source history; full nodes retain the protocol window.
    #[must_use]
    pub const fn retention_policy(self) -> neutrino_consensus_engine::RetentionPolicy {
        match self {
            Self::Archive => neutrino_consensus_engine::RetentionPolicy::Archive,
            Self::Validator | Self::Full | Self::LightClient => {
                neutrino_consensus_engine::RetentionPolicy::Pruned
            }
        }
    }

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
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Self-declared role (validator / full / archive / light).
    #[serde(default)]
    pub role: NodeRole,
    /// Chain id this node participates in.
    pub chain_id: u64,
    /// Proving backend, global concurrency and bounded block queue capacity.
    #[serde(default)]
    pub proving: ProvingConfig,
    /// Explicit local trust anchor and time policy for proof-only operation.
    #[serde(default)]
    pub light_client: LightClientConfig,
    /// Full/validator checkpoint bootstrap and local weak-subjectivity policy.
    #[serde(default)]
    pub bootstrap: BootstrapConfig,
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
    /// Inline hex-encoded BLS IKM (32 bytes). Convenient for tests only:
    /// the runner warns when a validator key is read from the config
    /// file itself. Prefer [`PROPOSER_IKM_ENV`] or `proposer_ikm_path`.
    #[serde(default)]
    pub proposer_ikm_hex: Option<String>,
    /// File holding the hex-encoded BLS IKM. On Unix the file must not be
    /// readable by group or others; the runner refuses looser modes.
    #[serde(default)]
    pub proposer_ikm_path: Option<PathBuf>,
    /// Fuel and memory budgets for WASM queries and admission checks.
    #[serde(default)]
    pub execution: ExecutionLimitsConfig,
    /// Initial position hint; signing resolves the public key in the authenticated active set.
    #[serde(default)]
    pub proposer_index: Option<u32>,
    /// Gossip topics to subscribe to on startup. Defaults to all canonical
    /// topics from `docs/design/06-networking.md`.
    #[serde(default)]
    pub subscribe_topics: Option<Vec<String>>,
    /// JSON-RPC server configuration. When omitted, no RPC listener
    /// is started; the node still functions for consensus and gossip
    /// but external observers have no read API.
    #[serde(default)]
    pub rpc: Option<RpcConfigToml>,
}

/// Local weak-subjectivity trust configuration. Peers cannot supply this anchor.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LightClientConfig {
    /// Local file containing a Borsh-encoded trusted `Checkpoint`.
    /// When omitted, the chain specification's genesis is the anchor.
    pub trusted_checkpoint_path: Option<std::path::PathBuf>,
    /// Unix time at which the explicit checkpoint was independently trusted.
    /// Must accompany `trusted_checkpoint_path`; genesis uses `genesis_time`.
    pub trusted_at: Option<u64>,
    /// Maximum tolerated future endpoint timestamp, in seconds.
    pub max_future_drift_secs: u64,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        Self {
            trusted_checkpoint_path: None,
            trusted_at: None,
            max_future_drift_secs: 30,
        }
    }
}

/// Full-node state bootstrap. Archive nodes always replay complete source history.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BootstrapConfig {
    /// Enable proof-backed state bootstrap when the local finalized anchor is behind.
    pub enabled: bool,
    /// Optional independently trusted checkpoint file, never selected by peers.
    pub trusted_checkpoint_path: Option<std::path::PathBuf>,
    /// Original local trust time, required with the checkpoint file.
    pub trusted_at: Option<u64>,
    /// Maximum accepted future endpoint timestamp.
    pub max_future_drift_secs: u64,
}
impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_checkpoint_path: None,
            trusted_at: None,
            max_future_drift_secs: 30,
        }
    }
}

/// Where the validator IKM was read from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposerIkmSource {
    /// [`PROPOSER_IKM_ENV`].
    Environment,
    /// `proposer_ikm_path`.
    File,
    /// `proposer_ikm_hex` inline in the config file.
    Inline,
}

/// Failure to obtain the validator IKM from the configured sources.
#[derive(Debug, thiserror::Error)]
pub enum ProposerIkmError {
    /// The key file could not be read.
    #[error("failed to read proposer_ikm_path `{path}`: {source}")]
    Read {
        /// Configured path.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The key file is readable by group or others.
    #[error("proposer_ikm_path `{path}` has mode {mode:o}; it must not be group or world readable")]
    Permissions {
        /// Configured path.
        path: String,
        /// Observed permission bits.
        mode: u32,
    },
    /// The environment variable is set but not valid UTF-8.
    #[error("{PROPOSER_IKM_ENV} is not valid UTF-8")]
    Environment,
}

impl NodeConfig {
    /// Resolve the validator IKM hex: environment, then key file, then inline.
    ///
    /// Returns `Ok(None)` when no source is configured.
    ///
    /// # Errors
    /// Returns [`ProposerIkmError`] when a configured source is unreadable
    /// or the key file is too permissive.
    pub fn resolve_proposer_ikm_hex(
        &self,
    ) -> Result<Option<(String, ProposerIkmSource)>, ProposerIkmError> {
        match std::env::var(PROPOSER_IKM_ENV) {
            Ok(value) if !value.trim().is_empty() => {
                return Ok(Some((
                    value.trim().to_owned(),
                    ProposerIkmSource::Environment,
                )));
            }
            Err(std::env::VarError::NotUnicode(_)) => return Err(ProposerIkmError::Environment),
            _ => {}
        }
        if let Some(path) = &self.proposer_ikm_path {
            let hex = read_secret_file(path)?;
            return Ok(Some((hex, ProposerIkmSource::File)));
        }
        Ok(self
            .proposer_ikm_hex
            .as_ref()
            .map(|hex| (hex.trim().to_owned(), ProposerIkmSource::Inline)))
    }
}

/// Read a single-line hex secret, refusing files other users can read.
fn read_secret_file(path: &Path) -> Result<String, ProposerIkmError> {
    let display = path.display().to_string();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|source| ProposerIkmError::Read {
                path: display.clone(),
                source,
            })?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(ProposerIkmError::Permissions {
                path: display,
                mode,
            });
        }
    }
    let raw = std::fs::read_to_string(path).map_err(|source| ProposerIkmError::Read {
        path: display,
        source,
    })?;
    Ok(raw.trim().to_owned())
}

/// Fuel and linear-memory budgets for untrusted WASM entrypoints.
///
/// Mirrors [`neutrino_runtime_host::wasm::WasmLimits`]; see there for the
/// semantics. Block execution keeps unlimited fuel because the header gas
/// limit already bounds it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionLimitsConfig {
    /// Fuel for one RPC `runtime_call` query.
    pub query_fuel: u64,
    /// Memory cap in bytes for one RPC query.
    pub query_memory_bytes: usize,
    /// Fuel for one mempool admission check.
    pub validate_tx_fuel: u64,
    /// Memory cap in bytes for one admission check.
    pub validate_tx_memory_bytes: usize,
    /// Memory cap in bytes for one block dry run.
    pub block_memory_bytes: usize,
}

impl Default for ExecutionLimitsConfig {
    fn default() -> Self {
        let limits = neutrino_runtime_host::wasm::WasmLimits::default();
        Self {
            query_fuel: limits.query_fuel,
            query_memory_bytes: limits.query_memory_bytes,
            validate_tx_fuel: limits.validate_tx_fuel,
            validate_tx_memory_bytes: limits.validate_tx_memory_bytes,
            block_memory_bytes: limits.block_memory_bytes,
        }
    }
}

impl ExecutionLimitsConfig {
    /// Convert into the runtime-host limit set.
    #[must_use]
    pub const fn to_wasm_limits(self) -> neutrino_runtime_host::wasm::WasmLimits {
        neutrino_runtime_host::wasm::WasmLimits {
            query_fuel: self.query_fuel,
            query_memory_bytes: self.query_memory_bytes,
            validate_tx_fuel: self.validate_tx_fuel,
            validate_tx_memory_bytes: self.validate_tx_memory_bytes,
            block_memory_bytes: self.block_memory_bytes,
        }
    }
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
    /// Requests executing at once across all connections. Defaults to 64.
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: u32,
    /// Sustained per-connection request rate; burst is twice this.
    /// Defaults to 50.
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second_per_connection: u32,
    /// Maximum entries per JSON-RPC batch. Defaults to 16.
    #[serde(default = "default_max_batch_requests")]
    pub max_batch_requests: u32,
    /// Wall-clock budget for one `runtime_call`, in milliseconds.
    /// Defaults to 2000.
    #[serde(default = "default_runtime_call_timeout_ms")]
    pub runtime_call_timeout_ms: u64,
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
const fn default_max_concurrent_requests() -> u32 {
    64
}
const fn default_requests_per_second() -> u32 {
    50
}
const fn default_max_batch_requests() -> u32 {
    16
}
const fn default_runtime_call_timeout_ms() -> u64 {
    2000
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
            max_concurrent_requests: self.max_concurrent_requests,
            requests_per_second_per_connection: self.requests_per_second_per_connection,
            max_batch_requests: self.max_batch_requests,
            runtime_call_timeout: Duration::from_millis(self.runtime_call_timeout_ms),
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
    fn rpc_limits_default_and_parse() {
        let cfg: NodeConfig = toml::from_str(
            r#"
chain_id = 1
[rpc]
listen = "127.0.0.1:9933"
max_concurrent_requests = 8
runtime_call_timeout_ms = 250
[execution]
query_fuel = 1000000
"#,
        )
        .unwrap();
        let rpc = cfg.rpc.unwrap().to_runtime_config().unwrap();
        assert_eq!(rpc.max_concurrent_requests, 8);
        assert_eq!(rpc.requests_per_second_per_connection, 50);
        assert_eq!(rpc.max_batch_requests, 16);
        assert_eq!(rpc.runtime_call_timeout, Duration::from_millis(250));
        let limits = cfg.execution.to_wasm_limits();
        assert_eq!(limits.query_fuel, 1_000_000);
        assert_eq!(
            limits.validate_tx_fuel,
            neutrino_runtime_host::wasm::WasmLimits::default().validate_tx_fuel
        );
    }

    #[test]
    fn proposer_ikm_prefers_file_over_inline_and_checks_permissions() {
        let dir = std::env::temp_dir().join(format!("neutrino-ikm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("validator.ikm");
        std::fs::write(&path, "  aa".repeat(16) + "\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let cfg = NodeConfig {
                chain_id: 1,
                proposer_ikm_path: Some(path.clone()),
                ..NodeConfig::default()
            };
            assert!(matches!(
                cfg.resolve_proposer_ikm_hex(),
                Err(ProposerIkmError::Permissions { .. })
            ));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(&path, format!("{}\n", "ab".repeat(32))).unwrap();
        let cfg = NodeConfig {
            chain_id: 1,
            proposer_ikm_path: Some(path),
            proposer_ikm_hex: Some("cd".repeat(32)),
            ..NodeConfig::default()
        };
        let (hex, source) = cfg.resolve_proposer_ikm_hex().unwrap().unwrap();
        assert_eq!(source, ProposerIkmSource::File);
        assert_eq!(hex, "ab".repeat(32));
        let inline = NodeConfig {
            chain_id: 1,
            proposer_ikm_hex: Some("cd".repeat(32)),
            ..NodeConfig::default()
        };
        assert_eq!(
            inline.resolve_proposer_ikm_hex().unwrap().unwrap().1,
            ProposerIkmSource::Inline
        );
        assert!(
            NodeConfig {
                chain_id: 1,
                ..NodeConfig::default()
            }
            .resolve_proposer_ikm_hex()
            .unwrap()
            .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rpc_config_omitted_means_no_rpc_listener() {
        let cfg: NodeConfig = toml::from_str("chain_id = 1\n").expect("parse minimal config");
        assert!(cfg.rpc.is_none());
    }

    #[test]
    fn proving_defaults_to_cpu_and_parses_explicit_cuda_device() {
        let cfg: NodeConfig = toml::from_str("chain_id = 1").unwrap();
        assert_eq!(cfg.proving.backend, ProvingBackend::Cpu);
        assert_eq!(cfg.proving.cuda_device, None);
        assert_eq!(cfg.proving.concurrency, 2);
        assert_eq!(cfg.proving.capacity, 16);
        assert!(cfg.proving.validate().is_ok());
        let cfg: NodeConfig = toml::from_str(
            "chain_id = 1\n[proving]\nbackend = 'cuda'\ncuda_device = 3\nconcurrency = 1",
        )
        .unwrap();
        assert_eq!(cfg.proving.backend, ProvingBackend::Cuda);
        assert_eq!(cfg.proving.cuda_device, Some(3));
        assert_eq!(cfg.proving.concurrency, 1);
        assert_eq!(cfg.proving.capacity, 16);
    }

    #[test]
    fn proving_rejects_unknown_backends_fields_and_invalid_budgets() {
        for options in [
            "backend = 'mock'",
            "backend = 'network'",
            "backned = 'cuda'",
            "cuda_device = -1",
        ] {
            assert!(
                toml::from_str::<NodeConfig>(&format!("chain_id = 1\n[proving]\n{options}"))
                    .is_err()
            );
        }
        for options in [
            "cuda_device = 0",
            "concurrency = 0",
            "concurrency = 65",
            "concurrency = 3\ncapacity = 2",
            "capacity = 1025",
        ] {
            let cfg: NodeConfig =
                toml::from_str(&format!("chain_id = 1\n[proving]\n{options}")).unwrap();
            assert!(cfg.proving.validate().is_err(), "accepted {options}");
        }
    }

    #[tokio::test]
    async fn invalid_proving_config_fails_before_network_and_chain_spec_for_every_role() {
        for role in ["validator", "full", "archive", "light-client"] {
            let cfg: NodeConfig = toml::from_str(&format!(
                "chain_id = 1\nrole = '{role}'\n[proving]\ncuda_device = 0"
            ))
            .unwrap();
            assert!(matches!(
                crate::run(cfg).await,
                Err(crate::NodeError::ProofSystem(_))
            ));
        }
    }

    #[cfg(not(all(feature = "cuda", target_os = "linux", target_arch = "x86_64")))]
    #[tokio::test]
    async fn unsupported_cuda_is_rejected_without_cpu_fallback() {
        let cfg: NodeConfig = toml::from_str("chain_id = 1\n[proving]\nbackend = 'cuda'").unwrap();
        let Err(crate::NodeError::ProofSystem(error)) = crate::run(cfg).await else {
            panic!("unsupported CUDA must fail before any node services start");
        };
        let expected = if cfg!(feature = "cuda") {
            "Linux x86-64"
        } else {
            "--features cuda"
        };
        assert!(error.contains(expected), "{error}");
    }
}

/// Backend used by every proof stage in this node.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProvingBackend {
    /// Local CPU proving, supported on all host platforms.
    #[default]
    Cpu,
    /// Local NVIDIA CUDA proving on Linux x86-64; requires the `cuda` feature.
    Cuda,
}

/// Selects the prover, global concurrency and block queue capacity.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProvingConfig {
    /// Shared backend for fact, evidence, block, chunk and history proofs.
    pub backend: ProvingBackend,
    /// CUDA device index (default 0). Invalid with the CPU backend.
    pub cuda_device: Option<u32>,
    /// Maximum simultaneous proving calls across all proof stages.
    pub concurrency: usize,
    /// Maximum queued plus running blocks, including restart recovery.
    pub capacity: usize,
}

impl Default for ProvingConfig {
    fn default() -> Self {
        Self {
            backend: ProvingBackend::Cpu,
            cuda_device: None,
            concurrency: 2,
            capacity: 16,
        }
    }
}

impl ProvingConfig {
    /// Validate budgets and backend support before starting node services.
    ///
    /// # Errors
    /// Rejects invalid budgets, CPU device options and unavailable CUDA builds.
    pub const fn validate(self) -> Result<(), &'static str> {
        if self.concurrency == 0
            || self.concurrency > 64
            || self.capacity < self.concurrency
            || self.capacity > 1024
        {
            return Err("proving requires 1..=64 workers and workers <= capacity <= 1024");
        }
        match self.backend {
            ProvingBackend::Cpu if self.cuda_device.is_some() => {
                Err("proving.cuda_device requires backend = cuda")
            }
            ProvingBackend::Cpu => Ok(()),
            ProvingBackend::Cuda if !cfg!(feature = "cuda") => {
                Err("CUDA requires building neutrino-node with --features cuda")
            }
            ProvingBackend::Cuda => neutrino_runtime_host::backend::ensure_cuda_available(),
        }
    }
}
