//! High-level node lifecycle.
//!
//! Builds a libp2p [`NetworkService`], spawns the [`SyncDriver`],
//! attaches a [`SyncBackend`], and waits for `SIGINT`/`SIGTERM` before
//! shutting down. The backend is selected at startup based on
//! [`NodeConfig::chain_spec_path`].

use std::sync::Arc;
use std::time::Duration;

use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_network::Topic;
use neutrino_network::libp2p::identity::Keypair;
use neutrino_network::service::{NetworkCommand, NetworkError, NetworkEvent, NetworkService};
use neutrino_primitives::ChainSpec;
use neutrino_rpc::{RpcBackend, RpcStartError};
use neutrino_runtime_host::{
    ProgramProver, Sp1HostError, Sp1ProofSystem, WasmExecutor, expect_runtime_code_hash,
};
use neutrino_storage::Database;
use neutrino_sync::{SyncBackend, SyncDriver, SyncDriverConfig};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::chain_backend::ChainBackend;
use crate::chain_spec::{ChainSpecError, ChainSpecFile, decode_hex_exact};
use crate::config::{NodeConfig, NodeRole, ProvingBackend};
use crate::db::{NodeDb, NodeDbError};
use crate::producer::{BlockProducerConfig, run_block_producer};

/// Errors returned by [`run`].
#[derive(Debug, Error)]
pub enum NodeError {
    /// Multiaddr parsing failed for a listen / bootnode entry.
    #[error("invalid multiaddr `{addr}`: {source}")]
    InvalidMultiaddr {
        /// Offending multiaddr string.
        addr: String,
        /// Underlying error.
        #[source]
        source: neutrino_network::libp2p::multiaddr::Error,
    },
    /// Network service construction failed.
    #[error("network service error: {0}")]
    Network(#[from] NetworkError),
    /// Chain spec loading or validation failed.
    #[error("chain spec error: {0}")]
    ChainSpec(#[from] ChainSpecError),
    /// Engine initialisation failed.
    #[error("engine error: {0}")]
    Engine(String),
    /// Proposer key derivation failed.
    #[error("proposer key error: {0}")]
    ProposerKey(String),
    /// Driver loop failed.
    #[error("sync driver error: {0}")]
    Driver(#[from] neutrino_sync::SyncDriverError),
    /// Database backend failed to open or operate on its data directory.
    #[error("storage error: {0}")]
    Storage(#[from] NodeDbError),
    /// `data_dir` could not be created on disk.
    #[error("failed to create data directory `{path}`: {source}")]
    DataDir {
        /// Configured data directory.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Generic I/O surface (signal hookup, config read, ...).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The configured RPC listen address could not be parsed.
    #[error("rpc listen address `{addr}` is invalid: {source}")]
    RpcListen {
        /// Configured `host:port` string.
        addr: String,
        /// Parse error.
        #[source]
        source: std::net::AddrParseError,
    },
    /// Failed to start the JSON-RPC server.
    #[error("rpc server failed to start: {0}")]
    Rpc(#[from] RpcStartError),
    /// Failed to initialise the SP1 proof system (vk setup or disk cache I/O).
    #[error("proof system error: {0}")]
    ProofSystem(String),
}

/// Run the node until `SIGINT` or `SIGTERM` arrive.
///
/// # Errors
///
/// Surfaces any of the variants of [`NodeError`].
pub async fn run(config: NodeConfig) -> Result<(), NodeError> {
    config
        .proving
        .validate()
        .map_err(|error| NodeError::ProofSystem(error.into()))?;
    if config.role == NodeRole::LightClient {
        return Box::pin(run_with_prover(config, || {
            Ok(sp1_sdk::blocking::ProverClient::builder().light().build())
        }))
        .await;
    }
    match config.proving.backend {
        ProvingBackend::Cpu => {
            Box::pin(run_with_prover(config, || {
                Ok(sp1_sdk::blocking::ProverClient::builder().cpu().build())
            }))
            .await
        }
        ProvingBackend::Cuda => {
            #[cfg(feature = "cuda")]
            {
                let device = config.proving.cuda_device.unwrap_or(0);
                Box::pin(run_with_prover(config, move || {
                    neutrino_runtime_host::backend::cuda_prover(device)
                }))
                .await
            }
            #[cfg(not(feature = "cuda"))]
            Err(NodeError::ProofSystem(
                "CUDA requires --features cuda".into(),
            ))
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run_with_prover<P: ProgramProver + 'static>(
    config: NodeConfig,
    build_prover: impl FnOnce() -> Result<P, Sp1HostError>,
) -> Result<(), NodeError> {
    // Every node requires a `chain_spec_path`. Misconfigured deployments
    // must fail loudly instead of silently running an unreachable chain.
    let Some(chain_spec_path) = config.chain_spec_path.clone() else {
        return Err(NodeError::ChainSpec(ChainSpecError::Validation(
            "chain_spec_path is required; the stub backend was removed".to_owned(),
        )));
    };
    let spec_file = ChainSpecFile::load_from_path(&chain_spec_path)?;
    let chain_spec = spec_file.to_chain_spec()?;
    if chain_spec.chain_id != config.chain_id {
        return Err(NodeError::ChainSpec(ChainSpecError::Validation(format!(
            "chain spec chain_id {} does not match node config chain_id {}",
            chain_spec.chain_id, config.chain_id
        ))));
    }
    // Refuse to start when the chain spec advertises a
    // `runtime_code_hash` that does not match the WASM cdylib this
    // binary embeds. A silent mismatch would let the node compute
    // post-state-roots against a different runtime than the network
    // agreed on, producing a divergent chain at proof time.
    //
    if let Err((spec, actual)) = expect_runtime_code_hash(chain_spec.runtime_code_hash) {
        return Err(NodeError::ChainSpec(ChainSpecError::Validation(format!(
            "chain spec runtime_code_hash {} does not match embedded runtime {}; \
             refusing to start so the chain cannot diverge silently",
            hex_short(&spec),
            hex_short(&actual),
        ))));
    }
    if chain_spec
        .runtime
        .evidence_max_age_blocks
        .checked_add(chain_spec.consensus.chunk_size)
        .is_none_or(|window| window >= chain_spec.runtime.unbonding_delay_blocks)
    {
        return Err(NodeError::ChainSpec(ChainSpecError::Validation(
            "unbonding delay must exceed evidence window plus one chunk".into(),
        )));
    }
    let production_config = build_block_producer_config(&config, &chain_spec)?;
    let db = open_node_db(&config)?;
    let engine = open_or_initialise_engine(db, chain_spec)?;
    let prover = build_prover().map_err(|error| NodeError::ProofSystem(error.to_string()))?;
    let proof_system =
        Sp1ProofSystem::new(prover).map_err(|error| NodeError::ProofSystem(error.to_string()))?;
    info!(backend = ?config.proving.backend, cuda_device = ?config.proving.cuda_device,
        concurrency = config.proving.concurrency, "SP1 proving backend initialized");
    info!(
        chain_id = config.chain_id,
        backend = "ChainBackend",
        head_height = engine.head_height(),
        "using real engine backend"
    );
    let concrete_backend = Arc::new(ChainBackend::new(engine, proof_system));
    concrete_backend.set_proving_concurrency(config.proving.concurrency);
    if config.role == NodeRole::LightClient {
        let (spec, domain) = concrete_backend
            .history_profile()
            .map_err(NodeError::ProofSystem)?;
        let (anchor, trusted_at) = match (
            &config.light_client.trusted_checkpoint_path,
            config.light_client.trusted_at,
        ) {
            (Some(path), Some(trusted_at)) => {
                let bytes = std::fs::read(path)?;
                if bytes.len() > 1024 {
                    return Err(NodeError::ProofSystem(
                        "trusted checkpoint exceeds size limit".into(),
                    ));
                }
                let anchor = borsh::from_slice(&bytes).map_err(|error| {
                    NodeError::ProofSystem(format!("trusted checkpoint: {error}"))
                })?;
                (anchor, trusted_at)
            }
            (None, None) => (
                neutrino_consensus_types::history_proof::Checkpoint {
                    domain,
                    boundary: neutrino_consensus_types::history_proof::ConsensusBoundary::genesis(
                        &spec,
                    ),
                },
                spec.genesis_time,
            ),
            _ => {
                return Err(NodeError::ProofSystem(
                    "trusted_checkpoint_path and trusted_at must be configured together".into(),
                ));
            }
        };
        concrete_backend
            .initialize_light(
                anchor,
                trusted_at,
                config.light_client.max_future_drift_secs,
            )
            .map_err(NodeError::ProofSystem)?;
    } else {
        concrete_backend
            .set_retention_policy(config.role.retention_policy())
            .map_err(NodeError::ProofSystem)?;
        concrete_backend
            .initialize_history()
            .map_err(NodeError::ProofSystem)?;
        // Install the WASM block executor so the producer loop's
        // dry-run path can build SP1 witnesses. The embedded default-
        // runtime master cdylib is the only runtime today; on-chain
        // upgrades will install a different `WasmExecutor` per
        // activation epoch.
        let block_executor = WasmExecutor::default_runtime()
            .map_err(|err| NodeError::ProofSystem(err.to_string()))?;
        concrete_backend.set_block_executor(block_executor);
        if config.role == NodeRole::Archive {
            concrete_backend
                .discard_bootstrap_download()
                .map_err(NodeError::ProofSystem)?;
        } else {
            concrete_backend
                .initialize_bootstrap(&config.bootstrap)
                .map_err(NodeError::ProofSystem)?;
        }
    }
    let local_key = Keypair::generate_ed25519();
    let local_peer_id = neutrino_network::PeerId::from(local_key.public());
    info!(%local_peer_id, role = ?config.role, chain_id = config.chain_id, "starting node");

    let (cmd_tx, cmd_rx) = mpsc::channel::<NetworkCommand>(256);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(256);

    let mut svc = NetworkService::new(local_key, cmd_rx, event_tx)?;

    // Bind every configured listener.
    for addr in config.effective_listen() {
        let parsed = addr.parse().map_err(|source| NodeError::InvalidMultiaddr {
            addr: addr.clone(),
            source,
        })?;
        match svc.listen_on(parsed) {
            Ok(id) => info!(%addr, ?id, "listening"),
            Err(err) => warn!(%addr, ?err, "listen failed"),
        }
    }

    // Own every runner task from its first spawn. Dropping the set aborts
    // them on startup errors, signal errors or cancellation of this future.
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(svc.run());

    // Dial bootnodes if any.
    for addr in &config.bootnodes {
        let parsed = addr.parse().map_err(|source| NodeError::InvalidMultiaddr {
            addr: addr.clone(),
            source,
        })?;
        if cmd_tx.send(NetworkCommand::Dial(parsed)).await.is_err() {
            warn!(%addr, "network command channel closed while dialing bootnode");
        }
    }

    // Subscribe to gossip topics: caller-overridable, but Stage 5 just
    // subscribes to every canonical topic.
    let topics_to_subscribe: Vec<Topic> = config.subscribe_topics.as_ref().map_or_else(
        || {
            if config.role == NodeRole::LightClient {
                vec![Topic::Checkpoints]
            } else {
                Topic::all_default().collect()
            }
        },
        |names| {
            names
                .iter()
                .filter_map(|name| {
                    topic_from_name(name).or_else(|| {
                        warn!(topic = %name, "unknown topic name; ignoring");
                        None
                    })
                })
                .collect()
        },
    );
    for topic in topics_to_subscribe {
        if cmd_tx.send(NetworkCommand::Subscribe(topic)).await.is_err() {
            warn!(?topic, "network command channel closed before subscribe");
        }
    }

    // Enable the multi-validator chunk-BFT loop. Every node installs
    // the network publisher so peer-detected slashing evidence and
    // aggregator emissions can broadcast; validator nodes
    // additionally install their local voter so the engine signs
    // prevotes / precommits and routes through `QuorumReached`.
    // Non-validator nodes leave `local_voter` unset; the engine
    // still ingests peer votes but emits nothing.
    concrete_backend.set_network_publisher(cmd_tx.clone());
    if let Some(cfg) = production_config.as_ref() {
        concrete_backend.set_local_voter(cfg.proposer.clone());
    }
    concrete_backend
        .resume_bft_sessions()
        .await
        .map_err(NodeError::Engine)?;
    tasks.spawn(Arc::clone(&concrete_backend).run_consensus_proof_notifications());
    if concrete_backend.local_voter().is_some() {
        tasks.spawn(Arc::clone(&concrete_backend).run_bft_round_timeouts());
    }
    let producer_job = production_config.map(|cfg| (Arc::clone(&concrete_backend), cfg));
    let rpc_backend: Arc<dyn RpcBackend> = Arc::clone(&concrete_backend) as Arc<dyn RpcBackend>;
    let backend: Arc<dyn SyncBackend> = Arc::clone(&concrete_backend) as Arc<dyn SyncBackend>;

    let local_progress = backend
        .local_progress()
        .await
        .map_err(|error| NodeError::Engine(error.to_string()))?;
    let driver_cfg = SyncDriverConfig {
        mode: config.role.sync_mode(),
        ..SyncDriverConfig::default()
    };
    let driver = SyncDriver::new(
        driver_cfg,
        backend,
        local_progress,
        cmd_tx.clone(),
        event_rx,
    );
    concrete_backend.set_sync_status(driver.status());
    drop(concrete_backend);
    tasks.spawn(async move {
        if let Err(error) = driver.run().await {
            warn!(%error, "sync driver stopped with an error");
        }
    });
    if let Some((backend, production_config)) = producer_job {
        tasks.spawn(run_block_producer(
            backend,
            cmd_tx.clone(),
            production_config,
        ));
    }
    // Optional JSON-RPC server. Started after the engine is open so
    // the very first request observes a consistent head.
    let rpc_handle = if let Some(rpc_cfg) = config.rpc.as_ref() {
        let runtime_cfg = rpc_cfg
            .to_runtime_config()
            .map_err(|source| NodeError::RpcListen {
                addr: rpc_cfg.listen.clone(),
                source,
            })?;
        let listen = runtime_cfg.listen;
        let handle = neutrino_rpc::serve(Arc::clone(&rpc_backend), runtime_cfg).await?;
        info!(%listen, "rpc server listening");
        Some(handle)
    } else {
        info!("rpc disabled (no [rpc] section in node config)");
        None
    };
    // Suppress the "unused" warning for nodes that never request RPC.
    let _ = &rpc_backend;

    // Clean up even when installing a signal handler fails. ServerHandle's
    // final drop also stops RPC if the caller cancels this whole future.
    let shutdown = wait_for_shutdown().await;
    if shutdown.is_ok() {
        info!("shutdown signal received");
    }

    // Abort the driver too: it owns command senders and backend/DB references,
    // so dropping only our sender cannot shut down the network task.
    tasks.abort_all();
    if let Some(handle) = rpc_handle.as_ref() {
        let _ = handle.stop();
    }
    drop(cmd_tx);

    // Give tasks a brief grace period to flush logs.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        tasks.shutdown().await;
        if let Some(handle) = rpc_handle {
            handle.stopped().await;
        }
    })
    .await;

    info!("node stopped");
    shutdown?;
    Ok(())
}

fn topic_from_name(name: &str) -> Option<Topic> {
    Topic::all_default().find(|t| t.protocol_string() == name)
}

fn open_node_db(config: &NodeConfig) -> Result<NodeDb, NodeError> {
    let Some(path) = &config.data_dir else {
        info!(
            backend = "memory",
            "no data_dir configured; using in-memory backend"
        );
        return Ok(NodeDb::memory());
    };
    std::fs::create_dir_all(path).map_err(|source| NodeError::DataDir {
        path: path.display().to_string(),
        source,
    })?;
    info!(backend = "rocksdb", path = %path.display(), "opened persistent data directory");
    Ok(NodeDb::open_rocks(path)?)
}

fn open_or_initialise_engine(
    db: NodeDb,
    chain_spec: ChainSpec,
) -> Result<Engine<NodeDb>, NodeError> {
    let already_initialised = db
        .get(
            neutrino_storage::Column::Meta,
            neutrino_consensus_engine::pointers::CHAIN_SPEC_HASH,
        )
        .map_err(NodeError::Storage)?
        .is_some();
    if already_initialised {
        let engine =
            Engine::open(chain_spec, db).map_err(|err| NodeError::Engine(err.to_string()))?;
        info!(
            head_height = engine.head_height(),
            recursive_covered_chunks = engine.recursive_covered_chunks(),
            "engine resumed from persistent state"
        );
        Ok(engine)
    } else {
        let engine =
            Engine::genesis(chain_spec, db).map_err(|err| NodeError::Engine(err.to_string()))?;
        info!("engine initialised at genesis");
        Ok(engine)
    }
}

fn build_block_producer_config(
    config: &NodeConfig,
    chain_spec: &ChainSpec,
) -> Result<Option<BlockProducerConfig>, NodeError> {
    if config.role != NodeRole::Validator {
        return Ok(None);
    }
    let Some(ikm_hex) = &config.proposer_ikm_hex else {
        warn!("validator role configured without proposer_ikm_hex; block production disabled");
        return Ok(None);
    };

    let proposer_index = config.proposer_index.unwrap_or(0);
    let ikm = decode_hex_exact::<32>(ikm_hex, "proposer_ikm_hex")?;
    let proposer = ProposerKey::from_ikm(&ikm, proposer_index)
        .map_err(|err| NodeError::ProposerKey(err.to_string()))?;

    // The configured position is a hint. Engine signing resolves the key's
    // position in the authenticated live set after replay or checkpoint bootstrap.
    Ok(Some(BlockProducerConfig {
        proving: config.proving,
        proposer,
        genesis_time_secs: chain_spec.genesis_time,
        slot_duration_secs: chain_spec.consensus.slot_duration_secs,
    }))
}

/// Short hex preview for log lines / error messages. Truncates to
/// the first 8 bytes so a `Display::fmt` of a hash stays readable.
fn hex_short(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(18);
    for b in &bytes[..8] {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s.push_str("..");
    s
}

async fn wait_for_shutdown() -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = sigint.recv() => Ok(()),
            _ = sigterm.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[cfg(test)]
mod tests {
    use super::{Topic, topic_from_name};

    #[test]
    fn configured_topics_include_valid_aggregate_subnets() {
        assert_eq!(
            topic_from_name("/neutrino/aggregate_finality_votes_0/borsh"),
            Some(Topic::AggregateFinalityVotes(0))
        );
        assert_eq!(
            topic_from_name("/neutrino/aggregate_finality_votes_15/borsh"),
            Some(Topic::AggregateFinalityVotes(15))
        );
        assert_eq!(
            topic_from_name("/neutrino/aggregate_finality_votes_16/borsh"),
            None
        );
        assert_eq!(topic_from_name("/unknown/topic"), None);
    }
}
