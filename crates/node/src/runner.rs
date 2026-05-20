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
use neutrino_runtime_host::{Sp1ProofSystem, WasmExecutor};
use sp1_sdk::blocking::CpuProver;

/// Concrete `ChainBackend` parameterisation used by the production
/// node binary: RocksDB-backed `NodeDb` storage + SP1 CPU prover.
type NodeBackend = ChainBackend<NodeDb, Sp1ProofSystem<CpuProver>>;
use neutrino_rpc::{RpcBackend, RpcStartError};
use neutrino_storage::Database;
use neutrino_sync::{SyncBackend, SyncDriver, SyncDriverConfig};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::chain_backend::ChainBackend;
use crate::chain_spec::{ChainSpecError, ChainSpecFile, decode_hex_exact};
use crate::config::{NodeConfig, NodeRole};
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
#[allow(clippy::too_many_lines)]
pub async fn run(config: NodeConfig) -> Result<(), NodeError> {
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

    // Spawn the network service.
    let network_handle = tokio::spawn(svc.run());

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
        || Topic::STATIC.to_vec(),
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

    // Every node now requires a `chain_spec_path`; the stub fallback
    // from earlier M6 bring-up was removed once the persistent
    // ChainBackend stabilised. Misconfigured deployments must fail
    // loudly instead of silently running an unreachable chain.
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
    let production_config = build_block_producer_config(&config, &chain_spec)?;
    let chain_spec_slot_duration = chain_spec.consensus.slot_duration_secs;
    let db = open_node_db(&config)?;
    let engine = open_or_initialise_engine(db, chain_spec)?;
    // SP1 CPU prover for production. Setup is paid once (then cached
    // to disk by `Sp1ProofSystem::new`), so subsequent node restarts
    // are fast. CudaProver / NetworkProver swap in here later.
    let cpu_prover = sp1_sdk::blocking::ProverClient::builder().cpu().build();
    let proof_system =
        Sp1ProofSystem::new(cpu_prover).map_err(|err| NodeError::ProofSystem(err.to_string()))?;
    info!(
        chain_id = config.chain_id,
        backend = "ChainBackend",
        head_height = engine.head_height(),
        "using real engine backend"
    );
    let concrete_backend = Arc::new(ChainBackend::new(engine, proof_system));
    // Install the WASM block executor so the producer loop's
    // dry-run path can build SP1 witnesses. The embedded default-
    // runtime master cdylib is the only runtime today; on-chain
    // upgrades will install a different `WasmExecutor` per
    // activation epoch.
    let block_executor =
        WasmExecutor::default_runtime().map_err(|err| NodeError::ProofSystem(err.to_string()))?;
    concrete_backend.set_block_executor(block_executor);
    let producer_job: Option<(Arc<NodeBackend>, BlockProducerConfig)> =
        production_config.map(|cfg| (Arc::clone(&concrete_backend), cfg));
    let rpc_backend: Arc<dyn RpcBackend> = Arc::clone(&concrete_backend) as Arc<dyn RpcBackend>;
    let backend: Arc<dyn SyncBackend> = concrete_backend;

    let local_progress = backend.local_progress().await;
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
    let driver_handle = tokio::spawn(driver.run());
    let producer_handle = producer_job.map(|(backend, production_config)| {
        tokio::spawn(run_block_producer(
            backend,
            cmd_tx.clone(),
            production_config,
        ))
    });
    let injector_handle = config.inject_test_transactions_per_slot.and_then(|count| {
        if count == 0 {
            return None;
        }
        let slot_duration = chain_spec_slot_duration;
        Some(tokio::spawn(crate::tx_injector::run_tx_injector(
            cmd_tx.clone(),
            slot_duration,
            count,
        )))
    });

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

    // Wait for shutdown signal.
    wait_for_shutdown().await?;
    info!("shutdown signal received");

    // Closing the command channel triggers the network service to stop;
    // dropping the channels propagates to the driver loop.
    if let Some(handle) = producer_handle.as_ref() {
        handle.abort();
    }
    if let Some(handle) = injector_handle.as_ref() {
        handle.abort();
    }
    if let Some(handle) = rpc_handle.as_ref() {
        let _ = handle.stop();
    }
    drop(cmd_tx);

    // Give tasks a brief grace period to flush logs.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let _ = network_handle.await;
        let _ = driver_handle.await;
        if let Some(handle) = producer_handle {
            let _ = handle.await;
        }
        if let Some(handle) = injector_handle {
            let _ = handle.await;
        }
        if let Some(handle) = rpc_handle {
            handle.stopped().await;
        }
    })
    .await;

    info!("node stopped");
    Ok(())
}

fn topic_from_name(name: &str) -> Option<Topic> {
    Topic::STATIC
        .iter()
        .copied()
        .find(|t| t.protocol_string() == name)
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
            latest_checkpoint_index = engine.latest_checkpoint_index(),
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

    let index = usize::try_from(proposer_index).expect("u32 fits usize on supported targets");
    let validator = chain_spec.initial_validators.get(index).ok_or_else(|| {
        NodeError::ChainSpec(ChainSpecError::Validation(format!(
            "proposer_index {proposer_index} is outside initial validator set"
        )))
    })?;
    if validator.pubkey != *proposer.public_key_bytes() {
        return Err(NodeError::ChainSpec(ChainSpecError::Validation(format!(
            "proposer key does not match validator pubkey at index {proposer_index}"
        ))));
    }

    Ok(Some(BlockProducerConfig {
        proposer,
        genesis_time_secs: chain_spec.genesis_time,
        slot_duration_secs: chain_spec.consensus.slot_duration_secs,
    }))
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
