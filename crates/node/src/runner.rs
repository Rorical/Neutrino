//! High-level node lifecycle.
//!
//! Builds a libp2p [`NetworkService`], spawns the [`SyncDriver`],
//! attaches a [`SyncBackend`], and waits for `SIGINT`/`SIGTERM` before
//! shutting down. The backend is selected at startup based on
//! [`NodeConfig::chain_spec_path`].

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_network::Topic;
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
use crate::supervision::{TaskFailure, TaskSupervisor};

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
    /// The persisted P2P identity could not be loaded or created.
    #[error("network identity error: {0}")]
    NetworkIdentity(String),
    /// A worker required for the node lifetime stopped unexpectedly.
    #[error("critical task `{task}` stopped: {reason}")]
    CriticalTask {
        /// Name registered by the runner or backend.
        task: &'static str,
        /// Failure or unexpected completion.
        reason: String,
    },
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
    /// The configured metrics listen address could not be parsed or bound.
    #[error("metrics listen address `{addr}` is invalid or unavailable: {reason}")]
    MetricsListen {
        /// Configured `host:port` string.
        addr: String,
        /// Parse or bind failure.
        reason: String,
    },
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
    config.health.validate().map_err(NodeError::Engine)?;
    let reporter = config
        .reporter_reward_address()
        .map_err(NodeError::Engine)?;
    if config.role == NodeRole::LightClient {
        return Box::pin(run_with_prover(config, reporter, || {
            Ok(sp1_sdk::blocking::ProverClient::builder().light().build())
        }))
        .await;
    }
    match config.proving.backend {
        ProvingBackend::Cpu => {
            Box::pin(run_with_prover(config, reporter, || {
                Ok(sp1_sdk::blocking::ProverClient::builder().cpu().build())
            }))
            .await
        }
        ProvingBackend::Cuda => {
            #[cfg(feature = "cuda")]
            {
                let device = config.proving.cuda_device.unwrap_or(0);
                Box::pin(run_with_prover(config, reporter, move || {
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

/// `reporter` is the reward address [`run`] already decoded from `config`.
#[allow(clippy::too_many_lines)]
async fn run_with_prover<P: ProgramProver + Send + Sync + 'static>(
    config: NodeConfig,
    reporter: Option<[u8; 32]>,
    build_prover: impl FnOnce() -> Result<P, Sp1HostError> + Send + 'static,
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
    let production_config = build_block_producer_config(&config, &chain_spec)?;
    // Validate addresses before starting any worker, including backend workers.
    let listen_addrs = parse_multiaddrs(&config.effective_listen())?;
    let bootnodes = parse_multiaddrs(&config.bootnodes)?;
    let rpc_config = config
        .rpc
        .as_ref()
        .map(|rpc| {
            rpc.to_runtime_config()
                .map_err(|source| NodeError::RpcListen {
                    addr: rpc.listen.clone(),
                    source,
                })
        })
        .transpose()?;
    let metrics_addr = config
        .metrics
        .as_ref()
        .map(|metrics| {
            metrics
                .listen
                .parse::<std::net::SocketAddr>()
                .map_err(|error| NodeError::MetricsListen {
                    addr: metrics.listen.clone(),
                    reason: error.to_string(),
                })
        })
        .transpose()?;
    let local_key = crate::identity::load_network_identity(&config)
        .map_err(|error| NodeError::NetworkIdentity(error.to_string()))?;
    let health = Arc::new(crate::health::NodeHealth::new(
        &config.health,
        chain_spec.consensus.slot_duration_secs,
        chain_spec.consensus.chunk_size,
    ));
    let tasks = TaskSupervisor::new();
    let mut rpc_handle = None;
    let shutdown = wait_for_shutdown();
    tokio::pin!(shutdown);

    // Startup and steady-state share one owner. An early error or signal also
    // stops workers created while restoring programs or BFT sessions.
    let outcome = supervise_lifecycle(
        &tasks,
        &mut shutdown,
        async {
            let db = open_node_db(&config)?;
            let engine = open_or_initialise_engine(db, chain_spec, &spec_file)?;
            // SP1's blocking prover clients drive their own runtime while they
            // initialise, which must not happen on an async worker thread.
            let proof_system = tokio::task::spawn_blocking(move || {
                let prover = build_prover()?;
                Sp1ProofSystem::new(prover)
            })
            .await
            .map_err(|error| NodeError::ProofSystem(format!("prover setup task failed: {error}")))?
            .map_err(|error| NodeError::ProofSystem(error.to_string()))?;
            info!(backend = ?config.proving.backend, cuda_device = ?config.proving.cuda_device,
                    concurrency = config.proving.concurrency, "SP1 proving backend initialized");
            info!(
                chain_id = config.chain_id,
                backend = "ChainBackend",
                head_height = engine.head_height(),
                "using real engine backend"
            );
            let concrete_backend = Arc::new(ChainBackend::new(engine, proof_system));
            concrete_backend.set_task_spawner(tasks.spawner());
            concrete_backend.set_proving_concurrency(config.proving.concurrency);
            concrete_backend.set_backlog_policy(config.proving.backlog_policy());
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
                            chain: domain.chain,
                            boundary: domain.genesis_boundary(&spec),
                        },
                        spec.genesis_time,
                    ),
                    _ => {
                        return Err(NodeError::ProofSystem(
                            "trusted_checkpoint_path and trusted_at must be configured together"
                                .into(),
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
                let block_executor =
                    WasmExecutor::default_runtime_with_limits(config.execution.to_wasm_limits())
                        .map_err(|err| NodeError::ProofSystem(err.to_string()))?;
                concrete_backend.set_block_executor(block_executor);
                // On-chain program artifacts (design 24): accepted artifacts persist
                // under the data directory and are reinstalled on every start.
                if let Some(data_dir) = &config.data_dir {
                    let programs_dir = data_dir.join("programs");
                    let store =
                        crate::programs::ProgramStore::open(&programs_dir).map_err(|source| {
                            NodeError::DataDir {
                                path: programs_dir.display().to_string(),
                                source,
                            }
                        })?;
                    concrete_backend.set_program_store(store);
                    concrete_backend.restore_programs();
                }
                if let Some(address) = reporter {
                    concrete_backend
                        .initialize_reporter(address)
                        .map_err(NodeError::Engine)?;
                }
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
            let local_peer_id = neutrino_network::PeerId::from(local_key.public());
            info!(%local_peer_id, role = ?config.role, chain_id = config.chain_id, "starting node");
            let (cmd_tx, cmd_rx) = mpsc::channel::<NetworkCommand>(256);
            let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(256);
            let mut svc = NetworkService::new(local_key, cmd_rx, event_tx)?;
            for addr in listen_addrs {
                let id = svc.listen_on(addr.clone()).map_err(NetworkError::from)?;
                info!(%addr, ?id, "listening");
            }
            svc.configure_bootnodes(bootnodes)?;
            concrete_backend.set_network_metrics(svc.metrics());
            if let Some(path) = &config.data_dir {
                concrete_backend.set_metrics_data_path(path.clone());
            }
            let _ = tasks.spawner().spawn_critical("network", async move {
                Box::pin(svc.run()).await.map_err(|error| error.to_string())
            });

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
                cmd_tx
                    .send(NetworkCommand::Subscribe(topic))
                    .await
                    .map_err(|_| NodeError::CriticalTask {
                        task: "network",
                        reason: "command channel closed during startup".into(),
                    })?;
            }
            concrete_backend.set_network_publisher(cmd_tx.clone());
            if let Some(production) = production_config.as_ref() {
                concrete_backend.set_local_voter(production.proposer.clone());
            }
            concrete_backend
                .resume_bft_sessions()
                .await
                .map_err(NodeError::Engine)?;
            let worker = Arc::clone(&concrete_backend);
            let _ = tasks
                .spawner()
                .spawn_critical("consensus-notifications", async move {
                    worker.run_consensus_proof_notifications().await;
                    Ok(())
                });
            if concrete_backend.local_voter().is_some() {
                let worker = Arc::clone(&concrete_backend);
                let _ = tasks.spawner().spawn_critical("bft-clock", async move {
                    worker.run_bft_round_timeouts().await;
                    Ok(())
                });
            }
            let source = Arc::clone(&concrete_backend) as Arc<dyn crate::metrics::MetricsSource>;
            let monitor_health = Arc::clone(&health);
            let monitor_source = Arc::clone(&source);
            let _ = tasks
                .spawner()
                .spawn_critical("health-monitor", async move {
                    monitor_health.monitor(monitor_source).await;
                    Ok(())
                });
            if let Some(addr) = metrics_addr {
                let listener =
                    crate::metrics::bind(addr)
                        .await
                        .map_err(|error| NodeError::MetricsListen {
                            addr: addr.to_string(),
                            reason: error.to_string(),
                        })?;
                let metrics_health = Arc::clone(&health);
                let _ = tasks.spawner().spawn_critical("metrics", async move {
                    crate::metrics::serve(listener, source, metrics_health)
                        .await
                        .map_err(|error| error.to_string())
                });
                info!(listen = %addr, "metrics endpoint listening");
            }
            let rpc_backend = Arc::clone(&concrete_backend) as Arc<dyn RpcBackend>;
            let backend = Arc::clone(&concrete_backend) as Arc<dyn SyncBackend>;
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
            let _ = tasks.spawner().spawn_critical("sync", async move {
                driver.run().await.map_err(|error| error.to_string())
            });
            if let Some(production) = production_config {
                let worker = Arc::clone(&concrete_backend);
                let _ = tasks.spawner().spawn_critical("producer", async move {
                    run_block_producer(worker, cmd_tx, production).await;
                    Ok(())
                });
            }
            if let Some(runtime_cfg) = rpc_config {
                let listen = runtime_cfg.listen;
                let handle = neutrino_rpc::serve_with_metrics(
                    rpc_backend,
                    runtime_cfg,
                    concrete_backend.rpc_metrics(),
                )
                .await?;
                let stop_handle = handle.clone();
                tasks.on_shutdown(move || {
                    let _ = stop_handle.stop();
                });
                let monitor_handle = handle.clone();
                let _ = tasks.spawner().spawn_critical("rpc", async move {
                    monitor_handle.stopped().await;
                    Ok(())
                });
                rpc_handle = Some(handle);
                info!(%listen, "rpc server listening");
            } else {
                info!("rpc disabled (no [rpc] section in node config)");
            }
            Ok::<(), NodeError>(())
        },
        || health.mark_running(),
    )
    .await;
    if outcome.is_ok() {
        health.mark_stopping();
        info!("shutdown signal received");
    } else {
        health.mark_failed();
    }
    tasks.close();
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        tasks.shutdown().await;
        if let Some(handle) = rpc_handle {
            handle.stopped().await;
        }
    })
    .await;
    info!("node stopped");
    outcome
}

async fn supervise_lifecycle(
    tasks: &TaskSupervisor,
    shutdown: impl Future<Output = Result<(), std::io::Error>>,
    startup: impl Future<Output = Result<(), NodeError>>,
    on_started: impl FnOnce(),
) -> Result<(), NodeError> {
    tokio::pin!(shutdown);
    tokio::select! {
        biased;
        failure = tasks.next_failure() => return Err(task_error(failure)),
        result = &mut shutdown => return result.map_err(NodeError::Io),
        result = startup => result?,
    }
    on_started();
    tokio::select! {
        biased;
        failure = tasks.next_failure() => Err(task_error(failure)),
        result = &mut shutdown => result.map_err(NodeError::Io),
    }
}

fn task_error(failure: TaskFailure) -> NodeError {
    NodeError::CriticalTask {
        task: failure.name,
        reason: failure.reason,
    }
}

fn parse_multiaddrs(addresses: &[String]) -> Result<Vec<neutrino_network::Multiaddr>, NodeError> {
    addresses
        .iter()
        .map(|addr| {
            addr.parse().map_err(|source| NodeError::InvalidMultiaddr {
                addr: addr.clone(),
                source,
            })
        })
        .collect()
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
    spec_file: &ChainSpecFile,
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
        let mut engine =
            Engine::genesis(chain_spec, db).map_err(|err| NodeError::Engine(err.to_string()))?;
        // Every node derives the same allocation from the same spec file;
        // the chain spec hash already binds its root.
        let genesis = crate::genesis::build_genesis_state(spec_file)?;
        engine
            .install_genesis_state(genesis.trie)
            .map_err(|err| NodeError::Engine(err.to_string()))?;
        info!(
            accounts = genesis.accounts,
            staked_validators = genesis.staked_validators,
            "engine initialised at genesis"
        );
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
    let (ikm_hex, source) = required_proposer_key(
        config
            .resolve_proposer_ikm_hex()
            .map_err(|err| NodeError::ProposerKey(err.to_string()))?,
    )?;
    match source {
        crate::config::ProposerIkmSource::Inline => warn!(
            "proposer key read inline from the config file; prefer {} or proposer_ikm_path",
            crate::config::PROPOSER_IKM_ENV
        ),
        other => info!(source = ?other, "proposer key loaded"),
    }

    let proposer_index = config.proposer_index.unwrap_or(0);
    let ikm = decode_hex_exact::<32>(&ikm_hex, "proposer key")?;
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

fn required_proposer_key(
    resolved: Option<(String, crate::config::ProposerIkmSource)>,
) -> Result<(String, crate::config::ProposerIkmSource), NodeError> {
    resolved.ok_or_else(|| NodeError::ProposerKey(format!(
        "validator role requires a proposer key ({} / proposer_ikm_path); use role=full for a non-validator node",
        crate::config::PROPOSER_IKM_ENV
    )))
}

/// Short hex preview for log lines / error messages. Truncates to
/// the first 8 bytes so a `Display::fmt` of a hash stays readable.
fn hex_short(bytes: &[u8; 32]) -> String {
    format!("{}..", hex::encode(&bytes[..8]))
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

#[cfg(test)]
#[path = "runner_lifecycle_tests.rs"]
mod lifecycle_tests;
