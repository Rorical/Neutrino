//! High-level node lifecycle.
//!
//! Builds a libp2p [`NetworkService`], spawns the [`SyncDriver`],
//! attaches a stub backend, and waits for `SIGINT`/`SIGTERM` before
//! shutting down. The runner intentionally avoids any pre-existing
//! consensus state — it is the wiring backbone that subsequent commits
//! flesh out with engine integration.

use std::sync::Arc;
use std::time::Duration;

use neutrino_network::Topic;
use neutrino_network::libp2p::identity::Keypair;
use neutrino_network::service::{NetworkCommand, NetworkError, NetworkEvent, NetworkService};
use neutrino_network::sync::LocalProgress;
use neutrino_sync::{SyncDriver, SyncDriverConfig};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::backend::StubSyncBackend;
use crate::config::NodeConfig;

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
    /// Driver loop failed.
    #[error("sync driver error: {0}")]
    Driver(#[from] neutrino_sync::SyncDriverError),
    /// Generic I/O surface (signal hookup, config read, ...).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Run the node until `SIGINT` or `SIGTERM` arrive.
///
/// # Errors
///
/// Surfaces any of the variants of [`NodeError`].
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

    // Spawn the sync driver.
    let backend = Arc::new(StubSyncBackend::new(config.chain_id));
    let local_progress = LocalProgress {
        chain_id: config.chain_id,
        ..LocalProgress::default()
    };
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

    // Wait for shutdown signal.
    wait_for_shutdown().await?;
    info!("shutdown signal received");

    // Closing the command channel triggers the network service to stop;
    // dropping the channels propagates to the driver loop.
    drop(cmd_tx);

    // Give tasks a brief grace period to flush logs.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let _ = network_handle.await;
        let _ = driver_handle.await;
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
