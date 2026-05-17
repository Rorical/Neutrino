//! Async driver loop that bridges the libp2p [`NetworkService`] with the
//! sync [`SyncMachine`].
//!
//! `SyncDriver` owns:
//! - the [`SyncMachine`] state machine,
//! - an [`mpsc::Sender<NetworkCommand>`] used to drive the network,
//! - an [`mpsc::Receiver<NetworkEvent>`] consuming inbound events, and
//! - an [`Arc<dyn SyncBackend>`] performing verification and persistence
//!   (read for serving RPCs, write for importing peer data).
//!
//! For every outbound RPC the driver spawns a short task that awaits the
//! `oneshot` result and forwards it to an internal channel, so the main
//! `select!` loop remains purely event-driven.
//!
//! [`NetworkService`]: neutrino_network::service::NetworkService

use alloc::sync::Arc;
use core::time::Duration;

use neutrino_network::rpc::{
    BlockProofByHeightRequest, BlocksByRangeRequest, ChunkProofByIdRequest, MetadataRequest,
    RecursiveProofByIndexRequest, RecursiveProofLatestRequest, RpcInboundId, RpcProtocol,
    RpcRequest, RpcResponse, StateByRootRequest,
};
use neutrino_network::service::{NetworkCommand, NetworkEvent};
use neutrino_network::sync::{SyncCommand, SyncEvent, SyncMachine, SyncMode};
use neutrino_network::topic::Topic;
use neutrino_primitives::StateRoot;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::backend::{HeadersImported, SyncBackend};
use crate::error::SyncDriverError;

/// Construction-time options for [`SyncDriver`].
#[derive(Clone, Copy, Debug)]
pub struct SyncDriverConfig {
    /// Sync mode passed into the underlying [`SyncMachine`].
    pub mode: SyncMode,
    /// Maximum outstanding outbound RPC responses tracked at once.
    pub outbound_buffer: usize,
}

impl Default for SyncDriverConfig {
    fn default() -> Self {
        Self {
            mode: SyncMode::Snap,
            outbound_buffer: 256,
        }
    }
}

/// Stage 5 sync driver — the engine-side bridge between the libp2p
/// network service and the sync state machine.
pub struct SyncDriver {
    fsm: SyncMachine,
    backend: Arc<dyn SyncBackend>,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    outbound_rx: mpsc::Receiver<OutboundOutcome>,
    outbound_tx: mpsc::Sender<OutboundOutcome>,
}

impl SyncDriver {
    /// Construct a new driver. The caller is responsible for spawning the
    /// network service that owns the other end of the supplied channels.
    pub fn new(
        config: SyncDriverConfig,
        backend: Arc<dyn SyncBackend>,
        local_progress: neutrino_network::sync::LocalProgress,
        cmd_tx: mpsc::Sender<NetworkCommand>,
        event_rx: mpsc::Receiver<NetworkEvent>,
    ) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel(config.outbound_buffer);
        let fsm = SyncMachine::new(config.mode, local_progress);
        Self {
            fsm,
            backend,
            cmd_tx,
            event_rx,
            outbound_rx,
            outbound_tx,
        }
    }

    /// Inspect the underlying [`SyncMachine`] (chiefly for tests and
    /// metrics).
    #[must_use]
    pub const fn fsm(&self) -> &SyncMachine {
        &self.fsm
    }

    /// Drive the loop until the network event channel closes.
    pub async fn run(mut self) -> Result<(), SyncDriverError> {
        loop {
            tokio::select! {
                event = self.event_rx.recv() => {
                    let Some(event) = event else {
                        info!("network event channel closed, sync driver stopping");
                        return Ok(());
                    };
                    self.handle_network_event(event).await;
                }
                outcome = self.outbound_rx.recv() => {
                    let Some(outcome) = outcome else {
                        // Cannot happen: we hold a sender alive.
                        warn!("outbound outcome channel closed unexpectedly");
                        return Ok(());
                    };
                    self.handle_outbound_outcome(outcome).await;
                }
            }
        }
    }

    // ---------------------------------------------------------------- inbound

    async fn handle_network_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::PeerConnected(peer) => {
                debug!(%peer, "peer connected, dispatching FSM event");
                let cmds = self.fsm.on_event(SyncEvent::PeerConnected(peer));
                self.dispatch_sync_commands(cmds).await;
            }
            NetworkEvent::PeerDisconnected(peer) => {
                debug!(%peer, "peer disconnected");
                let cmds = self.fsm.on_event(SyncEvent::PeerDisconnected(peer));
                self.dispatch_sync_commands(cmds).await;
            }
            NetworkEvent::NewListenAddr(addr) => {
                debug!(%addr, "node listening on new address");
            }
            NetworkEvent::GossipMessage { topic, data, .. } => {
                self.handle_gossip(topic, data).await;
            }
            NetworkEvent::RpcRequestReceived {
                peer,
                inbound_id,
                request,
            } => {
                self.handle_inbound_rpc(peer, inbound_id, request).await;
            }
        }
    }

    async fn handle_gossip(&mut self, topic: Topic, data: Vec<u8>) {
        if topic == Topic::BlockProofs {
            self.handle_block_proof_gossip(data).await;
            return;
        }
        if topic != Topic::Blocks {
            debug!(
                ?topic,
                len = data.len(),
                "ignoring gossip for non-Blocks topic"
            );
            return;
        }
        let block = match borsh::from_slice::<neutrino_consensus_types::Block>(&data) {
            Ok(b) => b,
            Err(err) => {
                warn!(?err, "failed to decode gossipped block; dropping");
                return;
            }
        };
        match self.backend.verify_and_import_gossip_block(block).await {
            Ok(HeadersImported {
                new_head_height,
                new_head_hash,
                new_head_slot,
            }) => {
                info!(
                    new_head_height,
                    head_hash = %hex_short(&new_head_hash),
                    new_head_slot,
                    "imported gossipped block"
                );
                let cmds = self.fsm.on_event(SyncEvent::HeadersAdvanced {
                    new_head_height,
                    new_head_hash,
                    new_head_slot,
                });
                self.dispatch_sync_commands(cmds).await;
            }
            Err(err) => {
                warn!(?err, "rejecting gossipped block");
            }
        }
    }

    async fn handle_block_proof_gossip(&self, data: Vec<u8>) {
        let proof = match borsh::from_slice::<neutrino_consensus_types::BlockProof>(&data) {
            Ok(p) => p,
            Err(err) => {
                warn!(?err, "failed to decode gossipped block proof; dropping");
                return;
            }
        };
        let height = proof.height;
        match self
            .backend
            .verify_and_import_block_proofs(height, vec![proof])
            .await
        {
            Ok(_) => debug!(height, "imported gossipped block proof"),
            Err(err) => warn!(height, ?err, "rejecting gossipped block proof"),
        }
    }

    async fn handle_inbound_rpc(
        &self,
        peer: neutrino_network::PeerId,
        inbound_id: RpcInboundId,
        request: RpcRequest,
    ) {
        debug!(
            %peer,
            protocol = ?inbound_id.protocol,
            "serving inbound RPC"
        );
        let response = match request {
            RpcRequest::Status(_peer_status) => {
                // Echo our own status back; peer's status arrives via a
                // separate Status RPC initiated by us.
                Some(RpcResponse::Status(self.backend.local_status().await))
            }
            RpcRequest::Metadata(MetadataRequest) => {
                // Stage 5 sends a minimal stub. Real role/subnet
                // advertising arrives with M7 multi-validator.
                Some(RpcResponse::Metadata(
                    neutrino_network::rpc::Metadata::default(),
                ))
            }
            RpcRequest::Ping(p) => Some(RpcResponse::Ping(p)),
            RpcRequest::BlocksByRange(BlocksByRangeRequest {
                start_height,
                count,
                step,
            }) => Some(RpcResponse::BlocksByRange(
                self.backend
                    .blocks_by_range(start_height, count, step)
                    .await,
            )),
            RpcRequest::BlocksByRoot(req) => Some(RpcResponse::BlocksByRoot(
                self.backend.blocks_by_root(&req.roots).await,
            )),
            RpcRequest::StateByRoot(StateByRootRequest { state_root, paths }) => Some(
                RpcResponse::StateByRoot(self.backend.state_nodes(state_root, &paths).await),
            ),
            RpcRequest::BlockProofByHash(req) => Some(RpcResponse::BlockProofByHash(
                self.backend.block_proofs_by_hash(&req.roots).await,
            )),
            RpcRequest::BlockProofByHeight(BlockProofByHeightRequest {
                start_height,
                count,
            }) => Some(RpcResponse::BlockProofByHeight(
                self.backend
                    .block_proofs_by_height(start_height, count)
                    .await,
            )),
            RpcRequest::ChunkProofById(ChunkProofByIdRequest { chunk_ids }) => Some(
                RpcResponse::ChunkProofById(self.backend.chunk_proofs_by_id(&chunk_ids).await),
            ),
            RpcRequest::RecursiveProofLatest(RecursiveProofLatestRequest) => {
                match self.backend.latest_recursive_proof().await {
                    Ok(resp) => Some(RpcResponse::RecursiveProofLatest(Box::new(resp))),
                    Err(err) => {
                        debug!(?err, "no latest recursive proof to serve; dropping channel");
                        None
                    }
                }
            }
            RpcRequest::RecursiveProofByIndex(RecursiveProofByIndexRequest {
                start_index,
                count,
            }) => Some(RpcResponse::RecursiveProofByIndex(
                self.backend
                    .recursive_proofs_by_index(start_index, count)
                    .await,
            )),
        };
        if let Some(response) = response {
            let _ = self
                .cmd_tx
                .send(NetworkCommand::SendRpcResponse {
                    inbound_id,
                    response,
                })
                .await;
        }
    }

    // --------------------------------------------------------------- outbound

    async fn dispatch_sync_commands(&self, cmds: Vec<SyncCommand>) {
        for cmd in cmds {
            self.dispatch_one(cmd).await;
        }
    }

    async fn dispatch_one(&self, cmd: SyncCommand) {
        match cmd {
            SyncCommand::RequestStatus(peer) => {
                let local = self.backend.local_status().await;
                self.send_rpc(peer, RpcRequest::Status(local), |peer, response| {
                    OutboundOutcome::StatusResponse { peer, response }
                })
                .await;
            }
            SyncCommand::RequestRecursiveProofs {
                peer,
                start_index,
                count,
            } => {
                self.send_rpc(
                    peer,
                    RpcRequest::RecursiveProofByIndex(RecursiveProofByIndexRequest {
                        start_index,
                        count,
                    }),
                    move |peer, response| OutboundOutcome::RecursiveProofs { peer, response },
                )
                .await;
            }
            SyncCommand::RequestBlocks {
                peer,
                start_height,
                count,
            } => {
                self.send_rpc(
                    peer,
                    RpcRequest::BlocksByRange(BlocksByRangeRequest {
                        start_height,
                        count,
                        step: 1,
                    }),
                    move |peer, response| OutboundOutcome::Blocks { peer, response },
                )
                .await;
            }
            SyncCommand::RequestStateNodes {
                peer,
                state_root,
                paths,
            } => {
                let paths_for_callback = paths.clone();
                self.send_rpc(
                    peer,
                    RpcRequest::StateByRoot(StateByRootRequest { state_root, paths }),
                    move |peer, response| OutboundOutcome::StateNodes {
                        peer,
                        state_root,
                        paths: paths_for_callback,
                        response,
                    },
                )
                .await;
            }
            SyncCommand::RequestBlockProofs {
                peer,
                start_height,
                count,
            } => {
                self.send_rpc(
                    peer,
                    RpcRequest::BlockProofByHeight(BlockProofByHeightRequest {
                        start_height,
                        count,
                    }),
                    move |peer, response| OutboundOutcome::BlockProofs {
                        peer,
                        start_height,
                        response,
                    },
                )
                .await;
            }
            SyncCommand::Subscribe(topic) => {
                let _ = self.cmd_tx.send(NetworkCommand::Subscribe(topic)).await;
            }
            SyncCommand::EnterFollowing => {
                info!("sync FSM entered Following");
            }
        }
    }

    /// Convenience: send an outbound RPC, spawning a forwarder task that
    /// translates the `oneshot` result into an [`OutboundOutcome`].
    async fn send_rpc<F>(&self, peer: neutrino_network::PeerId, request: RpcRequest, wrap: F)
    where
        F: FnOnce(
                neutrino_network::PeerId,
                Result<RpcResponse, neutrino_network::rpc::RpcError>,
            ) -> OutboundOutcome
            + Send
            + 'static,
    {
        let (resp_tx, resp_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NetworkCommand::SendRpcRequest {
                peer,
                request,
                response_tx: resp_tx,
            })
            .await
            .is_err()
        {
            warn!(%peer, "command channel closed; cannot send RPC");
            return;
        }
        let outbound_tx = self.outbound_tx.clone();
        tokio::spawn(async move {
            // Bound the wait so a vanished peer eventually surfaces.
            let result = match tokio::time::timeout(Duration::from_secs(30), resp_rx).await {
                Ok(Ok(r)) => r,
                Ok(Err(_canceled)) => Err(neutrino_network::rpc::RpcError::ResponseDeliveryFailed),
                Err(_elapsed) => Err(neutrino_network::rpc::RpcError::Outbound(
                    "timeout".to_owned(),
                )),
            };
            let _ = outbound_tx.send(wrap(peer, result)).await;
        });
    }

    async fn handle_outbound_outcome(&mut self, outcome: OutboundOutcome) {
        match outcome {
            OutboundOutcome::StatusResponse { peer, response } => match response {
                Ok(RpcResponse::Status(status)) => {
                    let cmds = self.fsm.on_event(SyncEvent::PeerStatus { peer, status });
                    self.dispatch_sync_commands(cmds).await;
                }
                Ok(other) => warn!(?other, "unexpected response type for Status RPC"),
                Err(err) => {
                    let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                        protocol: RpcProtocol::Status,
                        peer,
                        error: err.to_string(),
                    });
                    self.dispatch_sync_commands(cmds).await;
                }
            },
            OutboundOutcome::RecursiveProofs { peer, response } => match response {
                Ok(RpcResponse::RecursiveProofByIndex(payload)) => {
                    self.handle_recursive_proofs_response(peer, payload.items)
                        .await;
                }
                Ok(other) => warn!(
                    ?other,
                    "unexpected response type for RecursiveProofByIndex RPC"
                ),
                Err(err) => {
                    let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                        protocol: RpcProtocol::RecursiveProofByIndex,
                        peer,
                        error: err.to_string(),
                    });
                    self.dispatch_sync_commands(cmds).await;
                }
            },
            OutboundOutcome::Blocks { peer, response } => match response {
                Ok(RpcResponse::BlocksByRange(payload)) => {
                    self.handle_blocks_response(peer, payload.blocks).await;
                }
                Ok(other) => warn!(?other, "unexpected response type for BlocksByRange RPC"),
                Err(err) => {
                    let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                        protocol: RpcProtocol::BlocksByRange,
                        peer,
                        error: err.to_string(),
                    });
                    self.dispatch_sync_commands(cmds).await;
                }
            },
            OutboundOutcome::StateNodes {
                peer,
                state_root,
                paths,
                response,
            } => match response {
                Ok(RpcResponse::StateByRoot(payload)) => {
                    self.handle_state_nodes_response(peer, state_root, paths, payload.nodes)
                        .await;
                }
                Ok(other) => warn!(?other, "unexpected response type for StateByRoot RPC"),
                Err(err) => {
                    let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                        protocol: RpcProtocol::StateByRoot,
                        peer,
                        error: err.to_string(),
                    });
                    self.dispatch_sync_commands(cmds).await;
                }
            },
            OutboundOutcome::BlockProofs {
                peer,
                start_height,
                response,
            } => match response {
                Ok(RpcResponse::BlockProofByHeight(payload)) => {
                    self.handle_block_proofs_response(peer, start_height, payload.proofs)
                        .await;
                }
                Ok(other) => warn!(
                    ?other,
                    "unexpected response type for BlockProofByHeight RPC"
                ),
                Err(err) => {
                    let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                        protocol: RpcProtocol::BlockProofByHeight,
                        peer,
                        error: err.to_string(),
                    });
                    self.dispatch_sync_commands(cmds).await;
                }
            },
        }
    }

    async fn handle_recursive_proofs_response(
        &mut self,
        peer: neutrino_network::PeerId,
        items: Vec<(
            neutrino_primitives::Checkpoint,
            neutrino_consensus_types::RecursiveCheckpointProof,
        )>,
    ) {
        if items.is_empty() {
            // Peer reported no more checkpoints; treat as transient and
            // surface a soft failure so the FSM clears `in_flight`.
            let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::RecursiveProofByIndex,
                peer,
                error: "empty checkpoint batch".to_owned(),
            });
            self.dispatch_sync_commands(cmds).await;
            return;
        }
        match self.backend.verify_and_import_checkpoints(items).await {
            Ok(cp) => {
                let cmds = self.fsm.on_event(SyncEvent::CheckpointsAdvanced {
                    new_finalized_index: cp.new_finalized_index,
                    new_finalized_hash: cp.new_finalized_hash,
                    new_finalized_state_root: cp.new_finalized_state_root,
                    new_finalized_height: cp.new_finalized_height,
                    new_finalized_block_hash: cp.new_finalized_block_hash,
                });
                self.dispatch_sync_commands(cmds).await;
            }
            Err(err) => {
                warn!(?err, "rejected recursive proof batch");
                let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                    protocol: RpcProtocol::RecursiveProofByIndex,
                    peer,
                    error: err.to_string(),
                });
                self.dispatch_sync_commands(cmds).await;
            }
        }
    }

    async fn handle_blocks_response(
        &mut self,
        peer: neutrino_network::PeerId,
        blocks: Vec<neutrino_consensus_types::Block>,
    ) {
        if blocks.is_empty() {
            let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::BlocksByRange,
                peer,
                error: "empty block batch".to_owned(),
            });
            self.dispatch_sync_commands(cmds).await;
            return;
        }
        match self.backend.verify_and_import_headers(blocks).await {
            Ok(HeadersImported {
                new_head_height,
                new_head_hash,
                new_head_slot,
            }) => {
                info!(
                    new_head_height,
                    head_hash = %hex_short(&new_head_hash),
                    new_head_slot,
                    "imported block batch"
                );
                let cmds = self.fsm.on_event(SyncEvent::HeadersAdvanced {
                    new_head_height,
                    new_head_hash,
                    new_head_slot,
                });
                self.dispatch_sync_commands(cmds).await;
            }
            Err(err) => {
                warn!(?err, "rejected block batch");
                let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                    protocol: RpcProtocol::BlocksByRange,
                    peer,
                    error: err.to_string(),
                });
                self.dispatch_sync_commands(cmds).await;
            }
        }
    }

    async fn handle_block_proofs_response(
        &mut self,
        peer: neutrino_network::PeerId,
        start_height: u64,
        proofs: Vec<neutrino_consensus_types::BlockProof>,
    ) {
        if proofs.is_empty() {
            let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::BlockProofByHeight,
                peer,
                error: "empty block proof batch".to_owned(),
            });
            self.dispatch_sync_commands(cmds).await;
            return;
        }
        match self
            .backend
            .verify_and_import_block_proofs(start_height, proofs)
            .await
        {
            Ok(imported) => {
                info!(
                    new_proven_height = imported.new_proven_height,
                    "imported block proof batch"
                );
                let cmds = self.fsm.on_event(SyncEvent::ProofsAdvanced {
                    new_proven_height: imported.new_proven_height,
                });
                self.dispatch_sync_commands(cmds).await;
            }
            Err(err) => {
                warn!(?err, "rejected block proof batch");
                let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                    protocol: RpcProtocol::BlockProofByHeight,
                    peer,
                    error: err.to_string(),
                });
                self.dispatch_sync_commands(cmds).await;
            }
        }
    }

    async fn handle_state_nodes_response(
        &mut self,
        peer: neutrino_network::PeerId,
        state_root: StateRoot,
        paths: Vec<Vec<u8>>,
        nodes: Vec<Vec<u8>>,
    ) {
        match self
            .backend
            .import_state_nodes(state_root, paths, nodes)
            .await
        {
            Ok(progress) => {
                if progress.root_complete {
                    let cmds = self
                        .fsm
                        .on_event(SyncEvent::StateRootReconstructed(state_root));
                    self.dispatch_sync_commands(cmds).await;
                } else if !progress.next_paths.is_empty() {
                    // Continue the trie walk.
                    let _ = self
                        .cmd_tx
                        .send(NetworkCommand::SendRpcRequest {
                            peer,
                            request: RpcRequest::StateByRoot(StateByRootRequest {
                                state_root,
                                paths: progress.next_paths.clone(),
                            }),
                            response_tx: {
                                let (tx, rx) = oneshot::channel();
                                let outbound_tx = self.outbound_tx.clone();
                                let next_paths = progress.next_paths;
                                tokio::spawn(async move {
                                    let result = match tokio::time::timeout(
                                        Duration::from_secs(30),
                                        rx,
                                    )
                                    .await
                                    {
                                        Ok(Ok(r)) => r,
                                        Ok(Err(_)) => Err(
                                            neutrino_network::rpc::RpcError::ResponseDeliveryFailed,
                                        ),
                                        Err(_) => Err(neutrino_network::rpc::RpcError::Outbound(
                                            "timeout".to_owned(),
                                        )),
                                    };
                                    let _ = outbound_tx
                                        .send(OutboundOutcome::StateNodes {
                                            peer,
                                            state_root,
                                            paths: next_paths,
                                            response: result,
                                        })
                                        .await;
                                });
                                tx
                            },
                        })
                        .await;
                }
            }
            Err(err) => {
                warn!(?err, "rejected state node batch");
                let cmds = self.fsm.on_event(SyncEvent::RpcFailed {
                    protocol: RpcProtocol::StateByRoot,
                    peer,
                    error: err.to_string(),
                });
                self.dispatch_sync_commands(cmds).await;
            }
        }
    }
}

/// Result of one outbound RPC, forwarded from a spawned waiter task back
/// into the main driver loop.
#[derive(Debug)]
enum OutboundOutcome {
    StatusResponse {
        peer: neutrino_network::PeerId,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    },
    RecursiveProofs {
        peer: neutrino_network::PeerId,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    },
    Blocks {
        peer: neutrino_network::PeerId,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    },
    StateNodes {
        peer: neutrino_network::PeerId,
        state_root: StateRoot,
        paths: Vec<Vec<u8>>,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    },
    BlockProofs {
        peer: neutrino_network::PeerId,
        start_height: u64,
        response: Result<RpcResponse, neutrino_network::rpc::RpcError>,
    },
}

// Compact hex helper for debug logs; the full chain primitives use lowercase
// hex without a `0x` prefix, but our log lines are short so we truncate.
fn hex_short(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        use core::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}
