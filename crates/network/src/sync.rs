//! Sync state machine implementing `docs/design/06-networking.md`
//! §"Sync state machine".
//!
//! ```text
//!     Light: Init → CheckpointBackfill → Following
//!     Full:  Init → HeaderBackfill → StateFetch → ProofBackfill → Following
//!     Archive additionally fetches retained block bodies.
//! ```
//!
//! [`SyncMachine`] is a **pure state machine**: it owns no I/O, performs no
//! verification, and persists nothing. The driver — typically the consensus
//! engine in `node` mode — translates [`SyncCommand`]s emitted by the FSM
//! into [`crate::service::NetworkCommand`]s (and gossip subscriptions), runs
//! the corresponding verification + storage, then notifies the FSM with the
//! resulting [`SyncEvent`].
//!
//! Separating the FSM from its execution lets us unit-test every transition
//! against synthetic events without spinning up libp2p or rocksdb.

use crate::{
    rpc::{self, RpcProtocol},
    topic::Topic,
};
use libp2p::PeerId;
use neutrino_primitives::{BlockHash, CheckpointIndex, ChunkId, Hash, Height, Slot, StateRoot};

/// Sync goal selected at startup.
///
/// Defines which states the FSM walks before reaching [`SyncState::Following`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncMode {
    /// `Init → CheckpointBackfill → Following`.
    ///
    /// The light client advances an independently trusted boundary with recursive
    /// history receipts; it does not download block bodies or state.
    LightClient,
    /// `Init → HeaderBackfill → StateFetch →
    /// ProofBackfill → Following`.
    Snap,
    /// Same as [`SyncMode::Snap`] plus `BodyBackfill` before `Following`.
    Archive,
}

/// Live sync state.
///
/// Each backfilling state carries `in_flight` so the driver can suppress
/// duplicate RPCs while a previous batch is being verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncState {
    /// Waiting for the first peer handshake.
    Init,
    /// Fetching a proven suffix from the exact local genesis or
    /// the weak-subjectivity anchor.
    CheckpointBackfill {
        /// Chunk count at the locally authenticated endpoint.
        local_finalized_index: CheckpointIndex,
        /// Chunk count advertised at the chosen peer endpoint.
        target_index: CheckpointIndex,
        /// True while a `HistoryProofByRange` RPC is in flight.
        in_flight: bool,
    },
    /// Streaming headers (via `BlocksByRange`) up to the latest finalized
    /// checkpoint's `end_height`.
    HeaderBackfill {
        /// Highest header height already stored locally.
        local_head_height: Height,
        /// Target height = `end_height` of latest finalized checkpoint.
        target_height: Height,
        /// True while a `BlocksByRange` RPC is in flight.
        in_flight: bool,
    },
    /// Reconstructing the state trie at the latest checkpoint's
    /// `end_state_root`.
    ///
    /// The FSM only tracks completion here; trie traversal is the driver's
    /// concern.
    StateFetch {
        /// State root that must be locally rooted to leave this state.
        target_state_root: StateRoot,
    },
    /// Filling in `block_proofs` and `chunk_proofs` for the uncommitted
    /// tail between the latest checkpoint and the live head.
    ProofBackfill {
        /// First height still missing a proof.
        from_height: Height,
        /// Latest height that must be proven before going live.
        target_height: Height,
        /// True while a proof retrieval RPC is in flight.
        in_flight: bool,
    },
    /// Archive-only: fetch full block bodies for the chunks we just
    /// header-backfilled.
    BodyBackfill {
        /// First height still missing a body.
        from_height: Height,
        /// Latest height that needs a body.
        target_height: Height,
        /// True while a `BlocksByRange` RPC is in flight.
        in_flight: bool,
    },
    /// Live gossip subscriber. Pending sync requests are quiesced.
    Following,
    /// Permanent failure; the driver must reset before any further
    /// transitions are accepted.
    Stalled {
        /// Operator-readable reason.
        reason: SyncStallReason,
    },
}

/// Reason the sync machine became [`SyncState::Stalled`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncStallReason {
    /// All connected peers reported chain ids that differ from ours.
    ChainIdMismatch,
    /// No peer was ahead of us *and* we were still in pre-Following.
    ///
    /// Generally not fatal in production — the driver should usually
    /// remain in Init or Following — but useful as a sentinel in tests.
    NoUsefulPeer,
    /// Driver explicitly requested stop.
    Operator(&'static str),
}

/// Local view of chain progress at the moment the FSM was constructed.
///
/// The FSM does not mutate this directly — the driver updates it via
/// [`SyncEvent::CheckpointsAdvanced`] / [`SyncEvent::HeadersAdvanced`] /
/// [`SyncEvent::ProofsAdvanced`] / [`SyncEvent::BodiesAdvanced`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalProgress {
    /// Local chain id; peers reporting a mismatch are rejected.
    pub chain_id: u64,
    /// Canonical hash of the local chain spec.
    pub chain_spec_hash: Hash,
    /// Latest complete chunk finalized locally, independent of checkpoint recursion.
    pub finalized_chunk_id: Option<ChunkId>,
    /// Hash of the latest finalized chunk, or zero at genesis.
    pub finalized_chunk_hash: Hash,
    /// Authenticated recursive endpoint chunk count; full nodes publish a genesis prefix.
    pub recursive_covered_chunks: CheckpointIndex,
    /// Hash of the locally authenticated recursive endpoint.
    pub checkpoint_hash: Hash,
    /// State root at the locally authenticated recursive endpoint.
    pub finalized_state_root: StateRoot,
    /// Block hash at the locally authenticated recursive endpoint.
    pub finalized_block_hash: BlockHash,
    /// Block height at the locally authenticated recursive endpoint.
    pub finalized_height: Height,
    /// Highest authenticated head height (light clients need not store its header).
    pub head_height: Height,
    /// Hash of the local head block.
    pub head_block_hash: BlockHash,
    /// Slot of the local head block.
    pub head_slot: Slot,
    /// Highest height for which a block proof has been imported.
    pub proven_height: Height,
    /// Highest height for which the full body has been imported (archive).
    pub body_height: Height,
}

/// Pseudo-events the driver feeds to the FSM after performing verification
/// and storage.
#[derive(Clone, Debug)]
pub enum SyncEvent {
    /// A peer just became reachable.
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
    /// Peer responded to the [`rpc::Status`] handshake.
    ///
    /// The FSM compares chain ids and finalized cursors to decide whether
    /// this peer is a useful sync target.
    PeerStatus {
        /// Peer that produced the status.
        peer: PeerId,
        /// Reported status payload.
        status: rpc::Status,
    },
    /// Driver imported and verified a batch of recursive checkpoints. The
    /// new local finalized cursor is reported back as part of the event.
    CheckpointsAdvanced {
        /// Chunk count at the newly authenticated endpoint.
        new_finalized_index: CheckpointIndex,
        /// Hash of the newly authenticated endpoint.
        new_finalized_hash: Hash,
        /// New `end_state_root`.
        new_finalized_state_root: StateRoot,
        /// New `end_height`.
        new_finalized_height: Height,
        /// New `end_block_hash`.
        new_finalized_block_hash: BlockHash,
    },
    /// Driver imported and verified a batch of headers / blocks.
    HeadersAdvanced {
        /// New highest header height.
        new_head_height: Height,
        /// Hash of the new head.
        new_head_hash: BlockHash,
        /// Slot of the new head.
        new_head_slot: Slot,
    },
    /// Trie reconstruction reported root completion.
    StateRootReconstructed(StateRoot),
    /// Driver imported missing block proofs.
    ProofsAdvanced {
        /// Highest height now proven.
        new_proven_height: Height,
    },
    /// Driver imported missing bodies (archive mode).
    BodiesAdvanced {
        /// Highest height now bodied.
        new_body_height: Height,
    },
    /// An outstanding RPC failed.
    ///
    /// The FSM clears the `in_flight` bit for the matching state so the
    /// driver can retry — typically on a different peer.
    RpcFailed {
        /// The RPC that failed.
        protocol: RpcProtocol,
        /// Peer that failed to serve the request.
        peer: PeerId,
        /// Operator-readable error.
        error: String,
    },
    /// Reset the FSM to [`SyncState::Init`] (driver-initiated).
    Reset,
}

/// Outputs the FSM emits for the driver to execute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncCommand {
    /// Send a [`rpc::Status`] handshake to the given peer.
    RequestStatus(PeerId),
    /// Fetch a batch of recursive checkpoints from the peer.
    RequestHistoryProof {
        /// Peer to query.
        peer: PeerId,
        /// Exact current trusted endpoint.
        start_checkpoint_hash: Hash,
        /// Exact requested peer endpoint.
        end_checkpoint_hash: Hash,
    },
    /// Fetch a batch of blocks / headers from the peer.
    RequestBlocks {
        /// Peer to query.
        peer: PeerId,
        /// First block height to fetch.
        start_height: Height,
        /// Number of blocks to fetch.
        count: u64,
    },
    /// Fetch bounded content-addressed state fragments under `state_root`.
    ///
    /// The FSM emits this with the *root* path; the driver walks the trie
    /// and may issue additional `RequestStateNodes` commands on its own.
    RequestStateNodes {
        /// Peer to query.
        peer: PeerId,
        /// Target state root.
        state_root: StateRoot,
        /// Initial node/value hash and byte-offset requests.
        items: Vec<neutrino_consensus_types::bootstrap::StateItem>,
    },
    /// Fetch a batch of block proofs from the peer.
    RequestBlockProofs {
        /// Peer to query.
        peer: PeerId,
        /// First block height whose proof is missing.
        start_height: Height,
        /// Number of proofs to fetch.
        count: u64,
    },
    /// Subscribe to a gossip topic.
    Subscribe(Topic),
    /// Reached [`SyncState::Following`]; the driver should now treat the
    /// node as caught up.
    EnterFollowing,
}

/// Configurable batch sizes the FSM uses when emitting RPC requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncBatchSizes {
    /// Number of blocks requested per `BlocksByRange` RPC.
    pub block_batch: u64,
    /// Number of block proofs requested per `BlockProofByHeight` RPC.
    pub block_proof_batch: u64,
}

impl Default for SyncBatchSizes {
    fn default() -> Self {
        Self {
            block_batch: 16,
            block_proof_batch: rpc::MAX_BLOCK_PROOFS_PER_RESPONSE,
        }
    }
}

/// The sync state machine.
///
/// Construct with [`SyncMachine::new`], feed events with
/// [`SyncMachine::on_event`], and drain emitted commands from the returned
/// vector.
#[derive(Clone, Debug)]
pub struct SyncMachine {
    mode: SyncMode,
    state: SyncState,
    progress: LocalProgress,
    sync_peer: Option<PeerStatus>,
    batch_sizes: SyncBatchSizes,
}

/// Snapshot of a peer's last reported status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerStatus {
    peer: PeerId,
    status: rpc::Status,
}

impl SyncMachine {
    /// Construct a new sync machine in [`SyncState::Init`].
    #[must_use]
    pub const fn new(mode: SyncMode, progress: LocalProgress) -> Self {
        Self {
            mode,
            state: SyncState::Init,
            progress,
            sync_peer: None,
            batch_sizes: SyncBatchSizes {
                block_batch: 16,
                block_proof_batch: rpc::MAX_BLOCK_PROOFS_PER_RESPONSE,
            },
        }
    }

    /// Override batch sizes (useful in tests and tuning).
    #[must_use]
    pub const fn with_batch_sizes(mut self, batch_sizes: SyncBatchSizes) -> Self {
        self.batch_sizes = batch_sizes;
        self
    }

    /// Selected synchronization role.
    #[must_use]
    pub const fn mode(&self) -> SyncMode {
        self.mode
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> &SyncState {
        &self.state
    }

    /// Current local progress snapshot.
    #[must_use]
    pub const fn progress(&self) -> &LocalProgress {
        &self.progress
    }

    /// Refresh canonical cursors only after a backend atomically installs a checkpoint.
    pub const fn refresh_local_progress(&mut self, progress: LocalProgress) {
        self.progress = progress;
    }

    /// Selected sync peer, if any.
    #[must_use]
    pub fn sync_peer(&self) -> Option<PeerId> {
        self.sync_peer.map(|p| p.peer)
    }

    /// Advertised branch anchor for the selected sync peer.
    #[must_use]
    pub fn sync_head(&self, peer: PeerId) -> Option<BlockHash> {
        self.sync_peer
            .filter(|p| p.peer == peer)
            .map(|p| p.status.head_block_hash)
    }

    /// Apply an event and return the commands to execute.
    ///
    /// Returning an empty vector is normal — many events advance state
    /// without immediately requesting more data.
    pub fn on_event(&mut self, event: SyncEvent) -> Vec<SyncCommand> {
        match event {
            SyncEvent::Reset => self.reset(),
            SyncEvent::PeerConnected(peer) => self.on_peer_connected(peer),
            SyncEvent::PeerDisconnected(peer) => self.on_peer_disconnected(peer),
            SyncEvent::PeerStatus { peer, status } => self.on_peer_status(peer, &status),
            SyncEvent::CheckpointsAdvanced {
                new_finalized_index,
                new_finalized_hash,
                new_finalized_state_root,
                new_finalized_height,
                new_finalized_block_hash,
            } => self.on_checkpoints_advanced(
                new_finalized_index,
                new_finalized_hash,
                new_finalized_state_root,
                new_finalized_height,
                new_finalized_block_hash,
            ),
            SyncEvent::HeadersAdvanced {
                new_head_height,
                new_head_hash,
                new_head_slot,
            } => self.on_headers_advanced(new_head_height, new_head_hash, new_head_slot),
            SyncEvent::StateRootReconstructed(root) => self.on_state_root_reconstructed(root),
            SyncEvent::ProofsAdvanced { new_proven_height } => {
                self.on_proofs_advanced(new_proven_height)
            }
            SyncEvent::BodiesAdvanced { new_body_height } => {
                self.on_bodies_advanced(new_body_height)
            }
            SyncEvent::RpcFailed {
                protocol,
                peer,
                error,
            } => self.on_rpc_failed(protocol, peer, &error),
        }
    }

    /// Retry the same anchored range from another provider after unavailability.
    /// The driver bounds provider attempts; changing provider never changes the
    /// requested endpoint or treats that provider as a new trust anchor.
    pub fn retry_history_from(&mut self, peer: PeerId) -> Vec<SyncCommand> {
        if self.mode != SyncMode::LightClient {
            return Vec::new();
        }
        let SyncState::CheckpointBackfill {
            local_finalized_index,
            target_index,
            in_flight: false,
        } = self.state
        else {
            return Vec::new();
        };
        let Some(target) = self.sync_peer.as_mut() else {
            return Vec::new();
        };
        if target.status.recursive_covered_chunks <= local_finalized_index {
            return Vec::new();
        }
        target.peer = peer;
        self.state = SyncState::CheckpointBackfill {
            local_finalized_index,
            target_index,
            in_flight: true,
        };
        self.emit_checkpoint_fetch(peer, local_finalized_index)
    }

    // --- Event handlers ------------------------------------------------------

    const fn reset(&mut self) -> Vec<SyncCommand> {
        self.state = SyncState::Init;
        self.sync_peer = None;
        Vec::new()
    }

    #[allow(clippy::unused_self)] // kept on `&self` for API symmetry with other handlers
    fn on_peer_connected(&self, peer: PeerId) -> Vec<SyncCommand> {
        // Always handshake newly-connected peers, regardless of state.
        vec![SyncCommand::RequestStatus(peer)]
    }

    fn on_peer_disconnected(&mut self, peer: PeerId) -> Vec<SyncCommand> {
        if self.sync_peer.is_some_and(|s| s.peer == peer) {
            if self.mode == SyncMode::LightClient
                && let SyncState::CheckpointBackfill { in_flight, .. } = &mut self.state
            {
                *in_flight = false;
            } else {
                self.sync_peer = None;
                self.state = SyncState::Init;
            }
        }
        Vec::new()
    }

    fn on_peer_status(&mut self, peer: PeerId, status: &rpc::Status) -> Vec<SyncCommand> {
        // Wrong chain/spec → ignore the peer (could become a Stall condition
        // once we count all peers, but with one-peer-at-a-time semantics a
        // single mismatch is not fatal).
        if status.chain_id != self.progress.chain_id
            || status.chain_spec_hash != self.progress.chain_spec_hash
        {
            return Vec::new();
        }

        if self.mode == SyncMode::LightClient
            && status.recursive_covered_chunks == self.progress.recursive_covered_chunks
            && status.checkpoint_hash != self.progress.checkpoint_hash
        {
            return Vec::new();
        }

        if self.mode == SyncMode::LightClient
            && matches!(
                self.state,
                SyncState::CheckpointBackfill {
                    in_flight: true,
                    ..
                }
            )
        {
            // The active request owns its provider and exact endpoint until its
            // response or disconnect. The driver retains newer status for later.
            return Vec::new();
        }

        let is_ahead = status.recursive_covered_chunks > self.progress.recursive_covered_chunks
            || (self.mode != SyncMode::LightClient
                && status.head_height > self.progress.head_height);

        if !is_ahead {
            // Either equal or behind. In LightClient mode, equal finalized
            // index means we are already at the same recursive head and can
            // safely Follow.
            if matches!(self.state, SyncState::Init)
                && self.mode == SyncMode::LightClient
                && status.recursive_covered_chunks == self.progress.recursive_covered_chunks
                && status.checkpoint_hash == self.progress.checkpoint_hash
            {
                return self.enter_following();
            }
            return Vec::new();
        }

        // Adopt this peer as the sync target.
        self.sync_peer = Some(PeerStatus {
            peer,
            status: *status,
        });

        match self.state {
            SyncState::Init => self.advance_to_checkpoint_backfill(status),
            SyncState::Following if self.mode == SyncMode::LightClient => {
                self.advance_to_checkpoint_backfill(status)
            }
            SyncState::CheckpointBackfill { in_flight, .. } => {
                // Update target with the latest peer view. Issue a new RPC
                // only if we are not already waiting on one.
                let local = self.progress.recursive_covered_chunks;
                let target = status.recursive_covered_chunks.max(local);
                self.state = SyncState::CheckpointBackfill {
                    local_finalized_index: local,
                    target_index: target,
                    in_flight: true,
                };
                if in_flight {
                    Vec::new()
                } else {
                    self.emit_checkpoint_fetch(peer, local)
                }
            }
            _ => Vec::new(),
        }
    }

    fn advance_to_checkpoint_backfill(&mut self, status: &rpc::Status) -> Vec<SyncCommand> {
        if self.mode != SyncMode::LightClient {
            return self.advance_to_header_backfill(status.head_height);
        }
        let local = self.progress.recursive_covered_chunks;
        let target = status.recursive_covered_chunks;
        if target == local {
            return match self.mode {
                SyncMode::LightClient => self.enter_following(),
                SyncMode::Snap | SyncMode::Archive => {
                    self.advance_to_header_backfill(status.head_height)
                }
            };
        }
        self.state = SyncState::CheckpointBackfill {
            local_finalized_index: local,
            target_index: target,
            in_flight: true,
        };
        let peer = self
            .sync_peer
            .expect("sync peer set by on_peer_status before this transition")
            .peer;
        self.emit_checkpoint_fetch(peer, local)
    }

    fn emit_checkpoint_fetch(
        &self,
        peer: PeerId,
        local_finalized_index: CheckpointIndex,
    ) -> Vec<SyncCommand> {
        let Some(target) = self.sync_peer else {
            return Vec::new();
        };
        if target.status.recursive_covered_chunks <= local_finalized_index {
            return Vec::new();
        }
        vec![SyncCommand::RequestHistoryProof {
            peer,
            start_checkpoint_hash: self.progress.checkpoint_hash,
            end_checkpoint_hash: target.status.checkpoint_hash,
        }]
    }

    fn on_checkpoints_advanced(
        &mut self,
        new_finalized_index: CheckpointIndex,
        new_finalized_hash: Hash,
        new_finalized_state_root: StateRoot,
        new_finalized_height: Height,
        new_finalized_block_hash: BlockHash,
    ) -> Vec<SyncCommand> {
        // Full-node finality and published prefix coverage come from the backend,
        // never from an arbitrary suffix imported by a light-client flow.
        if self.mode != SyncMode::LightClient {
            return Vec::new();
        }
        let SyncState::CheckpointBackfill { target_index, .. } = self.state else {
            return Vec::new();
        };
        if new_finalized_index <= self.progress.recursive_covered_chunks {
            return Vec::new();
        }
        self.progress.recursive_covered_chunks = new_finalized_index;
        self.progress.checkpoint_hash = new_finalized_hash;
        self.progress.finalized_state_root = new_finalized_state_root;
        self.progress.finalized_height = new_finalized_height;
        self.progress.finalized_block_hash = new_finalized_block_hash;

        if new_finalized_index >= target_index {
            // Reached the peer's reported finalized cursor.
            match self.mode {
                SyncMode::LightClient => self.enter_following(),
                SyncMode::Snap | SyncMode::Archive => self.advance_to_header_backfill(
                    self.sync_peer.map_or(new_finalized_height, |sync_peer| {
                        sync_peer.status.head_height.max(new_finalized_height)
                    }),
                ),
            }
        } else {
            // Need more checkpoints.
            self.state = SyncState::CheckpointBackfill {
                local_finalized_index: new_finalized_index,
                target_index,
                in_flight: true,
            };
            let Some(sync_peer) = self.sync_peer else {
                return Vec::new();
            };
            self.emit_checkpoint_fetch(sync_peer.peer, new_finalized_index)
        }
    }

    fn advance_to_header_backfill(&mut self, target_height: Height) -> Vec<SyncCommand> {
        let local_head = self.progress.head_height;
        self.state = SyncState::HeaderBackfill {
            local_head_height: local_head,
            target_height,
            in_flight: true,
        };
        let Some(sync_peer) = self.sync_peer else {
            return Vec::new();
        };
        vec![SyncCommand::RequestBlocks {
            peer: sync_peer.peer,
            start_height: local_head.saturating_add(1),
            count: self.batch_sizes.block_batch,
        }]
    }

    fn on_headers_advanced(
        &mut self,
        new_head_height: Height,
        new_head_hash: BlockHash,
        new_head_slot: Slot,
    ) -> Vec<SyncCommand> {
        self.progress.head_height = new_head_height;
        self.progress.head_block_hash = new_head_hash;
        self.progress.head_slot = new_head_slot;

        let SyncState::HeaderBackfill { target_height, .. } = self.state else {
            return Vec::new();
        };

        if new_head_height >= target_height {
            // Headers caught up to latest finalized checkpoint's end_height.
            self.advance_to_state_fetch()
        } else {
            // Fetch more.
            self.state = SyncState::HeaderBackfill {
                local_head_height: new_head_height,
                target_height,
                in_flight: true,
            };
            let Some(sync_peer) = self.sync_peer else {
                return Vec::new();
            };
            vec![SyncCommand::RequestBlocks {
                peer: sync_peer.peer,
                start_height: new_head_height.saturating_add(1),
                count: self.batch_sizes.block_batch,
            }]
        }
    }

    fn advance_to_state_fetch(&mut self) -> Vec<SyncCommand> {
        let target_state_root = self.progress.finalized_state_root;
        self.state = SyncState::StateFetch { target_state_root };
        let Some(sync_peer) = self.sync_peer else {
            return Vec::new();
        };
        vec![SyncCommand::RequestStateNodes {
            peer: sync_peer.peer,
            state_root: target_state_root,
            // Seed with the authenticated root hash; verified nodes reveal child hashes.
            items: vec![neutrino_consensus_types::bootstrap::StateItem::node(
                target_state_root,
            )],
        }]
    }

    fn on_state_root_reconstructed(&mut self, root: StateRoot) -> Vec<SyncCommand> {
        let SyncState::StateFetch { target_state_root } = self.state else {
            return Vec::new();
        };
        if root != target_state_root {
            // Driver reported a different root than the one we were chasing;
            // ignore. The state stays in StateFetch and the driver will
            // retry.
            return Vec::new();
        }

        match self.mode {
            SyncMode::LightClient => self.enter_following(),
            SyncMode::Snap | SyncMode::Archive => self.advance_to_proof_backfill(),
        }
    }

    fn advance_to_proof_backfill(&mut self) -> Vec<SyncCommand> {
        let from = self.progress.proven_height.saturating_add(1);
        let target = self.progress.head_height;
        if from > target {
            // No tail to prove; jump straight to the next phase.
            return self.advance_past_proof_backfill();
        }
        self.state = SyncState::ProofBackfill {
            from_height: from,
            target_height: target,
            in_flight: true,
        };
        let Some(sync_peer) = self.sync_peer else {
            return Vec::new();
        };
        vec![SyncCommand::RequestBlockProofs {
            peer: sync_peer.peer,
            start_height: from,
            count: self.batch_sizes.block_proof_batch,
        }]
    }

    fn advance_past_proof_backfill(&mut self) -> Vec<SyncCommand> {
        match self.mode {
            SyncMode::Archive => self.advance_to_body_backfill(),
            SyncMode::Snap | SyncMode::LightClient => self.enter_following(),
        }
    }

    fn on_proofs_advanced(&mut self, new_proven_height: Height) -> Vec<SyncCommand> {
        self.progress.proven_height = new_proven_height;
        let SyncState::ProofBackfill { target_height, .. } = self.state else {
            return Vec::new();
        };
        if new_proven_height >= target_height {
            self.advance_past_proof_backfill()
        } else {
            let from = new_proven_height.saturating_add(1);
            self.state = SyncState::ProofBackfill {
                from_height: from,
                target_height,
                in_flight: true,
            };
            let Some(sync_peer) = self.sync_peer else {
                return Vec::new();
            };
            vec![SyncCommand::RequestBlockProofs {
                peer: sync_peer.peer,
                start_height: from,
                count: self.batch_sizes.block_proof_batch,
            }]
        }
    }

    fn advance_to_body_backfill(&mut self) -> Vec<SyncCommand> {
        let from = self.progress.body_height.saturating_add(1);
        let target = self.progress.head_height;
        if from > target {
            return self.enter_following();
        }
        self.state = SyncState::BodyBackfill {
            from_height: from,
            target_height: target,
            in_flight: true,
        };
        let Some(sync_peer) = self.sync_peer else {
            return Vec::new();
        };
        vec![SyncCommand::RequestBlocks {
            peer: sync_peer.peer,
            start_height: from,
            count: self.batch_sizes.block_batch,
        }]
    }

    fn on_bodies_advanced(&mut self, new_body_height: Height) -> Vec<SyncCommand> {
        self.progress.body_height = new_body_height;
        let SyncState::BodyBackfill { target_height, .. } = self.state else {
            return Vec::new();
        };
        if new_body_height >= target_height {
            self.enter_following()
        } else {
            self.state = SyncState::BodyBackfill {
                from_height: new_body_height.saturating_add(1),
                target_height,
                in_flight: true,
            };
            let Some(sync_peer) = self.sync_peer else {
                return Vec::new();
            };
            vec![SyncCommand::RequestBlocks {
                peer: sync_peer.peer,
                start_height: new_body_height.saturating_add(1),
                count: self.batch_sizes.block_batch,
            }]
        }
    }

    fn enter_following(&mut self) -> Vec<SyncCommand> {
        self.state = SyncState::Following;
        let mut cmds: Vec<SyncCommand> = match self.mode {
            SyncMode::LightClient => vec![SyncCommand::Subscribe(Topic::Checkpoints)],
            SyncMode::Snap | SyncMode::Archive => {
                Topic::all_default().map(SyncCommand::Subscribe).collect()
            }
        };
        cmds.push(SyncCommand::EnterFollowing);
        cmds
    }

    fn on_rpc_failed(
        &mut self,
        protocol: RpcProtocol,
        peer: PeerId,
        _error: &str,
    ) -> Vec<SyncCommand> {
        if self.mode == SyncMode::LightClient
            && matches!(
                protocol,
                RpcProtocol::HistoryProofByRange | RpcProtocol::CheckpointLatest
            )
            && self.sync_peer.is_none_or(|target| target.peer != peer)
        {
            return Vec::new();
        }
        // Clear in_flight on the matching state and let the driver retry.
        match (&self.state, protocol) {
            (
                SyncState::CheckpointBackfill {
                    local_finalized_index,
                    target_index,
                    ..
                },
                RpcProtocol::HistoryProofByRange | RpcProtocol::CheckpointLatest,
            ) => {
                let (local, target) = (*local_finalized_index, *target_index);
                self.state = SyncState::CheckpointBackfill {
                    local_finalized_index: local,
                    target_index: target,
                    in_flight: false,
                };
                Vec::new()
            }
            (
                SyncState::HeaderBackfill {
                    local_head_height,
                    target_height,
                    ..
                },
                RpcProtocol::BlocksByRange,
            ) => {
                let (head, target) = (*local_head_height, *target_height);
                self.state = SyncState::HeaderBackfill {
                    local_head_height: head,
                    target_height: target,
                    in_flight: false,
                };
                vec![SyncCommand::RequestBlocks {
                    peer,
                    start_height: head.saturating_add(1),
                    count: self.batch_sizes.block_batch,
                }]
            }
            (SyncState::StateFetch { target_state_root }, RpcProtocol::StateByRoot) => {
                let target_state_root = *target_state_root;
                self.state = SyncState::StateFetch { target_state_root };
                vec![SyncCommand::RequestStateNodes {
                    peer,
                    state_root: target_state_root,
                    items: vec![neutrino_consensus_types::bootstrap::StateItem::node(
                        target_state_root,
                    )],
                }]
            }
            (
                SyncState::ProofBackfill {
                    from_height,
                    target_height,
                    ..
                },
                RpcProtocol::BlockProofByHeight,
            ) => {
                let (from, target) = (*from_height, *target_height);
                self.state = SyncState::ProofBackfill {
                    from_height: from,
                    target_height: target,
                    in_flight: false,
                };
                vec![SyncCommand::RequestBlockProofs {
                    peer,
                    start_height: from,
                    count: self.batch_sizes.block_proof_batch,
                }]
            }
            (
                SyncState::BodyBackfill {
                    from_height,
                    target_height,
                    ..
                },
                RpcProtocol::BlocksByRange,
            ) => {
                let (from, target) = (*from_height, *target_height);
                self.state = SyncState::BodyBackfill {
                    from_height: from,
                    target_height: target,
                    in_flight: false,
                };
                vec![SyncCommand::RequestBlocks {
                    peer,
                    start_height: from,
                    count: self.batch_sizes.block_batch,
                }]
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity;

    fn pid() -> PeerId {
        PeerId::from(identity::Keypair::generate_ed25519().public())
    }

    fn fresh_progress(chain_id: u64) -> LocalProgress {
        LocalProgress {
            chain_id,
            ..LocalProgress::default()
        }
    }

    fn peer_status(chain_id: u64, finalized: CheckpointIndex, head: Height) -> rpc::Status {
        rpc::Status {
            chain_id,
            chain_spec_hash: [0; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
            recursive_covered_chunks: finalized,
            checkpoint_hash: if finalized == 0 { [0; 32] } else { [0xAA; 32] },
            head_block_hash: [0xBB; 32],
            head_slot: head,
            head_height: head,
        }
    }

    #[test]
    fn init_handshakes_new_peers() {
        let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
        let peer = pid();
        let cmds = fsm.on_event(SyncEvent::PeerConnected(peer));
        assert_eq!(cmds, vec![SyncCommand::RequestStatus(peer)]);
        assert!(matches!(fsm.state(), SyncState::Init));
    }

    #[test]
    fn init_ignores_peer_with_wrong_chain_id() {
        let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
        let peer = pid();
        let cmds = fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(99, 5, 100),
        });
        assert!(cmds.is_empty(), "wrong chain id must not advance");
        assert!(matches!(fsm.state(), SyncState::Init));
        assert_eq!(fsm.sync_peer(), None);
    }

    #[test]
    fn init_ignores_peer_with_wrong_chain_spec_hash() {
        let mut progress = fresh_progress(7);
        progress.chain_spec_hash = [1; 32];
        let mut fsm = SyncMachine::new(SyncMode::Snap, progress);
        let peer = pid();
        let mut status = peer_status(7, 5, 100);
        status.chain_spec_hash = [2; 32];
        let cmds = fsm.on_event(SyncEvent::PeerStatus { peer, status });
        assert!(cmds.is_empty(), "wrong chain spec must not advance");
        assert!(matches!(fsm.state(), SyncState::Init));
        assert_eq!(fsm.sync_peer(), None);
    }

    #[test]
    fn init_ignores_status_when_peer_is_not_ahead() {
        let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
        let peer = pid();
        let cmds = fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 0, 0),
        });
        assert_eq!(cmds, [] as [SyncCommand; 0]);
        assert!(matches!(fsm.state(), SyncState::Init));
    }

    #[test]
    fn light_client_at_equal_finalized_enters_following() {
        let mut fsm = SyncMachine::new(SyncMode::LightClient, fresh_progress(7));
        let peer = pid();
        let cmds = fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 0, 0),
        });
        // Expect Following + topic subscribes.
        assert!(matches!(fsm.state(), SyncState::Following));
        assert!(cmds.contains(&SyncCommand::EnterFollowing));
        assert!(
            cmds.iter()
                .any(|c| matches!(c, SyncCommand::Subscribe(Topic::Checkpoints)))
        );
    }

    #[test]
    fn init_to_checkpoint_backfill_when_peer_is_ahead() {
        let mut fsm = SyncMachine::new(SyncMode::LightClient, fresh_progress(7));
        let peer = pid();
        let cmds = fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 10, 1280),
        });
        match fsm.state() {
            SyncState::CheckpointBackfill {
                local_finalized_index,
                target_index,
                in_flight,
            } => {
                assert_eq!(*local_finalized_index, 0);
                assert_eq!(*target_index, 10);
                assert!(*in_flight);
            }
            other => panic!("expected CheckpointBackfill, got {other:?}"),
        }
        assert_eq!(
            cmds,
            vec![SyncCommand::RequestHistoryProof {
                peer,
                start_checkpoint_hash: [0; 32],
                end_checkpoint_hash: [0xAA; 32],
            }]
        );
    }

    #[test]
    fn snap_skips_checkpoint_backfill_when_only_head_is_ahead() {
        let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
        let peer = pid();
        let cmds = fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 0, 3),
        });
        match fsm.state() {
            SyncState::HeaderBackfill {
                local_head_height,
                target_height,
                in_flight,
            } => {
                assert_eq!(*local_head_height, 0);
                assert_eq!(*target_height, 3);
                assert!(*in_flight);
            }
            other => panic!("expected HeaderBackfill, got {other:?}"),
        }
        assert_eq!(
            cmds,
            vec![SyncCommand::RequestBlocks {
                peer,
                start_height: 1,
                count: 16,
            }]
        );
    }

    #[test]
    fn full_sync_ignores_recursive_lag_and_targets_live_blocks() {
        for mode in [SyncMode::Snap, SyncMode::Archive] {
            let mut fsm = SyncMachine::new(mode, fresh_progress(7));
            let peer = pid();
            let cmds = fsm.on_event(SyncEvent::PeerStatus {
                peer,
                status: peer_status(7, 2, 300),
            });
            assert!(matches!(
                fsm.state(),
                SyncState::HeaderBackfill {
                    target_height: 300,
                    ..
                }
            ));
            assert!(
                cmds.iter()
                    .any(|command| matches!(command, SyncCommand::RequestBlocks { .. }))
            );
            assert!(
                !cmds
                    .iter()
                    .any(|command| matches!(command, SyncCommand::RequestHistoryProof { .. }))
            );
            let before = *fsm.progress();
            assert_eq!(
                fsm.on_event(SyncEvent::CheckpointsAdvanced {
                    new_finalized_index: 99,
                    new_finalized_hash: [99; 32],
                    new_finalized_state_root: [99; 32],
                    new_finalized_height: 999,
                    new_finalized_block_hash: [99; 32],
                }),
                [] as [SyncCommand; 0]
            );
            assert_eq!(*fsm.progress(), before);
        }
    }

    #[test]
    fn checkpoint_backfill_completes_for_light_client() {
        let mut fsm = SyncMachine::new(SyncMode::LightClient, fresh_progress(7));
        let peer = pid();
        fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 4, 512),
        });
        // Apply 4 checkpoint advances (the driver verified each batch).
        for i in 1_u8..=4 {
            let cmds = fsm.on_event(SyncEvent::CheckpointsAdvanced {
                new_finalized_index: u64::from(i),
                new_finalized_hash: [i; 32],
                new_finalized_state_root: [i; 32],
                new_finalized_height: u64::from(i) * 128,
                new_finalized_block_hash: [i; 32],
            });
            if i < 4 {
                // Should request next batch.
                assert!(
                    cmds.iter()
                        .any(|c| matches!(c, SyncCommand::RequestHistoryProof { .. }))
                );
                assert!(matches!(fsm.state(), SyncState::CheckpointBackfill { .. }));
            } else {
                // Final batch — LightClient goes straight to Following.
                assert!(matches!(fsm.state(), SyncState::Following));
                assert!(cmds.contains(&SyncCommand::EnterFollowing));
                assert!(!cmds.contains(&SyncCommand::Subscribe(Topic::Blocks)));
            }
        }
    }

    #[test]
    fn snap_walks_full_state_sequence() {
        let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
        let peer = pid();

        // Peer ahead at checkpoint=2, head=256.
        fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 2, 256),
        });
        assert!(matches!(
            fsm.state(),
            SyncState::HeaderBackfill {
                target_height: 256,
                ..
            }
        ));
        // The full-node backend obtains finality from complete Chunk proofs;
        // emulate its independently authenticated finalized state cursor.
        fsm.progress.finalized_state_root = [2; 32];
        fsm.progress.finalized_height = 256;

        // Driver imports headers up to height 256.
        let cmds = fsm.on_event(SyncEvent::HeadersAdvanced {
            new_head_height: 256,
            new_head_hash: [2; 32],
            new_head_slot: 256,
        });
        match fsm.state() {
            SyncState::StateFetch { target_state_root } => {
                assert_eq!(*target_state_root, [2; 32]);
            }
            other => panic!("expected StateFetch, got {other:?}"),
        }
        assert!(
            cmds.iter()
                .any(|c| matches!(c, SyncCommand::RequestStateNodes { .. }))
        );

        // Driver reports state root reconstructed → ProofBackfill or
        // (if proven_height == head_height) straight to Following.
        let cmds = fsm.on_event(SyncEvent::StateRootReconstructed([2; 32]));
        // proven_height is 0 (default), so we should enter ProofBackfill.
        assert!(matches!(fsm.state(), SyncState::ProofBackfill { .. }));
        assert!(
            cmds.iter()
                .any(|c| matches!(c, SyncCommand::RequestBlockProofs { .. }))
        );

        // Driver fills proofs up to head height.
        let cmds = fsm.on_event(SyncEvent::ProofsAdvanced {
            new_proven_height: 256,
        });
        assert!(matches!(fsm.state(), SyncState::Following));
        assert!(cmds.contains(&SyncCommand::EnterFollowing));
    }

    #[test]
    fn archive_inserts_body_backfill_before_following() {
        let mut progress = fresh_progress(7);
        // Pretend head is already at height 8 (we'll target up to 256 once
        // checkpoints land).
        progress.head_height = 8;
        let mut fsm = SyncMachine::new(SyncMode::Archive, progress);
        let peer = pid();
        fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 1, 256),
        });
        // The full backend supplied this finalized Chunk state independently.
        fsm.progress.finalized_state_root = [1; 32];
        fsm.progress.finalized_height = 256;
        // Should now be in HeaderBackfill.
        assert!(matches!(fsm.state(), SyncState::HeaderBackfill { .. }));
        fsm.on_event(SyncEvent::HeadersAdvanced {
            new_head_height: 256,
            new_head_hash: [1; 32],
            new_head_slot: 256,
        });
        assert!(matches!(fsm.state(), SyncState::StateFetch { .. }));
        fsm.on_event(SyncEvent::StateRootReconstructed([1; 32]));
        assert!(matches!(fsm.state(), SyncState::ProofBackfill { .. }));
        // Proofs fill in.
        fsm.on_event(SyncEvent::ProofsAdvanced {
            new_proven_height: 256,
        });
        // Archive mode goes to BodyBackfill, not Following.
        match fsm.state() {
            SyncState::BodyBackfill { target_height, .. } => {
                assert_eq!(*target_height, 256);
            }
            other => panic!("expected BodyBackfill, got {other:?}"),
        }
        let cmds = fsm.on_event(SyncEvent::BodiesAdvanced {
            new_body_height: 256,
        });
        assert!(matches!(fsm.state(), SyncState::Following));
        assert!(cmds.contains(&SyncCommand::EnterFollowing));
    }

    #[test]
    fn lost_sync_peer_resets_to_init() {
        let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
        let peer = pid();
        fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 5, 640),
        });
        assert!(matches!(fsm.state(), SyncState::HeaderBackfill { .. }));

        fsm.on_event(SyncEvent::PeerDisconnected(peer));
        assert!(matches!(fsm.state(), SyncState::Init));
        assert_eq!(fsm.sync_peer(), None);
    }

    #[test]
    fn history_unavailable_waits_for_notification() {
        let mut fsm = SyncMachine::new(SyncMode::LightClient, fresh_progress(7));
        let peer = pid();
        fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 5, 640),
        });
        let cmds = fsm.on_event(SyncEvent::RpcFailed {
            protocol: RpcProtocol::HistoryProofByRange,
            peer,
            error: "transport closed".to_owned(),
        });
        assert_eq!(cmds, [] as [SyncCommand; 0]);
        match fsm.state() {
            SyncState::CheckpointBackfill { in_flight, .. } => assert!(!in_flight),
            other => panic!("expected CheckpointBackfill, got {other:?}"),
        }
        let resumed = fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 5, 640),
        });
        assert!(
            resumed
                .iter()
                .any(|cmd| matches!(cmd, SyncCommand::RequestHistoryProof { .. }))
        );
    }

    #[test]
    fn history_provider_failover_preserves_anchors_and_single_in_flight_request() {
        let mut local = fresh_progress(7);
        local.recursive_covered_chunks = 2;
        local.checkpoint_hash = [2; 32];
        let mut fsm = SyncMachine::new(SyncMode::LightClient, local);
        let original = pid();
        let replacement = pid();
        let status = peer_status(7, 5, 640);
        fsm.on_event(SyncEvent::PeerStatus {
            peer: original,
            status,
        });
        assert_eq!(fsm.retry_history_from(replacement), [] as [SyncCommand; 0]);
        fsm.on_event(SyncEvent::PeerDisconnected(original));
        assert_eq!(
            fsm.retry_history_from(replacement),
            vec![SyncCommand::RequestHistoryProof {
                peer: replacement,
                start_checkpoint_hash: local.checkpoint_hash,
                end_checkpoint_hash: status.checkpoint_hash,
            }]
        );
        assert_eq!(fsm.retry_history_from(original), [] as [SyncCommand; 0]);
        assert_eq!(fsm.progress(), &local);
        let mut full = SyncMachine::new(SyncMode::Snap, local);
        assert_eq!(full.retry_history_from(original), [] as [SyncCommand; 0]);
    }

    #[test]
    fn light_client_ignores_larger_header_heads_with_older_recursive_coverage() {
        let mut local = fresh_progress(7);
        local.recursive_covered_chunks = 10;
        local.checkpoint_hash = [10; 32];
        local.head_height = 1_280;
        let mut fsm = SyncMachine::new(SyncMode::LightClient, local);
        fsm.state = SyncState::Following;
        let peer = pid();
        assert_eq!(
            fsm.on_event(SyncEvent::PeerStatus {
                peer,
                status: peer_status(7, 9, 5_000),
            }),
            [] as [SyncCommand; 0]
        );
        assert_eq!(fsm.state(), &SyncState::Following);
        let commands = fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 20, 2_560),
        });
        assert!(matches!(
            commands.as_slice(),
            [SyncCommand::RequestHistoryProof { .. }]
        ));
    }

    #[test]
    fn in_flight_history_keeps_its_provider_target_and_ignores_foreign_failures() {
        let mut fsm = SyncMachine::new(SyncMode::LightClient, fresh_progress(7));
        let original = pid();
        let other = pid();
        fsm.on_event(SyncEvent::PeerStatus {
            peer: original,
            status: peer_status(7, 5, 640),
        });
        let state = fsm.state().clone();
        assert_eq!(
            fsm.on_event(SyncEvent::PeerStatus {
                peer: other,
                status: peer_status(7, 20, 2_560),
            }),
            [] as [SyncCommand; 0]
        );
        fsm.on_event(SyncEvent::PeerDisconnected(other));
        fsm.on_event(SyncEvent::RpcFailed {
            protocol: RpcProtocol::HistoryProofByRange,
            peer: other,
            error: "old request".to_owned(),
        });
        assert_eq!(fsm.state(), &state);
        assert_eq!(fsm.sync_peer(), Some(original));
        assert_eq!(fsm.retry_history_from(other), [] as [SyncCommand; 0]);
    }

    #[test]
    fn state_fetch_rpc_failure_retries_root_request() {
        let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
        let peer = pid();
        fsm.state = SyncState::StateFetch {
            target_state_root: [9; 32],
        };
        let cmds = fsm.on_event(SyncEvent::RpcFailed {
            protocol: RpcProtocol::StateByRoot,
            peer,
            error: "timeout".to_owned(),
        });
        assert_eq!(
            cmds,
            vec![SyncCommand::RequestStateNodes {
                peer,
                state_root: [9; 32],
                items: vec![neutrino_consensus_types::bootstrap::StateItem::node(
                    [9; 32]
                )],
            }]
        );
    }

    #[test]
    fn body_backfill_rpc_failure_retries_body_batch() {
        let mut fsm = SyncMachine::new(SyncMode::Archive, fresh_progress(7));
        let peer = pid();
        fsm.state = SyncState::BodyBackfill {
            from_height: 17,
            target_height: 32,
            in_flight: true,
        };
        let cmds = fsm.on_event(SyncEvent::RpcFailed {
            protocol: RpcProtocol::BlocksByRange,
            peer,
            error: "timeout".to_owned(),
        });
        assert_eq!(
            cmds,
            vec![SyncCommand::RequestBlocks {
                peer,
                start_height: 17,
                count: 16,
            }]
        );
        match fsm.state() {
            SyncState::BodyBackfill { in_flight, .. } => assert!(!in_flight),
            other => panic!("expected BodyBackfill, got {other:?}"),
        }
    }

    #[test]
    fn reset_clears_state() {
        let mut fsm = SyncMachine::new(SyncMode::Snap, fresh_progress(7));
        let peer = pid();
        fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 5, 640),
        });
        assert!(matches!(fsm.state(), SyncState::HeaderBackfill { .. }));
        fsm.on_event(SyncEvent::Reset);
        assert!(matches!(fsm.state(), SyncState::Init));
        assert_eq!(fsm.sync_peer(), None);
    }
    #[test]
    fn light_client_requires_endpoint_identity_and_resumes_on_new_status() {
        let mut fsm = SyncMachine::new(SyncMode::LightClient, fresh_progress(7));
        let peer = pid();
        let mut conflict = peer_status(7, 0, 0);
        conflict.checkpoint_hash = [99; 32];
        assert_eq!(
            fsm.on_event(SyncEvent::PeerStatus {
                peer,
                status: conflict
            }),
            [] as [SyncCommand; 0]
        );
        assert_eq!(fsm.state(), &SyncState::Init);
        fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 0, 0),
        });
        assert_eq!(fsm.state(), &SyncState::Following);
        let commands = fsm.on_event(SyncEvent::PeerStatus {
            peer,
            status: peer_status(7, 1, 128),
        });
        assert!(
            commands
                .iter()
                .any(|cmd| matches!(cmd, SyncCommand::RequestHistoryProof { .. }))
        );
    }
}
