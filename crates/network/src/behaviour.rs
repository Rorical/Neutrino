#![allow(missing_docs)]

use crate::rpc::{
    BlockProofByHashBehaviour, BlockProofByHeightBehaviour, BlocksByRangeBehaviour,
    BlocksByRootBehaviour, ChunkProofByIdBehaviour, FinalityCertByChunkBehaviour,
    MetadataBehaviour, PingBehaviour, RecursiveProofByIndexBehaviour,
    RecursiveProofLatestBehaviour, StateByRootBehaviour, StatusBehaviour, WitnessByBlockBehaviour,
};
use libp2p::{
    connection_limits, gossipsub, identify,
    kad::{self, store::MemoryStore},
    ping,
    swarm::NetworkBehaviour,
};

/// The composed libp2p `NetworkBehaviour` for Neutrino.
///
/// Combines:
/// - [`gossipsub::Behaviour`] — pub/sub for blocks, txs, proofs, votes (doc 06).
/// - [`kad::Behaviour`] with an in-memory routing store — peer discovery.
/// - [`identify::Behaviour`] — protocol negotiation and listen-addr exchange.
/// - [`ping::Behaviour`] — keepalive and RTT estimation.
/// - [`connection_limits::Behaviour`] — DoS resistance via hard caps.
/// - Eleven `request_response::Behaviour` instances, one per RPC: the six
///   core protocols (`status`, `metadata`, `ping` reply, `blocks_by_range`,
///   `blocks_by_root`, `state_by_root`) plus proof retrieval endpoints for
///   block, chunk, and recursive proofs.
#[derive(NetworkBehaviour)]
pub struct NeutrinoBehaviour {
    /// Connection limits to prevent resource exhaustion.
    pub connection_limits: connection_limits::Behaviour,
    /// Identify protocol for peer capability and address exchange.
    pub identify: identify::Behaviour,
    /// Ping protocol to keep connections alive and measure RTT.
    pub ping: ping::Behaviour,
    /// Gossipsub v1.1 for topic-based broadcast.
    pub gossipsub: gossipsub::Behaviour,
    /// Kademlia DHT for peer discovery.
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// `/neutrino/req/status/1` request/response.
    pub rpc_status: StatusBehaviour,
    /// `/neutrino/req/metadata/1` request/response.
    pub rpc_metadata: MetadataBehaviour,
    /// `/neutrino/req/ping/1` request/response.
    pub rpc_ping: PingBehaviour,
    /// `/neutrino/req/blocks_by_range/1` request/response.
    pub rpc_blocks_by_range: BlocksByRangeBehaviour,
    /// `/neutrino/req/blocks_by_root/1` request/response.
    pub rpc_blocks_by_root: BlocksByRootBehaviour,
    /// `/neutrino/req/state_by_root/1` request/response.
    pub rpc_state_by_root: StateByRootBehaviour,
    /// `/neutrino/req/block_proof_by_hash/1` request/response.
    pub rpc_block_proof_by_hash: BlockProofByHashBehaviour,
    /// `/neutrino/req/block_proof_by_height/1` request/response.
    pub rpc_block_proof_by_height: BlockProofByHeightBehaviour,
    /// `/neutrino/req/chunk_proof_by_id/1` request/response.
    pub rpc_chunk_proof_by_id: ChunkProofByIdBehaviour,
    /// `/neutrino/req/recursive_proof_latest/1` request/response.
    pub rpc_recursive_proof_latest: RecursiveProofLatestBehaviour,
    /// `/neutrino/req/recursive_proof_by_index/1` request/response.
    pub rpc_recursive_proof_by_index: RecursiveProofByIndexBehaviour,
    /// `/neutrino/req/finality_cert_by_chunk/1` request/response.
    pub rpc_finality_cert_by_chunk: FinalityCertByChunkBehaviour,
    /// `/neutrino/req/witness_by_block/1` request/response.
    pub rpc_witness_by_block: WitnessByBlockBehaviour,
}
