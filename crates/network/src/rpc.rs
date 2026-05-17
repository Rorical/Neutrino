//! Request/response RPC for Neutrino, per doc 06 §"Request/response protocols".
//!
//! Implements the **core** RPC family every full node supports:
//!
//! | Protocol id                          | Request → Response                  |
//! |--------------------------------------|-------------------------------------|
//! | `/neutrino/req/status/1`             | [`Status`] → [`Status`]             |
//! | `/neutrino/req/metadata/1`           | [`MetadataRequest`] → [`Metadata`]  |
//! | `/neutrino/req/ping/1`               | [`PingPayload`] → [`PingPayload`]   |
//! | `/neutrino/req/blocks_by_range/1`    | [`BlocksByRangeRequest`] → [`BlocksByRangeResponse`] |
//! | `/neutrino/req/blocks_by_root/1`     | [`BlocksByRootRequest`]  → [`BlocksByRootResponse`]  |
//! | `/neutrino/req/state_by_root/1`      | [`StateByRootRequest`]   → [`StateByRootResponse`]   |
//!
//! Every request and response is canonically encoded with `borsh`, matching
//! the wire format used by gossip and on-disk consensus types.
//!
//! Each protocol runs as its own [`request_response::Behaviour`] so per-protocol
//! peer scoring, rate limits, and size caps can be tuned independently. The
//! umbrella [`RpcRequest`] and [`RpcResponse`] enums exist only at the
//! crate-internal command/event boundary; they are never serialized to the wire.

use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use core::marker::PhantomData;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response};
use neutrino_consensus_types::Block;
use neutrino_primitives::{BlockHash, ChainId, CheckpointIndex, Hash, Height, Slot, StateRoot};
use std::io;
use thiserror::Error;

/// Status RPC protocol id.
pub const PROTOCOL_STATUS: &str = "/neutrino/req/status/1";
/// Metadata RPC protocol id.
pub const PROTOCOL_METADATA: &str = "/neutrino/req/metadata/1";
/// Ping RPC protocol id.
pub const PROTOCOL_PING: &str = "/neutrino/req/ping/1";
/// `BlocksByRange` RPC protocol id.
pub const PROTOCOL_BLOCKS_BY_RANGE: &str = "/neutrino/req/blocks_by_range/1";
/// `BlocksByRoot` RPC protocol id.
pub const PROTOCOL_BLOCKS_BY_ROOT: &str = "/neutrino/req/blocks_by_root/1";
/// `StateByRoot` RPC protocol id.
pub const PROTOCOL_STATE_BY_ROOT: &str = "/neutrino/req/state_by_root/1";

/// Default maximum request payload size in bytes (1 MiB).
pub const DEFAULT_MAX_REQUEST_SIZE: u64 = 1024 * 1024;
/// Default maximum response payload size in bytes (16 MiB).
pub const DEFAULT_MAX_RESPONSE_SIZE: u64 = 16 * 1024 * 1024;

/// Maximum number of blocks returned in a single `BlocksByRange` response.
///
/// Caller-driven pagination keeps any individual response below
/// [`DEFAULT_MAX_RESPONSE_SIZE`] even when blocks carry full bodies and
/// proofs.
pub const MAX_BLOCKS_PER_RESPONSE: u64 = 16;
/// Maximum number of paths queried in a single `StateByRoot` request.
pub const MAX_STATE_PATHS_PER_REQUEST: u64 = 256;

/// Identifies one of the core RPC protocols defined by doc 06.
///
/// Used to namespace per-protocol request IDs across the six independent
/// [`request_response::Behaviour`] instances.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RpcProtocol {
    /// Doc 06 `/neutrino/req/status/1`.
    Status,
    /// Doc 06 `/neutrino/req/metadata/1`.
    Metadata,
    /// Doc 06 `/neutrino/req/ping/1`.
    Ping,
    /// Doc 06 `/neutrino/req/blocks_by_range/1`.
    BlocksByRange,
    /// Doc 06 `/neutrino/req/blocks_by_root/1`.
    BlocksByRoot,
    /// Doc 06 `/neutrino/req/state_by_root/1`.
    StateByRoot,
}

impl RpcProtocol {
    /// Canonical wire protocol id.
    #[must_use]
    pub const fn protocol_id(self) -> &'static str {
        match self {
            Self::Status => PROTOCOL_STATUS,
            Self::Metadata => PROTOCOL_METADATA,
            Self::Ping => PROTOCOL_PING,
            Self::BlocksByRange => PROTOCOL_BLOCKS_BY_RANGE,
            Self::BlocksByRoot => PROTOCOL_BLOCKS_BY_ROOT,
            Self::StateByRoot => PROTOCOL_STATE_BY_ROOT,
        }
    }

    /// Build a [`StreamProtocol`] from the protocol id.
    #[must_use]
    pub const fn stream_protocol(self) -> StreamProtocol {
        StreamProtocol::new(self.protocol_id())
    }
}

/// Status handshake exchanged on every new connection.
///
/// Used by peers to detect chain mismatches and as input to the sync FSM
/// described in doc 06 §"Sync state machine".
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct Status {
    /// Chain identifier; mismatching peers should be disconnected.
    pub chain_id: ChainId,
    /// Highest checkpoint index finalized by the local node.
    pub finalized_checkpoint_index: CheckpointIndex,
    /// Hash of the highest finalized [`Checkpoint`].
    pub finalized_checkpoint_hash: Hash,
    /// Hash of the current local fork-choice head.
    pub head_block_hash: BlockHash,
    /// Slot of the current head.
    pub head_slot: Slot,
    /// Height of the current head.
    pub head_height: Height,
}

/// Empty metadata request marker.
///
/// Borsh deserializes a zero-byte payload as the unit struct, matching the
/// `() → Metadata` shape in doc 06.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetadataRequest;

/// Self-declared peer capabilities and seq number.
///
/// `vote_subnet_bits` packs one bit per subnet (LSB-first); `role_flags` is
/// a bitmask of [`RoleFlags`].
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Metadata {
    /// Monotonically incremented on every change to subscriptions or roles.
    pub seq_number: u64,
    /// Bitmask over `VOTE_SUBNETS = 16` finality-vote subnets.
    pub vote_subnet_bits: u16,
    /// Self-declared role flags, see [`RoleFlags`].
    pub role_flags: u32,
}

/// Self-declared role bits a peer advertises in [`Metadata`].
///
/// Roles are advisory only — misbehaviour is detected by application-level
/// scoring, not enforced cryptographically.
pub mod role_flags {
    /// Honest full node serving any other full node.
    pub const FULL_NODE: u32 = 1 << 0;
    /// Staked validator participating in proposer election and finality.
    pub const VALIDATOR: u32 = 1 << 1;
    /// Produces block proofs against the canonical runtime.
    pub const BLOCK_PROVER: u32 = 1 << 2;
    /// Aggregates ~128 block proofs into one chunk proof.
    pub const CHUNK_AGGREGATOR: u32 = 1 << 3;
    /// Produces recursive checkpoint proofs.
    pub const CHECKPOINT_PROVER: u32 = 1 << 4;
    /// Picks up missed-deadline blocks for the prover bounty market.
    pub const FALLBACK_PROVER: u32 = 1 << 5;
    /// Light client; verifier-only.
    pub const LIGHT_CLIENT: u32 = 1 << 6;
    /// Archive node retaining all bodies, proofs, and witnesses forever.
    pub const ARCHIVE: u32 = 1 << 7;
}

/// Ping payload — a free-form 64-bit nonce.
///
/// Per doc 06 the ping protocol is `u64 → u64`. Senders generally echo the
/// nonce; receivers may return anything.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PingPayload {
    /// Free-form 64-bit nonce.
    pub nonce: u64,
}

/// `BlocksByRange` request: stream blocks at `[start_height, start_height + count*step)`.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct BlocksByRangeRequest {
    /// First block height to include.
    pub start_height: Height,
    /// Number of blocks to include; clamped to [`MAX_BLOCKS_PER_RESPONSE`].
    pub count: u64,
    /// Stride between consecutive blocks. `1` for backfill, `>1` for sampling.
    pub step: u64,
}

/// `BlocksByRange` response carrying the requested blocks in height order.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct BlocksByRangeResponse {
    /// Blocks in canonical height order.
    pub blocks: Vec<Block>,
}

/// `BlocksByRoot` request: fetch specific blocks by header hash.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct BlocksByRootRequest {
    /// Block header hashes to fetch.
    pub roots: Vec<BlockHash>,
}

/// `BlocksByRoot` response carrying the requested blocks.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct BlocksByRootResponse {
    /// Blocks in the same order as the requested roots; entries omitted when unknown.
    pub blocks: Vec<Block>,
}

/// `StateByRoot` request: fetch trie nodes covering specified paths.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct StateByRootRequest {
    /// State trie root the paths address.
    pub state_root: StateRoot,
    /// Raw trie keys (or sub-paths) being requested.
    pub paths: Vec<Vec<u8>>,
}

/// `StateByRoot` response carrying trie node payloads.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct StateByRootResponse {
    /// Trie node bytes in the same order as the requested paths.
    pub nodes: Vec<Vec<u8>>,
}

/// Host-facing umbrella request enum used by the command surface.
///
/// Never serialized to the wire — each variant maps to a different
/// [`request_response::Behaviour`] which serializes only the inner type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcRequest {
    /// Status handshake.
    Status(Status),
    /// Metadata query.
    Metadata(MetadataRequest),
    /// Ping with a nonce.
    Ping(PingPayload),
    /// Block backfill by height range.
    BlocksByRange(BlocksByRangeRequest),
    /// Block fetch by header hash.
    BlocksByRoot(BlocksByRootRequest),
    /// State trie node fetch.
    StateByRoot(StateByRootRequest),
}

impl RpcRequest {
    /// Which protocol the variant maps to.
    #[must_use]
    pub const fn protocol(&self) -> RpcProtocol {
        match self {
            Self::Status(_) => RpcProtocol::Status,
            Self::Metadata(_) => RpcProtocol::Metadata,
            Self::Ping(_) => RpcProtocol::Ping,
            Self::BlocksByRange(_) => RpcProtocol::BlocksByRange,
            Self::BlocksByRoot(_) => RpcProtocol::BlocksByRoot,
            Self::StateByRoot(_) => RpcProtocol::StateByRoot,
        }
    }
}

/// Host-facing umbrella response enum used by the event surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcResponse {
    /// Status handshake reply.
    Status(Status),
    /// Metadata reply.
    Metadata(Metadata),
    /// Ping reply.
    Ping(PingPayload),
    /// `BlocksByRange` reply.
    BlocksByRange(BlocksByRangeResponse),
    /// `BlocksByRoot` reply.
    BlocksByRoot(BlocksByRootResponse),
    /// `StateByRoot` reply.
    StateByRoot(StateByRootResponse),
}

impl RpcResponse {
    /// Which protocol the variant maps to.
    #[must_use]
    pub const fn protocol(&self) -> RpcProtocol {
        match self {
            Self::Status(_) => RpcProtocol::Status,
            Self::Metadata(_) => RpcProtocol::Metadata,
            Self::Ping(_) => RpcProtocol::Ping,
            Self::BlocksByRange(_) => RpcProtocol::BlocksByRange,
            Self::BlocksByRoot(_) => RpcProtocol::BlocksByRoot,
            Self::StateByRoot(_) => RpcProtocol::StateByRoot,
        }
    }
}

/// Errors surfaced to RPC callers.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RpcError {
    /// libp2p reported an outbound request failure.
    #[error("outbound failure: {0}")]
    Outbound(String),
    /// The host attempted to reply to an inbound RPC with the wrong response type.
    #[error("response type mismatch: protocol {expected:?}, got {actual:?}")]
    ResponseTypeMismatch {
        /// Expected protocol (matching the inbound request).
        expected: RpcProtocol,
        /// Protocol of the response the host supplied.
        actual: RpcProtocol,
    },
    /// The inbound request id is unknown (timed out or already answered).
    #[error("unknown inbound request id: {0:?}")]
    UnknownInboundId(RpcInboundId),
    /// libp2p rejected the response: peer disconnected before delivery.
    #[error("failed to deliver response to peer")]
    ResponseDeliveryFailed,
}

/// Stable, protocol-namespaced inbound request identifier.
///
/// libp2p's `InboundRequestId` is only unique within a single
/// [`request_response::Behaviour`], so we tag each id with the originating
/// [`RpcProtocol`] before exposing it to host code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RpcInboundId {
    /// Protocol that produced the underlying libp2p id.
    pub protocol: RpcProtocol,
    /// Raw libp2p inbound request id, unique per protocol.
    pub raw: u64,
}

/// Generic borsh request/response codec.
///
/// One instance is parameterized per protocol via the (`Req`, `Resp`) type pair.
/// The implementation mirrors the canonical libp2p `cbor::codec::Codec`: it
/// reads up to `request_size_maximum` (or `response_size_maximum`) bytes,
/// then borsh-deserializes. Encoding writes the full borsh payload in one
/// `write_all` call.
pub struct BorshCodec<Req, Resp> {
    request_size_maximum: u64,
    response_size_maximum: u64,
    phantom: PhantomData<(Req, Resp)>,
}

impl<Req, Resp> Default for BorshCodec<Req, Resp> {
    fn default() -> Self {
        Self {
            request_size_maximum: DEFAULT_MAX_REQUEST_SIZE,
            response_size_maximum: DEFAULT_MAX_RESPONSE_SIZE,
            phantom: PhantomData,
        }
    }
}

impl<Req, Resp> Clone for BorshCodec<Req, Resp> {
    fn clone(&self) -> Self {
        Self {
            request_size_maximum: self.request_size_maximum,
            response_size_maximum: self.response_size_maximum,
            phantom: PhantomData,
        }
    }
}

impl<Req, Resp> BorshCodec<Req, Resp> {
    /// Override the maximum request payload size in bytes.
    #[must_use]
    pub const fn with_request_size_maximum(mut self, max: u64) -> Self {
        self.request_size_maximum = max;
        self
    }

    /// Override the maximum response payload size in bytes.
    #[must_use]
    pub const fn with_response_size_maximum(mut self, max: u64) -> Self {
        self.response_size_maximum = max;
        self
    }
}

#[async_trait]
impl<Req, Resp> request_response::Codec for BorshCodec<Req, Resp>
where
    Req: BorshSerialize + BorshDeserialize + Send + 'static,
    Resp: BorshSerialize + BorshDeserialize + Send + 'static,
{
    type Protocol = StreamProtocol;
    type Request = Req;
    type Response = Resp;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Req>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(self.request_size_maximum)
            .read_to_end(&mut buf)
            .await?;
        Req::try_from_slice(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Resp>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(self.response_size_maximum)
            .read_to_end(&mut buf)
            .await?;
        Resp::try_from_slice(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn write_request<T>(&mut self, _: &StreamProtocol, io: &mut T, req: Req) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = borsh::to_vec(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        io.write_all(&bytes).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        resp: Resp,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = borsh::to_vec(&resp)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        io.write_all(&bytes).await?;
        Ok(())
    }
}

// --- Per-protocol type aliases ------------------------------------------------

/// Codec for the Status RPC.
pub type StatusCodec = BorshCodec<Status, Status>;
/// Codec for the Metadata RPC.
pub type MetadataCodec = BorshCodec<MetadataRequest, Metadata>;
/// Codec for the Ping RPC.
pub type PingCodec = BorshCodec<PingPayload, PingPayload>;
/// Codec for the `BlocksByRange` RPC.
pub type BlocksByRangeCodec = BorshCodec<BlocksByRangeRequest, BlocksByRangeResponse>;
/// Codec for the `BlocksByRoot` RPC.
pub type BlocksByRootCodec = BorshCodec<BlocksByRootRequest, BlocksByRootResponse>;
/// Codec for the `StateByRoot` RPC.
pub type StateByRootCodec = BorshCodec<StateByRootRequest, StateByRootResponse>;

/// Behaviour type for the Status RPC.
pub type StatusBehaviour = request_response::Behaviour<StatusCodec>;
/// Behaviour type for the Metadata RPC.
pub type MetadataBehaviour = request_response::Behaviour<MetadataCodec>;
/// Behaviour type for the Ping RPC.
pub type PingBehaviour = request_response::Behaviour<PingCodec>;
/// Behaviour type for the `BlocksByRange` RPC.
pub type BlocksByRangeBehaviour = request_response::Behaviour<BlocksByRangeCodec>;
/// Behaviour type for the `BlocksByRoot` RPC.
pub type BlocksByRootBehaviour = request_response::Behaviour<BlocksByRootCodec>;
/// Behaviour type for the `StateByRoot` RPC.
pub type StateByRootBehaviour = request_response::Behaviour<StateByRootCodec>;

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::{from_slice, to_vec};
    use futures_ringbuf::Endpoint;
    use libp2p::request_response::Codec;
    use neutrino_consensus_types::{Body, Header};
    use neutrino_primitives::HEADER_VERSION;

    fn sample_header() -> Header {
        Header {
            version: HEADER_VERSION,
            height: 7,
            slot: 9,
            parent_hash: [1; 32],
            proposer_index: 2,
            vrf_proof: [3; 96],
            state_root: [4; 32],
            transactions_root: [5; 32],
            votes_root: [6; 32],
            slashings_root: [7; 32],
            validator_ops_root: [8; 32],
            da_root: [9; 32],
            runtime_extra: [10; 32],
            gas_used: 100,
            gas_limit: 1_000_000,
            timestamp: 1_800_000_000,
            signature: [11; 96],
        }
    }

    fn sample_block() -> Block {
        Block {
            header: sample_header(),
            body: Body::default(),
        }
    }

    #[test]
    fn protocol_ids_match_doc_06() {
        assert_eq!(RpcProtocol::Status.protocol_id(), "/neutrino/req/status/1");
        assert_eq!(
            RpcProtocol::Metadata.protocol_id(),
            "/neutrino/req/metadata/1"
        );
        assert_eq!(RpcProtocol::Ping.protocol_id(), "/neutrino/req/ping/1");
        assert_eq!(
            RpcProtocol::BlocksByRange.protocol_id(),
            "/neutrino/req/blocks_by_range/1"
        );
        assert_eq!(
            RpcProtocol::BlocksByRoot.protocol_id(),
            "/neutrino/req/blocks_by_root/1"
        );
        assert_eq!(
            RpcProtocol::StateByRoot.protocol_id(),
            "/neutrino/req/state_by_root/1"
        );
    }

    #[test]
    fn rpc_request_protocol_tagging_is_consistent() {
        let cases = [
            (
                RpcRequest::Status(Status {
                    chain_id: 1,
                    finalized_checkpoint_index: 0,
                    finalized_checkpoint_hash: [0; 32],
                    head_block_hash: [0; 32],
                    head_slot: 0,
                    head_height: 0,
                }),
                RpcProtocol::Status,
            ),
            (RpcRequest::Metadata(MetadataRequest), RpcProtocol::Metadata),
            (
                RpcRequest::Ping(PingPayload { nonce: 42 }),
                RpcProtocol::Ping,
            ),
            (
                RpcRequest::BlocksByRange(BlocksByRangeRequest {
                    start_height: 0,
                    count: 1,
                    step: 1,
                }),
                RpcProtocol::BlocksByRange,
            ),
            (
                RpcRequest::BlocksByRoot(BlocksByRootRequest { roots: vec![] }),
                RpcProtocol::BlocksByRoot,
            ),
            (
                RpcRequest::StateByRoot(StateByRootRequest {
                    state_root: [0; 32],
                    paths: vec![],
                }),
                RpcProtocol::StateByRoot,
            ),
        ];
        for (req, expected) in cases {
            assert_eq!(req.protocol(), expected);
        }
    }

    #[test]
    fn status_round_trips_via_borsh() {
        let status = Status {
            chain_id: 7,
            finalized_checkpoint_index: 12,
            finalized_checkpoint_hash: [1; 32],
            head_block_hash: [2; 32],
            head_slot: 99,
            head_height: 88,
        };
        let bytes = to_vec(&status).unwrap();
        let decoded: Status = from_slice(&bytes).unwrap();
        assert_eq!(decoded, status);
    }

    #[test]
    fn metadata_round_trips_via_borsh() {
        let meta = Metadata {
            seq_number: 1,
            vote_subnet_bits: 0b0000_0000_0000_0110,
            role_flags: role_flags::FULL_NODE | role_flags::VALIDATOR,
        };
        let bytes = to_vec(&meta).unwrap();
        let decoded: Metadata = from_slice(&bytes).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn blocks_by_range_request_round_trips() {
        let req = BlocksByRangeRequest {
            start_height: 1000,
            count: 16,
            step: 1,
        };
        let bytes = to_vec(&req).unwrap();
        let decoded: BlocksByRangeRequest = from_slice(&bytes).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn blocks_by_range_response_round_trips() {
        let resp = BlocksByRangeResponse {
            blocks: vec![sample_block(), sample_block()],
        };
        let bytes = to_vec(&resp).unwrap();
        let decoded: BlocksByRangeResponse = from_slice(&bytes).unwrap();
        assert_eq!(decoded, resp);
    }

    #[tokio::test]
    async fn borsh_codec_round_trips_status() {
        let req = Status {
            chain_id: 9,
            finalized_checkpoint_index: 1,
            finalized_checkpoint_hash: [3; 32],
            head_block_hash: [4; 32],
            head_slot: 1,
            head_height: 1,
        };
        let mut codec = StatusCodec::default();
        let protocol = RpcProtocol::Status.stream_protocol();

        let (mut a, mut b) = Endpoint::pair(1024, 1024);
        codec
            .write_request(&protocol, &mut a, req.clone())
            .await
            .expect("write request");
        a.close().await.unwrap();
        let decoded = codec
            .read_request(&protocol, &mut b)
            .await
            .expect("read request");
        assert_eq!(decoded, req);
    }

    #[tokio::test]
    async fn borsh_codec_rejects_request_above_size_limit() {
        // Build a State request whose borsh size exceeds 100 bytes.
        let req = StateByRootRequest {
            state_root: [0; 32],
            paths: (0..16).map(|_| vec![0_u8; 64]).collect(),
        };
        let mut codec = StateByRootCodec::default().with_request_size_maximum(100);
        let protocol = RpcProtocol::StateByRoot.stream_protocol();

        let (mut a, mut b) = Endpoint::pair(2048, 2048);
        codec
            .write_request(&protocol, &mut a, req)
            .await
            .expect("write request");
        a.close().await.unwrap();
        let result = codec.read_request(&protocol, &mut b).await;
        assert!(result.is_err(), "oversized request must fail to decode");
    }
}
