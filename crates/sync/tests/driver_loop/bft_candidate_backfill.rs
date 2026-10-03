//! Transport regressions; node/engine tests authenticate the actual BLS and receipts.

use super::*;
use neutrino_consensus_types::{BftCandidate, Chunk, FinalityVoteData, FinalityVotePhase};
use neutrino_network::{Topic, rpc::CandidateByChunkResponse};

type Reply = tokio::sync::oneshot::Sender<Result<RpcResponse, neutrino_network::rpc::RpcError>>;

struct Harness {
    backend: MockBackend,
    events: mpsc::Sender<NetworkEvent>,
    commands: mpsc::Receiver<NetworkCommand>,
    deferred: std::collections::VecDeque<(PeerId, RpcRequest, Reply)>,
    runner: tokio::task::JoinHandle<Result<(), neutrino_sync::SyncDriverError>>,
    blocks: Vec<Block>,
    candidate: BftCandidate,
}

impl Harness {
    fn new() -> Self {
        let backend = MockBackend::default();
        {
            let mut state = backend.inner.lock().unwrap();
            state.full_chunk_size = Some(20);
            state.candidate_sync = true;
            state.status.chain_id = 1;
        }
        let mut blocks = Vec::new();
        let mut parent = [0; 32];
        for height in 1..=20 {
            let mut block = sample_block(height, height, 0);
            block.header.parent_hash = parent;
            parent = block.hash();
            blocks.push(block);
        }
        let candidate = BftCandidate {
            round: 0,
            justification: None,
            chunk: Chunk {
                chunk_id: 0,
                start_height: 1,
                end_height: 20,
                start_state_root: [0; 32],
                end_state_root: [1; 32],
                start_block_hash: blocks[0].hash(),
                end_block_hash: parent,
                block_hash_root: [2; 32],
                block_proof_root: [3; 32],
                vrf_proof_root: [4; 32],
                active_validator_set_root: [5; 32],
                next_validator_set_root: [5; 32],
                da_root: [6; 32],
            },
        };
        let (command_tx, commands) = mpsc::channel(64);
        let (events, event_rx) = mpsc::channel(64);
        let driver = SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend.clone()),
            LocalProgress {
                chain_id: 1,
                ..LocalProgress::default()
            },
            command_tx,
            event_rx,
        );
        Self {
            backend,
            events,
            commands,
            deferred: std::collections::VecDeque::new(),
            runner: tokio::spawn(driver.run()),
            blocks,
            candidate,
        }
    }

    async fn raw_request(&mut self) -> (PeerId, RpcRequest, Reply) {
        if let Some(request) = self.deferred.pop_front() {
            return request;
        }
        loop {
            match timeout(Duration::from_secs(1), self.commands.recv())
                .await
                .unwrap()
                .unwrap()
            {
                NetworkCommand::SendRpcRequest {
                    peer,
                    request,
                    response_tx,
                } => return (peer, request, response_tx),
                NetworkCommand::Subscribe(_) | NetworkCommand::ReportGossipValidation { .. } => {}
                other => panic!("unexpected command {other:?}"),
            }
        }
    }

    async fn request(&mut self) -> (PeerId, RpcRequest, Reply) {
        loop {
            let (peer, request, reply) = self.raw_request().await;
            if matches!(request, RpcRequest::Status(_)) {
                reply
                    .send(Ok(RpcResponse::Status(Status {
                        chain_id: 1,
                        ..Status::default()
                    })))
                    .unwrap();
            } else {
                return (peer, request, reply);
            }
        }
    }

    async fn connect(&mut self, peer: PeerId) {
        self.events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        let (owner, request, reply) = self.raw_request().await;
        assert_eq!(owner, peer);
        assert!(matches!(request, RpcRequest::Status(_)));
        // No ordinary canonical backfill is needed. The candidate is a different availability path.
        reply
            .send(Ok(RpcResponse::Status(Status {
                chain_id: 1,
                ..Status::default()
            })))
            .unwrap();
    }

    async fn gossip(&mut self, peer: PeerId, topic: Topic, data: Vec<u8>) {
        self.events
            .send(NetworkEvent::GossipMessage {
                topic,
                data,
                propagation_source: peer,
                message_id: neutrino_network::libp2p::gossipsub::MessageId::from(
                    b"candidate".to_vec(),
                ),
            })
            .await
            .unwrap();
        loop {
            match timeout(Duration::from_secs(1), self.commands.recv())
                .await
                .unwrap()
                .unwrap()
            {
                NetworkCommand::ReportGossipValidation { .. } => break,
                NetworkCommand::Subscribe(_) => {}
                NetworkCommand::SendRpcRequest {
                    peer,
                    request: RpcRequest::Status(_),
                    response_tx,
                } => {
                    let _ = peer;
                    response_tx
                        .send(Ok(RpcResponse::Status(Status {
                            chain_id: 1,
                            ..Status::default()
                        })))
                        .unwrap();
                }
                NetworkCommand::SendRpcRequest {
                    peer,
                    request,
                    response_tx,
                } => self.deferred.push_back((peer, request, response_tx)),
                other => panic!("unexpected gossip barrier command {other:?}"),
            }
        }
    }

    fn blocks_reply(&self, request: &RpcRequest) -> RpcResponse {
        let RpcRequest::BlocksByRange(request) = request else {
            panic!("expected branch blocks")
        };
        assert_eq!(request.head_block_hash, self.candidate.chunk.end_block_hash);
        assert_eq!(request.step, 1);
        let first = usize::try_from(request.start_height - 1).unwrap();
        let count = usize::try_from(request.count).unwrap();
        RpcResponse::BlocksByRange(BlocksByRangeResponse {
            blocks: self.blocks[first..first + count].to_vec(),
        })
    }

    fn proofs_reply(&self, request: &RpcRequest) -> RpcResponse {
        let RpcRequest::BlockProofByHeight(request) = request else {
            panic!("expected branch proofs")
        };
        assert_eq!(request.head_block_hash, self.candidate.chunk.end_block_hash);
        let proofs = (request.start_height..request.start_height + request.count)
            .map(|height| {
                let mut proof = sample_block_proof(height);
                proof.block_hash = self.blocks[usize::try_from(height - 1).unwrap()].hash();
                proof.public_inputs.block_hash = proof.block_hash;
                proof
            })
            .collect();
        RpcResponse::BlockProofByHeight(BlockProofByHeightResponse { proofs })
    }

    async fn finish(&mut self) {
        for _ in 0..5 {
            let (_, request, reply) = self.request().await;
            let response = if matches!(request, RpcRequest::BlocksByRange(_)) {
                self.blocks_reply(&request)
            } else {
                self.proofs_reply(&request)
            };
            reply.send(Ok(response)).unwrap();
        }
        self.wait_completed().await;
        assert_eq!(
            self.backend.inner.lock().unwrap().candidate_replacements,
            vec![self.candidate.clone()]
        );
        assert_eq!(self.backend.proofs_imported_count(), 3);
    }

    async fn wait_completed(&self) {
        timeout(Duration::from_secs(1), async {
            loop {
                if !self
                    .backend
                    .inner
                    .lock()
                    .unwrap()
                    .candidate_replacements
                    .is_empty()
                {
                    return;
                }
                self.backend.candidate_notified.notified().await;
            }
        })
        .await
        .unwrap();
    }

    async fn stop(self) {
        drop(self.events);
        self.runner.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn exact_candidate_endpoint_backfills_bounded_pages_before_retarget() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    harness.finish().await;
    harness.stop().await;
}

#[tokio::test]
async fn disconnect_failover_ignores_old_candidate_response_without_releasing_new_request() {
    let mut harness = Harness::new();
    let first = random_peer();
    let second = random_peer();
    harness.connect(first).await;
    harness.connect(second).await;
    harness
        .gossip(
            first,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    let (provider, _, old_reply) = harness.request().await;
    assert_eq!(provider, first);
    harness
        .events
        .send(NetworkEvent::PeerDisconnected(first))
        .await
        .unwrap();
    let (provider, request, new_reply) = harness.request().await;
    assert_eq!(provider, second);
    old_reply
        .send(Ok(RpcResponse::BlocksByRange(
            BlocksByRangeResponse::default(),
        )))
        .unwrap();
    new_reply.send(Ok(harness.blocks_reply(&request))).unwrap();
    for _ in 0..4 {
        let (_, request, reply) = harness.request().await;
        let response = if matches!(request, RpcRequest::BlocksByRange(_)) {
            harness.blocks_reply(&request)
        } else {
            harness.proofs_reply(&request)
        };
        reply.send(Ok(response)).unwrap();
    }
    harness.wait_completed().await;
    assert_eq!(harness.backend.proofs_imported_count(), 3);
    harness.stop().await;
}

#[tokio::test]
async fn unknown_vote_queries_source_exact_target_and_rejects_substituted_candidate() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    let vote = FinalityVote {
        aggregation_bits: neutrino_primitives::BitVec::default(),
        signature: [0; 96],
        attestations: vec![],
        data: FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: harness.candidate.chunk.hash(),
            phase: FinalityVotePhase::Prevote,
        },
    };
    harness
        .gossip(
            peer,
            Topic::FinalityVotesPrevote,
            borsh::to_vec(&vote).unwrap(),
        )
        .await;
    let (source, request, reply) = harness.request().await;
    assert_eq!(source, peer);
    assert!(
        matches!(request, RpcRequest::CandidateByChunk(query) if query.chunk_hash == Some(vote.data.chunk_hash))
    );
    let mut wrong = harness.candidate.clone();
    wrong.chunk.end_block_hash = [99; 32];
    reply
        .send(Ok(RpcResponse::CandidateByChunk(Box::new(
            CandidateByChunkResponse { candidate: wrong },
        ))))
        .unwrap();
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    harness.finish().await;
    // The saved vote is replayed after the exact branch was installed.
    assert_eq!(harness.backend.finality_vote_count(), 2);
    harness.stop().await;
}

#[tokio::test]
async fn candidate_backfill_accepts_honest_contiguous_prefixes_under_response_budget() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    let (_, request, reply) = harness.request().await;
    let RpcResponse::BlocksByRange(mut payload) = harness.blocks_reply(&request) else {
        unreachable!()
    };
    payload.blocks.truncate(3);
    reply.send(Ok(RpcResponse::BlocksByRange(payload))).unwrap();
    let (_, request, reply) = harness.request().await;
    assert!(matches!(&request, RpcRequest::BlocksByRange(range) if range.start_height == 4));
    reply.send(Ok(harness.blocks_reply(&request))).unwrap();
    let (_, request, reply) = harness.request().await;
    reply.send(Ok(harness.blocks_reply(&request))).unwrap();
    let (_, request, reply) = harness.request().await;
    let RpcResponse::BlockProofByHeight(mut payload) = harness.proofs_reply(&request) else {
        unreachable!()
    };
    payload.proofs.truncate(4);
    reply
        .send(Ok(RpcResponse::BlockProofByHeight(payload)))
        .unwrap();
    for _ in 0..2 {
        let (_, request, reply) = harness.request().await;
        reply.send(Ok(harness.proofs_reply(&request))).unwrap();
    }
    harness.wait_completed().await;
    assert_eq!(harness.backend.inner.lock().unwrap().proven_height, 20);
    harness.stop().await;
}

#[tokio::test]
async fn unsigned_round_metadata_cannot_poison_a_later_legitimate_candidate_hint() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    let mut impossible = harness.candidate.clone();
    impossible.round = u32::MAX;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&impossible).unwrap(),
        )
        .await;
    let mut later_bare = harness.candidate.clone();
    later_bare.round = 16;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&later_bare).unwrap(),
        )
        .await;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    harness.finish().await;
    harness.stop().await;
}

#[tokio::test]
async fn invalid_same_round_quorum_does_not_displace_authenticated_candidate_quorum() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    let quorum = neutrino_consensus_types::QuorumCertificate {
        data: FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: harness.candidate.chunk.hash(),
            phase: FinalityVotePhase::Prevote,
        },
        aggregate: neutrino_consensus_types::AggregatedVote {
            aggregation_bits: neutrino_primitives::BitVec::from_bytes(1, vec![1]).unwrap(),
            signature: [77; 96],
        },
    };
    harness.candidate.round = 1;
    harness.candidate.justification = Some(quorum);
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    let mut malformed = harness.candidate.clone();
    malformed
        .justification
        .as_mut()
        .unwrap()
        .aggregate
        .signature = [0; 96];
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&malformed).unwrap(),
        )
        .await;
    let mut bare = harness.candidate.clone();
    bare.justification = None;
    bare.round = 16;
    harness
        .gossip(peer, Topic::BftCandidates, borsh::to_vec(&bare).unwrap())
        .await;
    harness.finish().await;
    harness.stop().await;
}

#[tokio::test]
async fn candidate_discovery_backlog_cannot_starve_known_branch_payload_pages() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    let (_, first_page, first_reply) = harness.request().await;
    assert!(matches!(&first_page, RpcRequest::BlocksByRange(range) if range.start_height == 1));
    // Queue three independent discoveries while one known branch page is held.
    // Each gossip's validation response is a deterministic driver barrier.
    for target in [90, 91, 92] {
        let vote = FinalityVote {
            aggregation_bits: neutrino_primitives::BitVec::default(),
            signature: [0; 96],
            attestations: vec![],
            data: FinalityVoteData {
                chunk_id: 0,
                round: 0,
                chunk_hash: [target; 32],
                phase: FinalityVotePhase::Prevote,
            },
        };
        harness
            .gossip(
                peer,
                Topic::FinalityVotesPrevote,
                borsh::to_vec(&vote).unwrap(),
            )
            .await;
    }
    first_reply
        .send(Ok(harness.blocks_reply(&first_page)))
        .unwrap();
    let (_, query, reply) = harness.request().await;
    assert!(matches!(query, RpcRequest::CandidateByChunk(_)));
    reply
        .send(Err(neutrino_network::rpc::RpcError::Remote(
            neutrino_network::rpc::RpcFailure::Unavailable("target unavailable".into()),
        )))
        .unwrap();
    let (_, page, reply) = harness.request().await;
    assert!(matches!(&page, RpcRequest::BlocksByRange(range) if range.start_height == 17));
    reply.send(Ok(harness.blocks_reply(&page))).unwrap();
    for start in [1, 9] {
        let (_, query, reply) = harness.request().await;
        assert!(matches!(query, RpcRequest::CandidateByChunk(_)));
        reply
            .send(Err(neutrino_network::rpc::RpcError::Remote(
                neutrino_network::rpc::RpcFailure::Unavailable("target unavailable".into()),
            )))
            .unwrap();
        let (_, page, reply) = harness.request().await;
        assert!(
            matches!(&page, RpcRequest::BlockProofByHeight(range) if range.start_height == start)
        );
        reply.send(Ok(harness.proofs_reply(&page))).unwrap();
    }
    let (_, page, reply) = harness.request().await;
    assert!(matches!(&page, RpcRequest::BlockProofByHeight(range) if range.start_height == 17));
    reply.send(Ok(harness.proofs_reply(&page))).unwrap();
    harness.wait_completed().await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().candidate_replacements,
        vec![harness.candidate.clone()]
    );
    harness.stop().await;
}
