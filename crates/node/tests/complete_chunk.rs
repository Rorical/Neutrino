//! Native consensus backend tests for asynchronous proof scheduling, not SP1 soundness.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use neutrino_consensus_engine::{BlockState, Engine, ProposerKey};
use neutrino_consensus_types::{BlockProof, BlockProofPublicInputs};
use neutrino_default_runtime_core::StfPublicOutput;
use neutrino_node::ChainBackend;
use neutrino_proof_system::{ProofError, ProofSystem};
use neutrino_prover_chunk::consensus::{ConsensusStatement, ConsensusWitness, validate_consensus};
use neutrino_storage::MemoryDatabase;
use neutrino_sync::SyncBackend;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};

struct NativeConsensusBackend {
    decisions: Mutex<mpsc::Receiver<bool>>,
    attempts: Arc<AtomicUsize>,
}

impl ProofSystem for NativeConsensusBackend {
    type BlockProof = StfPublicOutput;
    type ChunkProof = ConsensusStatement;
    type RecursiveProof = Vec<u8>;

    fn prove_block(
        &self,
        _: &[u8],
        _: &BlockProofPublicInputs,
    ) -> Result<Self::BlockProof, ProofError> {
        Err(ProofError::Unsupported)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        pi: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        if proof.block_height != pi.height || proof.post_state_root != pi.state_root_after {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
    }

    fn consensus_block_key(&self) -> Option<[u32; 8]> {
        Some([1; 8])
    }

    fn evidence_key(&self) -> Option<[u32; 8]> {
        Some([2; 8])
    }

    // Transparent native witness receipts are test-only. Production uses the
    // SP1 portable verifier; these bytes deliberately cannot pass that verifier.
    fn prove_evidence(
        &self,
        witness: &neutrino_prover_chunk::evidence::EvidenceWitness,
    ) -> Result<Vec<u8>, ProofError> {
        neutrino_prover_chunk::evidence::validate_evidence(witness)
            .map_err(|_| ProofError::InvalidWitness)?;
        borsh::to_vec(witness).map_err(|_| ProofError::InvalidWitness)
    }

    fn verify_evidence(
        &self,
        bytes: &[u8],
        expected: &neutrino_consensus_types::evidence::EvidenceStatement,
    ) -> Result<(), ProofError> {
        let witness = borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
        let actual = neutrino_prover_chunk::evidence::validate_evidence(&witness)
            .map_err(|_| ProofError::InvalidWitness)?;
        if &actual != expected {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
    }

    fn block_statement(&self, proof: &Self::BlockProof) -> Result<StfPublicOutput, ProofError> {
        Ok(proof.clone())
    }

    fn prove_consensus_chunk(
        &self,
        _: &[Self::BlockProof],
        witness: &ConsensusWitness,
    ) -> Result<Self::ChunkProof, ProofError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if !self
            .decisions
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or(false)
        {
            return Err(ProofError::BackendRejected);
        }
        validate_consensus(witness).map_err(|_| ProofError::InvalidWitness)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        expected: &ConsensusStatement,
    ) -> Result<(), ProofError> {
        if proof != expected {
            return Err(ProofError::BackendRejected);
        }
        Ok(())
    }
}

fn engine() -> (Engine<MemoryDatabase>, ConsensusWitness) {
    let (witness, _, _) = support::fixture([1; 8], [4; 32]);
    let mut engine = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    let block = &witness.blocks[0];
    let hash = block.header.hash();
    engine
        .import_block(&neutrino_consensus_types::Block {
            header: block.header.clone(),
            body: neutrino_consensus_types::Body::default(),
        })
        .unwrap();
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::Proven)
        .unwrap();
    engine
        .store_mut()
        .put_block_proof(
            &hash,
            &BlockProof {
                height: block.header.height,
                block_hash: hash,
                public_inputs: block.public_inputs.clone(),
                proof_bytes: borsh::to_vec(&block.output).unwrap(),
            },
        )
        .unwrap();
    (engine, witness)
}

#[tokio::test(flavor = "current_thread")]
async fn proof_job_keeps_network_responsive_and_retries_without_advancing_on_failure() {
    use neutrino_prover_chunk::consensus::as_chunk;
    use std::time::Duration;
    let (engine, witness) = engine();
    let (decisions, receiver) = mpsc::channel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let backend = ChainBackend::new(
        engine,
        NativeConsensusBackend {
            decisions: Mutex::new(receiver),
            attempts: Arc::clone(&attempts),
        },
    );
    backend.set_local_voter(ProposerKey::from_ikm(&[42; 32], 0).unwrap());
    backend.with_engine_mut_for_test(|engine| {
        engine
            .open_bft_session(as_chunk(&validate_consensus(&witness).unwrap().execution))
            .unwrap()
    });
    // The worker deliberately waits for a test-controlled result. Neither the
    // network-facing tick nor status may wait for that result.
    tokio::time::timeout(Duration::from_secs(5), backend.tick_bft_round_timeouts(0))
        .await
        .unwrap();
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        None
    );
    decisions.send(false).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while attempts.load(Ordering::SeqCst) < 2 {
            backend.tick_bft_round_timeouts(0).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        None
    );
    decisions.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while backend
            .local_status()
            .await
            .unwrap()
            .finalized_chunk_id
            .is_none()
        {
            backend.tick_bft_round_timeouts(0).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn evidence_worker_persists_gossips_and_rehydrates_verified_receipts() {
    use neutrino_consensus_types::{
        FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
        evidence::EvidenceArtifact,
    };
    use neutrino_network::{Topic, service::NetworkCommand};
    use neutrino_sync::SyncBackend;
    let (mut engine, witness) = engine();
    engine.set_evidence_programs([1; 8], [2; 8]);
    let (decisions, receiver) = mpsc::channel();
    decisions.send(true).unwrap();
    let prover = NativeConsensusBackend {
        decisions: Mutex::new(receiver),
        attempts: Arc::new(AtomicUsize::new(0)),
    };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &prover, &voter).unwrap();
    let key = neutrino_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let sign = |hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 2,
            chunk_hash: [hash; 32],
            phase: FinalityVotePhase::Precommit,
        };
        let mut message = Vec::from(neutrino_primitives::DOMAIN_PRECOMMIT);
        message.extend_from_slice(&7_u64.to_le_bytes());
        message.extend_from_slice(&borsh::to_vec(&data).unwrap());
        IndexedVote {
            data,
            signature: key.sign(&message).to_bytes(),
        }
    };
    let offence = SlashingEvidence::DoublePrecommit {
        validator_index: 0,
        vote_a: sign(1),
        vote_b: sign(2),
    };
    let backend = ChainBackend::new(engine, prover);
    let (publisher, mut messages) = tokio::sync::mpsc::channel(8);
    backend.set_network_publisher(publisher);
    backend.ingest_slashing_evidence(offence).await;
    let artifact = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let NetworkCommand::Publish {
                topic: Topic::EvidenceProofs,
                data,
            } = messages.recv().await.unwrap()
            {
                break borsh::from_slice::<EvidenceArtifact>(&data).unwrap();
            }
        }
    })
    .await
    .expect("background evidence completion notification");
    let database = backend.with_engine_mut_for_test(|engine| {
        assert_eq!(
            engine.store().evidence_artifacts().unwrap(),
            vec![artifact.clone()]
        );
        engine.store().db().clone()
    });
    let reopened = Engine::open(witness.chain_spec, database).unwrap();
    let (_sender, receiver) = mpsc::channel();
    let restarted = ChainBackend::new(
        reopened,
        NativeConsensusBackend {
            decisions: Mutex::new(receiver),
            attempts: Arc::new(AtomicUsize::new(0)),
        },
    );
    assert_eq!(
        restarted.ingest_evidence_proof(artifact.clone()).await,
        neutrino_sync::EvidenceProofAcceptance::Accepted
    );
    let mut forged = artifact.clone();
    forged.statement.offender.withdrawal_credentials[0] ^= 1;
    assert_eq!(
        restarted.ingest_evidence_proof(forged).await,
        neutrino_sync::EvidenceProofAcceptance::Rejected
    );
    let mut corrupt = artifact.clone();
    corrupt.proof_bytes.push(0);
    assert_eq!(
        restarted.ingest_evidence_proof(corrupt).await,
        neutrino_sync::EvidenceProofAcceptance::Rejected
    );
    let mut wrong_program = artifact.clone();
    wrong_program.evidence_guest_vk_digest[0] ^= 1;
    assert_eq!(
        restarted.ingest_evidence_proof(wrong_program).await,
        neutrino_sync::EvidenceProofAcceptance::Rejected
    );
    restarted.with_engine_mut_for_test(|engine| {
        assert_eq!(engine.store().evidence_artifacts().unwrap(), vec![artifact]);
    });
}

fn ready_prover() -> NativeConsensusBackend {
    let (sender, receiver) = mpsc::channel();
    sender.send(true).unwrap();
    NativeConsensusBackend {
        decisions: Mutex::new(receiver),
        attempts: Arc::new(AtomicUsize::new(0)),
    }
}

async fn assert_account_view(
    backend: &ChainBackend<MemoryDatabase, NativeConsensusBackend>,
    at: &neutrino_rpc::BlockId,
    address: [u8; 32],
    expected: Option<neutrino_default_runtime_core::Account>,
) {
    use neutrino_rpc::RpcBackend;
    let raw = backend
        .storage_at(&neutrino_default_runtime_core::account_key(&address), at)
        .await
        .unwrap();
    assert_eq!(
        raw,
        expected
            .as_ref()
            .map(neutrino_default_runtime_core::encode_account)
    );
    let response = backend
        .runtime_call(
            neutrino_default_runtime_core::QUERY_METHOD_ACCOUNT_GET.to_owned(),
            address.to_vec(),
            at,
        )
        .await
        .unwrap();
    assert_eq!(
        response.code,
        neutrino_runtime_abi::QueryStatus::Ok.as_u32()
    );
    let actual: Option<neutrino_default_runtime_core::Account> =
        borsh::from_slice(&response.payload).unwrap();
    assert_eq!(actual, expected);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One finality boundary, subsequent execution, forks and restart.
async fn rpc_queries_follow_committed_roots_across_finality_forks_and_restart() {
    use ed25519_dalek::{Signer, SigningKey};
    use neutrino_consensus_types::{Block, Body};
    use neutrino_default_runtime_core::{
        Account, Transaction, TransferTx, account_key, encode_account, transfer_sig_message,
    };
    use neutrino_primitives::{DOMAIN_PROPOSER_SIG, ZERO_HASH};
    use neutrino_rpc::{BlockId, QueryError, RpcBackend, RuntimeCallError};
    use neutrino_runtime_core::host::LiveTrie;
    use neutrino_runtime_host::WasmExecutor;
    use neutrino_storage::{Column, Database};
    use neutrino_trie::{Hasher, Poseidon2Hasher};

    let sender_key = SigningKey::from_bytes(&[19; 32]);
    let sender = sender_key.verifying_key().to_bytes();
    let recipient = [20; 32];
    let initial = Account {
        nonce: 0,
        balance: 1_000_000,
    };
    let mut live = LiveTrie::default();
    live.insert(&account_key(&sender), encode_account(&initial));
    let (witness, _, _) = support::fixture_with_live(
        [1; 8],
        neutrino_runtime_host::default_runtime_code_hash(),
        vec![],
        30_000_000,
        &live,
    );
    let spec = witness.chain_spec.clone();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine.replace_state_with_reconstructed(live.trie().clone());
    engine.flush_trie_to_store().unwrap();
    let prover = ready_prover();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let first = &witness.blocks[0];
    let boundary = first.header.hash();
    engine
        .import_block(&Block {
            header: first.header.clone(),
            body: Body::default(),
        })
        .unwrap();
    engine
        .store_mut()
        .put_block_state(&boundary, BlockState::Proven)
        .unwrap();
    engine
        .store_mut()
        .put_block_proof(
            &boundary,
            &BlockProof {
                height: 1,
                block_hash: boundary,
                public_inputs: first.public_inputs.clone(),
                proof_bytes: borsh::to_vec(&first.output).unwrap(),
            },
        )
        .unwrap();
    engine.finalize_chunk(0, &prover, &voter).unwrap();
    assert_eq!(
        engine.latest_checkpoint_index(),
        0,
        "checkpoint index is independent of chunk finality"
    );
    let backend = Arc::new(ChainBackend::new(engine, prover));
    let executor = tokio::task::spawn_blocking(WasmExecutor::default_runtime)
        .await
        .unwrap()
        .unwrap();
    backend.set_block_executor(executor);
    let finalized = backend.finalized().await.unwrap();
    assert_eq!(finalized.chunk_id, Some(0));
    assert_eq!(finalized.block_hash, boundary);
    assert_eq!(finalized.height, 1);
    assert_eq!(finalized.state_root, spec.genesis_state_root);

    let status = backend.local_status().await.unwrap();
    assert_eq!(status.finalized_chunk_id, Some(0));
    assert_eq!(status.finalized_checkpoint_index, 0);
    assert_eq!(
        status.finalized_checkpoint_hash,
        spec.genesis_checkpoint.hash()
    );
    assert_ne!(
        status.finalized_chunk_hash,
        status.finalized_checkpoint_hash
    );
    assert_eq!(
        backend.local_progress().await.unwrap().finalized_chunk_hash,
        status.finalized_chunk_hash
    );

    let mut transfer = TransferTx {
        from: sender,
        to: recipient,
        amount: 100,
        nonce: 0,
        signature: [0; 64],
    };
    transfer.signature = sender_key
        .sign(&transfer_sig_message(spec.chain_id, &transfer))
        .to_bytes();
    let tx = borsh::to_vec(&Transaction::Transfer(transfer)).unwrap();
    backend.submit_transaction(tx).unwrap();
    let producer = Arc::clone(&backend);
    let second = tokio::task::spawn_blocking(move || {
        producer
            .try_produce_block(2, &voter)
            .unwrap()
            .unwrap()
            .block
    })
    .await
    .unwrap();
    assert_ne!(second.header.state_root, finalized.state_root);
    assert_eq!(backend.finalized().await.unwrap(), finalized);
    assert_eq!(backend.head().await.unwrap().hash, second.hash());
    let paid = Account {
        nonce: 0,
        balance: 100,
    };
    for at in [
        BlockId::Latest,
        BlockId::Hash(second.hash()),
        BlockId::Height(2),
    ] {
        assert_account_view(&backend, &at, recipient, Some(paid)).await;
    }
    for at in [
        BlockId::Finalized,
        BlockId::Hash(boundary),
        BlockId::Height(1),
        BlockId::Height(0),
        BlockId::Hash(spec.genesis_block_hash),
    ] {
        assert_account_view(&backend, &at, recipient, None).await;
        assert_account_view(&backend, &at, sender, Some(initial)).await;
    }
    assert_eq!(
        backend.resolve_block_id(&BlockId::Finalized).await.unwrap(),
        Some(boundary)
    );

    // Archiving a sibling preserves the selected index for RPC and P2P reads.
    let mut sibling = Block {
        header: second.header.clone(),
        body: Body::default(),
    };
    neutrino_consensus_engine::apply_body_roots(
        &mut sibling.header,
        &neutrino_consensus_engine::compute_body_roots(&sibling.body),
    );
    sibling.header.state_root = finalized.state_root;
    sibling.header.gas_used = 0;
    sibling.header.receipts_root = first.header.receipts_root;
    sibling.header.runtime_extra = first.header.runtime_extra;
    let mut message = Vec::from(DOMAIN_PROPOSER_SIG);
    message.extend_from_slice(&spec.chain_id.to_le_bytes());
    message.extend_from_slice(&sibling.hash());
    sibling.header.signature = neutrino_crypto::bls::SecretKey::key_gen(&[42; 32], &[])
        .unwrap()
        .sign(&message)
        .to_bytes();
    backend.with_engine_mut_for_test(|engine| {
        engine.import_block(&sibling).unwrap();
        assert_eq!(
            engine.store().get_block_hash_by_height(2).unwrap(),
            Some(second.hash())
        );
        assert_eq!(engine.head_hash(), second.hash());
    });
    assert_eq!(
        backend.header_by_height(2).await.unwrap(),
        Some(second.header.clone())
    );
    assert_eq!(
        backend.block_by_height(2).await.unwrap(),
        Some(second.clone())
    );
    assert_account_view(&backend, &BlockId::Height(2), recipient, Some(paid)).await;
    assert_account_view(&backend, &BlockId::Hash(sibling.hash()), recipient, None).await;

    assert_eq!(
        backend
            .blocks_by_range(2, 16, 1, second.hash())
            .await
            .unwrap()
            .blocks,
        vec![second.clone()]
    );
    assert_eq!(
        backend
            .blocks_by_range(2, 1, 1, sibling.hash())
            .await
            .unwrap()
            .blocks,
        vec![sibling.clone()]
    );
    assert_eq!(
        backend
            .blocks_by_root(&[second.hash(), sibling.hash()])
            .await
            .unwrap()
            .blocks,
        vec![second.clone(), sibling.clone()]
    );
    assert_eq!(
        backend
            .block_proofs_by_height(1, 16, second.hash())
            .await
            .unwrap()
            .proofs[0]
            .block_hash,
        boundary
    );
    assert!(matches!(
        backend.block_proofs_by_height(2, 1, second.hash()).await,
        Err(neutrino_sync::SyncBackendError::NotAvailable(_))
    ));
    assert!(matches!(
        backend.blocks_by_range(1, 1, 0, second.hash()).await,
        Err(neutrino_sync::SyncBackendError::InvalidRequest(_))
    ));
    assert!(matches!(
        backend.blocks_by_range(1, 1, 1, [99; 32]).await,
        Err(neutrino_sync::SyncBackendError::NotAvailable(_))
    ));
    let old_state = backend
        .state_nodes(finalized.state_root, &[vec![]])
        .await
        .unwrap();
    assert!(old_state.values.contains(&encode_account(&initial)));
    assert!(!old_state.values.contains(&encode_account(&paid)));
    let head_state = backend
        .state_nodes(second.header.state_root, &[vec![]])
        .await
        .unwrap();
    assert!(head_state.values.contains(&encode_account(&paid)));
    assert!(!head_state.values.contains(&encode_account(&initial)));
    let snapshot_client = ChainBackend::new(
        Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap(),
        ready_prover(),
    );
    assert!(
        snapshot_client
            .import_state_nodes(
                finalized.state_root,
                vec![vec![]],
                old_state.nodes.clone(),
                vec![]
            )
            .await
            .is_err()
    );
    snapshot_client
        .import_state_nodes(
            finalized.state_root,
            vec![vec![]],
            old_state.nodes.clone(),
            old_state.values.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        snapshot_client
            .storage_at(&account_key(&sender), &BlockId::Latest)
            .await
            .unwrap(),
        Some(encode_account(&initial))
    );
    snapshot_client
        .import_state_nodes(
            second.header.state_root,
            vec![vec![]],
            head_state.nodes.clone(),
            head_state.values.clone(),
        )
        .await
        .unwrap();
    assert!(snapshot_client.engine_state_invariant_holds());
    assert_eq!(
        snapshot_client
            .storage_at(&account_key(&sender), &BlockId::Latest)
            .await
            .unwrap(),
        Some(encode_account(&initial))
    );
    assert!(
        snapshot_client
            .import_state_nodes(ZERO_HASH, vec![], vec![], vec![vec![1]])
            .await
            .is_err()
    );

    assert!(matches!(
        backend.state_nodes(finalized.state_root, &[vec![1]]).await,
        Err(neutrino_sync::SyncBackendError::InvalidRequest(_))
    ));
    assert!(matches!(
        backend.state_nodes([99; 32], &[vec![]]).await,
        Err(neutrino_sync::SyncBackendError::NotAvailable(_))
    ));
    assert!(matches!(
        backend.blocks_by_root(&[second.hash(); 17]).await,
        Err(neutrino_sync::SyncBackendError::InvalidRequest(_))
    ));

    let database = backend.with_engine_mut_for_test(|engine| engine.store().db().clone());
    let reopened = ChainBackend::new(Engine::open(spec, database).unwrap(), ready_prover());
    let executor = tokio::task::spawn_blocking(WasmExecutor::default_runtime)
        .await
        .unwrap()
        .unwrap();
    reopened.set_block_executor(executor);
    assert_eq!(reopened.finalized().await.unwrap(), finalized);
    assert_account_view(&reopened, &BlockId::Finalized, recipient, None).await;
    assert_account_view(&reopened, &BlockId::Height(2), recipient, Some(paid)).await;
    assert_eq!(
        reopened
            .storage_at(b"missing", &BlockId::Hash(ZERO_HASH))
            .await,
        Err(QueryError::BlockNotFound)
    );

    reopened.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .put_body(&second.hash(), &Body::default())
            .unwrap();
    });
    assert!(matches!(
        reopened.block_by_hash(second.hash()).await,
        Err(QueryError::Storage(_))
    ));

    assert!(matches!(
        reopened.blocks_by_root(&[second.hash()]).await,
        Err(neutrino_sync::SyncBackendError::Storage(_))
    ));

    reopened.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .db_mut()
            .delete(Column::Blocks, &second.hash())
            .unwrap();
        engine
            .store_mut()
            .db_mut()
            .delete(Column::TrieNodes, &second.header.state_root)
            .unwrap();
    });
    assert_eq!(
        reopened.block_by_hash(second.hash()).await,
        Err(QueryError::BodyUnavailable)
    );
    assert_eq!(
        reopened
            .storage_at(&account_key(&recipient), &BlockId::Latest)
            .await,
        Err(QueryError::StateUnavailable)
    );
    assert_eq!(
        reopened
            .runtime_call(
                "account_get".to_owned(),
                recipient.to_vec(),
                &BlockId::Latest
            )
            .await,
        Err(RuntimeCallError::Query(QueryError::StateUnavailable))
    );
    assert!(matches!(
        reopened.blocks_by_range(2, 1, 1, second.hash()).await,
        Err(neutrino_sync::SyncBackendError::NotAvailable(_))
    ));
    assert!(matches!(
        reopened
            .state_nodes(second.header.state_root, &[vec![]])
            .await,
        Err(neutrino_sync::SyncBackendError::NotAvailable(_))
    ));

    // Corruption and missing leaf values also fail explicitly, with old roots
    // still readable rather than falling through to a different state.
    let value_hash = Poseidon2Hasher::hash_value(&encode_account(&initial));
    reopened.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .db_mut()
            .put(Column::StateValues, &value_hash, b"corrupt")
            .unwrap();
    });
    assert!(matches!(
        reopened.storage_at(b"missing", &BlockId::Finalized).await,
        Err(QueryError::Storage(_))
    ));
    reopened.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .db_mut()
            .delete(Column::StateValues, &value_hash)
            .unwrap();
    });
    assert_eq!(
        reopened.storage_at(b"missing", &BlockId::Finalized).await,
        Err(QueryError::StateUnavailable)
    );
    reopened.with_engine_mut_for_test(|engine| {
        for hash in [second.hash(), boundary] {
            engine
                .store_mut()
                .db_mut()
                .delete(Column::Headers, &hash)
                .unwrap();
        }
    });
    assert!(matches!(reopened.head().await, Err(QueryError::Storage(_))));
    assert!(matches!(
        reopened.finalized().await,
        Err(QueryError::Storage(_))
    ));
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Proof rejection, branch finalization and restart share one fixture.
async fn imported_finality_selects_a_proven_archived_fork_and_survives_restart() {
    use neutrino_consensus_types::{Block, Body};
    use neutrino_crypto::bls::SecretKey;
    use neutrino_primitives::DOMAIN_PROPOSER_SIG;
    use neutrino_rpc::RpcBackend;
    use neutrino_runtime_host::WasmExecutor;
    let (mut producer, witness) = engine();
    let prover = ready_prover();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let finalized = producer.finalize_chunk(0, &prover, &voter).unwrap();
    let remote = Block {
        header: witness.blocks[0].header.clone(),
        body: Body::default(),
    };
    let mut local = remote.clone();
    local.header.slot = 2;
    local.header.timestamp = 2 * witness.chain_spec.consensus.slot_duration_secs;
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    local.header.vrf_proof = key
        .sign(&neutrino_vrf::vrf_message(7, &witness.seed, 2))
        .to_bytes();
    let mut message = Vec::from(DOMAIN_PROPOSER_SIG);
    message.extend_from_slice(&7_u64.to_le_bytes());
    message.extend_from_slice(&local.hash());
    local.header.signature = key.sign(&message).to_bytes();
    let mut follower = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    follower.set_evidence_programs([1; 8], [2; 8]);
    follower.import_block(&local).unwrap();
    follower.import_block(&remote).unwrap();
    let proof = producer
        .store()
        .get_block_proof(&remote.hash())
        .unwrap()
        .unwrap();
    follower
        .store_mut()
        .put_block_proof(&remote.hash(), &proof)
        .unwrap();
    follower
        .store_mut()
        .put_block_state(&remote.hash(), BlockState::Proven)
        .unwrap();
    let backend = ChainBackend::new(follower, ready_prover());
    let executor = tokio::task::spawn_blocking(WasmExecutor::default_runtime)
        .await
        .unwrap()
        .unwrap();
    backend.set_block_executor(executor);
    assert_eq!(
        backend.local_status().await.unwrap().head_block_hash,
        local.hash()
    );
    let mut invalid = finalized.chunk_proof.clone();
    invalid.proof_bytes.push(1);
    assert!(
        backend
            .verify_and_import_chunk_proof(invalid)
            .await
            .is_err()
    );
    assert_eq!(
        backend.local_status().await.unwrap().head_block_hash,
        local.hash()
    );
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        None
    );
    backend
        .verify_and_import_chunk_proof(finalized.chunk_proof.clone())
        .await
        .unwrap();
    assert_eq!(
        backend.header_by_height(1).await.unwrap(),
        Some(remote.header.clone())
    );
    assert_eq!(
        backend.local_status().await.unwrap().head_block_hash,
        remote.hash()
    );
    assert_eq!(backend.finalized().await.unwrap().block_hash, remote.hash());
    assert_eq!(
        backend
            .blocks_by_range(1, 1, 1, local.hash())
            .await
            .unwrap()
            .blocks,
        vec![local]
    );
    assert_eq!(
        backend
            .block_proofs_by_height(1, 1, remote.hash())
            .await
            .unwrap()
            .proofs[0]
            .block_hash,
        remote.hash()
    );
    let restarted = ChainBackend::new(
        Engine::open(witness.chain_spec, backend.snapshot_database()).unwrap(),
        ready_prover(),
    );
    assert_eq!(
        restarted.local_status().await.unwrap().head_block_hash,
        remote.hash()
    );
    assert_eq!(
        restarted.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    assert_eq!(
        restarted.finalized().await.unwrap().block_hash,
        remote.hash()
    );
}
