//! Deterministic bootstrap admission races; no proof receipt is accepted here.

use super::super::state_sync_tests;
use super::{BootstrapRuntime, ChainBackend};
use neutrino_consensus_engine::{Engine, ProposerKey};
use neutrino_consensus_types::{
    BlockProofPublicInputs, Chunk,
    history_proof::{ChainBinding, Checkpoint, ConsensusBoundary, ExecutionPrograms, ProofDomain},
};
use neutrino_proof_system::{
    MockBlockProof, MockProofSystem, ProofError, ProofSystem, UnsupportedExecutor,
};
use neutrino_storage::{Column, Database, MemoryDatabase};
use neutrino_sync::SyncBackendError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

fn backend<P>(proof_system: P) -> ChainBackend<MemoryDatabase, P>
where
    P: ProofSystem + Send + Sync + 'static,
{
    let spec = state_sync_tests::spec();
    let origin = Checkpoint {
        domain: ProofDomain {
            chain: ChainBinding::from_spec(&spec),
            execution: ExecutionPrograms {
                fact: [1; 8],
                evidence: [2; 8],
                block: [3; 8],
            },
            chunk: [4; 8],
            checkpoint: [5; 8],
        },
        boundary: ConsensusBoundary::genesis(&spec),
    };
    let backend = ChainBackend::new(
        Engine::genesis(spec, MemoryDatabase::new()).unwrap(),
        proof_system,
    );
    *backend.bootstrap.lock().unwrap() = Some(BootstrapRuntime {
        origin,
        trusted_at: 0,
        max_future_drift_secs: 30,
        fetching: false,
        pending: None,
    });
    backend.set_local_voter(ProposerKey::from_ikm(&[6; 32], 0).unwrap());
    backend
}

/// Stop production after its optimistic pending check, before its engine lock.
struct PausingProofSystem {
    entered: mpsc::Sender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
    paused: AtomicBool,
}

impl ProofSystem for PausingProofSystem {
    type BlockProof = MockBlockProof;
    type ChunkProof = Vec<u8>;

    fn prove_block(
        &self,
        witness: &[u8],
        inputs: &BlockProofPublicInputs,
    ) -> Result<MockBlockProof, ProofError> {
        MockProofSystem.prove_block(witness, inputs)
    }

    fn verify_block(
        &self,
        proof: &MockBlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        MockProofSystem.verify_block(proof, inputs)
    }

    fn consensus_block_key(&self) -> Option<[u32; 8]> {
        if !self.paused.swap(true, Ordering::AcqRel) {
            self.entered.send(()).unwrap();
            self.resume.lock().unwrap().recv().unwrap();
        }
        None
    }
}

#[tokio::test]
async fn production_rechecks_barrier_after_passing_optimistic_admission() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let backend = Arc::new(backend(PausingProofSystem {
        entered: entered_tx,
        resume: Mutex::new(resume_rx),
        // Construction also asks for this key; arm the pause afterwards.
        paused: AtomicBool::new(true),
    }));
    backend.proof_system.paused.store(false, Ordering::Release);
    backend.set_block_executor(UnsupportedExecutor);
    let producer = Arc::clone(&backend);
    let task = std::thread::spawn(move || {
        producer.try_produce_block(1, &ProposerKey::from_ikm(&[6; 32], 0).unwrap())
    });
    entered_rx.recv().unwrap();
    backend.bootstrap_fetch(true).await;
    resume_tx.send(()).unwrap();
    // Without the locked recheck this reaches the installed executor and errors.
    assert!(task.join().unwrap().unwrap().is_none());
    assert_eq!(backend.head_height(), 0);
    assert_eq!(
        backend.with_engine(|engine| engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap()),
        Vec::<(Vec<u8>, Vec<u8>)>::new()
    );
}

fn candidate() -> Chunk {
    Chunk {
        chunk_id: 0,
        start_height: 1,
        end_height: 1,
        start_state_root: [1; 32],
        end_state_root: [2; 32],
        start_block_hash: [3; 32],
        end_block_hash: [4; 32],
        block_hash_root: [5; 32],
        block_proof_root: [6; 32],
        vrf_proof_root: [7; 32],
        active_validator_set_root: state_sync_tests::spec().genesis_validator_set_root,
        next_validator_set_root: state_sync_tests::spec().genesis_validator_set_root,
        da_root: [8; 32],
    }
}

#[tokio::test]
async fn stale_bft_admission_cannot_reserve_a_vote_or_open_a_session() {
    let backend = Arc::new(backend(MockProofSystem));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let voter = Arc::clone(&backend);
    let task = std::thread::spawn(move || {
        assert!(!voter.bootstrap_pending());
        entered_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
        // This is the same guarded commit used after async chunk preparation.
        voter.with_live_engine_mut(|engine| {
            engine
                .open_bft_session_at(candidate(), 0)
                .map_err(|error| SyncBackendError::Rejected(error.to_string()))
        })
    });
    entered_rx.recv().unwrap();
    backend.bootstrap_fetch(true).await;
    resume_tx.send(()).unwrap();
    assert!(matches!(
        task.join().unwrap(),
        Err(SyncBackendError::NotAvailable(_))
    ));
    backend.with_engine(|engine| {
        assert!(engine.bft_session(0).is_none());
        for column in [Column::SigningJournal, Column::BftSessions] {
            assert_eq!(
                engine.store().db().iter_column(column).unwrap(),
                Vec::<(Vec<u8>, Vec<u8>)>::new()
            );
        }
    });
    backend.bootstrap_fetch(false).await;
    assert_eq!(backend.with_live_engine_mut(|_| Ok(7)).unwrap(), 7);
}

#[tokio::test]
async fn barrier_waits_for_an_admitted_engine_mutation_to_finish() {
    let backend = Arc::new(backend(MockProofSystem));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let mutation_backend = Arc::clone(&backend);
    let mutation = std::thread::spawn(move || {
        mutation_backend
            .with_live_engine_mut(|_| {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                // Fetching cannot flip while this admitted mutation holds the engine.
                assert!(!mutation_backend.bootstrap_pending());
                Ok(())
            })
            .unwrap();
    });
    entered_rx.recv().unwrap();
    let barrier_backend = Arc::clone(&backend);
    let runtime = tokio::runtime::Handle::current();
    let barrier =
        std::thread::spawn(move || runtime.block_on(barrier_backend.bootstrap_fetch(true)));
    resume_tx.send(()).unwrap();
    mutation.join().unwrap();
    barrier.join().unwrap();
    assert!(backend.bootstrap_pending());
}
