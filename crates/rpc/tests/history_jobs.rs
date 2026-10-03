//! In-process history RPC and watch-notification contract, without network sockets.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use jsonrpsee::core::server::{MethodsError, Subscription};
use neutrino_consensus_types::{Block, Header};
use neutrino_primitives::{BlockHash, ChainId, Hash, Height, Validator};
use neutrino_rpc::{
    BlockId, BytesHex, FinalizedInfo, HashHex, HeadInfo, HistoryJobInfo, HistoryJobStatus,
    QueryError, RpcBackend, RuntimeCallError, RuntimeCallResponse, SubmitError, build_module,
};
use tokio::sync::watch;

const JOB: Hash = [1; 32];
const START: Hash = [2; 32];
const END: Hash = [3; 32];
const PROOF: &[u8] = &[0, 1, 127, 128, 255];
const DEADLINE: Duration = Duration::from_secs(5);

struct Backend {
    job: watch::Sender<HistoryJobInfo>,
}

impl Backend {
    fn new(status: HistoryJobStatus) -> Arc<Self> {
        let (job, _) = watch::channel(HistoryJobInfo {
            id: HashHex(JOB),
            start: HashHex(START),
            end: HashHex(END),
            status,
            error: None,
        });
        Arc::new(Self { job })
    }

    fn transition(&self, status: HistoryJobStatus) {
        self.job.send_modify(|job| {
            job.status = status;
            job.error = (status == HistoryJobStatus::Failed).then(|| "prover stopped".into());
        });
    }
}

#[async_trait]
impl RpcBackend for Backend {
    async fn history_latest(&self) -> Result<Vec<u8>, QueryError> {
        Ok(PROOF.to_vec())
    }

    async fn history_request(&self, start: Hash, end: Hash) -> Result<HistoryJobInfo, QueryError> {
        if (start, end) != (START, END) {
            return Err(QueryError::BlockNotFound);
        }
        Ok(self.job.borrow().clone())
    }

    async fn history_job(&self, id: Hash) -> Result<HistoryJobInfo, QueryError> {
        if id != JOB {
            return Err(QueryError::BlockNotFound);
        }
        Ok(self.job.borrow().clone())
    }

    async fn history_subscribe(
        &self,
        id: Hash,
    ) -> Result<watch::Receiver<HistoryJobInfo>, QueryError> {
        if id != JOB {
            return Err(QueryError::BlockNotFound);
        }
        Ok(self.job.subscribe())
    }

    async fn history_proof(&self, start: Hash, end: Hash) -> Result<Vec<u8>, QueryError> {
        if (start, end) != (START, END) {
            return Err(QueryError::StateUnavailable);
        }
        Ok(PROOF.to_vec())
    }

    fn chain_id(&self) -> ChainId {
        7
    }
    fn runtime_code_hash(&self) -> Option<Hash> {
        None
    }
    fn runtime_available(&self) -> bool {
        false
    }
    fn mempool_len(&self) -> usize {
        0
    }
    async fn head(&self) -> Result<HeadInfo, QueryError> {
        Err(QueryError::BlockNotFound)
    }
    async fn finalized(&self) -> Result<FinalizedInfo, QueryError> {
        Err(QueryError::BlockNotFound)
    }
    async fn active_validator_set(&self) -> Vec<Validator> {
        Vec::new()
    }
    async fn resolve_block_id(&self, _: &BlockId) -> Result<Option<BlockHash>, QueryError> {
        Ok(None)
    }
    async fn header_by_hash(&self, _: BlockHash) -> Result<Option<Header>, QueryError> {
        Ok(None)
    }
    async fn header_by_height(&self, _: Height) -> Result<Option<Header>, QueryError> {
        Ok(None)
    }
    async fn block_by_hash(&self, _: BlockHash) -> Result<Option<Block>, QueryError> {
        Ok(None)
    }
    async fn block_by_height(&self, _: Height) -> Result<Option<Block>, QueryError> {
        Ok(None)
    }
    async fn storage_at(&self, _: &[u8], _: &BlockId) -> Result<Option<Vec<u8>>, QueryError> {
        Ok(None)
    }
    async fn submit_transaction(&self, _: Vec<u8>) -> Result<Hash, SubmitError> {
        Err(SubmitError::Full)
    }
    async fn runtime_call(
        &self,
        _: String,
        _: Vec<u8>,
        _: &BlockId,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        Err(RuntimeCallError::RuntimeNotConfigured)
    }
}

async fn next(subscription: &mut Subscription) -> HistoryJobInfo {
    tokio::time::timeout(DEADLINE, subscription.next::<HistoryJobInfo>())
        .await
        .expect("notification deadline")
        .expect("subscription remains open")
        .expect("valid job notification")
        .0
}

async fn released(backend: &Backend) {
    tokio::time::timeout(DEADLINE, backend.job.closed())
        .await
        .expect("subscription must release its watch receiver");
    assert_eq!(backend.job.receiver_count(), 0);
}

fn error_code(error: MethodsError) -> i32 {
    let MethodsError::JsonRpc(error) = error else {
        panic!("expected JSON-RPC error")
    };
    error.code()
}

#[tokio::test]
async fn completed_job_is_sent_immediately_and_releases_watcher() {
    let backend = Backend::new(HistoryJobStatus::Completed);
    let module = build_module(backend.clone()).unwrap();
    let mut subscription = module
        .subscribe("history_subscribeJob", [HashHex(JOB)], 2)
        .await
        .unwrap();
    assert_eq!(next(&mut subscription).await, *backend.job.borrow());
    assert!(
        tokio::time::timeout(DEADLINE, subscription.next::<HistoryJobInfo>())
            .await
            .unwrap()
            .is_none()
    );
    released(&backend).await;
}

#[tokio::test]
async fn new_jobs_notify_running_and_each_terminal_status() {
    for terminal in [
        HistoryJobStatus::Completed,
        HistoryJobStatus::Failed,
        HistoryJobStatus::Cancelled,
    ] {
        let backend = Backend::new(HistoryJobStatus::Queued);
        let module = build_module(backend.clone()).unwrap();
        let job: HistoryJobInfo = module
            .call("history_proveRange", [HashHex(START), HashHex(END)])
            .await
            .unwrap();
        assert_eq!(job.status, HistoryJobStatus::Queued);
        let mut subscription = module
            .subscribe("history_subscribeJob", [job.id], 2)
            .await
            .unwrap();
        assert_eq!(next(&mut subscription).await, job);
        backend.transition(HistoryJobStatus::Running);
        assert_eq!(
            next(&mut subscription).await.status,
            HistoryJobStatus::Running
        );
        backend.transition(terminal);
        let observed = next(&mut subscription).await;
        assert_eq!(observed.status, terminal);
        assert_eq!(
            observed.error.is_some(),
            terminal == HistoryJobStatus::Failed
        );
        let persisted: HistoryJobInfo = module.call("history_getJob", [job.id]).await.unwrap();
        assert_eq!(observed, persisted);
        assert!(
            tokio::time::timeout(DEADLINE, subscription.next::<HistoryJobInfo>())
                .await
                .unwrap()
                .is_none()
        );
        released(&backend).await;
    }
}

#[tokio::test]
async fn disconnect_releases_watcher_without_cancelling_job() {
    let backend = Backend::new(HistoryJobStatus::Running);
    let module = build_module(backend.clone()).unwrap();
    let mut subscription = module
        .subscribe("history_subscribeJob", [HashHex(JOB)], 2)
        .await
        .unwrap();
    assert_eq!(
        next(&mut subscription).await.status,
        HistoryJobStatus::Running
    );
    assert_eq!(backend.job.receiver_count(), 1);
    drop(subscription);
    released(&backend).await;
    assert_eq!(backend.job.borrow().status, HistoryJobStatus::Running);
}

#[tokio::test]
async fn endpoint_queries_preserve_exact_proof_bytes_and_missing_errors() {
    let backend = Backend::new(HistoryJobStatus::Completed);
    let module = build_module(backend).unwrap();
    let latest: BytesHex = module.call("history_getLatest", [(); 0]).await.unwrap();
    let proof: BytesHex = module
        .call("history_getProof", [HashHex(START), HashHex(END)])
        .await
        .unwrap();
    assert_eq!(latest.0, PROOF);
    assert_eq!(proof, latest);
    for method in ["history_getProof", "history_proveRange"] {
        let error = module
            .call::<_, serde_json::Value>(method, [HashHex(END), HashHex(START)])
            .await
            .unwrap_err();
        assert_eq!(
            error_code(error),
            if method == "history_getProof" {
                -32021
            } else {
                -32020
            }
        );
    }
    let missing = module
        .call::<_, HistoryJobInfo>("history_getJob", [HashHex([0; 32])])
        .await
        .unwrap_err();
    assert_eq!(error_code(missing), -32020);
    let missing = module
        .subscribe("history_subscribeJob", [HashHex([0; 32])], 1)
        .await
        .unwrap_err();
    assert_eq!(error_code(missing), -32020);
    let malformed = module
        .subscribe("history_subscribeJob", ["0x123"], 1)
        .await
        .unwrap_err();
    assert_eq!(error_code(malformed), -32602);
}
