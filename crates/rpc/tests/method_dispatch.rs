//! In-process method-dispatch tests for the JSON-RPC module.
//!
//! Builds the canonical [`RpcModule`] against a mock [`RpcBackend`]
//! and exercises every method through [`RpcModule::call`] — no TCP
//! socket required. Verifies request parsing, parameter shapes, and
//! the JSON envelope of each method's response.

use std::sync::Arc;

use async_trait::async_trait;
use jsonrpsee::server::RpcModule;
use neutrino_consensus_types::{Block, Body, Header};
use neutrino_primitives::{BlockHash, ChainId, Hash, Height, Slot, Validator};
use neutrino_rpc::{
    BlockId, FinalizedInfo, HeadInfo, RpcBackend, RpcContext, RuntimeCallError,
    RuntimeCallResponse, SubmitError, build_module,
};
use serde_json::{Value, json};

/// Call a method through `raw_json_request`, parse the response, and
/// return the `result` field (or `error` if non-null).
async fn call_named(
    module: &RpcModule<RpcContext>,
    method: &str,
    params: Value,
) -> Result<Value, Value> {
    let req = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    })
    .to_string();
    let (response, _rx) = module.raw_json_request(&req, 1).await.expect("dispatch");
    let parsed: Value = serde_json::from_str(&response).expect("response json");
    parsed.get("error").map_or_else(
        || Ok(parsed.get("result").cloned().unwrap_or(Value::Null)),
        |error| Err(error.clone()),
    )
}

struct MockBackend {
    chain_id: ChainId,
    head_hash: BlockHash,
    runtime_attached: bool,
    runtime_call_response: RuntimeCallResponse,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self {
            chain_id: 7,
            head_hash: [0xAA; 32],
            runtime_attached: true,
            runtime_call_response: RuntimeCallResponse {
                code: 0,
                payload: vec![1, 2, 3, 4],
                gas_used: 100,
            },
        }
    }
}

#[async_trait]
impl RpcBackend for MockBackend {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    fn runtime_abi_version(&self) -> Option<u32> {
        if self.runtime_attached {
            Some(neutrino_runtime_abi::VERSION)
        } else {
            None
        }
    }
    fn runtime_available(&self) -> bool {
        self.runtime_attached
    }
    fn mempool_len(&self) -> usize {
        3
    }
    async fn head(&self) -> HeadInfo {
        HeadInfo {
            height: 42,
            hash: self.head_hash,
            slot: 42,
            state_root: [0xBB; 32],
        }
    }
    async fn finalized(&self) -> FinalizedInfo {
        FinalizedInfo {
            index: 1,
            block_hash: [0xCC; 32],
            height: 8,
            state_root: [0xDD; 32],
        }
    }
    async fn active_validator_set(&self) -> Vec<Validator> {
        vec![Validator {
            pubkey: [0xEE; 48],
            withdrawal_credentials: [0xFF; 32],
            effective_stake: 1_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }]
    }
    async fn resolve_block_id(&self, id: &BlockId) -> Option<BlockHash> {
        match id {
            BlockId::Latest => Some(self.head_hash),
            BlockId::Finalized => Some([0xCC; 32]),
            BlockId::Hash(h) => Some(*h),
            BlockId::Height(h) if *h == 42 => Some(self.head_hash),
            BlockId::Height(_) => None,
        }
    }
    async fn header_by_hash(&self, hash: BlockHash) -> Option<Header> {
        if hash == self.head_hash {
            Some(sample_header(42, hash))
        } else {
            None
        }
    }
    async fn header_by_height(&self, height: Height) -> Option<Header> {
        if height == 42 {
            Some(sample_header(42, self.head_hash))
        } else {
            None
        }
    }
    async fn block_by_hash(&self, hash: BlockHash) -> Option<Block> {
        if hash == self.head_hash {
            Some(Block {
                header: sample_header(42, hash),
                body: Body::default(),
            })
        } else {
            None
        }
    }
    async fn block_by_height(&self, height: Height) -> Option<Block> {
        if height == 42 {
            Some(Block {
                header: sample_header(42, self.head_hash),
                body: Body::default(),
            })
        } else {
            None
        }
    }
    async fn storage_at(&self, key: &[u8], _at: &BlockId) -> Option<Vec<u8>> {
        if key == b"present" {
            Some(b"hello".to_vec())
        } else {
            None
        }
    }
    async fn submit_transaction(&self, _bytes: Vec<u8>) -> Result<Hash, SubmitError> {
        Ok([0x42; 32])
    }
    async fn runtime_call(
        &self,
        _method: String,
        _args: Vec<u8>,
        _at: &BlockId,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        if self.runtime_attached {
            Ok(self.runtime_call_response.clone())
        } else {
            Err(RuntimeCallError::RuntimeNotConfigured)
        }
    }
}

const fn sample_header(height: Height, hash_seed: BlockHash) -> Header {
    Header {
        version: 1,
        height,
        slot: height as Slot,
        parent_hash: [0; 32],
        proposer_index: 0,
        vrf_proof: [0; 96],
        state_root: hash_seed,
        transactions_root: [0; 32],
        votes_root: [0; 32],
        slashings_root: [0; 32],
        validator_ops_root: [0; 32],
        da_root: [0; 32],
        runtime_extra: [0; 32],
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: 1_700_000_000,
        signature: [0; 96],
    }
}

#[tokio::test]
async fn system_chain_id_returns_configured_chain_id() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: ChainId = module.call("system_chainId", [(); 0]).await.unwrap();
    assert_eq!(result, 7);
}

#[tokio::test]
async fn system_health_reports_runtime_and_mempool() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("system_health", [(); 0]).await.unwrap();
    assert_eq!(result["mempool"], 3);
    assert_eq!(result["runtime_available"], true);
    assert_eq!(result["head_height"], 42);
}

#[tokio::test]
async fn system_version_includes_runtime_abi_when_attached() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("system_version", [(); 0]).await.unwrap();
    assert_eq!(result["abi_version"], neutrino_runtime_abi::VERSION);
    assert_eq!(result["runtime_abi_version"], neutrino_runtime_abi::VERSION);
}

#[tokio::test]
async fn chain_head_returns_head_summary() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("chain_head", [(); 0]).await.unwrap();
    assert_eq!(result["height"], 42);
    assert_eq!(result["slot"], 42);
    assert!(result["hash"].as_str().unwrap().starts_with("0xaaaaaaaaaa"));
}

#[tokio::test]
async fn chain_get_header_defaults_to_latest() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("chain_getHeader", [(); 0]).await.unwrap();
    assert_eq!(result["height"], 42);
}

#[tokio::test]
async fn chain_get_header_accepts_height_number() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("chain_getHeader", [42_u64]).await.unwrap();
    assert_eq!(result["height"], 42);
}

#[tokio::test]
async fn chain_get_header_accepts_latest_string() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("chain_getHeader", ["latest"]).await.unwrap();
    assert_eq!(result["height"], 42);
}

#[tokio::test]
async fn chain_get_header_returns_null_for_unknown_height() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("chain_getHeader", [9999_u64]).await.unwrap();
    assert!(result.is_null());
}

#[tokio::test]
async fn chain_get_validator_set_returns_active_set() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("chain_getValidatorSet", [(); 0]).await.unwrap();
    let arr = result.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["effective_stake"], 1_000_000);
}

#[tokio::test]
async fn state_get_storage_returns_value_at_present_key() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result = call_named(
        &module,
        "state_getStorage",
        json!({"key": format!("0x{}", hex::encode(b"present"))}),
    )
    .await
    .unwrap();
    assert_eq!(result, json!(format!("0x{}", hex::encode(b"hello"))));
}

#[tokio::test]
async fn state_get_storage_returns_null_for_missing_key() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result = call_named(
        &module,
        "state_getStorage",
        json!({"key": format!("0x{}", hex::encode(b"missing"))}),
    )
    .await
    .unwrap();
    assert!(result.is_null());
}

#[tokio::test]
async fn mempool_submit_transaction_returns_hash() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result = call_named(
        &module,
        "mempool_submitTransaction",
        json!({"bytes": format!("0x{}", hex::encode([1, 2, 3]))}),
    )
    .await
    .unwrap();
    assert_eq!(
        result["hash"].as_str().unwrap(),
        format!("0x{}", hex::encode([0x42; 32]))
    );
}

#[tokio::test]
async fn mempool_status_returns_pending_count() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("mempool_status", [(); 0]).await.unwrap();
    assert_eq!(result["pending"], 3);
}

#[tokio::test]
async fn runtime_call_returns_payload_and_gas_used() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result = call_named(
        &module,
        "runtime_call",
        json!({
            "method": "account_get",
            "args": format!("0x{}", hex::encode([0xAA; 32])),
        }),
    )
    .await
    .unwrap();
    assert_eq!(result["code"], 0);
    assert_eq!(result["gas_used"], 100);
    assert_eq!(result["payload"].as_str().unwrap(), "0x01020304");
}

#[tokio::test]
async fn runtime_call_errors_when_runtime_not_configured() {
    let backend = Arc::new(MockBackend {
        runtime_attached: false,
        ..MockBackend::default()
    });
    let module = build_module(backend).unwrap();
    let err = call_named(
        &module,
        "runtime_call",
        json!({"method": "x", "args": "0x"}),
    )
    .await
    .expect_err("expected error");
    let msg = err["message"].as_str().unwrap_or("");
    assert!(msg.contains("runtime"), "unexpected error payload: {msg}");
}
