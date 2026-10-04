//! JSON-RPC server wiring.
//!
//! [`build_module`] returns an [`RpcModule`] populated with all
//! Neutrino methods, parameterised by an [`Arc<dyn RpcBackend>`].
//! [`serve`] additionally binds a TCP listener and spawns the
//! jsonrpsee server task; the returned [`ServerHandle`] terminates the
//! server when dropped.
//!
//! All methods share these characteristics:
//!
//! - Inputs are validated up front; invalid params return JSON-RPC
//!   error code `-32602`.
//! - Backend errors use distinct server error codes for block lookup,
//!   unavailable data, storage, runtime invocation, and transaction admission.
//! - The methods listed in `docs/design/08-crate-layout.md` for the
//!   `rpc` crate are all implemented.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jsonrpsee::server::middleware::rpc::{
    Batch, MethodResponse, Notification, Request, RpcServiceBuilder, RpcServiceT,
};
use jsonrpsee::server::{
    BatchRequestConfig, ConnectionId, RpcModule, Server, ServerConfig, ServerHandle,
};
use jsonrpsee::types::{ErrorObjectOwned, Id};

use crate::backend::{BlockId, QueryError, RpcBackend, RuntimeCallError, SubmitError};
use crate::types::{
    BlockIdJson, BlockJson, BytesHex, FinalizedInfoJson, HashHex, HeadInfoJson, HeaderJson,
    HealthJson, RuntimeCallResultJson, SubmitResultJson, SystemInfoJson, ValidatorJson,
};

/// Bind address + tuning knobs for the JSON-RPC server.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// `host:port` to bind on. Use `127.0.0.1:9933` for local-only
    /// access; `0.0.0.0:9933` to listen on every interface.
    pub listen: SocketAddr,
    /// Maximum concurrent connections. Reasonable default: 200.
    pub max_connections: u32,
    /// Maximum size of a single request body in bytes (default 10 MiB).
    pub max_request_body_size: u32,
    /// Maximum size of a single response body in bytes (default 15 MiB).
    pub max_response_body_size: u32,
    /// Requests allowed to execute at once across every connection
    /// (default 64). Excess requests fail immediately with `-32005`.
    pub max_concurrent_requests: u32,
    /// Sustained per-connection request rate (default 50/s, burst twice
    /// that). Requests over the budget fail with `-32006`.
    pub requests_per_second_per_connection: u32,
    /// Maximum entries in one JSON-RPC batch (default 16).
    pub max_batch_requests: u32,
    /// Wall-clock budget for one `runtime_call` (default 2 s). The WASM
    /// fuel cap bounds CPU; this bounds the caller's wait.
    pub runtime_call_timeout: Duration,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9933".parse().expect("default listen parses"),
            max_connections: 200,
            max_request_body_size: 10 * 1024 * 1024,
            max_response_body_size: 15 * 1024 * 1024,
            max_concurrent_requests: 64,
            requests_per_second_per_connection: 50,
            max_batch_requests: 16,
            runtime_call_timeout: Duration::from_secs(2),
        }
    }
}

/// Errors raised while building or starting the RPC server.
#[derive(Debug, thiserror::Error)]
pub enum RpcStartError {
    /// jsonrpsee's transport-layer setup failed.
    #[error("rpc transport error: {0}")]
    Transport(String),
    /// Failed to register one of the canonical methods.
    #[error("rpc method registration failed: {0}")]
    Registration(String),
}

/// Build a fully-populated [`RpcModule`] without binding a listener.
/// Useful for in-process tests that exercise method dispatch via
/// [`RpcModule::call`] without spinning up a TCP socket.
pub fn build_module(backend: Arc<dyn RpcBackend>) -> Result<RpcModule<RpcContext>, RpcStartError> {
    build_module_with(backend, RpcConfig::default().runtime_call_timeout)
}

/// [`build_module`] with an explicit `runtime_call` wall-clock budget.
///
/// # Errors
/// Returns [`RpcStartError::Registration`] when a method name collides.
pub fn build_module_with(
    backend: Arc<dyn RpcBackend>,
    runtime_call_timeout: Duration,
) -> Result<RpcModule<RpcContext>, RpcStartError> {
    let mut module = RpcModule::new(RpcContext {
        backend,
        runtime_call_timeout,
    });
    register_methods(&mut module)?;
    Ok(module)
}

/// Build the RPC module and start the jsonrpsee server. The returned
/// handle keeps the server alive until it is dropped or `stop()` is
/// called.
pub async fn serve(
    backend: Arc<dyn RpcBackend>,
    config: RpcConfig,
) -> Result<ServerHandle, RpcStartError> {
    let module = build_module_with(backend, config.runtime_call_timeout)?;
    let server_config = ServerConfig::builder()
        .max_connections(config.max_connections)
        .max_request_body_size(config.max_request_body_size)
        .max_response_body_size(config.max_response_body_size)
        .set_batch_request_config(BatchRequestConfig::Limit(config.max_batch_requests.max(1)))
        .build();
    let permits = Arc::new(tokio::sync::Semaphore::new(
        usize::try_from(config.max_concurrent_requests.max(1)).unwrap_or(usize::MAX),
    ));
    // HTTP builds the middleware per request, so per-connection state lives
    // in one shared table keyed by jsonrpsee's connection id; the execution
    // permits are shared process-wide.
    let buckets = Arc::new(Mutex::new(BucketTable::new(
        config.requests_per_second_per_connection.max(1),
        usize::try_from(config.max_connections.max(1))
            .unwrap_or(usize::MAX)
            .saturating_mul(4),
    )));
    let rpc_middleware = RpcServiceBuilder::new().layer_fn(move |service| RequestGovernor {
        service,
        permits: Arc::clone(&permits),
        buckets: Arc::clone(&buckets),
    });
    let server = Server::builder()
        .set_config(server_config)
        .set_rpc_middleware(rpc_middleware)
        .build(config.listen)
        .await
        .map_err(|err| RpcStartError::Transport(err.to_string()))?;
    Ok(server.start(module))
}

/// Per-connection token bucket: `rate` tokens per second, burst of twice
/// the rate. Refill is computed lazily on each request.
#[derive(Debug)]
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: u32) -> Self {
        let rate = f64::from(rate);
        Self {
            capacity: rate * 2.0,
            tokens: rate * 2.0,
            refill_per_sec: rate,
            last: Instant::now(),
        }
    }

    fn try_take(&mut self, cost: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = elapsed
            .mul_add(self.refill_per_sec, self.tokens)
            .min(self.capacity);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Token buckets keyed by connection id, bounded by evicting the oldest
/// entries once `capacity` distinct connections have been seen.
#[derive(Debug)]
struct BucketTable {
    rate: u32,
    capacity: usize,
    buckets: std::collections::HashMap<usize, TokenBucket>,
    order: std::collections::VecDeque<usize>,
}

impl BucketTable {
    fn new(rate: u32, capacity: usize) -> Self {
        Self {
            rate,
            capacity: capacity.max(1),
            buckets: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    fn try_take(&mut self, conn: usize, cost: f64) -> bool {
        if !self.buckets.contains_key(&conn) {
            while self.buckets.len() >= self.capacity {
                let Some(oldest) = self.order.pop_front() else {
                    break;
                };
                self.buckets.remove(&oldest);
            }
            self.buckets.insert(conn, TokenBucket::new(self.rate));
            self.order.push_back(conn);
        }
        self.buckets
            .get_mut(&conn)
            .is_some_and(|bucket| bucket.try_take(cost))
    }
}

/// Connection id used when jsonrpsee attached none to the request.
const ANONYMOUS_CONNECTION: usize = usize::MAX;

/// Rate and concurrency guard applied in front of method dispatch.
#[derive(Clone)]
struct RequestGovernor<S> {
    service: S,
    permits: Arc<tokio::sync::Semaphore>,
    buckets: Arc<Mutex<BucketTable>>,
}

impl<S> RequestGovernor<S> {
    fn admit(
        &self,
        conn: usize,
        cost: u32,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, ErrorObjectOwned> {
        let allowed = self
            .buckets
            .lock()
            .expect("rpc token buckets poisoned")
            .try_take(conn, f64::from(cost));
        if !allowed {
            return Err(ErrorObjectOwned::owned(
                -32006,
                "rate limited: per-connection request budget exhausted",
                None::<()>,
            ));
        }
        Arc::clone(&self.permits)
            .try_acquire_many_owned(cost)
            .map_err(|_| {
                ErrorObjectOwned::owned(
                    -32005,
                    "server busy: too many requests in flight",
                    None::<()>,
                )
            })
    }
}

impl<S> RpcServiceT for RequestGovernor<S>
where
    S: RpcServiceT<
            MethodResponse = MethodResponse,
            BatchResponse = MethodResponse,
            NotificationResponse = MethodResponse,
        > + Send
        + Sync
        + Clone
        + 'static,
{
    type MethodResponse = MethodResponse;
    type NotificationResponse = MethodResponse;
    type BatchResponse = MethodResponse;

    fn call<'a>(&self, request: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let conn = request
            .extensions()
            .get::<ConnectionId>()
            .map_or(ANONYMOUS_CONNECTION, |id| id.0);
        let admitted = self.admit(conn, 1);
        let service = self.service.clone();
        async move {
            match admitted {
                Ok(_permit) => service.call(request).await,
                Err(error) => MethodResponse::error(request.id(), error),
            }
        }
    }

    fn batch<'a>(&self, requests: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let mut requests = requests;
        let conn = requests
            .extensions()
            .get::<ConnectionId>()
            .map_or(ANONYMOUS_CONNECTION, |id| id.0);
        let cost = u32::try_from(requests.len()).unwrap_or(u32::MAX).max(1);
        let admitted = self.admit(conn, cost);
        let service = self.service.clone();
        async move {
            match admitted {
                Ok(_permit) => service.batch(requests).await,
                Err(error) => MethodResponse::error(Id::Null, error),
            }
        }
    }

    fn notification<'a>(
        &self,
        n: Notification<'a>,
    ) -> impl Future<Output = MethodResponse> + Send + 'a {
        self.service.notification(n)
    }
}

/// Shared context handed to every RPC handler.
#[derive(Clone)]
pub struct RpcContext {
    backend: Arc<dyn RpcBackend>,
    runtime_call_timeout: Duration,
}

impl RpcContext {
    /// Borrow the underlying backend.
    pub fn backend(&self) -> &Arc<dyn RpcBackend> {
        &self.backend
    }
}

fn register_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    register_system_methods(module)?;
    register_chain_methods(module)?;
    register_state_methods(module)?;
    register_mempool_methods(module)?;
    register_runtime_methods(module)?;
    register_history_methods(module)?;
    Ok(())
}

fn register_system_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("system_chainId", |_, ctx, _| async move {
            Ok::<_, ErrorObjectOwned>(ctx.backend().chain_id())
        })
        .map_err(reg_err)?;

    module
        .register_async_method("system_health", |_, ctx, _| async move {
            let head = ctx
                .backend()
                .head()
                .await
                .map_err(|error| query_err(&error))?;
            Ok::<_, ErrorObjectOwned>(HealthJson {
                peers: ctx.backend().peer_count(),
                is_syncing: ctx.backend().is_syncing(),
                runtime_available: ctx.backend().runtime_available(),
                mempool: u64::try_from(ctx.backend().mempool_len()).unwrap_or(u64::MAX),
                head_height: head.height,
            })
        })
        .map_err(reg_err)?;

    module
        .register_async_method("system_info", |_, ctx, _| async move {
            Ok::<_, ErrorObjectOwned>(SystemInfoJson {
                runtime_code_hash: ctx.backend().runtime_code_hash().map(HashHex::from),
            })
        })
        .map_err(reg_err)?;

    Ok(())
}

fn register_chain_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("chain_head", |_, ctx, _| async move {
            let head = ctx
                .backend()
                .head()
                .await
                .map_err(|error| query_err(&error))?;
            Ok::<_, ErrorObjectOwned>(HeadInfoJson::from(head))
        })
        .map_err(reg_err)?;

    module
        .register_async_method("chain_finalized", |_, ctx, _| async move {
            let fin = ctx
                .backend()
                .finalized()
                .await
                .map_err(|error| query_err(&error))?;
            Ok::<_, ErrorObjectOwned>(FinalizedInfoJson::from(fin))
        })
        .map_err(reg_err)?;

    module
        .register_async_method("chain_getHeader", |params, ctx, _| async move {
            let at: BlockIdJson = parse_optional_block_id(&params)?;
            let Some(hash) = resolve(&ctx, &at.0).await? else {
                return Ok::<_, ErrorObjectOwned>(None);
            };
            Ok::<_, ErrorObjectOwned>(
                ctx.backend()
                    .header_by_hash(hash)
                    .await
                    .map_err(|error| query_err(&error))?
                    .map(|h| HeaderJson::from(&h)),
            )
        })
        .map_err(reg_err)?;

    module
        .register_async_method("chain_getBlock", |params, ctx, _| async move {
            let at: BlockIdJson = parse_optional_block_id(&params)?;
            let Some(hash) = resolve(&ctx, &at.0).await? else {
                return Ok::<_, ErrorObjectOwned>(None);
            };
            Ok::<_, ErrorObjectOwned>(
                ctx.backend()
                    .block_by_hash(hash)
                    .await
                    .map_err(|error| query_err(&error))?
                    .map(|b| BlockJson::from(&b)),
            )
        })
        .map_err(reg_err)?;

    module
        .register_async_method("chain_getValidatorSet", |_, ctx, _| async move {
            let validators = ctx.backend().active_validator_set().await;
            Ok::<_, ErrorObjectOwned>(
                validators
                    .iter()
                    .map(ValidatorJson::from)
                    .collect::<Vec<_>>(),
            )
        })
        .map_err(reg_err)?;

    Ok(())
}

fn register_state_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("state_getStorage", |params, ctx, _| async move {
            #[derive(serde::Deserialize)]
            struct StorageParams {
                key: BytesHex,
                #[serde(default)]
                at: BlockIdJson,
            }
            let p: StorageParams = params.parse().map_err(invalid_params)?;
            let value = ctx
                .backend()
                .storage_at(&p.key.0, &p.at.0)
                .await
                .map_err(|error| query_err(&error))?;
            Ok::<_, ErrorObjectOwned>(value.map(BytesHex::from))
        })
        .map_err(reg_err)?;

    Ok(())
}

fn register_mempool_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("mempool_submitTransaction", |params, ctx, _| async move {
            #[derive(serde::Deserialize)]
            struct SubmitParams {
                bytes: BytesHex,
            }
            let p: SubmitParams = params.parse().map_err(invalid_params)?;
            match ctx.backend().submit_transaction(p.bytes.0).await {
                Ok(hash) => Ok::<_, ErrorObjectOwned>(SubmitResultJson::new(hash)),
                Err(err) => Err(submit_err(&err)),
            }
        })
        .map_err(reg_err)?;

    module
        .register_async_method("mempool_status", |_, ctx, _| async move {
            #[derive(Clone, serde::Serialize)]
            struct MempoolStatus {
                pending: u64,
            }
            Ok::<_, ErrorObjectOwned>(MempoolStatus {
                pending: u64::try_from(ctx.backend().mempool_len()).unwrap_or(u64::MAX),
            })
        })
        .map_err(reg_err)?;

    Ok(())
}

fn register_runtime_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("runtime_call", |params, ctx, _| async move {
            #[derive(serde::Deserialize)]
            struct CallParams {
                method: String,
                #[serde(default)]
                args: BytesHex,
                #[serde(default)]
                at: BlockIdJson,
            }
            let p: CallParams = params.parse().map_err(invalid_params)?;
            let call = ctx.backend().runtime_call(p.method, p.args.0, &p.at.0);
            match tokio::time::timeout(ctx.runtime_call_timeout, call).await {
                Ok(Ok(resp)) => Ok::<_, ErrorObjectOwned>(RuntimeCallResultJson {
                    code: resp.code,
                    payload: BytesHex(resp.payload),
                    gas_used: resp.gas_used,
                }),
                Ok(Err(err)) => Err(runtime_err(&err)),
                Err(_) => Err(ErrorObjectOwned::owned(
                    -32012,
                    "runtime_call timed out",
                    None::<()>,
                )),
            }
        })
        .map_err(reg_err)?;

    Ok(())
}

/// Resolve a [`BlockId`] to a block hash by asking the backend.
async fn resolve(ctx: &RpcContext, at: &BlockId) -> Result<Option<[u8; 32]>, ErrorObjectOwned> {
    ctx.backend()
        .resolve_block_id(at)
        .await
        .map_err(|error| query_err(&error))
}

/// Parse the optional `BlockIdJson` parameter; default to `Latest`.
///
/// Accepts either named (`{"at": ...}`) or positional (`[<id>]` /
/// empty `[]`) parameters so clients can use whichever style is
/// idiomatic for their JSON-RPC library.
fn parse_optional_block_id(
    params: &jsonrpsee::types::Params<'_>,
) -> Result<BlockIdJson, ErrorObjectOwned> {
    if params.is_object() {
        #[derive(serde::Deserialize)]
        struct Wrapped {
            #[serde(default)]
            at: BlockIdJson,
        }
        let w: Wrapped = params.parse().map_err(invalid_params)?;
        Ok(w.at)
    } else {
        let mut seq = params.sequence();
        let opt: Option<BlockIdJson> = seq.optional_next().map_err(invalid_params)?;
        Ok(opt.unwrap_or_default())
    }
}

fn register_history_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("history_getRetention", |_, ctx, _| async move {
            ctx.backend()
                .history_retention()
                .await
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_async_method("history_getLatest", |_, ctx, _| async move {
            ctx.backend
                .history_latest()
                .await
                .map(BytesHex)
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_async_method("history_proveRange", |params, ctx, _| async move {
            let (start, end): (HashHex, HashHex) = params.parse()?;
            ctx.backend
                .history_request(start.0, end.0)
                .await
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_async_method("history_getJob", |params, ctx, _| async move {
            let (id,): (HashHex,) = params.parse()?;
            ctx.backend
                .history_job(id.0)
                .await
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_async_method("history_getProof", |params, ctx, _| async move {
            let (start, end): (HashHex, HashHex) = params.parse()?;
            ctx.backend
                .history_proof(start.0, end.0)
                .await
                .map(BytesHex)
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_subscription(
            "history_subscribeJob",
            "history_job",
            "history_unsubscribeJob",
            |params, pending, ctx, _| async move {
                let id = match params.parse::<(HashHex,)>() {
                    Ok((id,)) => id,
                    Err(error) => {
                        pending.reject(error).await;
                        return Ok(());
                    }
                };
                let mut receiver = match ctx.backend.history_subscribe(id.0).await {
                    Ok(receiver) => receiver,
                    Err(error) => {
                        pending.reject(query_err(&error)).await;
                        return Ok(());
                    }
                };
                let sink = pending.accept().await?;
                loop {
                    let current = receiver.borrow_and_update().clone();
                    let terminal = current.status.is_terminal();
                    let message = serde_json::value::to_raw_value(&current)?;
                    sink.send(message).await?;
                    if terminal {
                        break;
                    }
                    tokio::select! {
                        () = sink.closed() => break,
                        changed = receiver.changed() => { if changed.is_err() { break; } }
                    }
                }
                drop(sink);
                drop(receiver);
                Ok::<(), jsonrpsee::core::SubscriptionError>(())
            },
        )
        .map_err(reg_err)?;
    Ok(())
}

fn reg_err(err: impl core::fmt::Display) -> RpcStartError {
    RpcStartError::Registration(err.to_string())
}

fn invalid_params(err: impl core::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, format!("invalid params: {err}"), None::<()>)
}

fn submit_err(err: &SubmitError) -> ErrorObjectOwned {
    let code = match err {
        SubmitError::Duplicate => -32001,
        SubmitError::Full => -32002,
        SubmitError::Rejected { .. } => -32003,
    };
    ErrorObjectOwned::owned(code, err.to_string(), None::<()>)
}

fn runtime_err(err: &RuntimeCallError) -> ErrorObjectOwned {
    let code = match err {
        RuntimeCallError::RuntimeNotConfigured => -32010,
        RuntimeCallError::Query(error) => return query_err(error),
        RuntimeCallError::Runtime(_) => -32012,
        RuntimeCallError::Decode(_) => -32013,
    };
    ErrorObjectOwned::owned(code, err.to_string(), None::<()>)
}

fn query_err(err: &QueryError) -> ErrorObjectOwned {
    let code = match err {
        QueryError::BlockNotFound => -32020,
        QueryError::StateUnavailable => -32021,
        QueryError::Storage(_) => -32022,
        QueryError::BodyUnavailable => -32023,
        QueryError::HistoryUnavailable => -32025,
        QueryError::Pruned {
            retained_from_chunk,
            retained_from_height,
        } => {
            return ErrorObjectOwned::owned(
                -32024,
                err.to_string(),
                Some(serde_json::json!({
                    "retained_from_chunk": retained_from_chunk,
                    "retained_from_height": retained_from_height,
                })),
            );
        }
    };
    ErrorObjectOwned::owned(code, err.to_string(), None::<()>)
}

#[cfg(test)]
mod governor_tests {
    use super::*;

    #[test]
    fn token_bucket_allows_burst_then_refills() {
        let mut bucket = TokenBucket::new(10);
        // Burst capacity is twice the rate.
        assert!((0..20).all(|_| bucket.try_take(1.0)));
        assert!(!bucket.try_take(1.0));
        // Simulate half a second elapsing: five tokens come back.
        bucket.last -= Duration::from_millis(500);
        assert!((0..5).all(|_| bucket.try_take(1.0)));
        assert!(!bucket.try_take(1.0));
        // Refill never exceeds capacity.
        bucket.last -= Duration::from_secs(60);
        assert!((0..20).all(|_| bucket.try_take(1.0)));
        assert!(!bucket.try_take(1.0));
    }

    #[test]
    fn admit_reports_rate_limit_and_busy_distinctly() {
        let governor = RequestGovernor {
            service: (),
            permits: Arc::new(tokio::sync::Semaphore::new(2)),
            buckets: Arc::new(Mutex::new(BucketTable::new(50, 16))),
        };
        let first = governor.admit(1, 1).unwrap();
        let second = governor.admit(1, 1).unwrap();
        // Permits are exhausted while two requests are in flight.
        assert_eq!(governor.admit(1, 1).unwrap_err().code(), -32005);
        drop(first);
        drop(second);
        assert!(governor.admit(1, 1).is_ok());
        // A batch larger than the whole burst budget is rate limited.
        assert_eq!(governor.admit(1, 1_000).unwrap_err().code(), -32006);
        // Connections are isolated: draining one leaves another untouched.
        // Four tokens are gone already: two admitted, one refused for lack of
        // a permit (still charged) and one admitted after the permits freed.
        for _ in 0..96 {
            drop(governor.admit(1, 1).unwrap());
        }
        assert_eq!(governor.admit(1, 1).unwrap_err().code(), -32006);
        assert!(governor.admit(2, 1).is_ok());
    }

    #[test]
    fn bucket_table_evicts_oldest_connections() {
        let mut table = BucketTable::new(1, 2);
        assert!(table.try_take(1, 2.0));
        assert!(!table.try_take(1, 1.0));
        assert!(table.try_take(2, 1.0));
        // A third connection evicts connection 1; it then starts fresh.
        assert!(table.try_take(3, 1.0));
        assert_eq!(table.buckets.len(), 2);
        assert!(table.try_take(1, 1.0));
    }
}
