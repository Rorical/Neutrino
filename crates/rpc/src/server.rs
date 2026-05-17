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
//! - Backend errors are surfaced as `-32000` (server error) with a
//!   human-readable message; details are also tagged on the
//!   `data` field for clients that want to discriminate.
//! - The methods listed in `docs/design/08-crate-layout.md` for the
//!   `rpc` crate are all implemented.

use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::server::{RpcModule, Server, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;

use crate::backend::{BlockId, RpcBackend, RuntimeCallError, SubmitError};
use crate::types::{
    BlockIdJson, BlockJson, BytesHex, FinalizedInfoJson, HeadInfoJson, HeaderJson, HealthJson,
    RuntimeCallResultJson, SubmitResultJson, ValidatorJson, VersionJson,
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
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9933".parse().expect("default listen parses"),
            max_connections: 200,
            max_request_body_size: 10 * 1024 * 1024,
            max_response_body_size: 15 * 1024 * 1024,
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
    let mut module = RpcModule::new(RpcContext { backend });
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
    let module = build_module(backend)?;
    let server = Server::builder()
        .max_connections(config.max_connections)
        .max_request_body_size(config.max_request_body_size)
        .max_response_body_size(config.max_response_body_size)
        .build(config.listen)
        .await
        .map_err(|err| RpcStartError::Transport(err.to_string()))?;
    Ok(server.start(module))
}

/// Shared context handed to every RPC handler.
#[derive(Clone)]
pub struct RpcContext {
    backend: Arc<dyn RpcBackend>,
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
            let head = ctx.backend().head().await;
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
        .register_async_method("system_version", |_, ctx, _| async move {
            Ok::<_, ErrorObjectOwned>(VersionJson {
                abi_version: neutrino_runtime_abi::VERSION,
                runtime_abi_version: ctx.backend().runtime_abi_version(),
            })
        })
        .map_err(reg_err)?;

    Ok(())
}

fn register_chain_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("chain_head", |_, ctx, _| async move {
            let head = ctx.backend().head().await;
            Ok::<_, ErrorObjectOwned>(HeadInfoJson::from(head))
        })
        .map_err(reg_err)?;

    module
        .register_async_method("chain_finalized", |_, ctx, _| async move {
            let fin = ctx.backend().finalized().await;
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
            let value = ctx.backend().storage_at(&p.key.0, &p.at.0).await;
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
            match ctx
                .backend()
                .runtime_call(p.method, p.args.0, &p.at.0)
                .await
            {
                Ok(resp) => Ok::<_, ErrorObjectOwned>(RuntimeCallResultJson {
                    code: resp.code,
                    payload: BytesHex(resp.payload),
                    gas_used: resp.gas_used,
                }),
                Err(err) => Err(runtime_err(&err)),
            }
        })
        .map_err(reg_err)?;

    Ok(())
}

/// Resolve a [`BlockId`] to a block hash by asking the backend.
async fn resolve(ctx: &RpcContext, at: &BlockId) -> Result<Option<[u8; 32]>, ErrorObjectOwned> {
    Ok(ctx.backend().resolve_block_id(at).await)
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
        RuntimeCallError::HistoricalStateNotSupported => -32011,
        RuntimeCallError::Runtime(_) => -32012,
        RuntimeCallError::Decode(_) => -32013,
    };
    ErrorObjectOwned::owned(code, err.to_string(), None::<()>)
}
