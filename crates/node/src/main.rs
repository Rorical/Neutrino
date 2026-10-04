#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! `neutrino-node` binary.
//!
//! Usage:
//! ```text
//! neutrino-node --config /path/to/config.toml
//! ```
//!
//! The config file format is documented at [`neutrino_node::NodeConfig`].

use std::env;
use std::process::ExitCode;

use neutrino_node::NodeConfig;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;

fn main() -> ExitCode {
    init_tracing();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            tracing::error!(error = %err, "failed to start tokio runtime");
            return ExitCode::FAILURE;
        }
    };
    let outcome = runtime.block_on(run());
    // A CPU proof in flight on the blocking pool can take many minutes.
    // Operators expect SIGTERM to stop the process promptly; the proof job
    // is resumable from persisted inputs, so abandon it after a short grace.
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "neutrino-node failed");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args()?;
    neutrino_node::run(config).await?;
    Ok(())
}

fn parse_args() -> Result<NodeConfig, Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let mut config_path: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                config_path = Some(args.next().ok_or("missing value for --config")?);
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`").into()),
        }
    }
    let path = config_path.ok_or("missing required --config <path>")?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read config `{path}`: {err}"))?;
    let cfg: NodeConfig =
        toml::from_str(&raw).map_err(|err| format!("failed to parse config `{path}`: {err}"))?;
    Ok(cfg)
}

fn print_usage() {
    eprintln!("usage: neutrino-node --config <path-to-toml>");
    eprintln!();
    eprintln!("Run a Neutrino full node. The config file must contain at least:");
    eprintln!("    chain_id = <u64>");
    eprintln!();
    eprintln!("Optional keys:");
    eprintln!("    role             = \"validator\" | \"full\" | \"light-client\" | \"archive\"");
    eprintln!("    listen           = [\"<multiaddr>\"]      # defaults to /ip4/0.0.0.0/tcp/0");
    eprintln!("    bootnodes        = [\"<multiaddr>\"]");
    eprintln!("    data_dir         = \"/path/to/data\"");
    eprintln!("    chain_spec_path  = \"/path/to/chain-spec.toml\"");
    eprintln!("    proposer_ikm_path = \"/path/to/validator.ikm\"  # validator only, mode 0600");
    eprintln!("    proposer_index   = 0                    # validator only");
    eprintln!("    # or export NEUTRINO_PROPOSER_IKM_HEX=<64 hex chars> (takes precedence)");
    eprintln!("    subscribe_topics = [\"/neutrino/blocks/borsh\", ...]");
    eprintln!();
    eprintln!("    [proving]");
    eprintln!(
        "    backend          = \"cpu\"              # or cuda (Linux x86-64, --features cuda)"
    );
    eprintln!("    concurrency      = 2");
    eprintln!("    capacity         = 16");
    eprintln!("    # cuda_device    = 0                    # CUDA only");
    eprintln!();
    eprintln!("    [rpc]");
    eprintln!("    listen           = \"127.0.0.1:9933\"");
    eprintln!("    max_concurrent_requests = 64");
    eprintln!("    requests_per_second_per_connection = 50");
    eprintln!("    runtime_call_timeout_ms = 2000");
    eprintln!();
    eprintln!("    [execution]                              # WASM fuel/memory caps");
    eprintln!("    query_fuel       = 50000000");
    eprintln!();
    eprintln!("Generate keys, genesis roots and configs with the neutrino-cli binary.");
}

fn init_tracing() {
    // Default to info; honour `RUST_LOG` (env-filter syntax) when present.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,libp2p=warn"));
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .init();
}
