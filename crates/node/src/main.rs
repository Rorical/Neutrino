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

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    match run().await {
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
    eprintln!("    runtime_elf_path = \"/path/to/runtime.elf\"");
    eprintln!("    proposer_ikm_hex = \"<64 hex chars>\"     # validator only");
    eprintln!("    proposer_index   = 0                    # validator only");
    eprintln!("    subscribe_topics = [\"/neutrino/blocks/borsh/1\", ...]");
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
