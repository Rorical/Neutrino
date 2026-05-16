#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! `neutrino-cli` binary entrypoint.

use std::env;
use std::fs;
use std::process::ExitCode;

use neutrino_cli::{SingleValidatorRunConfig, run_single_validator_node};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        return Err("missing command".to_string());
    };
    if command != "run-single-validator" {
        return Err(format!("unknown command `{command}`"));
    }

    let runtime_path = args
        .next()
        .ok_or_else(|| "missing runtime ELF path".to_string())?;
    let slots = parse_u64_arg(args.next(), "slots")?.unwrap_or(1_000);
    let chunk_size = parse_u64_arg(args.next(), "chunk_size")?.unwrap_or(125);
    if args.next().is_some() {
        return Err("too many arguments".to_string());
    }

    let runtime_elf = fs::read(&runtime_path)
        .map_err(|err| format!("failed to read runtime ELF `{runtime_path}`: {err}"))?;
    let mut config = SingleValidatorRunConfig::default_for_runtime(&runtime_elf);
    config.slots = slots;
    config.chunk_size = chunk_size;

    let dump = run_single_validator_node(config).map_err(|err| err.to_string())?;
    println!("head_height={}", dump.final_head_height);
    println!("head_hash={}", hex::encode(dump.final_head_hash));
    println!("state_root={}", hex::encode(dump.final_state_root));
    println!("finalized_seed={}", hex::encode(dump.final_finalized_seed));
    for block in &dump.blocks {
        println!(
            "block height={} slot={} hash={} state_root={}",
            block.height,
            block.slot,
            hex::encode(block.hash),
            hex::encode(block.state_root)
        );
    }
    for chunk in &dump.chunks {
        println!(
            "chunk id={} hash={}",
            chunk.chunk_id,
            hex::encode(chunk.hash)
        );
    }
    for checkpoint in &dump.checkpoints {
        println!(
            "checkpoint index={} hash={}",
            checkpoint.index,
            hex::encode(checkpoint.hash)
        );
    }
    Ok(())
}

fn parse_u64_arg(value: Option<String>, name: &str) -> Result<Option<u64>, String> {
    value
        .map(|raw| {
            raw.parse::<u64>()
                .map_err(|err| format!("invalid {name} `{raw}`: {err}"))
        })
        .transpose()
}

fn print_usage() {
    eprintln!("usage: neutrino-cli run-single-validator <runtime-elf> [slots] [chunk_size]");
}
