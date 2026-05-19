#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! `neutrino-cli` binary entrypoint.

use std::env;
use std::process::ExitCode;

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
    if args.next().is_some() {
        return Err("too many arguments".to_string());
    }
    Err(format!(
        "command `{command}` awaits the WASM/SP1 runtime rewrite"
    ))
}

fn print_usage() {
    eprintln!("usage: neutrino-cli <command>");
    eprintln!();
    eprintln!("Commands will be reintroduced on top of the WASM/SP1 runtime architecture.");
}
