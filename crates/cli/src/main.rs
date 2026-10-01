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
    Err(format!("command `{command}` is not implemented"))
}

fn print_usage() {
    eprintln!("usage: neutrino-cli <command>");
    eprintln!();
    eprintln!("Run a node with the neutrino-node binary.");
}
