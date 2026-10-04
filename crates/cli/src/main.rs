#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! `neutrino-cli`: operator tooling for bringing up a network.
//!
//! ```text
//! neutrino-cli keygen --out <dir> [--name <name>]
//! neutrino-cli genesis --spec <chain-spec.toml> [--write]
//! neutrino-cli node-config --spec <chain-spec.toml> --out <config.toml> [options]
//! ```
//!
//! `keygen` writes a BLS proposer IKM and an Ed25519 account key as
//! owner-only files and prints the public identities the chain spec needs.
//! `genesis` derives the genesis state root and chain-spec hash from the
//! allocation in the spec file and can pin the root into the file.
//! `node-config` emits a node configuration that references the key file
//! instead of embedding the secret.

use std::env;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use getrandom::SysRng;
use neutrino_consensus_engine::ProposerKey;
use neutrino_crypto::ed25519::SecretKey;
use neutrino_node::{ChainSpecFile, build_genesis_state};
use rand_core::UnwrapErr;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            eprintln!();
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        return Err("missing command".to_owned());
    }
    let command = args.remove(0);
    let opts = Options::parse(&args)?;
    match command.as_str() {
        "keygen" => keygen(&opts),
        "genesis" => genesis(&opts),
        "node-config" => node_config(&opts),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        other => Err(format!("unknown command `{other}`")),
    }
}

fn print_usage() {
    eprintln!("usage: neutrino-cli <command> [options]");
    eprintln!();
    eprintln!("commands:");
    eprintln!("  keygen --out <dir> [--name <name>]");
    eprintln!("      Write <name>.ikm (BLS proposer IKM) and <name>.ed25519 (account key)");
    eprintln!("      as owner-only files; print the BLS pubkey and runtime address.");
    eprintln!("  genesis --spec <chain-spec.toml> [--write]");
    eprintln!("      Derive the genesis state root, validator-set root and chain-spec hash.");
    eprintln!("      --write pins genesis_state_root_hex into the spec file.");
    eprintln!("  node-config --spec <chain-spec.toml> --out <config.toml>");
    eprintln!("      [--role validator|full|archive|light-client] [--data-dir <dir>]");
    eprintln!("      [--ikm-path <file>] [--proposer-index <n>] [--listen <multiaddr>]...");
    eprintln!("      [--bootnode <multiaddr>]... [--rpc <host:port>] [--proving cpu|cuda]");
    eprintln!("      Emit a node config; the proposer key stays in the referenced file.");
}

/// Minimal `--flag value` / `--flag` parser; repeated flags accumulate.
struct Options {
    values: Vec<(String, Option<String>)>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut values = Vec::new();
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            let Some(flag) = arg.strip_prefix("--") else {
                return Err(format!("unexpected argument `{arg}`"));
            };
            let value = match iter.peek() {
                Some(next) if !next.starts_with("--") => iter.next().cloned(),
                _ => None,
            };
            values.push((flag.to_owned(), value));
        }
        Ok(Self { values })
    }

    fn get(&self, flag: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(name, _)| name == flag)
            .and_then(|(_, value)| value.as_deref())
    }

    fn all(&self, flag: &str) -> Vec<&str> {
        self.values
            .iter()
            .filter(|(name, _)| name == flag)
            .filter_map(|(_, value)| value.as_deref())
            .collect()
    }

    fn has(&self, flag: &str) -> bool {
        self.values.iter().any(|(name, _)| name == flag)
    }

    fn require(&self, flag: &str) -> Result<&str, String> {
        self.get(flag)
            .ok_or_else(|| format!("missing required --{flag} <value>"))
    }
}

// ---------------------------------------------------------------- keygen

fn keygen(opts: &Options) -> Result<(), String> {
    let out = PathBuf::from(opts.require("out")?);
    let name = opts.get("name").unwrap_or("validator");
    fs::create_dir_all(&out).map_err(|err| format!("create {}: {err}", out.display()))?;

    let mut ikm = [0_u8; 32];
    getrandom::fill(&mut ikm).map_err(|err| format!("system randomness unavailable: {err}"))?;
    let proposer = ProposerKey::from_ikm(&ikm, 0).map_err(|err| err.to_string())?;
    let ikm_path = out.join(format!("{name}.ikm"));
    write_secret(&ikm_path, &hex::encode(ikm))?;

    let account = SecretKey::generate(&mut UnwrapErr(SysRng));
    let account_path = out.join(format!("{name}.ed25519"));
    write_secret(&account_path, &hex::encode(account.to_bytes()))?;
    let address = account.public_key().to_bytes();

    println!("proposer_ikm_path          = {}", ikm_path.display());
    println!("account_key_path           = {}", account_path.display());
    println!();
    println!("# chain-spec.toml entries");
    println!("[[validators]]");
    println!(
        "pubkey_hex = \"{}\"",
        hex::encode(proposer.public_key_bytes())
    );
    println!("withdrawal_credentials_hex = \"{}\"", hex::encode(address));
    println!("effective_stake = <stake>");
    println!();
    println!("[[accounts]]");
    println!("address_hex = \"{}\"", hex::encode(address));
    println!("balance = <balance>");
    Ok(())
}

/// Write `contents` to a new owner-only file, refusing to overwrite.
fn write_secret(path: &Path, contents: &str) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| format!("create {}: {err}", path.display()))?;
    writeln!(file, "{contents}").map_err(|err| format!("write {}: {err}", path.display()))
}

// --------------------------------------------------------------- genesis

fn genesis(opts: &Options) -> Result<(), String> {
    let spec_path = PathBuf::from(opts.require("spec")?);
    let file = ChainSpecFile::load_from_path(&spec_path).map_err(|err| err.to_string())?;
    let state = build_genesis_state(&file).map_err(|err| err.to_string())?;
    let root_hex = hex::encode(state.root);
    let mut pinned = file.clone();
    pinned.genesis_state_root_hex = Some(root_hex.clone());
    let spec = pinned.to_chain_spec().map_err(|err| err.to_string())?;

    println!("genesis_state_root_hex     = \"{root_hex}\"");
    println!(
        "genesis_validator_set_root = {}",
        hex::encode(spec.genesis_validator_set_root)
    );
    println!("chain_spec_hash            = {}", hex::encode(spec.hash()));
    println!(
        "runtime_code_hash          = {}",
        hex::encode(neutrino_runtime_host::default_runtime_code_hash())
    );
    println!("accounts                   = {}", state.accounts);
    println!("staked_validators          = {}", state.staked_validators);
    println!(
        "initial_validators         = {}",
        spec.initial_validators.len()
    );

    if opts.has("write") {
        let raw = fs::read_to_string(&spec_path)
            .map_err(|err| format!("read {}: {err}", spec_path.display()))?;
        let updated = pin_genesis_root(&raw, &root_hex);
        fs::write(&spec_path, updated)
            .map_err(|err| format!("write {}: {err}", spec_path.display()))?;
        println!("pinned genesis_state_root_hex into {}", spec_path.display());
    }
    Ok(())
}

/// Replace or insert the `genesis_state_root_hex` line without disturbing
/// the rest of the document.
fn pin_genesis_root(raw: &str, root_hex: &str) -> String {
    let line = format!("genesis_state_root_hex = \"{root_hex}\"");
    let mut out = Vec::new();
    let mut replaced = false;
    for existing in raw.lines() {
        if existing.trim_start().starts_with("genesis_state_root_hex") {
            out.push(line.clone());
            replaced = true;
        } else {
            out.push(existing.to_owned());
        }
    }
    if !replaced {
        // Keep top-level keys ahead of the first table.
        let at = out
            .iter()
            .position(|l| l.trim_start().starts_with('['))
            .unwrap_or(out.len());
        out.insert(at, line);
    }
    let mut text = out.join("\n");
    text.push('\n');
    text
}

// ----------------------------------------------------------- node-config

fn node_config(opts: &Options) -> Result<(), String> {
    let spec_path = PathBuf::from(opts.require("spec")?);
    let out = PathBuf::from(opts.require("out")?);
    let file = ChainSpecFile::load_from_path(&spec_path).map_err(|err| err.to_string())?;
    let role = opts.get("role").unwrap_or("validator");
    if !matches!(role, "validator" | "full" | "archive" | "light-client") {
        return Err(format!("unknown --role `{role}`"));
    }
    let proving = opts.get("proving").unwrap_or("cpu");
    if !matches!(proving, "cpu" | "cuda") {
        return Err(format!("unknown --proving `{proving}`"));
    }
    let mut text = String::new();
    text.push_str(&format!("chain_id = {}\n", file.chain_id));
    text.push_str(&format!("role = \"{role}\"\n"));
    text.push_str(&format!("chain_spec_path = \"{}\"\n", spec_path.display()));
    if let Some(dir) = opts.get("data-dir") {
        text.push_str(&format!("data_dir = \"{dir}\"\n"));
    }
    let listen = opts.all("listen");
    if !listen.is_empty() {
        text.push_str(&format!("listen = {}\n", toml_string_array(&listen)));
    }
    let bootnodes = opts.all("bootnode");
    if !bootnodes.is_empty() {
        text.push_str(&format!("bootnodes = {}\n", toml_string_array(&bootnodes)));
    }
    if role == "validator" {
        match opts.get("ikm-path") {
            Some(path) => text.push_str(&format!("proposer_ikm_path = \"{path}\"\n")),
            None => text.push_str(&format!(
                "# proposer_ikm_path = \"validator.ikm\"   # or export {}\n",
                neutrino_node::PROPOSER_IKM_ENV
            )),
        }
        let index = opts.get("proposer-index").unwrap_or("0");
        index
            .parse::<u32>()
            .map_err(|_| format!("--proposer-index must be an integer, got `{index}`"))?;
        text.push_str(&format!("proposer_index = {index}\n"));
    }
    text.push_str("\n[proving]\n");
    text.push_str(&format!("backend = \"{proving}\"\n"));
    text.push_str("concurrency = 2\ncapacity = 16\n");
    if let Some(rpc) = opts.get("rpc") {
        text.push_str("\n[rpc]\n");
        text.push_str(&format!("listen = \"{rpc}\"\n"));
        text.push_str("max_connections = 200\nmax_concurrent_requests = 64\n");
        text.push_str("requests_per_second_per_connection = 50\n");
        text.push_str("max_batch_requests = 16\nruntime_call_timeout_ms = 2000\n");
    }
    text.push_str("\n[execution]\n");
    text.push_str("query_fuel = 50000000\nvalidate_tx_fuel = 20000000\n");
    fs::write(&out, &text).map_err(|err| format!("write {}: {err}", out.display()))?;
    println!("wrote {}", out.display());
    Ok(())
}

fn toml_string_array(items: &[&str]) -> String {
    let quoted: Vec<String> = items.iter().map(|item| format!("\"{item}\"")).collect();
    format!("[{}]", quoted.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_parse_flags_values_and_repeats() {
        let args: Vec<String> = ["--out", "dir", "--write", "--listen", "a", "--listen", "b"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let opts = Options::parse(&args).unwrap();
        assert_eq!(opts.get("out"), Some("dir"));
        assert!(opts.has("write"));
        assert_eq!(opts.all("listen"), vec!["a", "b"]);
        assert!(Options::parse(&["stray".to_owned()]).is_err());
    }

    #[test]
    fn pin_genesis_root_replaces_or_inserts_before_first_table() {
        let raw = "name = \"x\"\nchain_id = 1\n[[validators]]\npubkey_hex = \"00\"\n";
        let pinned = pin_genesis_root(raw, "ab");
        assert_eq!(
            pinned,
            "name = \"x\"\nchain_id = 1\ngenesis_state_root_hex = \"ab\"\n[[validators]]\npubkey_hex = \"00\"\n"
        );
        let again = pin_genesis_root(&pinned, "cd");
        assert!(again.contains("genesis_state_root_hex = \"cd\""));
        assert_eq!(again.matches("genesis_state_root_hex").count(), 1);
    }

    #[test]
    fn generated_node_config_parses() {
        let dir = env::temp_dir().join(format!("neutrino-cli-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let spec = dir.join("chain-spec.toml");
        fs::write(
            &spec,
            "name = \"t\"\nchain_id = 9\ngenesis_time = 0\ngenesis_gas_limit = 1\n[[validators]]\npubkey_hex = \"00\"\neffective_stake = 1\n",
        )
        .unwrap();
        let out = dir.join("config.toml");
        let args: Vec<String> = [
            "--spec",
            spec.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--rpc",
            "127.0.0.1:9933",
            "--ikm-path",
            "validator.ikm",
            "--listen",
            "/ip4/0.0.0.0/tcp/30303",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        node_config(&Options::parse(&args).unwrap()).unwrap();
        let cfg: neutrino_node::NodeConfig =
            toml::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(cfg.chain_id, 9);
        assert_eq!(
            cfg.proposer_ikm_path.as_deref(),
            Some(Path::new("validator.ikm"))
        );
        assert!(cfg.rpc.is_some());
        let _ = fs::remove_dir_all(&dir);
    }
}
