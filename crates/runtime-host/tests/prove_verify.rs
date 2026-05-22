//! M2-new / M3-new / M4-A coverage. All proof tests share a single
//! [`ProverCtx`] so the SP1 preprocessing pass runs once per process.

use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey};
use neutrino_default_runtime_core::{
    Account, Address, StfInput, StfPublicOutput, Transaction, TransferTx, account_key,
    encode_account, transfer_sig_message,
};
use neutrino_runtime_abi::{StateWitness, TrieNodeBytes};
use neutrino_runtime_core::{empty_state_root, host::LiveTrie};
use neutrino_runtime_host::{ProverCtx, Sp1HostError, dry_run};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sp1_sdk::blocking::{MockProver, ProverClient};

const CHAIN_ID: u64 = 42;

static MOCK_CTX: OnceLock<ProverCtx<MockProver>> = OnceLock::new();

fn mock_ctx() -> &'static ProverCtx<MockProver> {
    MOCK_CTX.get_or_init(|| {
        let prover = ProverClient::builder().mock().build();
        ProverCtx::new_cached(prover).expect("mock setup")
    })
}

fn signing_key(seed: u64) -> SigningKey {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    SigningKey::generate(&mut rng)
}

fn address_of(sk: &SigningKey) -> Address {
    sk.verifying_key().to_bytes()
}

fn signed_transfer(
    sk: &SigningKey,
    to: Address,
    amount: u128,
    nonce: u64,
    chain_id: u64,
) -> TransferTx {
    let mut tx = TransferTx {
        from: address_of(sk),
        to,
        amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = sk.sign(&transfer_sig_message(chain_id, &tx)).to_bytes();
    tx
}

fn live_with_account(addr: Address, account: Account) -> LiveTrie {
    let mut live = LiveTrie::default();
    live.insert(&account_key(&addr), encode_account(&account));
    live
}

fn input_with_transfers(txs: Vec<TransferTx>) -> StfInput {
    StfInput {
        chain_id: CHAIN_ID,
        block_gas_limit: 30_000_000,
        transactions: txs.into_iter().map(Transaction::Transfer).collect(),
    }
}

/// M2-new exit criteria 1, 2 + M4-A transfer flow: dry-run a block
/// containing one signed transfer, prove it via SP1, verify the
/// committed `StfPublicOutput`.
#[test]
fn full_pipeline_signed_transfer_mock() {
    let ctx = mock_ctx();
    let alice = signing_key(101);
    let alice_addr = address_of(&alice);
    let bob_addr = [0xBB_u8; 32];
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );

    let tx = signed_transfer(&alice, bob_addr, 30, 0, CHAIN_ID);
    let input = input_with_transfers(vec![tx]);

    let dry = dry_run(&input, &live);
    assert_eq!(dry.output.applied, 1);
    assert_eq!(dry.output.failed, 0);

    let proof = ctx.prove(&input, dry.witness.clone()).unwrap();
    ctx.verify(&proof.proof, &dry.output)
        .expect("verify accepts proof");
}

/// M2-new exit criterion 5: tampered `post_state_root` is rejected by
/// the host-side public-output check.
#[test]
fn tampered_post_state_root_is_rejected() {
    let ctx = mock_ctx();
    let live = LiveTrie::default();
    let input = input_with_transfers(vec![]);
    let dry = dry_run(&input, &live);
    let proof = ctx.prove(&input, dry.witness.clone()).unwrap();

    let mut tampered = dry.output;
    tampered.post_state_root[0] ^= 0xFF;

    let err = ctx
        .verify(&proof.proof, &tampered)
        .expect_err("verify must reject tampered post_state_root");
    match err {
        Sp1HostError::PublicOutputMismatch { expected, actual } => {
            assert_eq!(expected.post_state_root, tampered.post_state_root);
            assert_eq!(actual.post_state_root, dry.output.post_state_root);
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

/// M2-new exit criterion 3 + M4-B Merkle witness: a witness whose
/// `witnessed_keys` set excludes a key the STF reads causes the guest
/// to panic on the unwitnessed read.
#[test]
fn missing_witness_entry_makes_guest_abort() {
    let ctx = mock_ctx();
    let alice = signing_key(202);

    // Empty live state + empty witness. The STF will try to read
    // alice's account, which is not in `witnessed_keys` → panic.
    let witness = StateWitness {
        pre_state_root: empty_state_root(),
        nodes: vec![],
        values: vec![],
        witnessed_keys: vec![],
    };
    let tx = signed_transfer(&alice, [0xCC; 32], 1, 0, CHAIN_ID);
    let input = input_with_transfers(vec![tx]);
    let (_pv, report) = ctx.execute(&input, &witness).expect("executor runs");
    assert_ne!(
        report.exit_code, 0,
        "guest must abort with non-zero exit when an unwitnessed account is read"
    );
}

/// M2-new exit criterion 4 + M4-B Merkle witness: a witness whose
/// `pre_state_root` cannot be reconstructed from the supplied trie
/// nodes makes the guest's `WitnessState::new` reject and abort.
#[test]
fn tampered_witness_value_makes_guest_abort() {
    let ctx = mock_ctx();

    // Claim a non-empty pre_state_root but supply node bytes that
    // hash to a *different* root. The host's verification
    // (`Blake3Hasher::hash_node(bytes) == hash`) passes for each
    // supplied node, but the *root* the witness claims is not among
    // them, so `WitnessState::new` returns `PreRootMissing`.
    let bogus_bytes = b"definitely-not-a-canonical-trie-node".to_vec();
    let bogus_hash =
        <neutrino_trie::Blake3Hasher as neutrino_trie::Hasher>::hash_node(&bogus_bytes);
    let witness = StateWitness {
        pre_state_root: [0xAA; 32],
        nodes: vec![TrieNodeBytes {
            hash: bogus_hash,
            bytes: bogus_bytes,
        }],
        values: vec![],
        witnessed_keys: vec![],
    };
    let input = input_with_transfers(vec![]);
    let (_pv, report) = ctx.execute(&input, &witness).expect("executor runs");
    assert_ne!(
        report.exit_code, 0,
        "guest must abort when the witness contradicts pre_state_root"
    );
}

/// Sanity: the master crate's native rlib `apply_block_with_witness`
/// produces the same public output as the dry-run path. No SP1 work.
#[test]
fn master_apply_block_with_witness_matches_dry_run() {
    let alice = signing_key(404);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 50,
        },
    );

    let tx = signed_transfer(&alice, [0xDD; 32], 7, 0, CHAIN_ID);
    let input = input_with_transfers(vec![tx]);
    let dry = dry_run(&input, &live);
    let bytes = borsh::to_vec(&(input, dry.witness.clone())).unwrap();
    let out_bytes = neutrino_default_runtime_master::apply_block_with_witness(&bytes);
    let out: StfPublicOutput = borsh::from_slice(&out_bytes).unwrap();

    assert_eq!(out, dry.output);
}

/// Opt-in real Compressed STARK pipeline. The prover is selected
/// by `SP1_PROVER` (`cpu`, `network`, …); run with `--ignored`.
#[test]
#[ignore = "runs real Compressed STARK proving (multi-minute on CPU)"]
fn real_prover_full_pipeline() {
    // `EnvProver::ProvingKey` is `EnvProvingKey`, not `SP1ProvingKey`,
    // so the on-disk vk cache (`new_cached_for`) does not apply — see
    // `runtime_host::ProverCtx` impl bounds. Pay the preprocessing
    // cost on every invocation; this is an opt-in demo path.
    let prover = ProverClient::from_env();
    let ctx = ProverCtx::new(prover).unwrap();

    let alice = signing_key(999);
    let alice_addr = address_of(&alice);
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );

    let tx = signed_transfer(&alice, [0xEE; 32], 25, 0, CHAIN_ID);
    let input = input_with_transfers(vec![tx]);
    let dry = dry_run(&input, &live);
    let proof = ctx.prove(&input, dry.witness.clone()).unwrap();
    ctx.verify(&proof.proof, &dry.output).unwrap();
}

/// Opt-in demonstration: print every artifact of one full block
/// transition under the real env-driven Compressed STARK prover.
///
/// Run with:
/// `SP1_PROVER=cpu cargo test -p neutrino-runtime-host --test prove_verify \
///    real_prover_demonstration -- --ignored --nocapture --test-threads=1`
///
/// Set `SP1_PROVER=network` (with a Succinct prover key configured)
/// to offload generation to the prover network instead of the local
/// CPU. `SP1_PROVER=mock` short-circuits proving for sanity checks.
///
/// Saves the bincode-encoded `SP1ProofWithPublicValues` to
/// `/tmp/opencode/neutrino_block_proof.bin` so the wire artifact
/// can be inspected directly.
#[test]
#[ignore = "runs real Compressed STARK proving (multi-minute on CPU)"]
#[allow(clippy::too_many_lines)] // demonstration test, intentionally linear
fn real_prover_demonstration() {
    use std::fmt::Write as _;
    use std::time::Instant;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            // `write!` to a `String` is infallible (only Err on alloc
            // OOM, which would have panicked at `with_capacity` or
            // earlier). Avoids the extra `format!` allocation flagged
            // by `clippy::format_push_string`.
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    println!();
    println!("=== Neutrino block proof demonstration ============================");
    println!("    real Compressed STARK prover (env-selected), one signed Transfer");
    println!();

    // -------------------------------------------------------------
    // 1. Pre-state
    // -------------------------------------------------------------
    let alice = signing_key(777);
    let alice_addr = address_of(&alice);
    let bob_addr = [0xBB_u8; 32];
    let live = live_with_account(
        alice_addr,
        Account {
            nonce: 0,
            balance: 100,
        },
    );

    println!("[1] Pre-state");
    println!("    alice address     0x{}", hex(&alice_addr));
    println!("    alice balance     100");
    println!("    alice nonce       0");
    println!("    bob address       0x{}", hex(&bob_addr));
    println!("    pre_state_root    0x{}", hex(&live.state_root()));
    println!();

    // -------------------------------------------------------------
    // 2. Block (single Transfer)
    // -------------------------------------------------------------
    let tx = signed_transfer(&alice, bob_addr, 30, 0, CHAIN_ID);
    let signature_first_16 = &tx.signature[..16];
    println!("[2] Block body");
    println!("    chain_id          {CHAIN_ID}");
    println!("    tx[0] = Transfer");
    println!("       from           0x{}", hex(&tx.from));
    println!("       to             0x{}", hex(&tx.to));
    println!("       amount         {}", tx.amount);
    println!("       nonce          {}", tx.nonce);
    println!("       signature[..16] 0x{}", hex(signature_first_16));
    println!();

    let input = input_with_transfers(vec![tx]);

    // -------------------------------------------------------------
    // 3. Host dry-run (no SP1) -> StateWitness
    // -------------------------------------------------------------
    println!("[3] Host dry-run (TracingState, no SP1)");
    let started = Instant::now();
    let dry = dry_run(&input, &live);
    let elapsed = started.elapsed();
    println!("    elapsed                 {elapsed:.2?}");
    println!("    applied                 {}", dry.output.applied);
    println!("    failed                  {}", dry.output.failed);
    println!(
        "    pre_state_root          0x{}",
        hex(&dry.output.pre_state_root)
    );
    println!(
        "    post_state_root         0x{}",
        hex(&dry.output.post_state_root)
    );
    println!(
        "    validator_set_root      0x{}",
        hex(&dry.output.validator_set_root)
    );
    println!(
        "    witness pre_state_root  0x{}",
        hex(&dry.witness.pre_state_root)
    );
    println!("    witness nodes           {}", dry.witness.nodes.len());
    println!("    witness values          {}", dry.witness.values.len());
    println!(
        "    witness witnessed_keys  {} key(s):",
        dry.witness.witnessed_keys.len()
    );
    for key in &dry.witness.witnessed_keys {
        println!("       0x{}", hex(key));
    }
    println!();

    // -------------------------------------------------------------
    // 4. SP1 prover setup (one-time preprocessing of guest ELF)
    // -------------------------------------------------------------
    println!("[4] SP1 prover setup (program ROM preprocessing)");
    let started = Instant::now();
    // See `real_prover_full_pipeline` for why this is `new`, not
    // `new_cached`: `EnvProver` uses `EnvProvingKey`.
    let prover = ProverClient::from_env();
    let ctx = ProverCtx::new(prover).unwrap();
    let elapsed = started.elapsed();
    println!("    elapsed                 {elapsed:.2?}");
    println!(
        "    vk fingerprint (bn254)  {}",
        neutrino_runtime_host::vk_fingerprint(&ctx.vk)
    );
    println!(
        "    sp1 circuit version     {}",
        sp1_sdk::SP1_CIRCUIT_VERSION
    );
    println!();

    // -------------------------------------------------------------
    // 5. Compressed STARK proof generation
    // -------------------------------------------------------------
    println!("[5] SP1 Compressed STARK proof generation (env-selected backend)");
    let started = Instant::now();
    let proof_bundle = ctx.prove(&input, dry.witness.clone()).unwrap();
    let elapsed = started.elapsed();
    println!("    elapsed                 {elapsed:.2?}");

    let wire_bytes = bincode::serialize(&proof_bundle.proof).expect("bincode encode proof");
    // `wire_bytes.len()` is the size of a Compressed STARK proof —
    // single-digit MiB in practice, well within f64's 2^52 mantissa.
    // The `as f64` cast can lose precision past 2^52, which can't
    // happen here, hence the explicit allow.
    #[allow(clippy::cast_precision_loss)]
    let kib = wire_bytes.len() as f64 / 1024.0;
    println!(
        "    wire size (bincode)     {} bytes ({kib:.1} KiB)",
        wire_bytes.len()
    );
    println!("    first 32 bytes          0x{}", hex(&wire_bytes[..32]));
    let tail_start = wire_bytes.len().saturating_sub(32);
    println!(
        "    last 32 bytes           0x{}",
        hex(&wire_bytes[tail_start..])
    );

    let pv = proof_bundle.proof.public_values.as_slice();
    println!("    public values           {} bytes", pv.len());
    println!("    public values hex       0x{}", hex(pv));
    let decoded: StfPublicOutput = borsh::from_slice(pv).expect("decode StfPublicOutput");
    println!(
        "       decoded pre          0x{}",
        hex(&decoded.pre_state_root)
    );
    println!(
        "       decoded post         0x{}",
        hex(&decoded.post_state_root)
    );
    println!("       decoded applied      {}", decoded.applied);
    println!("       decoded failed       {}", decoded.failed);
    println!(
        "       decoded vs_root      0x{}",
        hex(&decoded.validator_set_root)
    );

    let out_dir = std::path::Path::new("/tmp/opencode");
    std::fs::create_dir_all(out_dir).expect("ensure /tmp/opencode");
    let out_path = out_dir.join("neutrino_block_proof.bin");
    std::fs::write(&out_path, &wire_bytes).expect("write proof bytes");
    println!("    saved to                {}", out_path.display());
    println!();

    // -------------------------------------------------------------
    // 6. Verify the proof
    // -------------------------------------------------------------
    println!("[6] SP1 verifier");
    let started = Instant::now();
    ctx.verify(&proof_bundle.proof, &dry.output).unwrap();
    let elapsed = started.elapsed();
    println!("    elapsed                 {elapsed:.2?}");
    println!("    result                  ACCEPTED");
    println!();

    // -------------------------------------------------------------
    // 7. Tampered-output sanity check: same proof, different
    //    expected `StfPublicOutput` → verifier rejects.
    // -------------------------------------------------------------
    println!("[7] Tampered-output negative check");
    let mut tampered = dry.output;
    tampered.post_state_root[0] ^= 0xFF;
    let err = ctx
        .verify(&proof_bundle.proof, &tampered)
        .expect_err("verifier must reject tampered post_state_root");
    println!("    flipped post[0] bit     ");
    println!("    verifier returned       {err}");
    println!();
    println!("=== Done ============================================================");
}
