//! M2-new end-to-end coverage. All proof tests share a single
//! [`ProverCtx`] so the SP1 preprocessing pass runs once per process.

use std::sync::OnceLock;

use neutrino_default_runtime_core::{COUNTER_KEY, StfInput, StfPublicOutput};
use neutrino_runtime_abi::{StateWitness, WitnessEntry};
use neutrino_runtime_core::{empty_state_root, host::LiveStateMap, state_root_of};
use neutrino_runtime_host::{ProverCtx, Sp1HostError, dry_run};
use sp1_sdk::blocking::{MockProver, ProverClient};

static MOCK_CTX: OnceLock<ProverCtx<MockProver>> = OnceLock::new();

fn mock_ctx() -> &'static ProverCtx<MockProver> {
    MOCK_CTX.get_or_init(|| {
        let prover = ProverClient::builder().mock().build();
        ProverCtx::new_cached(prover).expect("mock setup")
    })
}

fn live_with_counter(value: u32) -> LiveStateMap {
    let mut live = LiveStateMap::default();
    live.insert(COUNTER_KEY.to_vec(), value.to_le_bytes().to_vec());
    live
}

/// Exit criteria 1, 2: same STF compiles to WASM and SP1 Guest, and a
/// block-level test exercises dry-run → witness → prove → verify.
#[test]
fn full_pipeline_dry_run_prove_verify_mock() {
    let ctx = mock_ctx();
    let live = live_with_counter(10);

    let dry = dry_run(StfInput { delta: 5 }, &live);
    assert_eq!(dry.output.counter, 15);

    let proof = ctx
        .prove(StfInput { delta: 5 }, dry.witness.clone())
        .unwrap();
    ctx.verify(&proof.proof, &dry.output)
        .expect("verify accepts proof");
}

/// Exit criterion 5: a tampered `post_state_root` makes verification
/// fail. The proof remains cryptographically valid; the host catches
/// the mismatch when comparing the committed output to the expected.
#[test]
fn tampered_post_state_root_is_rejected() {
    let ctx = mock_ctx();
    let live = live_with_counter(2);

    let dry = dry_run(StfInput { delta: 3 }, &live);
    let proof = ctx
        .prove(StfInput { delta: 3 }, dry.witness.clone())
        .unwrap();

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

/// Exit criterion 3: a witness missing the key the STF needs causes
/// the guest to panic on the unwitnessed read. We assert this via the
/// executor's exit code so the test stays fast under `MockProver`
/// (whose `verify` ignores status codes for compressed proofs); the
/// real CPU prover would catch the same condition via
/// `StatusCode::SUCCESS`.
#[test]
fn missing_witness_entry_makes_guest_abort() {
    let ctx = mock_ctx();

    let witness = StateWitness {
        pre_state_root: empty_state_root(),
        entries: vec![],
    };

    let (_pv, report) = ctx
        .execute(StfInput { delta: 1 }, &witness)
        .expect("executor runs");
    assert_ne!(
        report.exit_code, 0,
        "guest must abort with non-zero exit when an unwitnessed key is read"
    );
}

/// Exit criterion 4: a tampered witness (wrong pre-counter value with a
/// stale `pre_state_root`) makes the guest's `WitnessState::new` reject
/// the witness, panic, and exit non-zero.
#[test]
fn tampered_witness_value_makes_guest_abort() {
    let ctx = mock_ctx();

    let pre = state_root_of([(COUNTER_KEY, 2u32.to_le_bytes().as_slice())]);
    let witness = StateWitness {
        pre_state_root: pre,
        entries: vec![WitnessEntry {
            key: COUNTER_KEY.to_vec(),
            value: Some(99u32.to_le_bytes().to_vec()),
        }],
    };

    let (_pv, report) = ctx
        .execute(StfInput { delta: 1 }, &witness)
        .expect("executor runs");
    assert_ne!(
        report.exit_code, 0,
        "guest must abort when the witness contradicts pre_state_root"
    );
}

/// Sanity: the master crate's native rlib `apply_block_with_witness`
/// produces the same public output as the dry-run path. No SP1 work.
#[test]
fn master_apply_block_with_witness_matches_dry_run() {
    let live = live_with_counter(7);
    let dry = dry_run(StfInput { delta: 4 }, &live);

    let bytes = borsh::to_vec(&(StfInput { delta: 4 }, dry.witness.clone())).unwrap();
    let out_bytes = neutrino_default_runtime_master::apply_block_with_witness(&bytes);
    let out: StfPublicOutput = borsh::from_slice(&out_bytes).unwrap();

    assert_eq!(out, dry.output);
}

/// Opt-in real Compressed STARK pipeline — `cargo test -- --ignored`.
#[test]
#[ignore = "runs real Compressed STARK proving on the CPU (multi-minute)"]
fn cpu_prover_full_pipeline() {
    let prover = ProverClient::builder().cpu().build();
    let ctx = ProverCtx::new_cached(prover).unwrap();
    let live = live_with_counter(10);

    let dry = dry_run(StfInput { delta: 5 }, &live);
    let proof = ctx
        .prove(StfInput { delta: 5 }, dry.witness.clone())
        .unwrap();
    ctx.verify(&proof.proof, &dry.output).unwrap();
}
