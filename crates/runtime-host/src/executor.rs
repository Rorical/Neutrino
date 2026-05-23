//! [`BlockExecutor`] backed by the WASM dynamic runtime.
//!
//! Drives the embedded default-runtime master cdylib through
//! wasmtime, mutates the engine's state trie in place with the
//! block's writes, and emits the borsh-encoded `(StfInput,
//! StateWitness)` blob the configured proof system later replays.
//!
//! The executor is purely the dynamic-execution seam — it knows
//! nothing about SP1. The witness blob it emits happens to match
//! the layout the default-runtime guest reads from `SP1Stdin`, but
//! that's a property of the runtime ABI, not the executor. The
//! matching [`crate::Sp1ProofSystem::prove_block`] decodes the same
//! blob on its way into the SP1 prover.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::Body;
use neutrino_default_runtime_core::{StfInput, Transaction};
use neutrino_proof_system::executor::{BlockExecutionContext, BlockExecutor, ExecutionOutcome};
use neutrino_runtime_abi::{QueryRequest, QueryResponse, TxValidity};
use neutrino_runtime_core::host::LiveTrie;
use neutrino_trie::{Blake3Hasher, Trie};
use thiserror::Error;

use crate::DryRun;
use crate::wasm::{WasmError, WasmRuntime};

/// Errors produced by [`WasmExecutor::execute_block`].
#[derive(Debug, Error)]
pub enum ExecutorError {
    /// Wasmtime / WASM runtime failure during dry-run.
    #[error("WASM dry-run failed: {0}")]
    Wasm(String),
    /// Borsh failure encoding the prover stdin payload.
    #[error("borsh codec error: {0}")]
    Codec(String),
}

impl From<WasmError> for ExecutorError {
    fn from(err: WasmError) -> Self {
        Self::Wasm(err.to_string())
    }
}

/// Production block executor: WASM dynamic runtime + witness emission.
///
/// One per process; the embedded master cdylib is compiled in by
/// `runtime-host/build.rs` and shared across slots. `execute_block`
/// creates a fresh wasmtime `Store` per call so concurrent execution
/// on different threads is safe.
pub struct WasmExecutor {
    wasm: WasmRuntime,
}

impl WasmExecutor {
    /// Wrap an explicit [`WasmRuntime`]. Use [`Self::default_runtime`]
    /// for the embedded default-runtime cdylib.
    #[must_use]
    pub const fn new(wasm: WasmRuntime) -> Self {
        Self { wasm }
    }

    /// Build with the embedded default-runtime master cdylib.
    ///
    /// # Errors
    /// Surfaces [`WasmError`] if wasmtime fails to compile the
    /// embedded module.
    pub fn default_runtime() -> Result<Self, WasmError> {
        Ok(Self::new(WasmRuntime::default_runtime()?))
    }

    /// Borrow the underlying [`WasmRuntime`] (mostly for tests).
    #[must_use]
    pub const fn wasm(&self) -> &WasmRuntime {
        &self.wasm
    }
}

impl BlockExecutor for WasmExecutor {
    type Error = ExecutorError;

    fn execute_block(
        &self,
        ctx: &BlockExecutionContext,
        body: &Body,
        state: &mut Trie<Blake3Hasher>,
    ) -> Result<ExecutionOutcome, ExecutorError> {
        // Decode body.transactions into typed STF transactions.
        // Malformed entries are silently dropped here; the STF would
        // otherwise count them as `failed`, but a borsh-decode
        // failure means the runtime ABI doesn't even recognise the
        // byte string as a transaction so we exclude it from
        // `StfInput.transactions` entirely.
        let mut txs = Vec::with_capacity(body.transactions.len());
        for raw in &body.transactions {
            if let Ok(tx) = <Transaction as BorshDeserialize>::try_from_slice(raw.as_slice()) {
                txs.push(tx);
            }
        }
        let input = StfInput {
            chain_id: ctx.chain_id,
            block_height: ctx.block_height,
            block_gas_limit: ctx.gas_limit,
            gas_price: ctx.gas_price,
            proposer_address: ctx.proposer_address,
            transactions: txs,
        };

        // Snapshot the engine's authoritative trie into a read-only
        // LiveTrie view for dry-run. The TracingState used inside
        // the wasm runtime clones the live trie on first write, so
        // the snapshot itself stays untouched.
        let live = LiveTrie::from_trie(state.clone());

        let DryRun {
            output,
            witness,
            post_state,
        } = self.wasm.dry_run(&input, &live)?;

        // Commit the dry-run's post-state into the engine's trie.
        // Read-only blocks fall back to a clone of `live`, so the
        // swap is unconditional and idempotent.
        *state = post_state;

        // Encode the SP1 stdin payload exactly the way
        // `ProverCtx::prove` does: `borsh(input) || borsh(witness)`.
        // The wire format is owned by this executor; the matching
        // `Sp1ProofSystem::prove_block` decodes it.
        let witness_bytes = encode_witness_bundle(&input, &witness)
            .map_err(|err| ExecutorError::Codec(err.to_string()))?;

        Ok(ExecutionOutcome {
            state_root_after: output.post_state_root,
            runtime_extra: output.validator_set_root,
            receipts_root: output.receipts_root,
            gas_used: output.gas_used,
            witness_bytes,
        })
    }

    fn query(
        &self,
        request: &QueryRequest,
        state: &Trie<Blake3Hasher>,
    ) -> Result<QueryResponse, ExecutorError> {
        // Snapshot the trie into a read-only LiveTrie view. The
        // WasmRuntime's query path clones the scratch trie internally
        // and discards it after the call so no mutation can leak
        // back into `state`.
        let live = LiveTrie::from_trie(state.clone());
        Ok(self.wasm.query(request, &live)?)
    }

    fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        gas_price: u128,
        state: &Trie<Blake3Hasher>,
    ) -> Result<TxValidity, ExecutorError> {
        let live = LiveTrie::from_trie(state.clone());
        Ok(self
            .wasm
            .validate_tx(tx_bytes, chain_id, block_gas_limit, gas_price, &live)?)
    }
}

/// Wire format the SP1 Guest reads from `SP1Stdin`:
/// `borsh(StfInput) || borsh(StateWitness)`.
///
/// Kept symmetric to `runtime_host::encode_stdin` so the prover and
/// the executor agree on the exact byte layout the guest expects.
fn encode_witness_bundle(
    input: &StfInput,
    witness: &neutrino_runtime_abi::StateWitness,
) -> Result<Vec<u8>, borsh::io::Error> {
    let mut bytes = Vec::new();
    BorshSerialize::serialize(input, &mut bytes)?;
    BorshSerialize::serialize(witness, &mut bytes)?;
    Ok(bytes)
}

/// Decode a witness blob into its constituent `(StfInput, StateWitness)`.
///
/// Inverse of [`encode_witness_bundle`]; called by
/// [`crate::Sp1ProofSystem::prove_block`] before forwarding to the
/// SP1 prover.
///
/// # Errors
/// Returns [`borsh::io::Error`] if the blob is not a valid encoding
/// of the pair.
pub fn decode_witness_bundle(
    bytes: &[u8],
) -> Result<(StfInput, neutrino_runtime_abi::StateWitness), borsh::io::Error> {
    let mut cursor = bytes;
    let input = <StfInput as BorshDeserialize>::deserialize_reader(&mut cursor)?;
    let witness =
        <neutrino_runtime_abi::StateWitness as BorshDeserialize>::deserialize_reader(&mut cursor)?;
    Ok((input, witness))
}
