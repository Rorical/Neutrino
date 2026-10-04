//! [`BlockExecutor`] backed by the WASM dynamic runtime.
//!
//! Drives the embedded default-runtime master cdylib through
//! wasmtime, mutates the engine's state trie in place with the
//! block's writes, and emits a persisted [`BlockWitness`] for proving.
//!
//! Exact `EvidenceProof` receipts are verified before WASM mutation. The emitted
//! witness bundle is replayed by the matching SP1 block Guest.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::Body;
use neutrino_default_runtime_core::{StfInput, Transaction};
use neutrino_proof_system::executor::{BlockExecutionContext, BlockExecutor, ExecutionOutcome};
use neutrino_runtime_abi::{QueryRequest, QueryResponse, TxValidity};
use neutrino_runtime_core::host::LiveTrie;
use neutrino_trie::{Poseidon2Hasher, Trie};
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

    /// Build with the embedded default-runtime master cdylib and explicit
    /// per-call fuel and memory budgets.
    ///
    /// # Errors
    /// Surfaces [`WasmError`] if wasmtime fails to compile the embedded
    /// module or `limits` are invalid.
    pub fn default_runtime_with_limits(limits: crate::wasm::WasmLimits) -> Result<Self, WasmError> {
        Ok(Self::new(
            WasmRuntime::default_runtime()?.with_limits(limits)?,
        ))
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
        state: &mut Trie<Poseidon2Hasher>,
    ) -> Result<ExecutionOutcome, ExecutorError> {
        // Decode body.transactions into typed STF transactions.
        //
        // Q2 binding: the SP1 Guest commits `transactions_root` over
        // the borsh-encoded forms of `input.transactions`.  This
        // matches `header.transactions_root` (= Merkle over
        // `body.transactions` raw blobs) *only* if every blob in the
        // body decodes successfully AND the decoded `Transaction`
        // re-encodes to the original bytes.  Borsh is canonical, so
        // the second clause holds for any well-formed blob.  We
        // therefore fail-fast on the first clause: a single malformed
        // entry rejects the whole block, because silently dropping
        // would let a malicious proposer publish a header with a
        // `transactions_root` that the SP1 proof cannot reproduce.
        //
        // Honest producers always populate `body.transactions` from
        // a mempool whose admission already ran `validate_tx`, so
        // every blob is borsh-decodable in practice.  The fail-fast
        // path only triggers under adversarial conditions where a
        // peer gossiped a body with crafted garbage.
        let mut txs = Vec::with_capacity(body.transactions.len());
        for (idx, raw) in body.transactions.iter().enumerate() {
            let tx = <Transaction as BorshDeserialize>::try_from_slice(raw.as_slice()).map_err(
                |err| {
                    ExecutorError::Codec(format!(
                        "body.transactions[{idx}] failed to decode as Transaction: {err}",
                    ))
                },
            )?;
            txs.push(tx);
        }
        let input = StfInput {
            evidence_anchor: ctx.evidence_anchor,
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
        } = self.wasm.dry_run(&input, &live, &body.evidence_proofs)?;

        // Commit the dry-run's post-state into the engine's trie.
        // Read-only blocks fall back to a clone of `live`, so the
        // swap is unconditional and idempotent.
        // Persist attachments beside the semantic input and state witness.
        // The prover sends them through SP1's separate recursive proof stream.
        let witness_bytes = encode_witness_bundle(&input, &witness, &body.evidence_proofs)
            .map_err(|err| ExecutorError::Codec(err.to_string()))?;
        *state = post_state;

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
        state: &Trie<Poseidon2Hasher>,
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
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, ExecutorError> {
        let live = LiveTrie::from_trie(state.clone());
        Ok(self
            .wasm
            .validate_tx(tx_bytes, chain_id, block_gas_limit, gas_price, &live)?)
    }
}

/// Encode the persisted [`BlockWitness`], including ordered proof attachments.
///
/// The Guest receives only the input and state fields as normal stdin.
///
/// # Errors
/// Returns a codec error when the input, witness or attachments cannot be encoded.
pub fn encode_witness_bundle(
    input: &StfInput,
    witness: &neutrino_runtime_abi::StateWitness,
    evidence_proofs: &[neutrino_consensus_types::evidence::EvidenceArtifact],
) -> Result<Vec<u8>, borsh::io::Error> {
    let mut bytes = Vec::new();
    BorshSerialize::serialize(input, &mut bytes)?;
    BorshSerialize::serialize(witness, &mut bytes)?;
    BorshSerialize::serialize(evidence_proofs, &mut bytes)?;
    Ok(bytes)
}

/// Decode the complete persisted [`BlockWitness`] without trailing bytes.
///
/// Inverse of [`encode_witness_bundle`]; called by
/// [`crate::Sp1ProofSystem::prove_block`] before forwarding to the
/// SP1 prover.
///
/// # Errors
/// Returns [`borsh::io::Error`] if the blob is not a valid encoding
/// of the complete witness bundle.
pub fn decode_witness_bundle(bytes: &[u8]) -> Result<BlockWitness, borsh::io::Error> {
    borsh::from_slice(bytes)
}

/// Persisted proving input, including proof attachments outside STF semantics.
#[derive(BorshDeserialize, BorshSerialize)]
pub struct BlockWitness {
    /// Consensus transaction and execution context.
    pub input: StfInput,
    /// Authenticated state openings.
    pub state: neutrino_runtime_abi::StateWitness,
    /// Ordered proof witnesses for the evidence statements.
    pub evidence_proofs: Vec<neutrino_consensus_types::evidence::EvidenceArtifact>,
}
