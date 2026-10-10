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
use neutrino_trie::{Poseidon2Hasher, Trie};
use thiserror::Error;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use neutrino_primitives::Hash;

use crate::DryRun;
use crate::wasm::{WasmError, WasmLimits, WasmRuntime};

/// Errors produced by [`WasmExecutor::execute_block`].
#[derive(Debug, Error)]
pub enum ExecutorError {
    /// Wasmtime / WASM runtime failure during dry-run.
    #[error("WASM dry-run failed: {0}")]
    Wasm(String),
    /// Borsh failure encoding the prover stdin payload.
    #[error("borsh codec error: {0}")]
    Codec(String),
    /// The block names a runtime artifact this executor has not installed.
    #[error("runtime {} is not installed", hex_hash(.0))]
    UnknownRuntime(Hash),
    /// The chain specification declares a genesis runtime other than the
    /// embedded module, and this executor does not permit aliasing.
    #[error("chain declares runtime {} but the embedded runtime is {}", hex_hash(.declared), hex_hash(.embedded))]
    RuntimeHashMismatch {
        /// Hash the chain specification names.
        declared: Hash,
        /// Hash of the embedded module.
        embedded: Hash,
    },
}

/// Lowercase-hex rendering of a 32-byte hash for error messages.
const fn hex_hash(hash: &Hash) -> blake3::Hash {
    blake3::Hash::from_bytes(*hash)
}

impl From<WasmError> for ExecutorError {
    fn from(err: WasmError) -> Self {
        Self::Wasm(err.to_string())
    }
}

/// Production block executor: WASM dynamic runtimes + witness emission.
///
/// Holds one compiled [`WasmRuntime`] per runtime code hash. The embedded
/// default-runtime master cdylib is installed at construction; upgrade
/// runtimes distributed on chain are installed later with
/// [`Self::install_runtime`] (design 24). Each call picks the runtime the
/// engine names for the block, so a program switch at a chunk boundary
/// needs no new process. `execute_block` creates a fresh wasmtime `Store`
/// per call so concurrent execution on different threads is safe.
pub struct WasmExecutor {
    runtimes: RwLock<HashMap<Hash, Arc<WasmRuntime>>>,
    /// Code hash the constructor installed the embedded module under.
    default_hash: Hash,
    /// Whether the embedded module may serve a different declared hash.
    /// Only the harness constructor sets this.
    allow_alias: bool,
    limits: WasmLimits,
}

impl WasmExecutor {
    /// Wrap an explicit [`WasmRuntime`] under its code hash. Use
    /// [`Self::default_runtime`] for the embedded default-runtime cdylib.
    #[must_use]
    pub fn new(code_hash: Hash, wasm: WasmRuntime) -> Self {
        let limits = wasm.limits();
        Self {
            runtimes: RwLock::new(HashMap::from([(code_hash, Arc::new(wasm))])),
            default_hash: code_hash,
            allow_alias: false,
            limits,
        }
    }

    /// Harness constructor: the embedded default-runtime master cdylib with
    /// default limits, permitted to serve whatever genesis runtime hash the
    /// chain specification declares. Production nodes use
    /// [`Self::default_runtime_with_limits`], which refuses any alias.
    ///
    /// # Errors
    /// Surfaces [`WasmError`] if wasmtime fails to compile the
    /// embedded module.
    pub fn default_runtime() -> Result<Self, WasmError> {
        let mut executor = Self::new(
            crate::default_runtime_code_hash(),
            WasmRuntime::default_runtime()?,
        );
        executor.allow_alias = true;
        Ok(executor)
    }

    /// Build with the embedded default-runtime master cdylib and explicit
    /// per-call fuel and memory budgets.
    ///
    /// # Errors
    /// Surfaces [`WasmError`] if wasmtime fails to compile the embedded
    /// module or `limits` are invalid.
    pub fn default_runtime_with_limits(limits: WasmLimits) -> Result<Self, WasmError> {
        Ok(Self::new(
            crate::default_runtime_code_hash(),
            WasmRuntime::default_runtime()?.with_limits(limits)?,
        ))
    }

    /// Compile and install a runtime artifact under its BLAKE3 code hash,
    /// with this executor's limits. Idempotent for an already installed hash.
    ///
    /// # Errors
    /// Surfaces [`WasmError`] when the bytes are not a loadable runtime.
    pub fn install_runtime(&self, wasm: &[u8]) -> Result<Hash, WasmError> {
        let code_hash = neutrino_primitives::blake3_256(wasm);
        if self.has_runtime(&code_hash) {
            return Ok(code_hash);
        }
        let runtime = WasmRuntime::new(wasm)?.with_limits(self.limits)?;
        self.runtimes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(code_hash)
            .or_insert_with(|| Arc::new(runtime));
        Ok(code_hash)
    }

    /// Serve `code_hash` with the module installed by the constructor. An
    /// identity alias always succeeds; a different hash is accepted only by
    /// the harness constructor. See [`BlockExecutor::alias_default_runtime`].
    ///
    /// # Errors
    /// Returns [`ExecutorError::RuntimeHashMismatch`] when the chain declares
    /// another runtime and aliasing is not permitted.
    pub fn alias_default_runtime(&self, code_hash: Hash) -> Result<(), ExecutorError> {
        if code_hash == self.default_hash {
            return Ok(());
        }
        if !self.allow_alias {
            return Err(ExecutorError::RuntimeHashMismatch {
                declared: code_hash,
                embedded: self.default_hash,
            });
        }
        let default = self
            .runtimes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&self.default_hash)
            .cloned();
        if let Some(default) = default {
            self.runtimes
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(code_hash)
                .or_insert(default);
        }
        Ok(())
    }

    /// `true` when a runtime with this code hash is installed.
    #[must_use]
    pub fn has_runtime(&self, code_hash: &Hash) -> bool {
        self.runtimes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(code_hash)
    }

    /// Installed runtime code hashes.
    #[must_use]
    pub fn runtime_hashes(&self) -> Vec<Hash> {
        self.runtimes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }

    fn runtime(&self, code_hash: &Hash) -> Result<Arc<WasmRuntime>, ExecutorError> {
        self.runtimes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(code_hash)
            .cloned()
            .ok_or(ExecutorError::UnknownRuntime(*code_hash))
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
            proposer_address: ctx.proposer_address,
            participation: ctx.participation.clone(),
            transactions: txs,
        };

        // The runtime borrows the engine's authoritative trie as the
        // pre-state and applies writes to its own scratch copy, so
        // `state` stays untouched until the swap below.
        let DryRun {
            output,
            witness,
            post_state,
        } = self
            .runtime(&ctx.runtime_code_hash)?
            .dry_run(&input, state, &body.evidence_proofs)?;

        // Commit the dry-run's post-state into the engine's trie.
        // Read-only blocks fall back to a clone of `state`, so the
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
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, ExecutorError> {
        // The WasmRuntime's query path works on its own scratch copy
        // and discards it after the call so no mutation can leak back
        // into `state`.
        Ok(self.runtime(&runtime_code_hash)?.query(request, state)?)
    }

    fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, ExecutorError> {
        Ok(self.runtime(&runtime_code_hash)?.validate_tx(
            tx_bytes,
            chain_id,
            block_gas_limit,
            state,
        )?)
    }

    fn install_runtime(&self, wasm: &[u8]) -> Result<Hash, ExecutorError> {
        Ok(Self::install_runtime(self, wasm)?)
    }

    fn alias_default_runtime(&self, code_hash: Hash) -> Result<(), ExecutorError> {
        Self::alias_default_runtime(self, code_hash)
    }

    fn installed_runtimes(&self) -> Vec<Hash> {
        self.runtime_hashes()
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
