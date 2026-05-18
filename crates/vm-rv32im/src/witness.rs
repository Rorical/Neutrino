//! Per-block execution witness produced by the host while the VM runs.
//!
//! The witness captures everything a downstream proof system needs to
//! re-verify a block's state-transition without re-fetching chain data
//! from the node database:
//!
//! - The [`StateRoot`](neutrino_trie) at the start of the block.
//! - The engine-supplied [`BlockContextWitness`] (slot, height,
//!   parent hash, gas limit, VRF proof, etc.).
//! - The runtime input bytes delivered through `host_input`.
//! - Opaque borsh-encoded header and body bytes supplied by the engine
//!   after block sealing.
//! - Every state read the runtime performed, paired with an inclusion
//!   or exclusion proof against the base state root.
//!
//! Writes are *not* recorded explicitly: the proof system replays the
//! runtime trace to derive post-state values, then checks the resulting
//! post-state root against the header's `state_root`. The witness only
//! has to ground the inputs.
//!
//! Every public type derives [`borsh::BorshSerialize`] +
//! [`borsh::BorshDeserialize`] so the witness can be persisted in the
//! `witnesses` storage column and shipped over the
//! `/neutrino/req/witness_by_block/1` RPC. Borsh decoders do not
//! enforce canonical bit-path padding; consumers should only ingest
//! witnesses produced by this crate.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_trie::Proof;

/// Sub-witness mirroring `runtime-abi::BlockContext`.
///
/// Kept separate from the runtime-abi crate so the witness module does
/// not pull a runtime-abi dependency into `vm-rv32im`; the fields are
/// duplicated by intent and must stay in sync with
/// `neutrino_runtime_abi::BlockContext`.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, Eq, PartialEq)]
pub struct BlockContextWitness {
    /// Slot the block was produced in.
    pub slot: u64,
    /// Block height (1-indexed; genesis is height 0).
    pub height: u64,
    /// Public chunk-finalized seed mixed into the VRF and runtime.
    pub seed: [u8; 32],
    /// Hash of the parent block's header.
    pub parent_hash: [u8; 32],
    /// Parent state root delivered to the runtime.
    pub parent_state_root: [u8; 32],
    /// Gas limit the block was run with.
    pub gas_limit: u64,
    /// Proposer's active-set index. Matches the `u32`
    /// `ValidatorIndex` type used by `runtime-abi` and `primitives`.
    pub proposer_index: u32,
    /// Proposer VRF proof delivered to the runtime.
    pub vrf_proof: [u8; 96],
}

/// One state-read entry: the runtime read `key`, the underlying trie
/// at the base state root maps it to `base_value`, and `proof` proves
/// that mapping against the base root.
///
/// `base_value` is `None` for keys absent from the base trie. The proof
/// always commits to the *base* trie state at the start of the block.
/// If the runtime had previously written to the same key in this block,
/// the live value the runtime observes via the overlay differs from
/// `base_value`; the proof system reconstructs the live value by
/// replaying earlier syscall writes from the trace.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, Eq, PartialEq)]
pub struct StateRead {
    /// Key the runtime read.
    pub key: Vec<u8>,
    /// Value the base trie maps `key` to, or `None` for exclusion.
    pub base_value: Option<Vec<u8>>,
    /// Inclusion or exclusion proof against the witness's
    /// [`SealedWitness::parent_state_root`].
    pub proof: Proof,
}

/// One `state_next_key` entry recorded in syscall order.
///
/// The runtime observes the next live overlay-aware key matching
/// `prefix` and greater than `after`. The result key, when present, is
/// paired with its base-trie value/proof so the prover can anchor the
/// cursor result against the same parent state root as normal reads.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, Eq, PartialEq)]
pub struct StateNextKeyRead {
    /// Prefix argument supplied by the runtime.
    pub prefix: Vec<u8>,
    /// Cursor argument supplied by the runtime.
    pub after: Vec<u8>,
    /// Key returned by the host, or `None` when no matching live key
    /// existed.
    pub result_key: Option<Vec<u8>>,
    /// Base-trie value for [`Self::result_key`], if any.
    pub result_base_value: Option<Vec<u8>>,
    /// Inclusion or exclusion proof for [`Self::result_key`] against
    /// [`SealedWitness::parent_state_root`], if a result key existed.
    pub result_proof: Option<Proof>,
}

/// Mutable witness accumulator the host writes into while a block
/// executes.
///
/// The host appends one [`StateRead`] per state-access syscall that
/// queries the trie. [`ExecutionWitness::seal`] finalizes the
/// accumulator into a borsh-serializable [`SealedWitness`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExecutionWitness {
    parent_state_root: [u8; 32],
    block_context: BlockContextWitness,
    runtime_input: Vec<u8>,
    block_header: Vec<u8>,
    block_body: Vec<u8>,
    state_reads: Vec<StateRead>,
    state_next_key_reads: Vec<StateNextKeyRead>,
}

impl ExecutionWitness {
    /// Build a fresh witness for a block running against
    /// `parent_state_root` under the given `block_context`.
    #[must_use]
    pub const fn new(
        parent_state_root: [u8; 32],
        block_context: BlockContextWitness,
        runtime_input: Vec<u8>,
    ) -> Self {
        Self {
            parent_state_root,
            block_context,
            runtime_input,
            block_header: Vec::new(),
            block_body: Vec::new(),
            state_reads: Vec::new(),
            state_next_key_reads: Vec::new(),
        }
    }

    /// Snapshot of the parent state root the proofs are anchored to.
    #[must_use]
    pub const fn parent_state_root(&self) -> &[u8; 32] {
        &self.parent_state_root
    }

    /// Borrow the block-context portion of the witness.
    #[must_use]
    pub const fn block_context(&self) -> &BlockContextWitness {
        &self.block_context
    }

    /// Number of recorded state reads.
    #[must_use]
    pub fn state_read_count(&self) -> usize {
        self.state_reads.len()
    }

    /// Number of recorded `state_next_key` syscalls.
    #[must_use]
    pub fn state_next_key_read_count(&self) -> usize {
        self.state_next_key_reads.len()
    }

    /// Append one state-read entry.
    pub fn record_state_read(&mut self, read: StateRead) {
        self.state_reads.push(read);
    }

    /// Append one `state_next_key` entry.
    pub fn record_state_next_key_read(&mut self, read: StateNextKeyRead) {
        self.state_next_key_reads.push(read);
    }

    /// Finalize into a [`SealedWitness`].
    #[must_use]
    pub fn seal(self) -> SealedWitness {
        SealedWitness {
            parent_state_root: self.parent_state_root,
            block_context: self.block_context,
            runtime_input: self.runtime_input,
            block_header: self.block_header,
            block_body: self.block_body,
            state_reads: self.state_reads,
            state_next_key_reads: self.state_next_key_reads,
        }
    }
}

/// Immutable, borsh-serializable form of [`ExecutionWitness`].
///
/// The proof system ingests `SealedWitness` either directly through the
/// engine call graph (for the producer that just executed the block) or
/// by decoding bytes fetched from the `witnesses` storage column or
/// the `/neutrino/req/witness_by_block/1` RPC.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, Eq, PartialEq)]
pub struct SealedWitness {
    /// Trie root the proofs in `state_reads` are anchored to.
    pub parent_state_root: [u8; 32],
    /// Per-block context delivered by the engine.
    pub block_context: BlockContextWitness,
    /// Bytes delivered to the runtime through `host_input`.
    pub runtime_input: Vec<u8>,
    /// Borsh-encoded block header. Empty until the consensus engine
    /// seals the block and fills this field before persistence.
    pub block_header: Vec<u8>,
    /// Borsh-encoded block body. Empty until the consensus engine fills
    /// this field before persistence.
    pub block_body: Vec<u8>,
    /// Every state read the runtime performed, in syscall order.
    pub state_reads: Vec<StateRead>,
    /// Every `state_next_key` syscall the runtime performed, in syscall
    /// order.
    pub state_next_key_reads: Vec<StateNextKeyRead>,
}

impl SealedWitness {
    /// `true` when no read-side state syscalls were recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state_reads.is_empty() && self.state_next_key_reads.is_empty()
    }

    /// Number of recorded read-side state syscalls.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state_reads.len() + self.state_next_key_reads.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_trie::ProofTerminal;

    fn sample_context() -> BlockContextWitness {
        BlockContextWitness {
            slot: 42,
            height: 7,
            seed: [0xAB; 32],
            parent_hash: [0xCD; 32],
            parent_state_root: [0xEF; 32],
            gas_limit: 1_000_000,
            proposer_index: 3,
            vrf_proof: [0x12; 96],
        }
    }

    fn empty_proof() -> Proof {
        Proof {
            steps: Vec::new(),
            terminal: ProofTerminal::Empty,
        }
    }

    #[test]
    fn fresh_witness_is_empty() {
        let context = sample_context();
        let witness = ExecutionWitness::new(context.parent_state_root, context, Vec::new());
        assert_eq!(witness.state_read_count(), 0);
        assert_eq!(witness.state_next_key_read_count(), 0);
        let sealed = witness.seal();
        assert!(sealed.is_empty());
        assert_eq!(sealed.len(), 0);
    }

    #[test]
    fn record_and_seal_round_trips_through_borsh() {
        let context = sample_context();
        let mut witness = ExecutionWitness::new(
            context.parent_state_root,
            context,
            b"runtime-input".to_vec(),
        );
        witness.record_state_read(StateRead {
            key: b"counter".to_vec(),
            base_value: Some(7_u64.to_le_bytes().to_vec()),
            proof: empty_proof(),
        });
        witness.record_state_read(StateRead {
            key: b"missing".to_vec(),
            base_value: None,
            proof: empty_proof(),
        });
        witness.record_state_next_key_read(StateNextKeyRead {
            prefix: b"acct:".to_vec(),
            after: b"acct:alice".to_vec(),
            result_key: Some(b"acct:bob".to_vec()),
            result_base_value: Some(b"bob-value".to_vec()),
            result_proof: Some(empty_proof()),
        });
        let sealed = witness.seal();
        assert_eq!(sealed.len(), 3);
        assert_eq!(sealed.runtime_input, b"runtime-input");

        let encoded = borsh::to_vec(&sealed).expect("borsh encode");
        let decoded: SealedWitness = borsh::from_slice(&encoded).expect("borsh decode");
        assert_eq!(decoded, sealed);
    }

    #[test]
    fn block_context_round_trips_through_borsh() {
        let ctx = sample_context();
        let encoded = borsh::to_vec(&ctx).expect("borsh encode");
        let decoded: BlockContextWitness = borsh::from_slice(&encoded).expect("borsh decode");
        assert_eq!(decoded, ctx);
    }
}
