#![allow(missing_docs)]

use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionWitness {
    pub parent_state_root: [u8; 32],
    pub state_reads: Vec<StateRead>,
    pub block_context: Option<BlockContextWitness>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRead {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub trie_nodes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockContextWitness {
    pub slot: u64,
    pub height: u64,
    pub seed: [u8; 32],
    pub parent_hash: [u8; 32],
    pub gas_limit: u64,
    pub proposer_index: u64,
}

impl ExecutionWitness {
    #[must_use]
    pub fn new(parent_state_root: [u8; 32]) -> Self {
        Self {
            parent_state_root,
            state_reads: Vec::new(),
            block_context: None,
        }
    }

    pub fn record_state_read(&mut self, key: Vec<u8>, value: Vec<u8>, trie_nodes: Vec<Vec<u8>>) {
        self.state_reads.push(StateRead {
            key,
            value,
            trie_nodes,
        });
    }

    pub fn set_block_context(&mut self, ctx: BlockContextWitness) {
        self.block_context = Some(ctx);
    }

    #[must_use]
    pub fn seal(self) -> SealedWitness {
        SealedWitness {
            parent_state_root: self.parent_state_root,
            state_reads: self.state_reads,
            block_context: self.block_context,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedWitness {
    pub parent_state_root: [u8; 32],
    pub state_reads: Vec<StateRead>,
    pub block_context: Option<BlockContextWitness>,
}

impl SealedWitness {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state_reads.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.state_reads.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_witness_seals() {
        let witness = ExecutionWitness::new([0; 32]);
        let sealed = witness.seal();
        assert_eq!(sealed.parent_state_root, [0; 32]);
        assert!(sealed.state_reads.is_empty());
        assert!(sealed.block_context.is_none());
    }

    #[test]
    fn record_and_seal_state_reads() {
        let mut witness = ExecutionWitness::new([0xAB; 32]);
        witness.record_state_read(b"key1".to_vec(), b"val1".to_vec(), vec![b"node1".to_vec()]);
        witness.record_state_read(b"key2".to_vec(), b"val2".to_vec(), vec![]);

        let sealed = witness.seal();
        assert_eq!(sealed.len(), 2);
        assert_eq!(sealed.state_reads[0].key, b"key1");
        assert_eq!(sealed.state_reads[0].value, b"val1");
        assert_eq!(sealed.state_reads[1].key, b"key2");
    }

    #[test]
    fn set_block_context() {
        let mut witness = ExecutionWitness::new([0; 32]);
        witness.set_block_context(BlockContextWitness {
            slot: 42,
            height: 100,
            seed: [0xCD; 32],
            parent_hash: [0xEF; 32],
            gas_limit: 10_000_000,
            proposer_index: 0,
        });

        let sealed = witness.seal();
        let ctx = sealed.block_context.unwrap();
        assert_eq!(ctx.slot, 42);
        assert_eq!(ctx.height, 100);
        assert_eq!(ctx.gas_limit, 10_000_000);
    }

    #[test]
    fn witness_is_empty_when_no_reads() {
        let witness = ExecutionWitness::new([0; 32]);
        let sealed = witness.seal();
        assert!(sealed.is_empty());
        assert_eq!(sealed.len(), 0);
    }
}
