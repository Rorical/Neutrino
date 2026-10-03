//! Bounded checkpoint metadata and content-addressed state snapshot transport.
//!
//! Decoding these types does not authenticate their contents. A consumer verifies
//! the real history receipt, its local trust anchor, the endpoint context and all
//! historical openings before installing any live chain state. State fragments
//! are authenticated only after reconstructing the complete node or value.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize, io};
use neutrino_primitives::{BoundedBytes, BoundsError, Hash, Validator};

use crate::{
    Header, HistoryProof,
    history::{HISTORY_RETENTION_CHUNKS, HistoryFrontier},
    history_proof::BoundedVec,
};

/// Maximum active validator vector carried by one bootstrap response.
/// This is a transport limit, not a new validator activation rule.
pub const MAX_BOOTSTRAP_VALIDATORS: usize = 65_536;
/// Maximum historical openings needed to resume current consensus.
pub const MAX_BOOTSTRAP_HISTORY_RECORDS: usize = 8;
const _: () = assert!(HISTORY_RETENTION_CHUNKS == 8);
/// Aggregate encoded opening bytes carried by one bootstrap response.
pub const MAX_BOOTSTRAP_HISTORY_BYTES: usize = 8 * 1024 * 1024;
/// Maximum content-addressed items requested or returned in one state response.
pub const MAX_STATE_ITEMS: usize = 128;
/// Maximum bytes of one node or value fragment.
pub const MAX_STATE_FRAGMENT_BYTES: usize = 64 * 1024;
/// Maximum fragment payload bytes in one state response, excluding framing.
pub const MAX_STATE_RESPONSE_BYTES: usize = MAX_STATE_ITEMS * MAX_STATE_FRAGMENT_BYTES;

/// Bounded active validator set at the authenticated checkpoint endpoint.
pub type BootstrapValidators = BoundedVec<Validator, MAX_BOOTSTRAP_VALIDATORS>;
/// Canonical encoded historical openings, without a dependency on the prover.
pub type BootstrapHistory =
    BoundedVec<BoundedBytes<MAX_BOOTSTRAP_HISTORY_BYTES>, MAX_BOOTSTRAP_HISTORY_RECORDS>;

/// Metadata needed to initialize a full node from a verified recursive prefix.
/// An execution-state snapshot is fetched separately under the prefix's root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapData {
    /// Real genesis-to-end receipt, used to establish durable recursive coverage.
    /// A non-genesis local trust origin additionally requires an exact bridge.
    pub genesis_prefix: HistoryProof,
    /// Header at the end boundary, retained as the canonical parent anchor.
    pub anchor_header: Header,
    /// Ordered active validators effective for the next chunk.
    pub validators: BootstrapValidators,
    /// Counted history frontier at the same endpoint.
    pub frontier: HistoryFrontier,
    /// Exact preceding window of encoded `HistoricalOpening` objects.
    /// Their paths target the prefix endpoint's history root and count.
    pub recent: BootstrapHistory,
}

impl BootstrapData {
    /// Construct metadata with both element and aggregate byte bounds checked.
    pub fn new(
        genesis_prefix: HistoryProof,
        anchor_header: Header,
        validators: Vec<Validator>,
        frontier: HistoryFrontier,
        recent: Vec<BoundedBytes<MAX_BOOTSTRAP_HISTORY_BYTES>>,
    ) -> Result<Self, BoundsError> {
        let data = Self {
            genesis_prefix,
            anchor_header,
            validators: BootstrapValidators::new(validators)?,
            frontier,
            recent: BootstrapHistory::new(recent)?,
        };
        data.validate_limits()?;
        Ok(data)
    }

    /// Check the cumulative historical byte limit on a locally constructed value.
    pub fn validate_limits(&self) -> Result<(), BoundsError> {
        let actual = self.recent.iter().map(BoundedBytes::len).sum();
        if actual > MAX_BOOTSTRAP_HISTORY_BYTES {
            return Err(BoundsError {
                actual,
                max: MAX_BOOTSTRAP_HISTORY_BYTES,
            });
        }
        Ok(())
    }
}

impl BorshSerialize for BootstrapData {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        self.validate_limits()
            .map_err(|_| invalid_data("bootstrap historical byte budget"))?;
        self.genesis_prefix.serialize(writer)?;
        self.anchor_header.serialize(writer)?;
        self.validators.serialize(writer)?;
        self.frontier.serialize(writer)?;
        self.recent.serialize(writer)
    }
}

impl BorshDeserialize for BootstrapData {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let genesis_prefix = HistoryProof::deserialize_reader(reader)?;
        let anchor_header = Header::deserialize_reader(reader)?;
        let validators = BootstrapValidators::deserialize_reader(reader)?;
        let frontier = HistoryFrontier::deserialize_reader(reader)?;
        let count = u32::deserialize_reader(reader)? as usize;
        if count > MAX_BOOTSTRAP_HISTORY_RECORDS {
            return Err(invalid_data("bootstrap historical record count"));
        }
        let mut budget = MAX_BOOTSTRAP_HISTORY_BYTES;
        let mut recent = Vec::with_capacity(count);
        for _ in 0..count {
            let length = u32::deserialize_reader(reader)? as usize;
            budget = budget
                .checked_sub(length)
                .ok_or_else(|| invalid_data("bootstrap historical byte budget"))?;
            let mut bytes = alloc::vec![0; length];
            reader.read_exact(&mut bytes)?;
            recent.push(
                BoundedBytes::new(bytes)
                    .map_err(|_| invalid_data("bootstrap historical byte budget"))?,
            );
        }
        Ok(Self {
            genesis_prefix,
            anchor_header,
            validators,
            frontier,
            recent: BootstrapHistory::new(recent)
                .map_err(|_| invalid_data("bootstrap historical record count"))?,
        })
    }
}

/// Content-addressed state namespace, distinguishing equal node/value bytes.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, BorshSerialize, BorshDeserialize,
)]
pub enum StateItemKind {
    /// Canonically encoded trie node, hashed under the node namespace.
    Node,
    /// Raw runtime value bytes, hashed under the value namespace.
    Value,
}

/// An exact fragment request under an already authenticated state root.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, BorshSerialize, BorshDeserialize,
)]
pub struct StateItem {
    /// Namespace of the object.
    pub kind: StateItemKind,
    /// Expected complete content hash, never a hash of the fragment.
    pub hash: Hash,
    /// Byte offset of the requested fragment.
    pub offset: u64,
}

impl StateItem {
    /// Start fetching one trie node by its complete content hash.
    #[must_use]
    pub const fn node(hash: Hash) -> Self {
        Self {
            kind: StateItemKind::Node,
            hash,
            offset: 0,
        }
    }

    /// Start fetching one runtime value by its complete content hash.
    #[must_use]
    pub const fn value(hash: Hash) -> Self {
        Self {
            kind: StateItemKind::Value,
            hash,
            offset: 0,
        }
    }
}

/// One bounded fragment of a requested trie node or runtime value.
/// Large objects use successive offsets without changing their complete hash.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct StateEntry {
    /// Exact request this entry answers, including its offset.
    pub item: StateItem,
    /// Length of the complete object; this is untrusted until its hash verifies.
    /// Consumers must not allocate this many bytes directly from the declaration.
    pub total_len: u64,
    /// Bytes starting at the requested offset.
    pub bytes: BoundedBytes<MAX_STATE_FRAGMENT_BYTES>,
}

impl StateEntry {
    /// End offset, rejecting integer overflow.
    #[must_use]
    pub fn end_offset(&self) -> Option<u64> {
        self.item
            .offset
            .checked_add(u64::try_from(self.bytes.len()).ok()?)
    }

    /// Require an exact requested item and a bounded, advancing response.
    /// Empty values and an empty final fragment are permitted; a nonfinal empty
    /// response cannot make download progress and is rejected.
    #[must_use]
    pub fn validate_for(&self, requested: &StateItem) -> bool {
        self.item == *requested
            && self.item.offset <= self.total_len
            && self.end_offset().is_some_and(|end| end <= self.total_len)
            && (!self.bytes.is_empty() || self.item.offset == self.total_len)
    }

    /// Whether these bytes reach the declared end of the complete object.
    /// This is a framing property, not content authentication.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.end_offset() == Some(self.total_len)
    }
}

/// Bounded exact fragment requests for one state root.
pub type StateItems = BoundedVec<StateItem, MAX_STATE_ITEMS>;
/// Bounded fragment responses, with at most eight MiB of payload bytes.
pub type StateEntries = BoundedVec<StateEntry, MAX_STATE_ITEMS>;

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;
