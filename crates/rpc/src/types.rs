//! Serde-friendly JSON DTOs for the RPC layer.
//!
//! Internal consensus types use borsh for the wire and operate on raw
//! byte arrays. The DTOs here re-encode hashes as `0x..` hex strings,
//! produce decimal integers for heights/slots, and expose only the
//! fields a JSON-RPC client actually needs. Conversion is one-way
//! (consensus → JSON): clients submitting transactions send hex
//! strings directly through the method parameter shapes in
//! `server.rs`.

use neutrino_consensus_types::{Block, Body, Header};
use neutrino_primitives::{Hash, Validator};
use serde::{Deserialize, Serialize};

use crate::backend::{BlockId, FinalizedInfo, HeadInfo};

/// Wrapper that serializes a fixed-size byte array as `"0x.."` hex.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HashHex(pub [u8; 32]);

impl Serialize for HashHex {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; 2 + 64];
        buf[0] = b'0';
        buf[1] = b'x';
        hex::encode_to_slice(self.0, &mut buf[2..]).map_err(serde::ser::Error::custom)?;
        ser.serialize_str(core::str::from_utf8(&buf).map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for HashHex {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(de)?;
        let stripped = raw.strip_prefix("0x").unwrap_or(&raw);
        let mut out = [0u8; 32];
        hex::decode_to_slice(stripped, &mut out).map_err(serde::de::Error::custom)?;
        Ok(Self(out))
    }
}

impl From<[u8; 32]> for HashHex {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<HashHex> for [u8; 32] {
    fn from(value: HashHex) -> Self {
        value.0
    }
}

/// Wrapper that serializes opaque bytes as `"0x.."` hex.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BytesHex(pub Vec<u8>);

impl Serialize for BytesHex {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let encoded = if self.0.is_empty() {
            String::from("0x")
        } else {
            let mut s = String::with_capacity(2 + self.0.len() * 2);
            s.push_str("0x");
            s.push_str(&hex::encode(&self.0));
            s
        };
        ser.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for BytesHex {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(de)?;
        let stripped = raw.strip_prefix("0x").unwrap_or(&raw);
        if stripped.is_empty() {
            return Ok(Self(Vec::new()));
        }
        let bytes = hex::decode(stripped).map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

impl From<Vec<u8>> for BytesHex {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<BytesHex> for Vec<u8> {
    fn from(value: BytesHex) -> Self {
        value.0
    }
}

/// JSON representation of a block header.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeaderJson {
    /// Protocol version.
    pub version: u32,
    /// Block height.
    pub height: u64,
    /// Slot at which the block was produced.
    pub slot: u64,
    /// Parent header hash.
    pub parent_hash: HashHex,
    /// Block hash (BLAKE3 over the canonical-signed-payload).
    pub block_hash: HashHex,
    /// Proposer index in the active validator set.
    pub proposer_index: u32,
    /// Post-execution state root.
    pub state_root: HashHex,
    /// Transactions root.
    pub transactions_root: HashHex,
    /// Finality votes root.
    pub votes_root: HashHex,
    /// Slashings root.
    pub slashings_root: HashHex,
    /// Validator-operations root.
    pub validator_ops_root: HashHex,
    /// Data-availability root.
    pub da_root: HashHex,
    /// Runtime-defined commitment (typically the validator-set root).
    pub runtime_extra: HashHex,
    /// Gas consumed by the block.
    pub gas_used: u64,
    /// Gas limit the block was run with.
    pub gas_limit: u64,
    /// UNIX-epoch timestamp in seconds.
    pub timestamp: u64,
}

impl From<&Header> for HeaderJson {
    fn from(h: &Header) -> Self {
        Self {
            version: h.version,
            height: h.height,
            slot: h.slot,
            parent_hash: HashHex(h.parent_hash),
            block_hash: HashHex(h.hash()),
            proposer_index: h.proposer_index,
            state_root: HashHex(h.state_root),
            transactions_root: HashHex(h.transactions_root),
            votes_root: HashHex(h.votes_root),
            slashings_root: HashHex(h.slashings_root),
            validator_ops_root: HashHex(h.validator_ops_root),
            da_root: HashHex(h.da_root),
            runtime_extra: HashHex(h.runtime_extra),
            gas_used: h.gas_used,
            gas_limit: h.gas_limit,
            timestamp: h.timestamp,
        }
    }
}

/// JSON representation of a block body. Transaction blobs are exposed
/// as opaque hex strings; their decoding is runtime-defined.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BodyJson {
    /// Runtime-defined transaction blobs.
    pub transactions: Vec<BytesHex>,
    /// Number of aggregated finality votes (full vote contents are
    /// not exposed in v1; finality is reported through
    /// `chain_finalized`).
    pub finality_votes: u32,
    /// Number of slashing-evidence entries.
    pub slashings: u32,
    /// Number of validator deposits surfaced to the runtime.
    pub deposits: u32,
    /// Number of voluntary exits surfaced to the runtime.
    pub voluntary_exits: u32,
}

impl From<&Body> for BodyJson {
    fn from(b: &Body) -> Self {
        Self {
            transactions: b.transactions.iter().cloned().map(BytesHex).collect(),
            finality_votes: u32::try_from(b.finality_votes.len()).unwrap_or(u32::MAX),
            slashings: u32::try_from(b.slashings.len()).unwrap_or(u32::MAX),
            deposits: u32::try_from(b.deposits.len()).unwrap_or(u32::MAX),
            voluntary_exits: u32::try_from(b.voluntary_exits.len()).unwrap_or(u32::MAX),
        }
    }
}

/// JSON representation of a full block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockJson {
    /// Block header.
    pub header: HeaderJson,
    /// Block body.
    pub body: BodyJson,
}

impl From<&Block> for BlockJson {
    fn from(b: &Block) -> Self {
        Self {
            header: HeaderJson::from(&b.header),
            body: BodyJson::from(&b.body),
        }
    }
}

/// JSON shape returned by `chain_head`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeadInfoJson {
    /// Head block height.
    pub height: u64,
    /// Head block hash.
    pub hash: HashHex,
    /// Slot of the head block.
    pub slot: u64,
    /// Post-execution state root of the head block.
    pub state_root: HashHex,
}

impl From<HeadInfo> for HeadInfoJson {
    fn from(h: HeadInfo) -> Self {
        Self {
            height: h.height,
            hash: HashHex(h.hash),
            slot: h.slot,
            state_root: HashHex(h.state_root),
        }
    }
}

/// JSON shape returned by `chain_finalized`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FinalizedInfoJson {
    /// Checkpoint index.
    pub index: u64,
    /// Finalized block hash.
    pub block_hash: HashHex,
    /// Finalized block height.
    pub height: u64,
    /// Finalized state root.
    pub state_root: HashHex,
}

impl From<FinalizedInfo> for FinalizedInfoJson {
    fn from(f: FinalizedInfo) -> Self {
        Self {
            index: f.index,
            block_hash: HashHex(f.block_hash),
            height: f.height,
            state_root: HashHex(f.state_root),
        }
    }
}

/// JSON shape returned by `system_health`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HealthJson {
    /// Active libp2p peer count (stub: always 0 today).
    pub peers: u64,
    /// `true` if sync FSM is still trailing the network.
    pub is_syncing: bool,
    /// `true` if a runtime ELF is attached and queries are usable.
    pub runtime_available: bool,
    /// Local mempool transaction count.
    pub mempool: u64,
    /// Head block height.
    pub head_height: u64,
}

/// JSON shape returned by `system_version`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VersionJson {
    /// Runtime ABI version this node speaks.
    pub abi_version: u32,
    /// Runtime ABI version reported by the attached runtime ELF, if any.
    pub runtime_abi_version: Option<u32>,
}

/// JSON shape returned by `validator_set_active`. Validators are
/// emitted in the order the engine uses for proposer eligibility.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValidatorJson {
    /// BLS public key in hex.
    pub pubkey: BytesHex,
    /// Withdrawal credentials hash.
    pub withdrawal_credentials: HashHex,
    /// Effective stake.
    pub effective_stake: u64,
    /// Whether the validator is slashed.
    pub slashed: bool,
    /// Activation epoch.
    pub activation_epoch: u64,
    /// Exit epoch (`u64::MAX` if not exiting).
    pub exit_epoch: u64,
}

impl From<&Validator> for ValidatorJson {
    fn from(v: &Validator) -> Self {
        Self {
            pubkey: BytesHex(v.pubkey.to_vec()),
            withdrawal_credentials: HashHex(v.withdrawal_credentials),
            effective_stake: v.effective_stake,
            slashed: v.slashed,
            activation_epoch: v.activation_epoch,
            exit_epoch: v.exit_epoch,
        }
    }
}

/// JSON shape returned by `runtime_call`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeCallResultJson {
    /// Runtime-defined status code.
    pub code: u32,
    /// Runtime-defined response payload, hex-encoded.
    pub payload: BytesHex,
    /// Gas the query consumed.
    pub gas_used: u64,
}

/// JSON shape returned by `mempool_submit`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SubmitResultJson {
    /// BLAKE3 hash of the submitted transaction bytes.
    pub hash: HashHex,
}

impl SubmitResultJson {
    /// Wrap a raw `Hash` into the JSON envelope.
    #[must_use]
    pub const fn new(hash: Hash) -> Self {
        Self {
            hash: HashHex(hash),
        }
    }
}

/// JSON representation of [`BlockId`]. Accepts the strings
/// `"latest"` / `"finalized"`, a hex hash, or a decimal-or-hex height
/// integer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockIdJson(pub BlockId);

impl Serialize for BlockIdJson {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            BlockId::Latest => ser.serialize_str("latest"),
            BlockId::Finalized => ser.serialize_str("finalized"),
            BlockId::Hash(h) => HashHex(*h).serialize(ser),
            BlockId::Height(h) => ser.serialize_u64(*h),
        }
    }
}

impl<'de> Deserialize<'de> for BlockIdJson {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        // Accept string ("latest"/"finalized"/hash), number (height).
        let v = serde_json::Value::deserialize(de)?;
        match v {
            serde_json::Value::Null => Ok(Self(BlockId::Latest)),
            serde_json::Value::String(s) => {
                if s.eq_ignore_ascii_case("latest") {
                    Ok(Self(BlockId::Latest))
                } else if s.eq_ignore_ascii_case("finalized") {
                    Ok(Self(BlockId::Finalized))
                } else if let Some(stripped) = s.strip_prefix("0x") {
                    // Could be a hex hash (32 bytes => 64 hex chars) or
                    // a hex-encoded height.
                    if stripped.len() == 64 {
                        let mut out = [0u8; 32];
                        hex::decode_to_slice(stripped, &mut out)
                            .map_err(serde::de::Error::custom)?;
                        Ok(Self(BlockId::Hash(out)))
                    } else {
                        let h =
                            u64::from_str_radix(stripped, 16).map_err(serde::de::Error::custom)?;
                        Ok(Self(BlockId::Height(h)))
                    }
                } else {
                    // Decimal height as string.
                    let h: u64 = s.parse().map_err(serde::de::Error::custom)?;
                    Ok(Self(BlockId::Height(h)))
                }
            }
            serde_json::Value::Number(n) => {
                let h = n
                    .as_u64()
                    .ok_or_else(|| serde::de::Error::custom("block height must be a u64"))?;
                Ok(Self(BlockId::Height(h)))
            }
            other => Err(serde::de::Error::custom(format!(
                "unsupported block id encoding: {other}",
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_hex_round_trips_through_json() {
        let h = HashHex([0x12; 32]);
        let s = serde_json::to_string(&h).unwrap();
        assert!(s.starts_with("\"0x"));
        let back: HashHex = serde_json::from_str(&s).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn bytes_hex_round_trips_through_json() {
        let b = BytesHex(vec![1, 2, 3, 4]);
        let s = serde_json::to_string(&b).unwrap();
        assert_eq!(s, "\"0x01020304\"");
        let back: BytesHex = serde_json::from_str(&s).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn block_id_deserialises_latest() {
        let bid: BlockIdJson = serde_json::from_str("\"latest\"").unwrap();
        assert_eq!(bid.0, BlockId::Latest);
    }

    #[test]
    fn block_id_deserialises_finalized() {
        let bid: BlockIdJson = serde_json::from_str("\"finalized\"").unwrap();
        assert_eq!(bid.0, BlockId::Finalized);
    }

    #[test]
    fn block_id_deserialises_height_number() {
        let bid: BlockIdJson = serde_json::from_str("42").unwrap();
        assert_eq!(bid.0, BlockId::Height(42));
    }

    #[test]
    fn block_id_deserialises_height_decimal_string() {
        let bid: BlockIdJson = serde_json::from_str("\"100\"").unwrap();
        assert_eq!(bid.0, BlockId::Height(100));
    }

    #[test]
    fn block_id_deserialises_hex_hash() {
        let hex_hash = format!("\"0x{}\"", hex::encode([0xAB; 32]));
        let bid: BlockIdJson = serde_json::from_str(&hex_hash).unwrap();
        assert_eq!(bid.0, BlockId::Hash([0xAB; 32]));
    }

    #[test]
    fn block_id_defaults_to_latest_on_null() {
        let bid: BlockIdJson = serde_json::from_str("null").unwrap();
        assert_eq!(bid.0, BlockId::Latest);
    }
}
