//! Reusable cryptographic facts, independent of chain inclusion or guilt.
//!
//! Facts bind exact signed bytes and key/domain inputs. Evidence still checks
//! historical membership, offence logic and policy. Missing facts never mean
//! rejection. Only an authenticated explicit negative verdict can do that.

use crate::{
    bls::{self, Verifier},
    execution::commitment,
    history::HistoryError,
};
use alloc::{collections::BTreeMap, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::BlockProof;
use neutrino_primitives::{BlsPublicKey, BlsSignature, Hash};

/// Maximum independent assertions in one fact receipt.
pub const MAX_FACTS: usize = 64;

/// Exact input to a deterministic cryptographic check.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[allow(clippy::large_enum_variant)]
pub enum FactRequest {
    /// Signature or possession check with explicit cipher-suite separation.
    Signature {
        /// Public key.
        key: BlsPublicKey,
        /// Domain-tagged plaintext.
        message: Vec<u8>,
        /// Signature bytes.
        signature: BlsSignature,
        /// True only for POP (message must equal key).
        possession: bool,
    },
    /// Same-message aggregate; evidence separately authenticates key membership.
    Aggregate {
        /// Complete ordered signer keys.
        keys: Vec<BlsPublicKey>,
        /// Domain-tagged plaintext.
        message: Vec<u8>,
        /// Aggregate bytes.
        signature: BlsSignature,
    },
    /// Exact block envelope and accepted program identity.
    Block {
        /// Accepted runtime program.
        key: [u32; 8],
        /// Signed envelope, including proof bytes.
        proof: BlockProof,
    },
}

impl FactRequest {
    /// Content identity binds variant, lengths, domains, keys and exact bytes.
    pub fn id(&self) -> Hash {
        commitment(&(b"neutrino-cryptographic-fact", self))
    }

    fn verify(&self, verifier: &mut impl Verifier) -> Result<bool, HistoryError> {
        match self {
            Self::Signature {
                key,
                message,
                signature,
                possession,
            } => Ok(if *possession {
                message.as_slice() == key && verifier.pop(key, signature)
            } else {
                verifier.verify(key, message, signature)
            }),
            Self::Aggregate {
                keys,
                message,
                signature,
            } => Ok(verifier.aggregate(keys, message, signature)),
            Self::Block { key, proof } => block_is_valid(proof, key),
        }
    }
}

/// One explicit positive or negative cryptographic verdict.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProvenFact {
    /// Exact request identity.
    pub id: Hash,
    /// True means cryptographically valid, false means objective rejection.
    pub valid: bool,
}

/// Public values of the fact Guest. No signature or raw proof bytes remain.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct FactStatement {
    /// Ordered unique request identities and their proven verdicts.
    pub facts: Vec<ProvenFact>,
}

/// Fact Guest witness with expected verdicts; they are all checked inside it.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct FactWitness {
    /// Bounded unique assertions.
    pub requests: Vec<FactRequest>,
    /// Exact public values expected by the caller.
    pub statement: FactStatement,
}

/// Batch positive equations and individually establish negative verdicts.
/// Operational failure cannot be encoded as an invalid cryptographic artifact.
pub fn validate_facts(input: &FactWitness) -> Result<FactStatement, HistoryError> {
    if input.requests.is_empty()
        || input.requests.len() > MAX_FACTS
        || input.requests.len() != input.statement.facts.len()
    {
        return Err(HistoryError::Evidence);
    }
    let mut seen = alloc::collections::BTreeSet::new();
    let mut batch = bls::BatchVerifier::default();
    let mut direct = bls::DirectVerifier::default();
    for (request, fact) in input.requests.iter().zip(&input.statement.facts) {
        if request.id() != fact.id || !seen.insert(fact.id) {
            return Err(HistoryError::Evidence);
        }
        let actual = if fact.valid {
            request.verify(&mut batch)?
        } else {
            request.verify(&mut direct)?
        };
        if actual != fact.valid {
            return Err(HistoryError::Evidence);
        }
    }
    if !batch.finish() {
        return Err(HistoryError::Evidence);
    }
    Ok(input.statement.clone())
}

/// Evidence's cryptographic interface. Negative decisions require immediate
/// verification or an explicitly proven fact; never a deferred positive batch.
pub trait EvidenceVerifier: Verifier {
    /// Decide exact envelope rejection; errors are not slashable verdicts.
    fn rejects_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError>;
}

impl EvidenceVerifier for bls::DirectVerifier {
    fn rejects_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
        block_is_valid(proof, key).map(|valid| !valid)
    }
}

// The feature-disabled stub is constant; the real receipt verifier is not.
#[cfg_attr(not(feature = "sp1-verification"), allow(clippy::missing_const_for_fn))]
fn block_is_valid(proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
    #[cfg(feature = "sp1-verification")]
    {
        #[cfg(feature = "std")]
        let result = std::panic::catch_unwind(|| {
            crate::proof_verification::verify_block_artifact(proof, key)
        })
        .map_err(|_| HistoryError::Unsupported)?;
        #[cfg(not(feature = "std"))]
        let result = crate::proof_verification::verify_block_artifact(proof, key);
        Ok(result.is_ok())
    }
    #[cfg(not(feature = "sp1-verification"))]
    {
        let _ = (proof, key);
        Err(HistoryError::Unsupported)
    }
}

/// Collect unique facts while deriving offence statements on the host.
/// Cached verdicts must originate exclusively from already verified fact receipts.
#[derive(Default)]
pub struct FactRecorder {
    direct: bls::DirectVerifier,
    requests: BTreeMap<Hash, (FactRequest, bool)>,
    known: BTreeMap<Hash, bool>,
    failed: bool,
}

impl FactRecorder {
    /// Use authenticated cached verdicts to avoid repeating their cryptography.
    pub fn with_verified(known: BTreeMap<Hash, bool>) -> Self {
        Self {
            known,
            ..Self::default()
        }
    }
    /// Check or reuse one request and record its explicit verdict.
    pub fn check(&mut self, request: FactRequest) -> bool {
        let id = request.id();
        let value = self
            .known
            .get(&id)
            .copied()
            .or_else(|| self.requests.get(&id).map(|(_, value)| *value));
        let valid = if let Some(value) = value {
            value
        } else if let Ok(value) = request.verify(&mut self.direct) {
            value
        } else {
            self.failed = true;
            false
        };
        self.requests.entry(id).or_insert((request, valid));
        valid
    }
    /// Extract checked assertions. A panic/resource failure never becomes a fact.
    pub fn finish(self) -> Result<Vec<(FactRequest, bool)>, HistoryError> {
        if self.failed {
            Err(HistoryError::Unsupported)
        } else {
            Ok(self.requests.into_values().collect())
        }
    }
}

/// Reads only recursively authenticated fact statements. A missing lookup is
/// sticky, even when a caller branches on a negative signature result.
pub struct FactReader {
    facts: BTreeMap<Hash, bool>,
    missing: bool,
}

impl FactReader {
    /// Construct after verifying each statement against the pinned fact program.
    pub fn new(statements: &[FactStatement]) -> Result<Self, HistoryError> {
        let mut facts = BTreeMap::new();
        for statement in statements {
            if statement.facts.is_empty() || statement.facts.len() > MAX_FACTS {
                return Err(HistoryError::Evidence);
            }
            for fact in &statement.facts {
                if let Some(previous) = facts.insert(fact.id, fact.valid)
                    && previous != fact.valid
                {
                    return Err(HistoryError::Evidence);
                }
            }
        }
        Ok(Self {
            facts,
            missing: false,
        })
    }
    fn check(&mut self, request: &FactRequest) -> bool {
        self.facts.get(&request.id()).copied().unwrap_or_else(|| {
            self.missing = true;
            false
        })
    }
    /// Must be called before committing any derived offence statement.
    pub const fn complete(&self) -> bool {
        !self.missing
    }
}

macro_rules! signature_verifier {
    ($type:ty, $check:expr) => {
        impl Verifier for $type {
            fn verify(
                &mut self,
                key: &BlsPublicKey,
                message: &[u8],
                signature: &BlsSignature,
            ) -> bool {
                $check(
                    self,
                    FactRequest::Signature {
                        key: *key,
                        message: message.to_vec(),
                        signature: *signature,
                        possession: false,
                    },
                )
            }
            fn aggregate(
                &mut self,
                keys: &[BlsPublicKey],
                message: &[u8],
                signature: &BlsSignature,
            ) -> bool {
                $check(
                    self,
                    FactRequest::Aggregate {
                        keys: keys.to_vec(),
                        message: message.to_vec(),
                        signature: *signature,
                    },
                )
            }
            fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
                $check(
                    self,
                    FactRequest::Signature {
                        key: *key,
                        message: key.to_vec(),
                        signature: *signature,
                        possession: true,
                    },
                )
            }
        }
    };
}
signature_verifier!(FactRecorder, |this: &mut FactRecorder, request| this
    .check(request));
signature_verifier!(FactReader, |this: &mut FactReader, request| this
    .check(&request));
impl EvidenceVerifier for FactRecorder {
    fn rejects_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
        let valid = self.check(FactRequest::Block {
            key: *key,
            proof: proof.clone(),
        });
        if self.failed {
            Err(HistoryError::Unsupported)
        } else {
            Ok(!valid)
        }
    }
}
impl EvidenceVerifier for FactReader {
    fn rejects_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
        let valid = self.check(&FactRequest::Block {
            key: *key,
            proof: proof.clone(),
        });
        if self.missing {
            Err(HistoryError::Unsupported)
        } else {
            Ok(!valid)
        }
    }
}

/// Cryptographic requests available as soon as a BFT vote is observed.
/// This extraction does not assert membership, quorum, validity or guilt.
pub fn vote_requests(
    chain_id: u64,
    validators: &[neutrino_primitives::Validator],
    vote: &neutrino_consensus_types::FinalityVote,
) -> Vec<FactRequest> {
    let mut requests = Vec::new();
    let message = crate::slashing::vote_message(chain_id, &vote.data);
    let keys: Vec<_> = validators
        .iter()
        .enumerate()
        .filter_map(|(index, validator)| {
            (vote.aggregation_bits.get(u32::try_from(index).ok()?) == Some(true))
                .then_some(validator.pubkey)
        })
        .collect();
    if keys.len() == 1 {
        requests.push(FactRequest::Signature {
            key: keys[0],
            message: message.clone(),
            signature: vote.signature,
            possession: false,
        });
    }
    requests.push(FactRequest::Aggregate {
        keys,
        message,
        signature: vote.signature,
    });
    for claim in &vote.attestations {
        let Some(validator) = validators.get(claim.validator_index as usize) else {
            continue;
        };
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: crate::slashing::vote_message(chain_id, &claim.vote),
            signature: claim.vote_signature,
            possession: false,
        });
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: claim.signing_message(chain_id),
            signature: claim.signature,
            possession: false,
        });
        if let Some(quorum) = &claim.unlock_quorum {
            let keys = validators
                .iter()
                .enumerate()
                .filter_map(|(index, validator)| {
                    (quorum
                        .aggregate
                        .aggregation_bits
                        .get(u32::try_from(index).ok()?)
                        == Some(true))
                    .then_some(validator.pubkey)
                })
                .collect();
            requests.push(FactRequest::Aggregate {
                keys,
                message: crate::slashing::vote_message(chain_id, &quorum.data),
                signature: quorum.aggregate.signature,
            });
        }
    }
    requests
}

/// Header authentication and VRF facts can be compressed before finality.
pub fn header_requests(
    chain_id: u64,
    validators: &[neutrino_primitives::Validator],
    seed: &Hash,
    header: &neutrino_consensus_types::Header,
) -> Vec<FactRequest> {
    let Some(validator) = validators.get(header.proposer_index as usize) else {
        return Vec::new();
    };
    let mut message = Vec::from(neutrino_primitives::DOMAIN_PROPOSER_SIG);
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(&header.hash());
    alloc::vec![
        FactRequest::Signature {
            key: validator.pubkey,
            message,
            signature: header.signature,
            possession: false
        },
        FactRequest::Signature {
            key: validator.pubkey,
            message: neutrino_vrf::vrf_message(chain_id, seed, header.slot),
            signature: header.vrf_proof,
            possession: false
        },
    ]
}
