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
use neutrino_primitives::{BitVec, BlsPublicKey, BlsSignature, Hash, Validator};

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
        self.borrowed().id()
    }

    const fn borrowed(&self) -> FactRequestRef<'_> {
        match self {
            Self::Signature {
                key,
                message,
                signature,
                possession,
            } => FactRequestRef::Signature {
                key,
                message: message.as_slice(),
                signature,
                possession: *possession,
            },
            Self::Aggregate {
                keys,
                message,
                signature,
            } => FactRequestRef::Aggregate {
                keys: keys.as_slice(),
                message: message.as_slice(),
                signature,
            },
            Self::Block { key, proof } => FactRequestRef::Block { key, proof },
        }
    }

    fn verify(&self, verifier: &mut impl Verifier) -> Result<bool, HistoryError> {
        self.borrowed().verify(verifier)
    }
}

/// Borrowed [`FactRequest`] with an identical Borsh encoding: the same variant
/// order, and `&[u8]`/`&[BlsPublicKey]` encode exactly like the owned vectors.
/// Verifiers derive ids from it without cloning messages, keys or proofs.
#[derive(BorshSerialize, Clone, Copy)]
enum FactRequestRef<'a> {
    Signature {
        key: &'a BlsPublicKey,
        message: &'a [u8],
        signature: &'a BlsSignature,
        possession: bool,
    },
    Aggregate {
        keys: &'a [BlsPublicKey],
        message: &'a [u8],
        signature: &'a BlsSignature,
    },
    Block {
        key: &'a [u32; 8],
        proof: &'a BlockProof,
    },
}

impl FactRequestRef<'_> {
    /// Equal to [`FactRequest::id`] of the owned request.
    fn id(self) -> Hash {
        commitment(&(b"neutrino-cryptographic-fact", self))
    }

    fn verify(self, verifier: &mut impl Verifier) -> Result<bool, HistoryError> {
        match self {
            Self::Signature {
                key,
                message,
                signature,
                possession,
            } => Ok(if possession {
                message == key.as_slice() && verifier.pop(key, signature)
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

    fn to_request(self) -> FactRequest {
        match self {
            Self::Signature {
                key,
                message,
                signature,
                possession,
            } => FactRequest::Signature {
                key: *key,
                message: message.to_vec(),
                signature: *signature,
                possession,
            },
            Self::Aggregate {
                keys,
                message,
                signature,
            } => FactRequest::Aggregate {
                keys: keys.to_vec(),
                message: message.to_vec(),
                signature: *signature,
            },
            Self::Block { key, proof } => FactRequest::Block {
                key: *key,
                proof: proof.clone(),
            },
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
        let valid = self.verdict(&id, request.borrowed());
        self.requests.entry(id).or_insert((request, valid));
        valid
    }

    /// [`Self::check`] for a borrowed request, copied only when its id is new.
    fn check_fact(&mut self, request: FactRequestRef<'_>) -> bool {
        let id = request.id();
        let valid = self.verdict(&id, request);
        self.requests
            .entry(id)
            .or_insert_with(|| (request.to_request(), valid));
        valid
    }

    fn verdict(&mut self, id: &Hash, request: FactRequestRef<'_>) -> bool {
        let value = self
            .known
            .get(id)
            .copied()
            .or_else(|| self.requests.get(id).map(|(_, value)| *value));
        if let Some(value) = value {
            value
        } else if let Ok(value) = request.verify(&mut self.direct) {
            value
        } else {
            self.failed = true;
            false
        }
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
    fn check_fact(&mut self, request: FactRequestRef<'_>) -> bool {
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
    ($type:ty) => {
        impl Verifier for $type {
            fn verify(
                &mut self,
                key: &BlsPublicKey,
                message: &[u8],
                signature: &BlsSignature,
            ) -> bool {
                self.check_fact(FactRequestRef::Signature {
                    key,
                    message,
                    signature,
                    possession: false,
                })
            }
            fn aggregate(
                &mut self,
                keys: &[BlsPublicKey],
                message: &[u8],
                signature: &BlsSignature,
            ) -> bool {
                self.check_fact(FactRequestRef::Aggregate {
                    keys,
                    message,
                    signature,
                })
            }
            fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
                // A possession proof signs exactly the key bytes.
                self.check_fact(FactRequestRef::Signature {
                    key,
                    message: key,
                    signature,
                    possession: true,
                })
            }
        }
    };
}
signature_verifier!(FactRecorder);
signature_verifier!(FactReader);
signature_verifier!(HybridVerifier);

/// Answers from recursively authenticated fact statements first and falls
/// back to in-circuit BLS for anything they do not cover.
///
/// This lets a consensus chunk consume signature work that fact proofs
/// already did ahead of time without making chunk proving wait for them:
/// uncovered checks still run through the batched pairing path.
pub struct HybridVerifier {
    facts: BTreeMap<Hash, bool>,
    direct: bls::BatchVerifier,
    hits: usize,
    misses: usize,
}

impl HybridVerifier {
    /// Construct after every statement's receipt has been verified against
    /// the pinned fact program. Conflicting verdicts for one request are
    /// rejected as in [`FactReader::new`].
    pub fn new(statements: &[FactStatement]) -> Result<Self, HistoryError> {
        let reader = FactReader::new(statements)?;
        Ok(Self {
            facts: reader.facts,
            direct: bls::BatchVerifier::default(),
            hits: 0,
            misses: 0,
        })
    }

    fn check_fact(&mut self, request: FactRequestRef<'_>) -> bool {
        if let Some(valid) = self.facts.get(&request.id()) {
            self.hits += 1;
            return *valid;
        }
        self.misses += 1;
        request.verify(&mut self.direct).unwrap_or(false)
    }

    /// Checks answered by fact statements.
    #[must_use]
    pub const fn hits(&self) -> usize {
        self.hits
    }

    /// Checks that fell back to in-circuit verification.
    #[must_use]
    pub const fn misses(&self) -> usize {
        self.misses
    }

    /// Settle the batched fallback equations. Must be called before trusting
    /// any positive answer that came from the fallback path.
    #[must_use]
    pub fn finish(self) -> bool {
        self.direct.finish()
    }
}
impl EvidenceVerifier for FactRecorder {
    fn rejects_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
        let valid = self.check_fact(FactRequestRef::Block { key, proof });
        if self.failed {
            Err(HistoryError::Unsupported)
        } else {
            Ok(!valid)
        }
    }
}
impl EvidenceVerifier for FactReader {
    fn rejects_block(&mut self, proof: &BlockProof, key: &[u32; 8]) -> Result<bool, HistoryError> {
        let valid = self.check_fact(FactRequestRef::Block { key, proof });
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
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &neutrino_consensus_types::FinalityVote,
) -> Vec<FactRequest> {
    let mut requests = Vec::new();
    let message = vote.data.signing_message(domain);
    let keys = marked_keys(validators, &vote.aggregation_bits);
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
            message: claim.vote.signing_message(domain),
            signature: claim.vote_signature,
            possession: false,
        });
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: claim.signing_message(domain),
            signature: claim.signature,
            possession: false,
        });
        if let Some(quorum) = &claim.unlock_quorum {
            requests.push(quorum_request(domain, validators, quorum));
        }
    }
    requests
}

/// Keys of every validator marked in `bits`, in set order. Extraction only:
/// membership and activity are checked by the consuming verifier.
fn marked_keys(validators: &[Validator], bits: &BitVec) -> Vec<BlsPublicKey> {
    validators
        .iter()
        .enumerate()
        .filter_map(|(index, validator)| {
            (bits.get(u32::try_from(index).ok()?) == Some(true)).then_some(validator.pubkey)
        })
        .collect()
}

/// Aggregate check for a quorum certificate over `validators`.
fn quorum_request(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    quorum: &neutrino_consensus_types::QuorumCertificate,
) -> FactRequest {
    FactRequest::Aggregate {
        keys: marked_keys(validators, &quorum.aggregate.aggregation_bits),
        message: quorum.data.signing_message(domain),
        signature: quorum.aggregate.signature,
    }
}

/// Leader proposal signature plus every signature inside its round-change
/// certificate, so a chunk's proposal checks can be answered from facts.
pub fn proposal_requests(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    proposal: &neutrino_consensus_types::BftProposal,
) -> Vec<FactRequest> {
    let mut requests = Vec::new();
    if let Some(validator) = validators.get(proposal.proposer_index as usize) {
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: proposal.signing_message(domain),
            signature: proposal.signature,
            possession: false,
        });
    }
    if let Some(certificate) = &proposal.round_change_certificate {
        requests.extend(round_change_certificate_requests(
            domain,
            validators,
            certificate,
        ));
    }
    requests
}

/// Round-change report signature and its carried highest quorum, if any.
pub fn round_change_requests(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    report: &neutrino_consensus_types::RoundChange,
) -> Vec<FactRequest> {
    let mut requests = Vec::new();
    if let Some(validator) = validators.get(report.validator_index as usize) {
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: report.signing_message(domain),
            signature: report.signature,
            possession: false,
        });
    }
    if let Some(quorum) = &report.highest_quorum {
        requests.push(quorum_request(domain, validators, quorum));
    }
    requests
}

/// Every signature a round-change certificate carries.
pub fn round_change_certificate_requests(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    certificate: &neutrino_consensus_types::RoundChangeCertificate,
) -> Vec<FactRequest> {
    certificate
        .reports
        .iter()
        .flat_map(|report| round_change_requests(domain, validators, report))
        .collect()
}

/// Exact nil signatures available for early cryptographic fact compression.
pub fn nil_vote_requests(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &neutrino_consensus_types::NilVote,
) -> Vec<FactRequest> {
    let mut requests = Vec::new();
    let message = vote.data.signing_message(domain);
    requests.push(FactRequest::Aggregate {
        keys: marked_keys(validators, &vote.aggregation_bits),
        message: message.clone(),
        signature: vote.signature,
    });
    for claim in &vote.attestations {
        let Some(validator) = validators.get(claim.validator_index as usize) else {
            continue;
        };
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: message.clone(),
            signature: claim.vote_signature,
            possession: false,
        });
        requests.push(FactRequest::Signature {
            key: validator.pubkey,
            message: claim.signing_message(domain),
            signature: claim.signature,
            possession: false,
        });
    }
    requests
}

/// Header authentication and VRF facts can be compressed before finality.
pub fn header_requests(
    domain: neutrino_primitives::ConsensusDomain,
    validators: &[Validator],
    seed: &Hash,
    header: &neutrino_consensus_types::Header,
) -> Vec<FactRequest> {
    let Some(validator) = validators.get(header.proposer_index as usize) else {
        return Vec::new();
    };
    let message = domain.signing_message(neutrino_primitives::DOMAIN_PROPOSER_SIG, &header.hash());
    alloc::vec![
        FactRequest::Signature {
            key: validator.pubkey,
            message,
            signature: header.signature,
            possession: false
        },
        FactRequest::Signature {
            key: validator.pubkey,
            message: neutrino_vrf::vrf_message(domain, seed, header.slot),
            signature: header.vrf_proof,
            possession: false
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn block_proof() -> BlockProof {
        BlockProof {
            height: 3,
            block_hash: [4; 32],
            public_inputs: neutrino_consensus_types::BlockProofPublicInputs {
                chain_id: 1,
                height: 3,
                parent_block_hash: [2; 32],
                block_hash: [4; 32],
                state_root_before: [5; 32],
                state_root_after: [6; 32],
                transactions_root: [7; 32],
                receipt_root: [8; 32],
                da_root: [9; 32],
                vm_code_hash: [10; 32],
                block_program: [11; 8],
                gas_used: 12,
                gas_limit: 13,
                proposer_address: [14; 32],
                runtime_extra: [15; 32],
            },
            proof_bytes: vec![16, 17],
        }
    }

    #[test]
    fn borrowed_requests_encode_and_identify_like_owned_requests() {
        let requests = [
            FactRequest::Signature {
                key: [1; 48],
                message: vec![2, 3],
                signature: [4; 96],
                possession: false,
            },
            FactRequest::Signature {
                key: [1; 48],
                message: vec![1; 48],
                signature: [4; 96],
                possession: true,
            },
            FactRequest::Aggregate {
                keys: vec![[5; 48], [6; 48]],
                message: Vec::new(),
                signature: [7; 96],
            },
            FactRequest::Block {
                key: [8; 8],
                proof: block_proof(),
            },
        ];
        for request in &requests {
            let borrowed = request.borrowed();
            assert_eq!(
                borsh::to_vec(&borrowed).unwrap(),
                borsh::to_vec(request).unwrap()
            );
            assert_eq!(
                request.id(),
                commitment(&(b"neutrino-cryptographic-fact", request))
            );
            assert_eq!(borrowed.id(), request.id());
            assert_eq!(&borrowed.to_request(), request);
        }
    }
}
