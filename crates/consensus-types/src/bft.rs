//! Explicit value/nil voting, fair round leaders and signed pacemaker reports.

use alloc::{boxed::Box, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_primitives::{
    BitVec, BlsSignature, ConsensusDomain, DOMAIN_BFT_NIL, DOMAIN_BFT_NIL_ATTESTATION,
    DOMAIN_BFT_PROPOSAL, DOMAIN_BFT_ROUND_CHANGE, Validator, blake3_256,
};

use crate::{
    AggregatedVote, Chunk, FinalityVote, FinalityVoteData, FinalityVotePhase, QuorumCertificate,
    VoteAttestation,
};

/// Independently signed proposal from the designated leader of this round.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct BftProposal {
    /// Complete compact candidate; its block proofs are fetched separately.
    pub chunk: Chunk,
    /// Round for which the candidate is proposed.
    pub round: u32,
    /// Index in the authenticated active validator set.
    pub proposer_index: u32,
    /// Highest earlier prevote quorum known for this exact candidate.
    pub valid_quorum: Option<QuorumCertificate>,
    /// Authenticated entry into this nonzero round; absent only for round zero.
    pub round_change_certificate: Option<RoundChangeCertificate>,
    /// Signature binding all fields under the chain's proposal domain.
    pub signature: BlsSignature,
}

impl BftProposal {
    /// Canonical chain-bound signing bytes.
    #[must_use]
    pub fn signing_message(&self, domain: ConsensusDomain) -> Vec<u8> {
        signing_bytes(
            DOMAIN_BFT_PROPOSAL,
            domain,
            &(
                &self.chunk,
                self.round,
                self.proposer_index,
                &self.valid_quorum,
                &self.round_change_certificate,
            ),
        )
    }
}

/// An explicit vote for no value. A nil vote cannot finalize or erase a lock.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct NilVoteData {
    /// Chunk whose round is being advanced.
    pub chunk_id: u64,
    /// Round in which the validator did not select a value.
    pub round: u32,
    /// Prevote or precommit step; both sign this field.
    pub phase: FinalityVotePhase,
}

impl NilVoteData {
    /// Canonical chain-bound signing bytes, distinct from every value vote.
    #[must_use]
    pub fn signing_message(&self, domain: ConsensusDomain) -> Vec<u8> {
        signing_bytes(DOMAIN_BFT_NIL, domain, self)
    }
}

/// Individual signatures retained when a nil vote is aggregated.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct NilVoteAttestation {
    /// Index of the accountable signer.
    pub validator_index: u32,
    /// Exact nil vote.
    pub vote: NilVoteData,
    /// Individual signature of that nil vote.
    pub vote_signature: BlsSignature,
    /// Additional signature binding signer identity and retained vote signature.
    pub signature: BlsSignature,
}

impl NilVoteAttestation {
    /// Canonical chain-bound accountability signature bytes.
    #[must_use]
    pub fn signing_message(&self, domain: ConsensusDomain) -> Vec<u8> {
        signing_bytes(
            DOMAIN_BFT_NIL_ATTESTATION,
            domain,
            &(self.validator_index, &self.vote, &self.vote_signature),
        )
    }
}

/// Aggregate nil vote with complete individual signer coverage.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct NilVote {
    /// Signed nil payload.
    pub data: NilVoteData,
    /// Exact signers in the aggregate.
    pub aggregation_bits: BitVec,
    /// Aggregate signature of the nil payload.
    pub signature: BlsSignature,
    /// Individually signed accountable statements for every included signer.
    pub attestations: Vec<NilVoteAttestation>,
}

/// An independently signed nil vote used in objective equivocation evidence.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct IndexedNilVote {
    /// Exact nil payload.
    pub data: NilVoteData,
    /// The accused validator's individual signature.
    pub signature: BlsSignature,
}

/// Current BFT vote wire format with disjoint explicit nil and value targets.
#[derive(BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum BftVote {
    /// Vote for a particular proven chunk.
    Value(FinalityVote),
    /// Vote for no value during this phase.
    Nil(NilVote),
}

/// Signed readiness to enter a round, preserving the highest observed value QC.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct RoundChange {
    /// Chunk whose consensus session is advancing.
    pub chunk_id: u64,
    /// New round requested by this report.
    pub round: u32,
    /// Accountable active validator index.
    pub validator_index: u32,
    /// Highest earlier value prevote QC known to the signer.
    pub highest_quorum: Option<QuorumCertificate>,
    /// Chain-bound signature of the exact report and carried quorum.
    pub signature: BlsSignature,
}

impl RoundChange {
    /// Canonical chain-bound signing bytes.
    #[must_use]
    pub fn signing_message(&self, domain: ConsensusDomain) -> Vec<u8> {
        signing_bytes(
            DOMAIN_BFT_ROUND_CHANGE,
            domain,
            &(
                self.chunk_id,
                self.round,
                self.validator_index,
                &self.highest_quorum,
            ),
        )
    }
}

/// Unique signed reports with a quorum of authenticated active stake.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct RoundChangeCertificate {
    /// Chunk receiving a pacemaker certificate.
    pub chunk_id: u64,
    /// Exact new round shared by all reports.
    pub round: u32,
    /// Unique per-validator reports; the signatures may carry different QCs.
    pub reports: Vec<RoundChange>,
}

impl RoundChangeCertificate {
    /// The highest independently verified value QC carried by the certificate.
    /// Equal-round certificates are selected deterministically by target hash.
    #[must_use]
    pub fn highest_quorum(&self) -> Option<&QuorumCertificate> {
        self.reports
            .iter()
            .filter_map(|report| report.highest_quorum.as_ref())
            .max_by_key(|quorum| (quorum.data.round, quorum.data.chunk_hash))
    }
}

/// Bounded gossip envelope used by the live round protocol.
#[derive(BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum BftMessage {
    /// Signed leader proposal.
    Proposal(Box<BftProposal>),
    /// Explicit value or nil vote.
    Vote(BftVote),
    /// Signed pacemaker report.
    RoundChange(RoundChange),
    /// Quorum-certified catchup to a later round.
    RoundChangeCertificate(RoundChangeCertificate),
}

/// Select a fair leader from positive-stake, unslashed validator indices.
///
/// A chain/chunk/set-bound offset rotates deterministic round-robin order. Every
/// eligible validator receives one turn in every complete cycle; stake controls
/// quorum weights without permitting a large balance to monopolize leadership.
#[must_use]
pub fn bft_leader(
    chain_id: u64,
    chunk_id: u64,
    round: u32,
    validators: &[Validator],
) -> Option<u32> {
    let eligible: Vec<_> = validators
        .iter()
        .enumerate()
        .filter(|(_, validator)| !validator.slashed && validator.effective_stake > 0)
        .map(|(index, _)| u32::try_from(index).ok())
        .collect::<Option<_>>()?;
    let count = u64::try_from(eligible.len())
        .ok()
        .filter(|count| *count > 0)?;
    let root = blake3_256(&borsh::to_vec(validators).ok()?);
    let mut leader_input = Vec::from(DOMAIN_BFT_PROPOSAL);
    leader_input.extend_from_slice(&chain_id.to_le_bytes());
    leader_input.extend_from_slice(&borsh::to_vec(&(chunk_id, root)).ok()?);
    let offset = blake3_256(&leader_input);
    let offset = u64::from_le_bytes(offset[..8].try_into().ok()?) % count;
    let index = (offset + u64::from(round)) % count;
    eligible.get(usize::try_from(index).ok()?).copied()
}

fn signing_bytes(tag: [u8; 16], domain: ConsensusDomain, payload: &impl BorshSerialize) -> Vec<u8> {
    domain.signing_message(tag, &borsh::to_vec(payload).expect("canonical BFT payload"))
}

/// Local transport bound, matching candidate retrieval rather than consensus membership.
pub const MAX_BFT_SIGNERS: u32 = crate::candidate::MAX_CANDIDATE_SIGNERS;
/// Local transport bound on accepted proof-envelope hashes per signer.
pub const MAX_BFT_PROOF_HASHES: u32 = 65_536;

fn read_bounded_vec<T: BorshDeserialize, R: borsh::io::Read>(
    reader: &mut R,
    max: u32,
) -> borsh::io::Result<Vec<T>> {
    let count = u32::deserialize_reader(reader)?;
    if count > max {
        return Err(invalid_wire("BFT vector exceeds transport bound"));
    }
    let mut values = Vec::new();
    for _ in 0..count {
        values.push(T::deserialize_reader(reader)?);
    }
    Ok(values)
}

fn read_bitmap<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<BitVec> {
    let bit_len = u32::deserialize_reader(reader)?;
    let byte_len = u32::deserialize_reader(reader)?;
    if bit_len > MAX_BFT_SIGNERS || byte_len != bit_len.div_ceil(8) {
        return Err(invalid_wire("BFT bitmap exceeds transport bound"));
    }
    let mut bytes = Vec::new();
    for _ in 0..byte_len {
        bytes.push(u8::deserialize_reader(reader)?);
    }
    BitVec::from_bytes(bit_len, bytes).map_err(|_| invalid_wire("noncanonical BFT bitmap"))
}

fn invalid_wire(message: &str) -> borsh::io::Error {
    borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, message)
}

/// Decode a value quorum with local transport bitmap bounds.
pub fn read_quorum<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<QuorumCertificate> {
    Ok(QuorumCertificate {
        data: FinalityVoteData::deserialize_reader(reader)?,
        aggregate: AggregatedVote {
            aggregation_bits: read_bitmap(reader)?,
            signature: BlsSignature::deserialize_reader(reader)?,
        },
    })
}

fn read_optional_quorum<R: borsh::io::Read>(
    reader: &mut R,
) -> borsh::io::Result<Option<QuorumCertificate>> {
    match u8::deserialize_reader(reader)? {
        0 => Ok(None),
        1 => Ok(Some(read_quorum(reader)?)),
        _ => Err(invalid_wire("invalid BFT quorum option")),
    }
}

fn read_value_claim<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<VoteAttestation> {
    Ok(VoteAttestation {
        vote_signature: BlsSignature::deserialize_reader(reader)?,
        validator_index: u32::deserialize_reader(reader)?,
        vote: FinalityVoteData::deserialize_reader(reader)?,
        proof_hashes: read_bounded_vec(reader, MAX_BFT_PROOF_HASHES)?,
        unlock_quorum: read_optional_quorum(reader)?,
        signature: BlsSignature::deserialize_reader(reader)?,
    })
}

/// Decode a value vote with local transport bitmap and attestation bounds.
pub fn read_value<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<FinalityVote> {
    let aggregation_bits = read_bitmap(reader)?;
    let data = FinalityVoteData::deserialize_reader(reader)?;
    let signature = BlsSignature::deserialize_reader(reader)?;
    let count = u32::deserialize_reader(reader)?;
    if count > MAX_BFT_SIGNERS {
        return Err(invalid_wire(
            "BFT value attestations exceed transport bound",
        ));
    }
    let mut attestations = Vec::new();
    for _ in 0..count {
        attestations.push(read_value_claim(reader)?);
    }
    Ok(FinalityVote {
        aggregation_bits,
        data,
        signature,
        attestations,
    })
}

/// Decode an explicit nil vote with local transport allocation bounds.
pub fn read_nil<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<NilVote> {
    Ok(NilVote {
        data: NilVoteData::deserialize_reader(reader)?,
        aggregation_bits: read_bitmap(reader)?,
        signature: BlsSignature::deserialize_reader(reader)?,
        attestations: read_bounded_vec(reader, MAX_BFT_SIGNERS)?,
    })
}

/// Decode a round-leader proposal with local transport allocation bounds.
/// Core proposal decoding remains the canonical protocol codec.
pub fn read_proposal<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<BftProposal> {
    let chunk = Chunk::deserialize_reader(reader)?;
    let round = u32::deserialize_reader(reader)?;
    let proposer_index = u32::deserialize_reader(reader)?;
    let valid_quorum = read_optional_quorum(reader)?;
    let round_change_certificate = match u8::deserialize_reader(reader)? {
        0 => None,
        1 => Some(read_round_change_certificate(reader)?),
        _ => return Err(invalid_wire("invalid BFT round-entry option")),
    };
    Ok(BftProposal {
        chunk,
        round,
        proposer_index,
        valid_quorum,
        round_change_certificate,
        signature: BlsSignature::deserialize_reader(reader)?,
    })
}

/// Decode a signed round-change report with local transport quorum bounds.
pub fn read_round_change<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<RoundChange> {
    Ok(RoundChange {
        chunk_id: u64::deserialize_reader(reader)?,
        round: u32::deserialize_reader(reader)?,
        validator_index: u32::deserialize_reader(reader)?,
        highest_quorum: read_optional_quorum(reader)?,
        signature: BlsSignature::deserialize_reader(reader)?,
    })
}

/// Decode a pacemaker certificate with local transport allocation bounds.
pub fn read_round_change_certificate<R: borsh::io::Read>(
    reader: &mut R,
) -> borsh::io::Result<RoundChangeCertificate> {
    let chunk_id = u64::deserialize_reader(reader)?;
    let round = u32::deserialize_reader(reader)?;
    let count = u32::deserialize_reader(reader)?;
    if count > MAX_BFT_SIGNERS {
        return Err(invalid_wire("BFT reports exceed transport bound"));
    }
    let mut reports = Vec::new();
    for _ in 0..count {
        reports.push(read_round_change(reader)?);
    }
    Ok(RoundChangeCertificate {
        chunk_id,
        round,
        reports,
    })
}

impl BorshDeserialize for BftVote {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        match u8::deserialize_reader(reader)? {
            0 => Ok(Self::Value(read_value(reader)?)),
            1 => Ok(Self::Nil(read_nil(reader)?)),
            _ => Err(invalid_wire("invalid BFT vote target")),
        }
    }
}

impl BorshDeserialize for BftMessage {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        match u8::deserialize_reader(reader)? {
            0 => Ok(Self::Proposal(Box::new(read_proposal(reader)?))),
            1 => Ok(Self::Vote(BftVote::deserialize_reader(reader)?)),
            2 => Ok(Self::RoundChange(read_round_change(reader)?)),
            3 => Ok(Self::RoundChangeCertificate(read_round_change_certificate(
                reader,
            )?)),
            _ => Err(invalid_wire("invalid BFT message")),
        }
    }
}
