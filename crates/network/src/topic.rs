//! Canonical gossip topic registry.
//!
//! All topics follow the structure `/neutrino/<topic>/<format>/<version>` as
//! defined in `docs/design/06-networking.md`. The wire format is always
//! `borsh` and the version is `1`.
//!
//! Per-topic transmission byte caps, also defined in doc 06, are enforced on
//! the gossipsub `Config` at service construction.

use core::fmt;

/// Number of aggregate finality-vote subnets from doc 06.
pub const VOTE_SUBNETS: u8 = 16;

/// The set of canonical Neutrino gossip topics.
///
/// Every variant maps to a stable, versioned protocol string. The mapping is
/// consensus-relevant: changing it without bumping the version constitutes a
/// hard fork at the networking layer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Topic {
    /// `/neutrino/blocks/borsh/1`: full block (header + body) gossip.
    Blocks,
    /// `/neutrino/txs/borsh/1`: mempool transaction gossip.
    Transactions,
    /// `/neutrino/slashing_evidence/borsh/1`: objective slashing reports.
    SlashingEvidence,
    /// `/neutrino/block_proofs/borsh/1`: per-block validity proofs.
    BlockProofs,
    /// `/neutrino/chunk_proofs/borsh/1`: aggregated chunk proofs.
    ChunkProofs,
    /// `/neutrino/checkpoints/borsh/1`: recursive checkpoint proofs.
    Checkpoints,
    /// `/neutrino/prover_bounty/borsh/1`: missed-deadline bounty announcements.
    ProverBounty,
    /// `/neutrino/finality_votes_prevote/borsh/1`: BFT prevote votes.
    FinalityVotesPrevote,
    /// `/neutrino/finality_votes_precommit/borsh/1`: BFT precommit votes.
    FinalityVotesPrecommit,
    /// `/neutrino/aggregate_finality_votes_<subnet>/borsh/1` for `subnet` in
    /// `0..VOTE_SUBNETS`.
    AggregateFinalityVotes(u8),
}

impl Topic {
    /// All non-subnet topics, in canonical order.
    pub const STATIC: [Self; 9] = [
        Self::Blocks,
        Self::Transactions,
        Self::SlashingEvidence,
        Self::BlockProofs,
        Self::ChunkProofs,
        Self::Checkpoints,
        Self::ProverBounty,
        Self::FinalityVotesPrevote,
        Self::FinalityVotesPrecommit,
    ];

    /// All default gossip topics, including the 16 aggregate-vote subnet topics.
    pub fn all_default() -> impl Iterator<Item = Self> {
        Self::STATIC
            .into_iter()
            .chain((0..VOTE_SUBNETS).map(Self::AggregateFinalityVotes))
    }

    /// Whether an aggregate finality-vote subnet is in the doc-06 default range.
    #[must_use]
    pub const fn valid_aggregate_subnet(subnet: u8) -> bool {
        subnet < VOTE_SUBNETS
    }

    /// Maximum permitted transmission size in bytes, per doc 06.
    ///
    /// Enforced by gossipsub via `set_topic_max_transmit_size`. Messages
    /// larger than this are dropped before propagation.
    #[must_use]
    pub const fn max_transmit_size(self) -> usize {
        match self {
            Self::BlockProofs => 2 * 1024 * 1024,
            Self::Blocks | Self::ChunkProofs => 8 * 1024 * 1024,
            Self::Checkpoints => 64 * 1024,
            Self::FinalityVotesPrevote
            | Self::FinalityVotesPrecommit
            | Self::AggregateFinalityVotes(_)
            | Self::ProverBounty => 4 * 1024,
            Self::Transactions => 128 * 1024,
            Self::SlashingEvidence => 16 * 1024,
        }
    }

    /// Canonical protocol string, e.g. `/neutrino/blocks/borsh/1`.
    #[must_use]
    pub fn protocol_string(self) -> String {
        match self {
            Self::Blocks => "/neutrino/blocks/borsh/1".to_owned(),
            Self::Transactions => "/neutrino/txs/borsh/1".to_owned(),
            Self::SlashingEvidence => "/neutrino/slashing_evidence/borsh/1".to_owned(),
            Self::BlockProofs => "/neutrino/block_proofs/borsh/1".to_owned(),
            Self::ChunkProofs => "/neutrino/chunk_proofs/borsh/1".to_owned(),
            Self::Checkpoints => "/neutrino/checkpoints/borsh/1".to_owned(),
            Self::ProverBounty => "/neutrino/prover_bounty/borsh/1".to_owned(),
            Self::FinalityVotesPrevote => "/neutrino/finality_votes_prevote/borsh/1".to_owned(),
            Self::FinalityVotesPrecommit => "/neutrino/finality_votes_precommit/borsh/1".to_owned(),
            Self::AggregateFinalityVotes(subnet) => {
                format!("/neutrino/aggregate_finality_votes_{subnet}/borsh/1")
            }
        }
    }

    /// Convert to a libp2p [`libp2p::gossipsub::IdentTopic`].
    #[must_use]
    pub fn to_ident(self) -> libp2p::gossipsub::IdentTopic {
        libp2p::gossipsub::IdentTopic::new(self.protocol_string())
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.protocol_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_strings_match_doc_06() {
        assert_eq!(Topic::Blocks.protocol_string(), "/neutrino/blocks/borsh/1");
        assert_eq!(
            Topic::Transactions.protocol_string(),
            "/neutrino/txs/borsh/1"
        );
        assert_eq!(
            Topic::SlashingEvidence.protocol_string(),
            "/neutrino/slashing_evidence/borsh/1"
        );
        assert_eq!(
            Topic::BlockProofs.protocol_string(),
            "/neutrino/block_proofs/borsh/1"
        );
        assert_eq!(
            Topic::ChunkProofs.protocol_string(),
            "/neutrino/chunk_proofs/borsh/1"
        );
        assert_eq!(
            Topic::Checkpoints.protocol_string(),
            "/neutrino/checkpoints/borsh/1"
        );
        assert_eq!(
            Topic::ProverBounty.protocol_string(),
            "/neutrino/prover_bounty/borsh/1"
        );
        assert_eq!(
            Topic::FinalityVotesPrevote.protocol_string(),
            "/neutrino/finality_votes_prevote/borsh/1"
        );
        assert_eq!(
            Topic::FinalityVotesPrecommit.protocol_string(),
            "/neutrino/finality_votes_precommit/borsh/1"
        );
        assert_eq!(
            Topic::AggregateFinalityVotes(0).protocol_string(),
            "/neutrino/aggregate_finality_votes_0/borsh/1"
        );
        assert_eq!(
            Topic::AggregateFinalityVotes(15).protocol_string(),
            "/neutrino/aggregate_finality_votes_15/borsh/1"
        );
    }

    #[test]
    fn static_topics_are_unique() {
        let strings: Vec<_> = Topic::all_default().map(Topic::protocol_string).collect();
        let mut sorted = strings.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), strings.len());
    }

    #[test]
    fn max_transmit_sizes_match_doc_06() {
        assert_eq!(Topic::Blocks.max_transmit_size(), 8 * 1024 * 1024);
        assert_eq!(Topic::BlockProofs.max_transmit_size(), 2 * 1024 * 1024);
        assert_eq!(Topic::ChunkProofs.max_transmit_size(), 8 * 1024 * 1024);
        assert_eq!(Topic::Checkpoints.max_transmit_size(), 64 * 1024);
        assert_eq!(Topic::FinalityVotesPrevote.max_transmit_size(), 4 * 1024);
        assert_eq!(Topic::FinalityVotesPrecommit.max_transmit_size(), 4 * 1024);
        assert_eq!(
            Topic::AggregateFinalityVotes(0).max_transmit_size(),
            4 * 1024
        );
        assert_eq!(Topic::Transactions.max_transmit_size(), 128 * 1024);
        assert_eq!(Topic::SlashingEvidence.max_transmit_size(), 16 * 1024);
    }

    #[test]
    fn default_topic_set_includes_all_aggregate_subnets() {
        let topics: Vec<_> = Topic::all_default().collect();
        assert!(topics.contains(&Topic::AggregateFinalityVotes(0)));
        assert!(topics.contains(&Topic::AggregateFinalityVotes(15)));
        assert!(!topics.contains(&Topic::AggregateFinalityVotes(16)));
        assert_eq!(
            topics.len(),
            Topic::STATIC.len() + usize::from(VOTE_SUBNETS)
        );
    }
}
