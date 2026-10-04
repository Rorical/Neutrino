//! Persistent, phase-aware deadlines and authenticated round synchronization.

use alloc::{collections::BTreeMap, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrino_consensus_types::{RoundChange, RoundChangeCertificate};
use neutrino_primitives::Validator;

use crate::{BftError, quorum_reached, total_active_stake};

/// Current local signing phase. Received votes remain useful in every phase.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoundStep {
    /// Wait for the designated leader's independently valid proposal.
    Propose,
    /// Collect value/nil prevotes before choosing a precommit.
    Prevote,
    /// Collect value/nil precommits before changing round.
    Precommit,
    /// Local timeout has emitted its next-round report.
    AwaitRound,
}

/// Required local action when a phase's deadline expires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeoutAction {
    /// No legal timely proposal: sign an explicit nil prevote.
    PrevoteNil,
    /// No value QC: sign an explicit nil precommit while preserving every lock.
    PrecommitNil,
    /// Signed readiness for a later round after completing this round's phases.
    RoundChange {
        /// Exact requested next round.
        round: u32,
    },
}

/// Phase deadlines and bounded signed-report collection, durable with the session.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct Pacemaker {
    chunk_id: u64,
    round: u32,
    step: RoundStep,
    deadline: u64,
    base_timeout: u64,
    timeout_step: u64,
    reports: BTreeMap<u32, BTreeMap<u32, RoundChange>>,
}

impl Pacemaker {
    /// Start at propose with an increasing per-round deadline.
    /// A positive backoff is required for unknown eventual network delay.
    #[must_use]
    pub fn new(chunk_id: u64, round: u32, now: u64, base_timeout: u64, timeout_step: u64) -> Self {
        let mut state = Self {
            chunk_id,
            round,
            step: RoundStep::Propose,
            deadline: now,
            base_timeout: base_timeout.max(1),
            timeout_step: timeout_step.max(1),
            reports: BTreeMap::new(),
        };
        state.reset_deadline(now);
        state
    }

    /// Current round.
    #[must_use]
    pub const fn round(&self) -> u32 {
        self.round
    }

    /// Current local phase.
    #[must_use]
    pub const fn step(&self) -> RoundStep {
        self.step
    }

    /// Absolute phase deadline in the caller's monotonic clock units.
    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }

    /// A legal proposal has selected the local prevote; never rewind a later phase.
    pub fn enter_prevote(&mut self, now: u64) {
        if self.step == RoundStep::Propose {
            self.step = RoundStep::Prevote;
            self.reset_deadline(now);
        }
    }

    /// A verified value/nil QC selects precommit; never rewind an emitted report.
    pub fn enter_precommit(&mut self, now: u64) {
        if matches!(self.step, RoundStep::Propose | RoundStep::Prevote) {
            self.step = RoundStep::Precommit;
            self.reset_deadline(now);
        }
    }

    /// Finish this round before reporting readiness for the next one.
    /// Duplicate quorum observations cannot postpone retransmission deadlines.
    pub fn enter_await_round(&mut self, now: u64) {
        if self.step != RoundStep::AwaitRound {
            self.step = RoundStep::AwaitRound;
            self.reset_deadline(now);
        }
    }

    /// Emit each deadline action once. Nil never changes or clears a value lock.
    pub fn on_timeout(&mut self, now: u64) -> Option<TimeoutAction> {
        if now < self.deadline {
            return None;
        }
        let action = match self.step {
            RoundStep::Propose => {
                self.step = RoundStep::Prevote;
                TimeoutAction::PrevoteNil
            }
            RoundStep::Prevote => {
                self.step = RoundStep::Precommit;
                TimeoutAction::PrecommitNil
            }
            RoundStep::Precommit => {
                let round = self.round.checked_add(1)?;
                self.step = RoundStep::AwaitRound;
                TimeoutAction::RoundChange { round }
            }
            RoundStep::AwaitRound => TimeoutAction::RoundChange {
                round: self.round.checked_add(1)?,
            },
        };
        self.reset_deadline(now);
        Some(action)
    }

    /// Advance after independently verified quorum-certified round entry.
    /// The caller persists this transition before any new-round signing.
    pub fn advance_round(&mut self, round: u32, now: u64) -> Result<(), BftError> {
        if round <= self.round {
            return Err(BftError::RoundNotIncreased {
                current: self.round,
                requested: round,
            });
        }
        self.round = round;
        self.step = RoundStep::Propose;
        self.reports.retain(|reported, _| *reported > round);
        self.reset_deadline(now);
        Ok(())
    }

    /// Validate the immutable context before restoring durable phase state.
    #[must_use]
    pub const fn context_matches(&self, chunk_id: u64, round: u32, base: u64, step: u64) -> bool {
        self.chunk_id == chunk_id
            && self.round == round
            && self.base_timeout == if base == 0 { 1 } else { base }
            && self.timeout_step == if step == 0 { 1 } else { step }
    }

    /// Reauthenticate every saved report instead of trusting serialized state.
    pub fn validate_saved_reports(
        &self,
        domain: neutrino_primitives::ConsensusDomain,
        validators: &[Validator],
        fraction: (u64, u64),
    ) -> Result<(), BftError> {
        if self.reports.len() > 2 {
            return Err(BftError::WrongVoteTarget);
        }
        for (round, reports) in &self.reports {
            if *round <= self.round || reports.len() > validators.len() {
                return Err(BftError::WrongVoteTarget);
            }
            for (index, report) in reports {
                if report.chunk_id != self.chunk_id
                    || report.round != *round
                    || report.validator_index != *index
                {
                    return Err(BftError::WrongVoteTarget);
                }
                crate::verify_round_change_native(domain, validators, report, fraction)?;
            }
        }
        Ok(())
    }

    /// Collect independently authenticated readiness; one report per signer/round.
    /// Two nearest future rounds bound memory. Full certificates may authenticate
    /// direct catchup from any later round without trusting isolated hints.
    pub fn accept_round_change(
        &mut self,
        domain: neutrino_primitives::ConsensusDomain,
        validators: &[Validator],
        fraction: (u64, u64),
        report: RoundChange,
    ) -> Result<Option<RoundChangeCertificate>, BftError> {
        if report.chunk_id != self.chunk_id || report.round <= self.round {
            return Err(BftError::WrongVoteTarget);
        }
        crate::verify_round_change_native(domain, validators, &report, fraction)?;
        let reported_round = report.round;
        let reports = self.reports.entry(reported_round).or_default();
        if let Some(existing) = reports.get(&report.validator_index) {
            if existing != &report {
                return Err(BftError::WrongVoteTarget);
            }
        } else {
            reports.insert(report.validator_index, report);
        }
        while self.reports.len() > 2 {
            let last = *self.reports.last_key_value().expect("nonempty reports").0;
            self.reports.remove(&last);
        }
        let Some(reports) = self.reports.get(&reported_round) else {
            return Ok(None);
        };
        let stake = reports.keys().try_fold(0_u64, |stake, index| {
            stake
                .checked_add(validators[*index as usize].effective_stake)
                .ok_or(BftError::StakeOverflow)
        })?;
        if !quorum_reached(stake, total_active_stake(validators)?, fraction) {
            return Ok(None);
        }
        Ok(Some(RoundChangeCertificate {
            chunk_id: self.chunk_id,
            round: reported_round,
            reports: reports.values().cloned().collect::<Vec<_>>(),
        }))
    }

    fn reset_deadline(&mut self, now: u64) {
        self.deadline = now.saturating_add(
            self.base_timeout
                .saturating_add(u64::from(self.round).saturating_mul(self.timeout_step)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn test_domain() -> neutrino_primitives::ConsensusDomain {
        neutrino_primitives::ConsensusDomain {
            chain_id: 7,
            chain_spec_hash: [1; 32],
        }
    }

    fn validators() -> Vec<Validator> {
        (1..=4)
            .map(|byte| Validator {
                pubkey: neutrino_crypto::bls::SecretKey::key_gen(&[byte; 32], &[])
                    .unwrap()
                    .public_key()
                    .to_bytes(),
                withdrawal_credentials: [0; 32],
                effective_stake: 100,
                slashed: false,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                last_active_chunk: 0,
            })
            .collect()
    }

    fn report(index: u32, round: u32) -> RoundChange {
        let key =
            neutrino_crypto::bls::SecretKey::key_gen(&[u8::try_from(index + 1).unwrap(); 32], &[])
                .unwrap();
        let mut report = RoundChange {
            chunk_id: 0,
            round,
            validator_index: index,
            highest_quorum: None,
            signature: [0; 96],
        };
        report.signature = key.sign(&report.signing_message(test_domain())).to_bytes();
        report
    }

    #[test]
    fn missing_leader_runs_nil_phases_before_certified_next_round_and_backoff() {
        let mut clock = Pacemaker::new(0, 0, 10, 2, 3);
        assert_eq!(clock.on_timeout(11), None);
        assert_eq!(clock.on_timeout(12), Some(TimeoutAction::PrevoteNil));
        assert_eq!(clock.step(), RoundStep::Prevote);
        assert_eq!(clock.on_timeout(14), Some(TimeoutAction::PrecommitNil));
        assert_eq!(
            clock.on_timeout(16),
            Some(TimeoutAction::RoundChange { round: 1 })
        );
        assert_eq!(clock.on_timeout(17), None);
        assert_eq!(
            clock.on_timeout(18),
            Some(TimeoutAction::RoundChange { round: 1 })
        );
        let validators = validators();
        assert_eq!(
            clock
                .accept_round_change(test_domain(), &validators, (2, 3), report(0, 1))
                .unwrap(),
            None
        );
        assert_eq!(
            clock
                .accept_round_change(test_domain(), &validators, (2, 3), report(1, 1))
                .unwrap(),
            None
        );
        let cert = clock
            .accept_round_change(test_domain(), &validators, (2, 3), report(2, 1))
            .unwrap()
            .unwrap();
        assert_eq!(cert.reports.len(), 3);
        assert_eq!(clock.round(), 0);
        clock.advance_round(cert.round, 18).unwrap();
        assert_eq!(clock.step(), RoundStep::Propose);
        assert_eq!(clock.deadline(), 23);
        assert_eq!(
            clock.advance_round(0, 18),
            Err(BftError::RoundNotIncreased {
                current: 1,
                requested: 0
            })
        );
    }

    #[test]
    fn nil_precommit_quorum_ends_old_phases_without_postponing_reports() {
        let mut clock = Pacemaker::new(0, 0, 10, 2, 3);
        clock.enter_await_round(11);
        assert_eq!(clock.step(), RoundStep::AwaitRound);
        assert_eq!(clock.deadline(), 13);
        clock.enter_prevote(12);
        clock.enter_precommit(12);
        clock.enter_await_round(12);
        assert_eq!(clock.step(), RoundStep::AwaitRound);
        assert_eq!(clock.deadline(), 13);
        assert_eq!(clock.on_timeout(12), None);
        assert_eq!(
            clock.on_timeout(13),
            Some(TimeoutAction::RoundChange { round: 1 })
        );
        assert_eq!(clock.round(), 0);
    }

    #[test]
    fn exact_durable_phase_and_reports_roundtrip_and_are_reauthenticated() {
        let validators = validators();
        let mut clock = Pacemaker::new(0, 2, 10, 2, 3);
        clock.enter_prevote(11);
        clock
            .accept_round_change(test_domain(), &validators, (2, 3), report(0, 3))
            .unwrap();
        let restored: Pacemaker = borsh::from_slice(&borsh::to_vec(&clock).unwrap()).unwrap();
        assert_eq!(restored, clock);
        assert!(restored.context_matches(0, 2, 2, 3));
        assert!(!restored.context_matches(1, 2, 2, 3));
        assert_eq!(
            restored.validate_saved_reports(test_domain(), &validators, (2, 3)),
            Ok(())
        );
        assert!(
            restored
                .validate_saved_reports(
                    neutrino_primitives::ConsensusDomain {
                        chain_id: 8,
                        ..test_domain()
                    },
                    &validators,
                    (2, 3)
                )
                .is_err()
        );
        let mut bad = restored;
        bad.reports
            .get_mut(&3)
            .unwrap()
            .get_mut(&0)
            .unwrap()
            .signature[0] ^= 1;
        assert!(
            bad.validate_saved_reports(test_domain(), &validators, (2, 3))
                .is_err()
        );
    }

    #[test]
    fn replayed_old_report_and_single_attacker_cannot_authenticate_round_catchup() {
        let validators = validators();
        let mut clock = Pacemaker::new(0, 1, 10, 2, 3);
        assert_eq!(
            clock.accept_round_change(test_domain(), &validators, (2, 3), report(0, 1)),
            Err(BftError::WrongVoteTarget)
        );
        for round in 2..20 {
            assert_eq!(
                clock
                    .accept_round_change(test_domain(), &validators, (2, 3), report(0, round))
                    .unwrap(),
                None
            );
        }
        assert_eq!(clock.round(), 1);
        assert_eq!(clock.reports.len(), 2);
        clock
            .accept_round_change(test_domain(), &validators, (2, 3), report(1, 2))
            .unwrap();
        assert!(
            clock
                .accept_round_change(test_domain(), &validators, (2, 3), report(2, 2))
                .unwrap()
                .is_some()
        );
    }
}
