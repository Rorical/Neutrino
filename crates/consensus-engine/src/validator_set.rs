//! Validator-set commitment helpers shared by genesis and per-chunk
//! computations.
//!
//! The doc-level definition is "Merkle root of `(pubkey, stake, status)`
//! records over the active set". For M5 we commit to the canonical
//! borsh encoding of the full validator vector via BLAKE3, which is
//! collision-equivalent to a Merkle tree over its leaves for the
//! single-list use case and trivial to recompute deterministically.
//! Future milestones can swap in an incremental Merkle tree without
//! changing the call sites.

use neutrino_primitives::{Hash, Validator, blake3_256};

/// Compute the canonical validator-set commitment for `validators`.
///
/// The commitment is `BLAKE3(borsh(validators))`. The empty set commits
/// to `BLAKE3(borsh(Vec::<Validator>::new()))`, which is non-zero by
/// construction.
#[must_use]
pub fn validator_set_root(validators: &[Validator]) -> Hash {
    let bytes = borsh::to_vec(&validators.to_vec())
        .expect("borsh serialization of Vec<Validator> is infallible");
    blake3_256(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutrino_primitives::{BlsPublicKey, ZERO_HASH};

    fn validator(byte: u8, stake: u64) -> Validator {
        Validator {
            pubkey: [byte; 48],
            withdrawal_credentials: [byte; 32],
            effective_stake: stake,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        }
    }

    #[test]
    fn empty_set_root_is_deterministic_and_nonzero() {
        let r = validator_set_root(&[]);
        assert_ne!(r, ZERO_HASH);
        assert_eq!(r, validator_set_root(&[]));
    }

    #[test]
    fn distinct_sets_produce_distinct_roots() {
        let a = vec![validator(1, 1_000_000)];
        let b = vec![validator(1, 1_000_001)];
        let c = vec![validator(2, 1_000_000)];
        let ra = validator_set_root(&a);
        let rb = validator_set_root(&b);
        let rc = validator_set_root(&c);
        assert_ne!(ra, rb);
        assert_ne!(ra, rc);
        assert_ne!(rb, rc);
    }

    #[test]
    fn root_is_order_sensitive() {
        let v1 = validator(1, 1_000_000);
        let v2 = validator(2, 1_000_000);
        let ab = validator_set_root(&[v1.clone(), v2.clone()]);
        let ba = validator_set_root(&[v2, v1]);
        assert_ne!(ab, ba);
    }

    #[test]
    fn root_is_deterministic_across_runs() {
        let pubkey: BlsPublicKey = [7; 48];
        let v = Validator {
            pubkey,
            withdrawal_credentials: [9; 32],
            effective_stake: 32_000_000_000,
            slashed: false,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            last_active_chunk: 0,
        };
        let r1 = validator_set_root(std::slice::from_ref(&v));
        let r2 = validator_set_root(std::slice::from_ref(&v));
        assert_eq!(r1, r2);
    }
}
