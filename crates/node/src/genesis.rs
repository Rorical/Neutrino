//! Deterministic genesis runtime state derived from a [`ChainSpecFile`].
//!
//! Every node materialises the same trie from the same spec file, so the
//! allocation never has to be distributed separately. The resulting root is
//! bound into the chain spec hash through `genesis_state_root`, which peers
//! compare at handshake.

use neutrino_default_runtime_core::{
    Account, VALIDATOR_SET_KEY, Validator as RuntimeValidator, ValidatorSet, account_key,
    encode_account, encode_validator, validator_key,
};
use neutrino_primitives::{Hash, ZERO_HASH};
use neutrino_trie::Trie;

use crate::chain_spec::{ChainSpecError, ChainSpecFile, decode_hex_exact};

/// Genesis runtime state built from the spec's accounts and validators.
pub struct GenesisState {
    /// State trie holding every genesis record.
    pub trie: Trie,
    /// Root committed in the chain spec. All-zero when the allocation is
    /// empty, matching a spec that declares no runtime state.
    pub root: Hash,
    /// Number of funded accounts.
    pub accounts: usize,
    /// Number of validators with a runtime stake record.
    pub staked_validators: usize,
}

/// Build the genesis trie.
///
/// Each `[[accounts]]` entry seeds a nonce-zero balance. Each validator
/// with non-zero withdrawal credentials seeds a runtime validator record
/// whose stake equals its genesis `effective_stake` and joins the runtime
/// validator set, so sanctions can deduct from it and it can later exit.
/// Validators with all-zero credentials have no runtime identity and get
/// no record.
///
/// # Errors
/// Returns [`ChainSpecError`] on malformed hex, duplicate addresses or a
/// duplicate validator credential.
pub fn build_genesis_state(file: &ChainSpecFile) -> Result<GenesisState, ChainSpecError> {
    let mut trie = Trie::new();
    let mut entries = 0_usize;
    let mut seen_accounts = std::collections::BTreeSet::new();
    for (idx, entry) in file.accounts.iter().enumerate() {
        let field = format!("accounts[{idx}].address_hex");
        let address = decode_hex_exact::<32>(&entry.address_hex, &field)?;
        if !seen_accounts.insert(address) {
            return Err(ChainSpecError::Validation(format!(
                "duplicate genesis account {}",
                entry.address_hex
            )));
        }
        let account = Account {
            nonce: 0,
            balance: entry.balance,
        };
        trie.insert(&account_key(&address), encode_account(&account))
            .map_err(|err| ChainSpecError::Validation(format!("genesis trie: {err:?}")))?;
        entries += 1;
    }
    let mut set = ValidatorSet::default();
    let mut staked_validators = 0_usize;
    for (idx, validator) in file.validators.iter().enumerate() {
        let Some(hex) = validator.withdrawal_credentials_hex.as_deref() else {
            continue;
        };
        let field = format!("validators[{idx}].withdrawal_credentials_hex");
        let credentials = decode_hex_exact::<32>(hex, &field)?;
        if credentials == ZERO_HASH {
            continue;
        }
        if set.entries.iter().any(|entry| entry.address == credentials) {
            return Err(ChainSpecError::Validation(format!(
                "duplicate validator withdrawal credentials {hex}"
            )));
        }
        let stake = u128::from(validator.effective_stake);
        trie.insert(
            &validator_key(&credentials),
            encode_validator(&RuntimeValidator {
                stake,
                active: stake > 0,
            }),
        )
        .map_err(|err| ChainSpecError::Validation(format!("genesis trie: {err:?}")))?;
        if stake > 0 {
            set.upsert(credentials, stake);
        }
        staked_validators += 1;
        entries += 1;
    }
    if !set.entries.is_empty() {
        trie.insert(
            VALIDATOR_SET_KEY,
            borsh::to_vec(&set).expect("borsh encode ValidatorSet never fails"),
        )
        .map_err(|err| ChainSpecError::Validation(format!("genesis trie: {err:?}")))?;
    }
    let root = if entries == 0 { ZERO_HASH } else { trie.root() };
    Ok(GenesisState {
        trie,
        root,
        accounts: file.accounts.len(),
        staked_validators,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBKEY: &str = "010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748";

    fn spec(extra: &str) -> ChainSpecFile {
        ChainSpecFile::from_toml_str(&format!(
            r#"
name = "genesis-test"
chain_id = 7
genesis_time = 1700000000
genesis_gas_limit = 30000000
{extra}
[[validators]]
pubkey_hex = "{PUBKEY}"
withdrawal_credentials_hex = "{creds}"
effective_stake = 500
"#,
            creds = "11".repeat(32)
        ))
        .unwrap()
    }

    #[test]
    fn empty_allocation_keeps_zero_root() {
        let file = ChainSpecFile::from_toml_str(&format!(
            r#"
name = "x"
chain_id = 7
genesis_time = 0
genesis_gas_limit = 1
[[validators]]
pubkey_hex = "{PUBKEY}"
effective_stake = 1
"#
        ))
        .unwrap();
        let state = build_genesis_state(&file).unwrap();
        assert_eq!(state.root, ZERO_HASH);
        assert_eq!(state.staked_validators, 0);
    }

    #[test]
    fn accounts_and_validators_are_seeded_deterministically() {
        let extra = format!(
            "[[accounts]]\naddress_hex = \"{}\"\nbalance = 1000\n",
            "22".repeat(32)
        );
        let a = build_genesis_state(&spec(&extra)).unwrap();
        let b = build_genesis_state(&spec(&extra)).unwrap();
        assert_eq!(a.root, b.root);
        assert_ne!(a.root, ZERO_HASH);
        assert_eq!(a.accounts, 1);
        assert_eq!(a.staked_validators, 1);
        let account: Account =
            borsh::from_slice(&a.trie.get(&account_key(&[0x22; 32])).unwrap()).unwrap();
        assert_eq!(account.balance, 1000);
        let validator: RuntimeValidator =
            borsh::from_slice(&a.trie.get(&validator_key(&[0x11; 32])).unwrap()).unwrap();
        assert_eq!(validator.stake, 500);
        let set: ValidatorSet = borsh::from_slice(&a.trie.get(VALIDATOR_SET_KEY).unwrap()).unwrap();
        assert_eq!(set.entries.len(), 1);
        // The spec derives the same root and binds it into the chain spec.
        let chain_spec = spec(&extra).to_chain_spec().unwrap();
        assert_eq!(chain_spec.genesis_state_root, a.root);
    }

    #[test]
    fn declared_root_must_match_allocation() {
        let extra = format!(
            "genesis_state_root_hex = \"{}\"\n[[accounts]]\naddress_hex = \"{}\"\nbalance = 1\n",
            "ff".repeat(32),
            "22".repeat(32)
        );
        assert!(matches!(
            spec(&extra).to_chain_spec(),
            Err(ChainSpecError::Validation(_))
        ));
    }

    #[test]
    fn duplicate_account_is_rejected() {
        let extra = format!(
            "[[accounts]]\naddress_hex = \"{a}\"\nbalance = 1\n[[accounts]]\naddress_hex = \"{a}\"\nbalance = 2\n",
            a = "22".repeat(32)
        );
        assert!(build_genesis_state(&spec(&extra)).is_err());
    }
}
