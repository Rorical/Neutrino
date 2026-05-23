# 16 — Implemented Runtime Surface

Status: living reference of what the code actually does today.

This doc is the single source of truth for the implemented Neutrino
runtime semantics. Doc 13 defines the accepted architecture; doc 14
tracks the rewrite roadmap. This file describes the concrete wire
shapes, state-key layout, fee model, gas schedule, receipt codes,
withdrawal queue, and admission rules that ship in
`runtimes/neutrino-default`.

When the code and any other design doc disagree, this file plus the
runtime source code are authoritative.

---

## State-key layout

The default runtime stores all account- and validator-related state
under fixed byte prefixes:

| Key                        | Value                | Notes                                        |
|----------------------------|----------------------|----------------------------------------------|
| `b"acct:" \|\| addr (32B)` | `borsh(Account)`     | 37-byte key.                                 |
| `b"val:" \|\| addr (32B)`  | `borsh(Validator)`   | 36-byte key.                                 |
| `b"wdr:" \|\| addr (32B)`  | `borsh(WithdrawalQueue)` | 36-byte key. Empty queues remain (no delete). |
| `b"validator_set"`         | `borsh(ValidatorSet)` | Canonical set sorted by address. 13-byte key. |

```rust
pub struct Account     { pub nonce: u64, pub balance: u128 }
pub struct Validator   { pub stake: u128, pub active: bool }
pub struct ValidatorSet { pub entries: Vec<ValidatorSetEntry> }
pub struct ValidatorSetEntry { pub address: [u8; 32], pub stake: u128 }
pub struct WithdrawalQueue { pub entries: Vec<Withdrawal> }
pub struct Withdrawal  { pub amount: u128, pub mature_at_height: u64 }
```

`addr` is the 32-byte Ed25519 public key. There is no separate
"account id" — public key equals address.

---

## Transactions

`Transaction` is borsh-encoded with the variant index as the wire
tag. Variants must append, never reorder, because the index is
part of every `Receipt`.

| Tag | Variant                | Signed? | Domain tag             | Sig msg len | Fee? |
|----:|------------------------|--------:|------------------------|------------:|:----:|
| `0` | `Transfer(TransferTx)` | yes     | `NTRO/transfer`        |       112 B | yes  |
| `1` | `Stake(StakeTx)`       | yes     | `NTRO/stake`           |        80 B | yes  |
| `2` | `Unstake(UnstakeTx)`   | yes     | `NTRO/unstake`         |        80 B | yes  |
| `3` | `Slash(SlashTx)`       | no      | (consensus-driven)     |           – | no   |
| `4` | `InactivityLeak(LeakTx)`| no     | (consensus-driven)     |           – | no   |
| `5` | `Deposit(DepositTx)`   | yes     | `NTRO/deposit`         |       128 B | yes  |
| `6` | `VoluntaryExit(...)`   | yes     | `NTRO/vexit`           |        64 B | yes  |
| `7` | `Withdraw(WithdrawTx)` | yes     | `NTRO/withdraw`        |        64 B | yes  |

Domain tags are 16-byte ASCII constants right-padded with NUL.
Signed payloads always include the chain id at offset 16 to prevent
cross-chain replay; signatures cover the payload, not a hash of it.

### Slash / InactivityLeak

Both are consensus-driven: the chain backend re-encodes each accepted
`SlashingEvidence` variant and each non-participating validator's
inactivity report as a `Transaction::Slash` / `Transaction::InactivityLeak`
and prepends the borsh blobs to `Body.transactions`. The mempool
admission path returns `TxValidationCode::Unauthorized` for either
variant, so a user RPC submission of `Slash(...)` is rejected even if
its bytes happen to decode cleanly.

The `amount` field on both variants is clamped to the validator's
current stake; oversize values silently underflow the deduction to
zero. The runtime trusts the block-level inclusion gate (which
validates the underlying evidence / inactivity report) — the STF only
applies the deduction.

---

## Gas schedule

Fixed per-kind, deterministic, independent of outcome. Failed
transactions consume zero gas because no fee-payer mechanism exists yet.

| Kind                | Gas      |
|---------------------|---------:|
| `Transfer`          |  21 000  |
| `Stake`             |  50 000  |
| `Unstake`           |  50 000  |
| `Slash`             |   5 000  |
| `InactivityLeak`    |   5 000  |
| `Deposit`           |  30 000  |
| `VoluntaryExit`     |  40 000  |
| `Withdraw`          |  50 000  |

`apply_block` pre-flights every transaction: if the kind's full cost
would push the running `gas_used` past `StfInput.block_gas_limit`,
the transaction is rejected as `ReceiptStatus::OutOfBlockGas` without
state mutation, but later transactions in the same block are still
attempted (they may fit).

---

## Fee market

```rust
pub struct RuntimeParams {
    pub gas_price: u128,
    pub unbonding_delay_blocks: u64,
    pub slash_amount: u128,
    pub inactivity_leak_amount: u128,
}
```

`gas_price = 0` is the canonical pre-fee-market configuration (the
default). When set, every successfully-applied signed user
transaction debits `tx_gas(tx) * gas_price` from the sender's account
in addition to any transfer / stake amount. The sum is credited to
`proposer_address` at the end of `apply_block`.

`proposer_address` is the runtime account of the block's proposer.
The consensus engine derives it from
`active_validator_set[header.proposer_index].withdrawal_credentials`
and binds it through `BlockProofPublicInputs.proposer_address`, so a
malicious prover cannot redirect fees to a different account.

Consensus-driven `Slash` and `InactivityLeak` transactions pay no
fee even when `gas_price > 0`; the block proposer is required to
include them when the evidence / inactivity report is valid.

Self-transfers conserve the `amount` (sender pays themselves back)
but the fee leaves the signer's balance for the proposer pot.

---

## Receipts

```rust
pub enum ReceiptStatus {
    Success,             // 0
    BadSignature,        // 1
    NonceMismatch,       // 2
    InsufficientBalance, // 3
    OutOfBlockGas,       // 4
    Overflow,            // 5
}

pub struct Receipt {
    pub status_code: u32, // ReceiptStatus::as_u32
    pub gas_used:    u64, // kind's full cost on Success, 0 on failure
    pub kind:        u8,  // tx_kind_code(tx)
}
```

The receipts-root commitment is

```
receipts_root =
    BLAKE3(DOMAIN_RECEIPTS_ROOT || count_le_u64 ||
           (status_code_le_u32 || gas_used_le_u64 || kind_u8)*)
```

`DOMAIN_RECEIPTS_ROOT = b"NTRO/receipts\0\0\0"`. An empty
receipts vector still produces a well-defined non-zero digest
(commitment to count `0`) so `header.receipts_root` is never
`ZERO_HASH` by accident.

The receipts vector is hashed once per block and dropped; only the
digest survives in `header.receipts_root`. The default runtime does
not persist per-tx receipts.

`StfPublicOutput.receipts_root` is bound by the SP1 proof and
cross-checked against `BlockProofPublicInputs.receipt_root` and
`header.receipts_root` on every import.

---

## Withdrawal queue

Unstakes and voluntary exits do not return funds to the signer
immediately. Each `Unstake(amount)` and `VoluntaryExit` appends a

```
Withdrawal {
    amount,
    mature_at_height: current_block_height + unbonding_delay_blocks,
}
```

entry to the validator's per-address queue under
`withdrawal_key(addr) = b"wdr:" || addr`. A subsequent
`Transaction::Withdraw` signed by the validator drains every entry
whose `mature_at_height <= current_block_height` into the signer's
spendable balance. The transaction succeeds (consuming its full gas)
even when zero entries are matured.

`ChainSpec.runtime.unbonding_delay_blocks` defaults to `32` blocks.
Real chains pick a much longer delay (Ethereum's exit queue is roughly
a day).

`VoluntaryExit` is equivalent to `Unstake(validator.stake)` under the
`DOMAIN_VOLUNTARY_EXIT` tag: it always drains the validator's full
stake and marks them inactive.

---

## Mempool admission (`validate_tx`)

The runtime's `_neutrino_validate_tx` WASM export performs every
check `apply_block` would perform up to (but not including) the
first state mutation. The admission path is intentionally a strict
subset of the execution path: a transaction that passes admission
cannot subsequently be silently dropped by the STF for the same
checked condition (state changes between admission and inclusion
can still invalidate the transaction, e.g. another tx from the
same signer landing first).

Rejection codes match `TxValidationCode`:

| Code                 | Cause                                            |
|----------------------|--------------------------------------------------|
| `Malformed`          | borsh decoding failed or trailing junk           |
| `BadSignature`       | Ed25519 signature does not verify                |
| `NonceMismatch`      | `signer.nonce != tx.nonce`                       |
| `InsufficientBalance`| Balance / stake / gas-vs-limit / fee shortfall   |
| `Unauthorized`       | `Slash` / `InactivityLeak` submitted by a user   |

Transactions whose cost alone exceeds `block_gas_limit` are rejected
with `InsufficientBalance` because they could never be included in
any block under the current ChainSpec.

---

## `StfInput` / `StfPublicOutput`

```rust
pub struct StfInput {
    pub chain_id: u64,
    pub block_height: u64,
    pub block_gas_limit: u64,
    pub gas_price: u128,
    pub proposer_address: [u8; 32],
    pub transactions: Vec<Transaction>,
}

pub struct StfPublicOutput {
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub applied: u32,
    pub failed: u32,
    pub validator_set_root: [u8; 32],
    pub gas_used: u64,
    pub receipts_root: [u8; 32],
}
```

`StateWitness` (in `runtime-abi`) carries the trie nodes and values
the STF reads, plus a `witnessed_keys` set. The SP1 Guest's
`WitnessState` verifies every `(hash, bytes)` pair against the trie's
canonical hash functions and asserts the supplied `pre_state_root` is
present in the reconstructed subtree before any STF read.

Empty-access blocks still bind to `pre_state_root` cryptographically:
the host always includes the live root node in the witness when
present, so the guest's witness check fails on a tampered root even
when zero keys were accessed.

---

## Versioning rules

- New `Transaction` variants must append (the variant index is part
  of the receipts-root commitment).
- New `ReceiptStatus` variants must append (the `as_u32` mapping is
  part of the receipts-root commitment).
- New `RuntimeParams` fields must append and must have a sensible
  `Default` value (zero / preserve legacy behavior). The chain-spec
  hash captures every field.
- Domain tags are NUL-padded to exactly 16 bytes. Changing a tag is
  a consensus break.

Any change that affects `post_state_root`, `validator_set_root`,
`receipts_root`, or `gas_used` must execute in the shared `runtime-core`
crate so both the WASM master cdylib and the SP1 Guest see identical
semantics. WASM-only logic (RPC, dry-run, query) can drift without
breaking consensus safety because the SP1 proof is the consensus-bound
artifact.
