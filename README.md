# Semaphore for Stellar — Confidential Relay

The payer-privacy layer for Soroban/Stellar, built on the
[semaphore-stellar](https://github.com/edenbd1/semaphore-stellar) library.

ZK hides *who* acts, but on a normal transaction the fee payer is public, which deanonymizes
the member. `ConfidentialRelay` closes that gap: an anonymous group member authorizes an
action with a Semaphore proof and posts it off-chain; **any relayer** submits it (paying the
Stellar fee via a fee-bump, so the member needs no funded, linkable account) and is paid a
`tip` from a pool — without learning which member authorized it.

`relay()` binds `message = hash(action_digest)` and `scope = hash(scope_seed)`, verifies the
proof, consumes the nullifier (one payout per authorization), and transfers the tip to the
relayer. This is the "why Stellar" edge: native fee-bump (CAP-15) + sponsored reserves
(CAP-33) make a paying relayer a first-class citizen.

### Two payer-privacy models

1. **Reimbursement pool (this contract):** the relayer pays the fee and claims a tip from a
   pool, verified against the member's proof. Good when the relayer needs an on-chain incentive.
2. **Explicit fee-bump:** the member authorizes purely in zero-knowledge (no account, no key)
   and a distinct relayer wraps the inner tx in a Stellar fee-bump (CAP-15) and pays the fee
   directly — no reimbursement contract needed. Demonstrated end-to-end on testnet in the
   [multisig repo](https://github.com/edenbd1/semaphore-stellar-multisig)
   (`tools/onchain-checkauth/fee-bump.mjs`): the inner source paid `0 XLM`, the relayer paid the
   fee, tx `18c4a43b…` `SUCCESS`.

## Contracts

- **`contracts/relay`** — the confidential relay (tip pool, `fund` / `relay` / `pool_balance`).
- **`contracts/distributor`** — `ConfidentialDistributor`: anonymous, keyless, gasless payouts with
  a recipient-bound proof and a multi-sponsor pool. The aid / UBI / sybil-resistant-airdrop
  primitive. See [`DISTRIBUTOR.md`](DISTRIBUTOR.md).
- **`contracts/verifier`** — vendored Groth16/BN254 verifier (see `VENDORED.md`).

## Test

```bash
cargo test            # 17 tests (verifier 3, relay 5, distributor 9) — real value movement via SAC
stellar contract build
```

Runs live on testnet with the native XLM SAC pool (see `scripts/`). License: MIT.

## Status & safety

> ⚠️ **Prototype — unaudited, testnet only.** This code has **not** been audited and runs only
> on Stellar **testnet** with small fixtures. Do not use it with real value or on mainnet.

### Known limitations

- **Domain separation (enforced):** `relay` and `distributor` derive their scope **on-chain from the contract's own address** (`domain_scope_hash` = `keccak256(ascii(contract_strkey) ‖ scope_seed) >> 8`), so an authorization minted for one deployment **cannot** be replayed against another that shares a group root. Each has a `rejects_cross_contract_replay` test proving this against a real ceremony proof.
- `relay`: `scope_seed` is caller-chosen, so one member can mint a fresh nullifier per scope and collect one tip each — fund the tip pool only to the amount you are willing to pay out. RLN-style per-epoch rate limiting is planned.
- `relay`: the relayer is an open-market caller — anyone who observes a member's proof can submit it and collect the tip.
- `distributor`: the admin may recover the remainder only **after** the configured `end_ledger` (anti-rug), but the pool is still admin-custodied; `fund` is permissionless and commingled.
- Storage TTL is managed: every state-changing call extends the instance config and the relevant persistent entries (spent nullifiers, totals) by ~30 days (bumping when under ~15 days remain), so an actively-used contract never archives. A contract left completely idle past the bump window still needs a one-time Soroban `restore`.
> Proofs reuse Ethereum's Semaphore trusted-setup ceremony (no new ceremony is performed).
