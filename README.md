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
- **`contracts/verifier`** — vendored Groth16/BN254 verifier (see `VENDORED.md`).

## Test

```bash
cargo test            # 6 tests (verifier 3, relay 3) — real value movement via a SAC token
stellar contract build
```

Runs live on testnet with the native XLM SAC pool (see `scripts/`). License: MIT.
