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

## Contracts

- **`contracts/relay`** — the confidential relay (tip pool, `fund` / `relay` / `pool_balance`).
- **`contracts/verifier`** — vendored Groth16/BN254 verifier (see `VENDORED.md`).

## Test

```bash
cargo test            # 6 tests (verifier 3, relay 3) — real value movement via a SAC token
stellar contract build
```

Runs live on testnet with the native XLM SAC pool (see `scripts/`). License: MIT.
