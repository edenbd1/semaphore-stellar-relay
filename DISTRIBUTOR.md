# ConfidentialDistributor — anonymous, keyless, gasless payouts

`contracts/distributor` fuses the two layers that make Semaphore-for-Stellar more than a verifier:
**anonymous eligibility** (membership) and **keyless, gasless payout** (the relay edge). It is the
primitive behind verified aid / UBI, sybil-resistant airdrops, and one-per-person gated claims.

## What it does

A campaign is a Semaphore group of eligible beneficiaries plus a funded token pool and a fixed
`amount` paid once per member.

```
fund(sponsor, amount)        # any number of sponsors deposit into one pool
claim(recipient, proof)      # pays `amount` to recipient for an anonymous, eligible member
close(to)                    # admin recovers the unclaimed remainder
```

`claim` verifies a Semaphore proof against the group root and ceremony vkey, consumes the member's
per-campaign nullifier (one claim each), and transfers `amount` from the pool to `recipient`.

## The two properties nothing on Stellar has today

**1. The recipient is keyless and gasless.** The beneficiary never signs and never holds XLM. The
ZK proof *is* the authorization, so any relayer submits the `claim` transaction — the relayer is the
transaction source and pays the Stellar fee — and the contract pays the recipient. A person with no
crypto, no funded account, and no on-chain history receives a verified, one-per-person payout. This
is exactly the humanitarian-rails story Stellar cares about, with privacy added.

**2. The recipient is bound into the proof.** `message = reduce8(keccak(recipient_xdr))`. The proof
only verifies for the recipient the beneficiary chose, so a relayer who sees the off-chain proof
**cannot redirect the payout** to themselves. Without this binding, an open relay would be a theft
vector; with it, relaying is trustless and permissionless. (Verified on-chain: submitting member
A's proof for member B's recipient fails with `InvalidProof`.)

## Multi-sponsor pool — "sponsor deniability"

`fund` accepts deposits from any number of sponsors into **one commingled pool**. Payouts always
leave the *contract* address, never a sponsor's, so no on-chain link ties a given sponsor's money to
a given payout. Deposits are public — value moves on a public ledger — but *which* sponsor funded
*which* claim is unlinkable once two or more sponsors share the pool. We track only running totals
(`total_funded`, `total_claimed`), never a per-sponsor→claim mapping.

This matters whenever the *funder* wants deniability: a foundation subsidising activists, a company
covering whistleblower submission costs, a protocol funding user onboarding without exposing its
per-user treasury flows.

> Honest limits: the *action* (a payout of `amount` to `recipient`) is public; only the link to the
> beneficiary's identity and to the funding sponsor is hidden. Sponsor deniability is only as strong
> as the anonymity set — it needs ≥2 sponsors and enough volume. Prototype, unaudited, testnet only.

## How the recipient binding matches off-chain

Off-chain the beneficiary passes `signal = keccak(ScVal(recipient_address) XDR)` to Semaphore, which
publishes `message = keccak(toBeHex(signal,32)) >> 8`. On-chain `claim` recomputes
`keccak(recipient.to_xdr())` from the `recipient: Address` argument and applies the same `>> 8`
reduction, so the bound recipient and the paid recipient are provably the same account. See
`tools/gen-distributor-fixture.mjs`.
