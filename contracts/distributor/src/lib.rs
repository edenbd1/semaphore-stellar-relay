#![no_std]
//! `ConfidentialDistributor` — the flagship fusion of the two differentiating layers:
//! **anonymous eligibility (membership) + keyless, gasless payout (relay)**.
//!
//! A sponsor (or several — see below) funds a pool of a chosen token. A fixed `amount` is paid
//! out, exactly once, to each eligible beneficiary. Eligibility is a Semaphore group: a
//! beneficiary proves in zero-knowledge that they belong to the group, **without revealing which
//! member they are**. A per-campaign `nullifier` guarantees at most one payout per member.
//!
//! Two properties make this unlike any existing Stellar distributor:
//!
//! 1. **The recipient is keyless and gasless.** The beneficiary never signs or holds XLM. The
//!    proof *is* the authorization; any relayer submits the `claim` transaction (and pays the
//!    Stellar fee as the transaction source), and the contract pays the recipient. So a person
//!    with no crypto, no funded account, and no on-chain history can still receive a verified,
//!    one-per-person payout. This is the aid / UBI / sybil-resistant-airdrop primitive.
//!
//! 2. **The recipient is bound into the proof.** `message = reduce(keccak(recipient_xdr))`, so a
//!    relayer who sees the off-chain proof **cannot redirect the payout** to themselves — the
//!    proof only verifies for the recipient the beneficiary chose. Without this binding the open
//!    relay would be a theft vector; with it, relaying is trustless.
//!
//! **Multi-sponsor pool ("sponsor deniability").** `fund` accepts deposits from any number of
//! sponsors into one commingled pool. Payouts leave the *contract* address, never a sponsor's,
//! so no on-chain link ties a given sponsor's money to a given payout. Deposits are public (as
//! they must be — value is moving on a public ledger), but *which* sponsor funded *which* claim
//! is unlinkable once two or more sponsors share the pool. We track only running totals, never a
//! per-sponsor→claim mapping.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, token,
    xdr::ToXdr, Address, Bytes, BytesN, Env, Vec,
};
use semaphore_verifier::verify_encoded;

#[contractevent]
pub struct Funded {
    pub sponsor: Address,
    pub amount: i128,
    pub pool: i128,
}

#[contractevent]
pub struct Claimed {
    pub recipient: Address,
    pub amount: i128,
}

// BN254 scalar field order r, big-endian. Public inputs must be < r (canonical) so a
// non-canonical nullifier cannot be smuggled past the field reduction.
const R_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];
fn is_canonical(v: &BytesN<32>) -> bool {
    v.to_array() < R_BE
}

/// Semaphore's signal hash: `keccak256(x) >> 8` (drop the low byte so the result is < r).
// Storage TTL (~5s/ledger → ~17280 ledgers/day): keep live entries ~30 days out, bumping when
// under ~15 days remain, so an active campaign never lets its config, totals or spent-nullifier
// registry archive (an archived nullifier would reopen the double-claim window).
const TTL_BUMP: u32 = 518_400; // ~30 days
const TTL_THRESHOLD: u32 = 259_200; // ~15 days

fn reduce8(env: &Env, bytes: &Bytes) -> BytesN<32> {
    let k = env.crypto().keccak256(bytes).to_array();
    let mut out = [0u8; 32];
    out[1..32].copy_from_slice(&k[0..31]);
    BytesN::from_array(env, &out)
}
fn semaphore_hash(env: &Env, value: &BytesN<32>) -> BytesN<32> {
    reduce8(env, &Bytes::from(value.clone()))
}

/// Domain-separated campaign scope: fold the distributor's OWN contract address into the scope
/// so a claim proof minted for this campaign cannot be replayed against another distributor that
/// shares the group root. The prover binds `scope` to
/// `keccak256( ascii(contract_strkey) || scope_seed )` (then `>> 8`); we recompute it here from
/// `env.current_contract_address()`, which no other contract can forge.
fn domain_scope_hash(env: &Env, scope_seed: &BytesN<32>) -> BytesN<32> {
    let strkey = env.current_contract_address().to_string();
    let mut preimage = strkey.to_bytes();
    preimage.append(&Bytes::from(scope_seed.clone()));
    let rawscope = BytesN::from_array(env, &env.crypto().keccak256(&preimage).to_array());
    semaphore_hash(env, &rawscope)
}

/// The field element a proof must carry as its `message` to be payable to `recipient`:
/// `reduce8(keccak(keccak(recipient_xdr)))`. Off-chain the beneficiary passes
/// `signal = keccak(recipient_xdr)` to Semaphore, which hashes it to this same value.
fn recipient_message(env: &Env, recipient: &Address) -> BytesN<32> {
    let digest = env.crypto().keccak256(&recipient.clone().to_xdr(env)); // keccak(recipient_xdr)
    semaphore_hash(env, &digest.into()) // keccak(digest) >> 8
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    NonCanonicalInput = 2,
    InvalidProof = 3,
    AlreadyClaimed = 4,
    PoolEmpty = 5,
    NotAdmin = 6,
    InvalidAmount = 7,
    CampaignNotEnded = 8,
}

#[contracttype]
#[derive(Clone)]
pub struct VkData {
    pub alpha: BytesN<64>,
    pub beta: BytesN<128>,
    pub gamma: BytesN<128>,
    pub delta: BytesN<128>,
    pub ic: Vec<BytesN<64>>,
}

#[contracttype]
pub struct ProofEntry {
    pub a: BytesN<64>,
    pub b: BytesN<128>,
    pub c: BytesN<64>,
    pub nullifier: BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
pub struct Config {
    pub admin: Address,
    pub root: BytesN<32>,
    pub depth: u32,
    pub token: Address,
    pub amount: i128,
    pub scope_seed: BytesN<32>,
    pub vk: VkData,
    /// Ledger at/after which the admin may `close` and recover the remainder. Before it, the
    /// admin cannot drain the commingled pool, so sponsors and eligible members are protected
    /// against a mid-campaign rug.
    pub end_ledger: u32,
}

#[contracttype]
pub enum DataKey {
    Config,
    TotalFunded,
    TotalClaimed,
    Nullifier(BytesN<32>),
}

#[contract]
pub struct ConfidentialDistributor;

#[contractimpl]
impl ConfidentialDistributor {
    /// `scope_seed` scopes the campaign: a member's nullifier is deterministic in
    /// `(member, scope)`, so the same group can run many campaigns, one claim each.
    #[allow(clippy::too_many_arguments)]
    pub fn __constructor(
        env: Env,
        admin: Address,
        root: BytesN<32>,
        depth: u32,
        token: Address,
        amount: i128,
        scope_seed: BytesN<32>,
        vk: VkData,
        end_ledger: u32,
    ) {
        // A non-positive payout would brick every claim (the SAC transfer traps).
        if amount <= 0 {
            panic_with_error!(&env, Error::InvalidAmount);
        }
        env.storage().instance().set(
            &DataKey::Config,
            &Config { admin, root, depth, token, amount, scope_seed, vk, end_ledger },
        );
        env.storage().instance().set(&DataKey::TotalFunded, &0i128);
        env.storage().instance().set(&DataKey::TotalClaimed, &0i128);
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_BUMP);
    }

    fn config(env: &Env) -> Result<Config, Error> {
        env.storage().instance().get(&DataKey::Config).ok_or(Error::NotInitialized)
    }

    /// Deposit into the commingled pool. Any number of sponsors may call this; payouts are not
    /// linkable to any one sponsor (see module docs).
    pub fn fund(env: Env, sponsor: Address, amount: i128) -> Result<(), Error> {
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        sponsor.require_auth();
        let cfg = Self::config(&env)?;
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_BUMP);
        token::TokenClient::new(&env, &cfg.token).transfer(
            &sponsor,
            env.current_contract_address(),
            &amount,
        );
        let total: i128 = env.storage().instance().get(&DataKey::TotalFunded).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalFunded, &(total + amount));
        let pool = Self::pool_balance(env.clone())?;
        Funded { sponsor, amount, pool }.publish(&env);
        Ok(())
    }

    pub fn pool_balance(env: Env) -> Result<i128, Error> {
        let cfg = Self::config(&env)?;
        Ok(token::TokenClient::new(&env, &cfg.token).balance(&env.current_contract_address()))
    }

    pub fn total_funded(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::TotalFunded).unwrap_or(0)
    }

    pub fn total_claimed(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::TotalClaimed).unwrap_or(0)
    }

    pub fn has_claimed(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage().persistent().has(&DataKey::Nullifier(nullifier))
    }

    /// Pay `amount` to `recipient` for an anonymous, eligible, not-yet-claimed beneficiary.
    ///
    /// The recipient neither signs nor pays: the proof is the authorization, and the relayer
    /// submitting this transaction is its source and fee payer. The proof binds `recipient`, so
    /// the relayer cannot redirect the payout. The nullifier is consumed, so each member claims
    /// at most once per campaign.
    pub fn claim(
        env: Env,
        recipient: Address,
        entry: ProofEntry,
    ) -> Result<(), Error> {
        let cfg = Self::config(&env)?;
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_BUMP);
        if !is_canonical(&entry.nullifier) {
            return Err(Error::NonCanonicalInput);
        }

        let message = recipient_message(&env, &recipient);
        let scope = domain_scope_hash(&env, &cfg.scope_seed);
        let pub_signals = soroban_sdk::vec![
            &env,
            cfg.root.clone(),
            entry.nullifier.clone(),
            message,
            scope
        ];
        let ok = verify_encoded(
            &env,
            &pub_signals,
            &entry.a,
            &entry.b,
            &entry.c,
            &cfg.vk.alpha,
            &cfg.vk.beta,
            &cfg.vk.gamma,
            &cfg.vk.delta,
            &cfg.vk.ic,
        );
        if !ok {
            return Err(Error::InvalidProof);
        }

        let key = DataKey::Nullifier(entry.nullifier.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyClaimed);
        }

        let token_client = token::TokenClient::new(&env, &cfg.token);
        if token_client.balance(&env.current_contract_address()) < cfg.amount {
            return Err(Error::PoolEmpty);
        }
        env.storage().persistent().set(&key, &());
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_BUMP);

        token_client.transfer(&env.current_contract_address(), &recipient, &cfg.amount);
        let claimed: i128 = env.storage().instance().get(&DataKey::TotalClaimed).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalClaimed, &(claimed + cfg.amount));
        Claimed { recipient, amount: cfg.amount }.publish(&env);
        Ok(())
    }

    /// Admin recovers the unclaimed remainder once a campaign is over. Gated on `end_ledger`:
    /// before that ledger the admin cannot withdraw, so the commingled pool cannot be rugged
    /// mid-campaign. Eligible members have until `end_ledger` to claim.
    pub fn close(env: Env, to: Address) -> Result<i128, Error> {
        let cfg = Self::config(&env)?;
        cfg.admin.require_auth();
        if env.ledger().sequence() < cfg.end_ledger {
            return Err(Error::CampaignNotEnded);
        }
        let token_client = token::TokenClient::new(&env, &cfg.token);
        let bal = token_client.balance(&env.current_contract_address());
        if bal > 0 {
            token_client.transfer(&env.current_contract_address(), &to, &bal);
        }
        Ok(bal)
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
#[allow(dead_code)]
mod fixture;
#[cfg(test)]
mod test;
