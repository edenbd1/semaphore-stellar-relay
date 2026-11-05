#![no_std]
//! Phase-3 (the big layer): the **confidential relay** — the payer-privacy edge.
//!
//! ZK hides *who* acts, but on a normal transaction the fee payer is public, which
//! deanonymizes the member. Here an anonymous group member authorizes an action with a
//! Semaphore proof and posts it off-chain; **any relayer** submits the transaction (paying the
//! Stellar fee via a fee-bump, so the member needs no funded, linkable account) and is paid a
//! `tip` from a pool. The relayer never learns which member authorized the action.
//!
//! On-chain, `relay`:
//!   1. binds the proof's signal to `action_digest` and scope to `scope_seed`
//!      (`message = hash(action_digest)`, `scope = domain_scope_hash(this_contract, scope_seed)`,
//!      so the authorization is bound to THIS relay and cannot be replayed against another);
//!   2. verifies the Semaphore proof against the group root + vkey;
//!   3. consumes the nullifier (one relay per member per scope — no double payout);
//!   4. pays `tip` from the pool to the relayer (real value movement).
//!
//! The relayer is not bound into the proof: this is an open relayer market — whoever includes
//! the member's authorization first earns the tip (bind the relayer into `action_digest` for an
//! exclusive relay). The member only cares that the action executes, anonymously.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, token,
    Address, Bytes, BytesN, Env, Vec,
};
use semaphore_verifier::verify_encoded;

#[contractevent]
pub struct Relayed {
    pub action_digest: BytesN<32>,
    pub tip: i128,
}

const R_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];
fn is_canonical(v: &BytesN<32>) -> bool {
    v.to_array() < R_BE
}
fn semaphore_hash(env: &Env, value: &BytesN<32>) -> BytesN<32> {
    let k = env.crypto().keccak256(&Bytes::from(value.clone())).to_array();
    let mut out = [0u8; 32];
    out[1..32].copy_from_slice(&k[0..31]);
    BytesN::from_array(env, &out)
}

// Storage TTL (~5s/ledger → ~17280 ledgers/day): keep live entries ~30 days out, bumping when
// under ~15 days remain, so an active relay never lets its config or spent-nullifier registry
// archive (an archived nullifier would reopen the double-relay window).
const TTL_BUMP: u32 = 518_400; // ~30 days
const TTL_THRESHOLD: u32 = 259_200; // ~15 days

/// Domain-separated scope: fold the relay's OWN contract address into the scope so an
/// authorization minted for this relay cannot be replayed against another contract that
/// shares the same group root. The prover binds `scope` to
/// `keccak256( ascii(contract_strkey) || scope_seed )` (then `>> 8`); we recompute it here from
/// `env.current_contract_address()`, which no other contract can forge.
fn domain_scope_hash(env: &Env, scope_seed: &BytesN<32>) -> BytesN<32> {
    let strkey = env.current_contract_address().to_string();
    let mut preimage = strkey.to_bytes();
    preimage.append(&Bytes::from(scope_seed.clone()));
    let rawscope = BytesN::from_array(env, &env.crypto().keccak256(&preimage).to_array());
    semaphore_hash(env, &rawscope)
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    NonCanonicalInput = 2,
    InvalidProof = 3,
    AlreadyRelayed = 4,
    PoolEmpty = 5,
    InvalidAmount = 6,
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
    pub root: BytesN<32>,
    pub depth: u32,
    pub token: Address,
    pub tip: i128,
    pub vk: VkData,
}

#[contracttype]
pub enum DataKey {
    Config,
    Nullifier(BytesN<32>),
}

#[contract]
pub struct ConfidentialRelay;

#[contractimpl]
impl ConfidentialRelay {
    pub fn __constructor(
        env: Env,
        root: BytesN<32>,
        depth: u32,
        token: Address,
        tip: i128,
        vk: VkData,
    ) {
        // A non-positive tip would brick every relay (the SAC transfer traps) or be meaningless.
        if tip <= 0 {
            panic_with_error!(&env, Error::InvalidAmount);
        }
        env.storage()
            .instance()
            .set(&DataKey::Config, &Config { root, depth, token, tip, vk });
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_BUMP);
    }

    fn config(env: &Env) -> Result<Config, Error> {
        env.storage().instance().get(&DataKey::Config).ok_or(Error::NotInitialized)
    }

    /// Fund the tip pool.
    pub fn fund(env: Env, from: Address, amount: i128) -> Result<(), Error> {
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        from.require_auth();
        let cfg = Self::config(&env)?;
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_BUMP);
        token::TokenClient::new(&env, &cfg.token).transfer(
            &from,
            env.current_contract_address(),
            &amount,
        );
        Ok(())
    }

    pub fn pool_balance(env: Env) -> Result<i128, Error> {
        let cfg = Self::config(&env)?;
        Ok(token::TokenClient::new(&env, &cfg.token).balance(&env.current_contract_address()))
    }

    /// Relay an anonymous member's authorized action and pay the relayer the tip.
    pub fn relay(
        env: Env,
        action_digest: BytesN<32>,
        scope_seed: BytesN<32>,
        relayer: Address,
        entry: ProofEntry,
    ) -> Result<(), Error> {
        let cfg = Self::config(&env)?;
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_BUMP);
        if !is_canonical(&entry.nullifier) {
            return Err(Error::NonCanonicalInput);
        }

        let message = semaphore_hash(&env, &action_digest);
        let scope = domain_scope_hash(&env, &scope_seed);
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
            return Err(Error::AlreadyRelayed);
        }

        // Check the pool can cover the tip BEFORE consuming the nullifier, so an empty pool
        // returns a clean error and leaves the proof reusable once the pool is refunded,
        // rather than trapping on the transfer.
        let token_client = token::TokenClient::new(&env, &cfg.token);
        if token_client.balance(&env.current_contract_address()) < cfg.tip {
            return Err(Error::PoolEmpty);
        }

        env.storage().persistent().set(&key, &());
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_BUMP);

        relayer.require_auth();
        token_client.transfer(&env.current_contract_address(), &relayer, &cfg.tip);
        Relayed { action_digest: action_digest.clone(), tip: cfg.tip }.publish(&env);
        Ok(())
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
#[allow(dead_code)]
mod fixture;
#[cfg(test)]
mod test;
