use crate::fixture::*;
use crate::{ConfidentialDistributor, ConfidentialDistributorClient, Error, ProofEntry, VkData};
use soroban_sdk::{
    testutils::Address as _, token, vec, Address, BytesN, Env, String as SString,
};

const AMOUNT: i128 = 100;
const POOL: i128 = 1000;

fn vk(env: &Env) -> VkData {
    VkData {
        alpha: BytesN::from_array(env, &VK_ALPHA),
        beta: BytesN::from_array(env, &VK_BETA),
        gamma: BytesN::from_array(env, &VK_GAMMA),
        delta: BytesN::from_array(env, &VK_DELTA),
        ic: vec![
            env,
            BytesN::from_array(env, &VK_IC_0),
            BytesN::from_array(env, &VK_IC_1),
            BytesN::from_array(env, &VK_IC_2),
            BytesN::from_array(env, &VK_IC_3),
            BytesN::from_array(env, &VK_IC_4),
        ],
    }
}

fn entry_a(env: &Env) -> ProofEntry {
    ProofEntry {
        a: BytesN::from_array(env, &A_A),
        b: BytesN::from_array(env, &A_B),
        c: BytesN::from_array(env, &A_C),
        nullifier: BytesN::from_array(env, &NUL_A),
    }
}

fn entry_b(env: &Env) -> ProofEntry {
    ProofEntry {
        a: BytesN::from_array(env, &B_A),
        b: BytesN::from_array(env, &B_B),
        c: BytesN::from_array(env, &B_C),
        nullifier: BytesN::from_array(env, &NUL_B),
    }
}

fn recipient_a(env: &Env) -> Address {
    Address::from_string(&SString::from_str(env, RECIPIENT_A))
}
fn recipient_b(env: &Env) -> Address {
    Address::from_string(&SString::from_str(env, RECIPIENT_B))
}

struct Ctx {
    env: Env,
    client: ConfidentialDistributorClient<'static>,
    token: Address,
    sac_admin: Address,
}

fn setup(fund: bool) -> Ctx {
    let env = Env::default();
    env.mock_all_auths();
    let sac_admin = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(sac_admin.clone());
    let token = sac.address();
    let admin = Address::generate(&env);

    let id = env.register(
        ConfidentialDistributor,
        (
            admin,
            BytesN::from_array(&env, &ROOT),
            2u32,
            token.clone(),
            AMOUNT,
            BytesN::from_array(&env, &SCOPE_SEED),
            vk(&env),
        ),
    );
    if fund {
        token::StellarAssetClient::new(&env, &token).mint(&id, &POOL);
    }
    let client = ConfidentialDistributorClient::new(&env, &id);
    Ctx { env, client, token, sac_admin }
}

fn bal(ctx: &Ctx, who: &Address) -> i128 {
    token::TokenClient::new(&ctx.env, &ctx.token).balance(who)
}

#[test]
fn claim_pays_bound_recipient() {
    let ctx = setup(true);
    let ra = recipient_a(&ctx.env);
    assert_eq!(bal(&ctx, &ra), 0);
    ctx.client.claim(&ra, &entry_a(&ctx.env));
    assert_eq!(bal(&ctx, &ra), AMOUNT);
    assert_eq!(ctx.client.total_claimed(), AMOUNT);
    assert!(ctx.client.has_claimed(&BytesN::from_array(&ctx.env, &NUL_A)));
    assert_eq!(ctx.client.pool_balance(), POOL - AMOUNT);
}

#[test]
fn two_members_two_recipients() {
    let ctx = setup(true);
    ctx.client.claim(&recipient_a(&ctx.env), &entry_a(&ctx.env));
    ctx.client.claim(&recipient_b(&ctx.env), &entry_b(&ctx.env));
    assert_eq!(bal(&ctx, &recipient_a(&ctx.env)), AMOUNT);
    assert_eq!(bal(&ctx, &recipient_b(&ctx.env)), AMOUNT);
    assert_eq!(ctx.client.total_claimed(), 2 * AMOUNT);
}

#[test]
fn double_claim_rejected() {
    let ctx = setup(true);
    let ra = recipient_a(&ctx.env);
    ctx.client.claim(&ra, &entry_a(&ctx.env));
    let err = ctx.client.try_claim(&ra, &entry_a(&ctx.env)).err().unwrap().unwrap();
    assert_eq!(err, Error::AlreadyClaimed);
    assert_eq!(bal(&ctx, &ra), AMOUNT); // paid exactly once
}

#[test]
fn relayer_cannot_redirect() {
    // A's proof is bound to RECIPIENT_A; submitting it for RECIPIENT_B must not verify.
    let ctx = setup(true);
    let rb = recipient_b(&ctx.env);
    let err = ctx.client.try_claim(&rb, &entry_a(&ctx.env)).err().unwrap().unwrap();
    assert_eq!(err, Error::InvalidProof);
    assert_eq!(bal(&ctx, &rb), 0);
    assert!(!ctx.client.has_claimed(&BytesN::from_array(&ctx.env, &NUL_A)));
}

#[test]
fn tampered_proof_rejected() {
    // Keep every curve point valid but swap in a different (canonical) nullifier: the public
    // inputs no longer match the proof, so the pairing check returns false -> InvalidProof.
    let ctx = setup(true);
    let mut e = entry_a(&ctx.env);
    e.nullifier = BytesN::from_array(&ctx.env, &NUL_B);
    let err = ctx.client.try_claim(&recipient_a(&ctx.env), &e).err().unwrap().unwrap();
    assert_eq!(err, Error::InvalidProof);
}

#[test]
fn non_canonical_nullifier_rejected() {
    let ctx = setup(true);
    let mut e = entry_a(&ctx.env);
    e.nullifier = BytesN::from_array(&ctx.env, &[0xff; 32]);
    let err = ctx.client.try_claim(&recipient_a(&ctx.env), &e).err().unwrap().unwrap();
    assert_eq!(err, Error::NonCanonicalInput);
}

#[test]
fn pool_empty_does_not_consume_nullifier() {
    // Unfunded pool: claim fails with PoolEmpty and the nullifier is preserved, so once a
    // sponsor funds, the same proof claims successfully.
    let ctx = setup(false);
    let ra = recipient_a(&ctx.env);
    let err = ctx.client.try_claim(&ra, &entry_a(&ctx.env)).err().unwrap().unwrap();
    assert_eq!(err, Error::PoolEmpty);
    assert!(!ctx.client.has_claimed(&BytesN::from_array(&ctx.env, &NUL_A)));

    // A sponsor funds, then the claim goes through.
    let sponsor = Address::generate(&ctx.env);
    token::StellarAssetClient::new(&ctx.env, &ctx.token).mint(&sponsor, &POOL);
    ctx.client.fund(&sponsor, &POOL);
    ctx.client.claim(&ra, &entry_a(&ctx.env));
    assert_eq!(bal(&ctx, &ra), AMOUNT);
}

#[test]
fn multi_sponsor_pool_commingles() {
    // Several sponsors fund one pool; totals aggregate and payouts leave the contract address,
    // so no sponsor is linkable to a specific claim (sponsor deniability).
    let ctx = setup(false);
    let s1 = Address::generate(&ctx.env);
    let s2 = Address::generate(&ctx.env);
    let sac = token::StellarAssetClient::new(&ctx.env, &ctx.token);
    sac.mint(&s1, &600);
    sac.mint(&s2, &400);
    ctx.client.fund(&s1, &600);
    ctx.client.fund(&s2, &400);
    assert_eq!(ctx.client.total_funded(), 1000);
    assert_eq!(ctx.client.pool_balance(), 1000);

    ctx.client.claim(&recipient_a(&ctx.env), &entry_a(&ctx.env));
    // The recipient was paid by the contract, not by s1 or s2 directly.
    assert_eq!(bal(&ctx, &recipient_a(&ctx.env)), AMOUNT);
    assert_eq!(ctx.client.pool_balance(), 1000 - AMOUNT);
}

#[test]
fn close_returns_remainder() {
    let ctx = setup(true);
    ctx.client.claim(&recipient_a(&ctx.env), &entry_a(&ctx.env));
    let treasury = ctx.sac_admin.clone();
    let before = bal(&ctx, &treasury);
    let returned = ctx.client.close(&treasury);
    assert_eq!(returned, POOL - AMOUNT);
    assert_eq!(bal(&ctx, &treasury), before + POOL - AMOUNT);
    assert_eq!(ctx.client.pool_balance(), 0);
}
