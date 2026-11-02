use crate::fixture::*;
use crate::{ConfidentialRelay, ConfidentialRelayClient, Error, ProofEntry, VkData};
use soroban_sdk::{testutils::Address as _, token, vec, Address, BytesN, Env};

const TIP: i128 = 100;
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

struct Ctx {
    env: Env,
    client: ConfidentialRelayClient<'static>,
    token: Address,
    relayer: Address,
}

fn setup() -> Ctx {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(admin);
    let token = sac.address();

    let id = env.register(
        ConfidentialRelay,
        (BytesN::from_array(&env, &ROOT), 2u32, token.clone(), TIP, vk(&env)),
    );
    // Fund the pool by minting to the relay contract.
    token::StellarAssetClient::new(&env, &token).mint(&id, &POOL);

    let client = ConfidentialRelayClient::new(&env, &id);
    let relayer = Address::generate(&env);
    Ctx { env, client, token, relayer }
}

/// A relayer submits an anonymous member's authorized action and is paid the tip from the pool.
#[test]
fn relays_and_pays_tip() {
    let ctx = setup();
    let payload = BytesN::from_array(&ctx.env, &PAYLOAD);
    ctx.client.relay(&payload, &payload, &ctx.relayer, &entry_a(&ctx.env));

    let tok = token::TokenClient::new(&ctx.env, &ctx.token);
    assert_eq!(tok.balance(&ctx.relayer), TIP, "relayer paid the tip");
    assert_eq!(ctx.client.pool_balance(), POOL - TIP, "pool debited by the tip");
}

/// The same authorization cannot be relayed twice (nullifier consumed).
#[test]
fn rejects_double_relay() {
    let ctx = setup();
    let payload = BytesN::from_array(&ctx.env, &PAYLOAD);
    ctx.client.relay(&payload, &payload, &ctx.relayer, &entry_a(&ctx.env));
    let again = ctx.client.try_relay(&payload, &payload, &ctx.relayer, &entry_a(&ctx.env));
    assert_eq!(again, Err(Ok(Error::AlreadyRelayed)));
}

/// A proof not bound to the submitted action digest is rejected (no payout).
#[test]
fn rejects_wrong_action() {
    let ctx = setup();
    let mut bad = PAYLOAD;
    bad[0] ^= 0xff;
    let action = BytesN::from_array(&ctx.env, &bad);
    let scope = BytesN::from_array(&ctx.env, &PAYLOAD);
    let r = ctx.client.try_relay(&action, &scope, &ctx.relayer, &entry_a(&ctx.env));
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
    let tok = token::TokenClient::new(&ctx.env, &ctx.token);
    assert_eq!(tok.balance(&ctx.relayer), 0, "no payout on a bad proof");
}
