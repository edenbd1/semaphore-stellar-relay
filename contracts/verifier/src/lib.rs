#![no_std]
//! Phase-1 prototype: a Groth16/BN254 verifier for Semaphore v4 proofs on Soroban.
//!
//! Semaphore v4 uses BN254 (== Ethereum's alt_bn128) with 4 public inputs, in order:
//!   [merkleTreeRoot, nullifier, hash(message), hash(scope)]
//! so the verification key's IC vector has 5 points (nPublic + 1).
//!
//! Because Soroban's BN254 host functions are byte-for-byte EVM-compatible, a proof and
//! verification key produced by Ethereum's Semaphore trusted-setup ceremony verify here
//! unchanged. The milestone this crate proves: a REAL ceremony proof verifies via
//! `env.crypto().bn254().pairing_check`.

#[cfg(feature = "build-contract")]
use soroban_sdk::{contract, contractimpl};
use soroban_sdk::{
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    vec, BytesN, Env, Vec,
};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod fixture_multidepth;

/// Groth16/BN254 verification key. `ic` must have `public_inputs + 1` points.
pub struct Vk {
    pub alpha: Bn254G1Affine,
    pub beta: Bn254G2Affine,
    pub gamma: Bn254G2Affine,
    pub delta: Bn254G2Affine,
    pub ic: Vec<Bn254G1Affine>,
}

/// Verify a Groth16 proof against `vk` and `pub_signals`.
///
/// Checks the pairing identity in product form:
///   e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1
/// where vk_x = IC[0] + Σ pub_signals[i] · IC[i + 1].
pub fn groth16_verify(
    env: &Env,
    vk: &Vk,
    pub_signals: &Vec<Bn254Fr>,
    a: &Bn254G1Affine,
    b: &Bn254G2Affine,
    c: &Bn254G1Affine,
) -> bool {
    let bn = env.crypto().bn254();

    // vk_x = IC[0] + Σ pub_signals[i] · IC[i+1]
    let mut vk_x = vk.ic.get(0).expect("IC must contain at least one point");
    let n = pub_signals.len();
    assert_eq!(vk.ic.len(), n + 1, "IC length must equal public inputs + 1");
    for i in 0..n {
        let ic_point = vk.ic.get(i + 1).unwrap();
        let scalar = pub_signals.get(i).unwrap();
        let term = bn.g1_mul(&ic_point, &scalar);
        vk_x = bn.g1_add(&vk_x, &term);
    }

    let neg_a = -a.clone();
    let g1 = vec![env, neg_a, vk.alpha.clone(), vk_x, c.clone()];
    let g2 = vec![env, b.clone(), vk.beta.clone(), vk.gamma.clone(), vk.delta.clone()];
    bn.pairing_check(g1, g2)
}

/// Verify a Groth16 proof from Soroban-encoded bytes (reusable by other contracts).
///
/// `pub_signals` are 32-byte big-endian scalars; points use Soroban's uncompressed
/// BN254 encoding (G1 = X‖Y, 64B; G2 = Xc1‖Xc0‖Yc1‖Yc0, 128B).
#[allow(clippy::too_many_arguments)]
pub fn verify_encoded(
    env: &Env,
    pub_signals: &Vec<BytesN<32>>,
    a: &BytesN<64>,
    b: &BytesN<128>,
    c: &BytesN<64>,
    vk_alpha: &BytesN<64>,
    vk_beta: &BytesN<128>,
    vk_gamma: &BytesN<128>,
    vk_delta: &BytesN<128>,
    vk_ic: &Vec<BytesN<64>>,
) -> bool {
    let mut signals = Vec::new(env);
    for s in pub_signals.iter() {
        signals.push_back(Bn254Fr::from_bytes(s));
    }
    let mut ic = Vec::new(env);
    for p in vk_ic.iter() {
        ic.push_back(Bn254G1Affine::from_bytes(p));
    }
    let vk = Vk {
        alpha: Bn254G1Affine::from_bytes(vk_alpha.clone()),
        beta: Bn254G2Affine::from_bytes(vk_beta.clone()),
        gamma: Bn254G2Affine::from_bytes(vk_gamma.clone()),
        delta: Bn254G2Affine::from_bytes(vk_delta.clone()),
        ic,
    };
    groth16_verify(
        env,
        &vk,
        &signals,
        &Bn254G1Affine::from_bytes(a.clone()),
        &Bn254G2Affine::from_bytes(b.clone()),
        &Bn254G1Affine::from_bytes(c.clone()),
    )
}

/// The standalone verifier contract. Gated behind the `build-contract` feature so that when
/// this crate is used as a library dependency it exposes only `verify_encoded`, not a
/// contract entry point (which would otherwise leak a `verify` export into the dependent).
#[cfg(feature = "build-contract")]
#[contract]
pub struct SemaphoreVerifier;

#[cfg(feature = "build-contract")]
#[contractimpl]
impl SemaphoreVerifier {
    /// On-chain Groth16/BN254 verification entry point.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        env: Env,
        pub_signals: Vec<BytesN<32>>,
        a: BytesN<64>,
        b: BytesN<128>,
        c: BytesN<64>,
        vk_alpha: BytesN<64>,
        vk_beta: BytesN<128>,
        vk_gamma: BytesN<128>,
        vk_delta: BytesN<128>,
        vk_ic: Vec<BytesN<64>>,
    ) -> bool {
        verify_encoded(
            &env, &pub_signals, &a, &b, &c, &vk_alpha, &vk_beta, &vk_gamma, &vk_delta, &vk_ic,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fixture::*;
    use soroban_sdk::{vec, BytesN, Env};

    fn g1(env: &Env, b: &[u8; 64]) -> Bn254G1Affine {
        Bn254G1Affine::from_bytes(BytesN::from_array(env, b))
    }
    fn g2(env: &Env, b: &[u8; 128]) -> Bn254G2Affine {
        Bn254G2Affine::from_bytes(BytesN::from_array(env, b))
    }
    fn fr(env: &Env, b: &[u8; 32]) -> Bn254Fr {
        Bn254Fr::from_bytes(BytesN::from_array(env, b))
    }

    fn fixture_vk(env: &Env) -> Vk {
        Vk {
            alpha: g1(env, &VK_ALPHA),
            beta: g2(env, &VK_BETA),
            gamma: g2(env, &VK_GAMMA),
            delta: g2(env, &VK_DELTA),
            ic: vec![
                env,
                g1(env, &VK_IC_0),
                g1(env, &VK_IC_1),
                g1(env, &VK_IC_2),
                g1(env, &VK_IC_3),
                g1(env, &VK_IC_4),
            ],
        }
    }

    /// The milestone: a REAL Semaphore v4 ceremony proof (generated off-chain with
    /// Ethereum's artifacts) verifies via Soroban's BN254 pairing check.
    #[test]
    fn verifies_real_semaphore_proof() {
        let env = Env::default();
        let vk = fixture_vk(&env);
        let pub_signals = vec![&env, fr(&env, &PUB_0), fr(&env, &PUB_1), fr(&env, &PUB_2), fr(&env, &PUB_3)];
        let a = g1(&env, &PROOF_A);
        let b = g2(&env, &PROOF_B);
        let c = g1(&env, &PROOF_C);
        assert!(
            groth16_verify(&env, &vk, &pub_signals, &a, &b, &c),
            "a real Semaphore ceremony proof must verify on Soroban BN254"
        );
    }

    fn fixture_args(
        env: &Env,
    ) -> (
        soroban_sdk::Vec<BytesN<32>>,
        BytesN<64>,
        BytesN<128>,
        BytesN<64>,
        BytesN<64>,
        BytesN<128>,
        BytesN<128>,
        BytesN<128>,
        soroban_sdk::Vec<BytesN<64>>,
    ) {
        let pub_signals = vec![
            env,
            BytesN::from_array(env, &PUB_0),
            BytesN::from_array(env, &PUB_1),
            BytesN::from_array(env, &PUB_2),
            BytesN::from_array(env, &PUB_3),
        ];
        let ic = vec![
            env,
            BytesN::from_array(env, &VK_IC_0),
            BytesN::from_array(env, &VK_IC_1),
            BytesN::from_array(env, &VK_IC_2),
            BytesN::from_array(env, &VK_IC_3),
            BytesN::from_array(env, &VK_IC_4),
        ];
        (
            pub_signals,
            BytesN::from_array(env, &PROOF_A),
            BytesN::from_array(env, &PROOF_B),
            BytesN::from_array(env, &PROOF_C),
            BytesN::from_array(env, &VK_ALPHA),
            BytesN::from_array(env, &VK_BETA),
            BytesN::from_array(env, &VK_GAMMA),
            BytesN::from_array(env, &VK_DELTA),
            ic,
        )
    }

    /// Objective (b): measure the CPU instruction cost of an on-chain `verify` call, to
    /// confirm it fits a `__check_auth` budget (mainnet tx limit is 100,000,000 insns).
    #[cfg(feature = "build-contract")]
    #[test]
    fn reports_verify_budget() {
        let env = Env::default();
        let id = env.register(SemaphoreVerifier, ());
        let client = SemaphoreVerifierClient::new(&env, &id);
        let (pub_signals, a, b, c, alpha, beta, gamma, delta, ic) = fixture_args(&env);
        assert!(client.verify(&pub_signals, &a, &b, &c, &alpha, &beta, &gamma, &delta, &ic));
        let cpu = env.cost_estimate().budget().cpu_instruction_cost();
        let mem = env.cost_estimate().budget().memory_bytes_cost();
        std::println!("verify(): cpu_instructions = {cpu}, memory_bytes = {mem}");
        assert!(cpu < 100_000_000, "verify must fit the mainnet per-tx CPU limit");
    }

    /// Soundness smoke test: tampering with a public signal must break verification.
    #[test]
    fn rejects_tampered_public_signal() {
        let env = Env::default();
        let vk = fixture_vk(&env);
        // Flip one bit of the nullifier (PUB_1).
        let mut bad = PUB_1;
        bad[31] ^= 0x01;
        let pub_signals = vec![&env, fr(&env, &PUB_0), fr(&env, &bad), fr(&env, &PUB_2), fr(&env, &PUB_3)];
        let a = g1(&env, &PROOF_A);
        let b = g2(&env, &PROOF_B);
        let c = g1(&env, &PROOF_C);
        assert!(
            !groth16_verify(&env, &vk, &pub_signals, &a, &b, &c),
            "a proof with a tampered public signal must NOT verify"
        );
    }
}

#[cfg(test)]
mod multidepth_test {
    use super::*;
    use crate::fixture_multidepth::*;
    use soroban_sdk::{vec, BytesN, Env};

    #[allow(clippy::too_many_arguments)]
    fn verify_case(
        env: &Env,
        pubs: [[u8; 32]; 4],
        a: [u8; 64],
        b: [u8; 128],
        c: [u8; 64],
        al: [u8; 64],
        be: [u8; 128],
        ga: [u8; 128],
        de: [u8; 128],
        ic: [[u8; 64]; 5],
    ) -> bool {
        let p = vec![
            env,
            BytesN::from_array(env, &pubs[0]),
            BytesN::from_array(env, &pubs[1]),
            BytesN::from_array(env, &pubs[2]),
            BytesN::from_array(env, &pubs[3]),
        ];
        let icv = vec![
            env,
            BytesN::from_array(env, &ic[0]),
            BytesN::from_array(env, &ic[1]),
            BytesN::from_array(env, &ic[2]),
            BytesN::from_array(env, &ic[3]),
            BytesN::from_array(env, &ic[4]),
        ];
        verify_encoded(
            env,
            &p,
            &BytesN::from_array(env, &a),
            &BytesN::from_array(env, &b),
            &BytesN::from_array(env, &c),
            &BytesN::from_array(env, &al),
            &BytesN::from_array(env, &be),
            &BytesN::from_array(env, &ga),
            &BytesN::from_array(env, &de),
            &icv,
        )
    }

    /// Real proofs at tree depths 1, 2, 3 and 4 each verify against their own ceremony vkey —
    /// the verifier is depth-general, not depth-2-only.
    #[test]
    fn verifies_depths_1_to_4() {
        let env = Env::default();
        assert!(verify_case(&env, [D1_PUB_0, D1_PUB_1, D1_PUB_2, D1_PUB_3], D1_A, D1_B, D1_C,
            D1_VK_ALPHA, D1_VK_BETA, D1_VK_GAMMA, D1_VK_DELTA,
            [D1_VK_IC_0, D1_VK_IC_1, D1_VK_IC_2, D1_VK_IC_3, D1_VK_IC_4]), "depth 1");
        assert!(verify_case(&env, [D2_PUB_0, D2_PUB_1, D2_PUB_2, D2_PUB_3], D2_A, D2_B, D2_C,
            D2_VK_ALPHA, D2_VK_BETA, D2_VK_GAMMA, D2_VK_DELTA,
            [D2_VK_IC_0, D2_VK_IC_1, D2_VK_IC_2, D2_VK_IC_3, D2_VK_IC_4]), "depth 2");
        assert!(verify_case(&env, [D3_PUB_0, D3_PUB_1, D3_PUB_2, D3_PUB_3], D3_A, D3_B, D3_C,
            D3_VK_ALPHA, D3_VK_BETA, D3_VK_GAMMA, D3_VK_DELTA,
            [D3_VK_IC_0, D3_VK_IC_1, D3_VK_IC_2, D3_VK_IC_3, D3_VK_IC_4]), "depth 3");
        assert!(verify_case(&env, [D4_PUB_0, D4_PUB_1, D4_PUB_2, D4_PUB_3], D4_A, D4_B, D4_C,
            D4_VK_ALPHA, D4_VK_BETA, D4_VK_GAMMA, D4_VK_DELTA,
            [D4_VK_IC_0, D4_VK_IC_1, D4_VK_IC_2, D4_VK_IC_3, D4_VK_IC_4]), "depth 4");
    }

    /// A proof at depth 3 must NOT verify against depth 4's vkey (vkeys are depth-specific).
    #[test]
    fn wrong_depth_vkey_rejected() {
        let env = Env::default();
        assert!(!verify_case(&env, [D3_PUB_0, D3_PUB_1, D3_PUB_2, D3_PUB_3], D3_A, D3_B, D3_C,
            D4_VK_ALPHA, D4_VK_BETA, D4_VK_GAMMA, D4_VK_DELTA,
            [D4_VK_IC_0, D4_VK_IC_1, D4_VK_IC_2, D4_VK_IC_3, D4_VK_IC_4]), "cross-depth vkey must fail");
    }
}
