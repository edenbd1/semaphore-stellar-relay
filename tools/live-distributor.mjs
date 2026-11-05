// Live testnet deploy-then-prove helper for the ConfidentialDistributor with domain separation.
//   node live-distributor.mjs root                   -> {root, vk}
//   node live-distributor.mjs prove <DID> <RECIP>    -> {scope_seed, recipient, entry}
// scope is bound to the deployed distributor address DID; message is bound to RECIP.
import { Identity } from "@semaphore-protocol/identity"
import { Group } from "@semaphore-protocol/group"
import { generateProof, unpackGroth16Proof, verifyProof } from "@semaphore-protocol/proof"
import { keccak256, toBeHex, concat, toUtf8Bytes, getBytes } from "ethers"
import { nativeToScVal, Address } from "@stellar/stellar-sdk"
import { readFileSync } from "fs"
import { tmpdir } from "os"
import { join } from "path"

const VKEY = "/Users/eden/data/semaphore-stellar-relay/fixtures/vkey-depth2.json"
const ART = join(tmpdir(), "snark-artifacts", "semaphore", "4.13.0")
const SNARK = { wasm: join(ART, "semaphore-2.wasm"), zkey: join(ART, "semaphore-2.zkey") }

const A = new Identity("dist-live-member-A")
const B = new Identity("dist-live-member-B")
const C = new Identity("dist-live-member-C")
const group = new Group([A.commitment, B.commitment, C.commitment])

const SEED_HEX = "5c".repeat(32)
const be32 = (d) => BigInt(d).toString(16).padStart(64, "0")
const G1 = (p) => be32(p[0]) + be32(p[1])
const G2 = (p) => be32(p[0][1]) + be32(p[0][0]) + be32(p[1][1]) + be32(p[1][0])
const signalFor = (g) => BigInt(keccak256("0x" + nativeToScVal(new Address(g), { type: "address" }).toXDR("hex")))

const mode = process.argv[2]
if (mode === "root") {
    const vkey = JSON.parse(readFileSync(VKEY, "utf8"))
    console.log(JSON.stringify({
        root: be32(group.root.toString()),
        vk: { alpha: G1(vkey.vk_alpha_1), beta: G2(vkey.vk_beta_2), gamma: G2(vkey.vk_gamma_2), delta: G2(vkey.vk_delta_2), ic: vkey.IC.map(G1) },
    }))
    process.exit(0)
} else if (mode === "prove") {
    const DID = process.argv[3], RECIP = process.argv[4]
    if (!/^C[A-Z0-9]{55}$/.test(DID)) throw new Error("bad DID: " + DID)
    const rawscope = keccak256(concat([toUtf8Bytes(DID), getBytes("0x" + SEED_HEX)]))
    const p = await generateProof(A, group, signalFor(RECIP), BigInt(rawscope), 2, SNARK)
    if (!(await verifyProof(p))) throw new Error("verifyProof failed")
    const u = unpackGroth16Proof(p.points)
    console.log(JSON.stringify({
        scope_seed: SEED_HEX, recipient: RECIP,
        entry: { a: G1(u.pi_a), b: G2(u.pi_b), c: G1(u.pi_c), nullifier: be32(p.nullifier.toString()) },
    }))
    process.exit(0)
} else {
    throw new Error("usage: live-distributor.mjs root | prove <DID> <RECIP>")
}
