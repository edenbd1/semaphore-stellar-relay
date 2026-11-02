// Emit stellar-CLI args for the confidential DAO flow by parsing the Rust fixture
// (contracts/relay/src/fixture.rs) byte-array constants into hex / JSON. No proving.
import { readFileSync } from "fs"
import { fileURLToPath } from "url"
import { dirname, resolve } from "path"
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const src = readFileSync(resolve(root, "contracts/relay/src/fixture.rs"), "utf8")

function constHex(name) {
    const m = src.match(new RegExp(`pub const ${name}:[^=]*=\\s*\\[([^\\]]*)\\];`))
    if (!m) throw new Error("missing const " + name)
    return m[1]
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((b) => parseInt(b, 16).toString(16).padStart(2, "0"))
        .join("")
}
const entry = (p) => ({ a: constHex(`${p}_A`), b: constHex(`${p}_B`), c: constHex(`${p}_C`), nullifier: constHex(`NUL_${p === "A" ? "A" : "B"}`) })

console.log(JSON.stringify({
    payload: constHex("PAYLOAD"),
    root: constHex("ROOT"),
    entry_a: entry("A"),
    entry_b: entry("B"),
    vk: {
        alpha: constHex("VK_ALPHA"),
        beta: constHex("VK_BETA"),
        gamma: constHex("VK_GAMMA"),
        delta: constHex("VK_DELTA"),
        ic: [0, 1, 2, 3, 4].map((i) => constHex(`VK_IC_${i}`)),
    },
}))
