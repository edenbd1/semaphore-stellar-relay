#!/usr/bin/env bash
# Confidential relay flow on testnet: deploy (native XLM SAC pool) -> fund -> relay an
# anonymous member's authorized action, paying the relayer a tip. Usage: scripts/relay-flow.sh [identity]
set -euo pipefail
IDENTITY="${1:-semaphore-dev}"
cd "$(dirname "$0")/.."
stellar keys generate "$IDENTITY" --network testnet 2>/dev/null || true
stellar keys fund "$IDENTITY" --network testnet 2>/dev/null || true
ADMIN=$(stellar keys address "$IDENTITY")
NATIVE=$(stellar contract id asset --asset native --network testnet | tail -1)

stellar contract build
A=$(node tools/emit-relay-args.mjs)
val(){ echo "$A" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const o=JSON.parse(d);console.log($1)})"; }
VK=$(val 'JSON.stringify(o.vk)'); ROOT=$(val 'o.root'); PAY=$(val 'o.payload'); EA=$(val 'JSON.stringify(o.entry_a)')

WASM=target/wasm32v1-none/release/semaphore_relay.wasm
RID=$(stellar contract deploy --wasm "$WASM" --source "$IDENTITY" --network testnet -- \
  --root "$ROOT" --depth 2 --token "$NATIVE" --tip 1000000 --vk "$VK" | grep -oE 'C[A-Z0-9]{55}' | tail -1)
echo "RELAY_ID=$RID"
inv(){ stellar contract invoke --id "$RID" --source "$IDENTITY" --network testnet --send=yes -- "$@"; }
inv fund --from "$ADMIN" --amount 5000000
inv relay --action_digest "$PAY" --scope_seed "$PAY" --relayer "$ADMIN" --entry "$EA"
stellar contract invoke --id "$RID" --source "$IDENTITY" --network testnet -- pool_balance
