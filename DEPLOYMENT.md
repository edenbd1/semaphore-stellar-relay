# Testnet deployment

The confidential relay is deployed and exercised live on Stellar **testnet**, moving real
value through a native-XLM tip pool.

| | |
|---|---|
| `ConfidentialRelay` | `CB7LT647EIHJXBT2QO556BBGCZPEUG42SMZ3OPIC6GASBAZFENGYDMSA` |
| Pool token | native XLM SAC `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` |
| Flow | `fund` (0.5 XLM) → `pool_balance` 5,000,000 → `relay` → `pool_balance` 4,000,000 |
| Result | `relayed` event, tip of 1,000,000 stroops (0.1 XLM) paid from pool to relayer |
| Replaying the same authorization | rejected `Error(Contract, #4)` = `AlreadyRelayed` |

Run it: `scripts/relay-flow.sh`.
