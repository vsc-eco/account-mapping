# Account Mapping Contracts

TinyGo WASM smart contracts that bridge account-based blockchains (EVM and ERC-20 compatible) to the VSC/Magi network.

Companion to [vsc-eco/utxo-mapping](https://github.com/vsc-eco/utxo-mapping), which covers UTXO-based chains (BTC, LTC, DASH, DOGE, BCH).

## Supported Chains

| Contract | Chain(s) | Asset |
|----------|----------|-------|
| `evm-mapping-contract` | Ethereum + any EVM L2 (Arbitrum, Optimism, Base, …) | ETH + ERC-20 |

Chain selection is compile-time via the `NetworkMode` ldflag and runtime via `setChainId`.

## How It Works

The contract verifies on-chain deposit proofs (receipt-trie inclusion against a stored block header) and credits the depositor's VSC account with a wrapped token balance. Withdrawals (unmapping) construct and TSS-sign an EVM transaction, returning funds to the user's external address.

The vault, the L1 address that holds mapped funds, is the Ethereum address of the contract's `primary` TSS key; there is no admin setting for it. The address becomes the vault only once the key has shown its committee can sign: `requestVaultCheck` asks the key to sign a fixed personal_sign message naming the contract, its chain and the key, and `attestVault` submits that signature (both permissionless; the bridge bot does it on its own). Until then deposits are refused, so nothing is sent to a key that could not move it.

## Contract Actions

**Deposit & transfer:**
- `map` — process an incoming deposit with a receipt-trie proof
- `transfer` / `transferFrom` / `approve` / `increaseAllowance` / `decreaseAllowance` — ERC-20-style balance operations on mapped tokens
- `confirmSpend` — finalize a pending unmap after its tx confirms on-chain

**Withdrawal:**
- `unmapETH` — withdraw native ETH to an external address
- `unmapERC20` — withdraw a registered ERC-20 token
- `unmapFrom` — withdraw on behalf of a third party via allowance
- `rollWithdrawal` — after 1200 verified L1 blocks, anyone may roll back a withdrawal that never mined: the vault signs a 0-value self-transfer at its nonce, and `confirmSpend` refunds the withdrawer once that mines
- `expireWithdrawal` / `cancelMyWithdrawal` — release a withdrawal that can no longer complete

**Chain relay:** none in this contract. Block headers come from the ZK header verifier contract (`zk-header-verifier`), read through `zkverifier`.

**Vault check:**
- `requestVaultCheck` — ask the active `primary` key to sign the vault check message
- `attestVault` — `{"signature": "<r||s||v hex>"}`: the key's low-S signature over that message; the vault goes live

**Deploy:**
- `initContract` — one-shot, the deployer with active authority: `chain_id` (required), `is_testnet`, and optionally `verifier_contract` and `create_key` to wire the header verifier and request the `primary` TSS key at deploy. Set later, both wait out the 400K-block timelock below, so a bridge deployed without them takes ~14 days to accept its first deposit.

**Admin / owner** (`propose`, then `execute` once the timelock has passed; `cancel`, `expireProposal`):
- ~14 days (400K blocks): `setVerifierContract`, `createKey`, `renewKey`
- 24 hours: `replaceWithdrawal`, `clearNonce`
- 6 hours: `registerToken`, `registerRouter`, `registerRelayer`, `deregisterRelayer`, `clearTestnetState`
- immediate: `pause`, `unpause`

## Repo Layout

```
evm-mapping-contract/
├── Makefile                 # TinyGo build targets (dev/testnet/mainnet/…)
├── go.mod, go.sum
├── contract/                # on-chain logic
│   ├── main.go              # wasmexport entry points
│   ├── blocklist/           # EVM block header relay + reorg
│   ├── mapping/             # deposit/withdrawal flow
│   ├── crypto/              # keccak, RLP, receipt decoding
│   ├── constants/
│   └── contracterrors/
├── monitor/                 # off-chain helpers (scanner, receipt encoding)
├── sdk/                     # VSC WASM runtime bindings
└── runtime/                 # TinyGo GC shim (leaking allocator)
```

## Build

```bash
cd evm-mapping-contract
USE_DOCKER=1 make testnet   # -> bin/testnet.wasm
USE_DOCKER=1 make mainnet   # -> bin/mainnet.wasm
USE_DOCKER=1 make dev       # -> bin/dev.wasm (regtest)
make test                   # Go tests (no TinyGo)
```

Docker is recommended because TinyGo 0.39 requires Go 1.19–1.25 and most dev boxes run newer Go.

## License

See upstream at [vsc-eco/utxo-mapping](https://github.com/vsc-eco/utxo-mapping) — same license applies.
