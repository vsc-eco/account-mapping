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
- `map` — process an incoming deposit with a trie proof: `deposit_type` `eth` (a plain transfer to the vault, credited to its sender or to the depositor-signed `deposit_to=` calldata), `erc20` (a Transfer to the vault, credited to its sender), or `contract` (a `Deposit` log of the vault's MagiDeposit, credited to the recipient it names; `receipt_proof` base64). Anyone may map (RP-8). Limits: a deposit below a tenth of its asset's minimum withdrawal (ETH 0.001, a token min_withdrawal / 10, USDC at 10 USDC: 1 USDC) is never credited (DUST-1, like the BTC contract's MinDepositSats) and stays in the vault; and a deposit whose transaction receipt is over ~4 KB (about 25 Transfer-sized logs, e.g. inside a batch payout, a long multicall or a many-op 4337 bundle) cannot be proven within the node's 8,192-byte call payload and is never credited (RCPTCAP-1; the BTC bot records an oversize deposit the same way, THORChain ignores an inbound over 200 logs). Deposit with a plain transfer, or a direct `deposit`/`depositToken` call.
- `depositAddress` — the vault's MagiDeposit address (RP-7). MagiDeposit (`l1-deposit/`) takes `deposit(recipient)` with ETH and `depositToken(token, amount, recipient)` (after `approve`), forwards everything to the vault in the same call and holds nothing. Use it for a deposit from a smart wallet, a custodian or any contract, or to credit someone else; it is deployed by CREATE2 through the deterministic deployment proxy (`0x4e59b44847b379578588920cA78FbF26c0B4956C`, salt 0, init code = its creation code ++ the vault), so anyone can deploy it for a vault and the bridge accepts `Deposit` logs only from that address. Plain transfers keep working as before. Never show this address as one to send to: tokens sent to it with a plain `transfer`, or ETH sent before it is deployed, cannot be moved by anyone (it has no sweep, owner or upgrade). Plain ETH sends to it revert.
- `transfer` / `transferFrom` / `approve` / `increaseAllowance` / `decreaseAllowance` — ERC-20-style balance operations on mapped tokens
- `confirmSpend` — finalize a pending unmap after its tx confirms on-chain

**Withdrawal:**
- `unmapETH` — withdraw native ETH to an external address. Optional `gas_limit` (21,000..1,000,000, else the owner's `setETHGasLimit` default, else 21,000): under Glamsterdam's state-creation pricing (EIP-8037; live on Sepolia since 2026-10-06) a transfer to an address that does not exist yet costs ~200k gas and reverts at 21,000 (its fee is then lost), so a front end should pass `eth_estimateGas` for the recipient (GLAM-1)
- `unmapERC20` — withdraw a registered ERC-20 token (its gas limit is the one it was registered with)
- `unmapFrom` — withdraw on behalf of a third party via allowance
- Up to 8 withdrawals are in flight at once on consecutive vault nonces and confirm in nonce order (RP-11). With nothing waiting, an unmap is issued (priced and TSS-signed) at once and returns `issued:{nonce}`; otherwise it waits in an L2 queue (FIFO, up to 1,024) and returns `queued:{seq}`. Nothing another user does refuses a withdrawal; only a full queue does.
- `drainWithdrawalQueue` — `{"max": n}` (default 1, at most 8): issue queued withdrawals into free slots (permissionless; the bot calls it). Only this call issues queued ones. A queued withdrawal its own terms cannot pay at the current price (the ETH fee above its `max_fee` or above a `deduct_fee` amount, an ERC-20 transfer's gas above its `max_fee`) is refunded to its owner in full instead (QFREEZE-1, as the BTC contract's drain does); one waiting on the gas reserve stays queued. Up to 32 entries are issued or refunded per call (~1,235 RC per refund).
- `cancelQueuedWithdrawal` — `{"seq": n}`: the owner of a queued (not yet issued) withdrawal, or the contract owner, takes it back in full to the withdrawal's owner
- `rollWithdrawal` — after 1200 verified L1 blocks, anyone may roll back a withdrawal that never mined: the vault signs a 0-value self-transfer at its nonce, and `confirmSpend` refunds the withdrawer once that mines. The refund is the withdrawal's amount; the L1 fee prepaid with it is not returned (the vault pays for the roll itself)
- `expireWithdrawal` / `cancelMyWithdrawal` — release a withdrawal that can no longer complete

**Chain relay:** none in this contract. Block headers come from the ZK header verifier contract (`zk-header-verifier`), read through `zkverifier`.

**Vault check:**
- `requestVaultCheck` — ask the active `primary` key to sign the vault check message
- `attestVault` — `{"signature": "<r||s||v hex>"}`: the key's low-S signature over that message; the vault goes live

**Deploy:**
- `initContract` — one-shot, the deployer with active authority: `chain_id` (required), `is_testnet`, and optionally `verifier_contract` and `create_key` to wire the header verifier and request the `primary` TSS key at deploy. Set later, both wait out the 400K-block timelock below, so a bridge deployed without them takes ~14 days to accept its first deposit.

**Admin / owner** (`propose`, then `execute` once the timelock has passed; `cancel`, `expireProposal`):
- ~14 days (400K blocks): `setVerifierContract`, `createKey`
- 24 hours: `replaceWithdrawal`, `clearNonce`
- 6 hours: `registerToken`, `registerRouter`, `registerRelayer`, `deregisterRelayer`, `clearTestnetState`, `setETHGasLimit` (`{"gas_limit"}`, the default gas of an ETH withdrawal; raise it when the chain prices account creation higher), `setProofFee` (`{"asset", "amount"}`, see below)
- immediate: `pause`, `unpause`, `renewKey` (also while paused)

`registerToken` takes `{"address", "symbol", "decimals", "min_withdrawal"}` and optionally `revert_fee` (token units kept from a withdrawal whose L1 transfer reverts, e.g. to a blacklisted address; at most `min_withdrawal`; credited to the owner; USDC-1 B) and `gas_limit` (the token transfer's L1 gas, 21,000..500,000, default 65,000; a transfer to a first-time holder costs far more under Glamsterdam's pricing, so measure it with `eth_estimateGas` and register that; USDC-GAS-1 / GLAM-1). The symbol is the token's ledger asset (the `asset` of `transfer` and the allowance actions; case-sensitive). A symbol belongs to one token, and a registered token keeps its symbol: re-registering it under the same symbol only changes the other fields.

**Proving fee.** Every deposit and withdrawal needs its L1 block's header proven on Magi, which the operator buys from the Succinct Prover Network (about 0.4 PROVE a proof, several operations sharing one proof inside a 10-minute window). `setProofFee` sets, per asset (`"eth"` or a registered token's symbol), a flat fee in the asset's smallest unit, at most half the asset's smallest creditable deposit (ETH 0.0005; USDC at a 10 USDC minimum withdrawal: 0.5 USDC), and `registerToken` refuses a new `min_withdrawal` that would put the token's fee above that (lower the fee first); `"0"` removes it, and an asset with no fee set charges nothing. The contract cannot read the PROVE price, so the owner re-sets the fee when it moves. It is paid to `hive:altera.app` as an ordinary Magi balance:
- a deposit (`eth`, `erc20` and `contract` maps) pays it out of its credit, after the 1% ETH reserve share; a reserve deposit (`to_reserve=1`) pays none;
- a withdrawal (`unmapETH`, `unmapERC20`, `unmapFrom`) pays it on top of its debit, and is refused when the balance (and, for `unmapFrom`, the spender's allowance) does not cover both. It is not refunded if the withdrawal is later cancelled or refunded: the request has already caused the proving.

RC on the node runtime (measured on the bridge wasm): `unmapETH` ~9,400 RC, ~10,000 with the proving fee; `unmapERC20` ~12,900. Use an `rc_limit` of at least 15,000 for `unmapETH` and 20,000 for `unmapERC20`.

A token withdrawal's gas is paid from the bridge's ETH gas reserve, which must hold at least 0.05 ETH (`MinGasReserve`) when it is issued; until then it waits in the queue. An ETH withdrawal pays its own gas and does not need the reserve (RP-4). A fresh bridge's reserve is 0 and grows by 1% of each ETH deposit, so seed it: an ETH deposit to the vault whose calldata is `to_reserve=1` goes wholly to the reserve.

The `primary` key expires 365 epochs (~91 days) after keygen and retires ~14 days after that; a retired key can never sign, so every deposit in the vault would stay there. Run `renewKey` before expiry (the bot warns from 7 days out, and when the key has expired).

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
