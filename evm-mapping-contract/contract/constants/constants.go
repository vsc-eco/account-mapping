package constants

const DirPathDelimiter = "-"

// ALLOW-1 (allowance key collision), the BTC mapping contract's fix ported:
// the allowance key joins the owner and spender identities, both of which may
// contain "-" (Hive usernames allow it). Joined with "-", hive:alice approving
// the spender "bob-hive:mallory" wrote the key of hive:alice-bob's allowance
// for hive:mallory, so mallory could spend alice-bob's balance. The owner part
// is always env.Caller, an authenticated identity, and no identity that can
// own a balance contains "|", so "|" cannot be forged across owners. Spenders
// are also checked with sdk.VerifyAddress (mapping/handlers.go).
const AllowanceDelimiter = "|"

// State key prefixes — mirrors BTC contract pattern
const (
	BalancePrefix           = "a" + DirPathDelimiter // a-{address}-{asset} → balance
	AllowancePrefix         = "q" + AllowanceDelimiter // q|{owner}|{spender}|{asset} → allowance (ALLOW-1, see AllowanceDelimiter)
	ObservedBlockPrefix     = "o" + DirPathDelimiter // o-{height}-... → observed deposits
	// M21-22: per-entry observed keys make IsObserved/MarkObserved O(1) instead
	// of the previous O(N) blob read-append-rewrite (which was O(N^2) per block
	// across all deposits in a block, and an unbounded-blob scan reachable by
	// already-observed-replay spam). Three key families share the "o-" prefix:
	//   presence (dedup):   o-{height}-{hex(34-byte entry)} → "1"   (O(1) get/set)
	//   manifest slot:      o-{height}#{seq}                → entry bytes (cleanup)
	//   manifest length:    oc-{height}                     → decimal count
	// "#" cannot appear in a decimal height or in lowercase hex, so the presence
	// and manifest-slot keys never collide. The manifest exists only so the
	// testnet-only clearTestnetState cleanup can enumerate+delete per-entry keys
	// (the SDK exposes no prefix-delete / key-iteration primitive). MarkObserved
	// appends to the manifest by index (write at slot #count, bump count) without
	// reading prior entries, so MarkObserved is O(1), not O(N).
	ObservedCountPrefix     = "oc" + DirPathDelimiter // oc-{height} → entry count
	ObservedSeqDelimiter    = "#"                     // o-{height}#{seq} → manifest slot
	BlockPrefix             = "b" + DirPathDelimiter // b-{height} → block header data
	TxSpendsPrefix          = "d" + DirPathDelimiter // d-{nonce} → pending withdrawal
	SupplyKey               = "s"                    // supply tracking
	LastHeightKey           = "h"                    // last known block height
	NonceConfirmedKey       = "n"                    // confirmed nonce
	NoncePendingKey         = "np"                   // next pending nonce
	TokenRegistryPrefix     = "t" + DirPathDelimiter // t-{address} → {symbol, decimals}
	RouterContractIdKey     = "routerid"             // DEX router contract ID
	PausedKey               = "paused"               // "1" when paused
	GasReserveKey           = "gr"                   // gas reserve amount (wei — full L1 native precision; big.Int-encoded decimal string)
	VaultKeyCacheKey        = "vaultkey"             // A18: "<TSS pubkey hex>|<0x address>", the vault derived from the key
	VaultCheckedKey         = "vaultok"              // E23: pubkey hex of the primary key whose check signature verified
	ChainIdKey              = "chainid"              // EVM chain ID
	VerifierContractIdKey   = "zkverifier"           // ZK header verifier contract ID
	// MED-33 (M23-F16): block height of the most recent replaceWithdrawal.
	// HandleReplaceWithdrawal gates on this so an admin (or a compromised
	// owner key) cannot spam unbounded TSS signing requests by re-issuing
	// replaceWithdrawal every block — see ReplaceWithdrawalCooldown below.
	//
	// round3 C-SM3 (MED-33 follow-up): this is now a PREFIX, keyed per
	// confirmed-head nonce ("rwlast-{confirmedNonce}"), NOT a single global
	// key. The prior global key was set but never reset, so its wall-clock
	// cooldown bled across distinct withdrawal lifecycles — a freshly-stuck
	// withdrawal could be denied its FIRST fee-bump because an UNRELATED prior
	// withdrawal replaced recently. Per-nonce keying gives each withdrawal its
	// own cooldown clock; no reset bookkeeping is needed because the next
	// withdrawal reads a fresh (empty) key.
	//
	// INFO (round4): the OLD global key literal ("rwlast") written by any
	// pre-round3 deployment is now orphaned — it will never be read or deleted
	// by any handler. On testnet this is harmless (clearTestnetState does not
	// enumerate unknown singleton keys). On a fresh mainnet deploy the old key
	// never exists. No migration action needed; documented here for operator
	// awareness during any future state migration.
	ReplaceWithdrawalLastKey = "rwlast" + DirPathDelimiter // rwlast-{confirmedNonce} → last block a replaceWithdrawal ran for that withdrawal

	// W4 Cluster C CRIT #9 (D-C-4 / v20 §BI): propose/execute timelock state.
	// KeyProposalCounter holds the monotonic uint64 proposal id source.
	// ProposalPrefix builds per-proposal storage keys ("pr-{id}").
	// The Go constant name AND the literal on-chain state key string for
	// the counter are both "proposal_next_id" per v20 §BI (resolves
	// S-C-v19-1 ambiguity — DO NOT shorten to "pc").
	KeyProposalCounter = "proposal_next_id"
	ProposalPrefix     = "pr" + DirPathDelimiter // pr-{proposalId} → JSON PendingProposal

	// W4 Cluster C CRIT #8 native ETH relayer whitelist (S-C-v17-2):
	// per-relayer entry stored under "rl-{hiveAccountName}" → "1".
	RelayerRegistryPrefix = "rl" + DirPathDelimiter // rl-{hive_account} → "1"

	// E1 (RV re-verify): NativeAsset is the one asset symbol that is always
	// valid without a registry entry. AllowedSymbolPrefix+{symbol} is written by
	// RegisterToken as an O(1) allowlist marker so balance/allowance handlers can
	// reject free-form asset strings that would inject arbitrary ledger keys.
	NativeAsset         = "eth"
	AllowedSymbolPrefix = "as" + DirPathDelimiter // as-{symbol} → "1"

	// W4 Cluster C (v20 §BD): oracle account allowed to call addBlocks
	// without going through the propose/execute timelock. addBlocks must
	// remain a high-frequency operational path for the oracle relay; the
	// account identity itself is what is timelocked via setOracleAccount.
	OracleAccountKey = "oracle_account"

	// W4 Cluster C: initContract idempotency marker. initContract sets
	// this to "1" on first successful invocation to make subsequent
	// initContract calls fail (re-entry guard matching Cluster B §BF
	// pattern in zk-header-verifier).
	InitMarkerKey = "init"
)

const MaxBlockRetention = 101
const MaxMPTProofNodes = 20
// round3 C-RV: the per-node MaxMPTNodeSize=4096 cap was removed in R2-1 (it
// wrongly rejected large legitimate receipt-trie leaves) and is now deleted as
// dead code. The real ingress bound is MAX_TX_SIZE=16384 enforced by the
// transaction-pool in go-vsc-node; the in-contract bound is MaxMPTProofNodes.

// MED-66 (T2-7/CF-EVM-4) site 2: upper bound on the per-deposit instruction
// list. routeDeposit iterates MapParams.Instructions and string-slices every
// entry; without a cap an attacker pays dust for a deposit yet attaches a
// huge instruction array, forcing unbounded per-element CPU work (bounded
// only by WASM gas). Real routing needs at most a handful of directives
// (deposit_to / swap_to / asset_out / destination_chain), so 16 is generous
// headroom. Over the cap routeDeposit skips instruction parsing entirely and
// credits the depositor's own derived DID.
const MaxDepositInstructions = 16

// MED-20 (M18-D9): upper bound on a registered token's MinWithdrawal. Without
// a ceiling the owner could set MinWithdrawal=MaxInt64, which makes every
// unmap of that token revert at the `amount < tokenInfo.MinWithdrawal` gate —
// an admin-induced per-token DoS. 1e15 in token-native units is far above any
// real per-tx minimum (1e9 USDC at 6 decimals) yet leaves headroom below the
// downstream int64 fee/amount arithmetic.
const MaxTokenMinWithdrawal = int64(1_000_000_000_000_000)

// MED-21 (M18-D20): max byte length of a token symbol. The registry record is
// pipe-delimited (`symbol|decimals|minWithdrawal`); an unbounded or
// pipe-bearing symbol corrupts the positional parse. The length cap bounds
// the stored record; the `|` rejection (handlers.go RegisterToken) preserves
// the field structure.
const MaxTokenSymbolLen = 32

// Gas constants
const ETHTransferGas = uint64(21_000)
const ERC20TransferGas = uint64(65_000)

// Minimum withdrawal amounts (in token-native units).
// big.Int/wei migration: native ETH accounting is now full wei (18 decimals),
// no gwei scaling. These thresholds are bounded config values (well within
// int64) compared against big.Int amounts via big.NewInt at the call site;
// the unbounded accounting values (balances/supply/amounts) are *big.Int.
// 0.01 ETH = 10_000_000_000_000_000 wei.
// MaxPricingHeaderAge (LOW 10): a new withdrawal is priced from the newest L1
// header only while that header is at most this many seconds older than the L2
// block time. An hour is ~300 ETH blocks; the 2x base-fee margin covers normal
// moves over that span, a stalled header feed does not.
const MaxPricingHeaderAge uint64 = 3600

const MinETHWithdrawal = int64(10_000_000_000_000_000) // 0.01 ETH in WEI
const MinUSDCWithdrawal = int64(10_000_000)            // 10 USDC in micro-units

// Gas reserve
const GasReserveDepositTaxBps = int64(100) // 1% of ETH deposits go to gas reserve
// big.Int/wei migration: the reserve accumulator (GasReserveKey) is denominated
// in WEI. It is funded only by the proof-backed `to_reserve` deposit
// instruction and the 1% deposit tax — there is no admin write path.
// 0.05 ETH = 50_000_000_000_000_000 wei.
const MinGasReserve = int64(50_000_000_000_000_000) // 0.05 ETH in WEI minimum reserve

// W4 Cluster E CRIT #26 + D-E-3 (LOCKED): withdrawal auto-expiry window. Any
// L2 caller can submit `expireWithdrawal` once the verified L1 chain
// (blocklist.GetLastHeight) is WithdrawalExpiryWindow blocks past
// pending.BlockHeight, with an L1-proof-of-drop per D-E-4.
//
// E22: pending.BlockHeight is an L1 height. The window was 5000 "Hive blocks"
// compared against the Hive height, which is far above any L1 height, so it
// was always open. It is now 1200 L1 blocks (about 4 hours at 12 s).
const WithdrawalExpiryWindow uint64 = 1200

// D3: L1 blocks (of the verified header chain) after the withdrawal was queued
// before anyone may roll it back with rollWithdrawal: 1200 blocks, about 4
// hours at 12 s. PendingSpend.BlockHeight is an L1 height, so the window is
// counted in L1 blocks against blocklist.GetLastHeight().
const WithdrawalRollWindow uint64 = 1200

// MED-33 (M23-F16): minimum number of Hive blocks between two consecutive
// replaceWithdrawal executions. replaceWithdrawal calls sdk.TssSignKey on
// every invocation; without a cooldown, repeated execution burns TSS signing
// resources unbounded (the propose/execute timelock rate-limits the FIRST
// hop, but once a proposal is executable nothing stopped re-running it). A
// stuck tx legitimately needs at most one fee-bump per few minutes; 200
// blocks ≈ 10 minutes at Hive 3s cadence is comfortably above any real
// re-broadcast cadence while capping the TSS request rate.
const ReplaceWithdrawalCooldown uint64 = 200

// W4 Cluster E §D-E-8 + Cluster B §BG: chain-gate state key set by
// initContract when IsTestnet=true. clearTestnetState reads this key and
// aborts if absent or != "true".
const IsTestnetKey = "is_testnet"
