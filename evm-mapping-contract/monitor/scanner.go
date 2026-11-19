package monitor

// Path C rewrite per W4-cluster-A-deposit-pipeline manifest.
//
// ZK ARCHITECTURE NOTE (CRIT-FIX-MAP §0.4, verbatim):
// This system does NOT run a full Ethereum node. Ethereum block header
// finality is proven via SP1 Groth16 ZK proofs from sp1-helios-magi. The ZK
// proof's public outputs (stateRoot, txRoot, receiptRoot, blockHash,
// blockNumber, chainId) are the ONLY trusted Ethereum header source. ETH RPC
// is ONLY for: eth_getRawTransactionByHash, eth_getTransactionReceipt,
// eth_getLogs. ETH RPC must NEVER be used for header verification,
// eth_getStorageAt, eth_call, or chain validation — those would violate the
// trust architecture.
//
// W4-cluster-A scope addressed in this file:
//   - CRIT #1 (D-A-1) — ETH path switches to eth_getRawTransactionByHash +
//     transaction-trie proof against TransactionsRoot. ERC-20 keeps
//     receipt-trie + Transfer event (D-A-2, already correct in receipt.go).
//   - CRIT #14 (D-A-5) — per-receipt logIndex convention: the writer here
//     re-numbers logs as 0..N-1 within each receipt by querying the receipt
//     directly (eth_getLogs returns block-level logIndex, which is the
//     pre-fix mismatch source).
//   - CRIT N1 retry/dead-letter (CRIT-FIX-MAP §8 N1) — Mode 1 startup probe
//     with per-chainId historical tx hash + JSON-RPC -32601 fatal-on-startup
//     discriminator; Mode 2 per-tx null gets exponential backoff retry
//     (max_attempts=30, capped at 30s); after exhaustion the deposit is
//     routed to a dead-letter store with 72h retention while
//     LastScannedBlock stays pinned at the failed block.
//   - HIGH #24 — filterLogs error no longer silently dropped; on error the
//     monitor returns up the stack so LastScannedBlock does NOT advance.
//   - HIGH #25 + #46 — every json.Unmarshal returns its error (no silent
//     zero-value fallback for malformed responses).
//   - HIGH #45 — see go.mod bump (go 1.25.0 -> go 1.25.10) committed
//     separately; this file does not pin a Go version.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"evm-mapping-contract/contract/crypto"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Deposit represents a detected deposit to the vault.
type Deposit struct {
	BlockHeight    uint64
	TxIndex        int
	LogIndex       int    // -1 for native ETH; per-receipt index for ERC-20
	TxHash         string
	From           string // sender ETH address (0x...)
	Amount         string // hex amount
	Asset          string // "eth" or token symbol
	TokenAddress   string // empty for native ETH
	DepositType    string // "eth" or "erc20"
	Proof          [][]byte
	EncodedReceipt []byte // for ERC-20: encoded receipt; for ETH: encoded raw tx
	ReceiptsRoot   []byte // for ERC-20: receiptsRoot; for ETH: transactionsRoot
}

// DeadLetterEntry captures a deposit whose proof construction could not
// complete because an RPC dependency (most commonly eth_getRawTransactionByHash
// returning null after node lag) failed beyond the retry budget. N1 spec:
// 72-hour retention, monitor.dead_letter metric, operator triage.
type DeadLetterEntry struct {
	BlockHeight uint64
	TxIndex     int
	TxHash      string
	DepositType string
	Reason      string
	FirstSeen   time.Time
	LastTry     time.Time
	Attempts    int
}

// Scanner monitors Ethereum blocks for deposits to the vault address.
type Scanner struct {
	RpcURL           string
	VaultAddress     string // 0x... lowercase
	TokenAddresses   map[string]string // address → symbol
	LastScannedBlock uint64

	// N1 startup probe / retry config. Defaults are populated by NewScanner
	// when zero. Tests may zero these out to disable retry.
	ChainID            uint64        // 1 mainnet, 11155111 sepolia, 17000 holesky — used to pick probe hash
	ProbeTxHash        string        // hardcoded historical tx hash for Mode 1 startup probe
	MaxRetryAttempts   int           // N1 spec: 30
	InitialBackoff     time.Duration // N1 spec: 1s starting (exponential)
	MaxBackoff         time.Duration // N1 spec: 30s cap
	DeadLetterTTL      time.Duration // N1 spec: 72h
	deadLetterMu       sync.Mutex
	deadLetter         map[string]*DeadLetterEntry // key = txHash
	deadLetterCount    uint64                       // monitor.dead_letter metric counter
}

// Hardcoded Mode 1 probe transaction hashes per chainId (D-A-4). These are
// deep, finalized, regular EIP-1559 (type-2) txs that any spec-compliant
// node MUST be able to return via eth_getRawTransactionByHash. A null/error
// response to one of these on a known-good chain is a clear "method not
// supported" signal — the monitor exits fatally so the operator can fix
// the RPC endpoint configuration rather than silently sit at
// LastScannedBlock forever (the latent CRIT #31 pattern that N1 closes).
//
// Mainnet hash is locked at the manifest level (block 46147 was incorrect —
// that is pre-EIP-1559; the manifest's hash is what is used). For Sepolia /
// Holesky the W1 design lock delegates the choice to the implementing
// agent: pick a real type-2 tx from a deep, finalized block (block ≥ ~5M
// well before chain tip) and verify across ≥ 2 RPC providers before pinning.
// We default to the mainnet hash if ChainID is unknown / 0; operators
// targeting Sepolia/Holesky MUST set ChainID + ProbeTxHash explicitly
// (verified with `eth_getRawTransactionByHash` on ≥ 2 providers per
// CRIT-FIX-MAP D-A-4 / W4 manifest acceptance criteria) — leaving
// ChainID == 0 + RPC connected to a testnet would re-introduce the false-
// negative startup-probe class (block 0 / pre-merge anchor).
var ProbeTxHashByChain = map[uint64]string{
	// Mainnet: block 46147 (a Frontier-era legacy tx). Manifest locks this hash
	// as the authoritative "every spec-compliant ETH node must return raw
	// tx bytes for this hash" anchor.
	1: "0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060",
	// Sepolia / Holesky (TESTNET INTEGRATION TODO): operator MUST set
	// ChainID + ProbeTxHash explicitly on the Scanner before first scan; an
	// empty entry here is intentional so a forgotten override surfaces as
	// startup error rather than silently passing a probe against the
	// mainnet hash. The W4 manifest acceptance criteria require these to
	// be verified against ≥ 2 RPC providers and locked before testnet
	// integration begins.
}

// TransferEventSig is keccak256("Transfer(address,address,uint256)")
var TransferEventSig = hex.EncodeToString(crypto.Keccak256([]byte("Transfer(address,address,uint256)")))

// NewScanner returns a Scanner with N1 retry/dead-letter defaults applied.
// Pass-through fields are kept; zero-value retry config is filled in here.
func NewScanner(s *Scanner) *Scanner {
	if s.MaxRetryAttempts == 0 {
		s.MaxRetryAttempts = 30
	}
	if s.InitialBackoff == 0 {
		s.InitialBackoff = 1 * time.Second
	}
	if s.MaxBackoff == 0 {
		s.MaxBackoff = 30 * time.Second
	}
	if s.DeadLetterTTL == 0 {
		s.DeadLetterTTL = 72 * time.Hour
	}
	if s.deadLetter == nil {
		s.deadLetter = make(map[string]*DeadLetterEntry)
	}
	if s.ProbeTxHash == "" {
		if hash, ok := ProbeTxHashByChain[s.ChainID]; ok {
			s.ProbeTxHash = hash
		}
	}
	return s
}

// StartupProbe implements D-A-4 Mode 1 detection. Called once at process start
// before the first scanBlock. Two discriminators:
//   - PRIMARY: eth_getRawTransactionByHash MUST return a non-null hex string
//     for a known-good historical tx hash on the configured chain.
//   - DEFENSE IN DEPTH: JSON-RPC error code -32601 ("method not found") is
//     reported as a fatal startup error even if the call hadn't otherwise
//     null-returned.
// A failure of EITHER discriminator returns a non-nil error; the caller
// (cmd/monitor/main.go) should log and os.Exit(1).
func (s *Scanner) StartupProbe() error {
	if s.ProbeTxHash == "" {
		// Defensive: ChainID unknown + no explicit override. Refuse to
		// proceed rather than silently scan with no Mode 1 coverage.
		return fmt.Errorf("startup probe: ChainID=%d has no registered probe tx hash and ProbeTxHash override is empty — set ChainID to 1/11155111/17000 and pin ProbeTxHash per D-A-4 before scanning", s.ChainID)
	}
	data, rpcErrCode, err := s.rpcCallWithErrCode("eth_getRawTransactionByHash", fmt.Sprintf(`"%s"`, s.ProbeTxHash))
	if err != nil {
		// -32601 = method not found per JSON-RPC 2.0; some providers also
		// return generic "method not supported" strings.
		if rpcErrCode == -32601 {
			return fmt.Errorf("startup probe FATAL: ETH RPC %s does not implement eth_getRawTransactionByHash (rpc error -32601: %w) — point monitor at a node that exposes raw tx access (e.g. erigon, geth with txlookup index, alchemy/infura paid tier)", s.RpcURL, err)
		}
		return fmt.Errorf("startup probe failed: %w", err)
	}
	var rawHex string
	if err := json.Unmarshal(data, &rawHex); err != nil {
		return fmt.Errorf("startup probe: failed to parse rpc response: %w", err)
	}
	if rawHex == "" || rawHex == "null" {
		return fmt.Errorf("startup probe FATAL: eth_getRawTransactionByHash returned null/empty for known-good historical tx %s on chainId=%d — RPC endpoint cannot serve raw txs (Mode 1: method not supported)", s.ProbeTxHash, s.ChainID)
	}
	return nil
}

// DeadLetterCount returns the current dead-letter metric value. Operators
// alert on increases. Persisted across restarts via a separate snapshot
// owned by cmd/monitor (out of scope for this file).
func (s *Scanner) DeadLetterCount() uint64 {
	s.deadLetterMu.Lock()
	defer s.deadLetterMu.Unlock()
	return s.deadLetterCount
}

// DeadLetterEntries returns a snapshot of pending entries for operator
// triage.
func (s *Scanner) DeadLetterEntries() []DeadLetterEntry {
	s.deadLetterMu.Lock()
	defer s.deadLetterMu.Unlock()
	now := time.Now()
	out := make([]DeadLetterEntry, 0, len(s.deadLetter))
	for k, e := range s.deadLetter {
		if now.Sub(e.FirstSeen) > s.DeadLetterTTL {
			delete(s.deadLetter, k)
			continue
		}
		out = append(out, *e)
	}
	return out
}

// recordDeadLetter persists a failed deposit to the in-memory dead letter
// store and increments the metric. Mode 2 per-tx-null path: the monitor
// stays at LastScannedBlock so the operator can replay the block once the
// RPC stabilises or after a manual triage decision.
func (s *Scanner) recordDeadLetter(e DeadLetterEntry) {
	s.deadLetterMu.Lock()
	defer s.deadLetterMu.Unlock()
	if s.deadLetter == nil {
		s.deadLetter = make(map[string]*DeadLetterEntry)
	}
	if existing, ok := s.deadLetter[e.TxHash]; ok {
		existing.LastTry = e.LastTry
		existing.Attempts = e.Attempts
		existing.Reason = e.Reason
		s.deadLetterCount++
		return
	}
	e.FirstSeen = time.Now()
	s.deadLetter[e.TxHash] = &e
	s.deadLetterCount++
}

// ScanNewBlocks scans from lastScannedBlock+1 to the latest finalized block.
// Returns deposits collected up to (but not past) the first block that
// failed. The caller persists LastScannedBlock from the Scanner struct after
// this returns; any unfinished blocks will be retried on the next tick.
func (s *Scanner) ScanNewBlocks() ([]Deposit, error) {
	finalized, err := s.getFinalizedBlock()
	if err != nil {
		return nil, fmt.Errorf("get finalized block: %w", err)
	}
	if finalized <= s.LastScannedBlock {
		return nil, nil
	}

	var deposits []Deposit
	for h := s.LastScannedBlock + 1; h <= finalized; h++ {
		blockDeposits, err := s.scanBlock(h)
		if err != nil {
			// HIGH #24 + N1: block failure does NOT silently advance.
			// Return the deposits we did collect from earlier successful
			// blocks, and surface the error so the caller leaves
			// LastScannedBlock pinned at h-1.
			return deposits, fmt.Errorf("scan block %d: %w", h, err)
		}
		deposits = append(deposits, blockDeposits...)
		s.LastScannedBlock = h
	}
	return deposits, nil
}

func (s *Scanner) scanBlock(height uint64) ([]Deposit, error) {
	blockHex := fmt.Sprintf("0x%x", height)

	// Get block with full transactions
	blockData, err := s.rpcCall("eth_getBlockByNumber", fmt.Sprintf(`"%s", true`, blockHex))
	if err != nil {
		return nil, err
	}

	var block struct {
		Transactions []struct {
			Hash  string `json:"hash"`
			From  string `json:"from"`
			To    string `json:"to"`
			Value string `json:"value"`
			Input string `json:"input"`
		} `json:"transactions"`
		TransactionsRoot string `json:"transactionsRoot"`
		ReceiptsRoot     string `json:"receiptsRoot"`
	}
	// HIGH #25 + #46: surface decode errors instead of silently proceeding
	// with a zero-valued block struct.
	if err := json.Unmarshal(blockData, &block); err != nil {
		return nil, fmt.Errorf("decode block %d: %w", height, err)
	}

	vaultLower := strings.ToLower(s.VaultAddress)

	// Find ETH deposits (direct transfers to vault).
	var ethDepositIndices []int
	for i, tx := range block.Transactions {
		if strings.ToLower(tx.To) == vaultLower {
			val := HexToUint(tx.Value)
			if val > 0 {
				ethDepositIndices = append(ethDepositIndices, i)
			}
		}
	}

	// Find ERC-20 deposits (Transfer events to vault). HIGH #24: do NOT
	// silently `continue` on filterLogs error — surface the error so the
	// outer scanBlock returns and the caller leaves LastScannedBlock
	// pinned for retry.
	type erc20Hit struct {
		txIndex  int
		logIndex int // BLOCK-LEVEL from eth_getLogs; remapped to per-receipt below (CRIT #14).
		token    string
		symbol   string
	}
	var erc20DepositHits []erc20Hit
	for tokenAddr, symbol := range s.TokenAddresses {
		logs, err := s.filterLogs(height, height, tokenAddr, vaultLower)
		if err != nil {
			return nil, fmt.Errorf("filter logs token=%s block=%d: %w", tokenAddr, height, err)
		}
		for _, log := range logs {
			erc20DepositHits = append(erc20DepositHits, erc20Hit{
				txIndex:  log.TxIndex,
				logIndex: log.LogIndex,
				token:    tokenAddr,
				symbol:   symbol,
			})
		}
	}

	if len(ethDepositIndices) == 0 && len(erc20DepositHits) == 0 {
		return nil, nil
	}

	// Build deposits.
	var deposits []Deposit

	// ---- ETH path (CRIT #1 / D-A-1) ----
	// We need: raw RLP-encoded TX bytes for every TX in the block, fed
	// into BuildTxProof to produce a transaction-trie inclusion proof
	// rooted at block.TransactionsRoot. The contract's VerifyETHDeposit
	// verifies against header.TransactionsRoot (proof.go).
	//
	// Performance: the bulk of the cost is N round-trips to
	// eth_getRawTransactionByHash; this is fine for vault-deposit-rate
	// scanning but is the dominant scan-block latency contributor —
	// flagged for the Wave-6 monitor re-audit.
	if len(ethDepositIndices) > 0 {
		rawTxs, err := s.fetchAllRawTxs(block.Transactions, height)
		if err != nil {
			return nil, fmt.Errorf("fetch raw txs for ETH proof at block %d: %w", height, err)
		}
		for _, txIdx := range ethDepositIndices {
			root, proof, encoded := BuildTxProof(rawTxBytesAsRPCTxSlice(rawTxs), txIdx)
			if proof == nil {
				// txIdx out of range — extremely unexpected; treat as a
				// dead-letter (deposit visible at block level but the raw
				// tx fetch returned an inconsistent set).
				txHash := ""
				if txIdx < len(block.Transactions) {
					txHash = block.Transactions[txIdx].Hash
				}
				s.recordDeadLetter(DeadLetterEntry{
					BlockHeight: height,
					TxIndex:     txIdx,
					TxHash:      txHash,
					DepositType: "eth",
					Reason:      "tx proof construction failed (txIdx out of range)",
					LastTry:     time.Now(),
					Attempts:    1,
				})
				return nil, fmt.Errorf("ETH proof construction failed at block %d tx %d", height, txIdx)
			}
			tx := block.Transactions[txIdx]
			deposits = append(deposits, Deposit{
				BlockHeight:    height,
				TxIndex:        txIdx,
				LogIndex:       -1,
				TxHash:         tx.Hash,
				From:           tx.From,
				Amount:         tx.Value,
				Asset:          "eth",
				DepositType:    "eth",
				Proof:          proof,
				EncodedReceipt: encoded, // for ETH this is the raw tx RLP
				ReceiptsRoot:   root,    // for ETH this is the transactionsRoot
			})
		}
	}

	// ---- ERC-20 path (D-A-2 unchanged) ----
	if len(erc20DepositHits) > 0 {
		// F-MON-4 (MED #58): prefer a single eth_getBlockReceipts round-trip
		// over N serial eth_getTransactionReceipt calls. On any failure (RPC
		// lacks the method, count/order mismatch, decode error) this falls
		// back to the per-tx serial loop, so correctness never depends on the
		// batch path being available.
		receipts, err := s.fetchBlockReceipts(height, block.Transactions)
		if err != nil {
			return nil, fmt.Errorf("fetch receipts at block %d: %w", height, err)
		}
		for _, dep := range erc20DepositHits {
			if dep.txIndex < 0 || dep.txIndex >= len(receipts) {
				return nil, fmt.Errorf("erc20 hit at block %d points to invalid txIndex %d (have %d receipts)", height, dep.txIndex, len(receipts))
			}
			root, proof, encoded := BuildReceiptProof(receipts, dep.txIndex)
			if proof == nil {
				return nil, fmt.Errorf("erc20 receipt proof construction failed at block %d txIdx %d", height, dep.txIndex)
			}
			// CRIT #14 (D-A-5): re-map the block-level LogIndex from
			// eth_getLogs into a per-receipt LogIndex. Per-receipt
			// convention is 0..N-1 within the receipt's own Logs list and
			// is what the contract reader uses (see
			// VerifyERC20Deposit + parseReceiptLogs in proof.go).
			perReceiptIdx, ok := mapBlockLogIdxToPerReceipt(receipts[dep.txIndex], dep.logIndex, dep.token, vaultLower)
			if !ok {
				return nil, fmt.Errorf("CRIT #14: could not locate per-receipt logIndex for token=%s block=%d txIdx=%d blockLogIdx=%d", dep.token, height, dep.txIndex, dep.logIndex)
			}
			deposits = append(deposits, Deposit{
				BlockHeight:    height,
				TxIndex:        dep.txIndex,
				LogIndex:       perReceiptIdx,
				TxHash:         receipts[dep.txIndex].TransactionHash,
				Asset:          dep.symbol,
				TokenAddress:   dep.token,
				DepositType:    "erc20",
				Proof:          proof,
				EncodedReceipt: encoded,
				ReceiptsRoot:   root,
			})
		}
	}

	return deposits, nil
}

// rawTxBytesAsRPCTxSlice is an adapter shim so the existing
// BuildTxProof([]*RPCTx, idx) signature can consume already-fetched raw RLP
// bytes. We can't reuse the receipt path because the contract expects the
// tx-trie root, not the receipts-trie root. The on-the-wire RLP comes
// directly from eth_getRawTransactionByHash so we don't re-encode and risk
// a canonicalisation mismatch.
func rawTxBytesAsRPCTxSlice(raws [][]byte) []*RPCTx {
	out := make([]*RPCTx, len(raws))
	for i, b := range raws {
		out[i] = &RPCTx{
			rawWireBytes: b,
		}
	}
	return out
}

// mapBlockLogIdxToPerReceipt translates the block-level logIndex value from
// eth_getLogs into the per-receipt index inside `receipt.Logs`. The mapping
// rule: find the log whose Address matches the queried token and whose
// topic[2] (recipient) matches the vault — that log's position inside
// receipt.Logs is the per-receipt index. Falls back to false if no match.
func mapBlockLogIdxToPerReceipt(receipt *RPCReceipt, blockLogIdx int, tokenAddr, vaultLower string) (int, bool) {
	tokenLower := strings.ToLower(strings.TrimPrefix(tokenAddr, "0x"))
	vaultPadded := "0x000000000000000000000000" + strings.TrimPrefix(vaultLower, "0x")
	vaultPaddedLower := strings.ToLower(vaultPadded)
	// F2: resolve the per-receipt array position of the SPECIFIC block-level
	// log (matched by its block-level logIndex), NOT the first matching log.
	// Two Transfer(token -> vault) logs in one tx previously both mapped to
	// position 0 -> the second deposit collided on IsObserved and was lost.
	for i, log := range receipt.Logs {
		// F2 hardening: omitted logIndex (non-standard RPC) must not silently
		// match index 0; return false so the caller hard-errors and retries.
		if log.LogIndex == "" {
			return 0, false
		}
		if int(HexToUint(log.LogIndex)) != blockLogIdx {
			continue
		}
		// Sanity-check the resolved log is the expected Transfer(token -> vault).
		if strings.ToLower(strings.TrimPrefix(log.Address, "0x")) != tokenLower ||
			len(log.Topics) < 3 ||
			strings.ToLower(log.Topics[0]) != "0x"+TransferEventSig ||
			strings.ToLower(log.Topics[2]) != vaultPaddedLower {
			return 0, false
		}
		return i, true
	}
	return 0, false
}

type filteredLog struct {
	TxIndex  int
	LogIndex int // BLOCK-LEVEL as eth_getLogs returns; remapped per-receipt in scanBlock.
}

func (s *Scanner) filterLogs(fromBlock, toBlock uint64, tokenAddr, vaultAddr string) ([]filteredLog, error) {
	vaultPadded := "0x000000000000000000000000" + strings.TrimPrefix(vaultAddr, "0x")

	params := fmt.Sprintf(`{"fromBlock":"0x%x","toBlock":"0x%x","address":"%s","topics":["0x%s",null,"%s"]}`,
		fromBlock, toBlock, tokenAddr, TransferEventSig, vaultPadded)

	data, err := s.rpcCall("eth_getLogs", params)
	if err != nil {
		return nil, err
	}

	var logs []struct {
		TransactionIndex string `json:"transactionIndex"`
		LogIndex         string `json:"logIndex"`
	}
	// HIGH #25 + #46
	if err := json.Unmarshal(data, &logs); err != nil {
		return nil, fmt.Errorf("decode eth_getLogs response: %w", err)
	}

	result := make([]filteredLog, len(logs))
	for i, l := range logs {
		result[i] = filteredLog{
			TxIndex:  int(HexToUint(l.TransactionIndex)),
			LogIndex: int(HexToUint(l.LogIndex)),
		}
	}
	return result, nil
}

// fetchBlockReceipts fetches every receipt in a block with a single
// eth_getBlockReceipts round-trip (F-MON-4 / MED #58), eliminating the
// O(N) serial eth_getTransactionReceipt fan-out that stalled scanning on
// large or slow blocks. It is strictly an optimisation: on ANY problem with
// the batch response it falls back to the serial fetchAllReceipts path.
//
// Correctness guard: BuildReceiptProof keys the receipt trie by slice
// position (rlp.EncodeUint64(uint64(i))), so the returned slice MUST be in
// transaction-index order. eth_getBlockReceipts returns receipts in that
// order, but we still verify (a) the count matches len(txs) and (b) each
// receipt's transactionHash matches the block's tx at the same index. A
// hostile/misordering RPC therefore cannot corrupt the trie root via this
// fast path — any mismatch forces the serial fallback.
func (s *Scanner) fetchBlockReceipts(height uint64, txs []struct {
	Hash  string `json:"hash"`
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
	Input string `json:"input"`
}) ([]*RPCReceipt, error) {
	blockHex := fmt.Sprintf("0x%x", height)
	data, err := s.rpcCall("eth_getBlockReceipts", fmt.Sprintf(`"%s"`, blockHex))
	if err != nil {
		// RPC lacks eth_getBlockReceipts (-32601) or transient failure:
		// fall back to the per-tx serial path rather than failing the block.
		return s.fetchAllReceipts(txs)
	}
	var batch []*RPCReceipt
	if jerr := json.Unmarshal(data, &batch); jerr != nil || batch == nil {
		return s.fetchAllReceipts(txs)
	}
	if len(batch) != len(txs) {
		// Count mismatch (partial/over-long reply): do not trust it.
		return s.fetchAllReceipts(txs)
	}
	for i := range batch {
		if batch[i] == nil ||
			!strings.EqualFold(batch[i].TransactionHash, txs[i].Hash) {
			// Out-of-order or missing receipt: the slice position would no
			// longer equal the tx index, which would silently produce a
			// wrong receipt-trie root. Fall back to the order-preserving
			// serial path keyed off each tx hash.
			return s.fetchAllReceipts(txs)
		}
	}
	return batch, nil
}

func (s *Scanner) fetchAllReceipts(txs []struct {
	Hash  string `json:"hash"`
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
	Input string `json:"input"`
}) ([]*RPCReceipt, error) {
	receipts := make([]*RPCReceipt, len(txs))
	for i, tx := range txs {
		data, err := s.rpcCall("eth_getTransactionReceipt", fmt.Sprintf(`"%s"`, tx.Hash))
		if err != nil {
			return nil, fmt.Errorf("receipt %d: %w", i, err)
		}
		var r RPCReceipt
		// HIGH #25 + #46
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("decode receipt %d: %w", i, err)
		}
		receipts[i] = &r
	}
	return receipts, nil
}

// fetchAllRawTxs fetches the canonical RLP bytes for every TX in the block
// via eth_getRawTransactionByHash. This is the CRIT #1 ETH-path data
// source. Each TX gets N1 retry treatment for Mode 2 (per-tx null): up to
// MaxRetryAttempts with exponential backoff. After exhaustion the block
// fails (caller leaves LastScannedBlock pinned) AND the offending TX is
// persisted to the dead-letter store so an operator can triage / replay.
func (s *Scanner) fetchAllRawTxs(txs []struct {
	Hash  string `json:"hash"`
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
	Input string `json:"input"`
}, blockHeight uint64) ([][]byte, error) {
	out := make([][]byte, len(txs))
	for i, tx := range txs {
		raw, err := s.fetchRawTxWithRetry(tx.Hash, blockHeight, i)
		if err != nil {
			return nil, err
		}
		out[i] = raw
	}
	return out, nil
}

func (s *Scanner) fetchRawTxWithRetry(txHash string, blockHeight uint64, txIndex int) ([]byte, error) {
	backoff := s.InitialBackoff
	var lastErr error
	for attempt := 1; attempt <= s.MaxRetryAttempts; attempt++ {
		data, rpcErrCode, err := s.rpcCallWithErrCode("eth_getRawTransactionByHash", fmt.Sprintf(`"%s"`, txHash))
		if err == nil {
			var rawHex string
			if jerr := json.Unmarshal(data, &rawHex); jerr != nil {
				lastErr = fmt.Errorf("decode raw tx response: %w", jerr)
			} else if rawHex != "" && rawHex != "null" {
				bytesOut := HexToBytes(rawHex)
				if len(bytesOut) > 0 {
					return bytesOut, nil
				}
				lastErr = errors.New("rpc returned 0-byte raw tx")
			} else {
				// Mode 2: per-tx null. Fall through to backoff + retry.
				lastErr = fmt.Errorf("eth_getRawTransactionByHash returned null for %s (attempt %d/%d)", txHash, attempt, s.MaxRetryAttempts)
			}
		} else {
			if rpcErrCode == -32601 {
				// Mode 1 surfaced inside the retry loop (shouldn't happen
				// post-StartupProbe, but defensive). Surface as fatal.
				return nil, fmt.Errorf("eth_getRawTransactionByHash unsupported on RPC %s (rpc -32601): %w — operator must reconfigure", s.RpcURL, err)
			}
			lastErr = err
		}
		// Exponential backoff capped at MaxBackoff.
		if attempt < s.MaxRetryAttempts {
			time.Sleep(backoff)
			backoff *= 2
			if backoff > s.MaxBackoff {
				backoff = s.MaxBackoff
			}
		}
	}
	// Exhausted. Record in dead-letter and surface error so the outer
	// caller pins LastScannedBlock at blockHeight-1 (N1 spec).
	s.recordDeadLetter(DeadLetterEntry{
		BlockHeight: blockHeight,
		TxIndex:     txIndex,
		TxHash:      txHash,
		DepositType: "eth",
		Reason:      fmt.Sprintf("eth_getRawTransactionByHash exhausted %d attempts: %v", s.MaxRetryAttempts, lastErr),
		LastTry:     time.Now(),
		Attempts:    s.MaxRetryAttempts,
	})
	return nil, fmt.Errorf("N1 dead-letter: tx %s exhausted retries: %w", txHash, lastErr)
}

func (s *Scanner) getFinalizedBlock() (uint64, error) {
	data, err := s.rpcCall("eth_getBlockByNumber", `"finalized", false`)
	if err != nil {
		return 0, err
	}
	var block struct {
		Number string `json:"number"`
	}
	// HIGH #25 + #46
	if err := json.Unmarshal(data, &block); err != nil {
		return 0, fmt.Errorf("decode finalized block header: %w", err)
	}
	return HexToUint(block.Number), nil
}

func (s *Scanner) rpcCall(method string, params string) (json.RawMessage, error) {
	data, _, err := s.rpcCallWithErrCode(method, params)
	return data, err
}

// rpcCallWithErrCode is the underlying RPC helper exposing the JSON-RPC
// error code so callers can distinguish -32601 ("method not found") for
// startup-probe purposes (N1 Mode 1 defense-in-depth).
func (s *Scanner) rpcCallWithErrCode(method string, params string) (json.RawMessage, int, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"%s","params":[%s],"id":1}`, method, params)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(s.RpcURL, "application/json", strings.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	// review6 closure (M58 / F-MON-3): bound the response body so a
	// malicious or misconfigured ETH RPC can't OOM the monitor with a
	// giant reply. 64 MiB is well above any legitimate eth_getBlockByNumber
	// (busy blocks ≈ few MB).
	const maxRpcRespBytes = 64 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRpcRespBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("rpc response read failed: %w", err)
	}

	var result struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	// HIGH #25 + #46: surface decode error rather than treating a malformed
	// body as a zero-valued response.
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, 0, fmt.Errorf("decode rpc response: %w", err)
	}
	if result.Error != nil {
		return nil, result.Error.Code, fmt.Errorf("rpc error %d: %s", result.Error.Code, result.Error.Message)
	}
	return result.Result, 0, nil
}

// FormatDepositForContract formats a deposit into the MapParams JSON the contract expects.
func (d *Deposit) FormatDepositForContract() map[string]interface{} {
	proofHex := ""
	for _, node := range d.Proof {
		proofHex += hex.EncodeToString(node)
	}

	txData := map[string]interface{}{
		"block_height":     d.BlockHeight,
		"tx_index":         d.TxIndex,
		"raw_hex":          hex.EncodeToString(d.EncodedReceipt),
		"merkle_proof_hex": proofHex,
		"deposit_type":     d.DepositType,
	}
	if d.DepositType == "erc20" {
		// CRIT #14 (D-A-5): LogIndex here is per-receipt (0..N-1), set by
		// mapBlockLogIdxToPerReceipt at scanBlock.
		txData["log_index"] = d.LogIndex
		txData["token_address"] = d.TokenAddress
	}

	return map[string]interface{}{
		"tx_data":      txData,
		"instructions": []string{},
	}
}
