package monitor

import (
	"encoding/hex"
	"evm-mapping-contract/contract/rlp"
	"fmt"
	"strings"
)

// Defensive caps on RPC-returned slice sizes (F-MON-003 / MED #64). A hostile
// or buggy ETH RPC could return a receipt/tx with an absurd number of logs,
// topics, blob hashes, or access-list entries, and each encoder previously did
// `make([][]byte, len(X))` sized directly to whatever the RPC returned. The
// 64 MiB io.LimitReader on the RPC body (scanner.go rpcCallWithErrCode) already
// bounds total memory, but these explicit, local caps make the bound obvious
// and fail loudly instead of silently allocating against attacker input.
// Values are far above anything a real Ethereum block can produce:
//   - maxLogsPerReceipt: real receipts have <1k logs; gas limits cap this hard.
//   - maxTopicsPerLog: protocol maximum is 4 (1 event sig + 3 indexed args).
//   - maxBlobHashesPerTx: EIP-4844 caps blobs per tx well under 16.
//   - maxAuthListEntries: EIP-7702 set-code authorizations; a real tx carries
//     a handful, never an unbounded list. (Was referenced by encodeSetCodeTx
//     but never defined — the monitor package did not compile without it.)
//   - maxAccessListEntries / maxStorageKeysPerAccessEntry: EIP-2930 access
//     lists are bounded by the block gas limit; these caps keep the access-list
//     encoder from driving an unbounded make against a hostile RPC reply.
const (
	maxLogsPerReceipt            = 100_000
	maxTopicsPerLog              = 4
	maxBlobHashesPerTx           = 4096
	maxAuthListEntries           = 4096
	maxAccessListEntries         = 100_000
	maxStorageKeysPerAccessEntry = 100_000
)

// RPCReceipt represents a receipt from eth_getTransactionReceipt.
type RPCReceipt struct {
	Status            string   `json:"status"`
	CumulativeGasUsed string   `json:"cumulativeGasUsed"`
	LogsBloom         string   `json:"logsBloom"`
	Logs              []RPCLog `json:"logs"`
	Type              string   `json:"type"`
	TransactionHash   string   `json:"transactionHash"`
	TransactionIndex  string   `json:"transactionIndex"`
}

// RPCLog represents a log entry from a receipt.
type RPCLog struct {
	Address  string   `json:"address"`
	Topics   []string `json:"topics"`
	Data     string   `json:"data"`
	LogIndex string   `json:"logIndex"` // F2: block-level index, used to resolve the per-receipt position
}

// EncodeReceipt RLP-encodes a receipt in the format Ethereum uses in the receipt trie.
//
// F-MON-003 (MED #64): the per-log and per-topic slices are sized to whatever
// the RPC returns. A receipt with an absurd log/topic count is rejected up
// front (returns nil) rather than driving an unbounded `make`. A nil return
// fails safe: BuildReceiptProof yields a root that cannot match the real
// receiptsRoot, so the on-chain proof is rejected instead of the monitor OOMing.
func EncodeReceipt(r *RPCReceipt) []byte {
	if len(r.Logs) > maxLogsPerReceipt {
		return nil
	}
	status := HexToUint(r.Status)
	cumGas := HexToUint(r.CumulativeGasUsed)
	bloom := HexToBytes(r.LogsBloom)

	logItems := make([][]byte, len(r.Logs))
	for i, log := range r.Logs {
		if len(log.Topics) > maxTopicsPerLog {
			return nil
		}
		addr := HexToBytes(log.Address)
		topicItems := make([][]byte, len(log.Topics))
		for j, t := range log.Topics {
			topicItems[j] = rlp.EncodeBytes(HexToBytes(t))
		}
		topicsList := rlp.EncodeList(topicItems...)
		data := HexToBytes(log.Data)
		logItems[i] = rlp.EncodeList(
			rlp.EncodeBytes(addr),
			topicsList,
			rlp.EncodeBytes(data),
		)
	}
	logsList := rlp.EncodeList(logItems...)

	receiptRLP := rlp.EncodeList(
		rlp.EncodeUint64(status),
		rlp.EncodeUint64(cumGas),
		rlp.EncodeBytes(bloom),
		logsList,
	)

	txType := HexToUint(r.Type)
	if txType > 0 {
		return append([]byte{byte(txType)}, receiptRLP...)
	}
	return receiptRLP
}

// BuildReceiptProof builds an MPT proof for a specific receipt index from all block receipts.
func BuildReceiptProof(receipts []*RPCReceipt, targetIndex int) (root []byte, proof [][]byte, encodedReceipt []byte) {
	if targetIndex < 0 || targetIndex >= len(receipts) {
		return nil, nil, nil
	}
	keys := make([][]byte, len(receipts))
	values := make([][]byte, len(receipts))
	for i, r := range receipts {
		keys[i] = rlp.EncodeUint64(uint64(i))
		values[i] = EncodeReceipt(r)
	}

	trie := BuildTrie(keys, values)
	root = TrieRoot(trie)

	targetKey := rlp.EncodeUint64(uint64(targetIndex))
	proof = GenerateProof(trie, targetKey)
	encodedReceipt = values[targetIndex]

	return root, proof, encodedReceipt
}

// HexToBytes decodes a 0x-prefixed hex string. On ANY decode error — including
// the odd-length and invalid-character cases — it returns nil rather than the
// silently-truncated partial result that encoding/hex returns on error.
//
// EH-MED-6 / F-MON-001 (MED #62): the old `b, _ := hex.DecodeString(s)`
// discarded the error and, on odd-length input, kept the partially-decoded
// prefix (e.g. "0xabc" -> [0xab]). That corrupted bytes silently flowed into
// the RLP that builds the MPT proof, producing a wrong root that fails on-chain
// with no diagnosis. Use HexToBytesChecked at trust boundaries where the error
// must be surfaced; this convenience wrapper now at least never returns a
// silently-truncated value.
func HexToBytes(s string) []byte {
	b, err := HexToBytesChecked(s)
	if err != nil {
		return nil
	}
	return b
}

// HexToBytesChecked is the error-returning form of HexToBytes. Odd-length or
// non-hex input yields an error and a nil slice (never a partial decode).
func HexToBytesChecked(s string) ([]byte, error) {
	trimmed := strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid hex %q: %w", s, err)
	}
	return b, nil
}

// HexToUint parses a 0x-prefixed hex string to uint64. On any non-hex
// character it returns 0 rather than silently skipping the bad character.
//
// F-MON-002 (MED #63): the old loop did `v <<= 4` for EVERY character and only
// OR'd in a value for valid hex digits, so "0x1Z2" decoded to 0x102 instead of
// erroring — silent numeric corruption on every receipt/header field. It now
// rejects the whole value on the first invalid character (returns 0); callers
// that must distinguish "0" from "corrupt" use HexToUintChecked.
func HexToUint(s string) uint64 {
	v, err := HexToUintChecked(s)
	if err != nil {
		return 0
	}
	return v
}

// HexToUintChecked is the error-returning form of HexToUint. A non-hex
// character or an out-of-range (>16 nibble) value yields an error.
func HexToUintChecked(s string) (uint64, error) {
	trimmed := strings.TrimPrefix(s, "0x")
	if len(trimmed) > 16 {
		return 0, fmt.Errorf("hex value %q exceeds uint64 range", s)
	}
	var v uint64
	for _, c := range trimmed {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v |= uint64(c - 'A' + 10)
		default:
			return 0, fmt.Errorf("invalid hex digit %q in %q", c, s)
		}
	}
	return v, nil
}

// BuildTxProof builds an MPT proof for a transaction at targetIndex from all block transactions.
// Used for native ETH deposits (verified against transactionsRoot, not receiptsRoot).
func BuildTxProof(txs []*RPCTx, targetIndex int) (root []byte, proof [][]byte, encodedTx []byte) {
	if targetIndex < 0 || targetIndex >= len(txs) {
		return nil, nil, nil
	}
	keys := make([][]byte, len(txs))
	values := make([][]byte, len(txs))
	for i, tx := range txs {
		keys[i] = rlp.EncodeUint64(uint64(i))
		values[i] = EncodeTx(tx)
	}

	trie := BuildTrie(keys, values)
	root = TrieRoot(trie)

	targetKey := rlp.EncodeUint64(uint64(targetIndex))
	proof = GenerateProof(trie, targetKey)
	encodedTx = values[targetIndex]

	return root, proof, encodedTx
}
