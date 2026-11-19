package blocklist

import (
	"strconv"

	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/sdk"
)

// review6 H2: keccak256Hex / equalHex (added by main for the oracle-path
// parent-hash chain check in HandleAddBlocks) are removed alongside that
// handler — the ZK verifier now owns header-chain validation.

// EthBlockHeader — W4 Cluster B CRIT #6 Site 4 (LOCKED W1 §AH + W1 §BL):
//   - Added `ChainId uint64` field (appended at the END, after Timestamp).
//   - Added 1-byte version prefix at offset 0 (Sonnet v10 S6 future-upgrade
//     warning closure). The current version is byte 1.
//   - Final canonical layout: [version:1] + [existing 128 bytes byte-for-byte]
//   - [chainId:8 big-endian] = 137 bytes total.
//   - Append-last is REQUIRED — inserting chainId before Timestamp would
//     shift existing byte offsets and break any decoder that reads the
//     128-byte legacy layout.
//
// CRIT #29 v9 verdict: the version byte is defense-in-depth. A future
// schema change can bump it and DeserializeHeader can branch on version
// rather than silently misreading. v1 is the only valid version today;
// reads of any other version are rejected.
//
// Cluster B Site 4 + W4 Cluster A flow: the L2 ETH deposit verifier uses
// ChainId for the receipt-trie path (no parsed-tx ChainId available);
// the value comes from the ZK proof (Site 5/6 -> stored via submitProof
// in zk-header-verifier -> read here via blocklist.GetHeader). On the
// account-mapping side, the addBlocks legacy oracle path also gains a
// ChainId column (operator-supplied per Hive transaction) as a backward
// path during the ZK ramp-up window; the field is still validated against
// the contract's configured chainId BEFORE storing.
type EthBlockHeader struct {
	BlockNumber      uint64
	StateRoot        [32]byte
	TransactionsRoot [32]byte
	ReceiptsRoot     [32]byte
	BaseFeePerGas    uint64
	GasLimit         uint64
	Timestamp        uint64
	ChainId          uint64
}

// HeaderVersionV1 — W4 Cluster B Site 4 + CRIT #29 v9 verdict:
// the on-chain serialized header gains a 1-byte version prefix. v1 is
// the only valid version today; future schema changes bump this and
// DeserializeHeader branches on it.
const HeaderVersionV1 byte = 0x01

// HeaderSerializedSize — LOCKED 137 bytes:
//
//	version(1) + blockNumber(8) + stateRoot(32) + txRoot(32) + rcptRoot(32)
//	+ baseFee(8) + gasLimit(8) + timestamp(8) + chainId(8) = 137.
const HeaderSerializedSize = 137

func (h *EthBlockHeader) Serialize() string {
	buf := make([]byte, 0, HeaderSerializedSize)
	// Version byte (offset 0)
	buf = append(buf, HeaderVersionV1)
	// Legacy 128-byte body (offsets 1-128, BYTE-FOR-BYTE unchanged)
	buf = appendUint64(buf, h.BlockNumber)
	buf = append(buf, h.StateRoot[:]...)
	buf = append(buf, h.TransactionsRoot[:]...)
	buf = append(buf, h.ReceiptsRoot[:]...)
	buf = appendUint64(buf, h.BaseFeePerGas)
	buf = appendUint64(buf, h.GasLimit)
	buf = appendUint64(buf, h.Timestamp)
	// W4 Cluster B Site 4: appended chainId (offsets 129-136, big-endian)
	buf = appendUint64(buf, h.ChainId)
	return string(buf)
}

// DeserializeHeader — W4 Cluster B Site 4 + §BL LOCKED:
// length guard uses `< HeaderSerializedSize` (i.e. reject-if-shorter-than-137),
// NOT `!= 137`. Using `!=` would silently reject any future forward-compat
// padding; `<` accepts any buffer with at least the full 137 bytes.
func DeserializeHeader(data string) (*EthBlockHeader, error) {
	buf := []byte(data)
	if len(buf) < HeaderSerializedSize {
		return nil, ce.NewContractError(
			ce.ErrInput,
			"header data too short (expected at least 137 bytes after version prefix)",
		)
	}
	// Version byte gate.
	if buf[0] != HeaderVersionV1 {
		return nil, ce.NewContractError(ce.ErrInput, "header version unsupported")
	}
	h := &EthBlockHeader{}
	offset := 1 // skip version byte
	h.BlockNumber = readUint64(buf, &offset)
	copy(h.StateRoot[:], buf[offset:offset+32])
	offset += 32
	copy(h.TransactionsRoot[:], buf[offset:offset+32])
	offset += 32
	copy(h.ReceiptsRoot[:], buf[offset:offset+32])
	offset += 32
	h.BaseFeePerGas = readUint64(buf, &offset)
	h.GasLimit = readUint64(buf, &offset)
	h.Timestamp = readUint64(buf, &offset)
	// W4 Cluster B Site 4: chainId at byte offset 129-136
	h.ChainId = readUint64(buf, &offset)
	return h, nil
}

func GetHeader(blockNumber uint64) *EthBlockHeader {
	key := constants.BlockPrefix + strconv.FormatUint(blockNumber, 10)
	data := readState(key)
	if data == nil {
		return nil
	}
	h, err := DeserializeHeader(*data)
	if err != nil {
		return nil
	}
	return h
}

func GetLastHeight() uint64 {
	data := readState(constants.LastHeightKey)
	if data == nil {
		return 0
	}
	h, err := strconv.ParseUint(*data, 10, 64)
	if err != nil {
		return 0
	}
	return h
}

// readState reads block-header state from the configured ZK header verifier
// contract.
//
// review6 H2: the prior implementation fell back to own state when no
// verifier was configured ("oracle-trusted" legacy path). That path let a
// designated oracle account write arbitrary StateRoot / TransactionsRoot /
// ReceiptsRoot / BaseFeePerGas with no cryptographic anchoring — every
// finding in the audit's "forged header composes into…" chain (H10, H9,
// X3, L1) reduced to "oracle key compromise" through this fallback.
//
// The fallback is removed: headers MUST come from the ZK verifier. If
// VerifierContractIdKey is unset OR the verifier returns nothing, GetHeader
// / GetLastHeight return nil/0 — every consumer (deposit verify, withdrawal
// fee computation, drop-proof binding) already gracefully handles missing
// headers by aborting the operation with "no block headers available". The
// contract simply refuses to process bridge operations until a ZK verifier
// is wired up, which is the desired safety posture.
func readState(key string) *string {
	vcid := sdk.StateGetObject(constants.VerifierContractIdKey)
	if vcid == nil || *vcid == "" {
		return nil
	}
	result := sdk.ContractStateGet(*vcid, key)
	if result == nil || *result == "" {
		return nil
	}
	return result
}

// review6 H2 + MED M23-F5 (#31) — single source of truth for header state.
//
// AddBlockEntry / AddBlocksParams / HandleAddBlocks / HandleSeedBlock /
// HandleReplaceBlock have been REMOVED. Headers are now sourced EXCLUSIVELY
// from the configured ZK header-verifier contract (readState routes through
// VerifierContractIdKey). Any path that lets the operator (or an oracle
// account) write headers directly into this contract's state is by definition
// an unbacked-mint surface: the audit's H2 finding showed that forged
// StateRoot / ReceiptsRoot / BaseFeePerGas composes into H10, H9, X3, L1 —
// every "this proof verifies against the stored root" check becomes a
// tautology under operator/oracle compromise.
//
// M23-F5 (#31): the local-state WRITERS StoreHeader / SetLastHeight /
// DeleteHeader have ALSO been removed. GetHeader / GetLastHeight read via
// readState (the VERIFIER's b-{height} / h keys); a local StateSetObject /
// StateDeleteObject on BlockPrefix / LastHeightKey therefore targets a
// DIFFERENT key namespace than the readers ever consult — silently shadowed
// once a verifier is configured, exactly the divergent-lastHeight drift class
// M23-F5 / F-M22-MED-1 (#29) flag. They were dead code (no caller in this
// module; the ZK header verifier is a SEPARATE Go module that only MIRRORS
// this layout — it does NOT import this package, so the prior "retained for
// the verifier" rationale was incorrect). Removing them leaves the verifier
// as the single source of truth with no shadow writer that can ever diverge.
// The codec (Serialize / DeserializeHeader) is retained for the documented
// cross-module layout parity; it writes no state and so cannot drift.
//
// If a future operational need for an emergency local-state write arises
// (e.g. fork recovery without re-deploying), the only acceptable path is
// to re-add a wasmexport that takes a fresh ZK proof + verifies it inline
// — never a bare operator-signed header.

func appendUint64(buf []byte, v uint64) []byte {
	return append(buf,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
	)
}

func readUint64(buf []byte, offset *int) uint64 {
	v := uint64(buf[*offset])<<56 | uint64(buf[*offset+1])<<48 |
		uint64(buf[*offset+2])<<40 | uint64(buf[*offset+3])<<32 |
		uint64(buf[*offset+4])<<24 | uint64(buf[*offset+5])<<16 |
		uint64(buf[*offset+6])<<8 | uint64(buf[*offset+7])
	*offset += 8
	return v
}
