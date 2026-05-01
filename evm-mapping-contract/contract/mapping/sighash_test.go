package mapping

import (
	"bytes"
	"testing"

	"evm-mapping-contract/contract/rlp"
)

// End-to-end reproduction of pentest finding EVM-C5.
//
// Bug: computeTxSighash for EIP-1559 transactions only preserved
// a single level of children. EIP-2930 access list entries are
// themselves lists ([address, [storageKey1, ...]]); the buggy
// path silently re-encoded every nested list as empty, so
// transactions that differed only inside their storage-key
// sublists hashed to the same sighash. Wrong sighash →
// ecrecover recovers the wrong sender → deposit credited to a
// random unspendable DID.
//
// Mitigation that was in place: ETH-to-vault deposits rarely
// use access lists, and BuildETHWithdrawalTx / BuildERC20WithdrawalTx
// emit empty access lists (withdrawal.go). Severity MEDIUM.
//
// Pre-fix: two txs with identical other fields but different
// storage keys produce IDENTICAL sighashes (the bug).
// Post-fix: they differ.

func TestEVMC5_AccessListSighashPreservesNestedKeys(t *testing.T) {
	build := func(storageKey1, storageKey2 byte) []byte {
		// Minimal EIP-1559 raw: 0x02 || RLP([
		//   chainId, nonce, maxPrio, maxFee, gas, to, value, data,
		//   accessList, v, r, s
		// ])
		emptyBytes := rlp.EncodeBytes(nil)
		// Single access-list entry: [address20, [storageKey1, storageKey2]]
		addr := bytes.Repeat([]byte{0xaa}, 20)
		key1 := bytes.Repeat([]byte{storageKey1}, 32)
		key2 := bytes.Repeat([]byte{storageKey2}, 32)
		entry := rlp.EncodeList(
			rlp.EncodeBytes(addr),
			rlp.EncodeList(rlp.EncodeBytes(key1), rlp.EncodeBytes(key2)),
		)
		accessList := rlp.EncodeList(entry)

		body := rlp.EncodeList(
			rlp.EncodeUint64(1),                     // chainId
			rlp.EncodeUint64(0),                     // nonce
			rlp.EncodeUint64(1_000_000_000),         // maxPriorityFee
			rlp.EncodeUint64(20_000_000_000),        // maxFee
			rlp.EncodeUint64(21000),                 // gas
			rlp.EncodeBytes(bytes.Repeat([]byte{0xbb}, 20)), // to
			rlp.EncodeUint64(0),                     // value
			emptyBytes,                              // data
			accessList,                              // <-- field 8 — the bug
			emptyBytes,                              // v
			emptyBytes,                              // r
			emptyBytes,                              // s
		)
		return append([]byte{0x02}, body...)
	}

	rawA := build(0x11, 0x22)
	rawB := build(0x33, 0x44)
	tx := &ParsedTx{ChainId: 1}

	hashA := computeTxSighash(rawA, tx)
	hashB := computeTxSighash(rawB, tx)

	if bytes.Equal(hashA, hashB) {
		t.Fatalf(
			"EVM-C5 leak: two EIP-1559 transactions that differ ONLY in their\n"+
				"  access-list storage keys produced the same sighash. Pre-fix the\n"+
				"  storage-keys sublist was re-encoded as empty.\n"+
				"  hashA = %x\n"+
				"  hashB = %x",
			hashA, hashB)
	}
	if len(hashA) != 32 || len(hashB) != 32 {
		t.Errorf("expected 32-byte keccak256 hashes, got %d / %d", len(hashA), len(hashB))
	}
}
