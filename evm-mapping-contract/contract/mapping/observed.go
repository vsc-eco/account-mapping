package mapping

import (
	"encoding/hex"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
	"strconv"
)

// Each observed entry: 32-byte txHash + 2-byte index (txIndex or logIndex)
const observedEntrySize = 34

// observedCountKey holds the number of manifest slots written for a block.
// The manifest (o-{height}#{seq}) lets the testnet-only cleanup enumerate and
// delete the per-entry presence keys, since the SDK has no prefix-delete.
func observedCountKey(blockHeight uint64) string {
	return constants.ObservedCountPrefix + strconv.FormatUint(blockHeight, 10)
}

// observedSlotKey is a sequential cleanup-manifest slot: o-{height}#{seq}.
func observedSlotKey(blockHeight uint64, seq uint64) string {
	return constants.ObservedBlockPrefix + strconv.FormatUint(blockHeight, 10) +
		constants.ObservedSeqDelimiter + strconv.FormatUint(seq, 10)
}

// observedEntryKey is the content-addressed presence key for a single observed
// (txHash, index) at a block: o-{height}-{hex(34-byte entry)}. Lookup and
// insertion are both O(1) — no blob read-append-rewrite (M21-22).
func observedEntryKey(blockHeight uint64, txHash [32]byte, index uint16) string {
	return constants.ObservedBlockPrefix + strconv.FormatUint(blockHeight, 10) +
		constants.DirPathDelimiter + hex.EncodeToString(makeEntry(txHash, index))
}

// IsObserved reports whether (blockHeight, txHash, index) has been marked.
// M21-22: O(1) single-key lookup instead of an O(N) scan of the block blob.
//
// DEVNET-FOUND (host-vs-stub): the WASM host's db.get_object returns a non-nil
// EMPTY string for an ABSENT key (execution-context.go GetState -> Ok("") when
// the store returns nil). A bare `!= nil` therefore reads TRUE for every unset
// key on the real runtime, so EVERY deposit aborted "already processed" — while
// the unit-test stub (returns nil for absent) passed. MUST gate on a non-empty
// value (MarkObserved writes "1"). Same fix as isPaused / IsWhitelistedRelayer.
func IsObserved(blockHeight uint64, txHash [32]byte, index uint16) bool {
	data := sdk.StateGetObject(observedEntryKey(blockHeight, txHash, index))
	return data != nil && *data != ""
}

// MarkObserved records (blockHeight, txHash, index) as observed.
// M21-22: O(1) — write the presence key, then append the entry to the cleanup
// manifest by index (write slot #count, bump count) without reading any prior
// entries. No blob read-append-rewrite, so per-block cost is O(N), not O(N^2).
func MarkObserved(blockHeight uint64, txHash [32]byte, index uint16) {
	entryKey := observedEntryKey(blockHeight, txHash, index)
	// Idempotent: if already present, do not grow the manifest (a re-mark of
	// the same entry would otherwise leak a duplicate cleanup slot).
	// Host returns non-nil "" for absent keys (see IsObserved) — gate on non-empty.
	if d := sdk.StateGetObject(entryKey); d != nil && *d != "" {
		return
	}
	sdk.StateSetObject(entryKey, "1")

	count := observedCount(blockHeight)
	entry := makeEntry(txHash, index)
	sdk.StateSetObject(observedSlotKey(blockHeight, count), string(entry))
	sdk.StateSetObject(observedCountKey(blockHeight), strconv.FormatUint(count+1, 10))
}

// observedCount returns the number of manifest slots written for a block.
func observedCount(blockHeight uint64) uint64 {
	data := sdk.StateGetObject(observedCountKey(blockHeight))
	if data == nil {
		return 0
	}
	n, err := strconv.ParseUint(*data, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// ClearObservedBlock deletes every observed key for a block: the presence keys
// (via the manifest), the manifest slots, and the count. Used by the
// testnet-only clearTestnetState cleanup. O(N) in entries-per-block.
func ClearObservedBlock(blockHeight uint64) {
	count := observedCount(blockHeight)
	for seq := uint64(0); seq < count; seq++ {
		slotKey := observedSlotKey(blockHeight, seq)
		entryData := sdk.StateGetObject(slotKey)
		if entryData != nil && *entryData != "" {
			entry := []byte(*entryData)
			sdk.StateDeleteObject(constants.ObservedBlockPrefix +
				strconv.FormatUint(blockHeight, 10) +
				constants.DirPathDelimiter + hex.EncodeToString(entry))
		}
		sdk.StateDeleteObject(slotKey)
	}
	sdk.StateDeleteObject(observedCountKey(blockHeight))
}

func makeEntry(txHash [32]byte, index uint16) []byte {
	entry := make([]byte, observedEntrySize)
	copy(entry[:32], txHash[:])
	entry[32] = byte(index >> 8)
	entry[33] = byte(index)
	return entry
}

func TxHashFromHex(s string) ([32]byte, error) {
	var h [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return h, err
	}
	copy(h[:], b)
	return h, nil
}
