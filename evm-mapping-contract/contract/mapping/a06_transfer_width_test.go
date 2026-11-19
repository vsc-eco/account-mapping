package mapping

import (
	"math/big"
	"testing"
)

// A06: an ERC-20 deposit is credited from the Transfer log's data. Before the
// fix the whole data field was the amount, so a token emitting a longer data
// field (an upgraded or non-standard token) was credited the big-endian value
// of every byte: a 10 USDC deposit withdrew the whole 5,010 USDC vault on the
// real wasm (PRUNED phase 1). Only one 32-byte word is an amount.
func TestA06_TransferLogAmountIsOneWord(t *testing.T) {
	word := make([]byte, 32)
	big.NewInt(10_000_000).FillBytes(word)

	got, err := transferLogAmount(word)
	if err != nil || new(big.Int).SetBytes(got).Int64() != 10_000_000 {
		t.Fatalf("32-byte Transfer data: amount %x err %v, want 10000000", got, err)
	}

	// The exploit shape: the real amount word followed by a second word.
	long := append(append([]byte{}, word...), make([]byte, 32)...)
	long[63] = 1
	for _, bad := range [][]byte{long, word[:31], {}, append(word, 0)} {
		if amt, err := transferLogAmount(bad); err == nil {
			t.Fatalf("%d-byte Transfer data was accepted as amount %s", len(bad), new(big.Int).SetBytes(amt))
		}
	}
}
