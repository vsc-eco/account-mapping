package mapping

import (
	"math/big"
	"testing"

	"evm-mapping-contract/sdk"
)

// review2 #43 — HandleTransfer / HandleTransferFrom did not reject an
// empty recipient. Transferring to "" debited the caller and credited
// the "" address, where the funds are permanently unspendable (no caller
// can ever authenticate as ""). Differential: #170 baseline moves the
// balance and returns nil (RED); fix returns an error and leaves
// balances untouched (GREEN).
func TestReview2TransferRejectsEmptyRecipient(t *testing.T) {
	sdk.ResetTestState()
	sdk.SetTestCaller("alice")
	SetBalance("alice", "eth", big.NewInt(1000))

	err := HandleTransfer(&TransferParams{To: "", Asset: "eth", Amount: "100"})
	if err == nil {
		t.Fatalf("review2 #43: HandleTransfer(To:\"\") returned nil — " +
			"baseline credits the unspendable \"\" address")
	}
	if got := GetBalance("alice", "eth"); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("review2 #43: caller debited despite rejected transfer: %s, want 1000", got)
	}
	if got := GetBalance("", "eth"); got.Sign() != 0 {
		t.Fatalf("review2 #43: funds credited to \"\" address: %s, want 0", got)
	}

	// Sanity: a valid transfer still works (identical both arms).
	if err := HandleTransfer(&TransferParams{To: "hive:bob", Asset: "eth", Amount: "100"}); err != nil {
		t.Fatalf("review2 #43: valid transfer rejected: %v", err)
	}
	if got := GetBalance("hive:bob", "eth"); got.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("review2 #43: valid transfer not credited: %s", got)
	}
}

// review2 #44 — crypto.HexToAddress accepts the all-zero address as a
// valid [20]byte, so a TSS-signed withdrawal to 0x000…0 burns the funds
// irrecoverably. HandleUnmapETH had no zero-address guard. Differential:
// fix rejects with "zero address" before any downstream work (GREEN);
// #170 baseline has no such guard and proceeds past it (RED — the error,
// if any, is the unrelated downstream "no block headers" path).
func TestReview2UnmapRejectsZeroAddress(t *testing.T) {
	sdk.ResetTestState()
	sdk.SetTestCaller("alice")
	SetBalance("alice", "eth", big.NewInt(1_000_000_000_000_000_000)) // 1 ETH in wei

	zero := "0x0000000000000000000000000000000000000000"
	_, err := HandleUnmapETH(&TransferParams{
		To:     zero,
		Asset:  "eth",
		Amount: "10000000000000000", // == MinETHWithdrawal in wei (0.01 ETH) — passes the min check
	}, [20]byte{0x1}, 1)

	if err == nil {
		t.Fatalf("review2 #44: HandleUnmapETH(to=0x0) returned nil — zero-address burn allowed")
	}
	if !contains(err.Error(), "zero address") {
		t.Fatalf("review2 #44: expected a zero-address rejection, got %q "+
			"(baseline has no guard and fails later on an unrelated path)", err.Error())
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
