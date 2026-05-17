package mapping

import (
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
	SetBalance("alice", "eth", 1000)

	err := HandleTransfer(&TransferParams{To: "", Asset: "eth", Amount: "100"})
	if err == nil {
		t.Fatalf("review2 #43: HandleTransfer(To:\"\") returned nil — " +
			"baseline credits the unspendable \"\" address")
	}
	if got := GetBalance("alice", "eth"); got != 1000 {
		t.Fatalf("review2 #43: caller debited despite rejected transfer: %d, want 1000", got)
	}
	if got := GetBalance("", "eth"); got != 0 {
		t.Fatalf("review2 #43: funds credited to \"\" address: %d, want 0", got)
	}

	// Sanity: a valid transfer still works (identical both arms).
	if err := HandleTransfer(&TransferParams{To: "bob", Asset: "eth", Amount: "100"}); err != nil {
		t.Fatalf("review2 #43: valid transfer rejected: %v", err)
	}
	if got := GetBalance("bob", "eth"); got != 100 {
		t.Fatalf("review2 #43: valid transfer not credited: %d", got)
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
	SetBalance("alice", "eth", 1_000_000_000_000_000_000)

	zero := "0x0000000000000000000000000000000000000000"
	_, err := HandleUnmapETH(&TransferParams{
		To:     zero,
		Asset:  "eth",
		Amount: "10000000000000000", // == MinETHWithdrawal (passes the min check)
	}, [20]byte{0x1}, 1)

	if err == nil {
		t.Fatalf("review2 #44: HandleUnmapETH(to=0x0) returned nil — zero-address burn allowed")
	}
	if !contains(err.Error(), "zero address") {
		t.Fatalf("review2 #44: expected a zero-address rejection, got %q "+
			"(baseline has no guard and fails later on an unrelated path)", err.Error())
	}
}

// review2 #42 — adminMint did mapping.IncBalance only, never updating
// Supply, so admin-minted tokens were invisible to solvency accounting
// and a later TrackWithdrawal drove Supply.User/Active negative→clamped.
// The fix routes adminMint through AdminCredit, which mirrors the
// deposit/refund pattern (balance + supply together). This is a
// GREEN-only regression test (AdminCredit is a new symbol, so no
// both-arms differential is possible; the one-line IncBalance→AdminCredit
// change in main.adminMint is itself the fix).
func TestReview2AdminCreditTracksSupply(t *testing.T) {
	sdk.ResetTestState()

	if err := AdminCredit("alice", "eth", 500); err != nil {
		t.Fatalf("review2 #42: AdminCredit returned error: %v", err)
	}
	if got := GetBalance("alice", "eth"); got != 500 {
		t.Fatalf("review2 #42: balance = %d, want 500", got)
	}
	s := GetSupply("eth")
	if s.User != 500 || s.Active != 500 {
		t.Fatalf("review2 #42: supply not tracked: User=%d Active=%d, want 500/500 "+
			"(baseline adminMint used IncBalance only → supply stayed 0)", s.User, s.Active)
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
