package mapping

import (
	"strings"
	"testing"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/sdk"
)

// End-to-end reproduction of pentest finding EVM-C3.
//
// Bug: HasPendingWithdrawal checks a single global nonce pair.
// All three unmap paths (unmapETH, unmapERC20, unmapFrom) gate
// on it. Once user A's withdrawal is "stuck" (e.g. base fee was
// stale, the L1 transaction never mined), user B's unrelated
// unmap is blocked with "withdrawal pending: wait for confirmation".
// Resolution paths (clearNonce, replaceWithdrawal) are admin-only
// and have no automatic timeout. If the admin key is unavailable
// or the oracle stops, the bridge is permanently jammed.
//
// Fix: introduce HandleCancelStuckWithdrawal — anyone can call
// it once the pending spend is older than CancelStuckTTLBlocks
// L1 blocks. It refunds the user's balance + supply (same as the
// confirmSpend failure branch) and advances the confirmed nonce
// so subsequent unmaps can proceed.
//
// Pre-fix: function does not exist; only admin-only paths exist.
// Post-fix: a stuck pending spend is recoverable by anyone after
// the TTL elapses.

func TestEVMC3_CancelStuckWithdrawalAfterTTL(t *testing.T) {
	sdk.ResetTestStateStore()

	// Seed a current L1 height so blocklist.GetLastHeight() returns
	// something meaningful when the cancel handler reads it.
	const startTip = uint64(10_000)
	blocklist.SetLastHeight(startTip)

	// Stage a stuck pending spend: pending nonce ahead of confirmed,
	// with a PendingSpend at the confirmed slot whose BlockHeight
	// is the current tip (so it can NOT be cancelled yet).
	const stuckUser = "hive:alice"
	const asset = "eth"
	const amount = int64(50_000)

	SetConfirmedNonce(0)
	SetPendingNonce(1)
	StorePendingSpend(PendingSpend{
		Nonce:       0,
		Amount:      amount,
		From:        stuckUser,
		To:          "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		Asset:       asset,
		BlockHeight: startTip,
	})
	if !HasPendingWithdrawal() {
		t.Fatalf("setup invariant: should have a pending withdrawal")
	}

	t.Run("CancelTooSoonRejected", func(t *testing.T) {
		err := HandleCancelStuckWithdrawal()
		if err == nil {
			t.Fatalf("EVM-C3: cancel before TTL must be rejected, got nil error")
		}
		if !strings.Contains(strings.ToLower(err.Error()), "expir") &&
			!strings.Contains(strings.ToLower(err.Error()), "not yet") {
			t.Errorf("expected expiry-related error, got: %v", err)
		}
		// State must be unchanged.
		if !HasPendingWithdrawal() {
			t.Errorf("cancel-too-soon must not have advanced confirmed nonce")
		}
	})

	t.Run("CancelAfterTTLClears", func(t *testing.T) {
		// Advance the L1 tip past the TTL.
		blocklist.SetLastHeight(startTip + CancelStuckTTLBlocks + 1)

		err := HandleCancelStuckWithdrawal()
		if err != nil {
			t.Fatalf("cancel after TTL should succeed, got: %v", err)
		}
		if HasPendingWithdrawal() {
			t.Errorf("EVM-C3: confirmed nonce must advance past the cancelled pending")
		}
		// Pending spend record gone.
		if GetPendingSpend(0) != nil {
			t.Errorf("pending spend should be deleted after cancel")
		}
		// User refunded.
		bal := GetBalance(stuckUser, asset)
		if bal != amount {
			t.Errorf("user should be refunded %d, got %d", amount, bal)
		}
	})
}
