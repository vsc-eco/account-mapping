package mapping

import (
	"strings"
	"testing"

	"evm-mapping-contract/sdk"
)

// End-to-end reproduction of pentest finding F17.
//
// Bug: TrackWithdrawal silently clamps Active and User to 0
// when the requested amount would push them negative:
//
//   func TrackWithdrawal(asset string, amount int64) {
//       s := GetSupply(asset)
//       s.Active -= amount
//       if s.Active < 0 { s.Active = 0 }
//       s.User -= amount
//       if s.User < 0 { s.User = 0 }
//       SetSupply(asset, s)
//   }
//
// The pentest noted this is LATENT — every public withdrawal
// path validates the user's balance first, so the clamp can only
// fire if a separate bug lets `amount > supply` reach this
// helper. But "we have correct callers" is exactly the assumption
// you don't want to bake into your accounting layer: a future
// caller that violates it will silently corrupt the supply
// counters instead of failing loudly.
//
// Fix: abort the contract when amount exceeds the tracked
// supply, surfacing the programming error at the call site
// instead of papering over it.
//
// In unit tests sdk.Abort panics through the test stub, so we
// recover and assert on the panic message.

func TestF17_TrackWithdrawalAbortsOnUnderflow(t *testing.T) {
	sdk.ResetTestStateStore()
	// Test stub returns zero supply for any asset (no state).
	// Pre-fix: 999 > 0, both fields clamp to 0, SetSupply is a
	// no-op stub, function returns normally — no signal.
	// Post-fix: TrackWithdrawal aborts with an underflow message.
	var panicValue interface{}
	func() {
		defer func() { panicValue = recover() }()
		TrackWithdrawal("eth", 999)
	}()

	if panicValue == nil {
		t.Fatalf(
			"F17 leak: TrackWithdrawal silently clamped a 999-unit withdrawal " +
				"against zero supply instead of aborting.")
	}
	msg, _ := panicValue.(string)
	if !strings.Contains(strings.ToLower(msg), "supply") &&
		!strings.Contains(strings.ToLower(msg), "underflow") {
		t.Errorf("expected abort message mentioning supply/underflow, got: %v", panicValue)
	}
}

// Sanity: a withdrawal within the tracked supply must still
// proceed normally without panic. (In the test stub the supply
// is always zero from the read side, so we exercise the
// edge-case where both Active and User would land at exactly 0.)
func TestF17_TrackWithdrawalZeroAmountIsFine(t *testing.T) {
	sdk.ResetTestStateStore()
	var panicValue interface{}
	func() {
		defer func() { panicValue = recover() }()
		TrackWithdrawal("eth", 0)
	}()
	if panicValue != nil {
		t.Fatalf("zero-amount withdrawal should not abort: %v", panicValue)
	}
}
