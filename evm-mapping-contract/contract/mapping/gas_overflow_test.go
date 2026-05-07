package mapping

import (
	"math"
	"strconv"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// End-to-end reproduction of pentest finding EVM-C10.
//
// Bug: addGasReserve previously did `current + amount` with no
// overflow check. Economically impractical (~92,000 ETH would need
// to flow through ETH deposits to overflow int64), but cheap to
// guard. The fix uses safeAdd64 and clamps to MaxInt64 on overflow.
//
// Pre-fix: addGasReserve(MaxInt64-100) followed by
// addGasReserve(1000) wraps to a negative value.
// Post-fix: clamps to MaxInt64.

func TestEVMC10_AddGasReserveDoesNotOverflow(t *testing.T) {
	sdk.ResetTestStateStore()

	// Seed reserve close to MaxInt64.
	near := math.MaxInt64 - int64(100)
	sdk.StateSetObject(constants.GasReserveKey, strconv.FormatInt(near, 10))

	addGasReserve(int64(1000))

	got := getGasReserve()
	if got < 0 {
		t.Fatalf(
			"EVM-C10 leak: addGasReserve overflowed to a negative value. "+
				"got %d (start=%d, added=1000)",
			got, near)
	}
	if got != math.MaxInt64 {
		t.Errorf("expected clamp to MaxInt64, got %d", got)
	}
}
