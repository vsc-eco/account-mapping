package mapping

import (
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// D8: a pause must not block confirmSpend, which only records an L1 fact. Here
// the call still fails (there is no pending withdrawal), but never on the pause.
func TestD8_ConfirmSpendIsNotPauseGated(t *testing.T) {
	sdk.ResetTestState()
	defer sdk.ResetTestState()
	sdk.StateSetObject(constants.PausedKey, "1")
	err := HandleConfirmSpend(&ConfirmSpendRequest{}, 1)
	if err != nil && strings.Contains(err.Error(), "paused") {
		t.Fatalf("confirmSpend refused by the pause: %v", err)
	}
	// Control: the pause still stops new withdrawals.
	sdk.SetTestCaller("hive:alice")
	if _, err := HandleUnmapETH(&TransferParams{Amount: "1", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatalf("unmapETH while paused = %v, want the pause refusal", err)
	}
}
