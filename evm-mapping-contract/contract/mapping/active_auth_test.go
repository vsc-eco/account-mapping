package mapping

import (
	"strings"
	"testing"

	"evm-mapping-contract/sdk"
)

// A2: a posting signature makes its signer the Caller just as an active one
// does, so a handler that compared only the Caller let a posting key (the key a
// user hands to front ends) move the account's funds. Every fund-moving handler
// now requires the sender's active authority, as the BTC mapping contract does.
func TestA2_FundOpsRequireActiveAuth(t *testing.T) {
	const user = "hive:alice"
	ops := map[string]func() error{
		"transfer": func() error {
			return HandleTransfer(&TransferParams{Amount: "1", To: "hive:bob", Asset: "eth"})
		},
		"transferFrom": func() error {
			return HandleTransferFrom(&TransferParams{Amount: "1", From: "hive:carol", To: "hive:bob", Asset: "eth"})
		},
		"approve": func() error {
			return HandleApprove(&AllowanceParams{Spender: "hive:bob", Amount: "1", Asset: "eth"})
		},
		"increaseAllowance": func() error {
			return HandleIncreaseAllowance(&AllowanceParams{Spender: "hive:bob", Amount: "1", Asset: "eth"})
		},
		"decreaseAllowance": func() error {
			return HandleDecreaseAllowance(&AllowanceParams{Spender: "hive:bob", Amount: "1", Asset: "eth"})
		},
		"unmapETH": func() error {
			_, err := HandleUnmapETH(&TransferParams{Amount: "1", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1)
			return err
		},
		"unmapERC20": func() error {
			_, err := HandleUnmapERC20(&TransferParams{Amount: "1", To: "0x00000000000000000000000000000000000000e2", Asset: "usdc"}, [20]byte{1}, 1)
			return err
		},
		"unmapFrom": func() error {
			return HandleUnmapFrom(&TransferParams{Amount: "1", From: "hive:carol", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1)
		},
	}
	for name, op := range ops {
		sdk.ResetTestState()
		sdk.SetTestPostingCaller(user)
		if err := op(); err == nil || !strings.Contains(err.Error(), "active auth required") {
			t.Errorf("%s signed with posting authority only: err = %v, want the active-auth refusal", name, err)
		}

		// The same call signed with active authority gets past the check (it may
		// still fail later, e.g. on balance).
		sdk.ResetTestState()
		sdk.SetTestCaller(user)
		if err := op(); err != nil && strings.Contains(err.Error(), "active auth required") {
			t.Errorf("%s signed with active authority was refused: %v", name, err)
		}
	}
	sdk.ResetTestState()
}
