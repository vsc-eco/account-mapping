package mapping

import (
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// A8: a swap-routed deposit forwards the depositor's min_amount_out to the
// router, and sends none when the depositor gave none.
func TestA8_SwapForwardsTheDepositorsMinAmountOut(t *testing.T) {
	var sender [20]byte
	sender[19] = 0xd1
	for _, c := range []struct {
		instr []string
		want  string
	}{
		{[]string{"swap_to=hive:bob", "asset_out=hbd", "min_amount_out=900"}, `"min_amount_out":"900"`},
		{[]string{"min_amount_out=12345678901234567890", "swap_to=hive:bob", "asset_out=hbd"}, `"min_amount_out":"12345678901234567890"`},
		{[]string{"swap_to=hive:bob", "asset_out=hbd"}, ""},
	} {
		sdk.ResetStubState()
		sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
		var sent string
		sdk.StubSetContractCallResponder(func(contractId, method, payload string) *string {
			sent = payload
			ok := `{"ok":true,"result":"{}"}`
			return &ok
		})
		routeDeposit(sender, c.instr, "eth", big.NewInt(1000), 1)
		if sent == "" {
			t.Fatalf("%v: router not called", c.instr)
		}
		if c.want != "" && !strings.Contains(sent, c.want) {
			t.Errorf("%v: router got %s, want it to carry %s", c.instr, sent, c.want)
		}
		if c.want == "" && strings.Contains(sent, "min_amount_out") {
			t.Errorf("%v: router got a min_amount_out the depositor never gave: %s", c.instr, sent)
		}
	}
	sdk.ResetStubState()
}
