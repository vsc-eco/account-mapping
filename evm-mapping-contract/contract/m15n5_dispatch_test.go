package main

import (
	"fmt"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// M15-N5 through execute's dispatch: a second token under a registered
// symbol, or a registered token under a new symbol, aborts the registerToken
// proposal and writes nothing.
func TestM15N5_RegisterTokenDispatchRefusesASecondTokenUnderOneSymbol(t *testing.T) {
	sdk.ResetTestStateStore()
	sdk.StateSetObject(constants.ChainIdKey, "11155111")
	dispatch := func(addr, symbol string) (abort interface{}) {
		defer func() { abort = recover() }()
		dispatchAdmin("registerToken", []byte(fmt.Sprintf(`{"address":"%s","symbol":"%s","decimals":6,"min_withdrawal":10000000}`, addr, symbol)))
		return nil
	}
	const usdc = "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"
	const fake = "0x00000000000000000000000000000000000000bb"

	if a := dispatch(usdc, "usdc"); a != nil {
		t.Fatalf("first registration aborted: %v", a)
	}
	if a := dispatch(usdc, "usdc"); a != nil {
		t.Fatalf("re-registering the same token aborted: %v", a)
	}
	a := dispatch(fake, "usdc")
	if msg := fmt.Sprint(a); a == nil || !strings.Contains(msg, "registerToken: symbol usdc belongs to token") {
		t.Fatalf("second token under usdc: abort %v", a)
	}
	if sdk.StateGetObject(constants.TokenRegistryPrefix+"11155111-00000000000000000000000000000000000000bb") != nil {
		t.Fatal("the refused token was written to the registry")
	}
	a = dispatch(usdc, "usdcx")
	if msg := fmt.Sprint(a); a == nil || !strings.Contains(msg, "registerToken: token is registered as usdc") {
		t.Fatalf("symbol change: abort %v", a)
	}
}
