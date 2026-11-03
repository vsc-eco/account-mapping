package main

import (
	"testing"

	"evm-mapping-contract/contract/admin"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/mapping"
	"evm-mapping-contract/sdk"
)

// setTokenCustody goes through the operational timelock and execute's
// dispatch; a bad payload or an unregistered token aborts and writes nothing.
func TestTC_SetTokenCustodyDispatch(t *testing.T) {
	if d, err := admin.TimelockFor("setTokenCustody"); err != nil || d != admin.TimelockOperational {
		t.Fatalf("setTokenCustody timelock = %d %v, want operational", d, err)
	}
	sdk.ResetTestStateStore()
	if err := mapping.RegisterToken(1, [20]byte{19: 0xc0}, "usdc", 6, 1); err != nil {
		t.Fatal(err)
	}
	dispatch := func(payload string) (abort interface{}) {
		defer func() { abort = recover() }()
		dispatchAdmin("setTokenCustody", []byte(payload))
		return nil
	}
	for _, bad := range []string{`not json`, `{"asset":"dai","slot":9}`, `{"asset":"usdc","slot":9,"bits":300}`} {
		if a := dispatch(bad); a == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if _, ok := sdk.TestStateGet(constants.TokenCustodyConfigPrefix + "usdc"); ok {
		t.Fatal("a refused setTokenCustody wrote state")
	}
	if a := dispatch(`{"asset":"usdc","slot":9,"bits":255,"gap":"1000000"}`); a != nil {
		t.Fatalf("valid: %v", a)
	}
	if v, _ := sdk.TestStateGet(constants.TokenCustodyConfigPrefix + "usdc"); v != "9|255|1000000" {
		t.Fatalf("stored %q", v)
	}
}
