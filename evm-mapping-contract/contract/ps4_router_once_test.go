package main

import (
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// PS-4 (BTC VR2-20 parity): the DEX router is set once. The same id again is a
// no-op; another id is refused and the stored router stays.
func TestPS4_RouterIsSetOnce(t *testing.T) {
	sdk.ResetTestStateStore()
	dispatch := func(payload string) (abort interface{}) {
		defer func() { abort = recover() }()
		dispatchAdmin("registerRouter", []byte(payload))
		return nil
	}
	if a := dispatch("vsc1router1"); a != nil {
		t.Fatalf("first registration: %v", a)
	}
	if a := dispatch("vsc1router1"); a != nil {
		t.Fatalf("the same router again must be a no-op: %v", a)
	}
	if a := dispatch("vsc1attacker"); a == nil {
		t.Fatal("a second, different router was accepted")
	}
	if v, _ := sdk.TestStateGet(constants.RouterContractIdKey); v != "vsc1router1" {
		t.Fatalf("stored router %q, want vsc1router1", v)
	}
	if a := dispatch(""); a == nil {
		t.Fatal("an empty router id was accepted")
	}
}
