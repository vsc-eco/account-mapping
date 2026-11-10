package main

import (
	"reflect"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/mapping"
	"evm-mapping-contract/sdk"
)

// CG-A7: redriveSweep takes the owner past the version cap and keeps the
// operator under it.
func TestCGA7_RedriveHandlerByCaller(t *testing.T) {
	const owner, operator = "hive:magi.bridge.owner", "did:pkh:eip155:1:0x00000000000000000000000000000000000000b0"
	same := func(a, b any) bool { return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer() }
	sdk.ResetTestState()
	sdk.SetTestEnvKey("contract.owner", owner)
	sdk.StateSetObject(constants.VaultOperatorKey, operator)
	sdk.SetTestCaller(owner)
	if !same(redriveHandler(), mapping.HandleOwnerRedriveSweep) {
		t.Fatal("the owner's re-drive is capped")
	}
	sdk.SetTestCaller(operator)
	if !same(redriveHandler(), mapping.HandleRedriveSweep) {
		t.Fatal("the operator's re-drive goes past the cap")
	}
}
