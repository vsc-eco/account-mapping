package main

import (
	"strings"
	"testing"

	"evm-mapping-contract/sdk"
)

// A2: the owner's posting key made the owner the Caller and passed checkOwner,
// so it could propose, execute and cancel admin actions (pause among them) and
// run initContract without the multisig on the owner's active authority.
func TestA2_OwnerGatesRequireActiveAuth(t *testing.T) {
	const owner = "hive:magi.bridge.owner"
	abortOf := func(f func()) (msg string) {
		defer func() {
			if r := recover(); r != nil {
				msg, _ = r.(string)
				if msg == "" {
					msg = "panic"
				}
			}
		}()
		f()
		return ""
	}

	for name, gate := range map[string]func(){
		"checkOwner":   checkOwner,
		"initContract": func() { in := `{"chain_id":1}`; initContract(&in) },
	} {
		sdk.ResetTestState()
		sdk.SetTestEnvKey("contract.owner", owner)
		sdk.SetTestPostingCaller(owner)
		if msg := abortOf(gate); !strings.Contains(msg, "requires active authority") {
			t.Errorf("%s with the owner's posting key: abort = %q, want the active-authority refusal", name, msg)
		}

		sdk.ResetTestState()
		sdk.SetTestEnvKey("contract.owner", owner)
		sdk.SetTestCaller(owner)
		if msg := abortOf(gate); strings.Contains(msg, "requires active authority") {
			t.Errorf("%s with the owner's active key was refused: %q", name, msg)
		}
	}
	sdk.ResetTestState()
}
