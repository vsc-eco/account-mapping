package main

import (
	"encoding/json"
	"strings"
	"testing"

	"evm-mapping-contract/contract/admin"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// D7: the vault key expires after 365 epochs (~91 days) and retires 403,200
// blocks after that, never to sign again. renewKey sat behind the 400K-block
// timelock (and refused while paused), leaving ~3,200 blocks of margin. It is
// now immediate, as the BTC mapping contract's, and allowed while paused;
// createKey keeps its timelock.
func TestD7_RenewKeyIsImmediateAndWorksWhilePaused(t *testing.T) {
	const owner = "hive:magi.bridge.owner"
	call := func(f func(*string) *string, in string) (out, msg string) {
		defer func() {
			if r := recover(); r != nil {
				msg, _ = r.(string)
				if msg == "" {
					msg = "panic"
				}
			}
		}()
		if p := f(&in); p != nil {
			out = *p
		}
		return out, ""
	}
	proposeExecute := func(action string) string {
		out, msg := call(propose, `{"action":"`+action+`","payload_hex":""}`)
		if msg != "" {
			return "propose: " + msg
		}
		var resp admin.ProposeResponse
		_ = json.Unmarshal([]byte(out), &resp)
		_, msg = call(execute, `{"proposal_id":`+jsonUint(resp.ProposalId)+`}`)
		return msg
	}
	for _, paused := range []bool{false, true} {
		sdk.ResetStubState()
		sdk.SetTestEnvKey("contract.owner", owner)
		sdk.SetTestCaller(owner)
		if paused {
			sdk.StateSetObject(constants.PausedKey, "1")
		}
		if msg := proposeExecute("renewKey"); msg != "" {
			t.Fatalf("paused=%v: renewKey proposed and executed in the same block: %s", paused, msg)
		}
		if got := sdk.TestRenewedKeys(); len(got) != 1 || got[0] != "primary,365" {
			t.Fatalf("paused=%v: renewed %v, want the primary key for 365 epochs", paused, got)
		}
		if msg := proposeExecute("createKey"); !strings.Contains(msg, "timelock not elapsed") {
			t.Fatalf("paused=%v: createKey executed at once: %q", paused, msg)
		}
	}
	if tl, _ := admin.TimelockFor("renewKey"); tl != admin.TimelockImmediate {
		t.Fatalf("renewKey timelock %d", tl)
	}
}

func jsonUint(v uint64) string { b, _ := json.Marshal(v); return string(b) }
