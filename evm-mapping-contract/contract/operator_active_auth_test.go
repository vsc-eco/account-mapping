package main

import (
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// 18p (BTC contract 62ba2d9, ported 11-09): checkOperator was the only gate that
// let the owner through without active authority, so the owner's posting key
// alone could drive the four rotation exports. A hive: operator had the same
// gap. A did:pkh operator (the bot) has no posting variant and must keep working.
func TestP18p_OperatorExportsRequireActiveAuth(t *testing.T) {
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
	empty := "{}"
	exports := map[string]func(){
		"migrateVault": func() { migrateVault(&empty) },
		"redriveSweep": func() { redriveSweep(&empty) },
		"retireVault":  func() { retireVault(&empty) },
		"writeOffDust": func() { writeOffDust(&empty) },
	}
	setup := func(operator string) {
		sdk.ResetTestState()
		sdk.SetTestEnvKey("contract.owner", owner)
		if operator != "" {
			sdk.StateSetObject(constants.VaultOperatorKey, operator)
		}
	}
	const activeRefusal = "requires active authority"
	const notAllowed = "action must be performed by the contract owner or the vault operator"

	for name, export := range exports {
		// Owner, posting key only: refused before anything else runs.
		setup("")
		sdk.SetTestPostingCaller(owner)
		if msg := abortOf(export); !strings.Contains(msg, activeRefusal) {
			t.Errorf("%s by the owner's posting key: abort = %q, want the active-authority refusal", name, msg)
		}
		// Owner, active key: passes the gate (it may still stop later for an
		// unrelated reason, e.g. no vault yet; only the gate is under test).
		setup("")
		sdk.SetTestCaller(owner)
		if msg := abortOf(export); strings.Contains(msg, activeRefusal) || strings.Contains(msg, notAllowed) {
			t.Errorf("%s by the owner's active key was refused at the gate: %q", name, msg)
		}

		// hive: operator, posting only: refused.
		const hiveOp = "hive:magi.rotation.op"
		setup(hiveOp)
		sdk.SetTestPostingCaller(hiveOp)
		if msg := abortOf(export); !strings.Contains(msg, "vault operator action requires active authority") {
			t.Errorf("%s by a hive: operator's posting key: abort = %q, want the operator active-authority refusal", name, msg)
		}
		// hive: operator, active: passes the gate.
		setup(hiveOp)
		sdk.SetTestCaller(hiveOp)
		if msg := abortOf(export); strings.Contains(msg, activeRefusal) || strings.Contains(msg, notAllowed) {
			t.Errorf("%s by a hive: operator's active key was refused at the gate: %q", name, msg)
		}

		// did:pkh operator (the bot), not listed in required_auths: still passes
		// the gate (no posting variant exists for it).
		const didOp = "did:pkh:eip155:1:0x9861820c2E8399AEbf96D4e23A30DEA4AF2d532D"
		setup(didOp)
		sdk.SetTestPostingCaller(didOp)
		if msg := abortOf(export); strings.Contains(msg, activeRefusal) || strings.Contains(msg, notAllowed) {
			t.Errorf("%s by the did:pkh operator was refused at the gate: %q", name, msg)
		}

		// Anyone else: refused as before.
		setup(didOp)
		sdk.SetTestCaller("hive:stranger")
		if msg := abortOf(export); !strings.Contains(msg, notAllowed) {
			t.Errorf("%s by a stranger: abort = %q, want %q", name, msg, notAllowed)
		}
	}
	sdk.ResetTestState()
}
