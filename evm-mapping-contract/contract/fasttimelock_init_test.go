//go:build devnet_fasttimelock

package main

import (
	"strings"
	"testing"

	"evm-mapping-contract/sdk"
)

// A-1: the devnet_fasttimelock build cuts the admin timelocks to a few blocks.
// Deployed by mistake as a real bridge, every owner action (setVerifierContract,
// createKey, replaceWithdrawal) would land almost at once. It initializes only
// as a testnet bridge. Run with: go test -tags devnet_fasttimelock ./contract/
func TestA1_FastTimelockBuildInitializesOnlyAsTestnet(t *testing.T) {
	const owner = "hive:magi.bridge.owner"
	run := func(in string) (msg string) {
		defer func() {
			if r := recover(); r != nil {
				msg, _ = r.(string)
				if msg == "" {
					msg = "panic"
				}
			}
		}()
		initContract(&in)
		return ""
	}
	fresh := func() {
		sdk.ResetTestState()
		sdk.SetTestEnvKey("contract.owner", owner)
		sdk.SetTestCaller(owner)
	}
	fresh()
	if msg := run(`{"chain_id":1}`); !strings.Contains(msg, "devnet timelocks") {
		t.Fatalf("init of the fast-timelock build without is_testnet = %q, want refused", msg)
	}
	fresh()
	if msg := run(`{"chain_id":11155111,"is_testnet":true}`); msg != "" {
		t.Fatalf("init of the fast-timelock build as a testnet bridge: %s", msg)
	}
}
