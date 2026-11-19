package main

import (
	"strings"
	"testing"

	"evm-mapping-contract/contract/admin"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// D6: a fresh bridge waited out two 400K-block timelocks (setVerifierContract,
// createKey) before its first deposit. initContract may now wire both once;
// afterwards they go through propose/execute as before.
func TestD6_InitWiresTheVerifierAndKeyOnce(t *testing.T) {
	const owner = "hive:magi.bridge.owner"
	run := func(in string) (msg string) {
		if admin.FastTimelockBuild { // A-1: that build initializes only as a testnet bridge
			in = strings.Replace(in, "{", `{"is_testnet":true,`, 1)
		}
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
	if msg := run(`{"chain_id":11155111,"verifier_contract":"vsc1verifier","create_key":true}`); msg != "" {
		t.Fatalf("init with first wiring: %s", msg)
	}
	if v, _ := sdk.TestStateGet(constants.VerifierContractIdKey); v != "vsc1verifier" {
		t.Fatalf("verifier after init = %q, want vsc1verifier", v)
	}
	if keys := sdk.TestCreatedKeys(); len(keys) != 1 || keys[0] != "primary,ecdsa,365" {
		t.Fatalf("keys requested at init = %v, want the primary ecdsa key", keys)
	}
	// One-shot: a second init (which could re-point the verifier) is refused.
	if msg := run(`{"chain_id":11155111,"verifier_contract":"vsc1other"}`); !strings.Contains(msg, "already initialized") {
		t.Fatalf("second init = %q, want refused", msg)
	}
	if v, _ := sdk.TestStateGet(constants.VerifierContractIdKey); v != "vsc1verifier" {
		t.Fatalf("verifier after a refused second init = %q", v)
	}

	// Without the fields, init wires nothing (the existing deploy flow).
	fresh()
	if msg := run(`{"chain_id":11155111}`); msg != "" {
		t.Fatal(msg)
	}
	if _, ok := sdk.TestStateGet(constants.VerifierContractIdKey); ok || len(sdk.TestCreatedKeys()) != 0 {
		t.Fatalf("plain init wired the verifier or requested a key")
	}

	// A07: is_testnet unlocks clearTestnetState, so it is refused on Ethereum
	// mainnet (chain 1) and nothing is written.
	if !admin.FastTimelockBuild {
		fresh()
		if msg := run(`{"chain_id":1,"is_testnet":true}`); !strings.Contains(msg, "is_testnet cannot be set on chain_id 1") {
			t.Fatalf("is_testnet on chain 1 = %q, want refused", msg)
		}
		if _, ok := sdk.TestStateGet(constants.InitMarkerKey); ok {
			t.Fatal("a refused init marked the contract initialized")
		}
		fresh()
		if msg := run(`{"chain_id":1}`); msg != "" {
			t.Fatalf("mainnet init without is_testnet: %s", msg)
		}
		fresh()
		if msg := run(`{"chain_id":11155111,"is_testnet":true}`); msg != "" {
			t.Fatalf("Sepolia testnet init: %s", msg)
		}
	}

	// The admin path requests the same key.
	fresh()
	dispatchAdmin("createKey", []byte(`{}`))
	if keys := sdk.TestCreatedKeys(); len(keys) != 1 || keys[0] != "primary,ecdsa,365" {
		t.Fatalf("createKey via execute requested %v", keys)
	}
}
