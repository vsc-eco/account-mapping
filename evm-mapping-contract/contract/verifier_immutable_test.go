package main

import (
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// End-to-end reproduction of pentest finding EVM-C1.
//
// Bug: setVerifierContract accepted any string with no timelock,
// multisig, or target validation. readState reads blindly from
// whatever contract is configured. A single-owner-key compromise
// could redirect the verifier to an attacker-controlled contract,
// feed arbitrary fake headers, mint fake deposits, and drain the
// vault.
//
// Fix: lock the verifier-contract ID immutable after first set.
// Changing it requires redeploying the mapping contract.
//
// Pre-fix: setVerifierContract overwrites any prior value.
// Post-fix: a second setVerifierContract on a non-empty value
// aborts with an immutability error.

func TestEVMC1_VerifierContractImmutableAfterFirstSet(t *testing.T) {
	sdk.ResetTestStateStore()

	// Owner is whatever sdk.GetEnv().Caller resolves to in the
	// test stub; the stub doesn't enforce a real value, so
	// checkOwner has to pass either way. We bypass checkOwner
	// concerns by writing the state directly first to simulate
	// a previously-set verifier.
	first := "vsc1KnownVerifier"
	sdk.StateSetObject(constants.VerifierContractIdKey, first)

	// Attacker-flavoured second call.
	second := `{"contract_id":"vsc1AttackerControlled"}`
	var panicValue interface{}
	func() {
		defer func() { panicValue = recover() }()
		_ = setVerifierContract(&second)
	}()

	if panicValue == nil {
		// Pre-fix path: the second setVerifierContract just overwrote
		// the verifier. Read the state to confirm.
		got := sdk.StateGetObject(constants.VerifierContractIdKey)
		if got != nil && *got == "vsc1AttackerControlled" {
			t.Fatalf(
				"EVM-C1 leak: setVerifierContract overwrote a previously-set verifier " +
					"with an attacker-supplied contract id. A compromised owner key " +
					"can redirect the bridge to a fake header source.")
		}
		t.Fatalf("EVM-C1: expected an immutability abort, got no panic and state = %v", got)
	}
	msg, _ := panicValue.(string)
	if !strings.Contains(strings.ToLower(msg), "verifier") &&
		!strings.Contains(strings.ToLower(msg), "immutab") &&
		!strings.Contains(strings.ToLower(msg), "already") {
		t.Errorf("expected immutability-related abort, got: %v", panicValue)
	}

	// Confirm the original verifier is still in place.
	got := sdk.StateGetObject(constants.VerifierContractIdKey)
	if got == nil || *got != first {
		t.Errorf("EVM-C1 fix incomplete: original verifier was lost; state = %v", got)
	}
}

func TestEVMC1_FirstSetAccepted(t *testing.T) {
	sdk.ResetTestStateStore()

	// Empty initial state — first set must succeed.
	first := `{"contract_id":"vsc1FirstVerifier"}`
	var panicValue interface{}
	func() {
		defer func() { panicValue = recover() }()
		_ = setVerifierContract(&first)
	}()
	if panicValue != nil {
		t.Fatalf("EVM-C1: first setVerifierContract on empty state should succeed; got panic: %v", panicValue)
	}
	got := sdk.StateGetObject(constants.VerifierContractIdKey)
	if got == nil || *got != "vsc1FirstVerifier" {
		t.Errorf("first set should write the verifier; got %v", got)
	}
}
