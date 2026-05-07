package main

import (
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// End-to-end reproduction of pentest finding EVM-C8.
//
// Bug: setVerifierContract accepted an empty contract_id. The
// readState path then sees vcid != "" as false and falls back to
// sdk.StateGetObject — i.e. back to BLS-oracle headers (or the
// empty state). An attacker who got owner access for one moment
// could regress ZK → BLS by passing "".
//
// Fix: reject empty verifier-contract IDs in setVerifierContract.
// Combined with EVM-C1 immutability, the verifier can only move
// forward from the first set value.

func TestEVMC8_SetVerifierContractRejectsEmpty(t *testing.T) {
	sdk.ResetTestStateStore()

	// First set goes through — establishes the verifier.
	first := `{"contract_id":"vsc1Verifier"}`
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("first set should not panic: %v", r)
			}
		}()
		_ = setVerifierContract(&first)
	}()

	// Try to clear it via empty contract_id. The pentest also
	// noted EVM-C1 (immutability) would block this once the
	// fix lands; this test pins the empty-rejection at first
	// write so a fresh deploy can't ever land empty either.
	sdk.ResetTestStateStore()
	empty := `{"contract_id":""}`
	var panicValue interface{}
	func() {
		defer func() { panicValue = recover() }()
		_ = setVerifierContract(&empty)
	}()

	if panicValue == nil {
		got := sdk.StateGetObject(constants.VerifierContractIdKey)
		if got != nil && *got == "" {
			t.Fatalf(
				"EVM-C8 leak: setVerifierContract accepted an empty contract_id. " +
					"readState falls back to BLS-oracle state when verifier id is empty.")
		}
	}
	msg, _ := panicValue.(string)
	if !strings.Contains(strings.ToLower(msg), "empty") &&
		!strings.Contains(strings.ToLower(msg), "verifier") {
		t.Errorf("expected empty/verifier-related abort, got: %v", panicValue)
	}
}
