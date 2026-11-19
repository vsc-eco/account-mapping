package sdk

import "testing"

// Regression guard for the launch-blocking HIGH: the WASM host returns a non-nil
// empty string "" for an ABSENT state key (execution-context GetState ->
// result.Ok("")), whereas this package's host-Go stub returns nil. The contract
// was written + unit-tested against the stub, so a bare `StateGetObject(k) != nil`
// presence check was ALWAYS true on the real host — breaking IsObserved (all
// deposits rejected as "already processed") and chainId() (returned 0 not 1).
//
// StateGetObject / EphemStateGetObject now normalize "" -> nil so every existing
// presence check / nil-guard behaves identically on the host and the stub. These
// tests simulate the host's ""-for-absent by storing "" and asserting nil comes
// back. WITHOUT the normalization they fail (a non-nil pointer to "" is returned);
// WITH it they pass. The integration proof is the go-vsc-node devnet suite
// (W1 deposit FAIL->PASS); this is the in-repo guard against re-introduction.
func TestStateGetObject_NormalizesHostEmptyToNil(t *testing.T) {
	const key = "regress-empty-as-absent"

	// Host ""-for-absent: a present-but-empty value must read back as nil so a
	// `!= nil` presence check (e.g. IsObserved) treats it as ABSENT.
	StateSetObject(key, "")
	if got := StateGetObject(key); got != nil {
		t.Fatalf("StateGetObject(%q): host ''-for-absent must normalize to nil, got %q", key, *got)
	}

	// A real non-empty value must still pass through untouched.
	StateSetObject(key, "real")
	if got := StateGetObject(key); got == nil || *got != "real" {
		t.Fatalf("StateGetObject(%q): real value must pass through, got %v", key, got)
	}
}

func TestEphemStateGetObject_NormalizesHostEmptyToNil(t *testing.T) {
	const key = "regress-ephem-empty-as-absent"

	EphemStateSetObject(key, "")
	if got := EphemStateGetObject("self", key); got != nil {
		t.Fatalf("EphemStateGetObject(%q): host ''-for-absent must normalize to nil, got %q", key, *got)
	}

	EphemStateSetObject(key, "real")
	if got := EphemStateGetObject("self", key); got == nil || *got != "real" {
		t.Fatalf("EphemStateGetObject(%q): real value must pass through, got %v", key, got)
	}
}
