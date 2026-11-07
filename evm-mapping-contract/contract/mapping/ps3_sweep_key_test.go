package mapping

import (
	"strings"
	"testing"

	"evm-mapping-contract/sdk"
)

// PS-3 (BTC BRK-2 assertInputsSignable parity): a sweep is never built or
// re-driven with a retiring key the host will not sign with (deprecated or
// deleted): it would sit unsigned, its gas booked, the generation's later
// nonces behind it. The owner renews the key first.
func TestPS3_NoSweepWithAnUnsignableRetiringKey(t *testing.T) {
	newMigWorld(t) // gen 0 retiring ("primary"), gen 1 active and reshared
	for _, status := range []string{"deprecated", "deleted"} {
		sdk.StubSetTssKeyFor("primary", status+","+testPub1+",ecdsa,1,1")
		if _, err := HandleMigrateVault(1, nil); err == nil || !strings.Contains(err.Error(), "renewKey it first") {
			t.Fatalf("migrateVault with the retiring key %s: %v, want the renewKey refusal", status, err)
		}
		if _, err := HandleRedriveSweep(0, 0, 1); err == nil || !strings.Contains(err.Error(), "renewKey it first") {
			t.Fatalf("redriveSweep with the retiring key %s: %v, want the renewKey refusal", status, err)
		}
	}
	sdk.StubSetTssKeyFor("primary", "active,"+testPub1+",ecdsa,1,1")
	if _, err := HandleMigrateVault(1, nil); err != nil && strings.Contains(err.Error(), "renewKey") {
		t.Fatalf("migrateVault with an active retiring key refused for the key: %v", err)
	}
}
