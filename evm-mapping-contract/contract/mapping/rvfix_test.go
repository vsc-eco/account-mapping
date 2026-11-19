package mapping

import (
	"testing"

	"evm-mapping-contract/sdk"
)

// TestE1_AssetAllowlist is the regression guard for E1 (RV re-verify): the
// ledger balance key is `a-{addr}-{asset}`, so a free-form `asset` could alias
// another account's key (caller `hive:milo` + asset `hpr-eth` == account
// `hive:milo-hpr` + asset `eth`). Only the native "eth" or a REGISTERED token
// symbol may be used as a ledger asset.
func TestE1_AssetAllowlist(t *testing.T) {
	sdk.ResetTestStateStore()

	if err := requireAllowedAsset("eth"); err != nil {
		t.Fatalf("native eth must always be allowed: %v", err)
	}
	if err := requireAllowedAsset("USDC"); err == nil {
		t.Fatal("an UNregistered symbol must be rejected")
	}
	if err := requireAllowedAsset("hpr-eth"); err == nil {
		t.Fatal("a key-injection asset string must be rejected")
	}
	if err := requireAllowedAsset(""); err == nil {
		t.Fatal("empty asset must be rejected")
	}

	// After registration the symbol becomes an allowed ledger asset.
	var tok [20]byte
	tok[19] = 0xaa
	if err := RegisterToken(1, tok, "USDC", 6, 1000); err != nil {
		t.Fatal(err)
	}
	if err := requireAllowedAsset("USDC"); err != nil {
		t.Fatalf("a registered symbol must be allowed: %v", err)
	}
	// ...but a key-injection variant of it is still rejected (no as- marker).
	if err := requireAllowedAsset("USDC-eth"); err == nil {
		t.Fatal("a registered symbol must not whitelist a '-'-suffixed variant")
	}
}
