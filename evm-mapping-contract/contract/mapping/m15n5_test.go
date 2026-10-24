package mapping

import (
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

func m15Token(b byte) [20]byte {
	var a [20]byte
	a[19] = b
	return a
}

// M15-N5: a ledger symbol belongs to one token, and a registered token keeps
// its symbol. A second token under "usdc" would credit usdc balances that
// unmapERC20 pays out as the first token; a renamed token strands its
// balances under the old symbol.
func TestM15N5_SymbolBelongsToOneToken(t *testing.T) {
	sdk.ResetTestStateStore()
	usdc, fake := m15Token(0xaa), m15Token(0xbb)

	if err := RegisterToken(1, usdc, "usdc", 6, 10_000_000); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if got := sdk.StateGetObject(constants.TokenSymbolPrefix + "usdc"); got == nil || *got != "1-00000000000000000000000000000000000000aa" {
		t.Fatalf("owner record %v", got)
	}

	// The same token under its own symbol: allowed, record updated.
	if err := RegisterToken(1, usdc, "usdc", 6, 20_000_000); err != nil {
		t.Fatalf("re-registering the same token: %v", err)
	}
	if info := getTokenInfo(1, usdc); info == nil || info.MinWithdrawal != 20_000_000 {
		t.Fatalf("re-registration not applied: %+v", info)
	}

	// Another token under the same symbol: refused, nothing written.
	err := RegisterToken(1, fake, "usdc", 6, 1)
	if err == nil || !strings.Contains(err.Error(), "belongs to token 1-00000000000000000000000000000000000000aa") {
		t.Fatalf("second token under usdc: %v", err)
	}
	if getTokenInfo(1, fake) != nil {
		t.Fatal("the refused token was registered")
	}
	// Nor under another chain id.
	if err := RegisterToken(5, usdc, "usdc", 6, 1); err == nil {
		t.Fatal("the same symbol on another chain id was accepted")
	}

	// The token under a new symbol: refused, old record and markers kept.
	err = RegisterToken(1, usdc, "usdc2", 6, 1)
	if err == nil || !strings.Contains(err.Error(), "registered as usdc") {
		t.Fatalf("symbol change: %v", err)
	}
	if info := getTokenInfo(1, usdc); info == nil || info.Symbol != "usdc" {
		t.Fatalf("symbol changed to %+v", info)
	}
	if isAllowedAsset("usdc2") || sdk.StateGetObject(constants.TokenSymbolPrefix+"usdc2") != nil {
		t.Fatal("a refused symbol change left markers for the new symbol")
	}

	// The native asset is never a token symbol (main.go refuses it too).
	if err := RegisterToken(1, fake, constants.NativeAsset, 18, 1); err == nil {
		t.Fatal("a token registered as eth")
	}

	// A fresh symbol for the other token is fine.
	if err := RegisterToken(1, fake, "wbtc", 8, 1); err != nil {
		t.Fatalf("a distinct symbol: %v", err)
	}
}

// A symbol registered before the ts- owner index existed has its as- marker
// and registry record but no owner record. Only that token may re-register
// under it, which writes the owner record.
func TestM15N5_SymbolRegisteredBeforeTheIndex(t *testing.T) {
	sdk.ResetTestStateStore()
	usdc, fake := m15Token(0xaa), m15Token(0xbb)
	sdk.StateSetObject(constants.TokenRegistryPrefix+"1-00000000000000000000000000000000000000aa", "usdc|6|10000000")
	sdk.StateSetObject(constants.AllowedSymbolPrefix+"usdc", "1")

	if err := RegisterToken(1, fake, "usdc", 6, 1); err == nil || !strings.Contains(err.Error(), "already a registered asset") {
		t.Fatalf("another token under a pre-index symbol: %v", err)
	}
	if err := RegisterToken(1, usdc, "usdc", 6, 10_000_000); err != nil {
		t.Fatalf("the pre-index token re-registering: %v", err)
	}
	if got := sdk.StateGetObject(constants.TokenSymbolPrefix + "usdc"); got == nil || *got != "1-00000000000000000000000000000000000000aa" {
		t.Fatalf("owner record not written: %v", got)
	}
	if err := RegisterToken(1, fake, "usdc", 6, 1); err == nil {
		t.Fatal("another token under usdc after the owner record was written")
	}
}
