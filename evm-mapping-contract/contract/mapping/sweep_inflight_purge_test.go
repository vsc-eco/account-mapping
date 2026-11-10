package mapping

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// SWEEP-INFLIGHT-PURGE: a sweep is built to the generation active then. NN#3
// gates only createKey, so a pending generation minted earlier can be activated
// while that sweep is still open, superseding its destination. The amount then
// lands at an address that booked nothing for it (only the active generation's
// share is derived): the generation emptied, purged, and the amount stranded.

func inflightSweep(gen uint32, nonce uint64, kind, asset, to, amount string) *SweepRecord {
	return &SweepRecord{Gen: gen, Nonce: nonce, Kind: kind, Asset: asset, To: to, Amount: amount, Booked: "0",
		Versions: []SweepVersion{{Value: amount}}}
}

func TestSweepInflightPurge_ReceivedAmountIsBookedToASupersededDestination(t *testing.T) {
	newRP7World(t)
	a01Registry(t, VaultStatusDraining) // gen 0 superseded at rp7Vault, gen 1 active at testAdr2
	superseded := "0x" + hex.EncodeToString(rp7Vault[:])
	one := big.NewInt(1e18)

	// ETH sweep from an older generation (99) lands on the superseded gen 0.
	bookSweepAtDestination(inflightSweep(99, 0, sweepKindETH, constants.NativeAsset, superseded, one.String()), one.String(), 300)
	if b := VaultBook(0, constants.NativeAsset); b.Cmp(one) != 0 {
		t.Fatalf("ETH landing on a superseded generation: book %s, want 1e18", b)
	}
	// A token sweep books its amount there too.
	bookSweepAtDestination(inflightSweep(99, 1, sweepKindToken, "USDC", superseded, "5000000"), "0", 301)
	if b := VaultBook(0, "USDC"); b.Cmp(big.NewInt(5_000_000)) != 0 {
		t.Fatalf("token landing on a superseded generation: book %s, want 5000000", b)
	}
	// The active generation books nothing (its share is derived), as before.
	bookSweepAtDestination(inflightSweep(99, 2, sweepKindETH, constants.NativeAsset, testAdr2, one.String()), one.String(), 302)
	if b := VaultBook(1, constants.NativeAsset); b.Sign() != 0 {
		t.Fatalf("ETH landing on the active generation was booked: %s", b)
	}
	// ETH that gen 0's own sweep already carried on (mined at or before gen 0's
	// proof block) is not booked again (the F03 rule).
	sdk.StateSetObject(constants.ETHSweptPrefix+"0", "400")
	bookSweepAtDestination(inflightSweep(99, 3, sweepKindETH, constants.NativeAsset, superseded, one.String()), one.String(), 350)
	if b := VaultBook(0, constants.NativeAsset); b.Cmp(one) != 0 {
		t.Fatalf("ETH mined before gen 0's own proof block was booked again: book %s, want 1e18", b)
	}
}

func TestSweepInflightPurge_NoPurgeWhileASweepToItIsOpen(t *testing.T) {
	newRP7World(t) // stored L1 height 200
	a01Registry(t, VaultStatusInactive)
	vaults, next, active, _ := LoadVaultState()
	vaults[0].InactiveHeight = 1 // past the testnet grace + map window at height 200
	SaveVaultState(vaults, next, active)
	putSweep(inflightSweep(99, 0, sweepKindETH, constants.NativeAsset, "0x"+hex.EncodeToString(rp7Vault[:]), "1"))

	if out, err := ReconcileRetiringVaults(11155111); err != nil || strings.Contains(out, "purged=0") {
		t.Fatalf("an open sweep pays generation 0: reconcile %q err=%v, want no purge", out, err)
	}
	closeSweep(GetSweep(99, 0))
	if out, err := ReconcileRetiringVaults(11155111); err != nil || !strings.Contains(out, "purged=0") {
		t.Fatalf("no sweep pays it any more: reconcile %q err=%v, want generation 0 purged", out, err)
	}
}
