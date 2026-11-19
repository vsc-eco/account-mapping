package mapping

import (
	"encoding/hex"
	"math/big"
	"testing"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// D-2: after MaxSweepReverts reverted transfers of a token, migration skips it
// for that generation for good, so a temporary cause (a token pause) used to end
// in writeOffToken: a booked loss for tokens still at the old address, required
// because the generation otherwise stays funded and blocks every rotation.
// retryTokenSweep puts the token back into the next migration's sweeps.
func TestTokenSweepRetry_RevertedTokenIsSweptAgain(t *testing.T) {
	newRP7World(t)
	a01Registry(t, VaultStatusDraining) // gen 0 superseded
	sdk.StateSetObject(constants.TokenSymbolsKey, "USDC")
	sdk.StateSetObject(constants.TokenSymbolPrefix+"USDC", "1-0x"+hex.EncodeToString(rp7USDC[:]))
	setVaultBook(0, "USDC", big.NewInt(5_000_000))
	header := &blocklist.EthBlockHeader{BlockNumber: 300, BaseFeePerGas: 1e9, GasLimit: 30_000_000, ChainId: 1}

	plans, _, stuck, err := planTokenSweeps(1, 0, header)
	if err != nil || len(plans) != 1 || stuck != "" {
		t.Fatalf("before any revert: plans=%d stuck=%q err=%v, want the USDC sweep", len(plans), stuck, err)
	}

	sdk.StateSetObject(sweepRevertKey(0, "USDC"), "2") // two reverted sweeps
	plans, _, stuck, _ = planTokenSweeps(1, 0, header)
	if len(plans) != 0 || stuck != "USDC" {
		t.Fatalf("after %d reverts: plans=%d stuck=%q, want USDC parked", MaxSweepReverts, len(plans), stuck)
	}

	if _, err := HandleRetryTokenSweep(0, "USDC"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	plans, _, stuck, _ = planTokenSweeps(1, 0, header)
	if len(plans) != 1 || plans[0].sym != "USDC" || stuck != "" {
		t.Fatalf("after the retry: plans=%d stuck=%q, want the USDC sweep back", len(plans), stuck)
	}
	if b := VaultBook(0, "USDC"); b.Cmp(big.NewInt(5_000_000)) != 0 {
		t.Fatalf("retry moved the book: %s", b)
	}

	// Gates: only a parked token, and the write-off is no longer due.
	if _, err := HandleRetryTokenSweep(0, "USDC"); err == nil {
		t.Fatal("a second retry with no new reverts was accepted")
	}
	if _, err := HandleWriteOffToken(0, "USDC"); err == nil {
		t.Fatal("write-off still accepted after the retry reset the reverts")
	}
}
