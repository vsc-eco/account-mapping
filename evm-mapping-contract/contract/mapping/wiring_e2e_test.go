package mapping

import (
	"math/big"
	"strconv"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// The rotation fixes reached through the real handlers (HandleMigrateVault,
// HandleConfirmSweep, HandleRetryTokenSweep, the withdrawal guard), not only
// through the helpers their own tests call.

// STALE-BOOK-1, write side: an ETH sweep built from a proof at block P records P.
func TestWiring_ETHSweepRecordsItsProofBlock(t *testing.T) {
	w := newMigWorld(t)
	proof := w.accountProof(w.gen0, 0, new(big.Int).Add(VaultBook(0, "eth"), wei("10000000000000000")))
	if _, err := HandleMigrateVault(1, proof); err != nil {
		t.Fatal(err)
	}
	if r := GetSweep(0, 0); r == nil || r.Kind != sweepKindETH {
		t.Fatalf("sweep 0-0 = %+v; want the ETH sweep", r)
	}
	if b, swept := ethSweptProofBlock(0); !swept || b != proof.BlockHeight {
		t.Fatalf("recorded proof block %d (swept %v); want the sweep's proof block %d", b, swept, proof.BlockHeight)
	}
}

// SWEEP-INFLIGHT-PURGE through confirmSweep: gen 0's sweep is built to gen 1,
// gen 2 is activated before it mines (gen 1 superseded, its own ETH sweep proven
// at an earlier block), and the confirmation books what gen 1 received.
func TestWiring_ConfirmSweepBooksASupersededDestination(t *testing.T) {
	w := newMigWorld(t)
	if _, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, VaultBook(0, "eth"))); err != nil {
		t.Fatal(err)
	}
	r := GetSweep(0, 0)
	if r == nil || r.Kind != sweepKindETH {
		t.Fatalf("sweep 0-0 = %+v; want the ETH sweep", r)
	}
	value, _ := new(big.Int).SetString(r.Versions[0].Value, 10)
	if value == nil || value.Sign() <= 0 {
		t.Fatalf("sweep value %q", r.Versions[0].Value)
	}
	// A pending generation minted earlier is activated while the sweep is open
	// (NN#3 gates only createKey): gen 1 is superseded.
	if _, _, err := MintNextGeneration(uint32(w.n)); err != nil {
		t.Fatal(err)
	}
	sdk.StubSetTssKeyFor("primaryv2", "active,"+testPub3+",ecdsa,1,1")
	if _, _, _, err := ActivatePendingGeneration(uint32(w.n)); err != nil {
		t.Fatal(err)
	}
	// Gen 1's own ETH sweep was proven at the current block; gen 0's sweep mines
	// after it, so that sweep did not carry this amount on.
	sdk.StateSetObject(constants.ETHSweptPrefix+"1", strconv.FormatUint(w.n, 10))
	before := VaultBook(1, "eth")
	mined := w.mine(0, 0, w.sign(r.Versions[0].Unsigned, 1), 1)
	if err := HandleConfirmSweep(mined, 1); err != nil {
		t.Fatalf("confirmSweep: %v", err)
	}
	got := new(big.Int).Sub(VaultBook(1, "eth"), before)
	if got.Cmp(value) != 0 {
		t.Fatalf("superseded gen 1 booked %s for the sweep it received; want the mined value %s", got, value)
	}
}

// Token sweep retry: refused while any sweep of the generation is open.
func TestWiring_RetryTokenSweepRefusesWhileASweepIsOpen(t *testing.T) {
	newRP7World(t)
	a01Registry(t, VaultStatusDraining)
	sdk.StateSetObject(sweepRevertKey(0, "USDC"), strconv.Itoa(MaxSweepReverts))
	putSweep(inflightSweep(0, 0, sweepKindETH, constants.NativeAsset, testAdr2, "1"))
	if _, err := HandleRetryTokenSweep(0, "USDC"); err == nil || !strings.Contains(err.Error(), "a sweep is open") {
		t.Fatalf("retry with an open sweep: %v; want refused", err)
	}
	closeSweep(GetSweep(0, 0))
	if _, err := HandleRetryTokenSweep(0, "USDC"); err != nil {
		t.Fatalf("retry once no sweep is open: %v", err)
	}
}
