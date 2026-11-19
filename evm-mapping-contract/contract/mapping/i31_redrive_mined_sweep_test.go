package mapping

import (
	"math/big"
	"strings"
	"testing"
)

// I-31 (devnet 11-05, develop arm): the bot re-drove a sweep that had already
// mined (its receipt read failed). The re-drive moved BuiltL1 past the block the
// first version mined in, and confirmSweep refused every block at or below
// BuiltL1, so the mined sweep could never be confirmed and every new version was
// "nonce too low": the rotation stuck for good. The confirmation floor is now
// the first build; the re-drive timer still runs from the last one.
func TestI31_SweepMinedBeforeARedriveIsStillConfirmed(t *testing.T) {
	w := newMigWorld(t)
	stray := wei("10000000000000000")
	balance := new(big.Int).Add(VaultBook(0, "eth"), stray)
	if _, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, balance)); err != nil {
		t.Fatal(err)
	}
	built := GetSweep(0, 0).BuiltL1
	// Version 0 mines right away; its header is stored, but the confirm is not
	// sent yet (the bot could not read the receipt).
	minedV0 := w.mine(0, 0, w.sign(GetSweep(0, 0).Versions[0].Unsigned, 1), 1)
	// The bot re-drives it once the window passed, thinking it unmined.
	w.advance(SweepRedriveL1Blocks)
	if _, err := HandleRedriveSweep(0, 0, 1); err != nil {
		t.Fatalf("re-drive: %v", err)
	}
	r := GetSweep(0, 0)
	if r.BuiltL1 <= minedV0.BlockHeight || len(r.Versions) != 2 {
		t.Fatalf("after the re-drive: built_l1 %d (version 0 mined at %d), %d versions", r.BuiltL1, minedV0.BlockHeight, len(r.Versions))
	}
	if r.FirstBuiltL1 != built {
		t.Fatalf("first_built_l1 %d, want the first build %d", r.FirstBuiltL1, built)
	}
	// The mined version 0 is confirmed.
	if err := HandleConfirmSweep(minedV0, 1); err != nil {
		t.Fatalf("the version that mined before the re-drive is refused: %v", err)
	}
	if GetSweep(0, 0) != nil {
		t.Fatal("the confirmed sweep is still open")
	}
}

// A record written before first_built_l1 existed keeps the old floor.
func TestI31_OldRecordFallsBackToBuiltL1(t *testing.T) {
	w := newMigWorld(t)
	balance := new(big.Int).Add(VaultBook(0, "eth"), wei("10000000000000000"))
	if _, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, balance)); err != nil {
		t.Fatal(err)
	}
	r := GetSweep(0, 0)
	r.FirstBuiltL1 = 0 // as stored by the previous code
	r.BuiltL1 = w.n + 5
	putSweep(r)
	early := w.mine(0, 0, w.sign(r.Versions[0].Unsigned, 1), 1) // a block at or below built_l1
	if early.BlockHeight > r.BuiltL1 {
		t.Fatalf("test setup: block %d is above built_l1 %d", early.BlockHeight, r.BuiltL1)
	}
	if err := HandleConfirmSweep(early, 1); err == nil || !strings.Contains(err.Error(), "after the sweep was built") {
		t.Fatalf("an old record's floor is not built_l1: %v", err)
	}
}
