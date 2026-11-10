package mapping

import (
	"strings"
	"testing"
)

// CUSTODY-STALE-HEADER-1: once a complete proof finds the vault short at block
// S ("si" set: the nodes stop the vault's keysigns), a complete proof from an
// older block (it shows the vault before the loss) does not lift the halt; a
// proof at S or newer showing the custody back does.
func TestCUSTODYSTALE_AnOlderProofDoesNotLiftTheHalt(t *testing.T) {
	w := newMigWorld(t) // gen 0 retiring, gen 1 active; booked custody 3.5 ETH
	prove := func(p0, p1 *AccountProof) (string, error) {
		t.Helper()
		if out, err := HandleProveCustody(&ProveCustodyParams{Gen: 1, Proof: p1}); err != nil || !strings.Contains(out, "1 of 2") {
			t.Fatalf("first generation: %q %v", out, err)
		}
		return HandleProveCustody(&ProveCustodyParams{Gen: 0, Proof: p0})
	}
	full0, full1 := w.twoAccounts(w.gen0, wei("1000000000000000000"), w.gen1, wei("2500000000000000000"))   // block A
	short0, short1 := w.twoAccounts(w.gen0, wei("1000000000000000000"), w.gen1, wei("2000000000000000000")) // block B > A: 0.5 ETH gone
	if full0.BlockHeight >= short0.BlockHeight {
		t.Fatalf("fixture: full proof block %d not before the short one %d", full0.BlockHeight, short0.BlockHeight)
	}
	if out, err := prove(short0, short1); err != nil || !SolvencyHalted() {
		t.Fatalf("0.5 ETH short at block %d: %q %v halted=%v", short0.BlockHeight, out, err, SolvencyHalted())
	}
	out, err := prove(full0, full1)
	if err != nil || !SolvencyHalted() || !strings.Contains(out, "older than the shortfall") {
		t.Fatalf("a full proof from block %d, before the shortfall at %d: %q %v halted=%v; want the halt kept",
			full0.BlockHeight, short0.BlockHeight, out, err, SolvencyHalted())
	}
	back0, back1 := w.twoAccounts(w.gen0, wei("1000000000000000000"), w.gen1, wei("2500000000000000000")) // block C > B
	if out, err := prove(back0, back1); err != nil || SolvencyHalted() {
		t.Fatalf("custody back at block %d: %q %v halted=%v", back0.BlockHeight, out, err, SolvencyHalted())
	}
}
