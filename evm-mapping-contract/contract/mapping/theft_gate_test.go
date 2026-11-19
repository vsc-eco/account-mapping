package mapping

import (
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// P1: a vault address whose proven nonce is above what the bridge authorized
// sent a transaction nobody asked for; anyone can prove it and the theft halt
// is set. At or below the authorized count the report is refused and nothing
// is set (an honest vault can never be reported).
func TestP1_UnauthorizedSpendSetsTheTheftHalt(t *testing.T) {
	w := newMigWorld(t) // gen 0 retiring, gen 1 active; nothing sent yet
	report := func(gen uint32, addr [20]byte, nonce uint64) error {
		_, err := HandleReportUnauthorizedSpend(&ReportUnauthorizedSpendParams{Gen: gen, Proof: w.accountProof(addr, nonce, big.NewInt(1))})
		return err
	}
	if err := report(1, w.gen1, 0); err == nil || TheftHalted() {
		t.Fatalf("active gen at nonce 0 with nothing authorized: err %v halted %v; want refused, no halt", err, TheftHalted())
	}
	if err := report(0, w.gen0, 0); err == nil || TheftHalted() {
		t.Fatalf("retiring gen at nonce 0: err %v halted %v; want refused", err, TheftHalted())
	}
	// two sweeps authorized from gen 0 (sweep nonces 0, 1): nonce 2 is honest
	setSweepNonce(0, 2)
	if err := report(0, w.gen0, 2); err == nil || TheftHalted() {
		t.Fatalf("retiring gen at its authorized count: err %v; want refused", err)
	}
	if err := report(0, w.gen0, 3); err != nil || !TheftHalted() {
		t.Fatalf("retiring gen one past its authorized count: err %v halted %v; want the halt", err, TheftHalted())
	}
	found := false
	for _, l := range sdk.TestLogs() {
		found = found || strings.HasPrefix(l, "security|evm-theft-halt|gen=0|")
	}
	if !found {
		t.Fatalf("no security log: %v", sdk.TestLogs())
	}
	ClearTheftHalt()
	if TheftHalted() {
		t.Fatal("clearTheftHalt left the flag")
	}
	if _, ok := sdk.TestStateGet(constants.TheftHaltKey); ok {
		t.Fatal("cleared by writing a value, not by deletion (the node reads any value as a halt)")
	}
	// the active gen: one withdrawal nonce issued -> nonce 1 honest, 2 theft
	SetPendingNonce(1)
	if err := report(1, w.gen1, 1); err == nil {
		t.Fatal("active gen at its pending nonce was reported")
	}
	if err := report(1, w.gen1, 2); err != nil || !TheftHalted() {
		t.Fatalf("active gen past its pending nonce: err %v halted %v", err, TheftHalted())
	}
}

// While a superseded generation holds the withdrawal nonces, the active
// generation has authorized nothing; a pause does not stop a report; an
// unknown generation is refused.
func TestP1_HolderPauseAndUnknownGeneration(t *testing.T) {
	w := newMigWorld(t)
	sdk.StateSetObject(constants.WithdrawNonceHolderKey, "0")
	SetPendingNonce(5)
	sdk.StateSetObject(constants.PausedKey, "1")
	if _, err := HandleReportUnauthorizedSpend(&ReportUnauthorizedSpendParams{Gen: 1, Proof: w.accountProof(w.gen1, 1, big.NewInt(1))}); err != nil || !TheftHalted() {
		t.Fatalf("active gen sent a tx while gen 0 held the nonces, contract paused: err %v halted %v; want the halt", err, TheftHalted())
	}
	if _, err := HandleReportUnauthorizedSpend(&ReportUnauthorizedSpendParams{Gen: 9, Proof: w.accountProof(w.gen1, 1, big.NewInt(1))}); err == nil {
		t.Fatal("an unknown generation was accepted")
	}
	if _, err := HandleReportUnauthorizedSpend(&ReportUnauthorizedSpendParams{Gen: 1}); err == nil {
		t.Fatal("a report without a proof was accepted")
	}
}
