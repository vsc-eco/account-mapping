package mapping

import (
	"math/big"
	"strings"
	"testing"
)

// SWEEP-REMAP-1: a purged generation's old sweep (here the USDC Transfer it sent
// to the active generation during its migration) is the vault moving its own
// funds. Mapping it as a deposit used to mint the swept amount a second time,
// credited to the purged address's DID that no one can sign for; the next
// custody proof then read short and froze every withdrawal.
func TestSweepRemap1_PurgedGenerationSweepIsNotADeposit(t *testing.T) {
	w := newRP7World(t)
	a01Registry(t, VaultStatusDraining) // gen 0 Draining, 1 Active, 2 Purged, 3 Pending
	active := a01Addr(t, testAdr2)
	purged := a01Addr(t, testAdr3)

	// The purged generation's sweep to its successor.
	n, rc, nodes := w.mine(1, transferLog(rp7USDC, purged, active, 25_000_000))
	err := mapERC20(n, rc, nodes, 0)
	if err == nil || !strings.Contains(err.Error(), "vault's own addresses") {
		t.Fatalf("purged generation's sweep: err=%v, want the own-transfer refusal", err)
	}
	if s := GetSupply("USDC"); s.Active.Sign() != 0 || s.User.Sign() != 0 {
		t.Fatalf("purged generation's sweep minted supply: active=%s user=%s", s.Active, s.User)
	}

	// Unchanged: a fund-holding generation's transfer is refused the same way,
	// and a user's deposit to the active generation is still credited.
	n, rc, nodes = w.mine(1, transferLog(rp7USDC, rp7Vault, active, 1_000_000))
	if err := mapERC20(n, rc, nodes, 0); err == nil || !strings.Contains(err.Error(), "vault's own addresses") {
		t.Fatalf("draining generation's sweep: err=%v, want the own-transfer refusal", err)
	}
	n, rc, nodes = w.mine(1, transferLog(rp7USDC, rp7User, active, 5_000_000))
	if err := mapERC20(n, rc, nodes, 0); err != nil {
		t.Fatalf("user deposit to the active generation: %v", err)
	}
	if s := GetSupply("USDC"); s.Active.Cmp(big.NewInt(5_000_000)) != 0 {
		t.Fatalf("supply %s after one user deposit, want 5000000", s.Active)
	}
}
