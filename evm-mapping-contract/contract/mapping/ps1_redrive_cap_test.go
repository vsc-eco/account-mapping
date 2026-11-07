package mapping

import (
	"math/big"
	"strings"
	"testing"
)

// PS-1 (BTC MaxSpendGroupMembers / cold-scan B): a sweep is re-driven at most
// MaxSweepVersions times; each version raises the fee 10% and books its extra
// gas, so a sweep stuck for a reason other than its fee must not escalate
// forever.
func TestPS1_SweepRedrivesAreCapped(t *testing.T) {
	w := newMigWorld(t)
	addGasReserve(wei("1000000000000000000000")) // the reserve is not what stops it
	setVaultBook(0, "usdc", new(big.Int))
	if _, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, VaultBook(0, "eth"))); err != nil {
		t.Fatal(err)
	}
	var err error
	for i := 0; i < MaxSweepVersions+5 && err == nil; i++ {
		w.advance(SweepRedriveL1Blocks)
		_, err = HandleRedriveSweep(0, 0, 1)
	}
	if err == nil || !strings.Contains(err.Error(), "re-drive cap") {
		t.Fatalf("re-drives ended with %v, want the version cap", err)
	}
	if n := len(GetSweep(0, 0).Versions); n != MaxSweepVersions {
		t.Fatalf("%d versions at the cap, want %d", n, MaxSweepVersions)
	}
}

// PS-1 (BTC cold-scan C / V5-4): a re-drive may not spend more than half of
// what an ETH sweep moves on gas.
func TestPS1_SweepRedriveFeeCeiling(t *testing.T) {
	w := newMigWorld(t)
	addGasReserve(wei("1000000000000000000000"))
	setVaultBook(0, "usdc", new(big.Int))
	setVaultBook(0, "eth", wei("20000000000000000")) // 0.02 ETH left to sweep
	if _, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, VaultBook(0, "eth"))); err != nil {
		t.Fatal(err)
	}
	var err error
	n := 0
	for ; n < MaxSweepVersions && err == nil; n++ {
		w.advance(SweepRedriveL1Blocks)
		_, err = HandleRedriveSweep(0, 0, 1)
	}
	if err == nil || !strings.Contains(err.Error(), "more than half of the ETH sweep") {
		t.Fatalf("after %d re-drives: %v, want the half-the-sweep ceiling", n, err)
	}
	r := GetSweep(0, 0)
	last := r.Versions[len(r.Versions)-1]
	fee := new(big.Int).Mul(new(big.Int).SetUint64(r.Gas), new(big.Int).SetUint64(last.FeeCap))
	moved := new(big.Int).Add(wei(last.Value), fee)
	if new(big.Int).Mul(fee, big.NewInt(2)).Cmp(moved) > 0 {
		t.Fatalf("the last accepted version spends %s of %s on gas: over half", fee, moved)
	}
}
