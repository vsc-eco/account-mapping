package mapping

import (
	"math/big"

	ce "evm-mapping-contract/contract/contracterrors"
)

// A01: a deposit is credited when it paid any fund-holding generation's address
// (Active, Retiring, Draining or Inactive), or that generation's MagiDeposit, as
// the BTC contract keeps every fund-holding generation's address matchable. A
// late deposit to a superseded generation is credited like any other and booked
// to that generation, so the migration sweeps it and the purge waits for it.
// Pending (no funds sent there yet) and Purged (address retired) generations
// are not credited.

type depositTargetSet struct {
	gens    []fundHoldingGen
	matched [20]byte
	l1      uint64 // the deposit's L1 block
}

// newDepositTargets is the fund-holding generations, or, for a contract with no
// registry (nothing to fold), the single vault the caller passed.
func newDepositTargets(vault [20]byte) *depositTargetSet {
	t := &depositTargetSet{gens: FundHoldingGens()}
	if len(t.gens) == 0 && vault != ([20]byte{}) {
		t.gens = []fundHoldingGen{{Vault: Vault{Status: VaultStatusActive}, Address: vault}}
	}
	return t
}

// ownAddress reports whether a is one of the vault's own addresses: a
// fund-holding generation's, or the single vault a contract with no registry
// uses. Those are the only vault addresses that can send (a pending generation
// holds nothing, a purged one is empty). A transfer from one of them is the
// vault moving its own funds (a migration sweep, or a withdrawal paid to a
// vault address), never a deposit: crediting it would mint the moved amount a
// second time.
func (t *depositTargetSet) ownAddress(a [20]byte) bool {
	return t.find(a) != nil
}

// errOwnTransfer refuses a "deposit" sent by the vault itself.
var errOwnTransfer = ce.NewContractError(ce.ErrInput, "the sender is one of the vault's own addresses: a sweep or a withdrawal to the vault, not a deposit")

func (t *depositTargetSet) find(a [20]byte) *fundHoldingGen {
	for i := range t.gens {
		if t.gens[i].Address == a {
			return &t.gens[i]
		}
	}
	return nil
}

// isVault reports whether a is a fund-holding generation's address and
// remembers it as the deposit's vault.
func (t *depositTargetSet) isVault(a [20]byte) bool {
	if t.find(a) != nil {
		t.matched = a
		return true
	}
	return false
}

// vaultOfDepositContract maps a MagiDeposit address to the generation it pays.
func (t *depositTargetSet) vaultOfDepositContract(dc [20]byte) ([20]byte, bool) {
	for i := range t.gens {
		if DepositContractAddress(t.gens[i].Address) == dc {
			t.matched = t.gens[i].Address
			return t.gens[i].Address, true
		}
	}
	return [20]byte{}, false
}

// book records that amount of asset arrived at the matched vault: a superseded
// generation's book grows (the active generation's share is derived).
func (t *depositTargetSet) book(asset string, amount *big.Int) {
	g := t.find(t.matched)
	if g == nil || !isSupersededStatus(g.Status) || amount.Sign() <= 0 {
		return
	}
	addVaultBook(g.Generation, asset, amount)
	noteBookedHeight(g.Generation, t.l1)
}
