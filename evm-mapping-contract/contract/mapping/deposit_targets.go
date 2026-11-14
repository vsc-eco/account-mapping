package mapping

import (
	"math/big"

	"evm-mapping-contract/contract/constants"
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
// fund-holding generation's, a purged generation's, or the single vault a
// contract with no registry uses. A transfer from one of them is the vault
// moving its own funds (a migration sweep, or a withdrawal paid to a vault
// address), never a deposit: crediting it would mint the moved amount a
// second time. A pending generation has sent nothing.
func (t *depositTargetSet) ownAddress(a [20]byte) bool {
	return t.find(a) != nil || isPurgedGenAddress(a)
}

// isPurgedGenAddress reports whether a is a purged generation's address
// (SWEEP-REMAP-1). A purged generation is empty and no longer a deposit target,
// but the sweeps it sent before the purge stay provable for as long as the
// verifier keeps their headers: without this check each of them maps as a new
// deposit to the successor and mints the swept amount again. The registry read
// is memoized, and a purged generation's address is cached.
func isPurgedGenAddress(a [20]byte) bool {
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return false // unreadable registry: as before, only the handler's vault applies
	}
	for i := range vaults {
		if vaults[i].Status != VaultStatusPurged {
			continue
		}
		if addr, ok := GenAddress(&vaults[i]); ok && addr == a {
			return true
		}
	}
	return false
}

// errVaultDestination refuses a withdrawal paid to one of the vault's own
// addresses (I-15, testnet 11-04): the payout would land in the vault and is
// never credited back (a map from a vault address is errOwnTransfer), so the
// user loses it. The BTC contract refuses a payout to its change address for
// the same reason ("self-harm, no theft, but cheap to reject outright").
var errVaultDestination = ce.NewContractError(ce.ErrInput, "refusing withdrawal to one of the vault's own addresses: the payout would stay in the vault and never be credited back")

// refuseVaultDestination is errVaultDestination when to is a fund-holding
// generation's address: the active vault (the handler's vault, already
// derived) or a superseded one still holding funds. Only the superseded
// generations' addresses are derived here, so outside a rotation the check
// costs one registry read (a first version derived every generation through
// FundHoldingGens: +114 RC on every unmap).
func refuseVaultDestination(to, vault [20]byte) error {
	if vault != ([20]byte{}) && to == vault {
		return errVaultDestination
	}
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return nil // the withdrawal's own vault reads fail it further on
	}
	for i := range vaults {
		v := vaults[i]
		if v.Status == VaultStatusActive || !isFundHoldingStatus(v.Status) {
			continue
		}
		if addr, ok := GenAddress(&v); ok && addr == to {
			return errVaultDestination
		}
	}
	return nil
}

// errTokenDestination refuses an ERC-20 withdrawal paid to the token contract
// itself (TC04-1, from THORChain's evm-null-address-outbound test): a token
// without a self-transfer guard keeps the tokens at its own address forever,
// and one with a guard (USDC) reverts, so the reserve fronts the gas of a
// payout that cannot land. Self-harm, no theft, cheap to reject at request,
// like the zero address and the vault's own addresses.
var errTokenDestination = ce.NewContractError(ce.ErrInput, "refusing withdrawal to the token contract itself: the tokens would be stuck at the token's own address")

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
	// STALE-BOOK-1: an ETH sweep sends the balance proven at its proof block, so
	// an ETH deposit mined at or before that block already went with it to the
	// active generation (whose share is derived). Booking it here leaves a book
	// the address never holds: the generation never empties and NN#3 refuses
	// every later rotation. Tokens are swept by book, so they stay booked.
	if asset == constants.NativeAsset {
		if proofBlock, swept := ethSweptProofBlock(g.Generation); swept && t.l1 <= proofBlock {
			return
		}
	}
	addVaultBook(g.Generation, asset, amount)
	noteBookedHeight(g.Generation, t.l1)
}
