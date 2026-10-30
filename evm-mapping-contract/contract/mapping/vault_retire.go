package mapping

import (
	"math/big"
	"strconv"
	"strings"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/sdk"
)

// A01 retirement tail, as the BTC contract's ReconcileRetiringVaults:
//
//	Retiring|Draining, nothing booked, no sweep open -> Inactive (grace anchor)
//	Inactive, funded again (a late deposit)           -> Draining
//	Inactive, empty, grace elapsed                    -> Purged
//
// A generation is never purged while anything is booked to it: a late deposit
// to an Inactive address is credited and booked, the next reconcile returns it
// to Draining, and the migration sweeps it. Purging deletes no key; it retires
// the address from deposit matching and, on the node, releases its committee's
// bonds. Owner or vault operator; pause-gated.

// ReconcileRetiringVaults applies at most one transition per generation.
func ReconcileRetiringVaults(chainId uint64) (string, error) {
	height := L1Height()
	if height == 0 {
		return "", ce.NewContractError(ce.ErrStateAccess, "retireVault: no L1 header height")
	}
	grace := constants.VaultPurgeGraceL1Blocks(chainId)
	FoldLegacyKeyIfNeeded(false)
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return "", err
	}
	var toInactive, toDraining, toPurged []string
	for i := range vaults {
		v := &vaults[i]
		g := strconv.FormatUint(uint64(v.Generation), 10)
		switch v.Status {
		case VaultStatusRetiring, VaultStatusDraining:
			if !genFunded(v.Generation) {
				v.Status = VaultStatusInactive
				v.InactiveHeight = inactiveAnchor(v.InactiveHeight, height, grace)
				toInactive = append(toInactive, g)
			}
		case VaultStatusInactive:
			if genFunded(v.Generation) {
				v.Status = VaultStatusDraining
				toDraining = append(toDraining, g)
			} else if v.InactiveHeight != 0 && height >= v.InactiveHeight && height-v.InactiveHeight >= grace {
				v.Status = VaultStatusPurged
				toPurged = append(toPurged, g)
			}
		}
	}
	SaveVaultState(vaults, nextGen, activeGen)
	if len(toInactive)+len(toDraining)+len(toPurged) == 0 {
		return "retire: no generation transitions", nil
	}
	out := "retire:"
	if len(toInactive) > 0 {
		out += " inactivated=" + strings.Join(toInactive, ",")
	}
	if len(toDraining) > 0 {
		out += " reverted-to-draining=" + strings.Join(toDraining, ",")
	}
	if len(toPurged) > 0 {
		out += " purged=" + strings.Join(toPurged, ",")
	}
	return out, nil
}

// inactiveAnchor is the purge-grace anchor of an emptying at height (BTC
// PURGE-GRIEF-1): the first emptying anchors there; a re-emptying after a late
// deposit keeps it, moved forward only so the purge still waits
// VaultPurgeReorgL1Blocks after this emptying.
func inactiveAnchor(prev, height, grace uint32) uint32 {
	if prev == 0 {
		return height
	}
	if height+constants.VaultPurgeReorgL1Blocks > grace {
		if floor := height + constants.VaultPurgeReorgL1Blocks - grace; floor > prev {
			return floor
		}
	}
	return prev
}

// HandleWriteOffDust writes off a superseded generation's ETH that cannot pay
// for its own sweep: no token is booked to it, no sweep is open, and its ETH
// book is at most one ETH sweep's gas at the current price. The ETH stays at
// the old address; its book goes to 0 and the gas reserve bears it (BTC: the
// reserve covers a write-off). Owner or vault operator; pause-gated.
func HandleWriteOffDust() (string, error) {
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return "", err
	}
	header, err := pricingHeader()
	if err != nil {
		return "", err
	}
	_, cost, err := safeGasFee(defaultETHGasLimit(), header.BaseFeePerGas, 2, sweepTipCap)
	if err != nil {
		return "", err
	}
	for i := range vaults {
		v := vaults[i]
		if v.Status != VaultStatusRetiring && v.Status != VaultStatusDraining && v.Status != VaultStatusInactive {
			continue
		}
		if hasOpenSweep(v.Generation) {
			continue
		}
		tokens := false
		for _, sym := range RegisteredSymbols() {
			tokens = tokens || VaultBook(v.Generation, sym).Sign() > 0
		}
		dust := VaultBook(v.Generation, constants.NativeAsset)
		if tokens || dust.Sign() == 0 || dust.Cmp(cost) > 0 {
			continue
		}
		if getGasReserve().Cmp(dust) < 0 {
			return "", ce.NewContractError(ce.ErrIntent, "gas reserve below the dust to write off")
		}
		deductGasReserve(dust)
		TrackReserveSpend(dust)
		setVaultBook(v.Generation, constants.NativeAsset, new(big.Int))
		g := strconv.FormatUint(uint64(v.Generation), 10)
		sdk.Log("dustoff|g=" + g + "|a=eth|v=" + dust.String())
		return "wrote off " + dust.String() + " wei of generation " + g, nil
	}
	return "no dust to write off", nil
}

// HandleWriteOffToken writes off a token a superseded generation can no longer
// transfer: its sweep reverted MaxSweepReverts times (for example a token that
// blocklisted the address). Owner only. The tokens stay at the old address and
// the custody drops by the book: the shortfall against what users hold is a
// loss the owner has to cover, and the log says so.
func HandleWriteOffToken(gen uint32, symbol string) (string, error) {
	if sweepReverts(gen, symbol) < MaxSweepReverts {
		return "", ce.NewContractError(ce.ErrIntent, "token "+symbol+" has not reverted "+strconv.Itoa(MaxSweepReverts)+" times for this generation")
	}
	if hasOpenSweep(gen) {
		return "", ce.NewContractError(ce.ErrIntent, "a sweep is open for this generation")
	}
	book := VaultBook(gen, symbol)
	if book.Sign() == 0 {
		return "", ce.NewContractError(ce.ErrIntent, "nothing booked")
	}
	s := GetSupply(symbol)
	if book.Cmp(s.Active) > 0 {
		sdk.Abort("token write-off above the custody")
	}
	s.Active.Sub(s.Active, book)
	SetSupply(symbol, s)
	setVaultBook(gen, symbol, new(big.Int))
	sdk.Log("tokenoff|g=" + strconv.FormatUint(uint64(gen), 10) + "|a=" + symbol + "|v=" + book.String() +
		"|insolvent=" + new(big.Int).Sub(s.User, s.Active).String() + "|l1=" + strconv.FormatUint(blocklist.GetLastHeight(), 10))
	return "wrote off " + book.String() + " " + symbol + " of generation " + strconv.FormatUint(uint64(gen), 10), nil
}
