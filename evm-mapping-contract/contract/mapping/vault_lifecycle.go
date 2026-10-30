package mapping

import (
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/sdk"
)

// A01 generation lifecycle, mirroring the BTC contract's vault_lifecycle.go:
//
//   createKey          -> MintNextGeneration        (append a Pending successor)
//   activateKey        -> ActivatePendingGeneration (cut over; predecessor retires)
//   discardPendingKey  -> DiscardPendingGeneration  (drop a stalled keygen)
//
// Never-brick, as BTC: a superseded generation keeps its key and funds until
// they are swept and it is purged; every guard failure aborts the whole call,
// so the live vault keeps serving through a failed ceremony; generation numbers
// are monotonic and never reused.
//
// Key authenticity: a generation activates only with its key as the TSS
// ceremony produced it (TssGetKey), after the node has seen that key produce a
// verified check signature (field 4, BRK-2) and, for a rotation, after the key
// has been handed to a committee by a reshare (field 5, VR2-12). The owner can
// trigger a rotation but never choose the key.

// L1Height is the newest Ethereum height the contract has a header for, as the
// registry's uint32 heights.
func L1Height() uint32 {
	h := blocklist.GetLastHeight()
	if h > 0xffffffff {
		return 0xffffffff
	}
	return uint32(h)
}

// RegisteredSymbols lists the registered token symbols (TokenSymbolsKey).
func RegisteredSymbols() []string {
	s := sdk.StateGetObject(constants.TokenSymbolsKey)
	if s == nil || *s == "" {
		return nil
	}
	return strings.Split(*s, "|")
}

func indexTokenSymbol(symbol string) {
	for _, s := range RegisteredSymbols() {
		if s == symbol {
			return
		}
	}
	syms := append(RegisteredSymbols(), symbol)
	sdk.StateSetObject(constants.TokenSymbolsKey, strings.Join(syms, "|"))
}

// vaultAssets is every asset a vault address can hold: ETH and each token.
func vaultAssets() []string {
	return append([]string{constants.NativeAsset}, RegisteredSymbols()...)
}

func vaultBookKey(gen uint32, asset string) string {
	return constants.VaultBookPrefix + strconv.FormatUint(uint64(gen), 10) + constants.DirPathDelimiter + asset
}

// VaultBook is what superseded generation gen's address holds of asset.
func VaultBook(gen uint32, asset string) *big.Int {
	if s := sdk.StateGetObject(vaultBookKey(gen, asset)); s != nil {
		return parseAmount(*s)
	}
	return new(big.Int)
}

func setVaultBook(gen uint32, asset string, amt *big.Int) {
	if amt.Sign() < 0 {
		sdk.Abort("vault book underflow: generation " + strconv.FormatUint(uint64(gen), 10) + " " + asset)
	}
	if amt.Sign() == 0 {
		sdk.StateDeleteObject(vaultBookKey(gen, asset))
		return
	}
	sdk.StateSetObject(vaultBookKey(gen, asset), amt.String())
}

func addVaultBook(gen uint32, asset string, delta *big.Int) {
	setVaultBook(gen, asset, new(big.Int).Add(VaultBook(gen, asset), delta))
}

// SupersededBookTotal sums the books of every superseded generation for asset:
// the part of the custody that is not at the active generation's address.
func SupersededBookTotal(asset string) *big.Int {
	total := new(big.Int)
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return total
	}
	for i := range vaults {
		if isSupersededStatus(vaults[i].Status) {
			total.Add(total, VaultBook(vaults[i].Generation, asset))
		}
	}
	return total
}

// openSweeps lists the open migration sweeps as "{gen}-{nonce}".
func openSweeps() []string {
	s := sdk.StateGetObject(constants.MigrationSweepsKey)
	if s == nil || *s == "" {
		return nil
	}
	return strings.Split(*s, "|")
}

func hasOpenSweep(gen uint32) bool {
	prefix := strconv.FormatUint(uint64(gen), 10) + constants.DirPathDelimiter
	for _, k := range openSweeps() {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// genFunded reports whether generation gen still holds anything the contract
// knows of: a booked balance in any asset, or a sweep not yet settled.
func genFunded(gen uint32) bool {
	for _, a := range vaultAssets() {
		if VaultBook(gen, a).Sign() > 0 {
			return true
		}
	}
	return hasOpenSweep(gen) || holdsInFlightWithdrawals(gen)
}

// AnyFundedSupersededGen is NN#3: no new generation while a superseded one still
// holds funds, or funded old keys pile up (each a reconstruction target).
func AnyFundedSupersededGen() (bool, error) {
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return false, err
	}
	for i := range vaults {
		if isSupersededStatus(vaults[i].Status) && genFunded(vaults[i].Generation) {
			return true, nil
		}
	}
	return false, nil
}

// MintNextGeneration appends a Pending generation and returns it with its TSS
// key name; the caller requests the key. Genesis (an empty registry, nothing to
// fold) mints a self-referential vault; a rotation binds the new generation to
// the active one. At most one keygen in flight.
func MintNextGeneration(height uint32) (uint32, string, error) {
	FoldLegacyKeyIfNeeded(true)
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return 0, "", err
	}
	if firstVaultWithStatus(vaults, VaultStatusPending) >= 0 {
		return 0, "", ce.NewContractError(ce.ErrTransaction,
			"a key generation is already in flight (a pending vault exists); activate or discard it before minting another")
	}
	gen := nextGen
	predecessor := gen // genesis
	if len(vaults) > 0 {
		if countVaultsWithStatus(vaults, VaultStatusActive) != 1 {
			return 0, "", ce.NewContractError(ce.ErrTransaction,
				"cannot mint a successor: expected exactly one active vault to rotate from")
		}
		predecessor = activeGen
	}
	vaults = append(vaults, Vault{
		Generation:    gen,
		Status:        VaultStatusPending,
		Predecessor:   predecessor,
		CreatedHeight: height,
	})
	SaveVaultState(vaults, gen+1, activeGen)
	return gen, VaultKeyName(gen), nil
}

// ActivatePendingGeneration makes the pending generation active and retires the
// active one, which keeps its key and funds until swept. Returns (activated,
// retired, hadPredecessor).
func ActivatePendingGeneration(height uint32) (uint32, uint32, bool, error) {
	FoldLegacyKeyIfNeeded(true)
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return 0, 0, false, err
	}
	pendingIdx := firstVaultWithStatus(vaults, VaultStatusPending)
	if pendingIdx < 0 {
		return 0, 0, false, ce.NewContractError(ce.ErrTransaction, "no pending vault to activate")
	}
	v := &vaults[pendingIdx]
	name := VaultKeyName(v.Generation)
	parts := tssKeyParts(name)
	pub, ok := tssKeyPub(name, "active")
	if !ok {
		return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
			"cannot activate generation: its TSS key is not an active ecdsa key (keygen incomplete or missing)")
	}
	if !isZeroKey(v.Primary) && v.Primary != pub {
		return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
			"the generation's key does not match the TSS ceremony output")
	}
	genesis := isGenesisVault(v)
	// BRK-2: agreement on a key is not proof its committee can sign with it. The
	// node reports a verified check signature in field 4. A genesis key the
	// pre-rotation contract already checked (attestVault) counts too.
	checked := len(parts) >= 4 && parts[3] == "1"
	if !checked && !(genesis && vaultVerified(hex.EncodeToString(pub[:]))) {
		return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
			"cannot activate generation: its TSS key has not produced a verified check signature yet (BRK-2)")
	}
	// VR2-12: a rotation's key must have survived a committee change (field 5)
	// before any funds go to it; the old generation keeps serving meanwhile.
	if !genesis && !(len(parts) >= 5 && parts[4] == "1") {
		return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
			"cannot activate generation: its TSS key has not been reshared into a committee yet; the old generation keeps serving until it is (VR2-12)")
	}

	oldIdx := firstVaultWithStatus(vaults, VaultStatusActive)
	hadPredecessor := oldIdx >= 0
	var retiredGen uint32
	if genesis {
		if hadPredecessor {
			return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
				"genesis vault cannot activate while an active vault already exists")
		}
	} else {
		if !hadPredecessor {
			return 0, 0, false, ce.NewContractError(ce.ErrTransaction, "cannot activate a successor: no active vault to retire")
		}
		if vaults[oldIdx].Generation != activeGen {
			return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
				"state inconsistency: active vault generation does not match the active-gen counter")
		}
		if v.Predecessor != activeGen {
			return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
				"pending vault predecessor does not match the active generation (broken lineage)")
		}
	}

	if hadPredecessor {
		retiredGen = vaults[oldIdx].Generation
		if err := retireActiveGeneration(vaults, retiredGen); err != nil {
			return 0, 0, false, err
		}
		vaults[oldIdx].Status = VaultStatusRetiring
		vaults[oldIdx].RetiredHeight = height
	}
	v.Primary = pub
	v.Status = VaultStatusActive
	v.ActivatedHeight = height
	activeGen = v.Generation
	if countVaultsWithStatus(vaults, VaultStatusActive) != 1 {
		return 0, 0, false, ce.NewContractError(ce.ErrTransaction,
			"invariant violation: expected exactly one active vault after activation")
	}
	SaveVaultState(vaults, nextGen, activeGen)
	return v.Generation, retiredGen, hadPredecessor, nil
}

// retireActiveGeneration hands the vault from generation gen to its successor.
//
// The cut-over never waits for gen's in-flight withdrawals (ROT-HALT-1: with
// withdrawals arriving faster than they settle, a settle-first rule could
// refuse activation for good). gen keeps the withdrawal nonces until they
// settle (WithdrawNonceHolder), and its key may still replace or roll them:
// the node lets a retiring key sign below WithdrawCeiling only the contract's
// own record of such a withdrawal, or a 0-value roll to itself. New
// withdrawals wait for the hand-off; they wait for the sweep to reach the new
// generation anyway.
//
// It books what gen's address holds, per asset: the custody, plus the queued
// withdrawals' debits (requested, not yet sent, so still there), minus what
// other superseded generations hold. In-flight withdrawals left the custody
// when issued and leave gen's address when they mine; one that is refunded
// instead is booked back to gen (bookSpendRefund). The new generation starts
// with nothing; it serves from its own deposits and from the sweep once that
// lands. gen's sweeps carry on from the nonce after its withdrawals.
func retireActiveGeneration(vaults VaultRegistry, gen uint32) error {
	if _, held := WithdrawNonceHolder(); held && HasPendingWithdrawal() {
		// Two cut-overs within one settle time: the older generation's
		// withdrawals still hold the nonces. Rare (a new key takes a keygen, a
		// check signature and a reshare); it clears as they settle.
		return ce.NewContractError(ce.ErrTransaction,
			"cannot activate: an earlier generation's in-flight withdrawals still hold the withdrawal nonces; retry once they settle")
	}
	withdrawalNoncesHeld() // a finished hand-off clears the old holder
	if !StepQueuedDebitRecount() {
		return ce.NewContractError(ce.ErrTransaction,
			"cannot activate yet: counting the withdrawal queue left from before the rotation upgrade, a bounded step per call; retry")
	}
	for _, asset := range vaultAssets() {
		held := new(big.Int).Set(GetSupply(asset).Active)
		held.Add(held, QueuedDebit(asset))
		for i := range vaults {
			if vaults[i].Generation != gen && isSupersededStatus(vaults[i].Status) {
				held.Sub(held, VaultBook(vaults[i].Generation, asset))
			}
		}
		setVaultBook(gen, asset, held) // aborts on a negative: the books disagree with the custody
	}
	next := GetPendingNonce()
	setSweepNonce(gen, next)
	sdk.StateSetObject(constants.WithdrawCeilingPrefix+strconv.FormatUint(uint64(gen), 10), strconv.FormatUint(next, 10))
	// Every deposit in the snapshot mined at or before the newest stored
	// header: an ETH sweep's balance proof must not be older.
	noteBookedHeight(gen, blocklist.GetLastHeight())
	if HasPendingWithdrawal() {
		sdk.StateSetObject(constants.WithdrawNonceHolderKey, strconv.FormatUint(uint64(gen), 10))
		return nil
	}
	sdk.StateDeleteObject(constants.NonceConfirmedKey)
	sdk.StateDeleteObject(constants.NoncePendingKey)
	return nil
}

// bookSpendRefund books amount of a refunded withdrawal back to the superseded
// generation it was issued from: it never left that address, and the custody
// it returns to must not be counted as the active generation's. ETH is the
// exception once the generation's ETH has been swept from a proven balance:
// the proof was taken after the withdrawal's nonce was spent, so the ETH went
// with that sweep to the active generation.
func bookSpendRefund(ps *PendingSpend, amount *big.Int) {
	g, ok := SpendGen(ps)
	if !ok || g.Status == VaultStatusActive || amount.Sign() <= 0 {
		return
	}
	if ps.Asset == constants.NativeAsset && sdk.StateGetObject(constants.ETHSweptPrefix+strconv.FormatUint(uint64(g.Generation), 10)) != nil {
		return
	}
	addVaultBook(g.Generation, ps.Asset, amount)
}

func sweepNonceKey(gen uint32) string {
	return constants.SweepNoncePrefix + strconv.FormatUint(uint64(gen), 10)
}

// SweepNonce is the next L1 nonce of retiring generation gen's address.
func SweepNonce(gen uint32) uint64 {
	if s := sdk.StateGetObject(sweepNonceKey(gen)); s != nil {
		n, _ := strconv.ParseUint(*s, 10, 64)
		return n
	}
	return 0
}

func setSweepNonce(gen uint32, n uint64) {
	sdk.StateSetObject(sweepNonceKey(gen), strconv.FormatUint(n, 10))
}

// DiscardPendingGeneration drops the pending generation (a stalled or failed
// keygen). It never held funds. The generation number is not reused.
func DiscardPendingGeneration() (uint32, error) {
	FoldLegacyKeyIfNeeded(true)
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return 0, err
	}
	i := firstVaultWithStatus(vaults, VaultStatusPending)
	if i < 0 {
		return 0, ce.NewContractError(ce.ErrTransaction, "no pending vault to discard")
	}
	gen := vaults[i].Generation
	vaults = append(vaults[:i], vaults[i+1:]...)
	SaveVaultState(vaults, nextGen, activeGen)
	return gen, nil
}

// RenewableVaultKeyNames lists the key of every fund-holding generation that can
// be renewed without aborting (status active or deprecated, BTC R3-1), and the
// fund-holding ones that cannot (so the caller can warn).
func RenewableVaultKeyNames() (renewable, skipped []string, err error) {
	FoldLegacyKeyIfNeeded(true)
	vaults, _, _, lerr := LoadVaultState()
	if lerr != nil {
		return nil, nil, lerr
	}
	if len(vaults) == 0 {
		// No registry and no legacy key to fold: the original key, if any.
		if p := tssKeyParts(constants.VaultKeyBaseName); p[0] == "active" || p[0] == "deprecated" {
			return []string{constants.VaultKeyBaseName}, nil, nil
		}
		return nil, nil, nil
	}
	for i := range vaults {
		if !isFundHoldingStatus(vaults[i].Status) {
			continue
		}
		name := VaultKeyName(vaults[i].Generation)
		if p := tssKeyParts(name); p[0] == "active" || p[0] == "deprecated" {
			renewable = append(renewable, name)
		} else {
			skipped = append(skipped, name)
		}
	}
	return renewable, skipped, nil
}
