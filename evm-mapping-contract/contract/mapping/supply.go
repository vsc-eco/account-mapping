package mapping

import (
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
	"math/big"
	"strconv"
	"strings"
)

// Supply tracks per-asset solvency totals. The three monetary accumulators
// are *big.Int (full wei / token-native precision, no overflow). BaseFee is
// a per-gas price observation (wei/gas) and stays a uint64 scalar.
//
// Semantics (canonical, per product spec):
//
//   - Active — total custody: the exact amount of the asset the bridge
//     believes it holds (for "eth", the L1 vault balance including the gas
//     reserve). This is the maximum theoretical spend. L1 gas paid to
//     mainnet miners LEAVES custody and is debited from Active; it is
//     never parked in Fee. Exact up to gas-ESTIMATE variance: unmaps debit
//     the upper-bound estimate (gasUnits × gasFeeCap), so Active may
//     slightly UNDERSTATE real custody — the safe direction for solvency.
//
//   - User — the portion of Active attributed to Magi-network accounts
//     (Σ of all ledger balances; smart contracts count as users).
//
//   - Fee — Magi-internal revenue fees ONLY (e.g. a percentage of unmaps).
//     No such fee exists today, so Fee stays 0. L1 gas and the gas-reserve
//     deposit tax are NOT Magi fees and never land here.
//
// The ETH gas reserve (GasReserveKey) is custody that is neither user- nor
// fee-attributed, so for "eth": Active == User + Fee + gasReserve. For
// ERC-20 assets there is no reserve component: Active == User + Fee.
type Supply struct {
	Active  *big.Int // total custody (max theoretical spend)
	User    *big.Int // attributed to Magi accounts (Σ balances)
	Fee     *big.Int // Magi-internal revenue fees only (0 today)
	BaseFee uint64   // latest base fee
}

// newSupply returns a zero Supply with non-nil accumulators so callers can
// always do s.Active.Add(...) without a nil check.
func newSupply() Supply {
	return Supply{Active: new(big.Int), User: new(big.Int), Fee: new(big.Int)}
}

func supplyKey(asset string) string {
	return constants.SupplyKey + constants.DirPathDelimiter + asset
}

// GetSupply reads the per-asset supply record.
//
// MED-133 (m59 F3), ported to develop's big.Int/wei + abort-loudly model: a
// MISSING key legitimately yields a zero Supply (no bridged balance yet). But a
// key that EXISTS yet decodes to fewer than 4 fields is CORRUPT (e.g. a layout
// migration that changed the encoding). Pre-fix develop silently returned
// Supply{} for both cases, and the caller wrote those zeros straight back,
// PERMANENTLY destroying the accounting. Abort on the corrupt case so the whole
// contract call reverts WITHOUT clobbering the stored record — matching
// TrackWithdrawal's existing underflow abort. (30710e4 used an error-return
// refactor of GetSupply; develop keeps the no-error signature and aborts, to
// avoid rippling a signature change through every supply caller.)
func GetSupply(asset string) Supply {
	s := newSupply()
	data := sdk.StateGetObject(supplyKey(asset))
	if data == nil {
		return s
	}
	fields := strings.Split(*data, "|")
	if len(fields) < 4 {
		sdk.Abort("GetSupply: corrupt supply record for asset " + asset + " (fewer than 4 fields) — refusing to overwrite")
	}
	s.Active = parseAmount(fields[0])
	s.User = parseAmount(fields[1])
	s.Fee = parseAmount(fields[2])
	s.BaseFee, _ = strconv.ParseUint(fields[3], 10, 64)
	return s
}

func SetSupply(asset string, s Supply) {
	data := s.Active.String() + "|" +
		s.User.String() + "|" +
		s.Fee.String() + "|" +
		strconv.FormatUint(s.BaseFee, 10)
	sdk.StateSetObject(supplyKey(asset), data)
}

// TrackDeposit accumulates per-asset supply totals. big.Int accumulators
// cannot overflow, so there is no failure mode and nothing to return.
//
// userAmount    — the portion credited to the depositor's ledger balance.
// reserveAmount — the portion diverted to the gas reserve (the 1% ETH
//
//	deposit tax; pass 0 for ERC-20). It stays in custody, so
//	Active includes it, but it is NOT user-attributed and NOT
//	a Magi revenue fee — Fee is untouched. The reserve
//	counter itself is maintained separately (addGasReserve).
func TrackDeposit(asset string, userAmount, reserveAmount *big.Int) {
	s := GetSupply(asset)
	delta := new(big.Int).Add(userAmount, reserveAmount)
	s.Active.Add(s.Active, delta)
	s.User.Add(s.User, userAmount)
	SetSupply(asset, s)
}

// TrackWithdrawal subtracts amount from the tracked Active and
// User supply for an asset.
//
// amount is the FULL user debit for the unmap: the L1 tx value plus any
// prepaid L1 fee (ps.Amount + ps.GasCost on the ETH path; the bare token
// amount on ERC-20 paths, whose gas comes from the reserve instead). Both
// custody and the user attribution shrink by exactly what the user paid;
// the L1 fee portion is real custody outflow (paid to mainnet miners), so
// it is NOT rebooked into Fee.
//
// Pentest finding F17: previously this function silently clamped
// negative results to 0. Every public withdrawal path validates the
// user's balance before reaching here, so a negative result can only
// mean some other code path violated that invariant. Abort loudly
// instead so a programming error in a caller is caught immediately
// rather than papered over by silently corrupting the supply counters.
// big.Int/wei: the comparison and subtraction are full-precision.
func TrackWithdrawal(asset string, amount *big.Int) {
	s := GetSupply(asset)
	if amount.Cmp(s.Active) > 0 || amount.Cmp(s.User) > 0 {
		sdk.Abort("supply underflow on TrackWithdrawal: amount " +
			amount.String() + " exceeds tracked supply for asset " + asset)
	}
	s.Active.Sub(s.Active, amount)
	s.User.Sub(s.User, amount)
	SetSupply(asset, s)
}

// TrackReserveSpend books an ETH-custody outflow paid from the gas reserve
// (the L1 mining fee for an ERC-20 withdrawal). The reserve is custody that
// is neither user- nor fee-attributed, so only Active("eth") moves; the
// reserve counter itself is maintained separately (deductGasReserve).
// F17-style: abort on underflow rather than clamp — the MinGasReserve floor
// check upstream should make this unreachable.
func TrackReserveSpend(gasCost *big.Int) {
	s := GetSupply("eth")
	if gasCost.Cmp(s.Active) > 0 {
		sdk.Abort("supply underflow on TrackReserveSpend: gas cost " +
			gasCost.String() + " exceeds tracked eth custody")
	}
	s.Active.Sub(s.Active, gasCost)
	SetSupply("eth", s)
}

// TrackReserveRestore reverses TrackReserveSpend for a withdrawal whose L1
// tx is PROVEN dropped (never mined): the reserve never actually paid the
// miner, so the custody debit taken optimistically at unmap is returned.
func TrackReserveRestore(gasCost *big.Int) {
	s := GetSupply("eth")
	s.Active.Add(s.Active, gasCost)
	SetSupply("eth", s)
}
