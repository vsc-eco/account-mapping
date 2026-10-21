package mapping

import (
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
	"math/big"
)

// parseAmount decodes a base-10 decimal string into a big.Int, returning a
// zero value (never nil) for empty/garbage input. State stores all monetary
// values as big.Int decimal strings (.String()), so this is the single
// decode path for balances, allowances, and the gas reserve.
func parseAmount(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return new(big.Int)
	}
	return v
}

// safeGasFee computes (gasFeeCap, fee) where
//
//	gasFeeCap = baseFeePerGas*multiplier + gasTipCap   (wei per gas, uint64)
//	fee       = gasUnits * gasFeeCap                    (total wei, *big.Int)
//
// rejecting every uint64 overflow in the per-gas cap. The total fee is a
// *big.Int so it composes with big.Int wei balances and CANNOT overflow —
// this structurally closes review2 HIGH #16 (the old int64 fee could wrap
// negative and inflate the user's balance instead of debiting it).
//
// gasFeeCap stays uint64 because it is an EIP-1559 per-gas price written
// directly into the RLP tx via rlp.EncodeUint64; real per-gas prices sit far
// below the uint64 ceiling, and the overflow checks below reject any input
// that would wrap it (which would otherwise sign an under-priced tx).
//
// multiplier is the base-fee headroom factor: the unmap paths use 2,
// replaceWithdrawal re-prices at 3. Pass gasUnits=0 when only the checked
// gasFeeCap is needed and no fee is charged (the fee return is then 0) —
// replaceWithdrawal does this because the gas reserve was already deducted
// at the original unmap.
func safeGasFee(gasUnits, baseFeePerGas, multiplier, gasTipCap uint64) (uint64, *big.Int, error) {
	scaled := baseFeePerGas * multiplier
	if baseFeePerGas != 0 && multiplier != 0 && scaled/multiplier != baseFeePerGas {
		return 0, nil, ce.NewContractError(ce.ErrArithmetic, "gas fee cap overflow")
	}
	gasFeeCap := scaled + gasTipCap
	if gasFeeCap < scaled {
		return 0, nil, ce.NewContractError(ce.ErrArithmetic, "gas fee cap overflow")
	}
	if gasUnits == 0 || gasFeeCap == 0 {
		return gasFeeCap, new(big.Int), nil
	}
	// big.Int product — exact, no overflow possible.
	fee := new(big.Int).Mul(new(big.Int).SetUint64(gasUnits), new(big.Int).SetUint64(gasFeeCap))
	return gasFeeCap, fee, nil
}

// review6 L1/X3 note: the SafeMul64 / SafeMulUint64 / computeGasFeeCap int64
// helpers this commit introduced are intentionally omitted on this base. Main
// already rebuilt all fee arithmetic on *big.Int (see safeGasFee above), which
// cannot overflow, so the int64 overflow guards the audit asked for are
// structurally unnecessary here.

// review6 L1/X3 5th-site note: HandleReplaceWithdrawal's 3x re-price (the
// site the audit's "four sites" list missed) routes through safeGasFee with
// multiplier=3, so the separate computeReplaceGasFeeCap helper from the
// adversarial-review commit is unnecessary on this base.

func balanceKey(address, asset string) string {
	return constants.BalancePrefix + crypto.CanonicalIdentity(address) + constants.DirPathDelimiter + asset
}

func allowanceKey(owner, spender, asset string) string {
	return constants.AllowancePrefix + crypto.CanonicalIdentity(owner) + constants.AllowanceDelimiter + crypto.CanonicalIdentity(spender) + constants.AllowanceDelimiter + asset
}

// GetBalance returns the caller's ledger balance in the asset's native unit
// (wei for "eth"). Always non-nil; absent/garbage state reads as zero.
func GetBalance(address, asset string) *big.Int {
	data := sdk.StateGetObject(balanceKey(address, asset))
	if data == nil {
		return new(big.Int)
	}
	return parseAmount(*data)
}

func SetBalance(address, asset string, amount *big.Int) {
	sdk.StateSetObject(balanceKey(address, asset), amount.String())
}

// IncBalance credits `amount` to the address's ledger balance. big.Int cannot
// overflow, so there is no failure mode and nothing to return.
func IncBalance(address, asset string, amount *big.Int) {
	bal := GetBalance(address, asset)
	bal.Add(bal, amount)
	SetBalance(address, asset, bal)
}

func DecBalance(address, asset string, amount *big.Int) bool {
	// CRIT #3: reject non-positive amount. Without this guard, a negative
	// amount drives `bal - amount` upward and SetBalance writes a credit —
	// free vault drain. Signature is bool (not (bool,error)) to preserve
	// every existing caller. Negative/zero amounts are programmer errors,
	// not user-recoverable conditions.
	if amount.Sign() <= 0 {
		return false
	}
	bal := GetBalance(address, asset)
	if bal.Cmp(amount) < 0 {
		return false
	}
	bal.Sub(bal, amount)
	SetBalance(address, asset, bal)
	return true
}

func GetAllowance(owner, spender, asset string) *big.Int {
	data := sdk.StateGetObject(allowanceKey(owner, spender, asset))
	if data == nil {
		return new(big.Int)
	}
	return parseAmount(*data)
}

func SetAllowance(owner, spender, asset string, amount *big.Int) {
	sdk.StateSetObject(allowanceKey(owner, spender, asset), amount.String())
}
