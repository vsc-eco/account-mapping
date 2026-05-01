package mapping

import (
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/sdk"
	"math"
	"math/big"
	"strconv"
)

// safeMulAddU64 returns a*b + c, computed in big.Int and range-checked to uint64.
// Used for gasFeeCap = baseFeePerGas*multiplier + tipCap, where the intermediate
// product can wrap a native uint64 even when the final value fits.
func safeMulAddU64(a, b, c uint64) (uint64, error) {
	r := new(big.Int).Mul(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b))
	r.Add(r, new(big.Int).SetUint64(c))
	if !r.IsUint64() {
		return 0, ce.NewContractError(ce.ErrArithmetic, "uint64 overflow")
	}
	return r.Uint64(), nil
}

// safeMulU64ToI64 returns a*b, computed in big.Int and range-checked to int64.
// Gas fees must land as int64 because the balance ledger is int64.
func safeMulU64ToI64(a, b uint64) (int64, error) {
	r := new(big.Int).Mul(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b))
	if !r.IsInt64() {
		return 0, ce.NewContractError(ce.ErrArithmetic, "int64 overflow")
	}
	return r.Int64(), nil
}

func safeAdd64(a, b int64) (int64, error) {
	if a > 0 && b > math.MaxInt64-a {
		return 0, ce.NewContractError(ce.ErrArithmetic, "overflow")
	}
	if a < 0 && b < math.MinInt64-a {
		return 0, ce.NewContractError(ce.ErrArithmetic, "underflow")
	}
	return a + b, nil
}

func balanceKey(address, asset string) string {
	return constants.BalancePrefix + address + constants.DirPathDelimiter + asset
}

func allowanceKey(owner, spender, asset string) string {
	return constants.AllowancePrefix + owner + constants.DirPathDelimiter + spender + constants.DirPathDelimiter + asset
}

func GetBalance(address, asset string) int64 {
	data := sdk.StateGetObject(balanceKey(address, asset))
	if data == nil {
		return 0
	}
	v, err := strconv.ParseInt(*data, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func SetBalance(address, asset string, amount int64) {
	sdk.StateSetObject(balanceKey(address, asset), strconv.FormatInt(amount, 10))
}

func IncBalance(address, asset string, amount int64) error {
	bal := GetBalance(address, asset)
	newBal, err := safeAdd64(bal, amount)
	if err != nil {
		return err
	}
	SetBalance(address, asset, newBal)
	return nil
}

func DecBalance(address, asset string, amount int64) bool {
	bal := GetBalance(address, asset)
	if bal < amount {
		return false
	}
	SetBalance(address, asset, bal-amount)
	return true
}

func GetAllowance(owner, spender, asset string) int64 {
	data := sdk.StateGetObject(allowanceKey(owner, spender, asset))
	if data == nil {
		return 0
	}
	v, err := strconv.ParseInt(*data, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func SetAllowance(owner, spender, asset string, amount int64) {
	sdk.StateSetObject(allowanceKey(owner, spender, asset), strconv.FormatInt(amount, 10))
}
