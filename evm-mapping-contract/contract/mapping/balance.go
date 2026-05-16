package mapping

import (
	"errors"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
	"math"
	"strconv"
)

func safeAdd64(a, b int64) (int64, error) {
	if a > 0 && b > math.MaxInt64-a {
		return 0, errors.New("overflow")
	}
	if a < 0 && b < math.MinInt64-a {
		return 0, errors.New("underflow")
	}
	return a + b, nil
}

// safeGasFee computes (gasFeeCap, fee) where
//   gasFeeCap = baseFeePerGas*2 + gasTipCap
//   fee       = gasUnits * gasFeeCap
// rejecting every uint64 add/mul overflow and the int64 truncation.
//
// review2 HIGH #16: this was `int64(gasUnits * (baseFeePerGas*2 +
// gasTipCap))` with no checks. A large baseFeePerGas made the uint64
// product exceed MaxInt64, the int64 cast wrapped NEGATIVE, and the
// negative fee inflated the user's balance instead of debiting it.
func safeGasFee(gasUnits, baseFeePerGas, gasTipCap uint64) (uint64, int64, error) {
	doubled := baseFeePerGas * 2
	if baseFeePerGas != 0 && doubled/2 != baseFeePerGas {
		return 0, 0, errors.New("gas fee cap overflow")
	}
	gasFeeCap := doubled + gasTipCap
	if gasFeeCap < doubled {
		return 0, 0, errors.New("gas fee cap overflow")
	}
	if gasUnits == 0 || gasFeeCap == 0 {
		return gasFeeCap, 0, nil
	}
	product := gasUnits * gasFeeCap
	if product/gasFeeCap != gasUnits {
		return 0, 0, errors.New("gas fee overflow")
	}
	if product > math.MaxInt64 {
		return 0, 0, errors.New("gas fee exceeds int64")
	}
	return gasFeeCap, int64(product), nil
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
