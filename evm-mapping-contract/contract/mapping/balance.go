package mapping

import (
	"errors"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
	"math"
	"strconv"
)

func safeCastGasFee(gas uint64, feeCap uint64) (int64, error) {
	product := gas * feeCap
	if feeCap != 0 && product/feeCap != gas {
		return 0, errors.New("gas fee overflow")
	}
	if product > uint64(math.MaxInt64) {
		return 0, errors.New("gas fee exceeds max int64")
	}
	return int64(product), nil
}

func safeAdd64(a, b int64) (int64, error) {
	if a > 0 && b > math.MaxInt64-a {
		return 0, errors.New("overflow")
	}
	if a < 0 && b < math.MinInt64-a {
		return 0, errors.New("underflow")
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
