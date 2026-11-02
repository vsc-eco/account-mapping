package mapping

import (
	"math/big"
	"strconv"
	"strings"

	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/sdk"
)

// maxWithdrawPerBlock is asset's per-Hive-block withdrawal cap: the owner's
// setting, else the default for the asset (decimals: 18 for ETH, the token's
// registered decimals). A zero cap means the limit is off.
func maxWithdrawPerBlock(asset string, decimals uint8) *big.Int {
	if s := sdk.StateGetObject(constants.MaxWithdrawPerBlockPrefix + asset); s != nil && *s != "" {
		if v, ok := new(big.Int).SetString(*s, 10); ok && v.Sign() >= 0 {
			return v
		}
	}
	if asset == constants.NativeAsset {
		v, _ := new(big.Int).SetString(constants.DefaultMaxWithdrawPerBlockETHWei, 10)
		return v
	}
	unit := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	return unit.Mul(unit, big.NewInt(constants.DefaultMaxWithdrawPerBlockTokens))
}

// checkAndUpdateWithdrawRateLimit charges debit against asset's cap for this
// Hive block and records it. An error refuses the withdrawal; the caller aborts,
// so the runtime reverts the whole transaction (the debit and this record
// included), as the BTC contract's checkAndUpdateUnmapRateLimit does.
func checkAndUpdateWithdrawRateLimit(blockHeight uint64, asset string, decimals uint8, debit *big.Int) error {
	limit := maxWithdrawPerBlock(asset, decimals)
	if limit.Sign() == 0 || debit == nil || debit.Sign() <= 0 {
		return nil
	}
	key := constants.WithdrawBlockAccPrefix + asset
	acc := new(big.Int)
	if s := sdk.StateGetObject(key); s != nil {
		if h, v, ok := strings.Cut(*s, ":"); ok && h == strconv.FormatUint(blockHeight, 10) {
			if prev, ok := new(big.Int).SetString(v, 10); ok {
				acc = prev
			}
		}
	}
	acc.Add(acc, debit)
	if acc.Cmp(limit) > 0 {
		return ce.NewContractError(ce.ErrIntent, "withdrawal rate limit: "+acc.String()+" "+asset+
			" this Hive block > cap "+limit.String()+" per block; try again next block")
	}
	sdk.StateSetObject(key, strconv.FormatUint(blockHeight, 10)+":"+acc.String())
	return nil
}

// SetMaxWithdrawPerBlock sets asset's cap (owner, through the operational
// timelock). 0 turns the limit off for that asset.
func SetMaxWithdrawPerBlock(asset string, limit *big.Int) {
	sdk.StateSetObject(constants.MaxWithdrawPerBlockPrefix+asset, limit.String())
}
