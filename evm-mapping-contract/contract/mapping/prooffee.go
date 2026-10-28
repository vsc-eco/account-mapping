package mapping

import (
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"

	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/sdk"
)

// ProofFee is asset's proving fee in its smallest unit, 0 when unset.
func ProofFee(asset string) *big.Int {
	if v := sdk.StateGetObject(constants.ProofFeePrefix + asset); v != nil {
		if n, ok := new(big.Int).SetString(*v, 10); ok && n.Sign() > 0 {
			return n
		}
	}
	return new(big.Int)
}

// SetProofFee sets asset's proving fee; 0 removes it.
func SetProofFee(asset string, fee *big.Int) {
	if fee.Sign() <= 0 {
		sdk.StateDeleteObject(constants.ProofFeePrefix + asset)
		return
	}
	sdk.StateSetObject(constants.ProofFeePrefix+asset, fee.String())
}

// MaxProofFee is the highest proving fee setProofFee takes for an asset: half
// its smallest creditable deposit, so a deposit at the floor still credits its
// sender most of it.
func MaxProofFee(minDeposit *big.Int) *big.Int {
	return new(big.Int).Div(minDeposit, big.NewInt(2))
}

// takeDepositProofFee pays the proving fee out of a deposit's credit to
// ProofFeeRecipient and returns what is left for the depositor (all of it
// when the credit is smaller than the fee). Supply is unchanged: the
// recipient's balance is user supply like any other.
func takeDepositProofFee(asset string, credit *big.Int) *big.Int {
	fee := ProofFee(asset)
	if fee.Cmp(credit) > 0 {
		fee.Set(credit)
	}
	if fee.Sign() > 0 {
		IncBalance(constants.ProofFeeRecipient, asset, fee)
		sdk.Log("prooffee|deposit|a=" + asset + "|s=" + fee.String())
	}
	return new(big.Int).Sub(credit, fee)
}

// chargeWithdrawalProofFee moves asset's proving fee from payer to
// ProofFeeRecipient (a Magi transfer; supply is unchanged). The caller checks
// beforehand that payer holds it on top of the withdrawal's debit. It is not
// refunded if the withdrawal is later refunded or cancelled.
func chargeWithdrawalProofFee(payer, asset string, fee *big.Int) error {
	if fee.Sign() <= 0 {
		return nil
	}
	if !DecBalance(payer, asset, fee) {
		return ce.NewContractError(ce.ErrBalance, "insufficient balance for the proving fee")
	}
	IncBalance(constants.ProofFeeRecipient, asset, fee)
	sdk.Log("prooffee|withdrawal|f=" + payer + "|a=" + asset + "|s=" + fee.String())
	return nil
}

// ProofFeeFloor is the smallest creditable deposit of asset ("eth" or a
// registered token's symbol), which bounds its proving fee; nil for an asset
// the bridge does not hold.
func ProofFeeFloor(asset string) *big.Int {
	if asset == constants.NativeAsset {
		return big.NewInt(constants.MinETHDeposit)
	}
	ref := sdk.StateGetObject(constants.TokenSymbolPrefix + asset)
	if ref == nil {
		return nil
	}
	parts := strings.SplitN(*ref, constants.DirPathDelimiter, 2)
	if len(parts) != 2 {
		return nil
	}
	chainId, err := strconv.ParseUint(parts[0], 10, 64)
	raw, herr := hex.DecodeString(parts[1])
	if err != nil || herr != nil || len(raw) != 20 {
		return nil
	}
	var addr [20]byte
	copy(addr[:], raw)
	info := getTokenInfo(chainId, addr)
	if info == nil || info.Symbol != asset {
		return nil
	}
	return big.NewInt(info.MinDeposit())
}
