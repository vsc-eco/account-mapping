package mapping

import (
	"encoding/binary"
	"math/big"

	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/sdk"
)

// withdrawAccLen is the fixed width of an asset's per-block accumulator: an
// 8-byte Hive block height and a 32-byte amount, big-endian. The BTC contract
// keeps its accumulator at a fixed 16 bytes (sats fit 8) for the same reason:
// a state write is charged by the bytes it adds to the contract, so a value
// that never changes length costs a withdrawal only its read, never a growth
// charge. The key is created by initContract (ETH) and registerToken (each
// token), paid by the deployer and owner; on a bridge deployed before this, the
// first withdrawal of each asset creates it once.
const withdrawAccLen = 8 + 32

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

// loadWithdrawAccumulator returns the block height and amount stored for
// asset; an absent or malformed value reads as block 0, nothing debited.
func loadWithdrawAccumulator(asset string) (uint64, *big.Int) {
	s := sdk.StateGetObject(constants.WithdrawBlockAccPrefix + asset)
	if s == nil || len(*s) != withdrawAccLen {
		return 0, new(big.Int)
	}
	b := []byte(*s)
	return binary.BigEndian.Uint64(b[:8]), new(big.Int).SetBytes(b[8:])
}

// saveWithdrawAccumulator stores asset's accumulator at its fixed width. acc
// is at most the asset's cap, which setMaxWithdrawPerBlock keeps below 2^256.
func saveWithdrawAccumulator(asset string, height uint64, acc *big.Int) {
	var b [withdrawAccLen]byte
	binary.BigEndian.PutUint64(b[:8], height)
	acc.FillBytes(b[8:])
	sdk.StateSetObject(constants.WithdrawBlockAccPrefix+asset, string(b[:]))
}

// EnsureWithdrawAccumulator creates asset's accumulator (block 0, nothing
// debited) when it has none, so no user withdrawal pays to create it. An
// existing one is left as it is: re-registering a token mid-block must not
// reset what that block has already debited.
func EnsureWithdrawAccumulator(asset string) {
	if s := sdk.StateGetObject(constants.WithdrawBlockAccPrefix + asset); s == nil {
		saveWithdrawAccumulator(asset, 0, new(big.Int))
	}
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
	height, acc := loadWithdrawAccumulator(asset)
	if height != blockHeight {
		acc.SetInt64(0) // a different Hive block: nothing debited yet in this one
	}
	acc.Add(acc, debit)
	if acc.Cmp(limit) > 0 {
		return ce.NewContractError(ce.ErrIntent, "withdrawal rate limit: "+acc.String()+" "+asset+
			" this Hive block > cap "+limit.String()+" per block; try again next block")
	}
	saveWithdrawAccumulator(asset, blockHeight, acc)
	return nil
}

// MaxWithdrawPerBlockBits bounds a cap so the accumulator's 32-byte amount
// always holds it.
const MaxWithdrawPerBlockBits = 256

// SetMaxWithdrawPerBlock sets asset's cap (owner, through the operational
// timelock). 0 turns the limit off for that asset.
func SetMaxWithdrawPerBlock(asset string, limit *big.Int) {
	sdk.StateSetObject(constants.MaxWithdrawPerBlockPrefix+asset, limit.String())
}
