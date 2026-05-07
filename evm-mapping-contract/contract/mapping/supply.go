package mapping

import (
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
	"strconv"
	"strings"
)

type Supply struct {
	Active   int64 // total bridged
	User     int64 // credited to users
	Fee      int64 // protocol fees
	BaseFee  uint64 // latest base fee
}

func supplyKey(asset string) string {
	return constants.SupplyKey + constants.DirPathDelimiter + asset
}

func GetSupply(asset string) Supply {
	data := sdk.StateGetObject(supplyKey(asset))
	if data == nil {
		return Supply{}
	}
	fields := strings.Split(*data, "|")
	if len(fields) < 4 {
		return Supply{}
	}
	s := Supply{}
	s.Active, _ = strconv.ParseInt(fields[0], 10, 64)
	s.User, _ = strconv.ParseInt(fields[1], 10, 64)
	s.Fee, _ = strconv.ParseInt(fields[2], 10, 64)
	s.BaseFee, _ = strconv.ParseUint(fields[3], 10, 64)
	return s
}

func SetSupply(asset string, s Supply) {
	data := strconv.FormatInt(s.Active, 10) + "|" +
		strconv.FormatInt(s.User, 10) + "|" +
		strconv.FormatInt(s.Fee, 10) + "|" +
		strconv.FormatUint(s.BaseFee, 10)
	sdk.StateSetObject(supplyKey(asset), data)
}

func TrackDeposit(asset string, userAmount, feeAmount int64) {
	s := GetSupply(asset)
	s.Active += userAmount + feeAmount
	s.User += userAmount
	s.Fee += feeAmount
	SetSupply(asset, s)
}

// TrackWithdrawal subtracts amount from the tracked Active and
// User supply for an asset.
//
// Pentest finding F17: previously this function silently clamped
// negative results to 0:
//
//   if s.Active < 0 { s.Active = 0 }
//   if s.User   < 0 { s.User   = 0 }
//
// Every public withdrawal path validates the user's balance before
// reaching here, so the clamp could only fire if some other code
// path violated that invariant. That made it defense-in-depth
// against latent bugs — but instead of surfacing the bug at the
// call site, the helper would silently corrupt the supply counters.
// Abort loudly instead so a programming error in a caller is
// caught immediately rather than papered over.
func TrackWithdrawal(asset string, amount int64) {
	s := GetSupply(asset)
	if amount > s.Active || amount > s.User {
		sdk.Abort("supply underflow on TrackWithdrawal: amount " +
			strconv.FormatInt(amount, 10) + " exceeds tracked supply for asset " + asset)
	}
	s.Active -= amount
	s.User -= amount
	SetSupply(asset, s)
}
