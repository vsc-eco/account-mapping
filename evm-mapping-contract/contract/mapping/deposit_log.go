package mapping

import (
	"math/big"
	"strconv"
	"strings"

	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

// DEPOSIT-LOG-1 (owner 11-21: "altera isnt showing EVM transactions at all"):
// a credited deposit leaves no record that names its receiver, so a wallet
// cannot list it. The BTC bridge logs "map|t=<to>|f=<from>|a=<amount>" on
// every credit and the indexer turns that into btc_mapping_deposit_events;
// this is the same line with the asset and the Ethereum transaction's place
// added:
//
//	map|t=<credited Magi account>|f=<0x sender>|a=<amount, smallest units>|as=<asset>|bn=<L1 block>|ti=<tx index>
//
// The block and index, not a hash: the ERC-20 and MagiDeposit paths prove a
// receipt and key it by a receipt hash (proof.go, deposit_contract.go), not
// the transaction's hash; block + index name the same transaction exactly on
// every path.
//
// Written only where a deposit is credited to an account (the plain ETH, plain
// ERC-20 and MagiDeposit paths). A gas-reserve top-up credits nobody, and a
// deposit routed into a swap is recorded by the router's swap.
func logDepositCredit(to string, from [20]byte, amount *big.Int, asset string, l1Block, txIndex uint64) {
	// The identity as the balance is keyed (balanceKey: CanonicalIdentity), so
	// a lower-case or 0X-prefixed did:pkh:eip155 is listed under the account
	// it credited; a '|' or line break cannot add or shift fields.
	to = logField(crypto.CanonicalIdentity(to))
	sdk.Log("map|t=" + to + "|f=" + crypto.AddressToHex(from) + "|a=" + amount.String() +
		"|as=" + strings.ToLower(asset) + "|bn=" + strconv.FormatUint(l1Block, 10) +
		"|ti=" + strconv.FormatUint(txIndex, 10))
}

// logField keeps one value inside its field of a "|"-delimited log line.
func logField(v string) string {
	return strings.Map(func(r rune) rune {
		if r == '|' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, v)
}
