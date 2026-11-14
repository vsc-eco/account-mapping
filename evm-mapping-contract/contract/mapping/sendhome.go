package mapping

import (
	"math/big"
	"net/url"
	"strings"

	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

// sendhome.go: funds that land on an Ethereum address's own Magi account by
// default (a deposit with no usable instruction, an ERC-20 deposit, a deposit
// swap that did not run, a contract's withdrawal for a user that came back) are
// recorded as refundable. That account has no RC unless it holds HBD, so its
// owner may be unable to move them. sendHome, which anyone may call and pay the
// RC for, returns them to the address itself on Ethereum. The destination is the
// address and the amount is capped at what was recorded, so it moves nobody's
// funds anywhere else. A CEX withdrawal (no calldata) goes back to the address it
// came from, as a refund goes back to the sender on THORChain.

const evmDIDPrefix = "did:pkh:eip155:"

func refundableKey(account, asset string) string {
	return constants.RefundablePrefix + strings.ToLower(asset) + constants.DirPathDelimiter + account
}

func getRefundable(account, asset string) *big.Int {
	v := sdk.StateGetObject(refundableKey(account, asset))
	n := new(big.Int)
	if v == nil || *v == "" {
		return n
	}
	if _, ok := n.SetString(*v, 10); !ok || n.Sign() < 0 {
		return new(big.Int)
	}
	return n
}

func setRefundable(account, asset string, amount *big.Int) {
	if amount == nil || amount.Sign() <= 0 {
		sdk.StateDeleteObject(refundableKey(account, asset))
		return
	}
	sdk.StateSetObject(refundableKey(account, asset), amount.String())
}

// markRefundable records amount of asset on an Ethereum address's own account as
// returnable by sendHome. Other accounts (hive:, contracts) are left alone.
func markRefundable(account, asset string, amount *big.Int) {
	if amount == nil || amount.Sign() <= 0 || !strings.HasPrefix(account, evmDIDPrefix) {
		return
	}
	total := new(big.Int).Add(getRefundable(account, asset), amount)
	setRefundable(account, asset, total)
	sdk.Log("refundable|t=" + account + "|a=" + asset + "|d=" + amount.String())
}

// noteWithdrawalRefund marks a withdrawal that came back as refundable when
// sending it home changes nothing its owner chose: a contract withdrew for the
// account (a router settlement), or the withdrawal was to the account's own
// address anyway.
func noteWithdrawalRefund(from, to, account, asset string, amount *big.Int) {
	if !strings.HasPrefix(account, evmDIDPrefix) {
		return
	}
	own := strings.EqualFold(account[strings.LastIndex(account, ":")+1:], to)
	if strings.HasPrefix(from, "contract:") || own {
		markRefundable(account, asset, amount)
	}
}

// HandleSendHome returns an Ethereum address's refundable funds of one asset to
// that address. Input: "address=0x...&asset=eth" (or a token symbol).
func HandleSendHome(input string, vaultAddress [20]byte, chainId uint64) (string, error) {
	params, err := url.ParseQuery(input)
	if err != nil {
		return "", ce.NewContractError(ce.ErrInput, "sendHome input: address=0x...&asset=<eth|symbol>")
	}
	addr, err := crypto.HexToAddress(params.Get("address"))
	if err != nil || addr == ([20]byte{}) {
		return "", ce.NewContractError(ce.ErrInput, "sendHome needs an Ethereum address")
	}
	asset := strings.ToLower(strings.TrimSpace(params.Get("asset")))
	if asset == "" {
		asset = constants.NativeAsset
	}
	account := crypto.AddressToDID(addr)
	refundable := getRefundable(account, asset)
	if refundable.Sign() <= 0 {
		return "", ce.NewContractError(ce.ErrInput, "nothing refundable for "+account+" in "+asset)
	}
	bal := GetBalance(account, asset)
	avail := new(big.Int).Sub(bal, ProofFee(asset))
	amount := new(big.Int).Set(refundable)
	if avail.Cmp(amount) < 0 {
		amount.Set(avail)
	}
	if amount.Sign() <= 0 {
		return "", ce.NewContractError(ce.ErrBalance, "the refundable "+asset+" does not cover the proof fee")
	}
	to := crypto.AddressToHex(addr)
	var out string
	if asset == constants.NativeAsset {
		out, err = unmapETH(&TransferParams{Amount: amount.String(), To: to, DeductFee: true}, vaultAddress, chainId, account)
	} else {
		tokenAddr, _, ok := tokenBySymbol(chainId, asset)
		if !ok {
			return "", ErrInvalidToken
		}
		out, err = unmapERC20(&TransferParams{Amount: amount.String(), To: to, TokenAddress: crypto.AddressToHex(tokenAddr)}, vaultAddress, chainId, account)
	}
	if err != nil {
		return "", ce.Prepend(err, "sendHome")
	}
	after := GetBalance(account, asset)
	left := new(big.Int).Sub(refundable, new(big.Int).Sub(bal, after))
	if left.Cmp(after) > 0 {
		left.Set(after)
	}
	setRefundable(account, asset, left)
	sdk.Log("sendhome|t=" + to + "|a=" + asset + "|d=" + new(big.Int).Sub(bal, after).String())
	return out, nil
}
