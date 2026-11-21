package mapping

import (
	"math/big"
	"net/url"
	"slices"
	"strconv"
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

// refundableKey uses the asset exactly as the ledger does: token symbols are
// case-sensitive (a token registered as USDC has its balance under USDC).
func refundableKey(account, asset string) string {
	return constants.RefundablePrefix + asset + constants.DirPathDelimiter + account
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

// owedHomeKey is the owed-home record of an account's asset.
func owedHomeKey(account, asset string) string {
	return constants.OwedHomePrefix + asset + constants.DirPathDelimiter + account
}

func getOwedHome(account, asset string) *big.Int {
	v := sdk.StateGetObject(owedHomeKey(account, asset))
	n := new(big.Int)
	if v == nil || *v == "" {
		return n
	}
	if _, ok := n.SetString(*v, 10); !ok || n.Sign() < 0 {
		return new(big.Int)
	}
	return n
}

// owedHomeSendable is the least owed amount listed for the bot: more than its
// proving fee (less can never be sent: it is fee, keepOwedDust). The payout's
// gas comes out of the rest when it is sent; while the gas price leaves too
// little, the bot's dry run fails and it waits.
func owedHomeSendable(asset string) *big.Int {
	if asset != constants.NativeAsset {
		if info, _ := TokenBySymbol(asset); info == nil {
			return nil
		}
	}
	// More than its proving fee: the payout's gas comes out of the rest when it
	// is sent (the keeper's dry run waits out a gas price it cannot cover).
	return new(big.Int).Add(ProofFee(asset), big.NewInt(1))
}

// setOwedHome writes the record and keeps the bot's list in step with it.
func setOwedHome(account, asset string, amount *big.Int) {
	entry := asset + "|" + account
	list := owedHomeList()
	at := -1
	for i, e := range list {
		if e == entry {
			at = i
			break
		}
	}
	listed := owedHomeListable(account, asset, amount)
	queued := sdk.StateGetObject(constants.OwedHomeQueuedMarkPrefix+entry) != nil
	if amount == nil || amount.Sign() <= 0 {
		sdk.StateDeleteObject(owedHomeKey(account, asset))
	} else {
		sdk.StateSetObject(owedHomeKey(account, asset), amount.String())
	}
	switch {
	case !listed && at >= 0:
		list = append(list[:at], list[at+1:]...)
		setOwedHomeList(refillOwedHomeList(list))
	case listed && at < 0 && !queued:
		// Sendable and in neither the list nor the overflow: listed, or queued
		// while the list is full.
		if len(list) < constants.MaxOwedHomeList {
			setOwedHomeList(append(list, entry))
		} else {
			pushOwedHomeOverflow(entry)
		}
	}
}

func overflowBound(key string) uint64 {
	if v := sdk.StateGetObject(key); v != nil {
		n, _ := strconv.ParseUint(*v, 10, 64)
		return n
	}
	return 0
}

// pushOwedHomeOverflow queues an entry that found the bot's list full.
func pushOwedHomeOverflow(entry string) {
	tail := overflowBound(constants.OwedHomeOverflowTailKey)
	sdk.StateSetObject(constants.OwedHomeOverflowPrefix+strconv.FormatUint(tail, 10), entry)
	sdk.StateSetObject(constants.OwedHomeOverflowTailKey, strconv.FormatUint(tail+1, 10))
	sdk.StateSetObject(constants.OwedHomeQueuedMarkPrefix+entry, "1")
	sdk.Log("owedhome|queued|e=" + entry)
}

// refillOwedHomeList moves queued entries into the list while it has room, at
// most OwedHomeRefillPerExit per call, dropping any no longer sendable (sent
// home, pruned) or already listed.
func refillOwedHomeList(list []string) []string {
	head, tail := overflowBound(constants.OwedHomeOverflowHeadKey), overflowBound(constants.OwedHomeOverflowTailKey)
	moved := 0
	for head < tail && len(list) < constants.MaxOwedHomeList && moved < constants.OwedHomeRefillPerExit {
		key := constants.OwedHomeOverflowPrefix + strconv.FormatUint(head, 10)
		head++
		moved++
		v := sdk.StateGetObject(key)
		sdk.StateDeleteObject(key)
		if v == nil {
			continue
		}
		sdk.StateDeleteObject(constants.OwedHomeQueuedMarkPrefix + *v)
		asset, account, ok := strings.Cut(*v, "|")
		if !ok || slices.Contains(list, *v) {
			continue
		}
		if !owedHomeListable(account, asset, getOwedHome(account, asset)) {
			continue
		}
		list = append(list, *v)
	}
	if moved > 0 {
		if head >= tail {
			sdk.StateDeleteObject(constants.OwedHomeOverflowHeadKey)
			sdk.StateDeleteObject(constants.OwedHomeOverflowTailKey)
		} else {
			sdk.StateSetObject(constants.OwedHomeOverflowHeadKey, strconv.FormatUint(head, 10))
		}
	}
	return list
}

func owedHomeList() []string {
	s := sdk.StateGetObject(constants.OwedHomeListKey)
	if s == nil || *s == "" {
		return nil
	}
	return strings.Split(*s, ",")
}

func setOwedHomeList(l []string) {
	if len(l) == 0 {
		sdk.StateDeleteObject(constants.OwedHomeListKey)
		return
	}
	sdk.StateSetObject(constants.OwedHomeListKey, strings.Join(l, ","))
}

// owedHomeListable reports whether an owed record belongs on the bot's list:
// it can go out alone (at least the minimum withdrawal plus the proof fee) and
// its sends have not kept reverting.
func owedHomeListable(account, asset string, amount *big.Int) bool {
	sendable := owedHomeSendable(asset)
	return amount != nil && sendable != nil && amount.Cmp(sendable) >= 0 &&
		owedHomeReverts(account, asset) < constants.MaxOwedHomeReverts
}

func owedHomeRevertKey(account, asset string) string {
	return constants.OwedHomeRevertPrefix + asset + constants.DirPathDelimiter + account
}

func owedHomeReverts(account, asset string) uint64 {
	return payoutReturnCounter(owedHomeRevertKey(account, asset))
}

// resetOwedHomeReverts clears an address's revert count when a new failed swap
// owes it something: the address may accept it now, so the bot tries again.
func resetOwedHomeReverts(account, asset string) {
	sdk.StateDeleteObject(owedHomeRevertKey(account, asset))
}

// recordOwedHome records amount of asset as owed home to an Ethereum address:
// a swap its sender asked for did not complete (or its payout came back), so
// the bot sends it back to the address (THORChain's refundTx: a failed swap
// goes back to its sender on its own chain). The value itself is held on
// OwedHomeHoldAccount (holdOwedHome, or the deposit credit), never on the
// address's Magi balance (owner 11-21: a failure goes to the sender or the
// recipient only).
func recordOwedHome(account, asset string, amount *big.Int) {
	total := new(big.Int).Add(getOwedHome(account, asset), amount)
	sdk.Log("owedhome|t=" + account + "|a=" + asset + "|d=" + amount.String())
	if total.Cmp(ProofFee(asset)) <= 0 {
		keepOwedDust(account, asset, total)
		return
	}
	setOwedHome(account, asset, total)
}

// keepOwedDust takes an owed amount that cannot pay its own proving fee off
// the hold (THORChain: a refund below its outbound fee is not sent): ETH to the
// gas reserve, a token to the token gas fee account that pays for its gas.
func keepOwedDust(account, asset string, amount *big.Int) {
	setOwedHome(account, asset, new(big.Int))
	if amount.Sign() <= 0 || !DecBalance(constants.OwedHomeHoldAccount, asset, amount) {
		return
	}
	if asset == constants.NativeAsset {
		sup := GetSupply(asset)
		sup.User.Sub(sup.User, amount)
		SetSupply(asset, sup)
		addGasReserve(amount)
	} else {
		IncBalance(constants.TokenGasFeeRecipient, asset, amount)
	}
	sdk.Log("owedhome|dust|t=" + account + "|a=" + asset + "|d=" + amount.String())
}

// holdOwedHome holds amount for an Ethereum address and records it owed home.
func holdOwedHome(account, asset string, amount *big.Int) {
	if amount == nil || amount.Sign() <= 0 {
		return
	}
	IncBalance(constants.OwedHomeHoldAccount, asset, amount)
	recordOwedHome(account, asset, amount)
}

// creditWithdrawalRefund puts a withdrawal that came back where it belongs: an
// Ethereum address's swap payout (a contract withdrew for it) or owed send
// (from the hold) is held and owed home again, never credited to its Magi
// balance; anything else is credited to the account that paid it (a Magi
// sender's own withdrawal), and marked refundable when it was to the
// account's own address.
func creditWithdrawalRefund(from, to, account, asset string, amount *big.Int, reverted bool) {
	if strings.HasPrefix(account, evmDIDPrefix) && (strings.HasPrefix(from, "contract:") || from == constants.OwedHomeHoldAccount) {
		// Only a send home that mined and reverted (the address refused it)
		// counts toward MaxOwedHomeReverts; a cancel, a roll or the queue's
		// refusal is not the address's doing.
		if from == constants.OwedHomeHoldAccount && reverted {
			n := owedHomeReverts(account, asset) + 1
			sdk.StateSetObject(owedHomeRevertKey(account, asset), strconv.FormatUint(n, 10))
			sdk.Log("owedhome|reverted|t=" + account + "|a=" + asset + "|n=" + strconv.FormatUint(n, 10))
		} else if from != constants.OwedHomeHoldAccount {
			resetOwedHomeReverts(account, asset) // a new failure, not our own send's
		}
		holdOwedHome(account, asset, amount)
		return
	}
	IncBalance(account, asset, amount)
	noteWithdrawalRefund(from, to, account, asset, amount)
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
	if own {
		markRefundable(account, asset, amount)
	}
}

// HandleSendHome returns an Ethereum address's refundable funds of one asset to
// that address. Input: "address=0x...&asset=eth" (or a token symbol), plus
// "&owed=1" to send only what a swap owes home (the bot's keeper).
func HandleSendHome(input string, vaultAddress [20]byte, chainId uint64) (string, error) {
	params, err := url.ParseQuery(input)
	if err != nil {
		return "", ce.NewContractError(ce.ErrInput, "sendHome input: address=0x...&asset=<eth|symbol>")
	}
	addr, err := crypto.HexToAddress(params.Get("address"))
	if err != nil || addr == ([20]byte{}) {
		return "", ce.NewContractError(ce.ErrInput, "sendHome needs an Ethereum address")
	}
	// ETH in any case; a token by its registered symbol, exactly (the ledger's
	// balance keys and the token index are case-sensitive).
	asset := strings.TrimSpace(params.Get("asset"))
	if asset == "" || strings.EqualFold(asset, constants.NativeAsset) {
		asset = constants.NativeAsset
	}
	account := crypto.AddressToDID(addr)
	if params.Get("owed") == "1" {
		// Only the bridge's bot (a registered relayer) or the address itself
		// sends an owed refund: the caller picks its gas_limit, which the refund
		// pays, so a stranger must not (burning it, or a limit too low for a
		// contract wallet to accept it).
		if c := sdk.GetEnv().Caller.String(); !IsWhitelistedRelayer(c) && !crypto.SameIdentity(c, account) {
			return "", ce.NewContractError(ce.ErrNoPermission, "an owed refund is sent by the bridge's bot or by its address")
		}
		// gas_limit (ETH): what the address needs to receive (a contract wallet
		// needs more than a transfer); at most MaxPayoutGasLimit (unmapETH).
		var gasLimit uint64
		if g := params.Get("gas_limit"); g != "" {
			if gasLimit, err = strconv.ParseUint(g, 10, 64); err != nil || asset != constants.NativeAsset {
				return "", ce.NewContractError(ce.ErrInput, "gas_limit is a whole number of gas units, for ETH")
			}
		}
		return sendOwedHome(account, addr, asset, gasLimit, vaultAddress, chainId)
	}
	recorded := getRefundable(account, asset)
	refundable := recorded
	bal := GetBalance(account, asset)
	if refundable.Sign() <= 0 {
		return "", ce.NewContractError(ce.ErrInput, "nothing refundable for "+account+" in "+asset)
	}
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
		out, err = unmapETH(&TransferParams{Amount: amount.String(), To: to, DeductFee: true}, vaultAddress, chainId, account, false)
	} else {
		tokenAddr, _, ok := tokenBySymbol(chainId, asset)
		if !ok {
			return "", ErrInvalidToken
		}
		out, err = unmapERC20(&TransferParams{Amount: amount.String(), To: to, TokenAddress: crypto.AddressToHex(tokenAddr)}, vaultAddress, chainId, account, false)
	}
	if err != nil {
		return "", ce.Prepend(err, "sendHome")
	}
	// Both records go down by what left the account (the amount and its proof
	// fee) and never stay above what is still there.
	after := GetBalance(account, asset)
	debited := new(big.Int).Sub(bal, after)
	if recorded.Sign() > 0 {
		left := new(big.Int).Sub(recorded, debited)
		if left.Cmp(after) > 0 {
			left.Set(after)
		}
		setRefundable(account, asset, left)
	}
	sdk.Log("sendhome|t=" + to + "|a=" + asset + "|d=" + new(big.Int).Sub(bal, after).String())
	return out, nil
}

// sendOwedHome sends what is owed home to an Ethereum address from the hold,
// all of it, as a payout (the expected fee out of the amount, nothing refunded
// on Magi). If it reverts it comes back to the hold, owed again
// (creditWithdrawalRefund). Below what can go out alone it stays held until
// more is owed.
func sendOwedHome(account string, addr [20]byte, asset string, gasLimit uint64, vaultAddress [20]byte, chainId uint64) (string, error) {
	owed := getOwedHome(account, asset)
	if owed.Sign() <= 0 {
		return "", ce.NewContractError(ce.ErrInput, "nothing owed home to "+account+" in "+asset)
	}
	if sendable := owedHomeSendable(asset); sendable == nil || owed.Cmp(sendable) < 0 {
		// Below what can go out alone (the minimum or the proof fee was raised
		// since it was listed): kept held and taken off the bot's list, so dead
		// entries cannot fill it. Not an error, or the delisting would revert.
		setOwedHome(account, asset, owed)
		sdk.Log("owedhome|delisted|t=" + account + "|a=" + asset + "|d=" + owed.String())
		return "held: below what can be sent alone", nil
	}
	if GetBalance(constants.OwedHomeHoldAccount, asset).Cmp(owed) < 0 {
		return "", ce.NewContractError(ce.ErrStateAccess, "the owed-home hold does not cover "+account)
	}
	send := new(big.Int).Sub(owed, ProofFee(asset))
	to := crypto.AddressToHex(addr)
	var out string
	var err error
	if asset == constants.NativeAsset {
		out, err = unmapETH(&TransferParams{Amount: send.String(), To: to, DeductFee: true, RefundTo: account, GasLimit: gasLimit}, vaultAddress, chainId, constants.OwedHomeHoldAccount, true)
	} else {
		tokenAddr, _, ok := tokenBySymbol(chainId, asset)
		if !ok {
			return "", ErrInvalidToken
		}
		out, err = unmapERC20(&TransferParams{Amount: send.String(), To: to, TokenAddress: crypto.AddressToHex(tokenAddr), RefundTo: account}, vaultAddress, chainId, constants.OwedHomeHoldAccount, true)
	}
	if err != nil {
		return "", ce.Prepend(err, "sendHome")
	}
	// Sent now or not at all: a queued send refused at the drain would come
	// back less its proving fee, again on every try. Refused (nothing charged),
	// it stays held and the bot tries again.
	if strings.HasPrefix(out, "queued:") {
		return "", ce.NewContractError(ce.ErrIntent, "the bridge cannot send it now; it stays held and is sent later")
	}
	setOwedHome(account, asset, new(big.Int))
	sdk.Log("sendhome|t=" + to + "|a=" + asset + "|d=" + owed.String() + "|owed=1")
	return out, nil
}
