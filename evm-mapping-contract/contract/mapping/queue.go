package mapping

import (
	"encoding/hex"
	"errors"
	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
	"math/big"
	"strconv"
	"strings"
)

// RP-11: a withdrawal request is validated and debited by the unmap handlers,
// then submitted here. With nothing queued, fewer than MaxInFlightWithdrawals
// in flight and a fresh pricing header, it is issued (priced, given the next
// vault nonce, TSS-signed) in the same call; otherwise it waits in the L2
// queue. Nothing about another user's withdrawal can make a request fail.
//
// Queued withdrawals are issued only by the permissionless
// drainWithdrawalQueue (the bot calls it whenever the queue is non-empty and a
// slot is free). Never by an unmap, confirmSpend or an escape hatch: each issue
// costs ~10-12k RC on the node's runtime, and a call that issued other users'
// withdrawals could exceed its caller's rc_limit and fail (a confirmSpend
// failing that way would stall the queue head).

// submitWithdrawal queues q and drains. It returns "issued:{nonce}" when q went
// straight into flight, else "queued:{seq}".
// vault is the vault the unmap handler was given (main passes vault(), the TSS
// key's verified address; zero when there is none, and then nothing issues).
func submitWithdrawal(q QueuedWithdrawal, vault [20]byte, chainId uint64) (string, error) {
	// P2 (BTC-C3): every unmap path (ETH, ERC-20, unmapFrom) has debited the
	// owner just before this call; charge that debit against the asset's
	// per-Hive-block cap, as the BTC contract charges each unmap at its debit.
	debit := q.Debit
	if debit == nil {
		debit = q.Amount
	}
	decimals := uint8(18)
	if q.Asset != constants.NativeAsset {
		if addr, err := crypto.HexToAddress(q.TokenAddress); err == nil {
			if info := getTokenInfo(chainId, addr); info != nil {
				decimals = info.Decimals
			}
		}
	}
	if err := checkAndUpdateWithdrawRateLimit(sdk.GetEnv().BlockHeight, q.Asset, decimals, debit); err != nil {
		return "", err
	}
	next := GetPendingNonce()
	// Nothing waiting: issue now, without writing a queue entry that the same
	// call would delete (a state write costs RC even when it is undone).
	if QueueLen() == 0 {
		if header := issuableNow(vault); header != nil {
			switch out, why := issueQueued(&q, vault, chainId, header, false); out {
			case queueIssued:
				return "issued:" + strconv.FormatUint(next, 10), nil
			case queueRefund:
				// Its own terms cannot pay it now (max_fee, a fee the amount does
				// not cover): refused here, so the caller gets it back at once (a
				// router refunds the swap's sender), not after a queue round trip.
				return "", ce.NewContractError(ce.ErrIntent, why)
			}
		}
	}
	if QueuedLive() >= constants.MaxQueuedWithdrawals {
		return "", ce.NewContractError(ce.ErrIntent, "withdrawal queue is full; try again later")
	}
	if queuedBy(q.refundAccount()) >= constants.MaxQueuedPerAccount {
		return "", ce.NewContractError(ce.ErrIntent, "you have "+strconv.FormatUint(constants.MaxQueuedPerAccount, 10)+
			" withdrawals queued; wait for them to go out (or cancel one) before queuing another")
	}
	seq := Enqueue(q)
	logQueued(seq, &q)
	return "queued:" + strconv.FormatUint(seq, 10), nil
}

// payoutGasFee is what a payout pays for gas units: units x (1.5 x base fee +
// tip), THORChain's outbound fee (GetAssetOutboundFee: the observed gas rate x
// a multiplier, 1.5 at its floor). The transaction is still signed at 2 x base
// fee + tip so it is included; the gas reserve fronts the difference and gets
// back whatever is not burned. Nothing is refunded to the user.
func payoutGasFee(units, baseFee, tip uint64) *big.Int {
	price := new(big.Int).SetUint64(baseFee)
	price.Mul(price, big.NewInt(constants.PayoutBaseFeePct))
	price.Div(price, big.NewInt(100))
	price.Add(price, new(big.Int).SetUint64(tip))
	return price.Mul(price, new(big.Int).SetUint64(units))
}

// payoutTokenGas is the gas a token payout is charged for: an ERC-20 transfer
// (ERC20TransferGas), or the token's registered limit when that is lower. A
// token transfer runs no code of the recipient's, so it cannot burn more.
func payoutTokenGas(registered uint64) uint64 {
	return min(TokenGasLimit(registered), constants.ERC20TransferGas)
}

// DrainWithdrawalQueue moves up to max queued withdrawals into flight, oldest
// first, while fewer than MaxInFlightWithdrawals are in flight. It never fails
// the calling transaction: when it cannot issue (paused, no active TSS key or
// verified vault, stale pricing header, the gas reserve too low at the current
// price) the entries stay queued and it returns.
//
// QFREEZE-1: an entry its own terms cannot pay at the current (fresh) price —
// the ETH fee above its cap or above a netted amount, an ERC-20 transfer's gas
// above its max_fee — is refunded to its owner in full and removed, as the BTC
// mapping contract's drain refunds a queued withdrawal it cannot pay at the
// current fee rate (unmap_queue.go drainUnmapQueue). It used to stay at the
// head: 32 such entries (max_fee 1 wei, queued while no fresh pricing header
// existed) took every drain's MaxDrainScan budget and froze all withdrawals.
func DrainWithdrawalQueue(chainId uint64, max int) int {
	StepQueuedDebitRecount()
	vault, ok := TssVaultAddress()
	if !ok {
		return 0
	}
	return drainWith(chainId, vault, max)
}

// issuableNow is the pricing header to issue a withdrawal with now, or nil
// when none can be issued (no vault, paused, MaxInFlightWithdrawals in flight,
// a superseded generation's in-flight withdrawals still holding the nonces, no
// active TSS key, no fresh pricing header).
func issuableNow(vault [20]byte) *blocklist.EthBlockHeader {
	if vault == ([20]byte{}) || isPaused() || InFlightWithdrawals() >= constants.MaxInFlightWithdrawals {
		return nil
	}
	if withdrawalNoncesHeld() {
		return nil
	}
	if requireTssKey() != nil {
		return nil
	}
	header, err := pricingHeader()
	if err != nil {
		return nil
	}
	return header
}

// immediateETHFee is what an ETH withdrawal of gas units is charged if it is
// issued in this call (nothing queued and issuableNow), else nil. An unmap
// then debits exactly this fee instead of its cap, so nothing is refunded.
func immediateETHFee(gas uint64, vault [20]byte) *big.Int {
	if QueueLen() != 0 {
		return nil
	}
	header := issuableNow(vault)
	if header == nil {
		return nil
	}
	_, fee, err := safeGasFee(gas, header.BaseFeePerGas, 2, 2_000_000_000)
	if err != nil {
		return nil
	}
	return fee
}

// payoutETHFee is what an ETH payout of gas units pays if it is issued in this
// call (payoutGasFee, never above the signed maximum), else nil (it is then
// queued with its cap and priced at issue).
func payoutETHFee(gas uint64, vault [20]byte) *big.Int {
	header := issuableNow(vault)
	if header == nil {
		return nil
	}
	_, maxWei, err := safeGasFee(gas, header.BaseFeePerGas, 2, 2_000_000_000)
	if err != nil {
		return nil
	}
	return minBig(payoutGasFee(gas, header.BaseFeePerGas, 2_000_000_000), maxWei)
}

// PayoutGasFee is what a payout of asset ("eth" or a registered token's
// symbol) pays for gas if it is issued now, in the asset's base units: what a
// wallet shows as the network fee of a swap paid out on Ethereum (getInfo
// "fees"). An ETH payout is priced at gasLimit, the per-payout gas_limit the
// wallet will send (0: the bridge's default, what a payout without one uses).
// nil without a fresh L1 header (a payout is refused then), for an unknown
// asset, or for a gas_limit a payout may not ask for.
func PayoutGasFee(asset string, gasLimit uint64) *big.Int {
	header, err := pricingHeader()
	if err != nil {
		return nil
	}
	if asset == constants.NativeAsset {
		gas, gerr := ethGasLimit(gasLimit)
		if gerr != nil || gas > constants.MaxPayoutGasLimit && gasLimit != 0 {
			return nil
		}
		_, maxWei, ferr := safeGasFee(gas, header.BaseFeePerGas, 2, 2_000_000_000)
		if ferr != nil {
			return nil
		}
		return minBig(payoutGasFee(gas, header.BaseFeePerGas, 2_000_000_000), maxWei)
	}
	info, _ := TokenBySymbol(asset)
	if info == nil {
		return nil
	}
	_, maxWei, ferr := safeGasFee(TokenGasLimit(info.GasLimit), header.BaseFeePerGas, 2, 2_000_000_000)
	if ferr != nil {
		return nil
	}
	gasWei := minBig(payoutGasFee(payoutTokenGas(info.GasLimit), header.BaseFeePerGas, 2_000_000_000), maxWei)
	return tokenGasFee(asset, gasWei, info.MinWithdrawal)
}

// isPayout reports whether a withdrawal is a payout (see
// QueuedWithdrawal.Payout): requested by a contract, or the bot's sendHome of
// what a swap owes home (owedHome). A plain sendHome (anyone may make one for a
// deposit that fell back to its sender) keeps the user-withdrawal terms: it is
// paid from the depositor's account, which a stranger must not be able to
// charge a no-refund fee.
//
// home is the account a sendHome debits: a contract that calls sendHome does
// not make that account's withdrawal its own payout.
func isPayout(env sdk.Env, home string, owedHome bool) bool {
	return owedHome || home == constants.PayoutReturnHoldAccount || (home == "" && strings.HasPrefix(env.Caller.String(), "contract:"))
}

// scaleReturnMin is q's ReturnMin for a refund of sent (what the L1 transaction
// carries, after a netted fee): the floor scales with the value.
func scaleReturnMin(q *QueuedWithdrawal, sent *big.Int) *big.Int {
	if q.ReturnMin == nil || q.ReturnMin.Sign() <= 0 || q.Amount == nil || q.Amount.Sign() <= 0 {
		return nil
	}
	m := new(big.Int).Mul(q.ReturnMin, sent)
	m.Div(m, q.Amount)
	if m.Sign() <= 0 {
		m.SetInt64(1) // a floor never scales away to none
	}
	return m
}

// drainWith is DrainWithdrawalQueue against a given vault address.
func drainWith(chainId uint64, vault [20]byte, max int) int {
	if QueueLen() == 0 {
		return 0
	}
	header := issuableNow(vault)
	if header == nil {
		return 0
	}
	advanceQueueHead()
	head, tail := QueueBounds()
	issued, scanned := 0, uint64(0)
	// Bounded in slots read too (MaxQueueWalk), not only in live entries.
	for seq := head; seq < tail && seq-head < constants.MaxQueueWalk && scanned < constants.MaxDrainScan && issued < max; seq++ {
		if InFlightWithdrawals() >= constants.MaxInFlightWithdrawals {
			break
		}
		q := GetQueued(seq)
		if q == nil {
			continue
		}
		scanned++
		switch out, why := issueQueued(q, vault, chainId, header, true); out {
		case queueIssued:
			RemoveQueued(seq, q)
			issued++
		case queueRefund:
			refundQueued(seq, q, why) // its own terms cannot pay it (a payout: back to its sender)
		case queueWait:
			// D-4: an entry that waits changes nothing (it stays queued) and says
			// nothing about the entries behind it: a token withdrawal waiting on
			// the gas reserve, or one waiting for its token to be swept to the
			// active generation, while an ETH withdrawal behind it could go now.
			// Counted, 32 of them at the head used up MaxDrainScan and every
			// withdrawal behind them waited (for a top-up, or for the token
			// sweep, which can be wedged until the owner retries it). Waits do
			// not count against the scan budget; MaxQueueWalk still bounds the
			// slots one call reads.
			scanned--
		}
	}
	return issued
}

// What issueQueued did with an entry.
const (
	queueIssued = iota // in flight now
	queueWait          // not now: a shared condition (the gas reserve); it stays queued
	queueRefund        // its own terms cannot pay at this price: refund it
)

// refundQueued returns a queued withdrawal's whole debit to its owner and
// removes it (QFREEZE-1).
func refundQueued(seq uint64, q *QueuedWithdrawal, why string) {
	trackRefund(q.Asset, q.Debit)
	RemoveQueued(seq, q)
	sdk.Log("unmapq|refund|q=" + strconv.FormatUint(seq, 10) + "|f=" + q.From + "|a=" + q.Asset + "|d=" + q.Debit.String() + "|why=" + why)
	// A payout of a swap paid from Hive or Bitcoin is held for its sender and
	// swapped back by the bot, never put on a Magi balance.
	if q.ReturnAsset != "" {
		returnPayoutToSender(&PendingSpend{Nonce: seq, Asset: q.Asset, RefundTo: q.RefundTo,
			Amount: q.Amount, ReturnAsset: q.ReturnAsset, ReturnMin: q.ReturnMin}, q.Debit)
		return
	}
	creditWithdrawalRefund(q.From, q.To, q.refundAccount(), q.Asset, q.Debit, false)
}

// issueQueued prices q from header, gives it the next vault nonce, requests the
// TSS signature and stores its PendingSpend (queueIssued). It changes nothing
// when q cannot be issued at this price: queueRefund (with why) when q's own
// terms cannot pay it (the ETH fee is above the caller's cap or does not fit
// in a netted amount; an ERC-20 transfer's gas is above the caller's
// max_fee), queueWait when the gas reserve does not cover an ERC-20 transfer.
//
// queued says q is a queue entry (its debit is in QueuedDebit); false for the
// request issuing at once without one.
func issueQueued(q *QueuedWithdrawal, vault [20]byte, chainId uint64, header *blocklist.EthBlockHeader, queued bool) (int, string) {
	// q's own terms cannot pay it (its max_fee, the fee it set aside, an amount
	// the gas does not fit in): it goes back (a payout to its sender), never
	// waits. A wait is only for what every entry shares (a fresh header, the
	// reserve, the active vault): 64 entries waiting on their own limits would
	// stop the drain's walk for everyone behind them (QFREEZE-1).
	cannot := func(why string) (int, string) {
		return queueRefund, why
	}
	toAddr, err := crypto.HexToAddress(q.To)
	if err != nil || toAddr == ([20]byte{}) {
		return queueRefund, "bad recipient" // validated at request time; unreachable
	}
	const gasTipCap = uint64(2_000_000_000) // 2 gwei, as before
	nonce := GetPendingNonce()
	ps := PendingSpend{
		Nonce:        nonce,
		From:         q.From,
		RefundTo:     q.RefundTo,
		ReturnAsset:  q.ReturnAsset,
		To:           q.To,
		Asset:        q.Asset,
		TokenAddress: q.TokenAddress,
		BlockHeight:  blocklist.GetLastHeight(),
		VaultAtQueue: "0x" + hex.EncodeToString(vault[:]),
		Payout:       q.Payout,
		Attempt:      q.Attempt,
	}
	var unsigned []byte
	userCost := new(big.Int)
	if q.Asset == constants.NativeAsset {
		gas := ETHGasLimit(q.GasLimit)
		gasFeeCap, maxWei, ferr := safeGasFee(gas, header.BaseFeePerGas, 2, gasTipCap)
		if ferr != nil {
			return queueWait, ""
		}
		// feeWei is what the withdrawer pays. A payout pays its gas limit at
		// the expected price (the recipient can burn up to the limit, so the
		// units are the limit's), and the reserve fronts the rest of the
		// signed maximum (reserveGap).
		feeWei := maxWei
		reserveGap := new(big.Int)
		if q.Payout {
			feeWei = minBig(payoutGasFee(gas, header.BaseFeePerGas, gasTipCap), maxWei)
			reserveGap.Sub(maxWei, feeWei)
			reserve := getGasReserve()
			if reserveGap.Sign() > 0 && (reserve.Cmp(big.NewInt(constants.MinGasReserve)) < 0 || reserve.Cmp(reserveGap) < 0) {
				return queueWait, ""
			}
		}
		// The caller's limit: what the request authorized (MaxFee), or FeeCap for
		// an entry queued before EVM-QCAP-1.
		limit := q.MaxFee
		if limit == nil && !q.Payout {
			limit = q.FeeCap
		}
		if limit != nil && feeWei.Cmp(limit) > 0 {
			return cannot("fee " + feeWei.String() + " above the cap " + limit.String())
		}
		// EVM-QCAP-1: a request expecting to issue at once set aside the exact
		// fee at its own price (FeeCap). If it was queued instead (A01: the new
		// generation could not pay it yet) and the fee rose while it waited,
		// within the limit, the owner's own direct withdrawal is charged the rest
		// from its balance now, as the BTC mapping contract's drain charges a
		// queued unmap the rest of its miner fee (unmap_queue.go payQueuedUnmap).
		// It is refunded only when the balance cannot cover it, or when it is a
		// contract's or allowance spender's withdrawal (BTC never queues those).
		// A netted fee (DeductFee) comes out of the amount: nothing to charge.
		rise := new(big.Int)
		if !q.DeductFee && q.FeeCap != nil && feeWei.Cmp(q.FeeCap) > 0 {
			rise.Sub(feeWei, q.FeeCap)
			if !q.ChargeRise {
				return cannot("fee " + feeWei.String() + " above the " + q.FeeCap.String() + " set aside (a contract's or spender's withdrawal is not charged later)")
			}
			if GetBalance(q.From, constants.NativeAsset).Cmp(rise) < 0 {
				return queueRefund, "balance cannot cover the fee rise " + rise.String()
			}
		}
		l1Value := new(big.Int).Set(q.Amount)
		if q.DeductFee {
			l1Value.Sub(l1Value, feeWei)
			if l1Value.Sign() <= 0 {
				return cannot("fee " + feeWei.String() + " not below the amount")
			}
		}
		// Before anything is credited: a wait leaves the entry as it was. The
		// active generation sends the value and can burn up to the signed
		// maximum.
		if !activeGenCovers(q, queued, constants.NativeAsset, new(big.Int).Add(l1Value, maxWei), nil) {
			return queueWait, ""
		}
		if q.DeductFee {
			userCost.Set(q.Amount)
		} else {
			// Fee on top: the caller set aside FeeCap; return what the priced
			// fee does not use, or charge a rise (checked above).
			if rise.Sign() > 0 {
				if !DecBalance(q.From, constants.NativeAsset, rise) {
					return queueRefund, "balance cannot cover the fee rise " + rise.String() // checked above; nothing written yet
				}
				TrackWithdrawal(constants.NativeAsset, rise)
			} else if unused := new(big.Int).Sub(q.FeeCap, feeWei); unused.Sign() > 0 {
				// A payout's fee set-aside was its contract's own: what is not
				// used goes back to that contract, not to the user's Magi balance.
				back := q.refundAccount()
				if q.Payout {
					back = q.From
				}
				IncBalance(back, constants.NativeAsset, unused)
				trackRefund(constants.NativeAsset, unused)
			}
			userCost.Add(q.Amount, feeWei)
		}
		unsigned = BuildETHWithdrawalTxGas(chainId, nonce, gasTipCap, gasFeeCap, toAddr, l1Value, gas)
		ps.Amount = l1Value // the L1 tx value: returns to the vault on revert
		ps.ReturnMin = scaleReturnMin(q, l1Value)
		ps.GasCost = feeWei // prepaid by the caller
		if q.Payout {
			// The reserve fronts the rest of the signed maximum, and settles all
			// of it (gx- = the whole prepaid gas): what the transaction does not
			// burn goes to the reserve, nothing to the withdrawer.
			if reserveGap.Sign() > 0 {
				deductGasReserve(reserveGap)
				TrackReserveSpend(reserveGap)
			}
			ps.GasCost = maxWei
			addSpendReserveExtra(nonce, maxWei)
		}
		if gas != constants.ETHTransferGas {
			ps.GasLimit = gas // 0 (omitted) is ETHTransferGas: a smaller record
		}
	} else {
		tokenAddr, terr := crypto.HexToAddress(q.TokenAddress)
		if terr != nil {
			return queueRefund, "bad token" // validated at request time; unreachable
		}
		gasFeeCap, gasCost, ferr := safeGasFee(TokenGasLimit(q.GasLimit), header.BaseFeePerGas, 2, gasTipCap)
		if ferr != nil {
			return queueWait, ""
		}
		// userGas is the gas the withdrawal pays for in the token: the signed
		// maximum (the unused part refunded at settlement), or for a payout an
		// ERC-20 transfer at the expected price, never refunded.
		userGas := gasCost
		if q.Payout {
			userGas = minBig(payoutGasFee(payoutTokenGas(q.GasLimit), header.BaseFeePerGas, gasTipCap), gasCost)
		}
		if q.MaxFee != nil && userGas.Cmp(q.MaxFee) > 0 {
			return cannot("gas " + userGas.String() + " above the max_fee " + q.MaxFee.String())
		}
		// The ERC-20 gas comes from the shared ETH reserve: keep its floor and
		// require it to cover this transfer (RV-6), else wait for a top-up.
		reserve := getGasReserve()
		if reserve.Cmp(big.NewInt(constants.MinGasReserve)) < 0 || reserve.Cmp(gasCost) < 0 {
			return queueWait, ""
		}
		if !activeGenCovers(q, queued, q.Asset, q.Amount, gasCost) {
			return queueWait, ""
		}
		// A11: the reserve fronts the gas; the withdrawal pays it back in the
		// token, out of what it sends (THORChain takes its outbound fee from the
		// outbound amount), to the operator who tops the reserve up.
		send := new(big.Int).Set(q.Amount)
		var gasFee *big.Int
		if info := getTokenInfo(chainId, tokenAddr); info != nil {
			gasFee = tokenGasFee(q.Asset, userGas, info.MinWithdrawal)
			if gasFee.Cmp(send) >= 0 {
				return cannot("gas fee " + gasFee.String() + " " + q.Asset + " not below the amount")
			}
			send.Sub(send, gasFee)
		}
		deductGasReserve(gasCost)
		TrackReserveSpend(gasCost)
		if gasFee != nil && gasFee.Sign() > 0 {
			IncBalance(constants.TokenGasFeeRecipient, q.Asset, gasFee)
			TrackDeposit(q.Asset, gasFee, new(big.Int)) // it stays in custody, now the recipient's
			sdk.Log("tokengasfee|a=" + q.Asset + "|v=" + gasFee.String() + "|gas=" + userGas.String())
		}
		unsigned = BuildERC20WithdrawalTxGas(chainId, nonce, gasTipCap, gasFeeCap, tokenAddr, toAddr, send, q.GasLimit)
		ps.Amount = send
		ps.ReturnMin = scaleReturnMin(q, send)
		ps.GasCost = gasCost
		if gasFee != nil && gasFee.Sign() > 0 && !q.Payout {
			setSpendTokenGasFee(nonce, gasFee) // EVM-FEE-1: refunded pro rata at settlement
		}
		ps.RevertFee = q.RevertFee
		ps.GasLimit = q.GasLimit
		userCost.Set(q.Amount)
	}
	ps.UnsignedTxHex = hex.EncodeToString(unsigned)
	sdk.TssSignKey(ActiveKeyName(), ComputeSighash(unsigned))
	StorePendingSpend(ps)
	logged := ps
	if q.Payout && q.Asset == constants.NativeAsset {
		// g is the gas the withdrawer paid; the reserve fronted the rest of
		// the signed maximum (GasCost).
		logged.GasCost = new(big.Int).Sub(q.Amount, ps.Amount)
		if !q.DeductFee {
			logged.GasCost = new(big.Int).Sub(userCost, q.Amount)
		}
	}
	logUnmap(logged, userCost, q.Asset == constants.NativeAsset)
	SetPendingNonce(nonce + 1)
	return queueIssued, ""
}

// HandleCancelQueuedWithdrawal returns a queued (not yet issued) withdrawal to
// its owner in full. Nothing reached L1, so no proof is needed. Allowed while
// paused: it only moves funds back to the owner's L2 balance. The withdrawal's
// owner may cancel it, and so may the contract owner (an escape hatch for an
// entry that cannot be paid, as in the BTC mapping contract's
// HandleCancelQueuedUnmap); the debit goes back to the withdrawal's owner
// either way.
func HandleCancelQueuedWithdrawal(seq uint64) error {
	env := sdk.GetEnv()
	if err := checkAuth(env); err != nil {
		return err
	}
	q := GetQueued(seq)
	if q == nil {
		return ce.NewContractError(ce.ErrIntent, "no queued withdrawal "+strconv.FormatUint(seq, 10))
	}
	caller := env.Caller.String()
	owner := sdk.GetEnvKey("contract.owner")
	beneficiary := q.RefundTo != "" && crypto.SameIdentity(caller, q.RefundTo)
	if !crypto.SameIdentity(caller, q.From) && !beneficiary && (owner == nil || caller != *owner) {
		return errors.New("cancelQueuedWithdrawal: only the withdrawal's owner or the contract owner can cancel it")
	}
	trackRefund(q.Asset, q.Debit)
	RemoveQueued(seq, q)
	sdk.Log("unmapcancel|q=" + strconv.FormatUint(seq, 10) + "|f=" + q.From + "|a=" + q.Asset + "|d=" + q.Debit.String() + "|by=" + caller)
	// A cancelled payout of a swap paid from Hive goes back there, as a
	// reverted one does.
	if q.ReturnAsset != "" {
		returnPayoutToSender(&PendingSpend{Nonce: seq, Asset: q.Asset, RefundTo: q.RefundTo,
			Amount: q.Amount, ReturnAsset: q.ReturnAsset, ReturnMin: q.ReturnMin}, q.Debit)
		return nil
	}
	creditWithdrawalRefund(q.From, q.To, q.refundAccount(), q.Asset, q.Debit, false)
	return nil
}

// trackRefund books amount back into custody and user supply: it reverses
// part of the TrackWithdrawal taken when the withdrawal was requested.
func trackRefund(asset string, amount *big.Int) {
	s := GetSupply(asset)
	s.Active.Add(s.Active, amount)
	s.User.Add(s.User, amount)
	SetSupply(asset, s)
}

// logQueued emits the request event; logUnmap follows at issue with the nonce.
func logQueued(seq uint64, q *QueuedWithdrawal) {
	sdk.Log("unmapq|q=" + strconv.FormatUint(seq, 10) + "|f=" + q.From + "|t=" + q.To + "|a=" + q.Asset +
		"|d=" + q.Debit.String())
}

// defaultETHFeeCap is the fee authorization an ETH unmap of gas units reserves
// when the caller sets no max_fee: twice the issue-time formula at the newest
// header's base fee (2x base + 2 gwei tip), never below gas x
// DefaultETHFeeCapFloorGwei. The unused part is refunded at issue.
func defaultETHFeeCap(gas uint64) *big.Int {
	floor := new(big.Int).Mul(new(big.Int).SetUint64(gas), big.NewInt(constants.DefaultETHFeeCapFloorGwei*1_000_000_000))
	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return floor
	}
	_, fee, err := safeGasFee(gas, header.BaseFeePerGas, 4, 4_000_000_000)
	if err != nil || fee.Cmp(floor) < 0 {
		return floor
	}
	return fee
}

// activeGenCovers reports whether the active vault generation's own funds cover
// a withdrawal: amount of asset plus, for an ERC-20, ethGas of ETH (A01).
//
// While a superseded generation still holds funds, part of the custody sits at
// its address until the sweep lands; the new generation can only send what
// reached it. What is there and not yet committed to an issued withdrawal is
// the custody plus the queued debits (requested, not yet sent) plus this
// request's own debit when it is not queued, less the superseded generations'
// books. Short means wait: the entry stays queued until the sweep confirms. With
// no superseded book in these assets, nothing is checked (the pre-rotation
// behaviour).
func activeGenCovers(q *QueuedWithdrawal, queued bool, asset string, amount, ethGas *big.Int) bool {
	need := map[string]*big.Int{asset: new(big.Int).Set(amount)}
	if ethGas != nil {
		if e, ok := need[constants.NativeAsset]; ok {
			e.Add(e, ethGas)
		} else {
			need[constants.NativeAsset] = new(big.Int).Set(ethGas)
		}
	}
	for a, n := range need {
		books := SupersededBookTotal(a)
		if books.Sign() == 0 {
			continue
		}
		avail := new(big.Int).Set(GetSupply(a).Active)
		avail.Add(avail, QueuedDebit(a))
		if !queued && q.Asset == a && q.Debit != nil {
			avail.Add(avail, q.Debit)
		}
		avail.Sub(avail, books)
		if avail.Cmp(n) < 0 {
			return false
		}
	}
	return true
}
