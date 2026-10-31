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
	next := GetPendingNonce()
	// Nothing waiting: issue now, without writing a queue entry that the same
	// call would delete (a state write costs RC even when it is undone).
	if QueueLen() == 0 {
		if header := issuableNow(vault); header != nil {
			if out, _ := issueQueued(&q, vault, chainId, header, false); out == queueIssued {
				return "issued:" + strconv.FormatUint(next, 10), nil
			}
		}
	}
	if QueuedLive() >= constants.MaxQueuedWithdrawals {
		return "", ce.NewContractError(ce.ErrIntent, "withdrawal queue is full; try again later")
	}
	if queuedBy(q.From) >= constants.MaxQueuedPerAccount {
		return "", ce.NewContractError(ce.ErrIntent, "you have "+strconv.FormatUint(constants.MaxQueuedPerAccount, 10)+
			" withdrawals queued; wait for them to go out (or cancel one) before queuing another")
	}
	seq := Enqueue(q)
	logQueued(seq, &q)
	return "queued:" + strconv.FormatUint(seq, 10), nil
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
			refundQueued(seq, q, why)
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
	IncBalance(q.From, q.Asset, q.Debit)
	trackRefund(q.Asset, q.Debit)
	RemoveQueued(seq, q)
	sdk.Log("unmapq|refund|q=" + strconv.FormatUint(seq, 10) + "|f=" + q.From + "|a=" + q.Asset + "|d=" + q.Debit.String() + "|why=" + why)
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
	toAddr, err := crypto.HexToAddress(q.To)
	if err != nil || toAddr == ([20]byte{}) {
		return queueRefund, "bad recipient" // validated at request time; unreachable
	}
	const gasTipCap = uint64(2_000_000_000) // 2 gwei, as before
	nonce := GetPendingNonce()
	ps := PendingSpend{
		Nonce:        nonce,
		From:         q.From,
		To:           q.To,
		Asset:        q.Asset,
		TokenAddress: q.TokenAddress,
		BlockHeight:  blocklist.GetLastHeight(),
		VaultAtQueue: "0x" + hex.EncodeToString(vault[:]),
	}
	var unsigned []byte
	userCost := new(big.Int)
	if q.Asset == constants.NativeAsset {
		gas := ETHGasLimit(q.GasLimit)
		gasFeeCap, feeWei, ferr := safeGasFee(gas, header.BaseFeePerGas, 2, gasTipCap)
		if ferr != nil {
			return queueWait, ""
		}
		if q.FeeCap != nil && feeWei.Cmp(q.FeeCap) > 0 {
			return queueRefund, "fee " + feeWei.String() + " above the cap " + q.FeeCap.String()
		}
		l1Value := new(big.Int).Set(q.Amount)
		if q.DeductFee {
			l1Value.Sub(l1Value, feeWei)
			if l1Value.Sign() <= 0 {
				return queueRefund, "fee " + feeWei.String() + " not below the amount"
			}
		}
		// Before anything is credited: a wait leaves the entry as it was.
		if !activeGenCovers(q, queued, constants.NativeAsset, new(big.Int).Add(l1Value, feeWei), nil) {
			return queueWait, ""
		}
		if q.DeductFee {
			userCost.Set(q.Amount)
		} else {
			// Fee on top: the caller authorized FeeCap; return what the
			// priced fee does not use.
			if unused := new(big.Int).Sub(q.FeeCap, feeWei); unused.Sign() > 0 {
				IncBalance(q.From, constants.NativeAsset, unused)
				trackRefund(constants.NativeAsset, unused)
			}
			userCost.Add(q.Amount, feeWei)
		}
		unsigned = BuildETHWithdrawalTxGas(chainId, nonce, gasTipCap, gasFeeCap, toAddr, l1Value, gas)
		ps.Amount = l1Value // the L1 tx value: returns to the vault on revert
		ps.GasCost = feeWei // prepaid by the caller
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
		if q.MaxFee != nil && gasCost.Cmp(q.MaxFee) > 0 {
			return queueRefund, "gas " + gasCost.String() + " above the max_fee " + q.MaxFee.String()
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
			gasFee = tokenGasFee(q.Asset, gasCost, info.MinWithdrawal)
			if gasFee.Cmp(send) >= 0 {
				return queueRefund, "gas fee " + gasFee.String() + " " + q.Asset + " not below the amount"
			}
			send.Sub(send, gasFee)
		}
		deductGasReserve(gasCost)
		TrackReserveSpend(gasCost)
		if gasFee != nil && gasFee.Sign() > 0 {
			IncBalance(constants.TokenGasFeeRecipient, q.Asset, gasFee)
			TrackDeposit(q.Asset, gasFee, new(big.Int)) // it stays in custody, now the recipient's
			sdk.Log("tokengasfee|a=" + q.Asset + "|v=" + gasFee.String() + "|gas=" + gasCost.String())
		}
		unsigned = BuildERC20WithdrawalTxGas(chainId, nonce, gasTipCap, gasFeeCap, tokenAddr, toAddr, send, q.GasLimit)
		ps.Amount = send
		ps.GasCost = gasCost
		ps.RevertFee = q.RevertFee
		ps.GasLimit = q.GasLimit
		userCost.Set(q.Amount)
	}
	ps.UnsignedTxHex = hex.EncodeToString(unsigned)
	sdk.TssSignKey(ActiveKeyName(), ComputeSighash(unsigned))
	StorePendingSpend(ps)
	logUnmap(ps, userCost, q.Asset == constants.NativeAsset)
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
	if !crypto.SameIdentity(caller, q.From) && (owner == nil || caller != *owner) {
		return errors.New("cancelQueuedWithdrawal: only the withdrawal's owner or the contract owner can cancel it")
	}
	IncBalance(q.From, q.Asset, q.Debit)
	trackRefund(q.Asset, q.Debit)
	RemoveQueued(seq, q)
	sdk.Log("unmapcancel|q=" + strconv.FormatUint(seq, 10) + "|f=" + q.From + "|a=" + q.Asset + "|d=" + q.Debit.String() + "|by=" + caller)
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
