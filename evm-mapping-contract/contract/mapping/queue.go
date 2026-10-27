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
// then submitted here. It is issued (priced, given the next vault nonce,
// TSS-signed) as soon as fewer than MaxInFlightWithdrawals are in flight and a
// fresh pricing header exists; otherwise it waits in the L2 queue. Nothing about
// another user's withdrawal can make a request fail.
//
// Issuing happens on every head close (confirmSpend, expireWithdrawal,
// cancelMyWithdrawal, clearNonce) and through the permissionless
// drainWithdrawalQueue, which the bot calls after a proof brings a fresh header.

// submitWithdrawal queues q and drains. It returns "issued:{nonce}" when q went
// straight into flight, else "queued:{seq}".
// vault is the vault the unmap handler was given (main passes vault(), the TSS
// key's verified address; zero when there is none, and then nothing issues).
func submitWithdrawal(q QueuedWithdrawal, vault [20]byte, chainId uint64) (string, error) {
	if QueueLen() >= constants.MaxQueuedWithdrawals {
		return "", ce.NewContractError(ce.ErrIntent, "withdrawal queue is full; try again later")
	}
	next := GetPendingNonce()
	seq := Enqueue(q)
	logQueued(seq, &q)
	drainWith(chainId, vault)
	if GetQueued(seq) == nil {
		return "issued:" + strconv.FormatUint(next, 10), nil
	}
	return "queued:" + strconv.FormatUint(seq, 10), nil
}

// DrainWithdrawalQueue moves queued withdrawals into flight, oldest first, while
// fewer than MaxInFlightWithdrawals are in flight. It never fails the calling
// transaction: when it cannot issue (paused, no active TSS key or verified
// vault, stale pricing header, an entry's fee cap or the gas reserve too low
// at the current price) the entries stay queued and it returns.
func DrainWithdrawalQueue(chainId uint64) int {
	vault, ok := TssVaultAddress()
	if !ok {
		return 0
	}
	return drainWith(chainId, vault)
}

// drainWith is DrainWithdrawalQueue against a given vault address.
func drainWith(chainId uint64, vault [20]byte) int {
	if vault == ([20]byte{}) || isPaused() || QueueLen() == 0 || InFlightWithdrawals() >= constants.MaxInFlightWithdrawals {
		return 0
	}
	if requireTssKey() != nil {
		return 0
	}
	header, err := pricingHeader()
	if err != nil {
		return 0
	}
	head, tail := QueueBounds()
	issued, scanned := 0, uint64(0)
	for seq := head; seq < tail && scanned < constants.MaxDrainScan; seq++ {
		if InFlightWithdrawals() >= constants.MaxInFlightWithdrawals {
			break
		}
		q := GetQueued(seq)
		if q == nil {
			continue
		}
		scanned++
		if issueQueued(q, vault, chainId, header) {
			RemoveQueued(seq)
			issued++
		}
	}
	return issued
}

// issueQueued prices q from header, gives it the next vault nonce, requests the
// TSS signature and stores its PendingSpend. It returns false (and changes
// nothing) when q cannot be issued at this price: the ETH fee is above the
// caller's cap or does not fit in a netted amount, or (ERC-20) the caller's
// max_fee or the gas reserve does not cover the gas.
func issueQueued(q *QueuedWithdrawal, vault [20]byte, chainId uint64, header *blocklist.EthBlockHeader) bool {
	toAddr, err := crypto.HexToAddress(q.To)
	if err != nil || toAddr == ([20]byte{}) {
		return false // validated at request time; unreachable
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
		gasFeeCap, feeWei, ferr := safeGasFee(constants.ETHTransferGas, header.BaseFeePerGas, 2, gasTipCap)
		if ferr != nil || (q.FeeCap != nil && feeWei.Cmp(q.FeeCap) > 0) {
			return false
		}
		l1Value := new(big.Int).Set(q.Amount)
		if q.DeductFee {
			l1Value.Sub(l1Value, feeWei)
			if l1Value.Sign() <= 0 {
				return false
			}
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
		unsigned = BuildETHWithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, toAddr, l1Value)
		ps.Amount = l1Value // the L1 tx value: returns to the vault on revert
		ps.GasCost = feeWei // prepaid by the caller
	} else {
		tokenAddr, terr := crypto.HexToAddress(q.TokenAddress)
		if terr != nil {
			return false // validated at request time; unreachable
		}
		gasFeeCap, gasCost, ferr := safeGasFee(TokenGasLimit(q.GasLimit), header.BaseFeePerGas, 2, gasTipCap)
		if ferr != nil || (q.MaxFee != nil && gasCost.Cmp(q.MaxFee) > 0) {
			return false
		}
		// The ERC-20 gas comes from the shared ETH reserve: keep its floor and
		// require it to cover this transfer (RV-6), else wait for a top-up.
		reserve := getGasReserve()
		if reserve.Cmp(big.NewInt(constants.MinGasReserve)) < 0 || reserve.Cmp(gasCost) < 0 {
			return false
		}
		deductGasReserve(gasCost)
		TrackReserveSpend(gasCost)
		unsigned = BuildERC20WithdrawalTxGas(chainId, nonce, gasTipCap, gasFeeCap, tokenAddr, toAddr, q.Amount, q.GasLimit)
		ps.Amount = q.Amount
		ps.GasCost = gasCost
		ps.RevertFee = q.RevertFee
		ps.GasLimit = q.GasLimit
		userCost.Set(q.Amount)
	}
	ps.UnsignedTxHex = hex.EncodeToString(unsigned)
	sdk.TssSignKey("primary", ComputeSighash(unsigned))
	StorePendingSpend(ps)
	logUnmap(ps, userCost, q.Asset == constants.NativeAsset)
	SetPendingNonce(nonce + 1)
	return true
}

// HandleCancelQueuedWithdrawal returns a queued (not yet issued) withdrawal to
// its owner in full. Nothing reached L1, so no proof is needed. Allowed while
// paused: it only moves funds back to the owner's L2 balance.
func HandleCancelQueuedWithdrawal(seq uint64) error {
	env := sdk.GetEnv()
	if err := checkAuth(env); err != nil {
		return err
	}
	q := GetQueued(seq)
	if q == nil {
		return ce.NewContractError(ce.ErrIntent, "no queued withdrawal "+strconv.FormatUint(seq, 10))
	}
	if !crypto.SameIdentity(env.Caller.String(), q.From) {
		return errors.New("cancelQueuedWithdrawal: only the withdrawal's owner can cancel it")
	}
	IncBalance(q.From, q.Asset, q.Debit)
	trackRefund(q.Asset, q.Debit)
	RemoveQueued(seq)
	sdk.Log("unmapcancel|q=" + strconv.FormatUint(seq, 10) + "|f=" + q.From + "|a=" + q.Asset + "|d=" + q.Debit.String())
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

// defaultETHFeeCap is the fee authorization an ETH unmap reserves when the
// caller sets no max_fee: twice the issue-time formula at the newest header's
// base fee (2x base + 2 gwei tip), never below DefaultETHFeeCapFloor. The
// unused part is refunded at issue.
func defaultETHFeeCap() *big.Int {
	floor := big.NewInt(constants.DefaultETHFeeCapFloor)
	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return floor
	}
	_, fee, err := safeGasFee(constants.ETHTransferGas, header.BaseFeePerGas, 4, 4_000_000_000)
	if err != nil || fee.Cmp(floor) < 0 {
		return floor
	}
	return fee
}
