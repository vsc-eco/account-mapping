package mapping

import (
	"encoding/json"
	"math/big"
	"strconv"
	"strings"

	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

// A payout that fails for good (its address refused it, or it could not be
// sent in MaxPayoutAttempts tries) goes back to its sender on the sender's own
// chain, never to a Magi balance (owner 11-21). This is THORChain's reverse
// swap of a failed outbound (manager_slasher_current.go
// sendFailedSwapReverseSwap): back to the inbound asset, to the inbound sender.
//
// One adjustment for Magi: anyone can put a call inside a transaction of their
// own (dump into the pool, trigger the swap back, buy back) and skim it. So the
// swap back never runs inside a call anyone can make (confirmSpend, a cancel,
// the queue): the value is held on PayoutReturnHoldAccount (no user's balance)
// and only the bridge's bot (a registered relayer) runs it, with retryPayoutReturn
// and a min_out from its dry run at today's price. For the first
// PayoutFloorFor seconds it never goes below the swap's own rate less 5% (the
// floor the router set); after that the floor drops 5% a day, so nothing waits
// for the price forever and nothing is skimmed far below the real price. The sender may also take it back at their own price,
// or have the held asset itself sent to an Ethereum address
// (releasePayoutReturn).

// heldReturn is one held return.
type heldReturn struct {
	To          string   `json:"t"`  // the sender (hive: or did:pkh:bip122)
	Asset       string   `json:"a"`  // what is held (eth or a token)
	Amount      *big.Int `json:"d"`  // how much
	ReturnAsset string   `json:"ra"` // hive, hbd or btc
	// Floor is the least the swap back may give while the floor holds (the
	// swap's own rate less 5%, for this amount).
	Floor *big.Int `json:"m"`
	// HeldAt is when it was held (unix seconds): the floor holds for
	// PayoutFloorFor from then.
	HeldAt uint64 `json:"h,omitempty"`
}

// PayoutReturnParams names a held return and the least its swap back must give
// (min_out, in the return asset's smallest units).
type PayoutReturnParams struct {
	Id     uint64 `json:"id"`
	MinOut string `json:"min_out,omitempty"`
	// To (releasePayoutReturn only): an Ethereum address the sender picks to
	// receive the held asset itself instead of the swap back (the exit when no
	// pool can take it back). The proving fee and the payout's gas come out of
	// the held amount.
	To string `json:"to,omitempty"`
}

func payoutReturnKey(id uint64) string {
	return constants.PayoutReturnPrefix + strconv.FormatUint(id, 10)
}

func payoutReturnCounter(key string) uint64 {
	if v := sdk.StateGetObject(key); v != nil && *v != "" {
		if n, err := strconv.ParseUint(*v, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func getHeldReturn(id uint64) *heldReturn {
	v := sdk.StateGetObject(payoutReturnKey(id))
	if v == nil || *v == "" {
		return nil
	}
	var h heldReturn
	if err := json.Unmarshal([]byte(*v), &h); err != nil || h.Amount == nil {
		return nil
	}
	return &h
}

func setHeldReturn(id uint64, h *heldReturn) {
	b, _ := json.Marshal(h)
	sdk.StateSetObject(payoutReturnKey(id), string(b))
}

// scaleFloor is floor's share for part of whole (0 when there is no floor).
func scaleFloor(floor, part, whole *big.Int) *big.Int {
	if floor == nil || floor.Sign() <= 0 || part == nil || whole == nil || whole.Sign() <= 0 {
		return new(big.Int)
	}
	f := new(big.Int).Mul(floor, part)
	f.Div(f, whole)
	if f.Sign() <= 0 {
		f.SetInt64(1)
	}
	return f
}

// returnPayoutToSender holds amount of a failed payout ps for its sender
// (ps.RefundTo, to go back as ps.ReturnAsset); the bot swaps it back.
func returnPayoutToSender(ps *PendingSpend, amount *big.Int) {
	if amount == nil || amount.Sign() <= 0 {
		return
	}
	holdPayoutReturn(ps.RefundTo, ps.Asset, amount, ps.ReturnAsset, scaleFloor(ps.ReturnMin, amount, ps.Amount),
		"n="+strconv.FormatUint(ps.Nonce, 10))
}

// swapBackToSender has the router swap amount of asset to returnAsset and pay
// it to the sender `to` on its own chain, giving at least minOut. amount is on
// no account when it is called; what of it did not go out (all of it when the
// swap did not run, with the reason; the part the router left when it did) is
// returned, again on no account, with what the swap gave (amount_out). It is
// called the way routeDeposit calls the router: amount credited to this
// contract with an allowance for the router, in try mode, so a refusal rolls
// the router's side back.
func swapBackToSender(asset string, amount *big.Int, returnAsset, to string, minOut *big.Int) (*big.Int, string, string) {
	if minOut == nil || minOut.Sign() <= 0 {
		return new(big.Int).Set(amount), "", "no min_out"
	}
	routerIdPtr := sdk.StateGetObject(constants.RouterContractIdKey)
	if routerIdPtr == nil || *routerIdPtr == "" {
		return new(big.Int).Set(amount), "", "router not set"
	}
	routerId := *routerIdPtr
	selfAddr := "contract:" + sdk.GetEnv().ContractId
	routerSpender := "contract:" + routerId
	IncBalance(selfAddr, asset, amount)
	prevAllowance := GetAllowance(selfAddr, routerSpender, asset)
	SetAllowance(selfAddr, routerSpender, asset, new(big.Int).Add(prevAllowance, amount))
	min := minOut.String()
	// Back to Hive for a hive: sender; to the sender's Bitcoin address for a
	// did:pkh:bip122 one (SENDER-REFUND-1), paid by the router through the BTC
	// mapping contract.
	destination, recipient := "HIVE", to
	if returnAsset == "btc" {
		destination, recipient = "BTC", to[strings.LastIndex(to, ":")+1:]
	}
	instrJSON, _ := json.Marshal(DexInstruction{
		Type:             "swap",
		Version:          "1.0.0",
		AssetIn:          asset,
		AmountIn:         amount.String(),
		AssetOut:         returnAsset,
		Recipient:        recipient,
		DestinationChain: destination,
		MinAmountOut:     &min,
	})
	result := sdk.ContractCall(routerId, "execute", string(instrJSON), &sdk.ContractCallOptions{Try: true})
	unspent := new(big.Int).Sub(GetAllowance(selfAddr, routerSpender, asset), prevAllowance)
	if unspent.Sign() < 0 || unspent.Cmp(amount) > 0 {
		unspent.SetInt64(0)
	}
	SetAllowance(selfAddr, routerSpender, asset, prevAllowance)
	if !tryCallSucceeded(result) {
		DecBalance(selfAddr, asset, amount)
		return new(big.Int).Set(amount), "", tryCallError(result)
	}
	if unspent.Sign() > 0 {
		DecBalance(selfAddr, asset, unspent)
	}
	return unspent, tryCallAmountOut(result), ""
}

// tryCallAmountOut is the router's amount_out from a try-mode call's result
// ("" when it has none).
func tryCallAmountOut(result *string) string {
	if result == nil {
		return ""
	}
	inner := *result
	var wrapped struct {
		Ok     *bool  `json:"ok"`
		Result string `json:"result"`
	}
	if json.Unmarshal([]byte(inner), &wrapped) == nil && wrapped.Ok != nil {
		inner = wrapped.Result
	}
	var out struct {
		AmountOut string `json:"amount_out"`
	}
	if json.Unmarshal([]byte(inner), &out) != nil {
		return ""
	}
	return out.AmountOut
}

// holdPayoutReturn holds amount for its sender until the bot swaps it back.
func holdPayoutReturn(to, asset string, amount *big.Int, returnAsset string, floor *big.Int, ref string) {
	IncBalance(constants.PayoutReturnHoldAccount, asset, amount)
	id := payoutReturnCounter(constants.PayoutReturnTailKey)
	sdk.StateSetObject(constants.PayoutReturnTailKey, strconv.FormatUint(id+1, 10))
	now, _ := blockTime(sdk.GetEnv().Timestamp)
	setHeldReturn(id, &heldReturn{To: to, Asset: asset, Amount: new(big.Int).Set(amount), ReturnAsset: returnAsset, Floor: floor, HeldAt: now})
	sdk.Log("payoutreturnheld|id=" + strconv.FormatUint(id, 10) + "|" + ref + "|t=" + to + "|a=" + asset + "|d=" + amount.String() +
		"|ra=" + returnAsset + "|m=" + floor.String())
}

// HandleRetryPayoutReturn swaps a held return back to its sender, giving at
// least min_out (the bot's dry run at today's price, less 1%), and never less
// than the floor (heldReturnFloor). Only the bridge's bot (a registered relayer)
// may call it: a call anyone could make could be wrapped and skimmed. It
// returns what the swap gave (amount_out), so the bot's dry run reads today's
// price from it.
func HandleRetryPayoutReturn(id uint64, minOut string) (string, error) {
	if isPaused() {
		return "", ce.NewContractError(ce.ErrInitialization, "contract is paused")
	}
	h := getHeldReturn(id)
	if h == nil {
		return "", ce.NewContractError(ce.ErrInput, "no held return "+strconv.FormatUint(id, 10))
	}
	if !IsWhitelistedRelayer(sdk.GetEnv().Caller.String()) {
		return "", ce.NewContractError(ce.ErrNoPermission, "only the bridge's bot swaps a held return back ("+h.To+" may release it)")
	}
	min, ok := new(big.Int).SetString(minOut, 10)
	if !ok || min.Sign() <= 0 {
		return "", ce.NewContractError(ce.ErrInput, "min_out must be a positive amount of "+h.ReturnAsset)
	}
	if floor := heldReturnFloor(h); min.Cmp(floor) < 0 {
		min = floor
	}
	return runHeldReturn(id, h, min)
}

// HandleReleasePayoutReturn lets a held return's sender take it back now, at
// the least they accept (min_out, in the return asset's smallest units).
func HandleReleasePayoutReturn(id uint64, minOut string, to string, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrInitialization, "contract is paused")
	}
	h := getHeldReturn(id)
	if h == nil {
		return ce.NewContractError(ce.ErrInput, "no held return "+strconv.FormatUint(id, 10))
	}
	env := sdk.GetEnv()
	if env.Caller.String() != h.To {
		return ce.NewContractError(ce.ErrNoPermission, "only "+h.To+" can release this return")
	}
	if err := checkAuth(env); err != nil {
		return err
	}
	if to != "" {
		return releaseHeldReturnOnEthereum(id, h, to, vaultAddress, chainId)
	}
	min, ok := new(big.Int).SetString(minOut, 10)
	if !ok || min.Sign() <= 0 {
		return ce.NewContractError(ce.ErrInput, "min_out must be a positive amount of "+h.ReturnAsset)
	}
	_, err := runHeldReturn(id, h, min)
	return err
}

// heldReturnFloor is the least a held return's swap back may give now: its
// floor (the swap's own rate less 5%) for the first day, then 5% less each
// further day (gone after PayoutFloorDays more), so it is never skimmed far
// below what the price really is, and never waits forever.
func heldReturnFloor(h *heldReturn) *big.Int {
	if h.Floor == nil || h.Floor.Sign() <= 0 {
		return new(big.Int)
	}
	now, ok := blockTime(sdk.GetEnv().Timestamp)
	if !ok || h.HeldAt == 0 || now < h.HeldAt+constants.PayoutFloorFor {
		return h.Floor
	}
	days := (now - h.HeldAt) / constants.PayoutFloorFor
	if days > constants.PayoutFloorDays {
		return new(big.Int)
	}
	f := new(big.Int).Mul(h.Floor, big.NewInt(int64(constants.PayoutFloorDays-days)))
	return f.Div(f, big.NewInt(constants.PayoutFloorDays))
}

func runHeldReturn(id uint64, h *heldReturn, minOut *big.Int) (string, error) {
	if !DecBalance(constants.PayoutReturnHoldAccount, h.Asset, h.Amount) {
		return "", ce.NewContractError(ce.ErrStateAccess, "the return hold does not cover return "+strconv.FormatUint(id, 10))
	}
	left, out, why := swapBackToSender(h.Asset, h.Amount, h.ReturnAsset, h.To, minOut)
	if why != "" {
		IncBalance(constants.PayoutReturnHoldAccount, h.Asset, h.Amount)
		return "", ce.NewContractError(ce.ErrTransaction, "the swap back did not run: "+why)
	}
	ids := strconv.FormatUint(id, 10)
	sent := new(big.Int).Sub(h.Amount, left)
	sdk.Log("payoutreturn|id=" + ids + "|t=" + h.To + "|a=" + h.Asset + "|d=" + sent.String() + "|ra=" + h.ReturnAsset + "|o=" + out)
	if left.Sign() > 0 {
		IncBalance(constants.PayoutReturnHoldAccount, h.Asset, left)
		h.Floor = scaleFloor(h.Floor, left, h.Amount)
		h.Amount = left
		setHeldReturn(id, h)
		return out, nil
	}
	finishHeldReturn(id)
	return out, nil
}

// releaseHeldReturnOnEthereum withdraws a held return to an Ethereum address
// its sender picked, as a payout (its own amount pays the proving fee and the
// gas). If that payout fails it comes back to the sender and is held again.
func releaseHeldReturnOnEthereum(id uint64, h *heldReturn, to string, vaultAddress [20]byte, chainId uint64) error {
	send := new(big.Int).Sub(h.Amount, ProofFee(h.Asset))
	if send.Sign() <= 0 {
		return ce.NewContractError(ce.ErrInput, "the held amount does not cover the proving fee")
	}
	p := &TransferParams{Amount: send.String(), To: to, Asset: h.Asset, DeductFee: true,
		RefundTo: h.To, ReturnAsset: h.ReturnAsset, ReturnMin: "1"}
	if h.Floor != nil && h.Floor.Sign() > 0 {
		p.ReturnMin = scaleFloor(h.Floor, send, h.Amount).String()
	}
	var status string
	var err error
	if h.Asset == constants.NativeAsset {
		status, err = unmapETH(p, vaultAddress, chainId, constants.PayoutReturnHoldAccount, false)
	} else {
		tokenAddr, _, ok := tokenBySymbol(chainId, h.Asset)
		if !ok {
			return ErrInvalidToken
		}
		p.TokenAddress = crypto.AddressToHex(tokenAddr)
		p.DeductFee = false // a token's gas fee comes out of the amount (tokengasfee)
		status, err = unmapERC20(p, vaultAddress, chainId, constants.PayoutReturnHoldAccount, false)
	}
	if err != nil {
		return err
	}
	sdk.Log("payoutreturnout|id=" + strconv.FormatUint(id, 10) + "|t=" + h.To + "|a=" + h.Asset + "|d=" + send.String() + "|to=" + to + "|s=" + status)
	finishHeldReturn(id)
	return nil
}

// finishHeldReturn removes a held return that has gone out and steps the head
// past returns no longer held.
func finishHeldReturn(id uint64) {
	sdk.StateDeleteObject(payoutReturnKey(id))
	head := payoutReturnCounter(constants.PayoutReturnHeadKey)
	tail := payoutReturnCounter(constants.PayoutReturnTailKey)
	for i := 0; i < constants.PayoutReturnHeadSkip && head < tail && getHeldReturn(head) == nil; i++ {
		head++
	}
	sdk.StateSetObject(constants.PayoutReturnHeadKey, strconv.FormatUint(head, 10))
}

// resendPayout sends a rolled payout again (THORChain reschedules an unsent
// outbound): the same recipient, asset, value, gas limit and return, one
// attempt more. Like every send it pays its own gas out of its own amount (the
// reserve only lends the gas and gets the unused part back), so a re-send
// never costs the reserve. Its value never left custody and stays withdrawn
// (no supply change); the rolled spend leaves its generation's book. It is
// issued now when nothing waits, else queued; the queue caps and the per-block
// rate limit do not apply (the value was counted when it was first withdrawn;
// re-sends are bounded by the spends in flight). false (nothing done) for a
// user's own withdrawal, a payout from before this, or one out of attempts:
// the caller sends that back to its sender.
func resendPayout(ps *PendingSpend, chainId uint64) bool {
	if !ps.Payout || int(ps.Attempt)+1 >= constants.MaxPayoutAttempts || ps.Amount == nil || ps.Amount.Sign() <= 0 {
		return false
	}
	q := QueuedWithdrawal{
		From: ps.From, To: ps.To, Asset: ps.Asset, TokenAddress: ps.TokenAddress,
		Amount: new(big.Int).Set(ps.Amount), Debit: new(big.Int).Set(ps.Amount),
		RevertFee: ps.RevertFee, GasLimit: ps.GasLimit, RefundTo: ps.RefundTo,
		Payout: true, ReturnAsset: ps.ReturnAsset, Attempt: ps.Attempt + 1, DeductFee: true,
	}
	if ps.ReturnMin != nil {
		q.ReturnMin = new(big.Int).Set(ps.ReturnMin)
	}
	// First: the value is still in the vault it was to leave from (a retiring
	// generation's book holds it again), so the issue check below sees what the
	// active vault really holds.
	bookSpendRefund(ps, ps.Amount)
	status := ""
	if vault, ok := TssVaultAddress(); ok && QueueLen() == 0 {
		if header := issuableNow(vault); header != nil {
			next := GetPendingNonce()
			if out, _ := issueQueued(&q, vault, chainId, header, false); out == queueIssued {
				status = "issued:" + strconv.FormatUint(next, 10)
			}
		}
	}
	if status == "" {
		seq := Enqueue(q)
		logQueued(seq, &q)
		status = "queued:" + strconv.FormatUint(seq, 10)
	}
	sdk.Log("payoutresend|n=" + strconv.FormatUint(ps.Nonce, 10) + "|t=" + ps.To + "|a=" + ps.Asset + "|d=" + ps.Amount.String() +
		"|attempt=" + strconv.Itoa(int(q.Attempt)+1) + "|s=" + status)
	return true
}
