package mapping

import (
	"encoding/json"
	"evm-mapping-contract/contract/blocklist"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

// PAYOUT-1: a withdrawal a contract requests (a router swap's payout) or
// sendHome makes is sent at once or refused, and pays its gas at the expected
// price with nothing refunded later (THORChain's outbound fee): its user may
// hold no Magi balance at all, so a refund there is lost to them. A user's own
// withdrawal keeps EVM-FEE-1 (prepay the maximum, the unused part back to the
// balance it came from).

const poTip = uint64(2_000_000_000)

// poSettle settles ps as mined first in its block (txIndex 0) at gasUsed and
// the rpBridge header's 1 gwei base fee.
func poSettle(t *testing.T, ps *PendingSpend, gasUsed uint64) {
	t.Helper()
	userGas, tokenGasFee := spendGasShares(ps)
	finishWithdrawalGas(ps, userGas, tokenGasFee, gasUsed, 1e9+poTip, 101, 0)
}

func TestPayout_ETHPaysItsLimitAtTheExpectedPriceAndNothingComesBack(t *testing.T) {
	for _, egl := range []uint64{0, 60_000, 250_000} {
		t.Run("egl="+strconv.FormatUint(egl, 10), func(t *testing.T) {
			rpBridge(t, ethWei(20), rtRouter)
			if egl != 0 {
				SetETHGasLimit(egl)
			}
			gas := ETHGasLimit(egl)
			reserve0 := getGasReserve()
			routerBefore := GetBalance(rtRouter, "eth")
			out, err := rtUnmapETH(t, "hive:alice", "", rpNow)
			if err != nil || !strings.HasPrefix(out, "issued:") {
				t.Fatalf("routed unmap: %q %v", out, err)
			}
			ethInvariant(t, "after issue")
			ps := GetPendingSpend(0)
			fee := payoutGasFee(gas, 1e9, poTip) // gas x 3.5 gwei
			_, maxWei, _ := safeGasFee(gas, 1e9, 2, poTip)
			if want := new(big.Int).Mul(new(big.Int).SetUint64(gas), big.NewInt(3_500_000_000)); fee.Cmp(want) != 0 {
				t.Fatalf("payout fee %s, want %s", fee, want)
			}
			if want := new(big.Int).Sub(big.NewInt(1e16), fee); ps.Amount.Cmp(want) != 0 {
				t.Fatalf("sent %s, want the amount less the payout fee %s", ps.Amount, want)
			}
			if ps.GasCost.Cmp(maxWei) != 0 {
				t.Fatalf("GasCost %s, want the signed maximum %s", ps.GasCost, maxWei)
			}
			if debited := new(big.Int).Sub(routerBefore, GetBalance(rtRouter, "eth")); debited.Cmp(new(big.Int).Add(big.NewInt(1e16), ProofFee("eth"))) != 0 {
				t.Fatalf("debited %s", debited)
			}
			gap := new(big.Int).Sub(maxWei, fee)
			if got := new(big.Int).Sub(reserve0, getGasReserve()); got.Cmp(gap) != 0 {
				t.Fatalf("reserve fronted %s, want the gap %s", got, gap)
			}
			// Mined using 21,000 at 3 gwei: everything unburned goes to the reserve.
			poSettle(t, ps, constants.ETHTransferGas)
			if GetBalance("hive:alice", "eth").Sign() != 0 || GetBalance(rtRouter, "eth").Cmp(new(big.Int).Sub(routerBefore, new(big.Int).Add(big.NewInt(1e16), ProofFee("eth")))) != 0 {
				t.Fatal("a gas refund reached a Magi balance")
			}
			real := new(big.Int).Mul(big.NewInt(int64(constants.ETHTransferGas)), big.NewInt(3e9))
			if got, want := new(big.Int).Sub(getGasReserve(), reserve0), new(big.Int).Sub(fee, real); got.Cmp(want) != 0 {
				t.Fatalf("reserve moved %s, want fee - real cost %s", got, want)
			}
			ethInvariant(t, "after settlement")
		})
	}
}

// The reserve carries a payout that burns more than it paid (a contract
// recipient up to the limit; the fee covers the limit's units, so only a base
// fee rise above 1.5x can make the reserve pay).
func TestPayout_ETHReserveCarriesWhatTheFeeDoesNotCover(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	SetETHGasLimit(60_000)
	reserve0 := getGasReserve()
	if _, err := rtUnmapETH(t, "hive:alice", "", rpNow); err != nil {
		t.Fatal(err)
	}
	ps := GetPendingSpend(0)
	fee := payoutGasFee(60_000, 1e9, poTip)
	userGas, _ := spendGasShares(ps)
	// The base fee rose to 1.9 gwei before inclusion and the recipient burned
	// the whole limit: 60,000 x 3.9 gwei > the 3.5 gwei it paid.
	finishWithdrawalGas(ps, userGas, new(big.Int), 60_000, 3_900_000_000, 101, 0)
	real := new(big.Int).Mul(big.NewInt(60_000), big.NewInt(3_900_000_000))
	if got, want := new(big.Int).Sub(reserve0, getGasReserve()), new(big.Int).Sub(real, fee); got.Cmp(want) != 0 {
		t.Fatalf("reserve paid %s, want real - fee %s", got, want)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 {
		t.Fatal("refund to a Magi balance")
	}
	ethInvariant(t, "after settlement")
}

func TestPayout_TokenPaysAnERC20TransferAtTheExpectedPrice(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	var tok [20]byte
	tok[19] = 0xc0
	if err := RegisterTokenFull(1, tok, "USDC", 6, 3_000_000, 0, 200_000); err != nil {
		t.Fatal(err)
	}
	SetTokenGasRate("USDC", big.NewInt(1_760_000_000)) // 1,760 USDC per ETH
	IncBalance(rtRouter, "USDC", big.NewInt(9_000_000))
	s := GetSupply("USDC")
	SetSupply("USDC", Supply{Active: new(big.Int).Add(s.Active, big.NewInt(9_000_000)), User: new(big.Int).Add(s.User, big.NewInt(9_000_000)), Fee: s.Fee})
	reserve0 := getGasReserve()
	asContract(t, rtRouter, "hive:alice", rpNow)
	out, err := HandleUnmapERC20(&TransferParams{Amount: "3094000", To: qfTo, Asset: "USDC",
		TokenAddress: "0x00000000000000000000000000000000000000c0", RefundTo: "hive:alice"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("routed USDC: %q %v", out, err)
	}
	ps := GetPendingSpend(0)
	// 65,000 x 3.5 gwei = 0.0002275 ETH x 1,760 = 0.4004 USDC, rounded up.
	wantFee := tokenGasFee("USDC", payoutGasFee(65_000, 1e9, poTip), 3_000_000)
	if wantFee.Cmp(big.NewInt(400_400)) != 0 {
		t.Fatalf("token fee %s, want 400400", wantFee)
	}
	if got := new(big.Int).Sub(big.NewInt(3_094_000), ps.Amount); got.Cmp(wantFee) != 0 {
		t.Fatalf("token fee taken %s, want %s", got, wantFee)
	}
	// The old charge: the 200,000 limit at 4 gwei, 1.408 USDC.
	_, maxWei, _ := safeGasFee(200_000, 1e9, 2, poTip)
	if old := tokenGasFee("USDC", maxWei, 3_000_000); old.Cmp(big.NewInt(1_408_000)) != 0 {
		t.Fatalf("old charge %s", old)
	}
	if ps.GasCost.Cmp(maxWei) != 0 {
		t.Fatalf("the reserve fronts the signed maximum: GasCost %s, want %s", ps.GasCost, maxWei)
	}
	if v := sdk.StateGetObject(gasTokenFeeKey(0)); v != nil {
		t.Fatalf("a payout recorded a token refund share %s", *v)
	}
	feeRecipient := GetBalance(constants.TokenGasFeeRecipient, "USDC")
	poSettle(t, ps, 45_148)
	if GetBalance("hive:alice", "USDC").Sign() != 0 || GetBalance(constants.TokenGasFeeRecipient, "USDC").Cmp(feeRecipient) != 0 {
		t.Fatal("a token gas refund moved")
	}
	real := new(big.Int).Mul(big.NewInt(45_148), big.NewInt(3e9))
	if got, want := new(big.Int).Sub(reserve0, getGasReserve()), real; got.Cmp(want) != 0 {
		t.Fatalf("reserve paid %s, want the real cost %s", got, want)
	}
	ethInvariant(t, "after settlement")
}

// A user's own withdrawal is unchanged: it prepays the maximum and the unused
// part comes back to the balance it was paid from (EVM-FEE-1).
func TestPayout_OwnWithdrawalKeepsItsRefund(t *testing.T) {
	rpBridge(t, ethWei(20), "hive:alice")
	SetETHGasLimit(60_000)
	start := GetBalance("hive:alice", "eth")
	out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("own unmap: %q %v", out, err)
	}
	ps := GetPendingSpend(0)
	_, maxWei, _ := safeGasFee(60_000, 1e9, 2, poTip)
	if ps.GasCost.Cmp(maxWei) != 0 || new(big.Int).Sub(big.NewInt(1e16), ps.Amount).Cmp(maxWei) != 0 {
		t.Fatalf("own withdrawal: GasCost %s, sent %s; want the maximum %s prepaid", ps.GasCost, ps.Amount, maxWei)
	}
	poSettle(t, ps, constants.ETHTransferGas)
	real := new(big.Int).Mul(big.NewInt(int64(constants.ETHTransferGas)), big.NewInt(3e9))
	refund := new(big.Int).Sub(GetBalance("hive:alice", "eth"), new(big.Int).Sub(start, new(big.Int).Add(big.NewInt(1e16), ProofFee("eth"))))
	if want := new(big.Int).Sub(maxWei, real); refund.Cmp(want) != 0 {
		t.Fatalf("own refund %s, want %s", refund, want)
	}
	ethInvariant(t, "after settlement")
}

// sendHome of what a swap owes home is a payout: the expected fee and nothing
// refunded to the Magi account afterwards. A plain sendHome (anyone may make
// one for a deposit that fell back to its sender) keeps the user-withdrawal
// terms: a stranger must not charge the depositor a no-refund fee.
func TestPayout_SendHomeIsAPayout(t *testing.T) {
	addr, _ := crypto.HexToAddress("0x00000000000000000000000000000000000000e2")
	holderAddr := crypto.AddressToHex(addr)
	holder := crypto.AddressToDID(addr)
	rpBridge(t, ethWei(20), holder, "hive:keeper")
	SetETHGasLimit(60_000)
	holdOwedHome(holder, "eth", big.NewInt(2e16))
	s := GetSupply("eth")
	SetSupply("eth", Supply{Active: new(big.Int).Add(s.Active, big.NewInt(2e16)), User: new(big.Int).Add(s.User, big.NewInt(2e16)), Fee: s.Fee})
	SetRelayer("hive:keeper") // the bridge's bot
	as(t, "hive:keeper", rpNow)
	out, err := HandleSendHome("address="+holderAddr+"&asset=eth&owed=1", [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("sendHome: %q %v", out, err)
	}
	ps := GetPendingSpend(0)
	fee := payoutGasFee(60_000, 1e9, poTip)
	if got := new(big.Int).Sub(new(big.Int).Sub(big.NewInt(2e16), ProofFee("eth")), ps.Amount); got.Cmp(fee) != 0 {
		t.Fatalf("sendHome fee %s, want the payout fee %s", got, fee)
	}
	before := GetBalance(holder, "eth")
	poSettle(t, ps, constants.ETHTransferGas)
	if GetBalance(holder, "eth").Cmp(before) != 0 {
		t.Fatal("sendHome's gas surplus was refunded to the depositor's Magi account")
	}
	ethInvariant(t, "after settlement")

	// A plain sendHome by a stranger: prepaid at the maximum, the unused part
	// back to the depositor's account, as before PAYOUT-1.
	rpBridge(t, ethWei(20), holder, "hive:keeper")
	SetETHGasLimit(60_000)
	markRefundable(holder, "eth", big.NewInt(2e16))
	as(t, "hive:keeper", rpNow)
	if out, err := HandleSendHome("address="+holderAddr+"&asset=eth", [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("plain sendHome: %q %v", out, err)
	}
	_, maxWei, _ := safeGasFee(60_000, 1e9, 2, poTip)
	if got := new(big.Int).Sub(big.NewInt(2e16), GetPendingSpend(0).Amount); got.Cmp(maxWei) != 0 {
		t.Fatalf("plain sendHome prepaid %s, want the maximum %s (refunded later)", got, maxWei)
	}
}

// A payout the gas reserve cannot front waits in the queue and is sent after a
// top-up.
func TestPayout_ReserveShortWaits(t *testing.T) {
	rpBridge(t, ethWei(5), rtRouter) // 0.005 ETH: below the 0.01 floor
	if out, err := rtUnmapETH(t, "hive:alice", "", rpNow); err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("payout with the reserve below its floor: %q %v, want queued", out, err)
	}
	if n := drainWith(1, [20]byte{1}, 8); n != 0 || QueueLen() != 1 {
		t.Fatalf("drained %d with the reserve short, queue %d", n, QueueLen())
	}
	addGasReserve(ethWei(20))
	s := GetSupply("eth")
	SetSupply("eth", Supply{Active: new(big.Int).Add(s.Active, ethWei(20)), User: s.User, Fee: s.Fee})
	if n := drainWith(1, [20]byte{1}, 8); n != 1 || QueueLen() != 0 {
		t.Fatalf("after the top-up: drained %d, queue %d", n, QueueLen())
	}
	ethInvariant(t, "after the drain")
}

// A queued payout whose fee no longer fits its amount (a gas spike while it
// waited) goes back to its sender at once instead of waiting: an entry waiting
// on its own terms would hold the drain's 64-entry walk (QFREEZE-1). This one
// was paid from a Magi balance (no return asset), so it goes back there.
func TestPayout_FeeAboveTheAmountGoesBackToItsSender(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	SetETHGasLimit(60_000)
	SetPendingNonce(constants.MaxInFlightWithdrawals) // queue it
	if out, err := rtUnmapETH(t, "hive:alice", "", rpNow); err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("%q %v", out, err)
	}
	SetPendingNonce(0)
	qcBaseFee(200_000_000_000) // 200 gwei: 60,000 x 302 gwei > 0.01 ETH
	if n := drainWith(1, [20]byte{1}, 8); n != 0 || QueueLen() != 0 || GetBalance("hive:alice", "eth").Cmp(big.NewInt(1e16)) != 0 {
		t.Fatalf("drained %d, queue %d, alice %s: want it back with its Magi sender", n, QueueLen(), GetBalance("hive:alice", "eth"))
	}
	ethInvariant(t, "after the refund")
}

// QFREEZE-1 regression: 70 payouts whose own max_fee is below the price (5
// accounts, under the per-account cap) cannot hold the queue: each goes back
// to its sender and a payout queued behind them is sent.
func TestPayout_OwnMaxFeeCannotFreezeTheQueue(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	SetPendingNonce(constants.MaxInFlightWithdrawals) // everything queues
	for i := 0; i < 70; i++ {
		who := "hive:grief" + strconv.Itoa(i%5)
		asContract(t, rtRouter, who, rpNow)
		if out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth",
			DeductFee: true, MaxFee: "1", RefundTo: who}, [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "queued:") {
			t.Fatalf("payout %d: %q %v", i, out, err)
		}
	}
	asContract(t, rtRouter, "hive:bob", rpNow)
	if out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth",
		DeductFee: true, RefundTo: "hive:bob"}, [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("bob's payout: %q %v", out, err)
	}
	SetPendingNonce(0)
	for i := 0; i < 4 && QueueLen() > 0; i++ {
		drainWith(1, [20]byte{1}, 8)
	}
	if QueueLen() != 0 {
		t.Fatalf("queue %d after the drains: the max_fee payouts held it", QueueLen())
	}
	if ps := GetPendingSpend(0); ps == nil || ps.RefundTo != "hive:bob" {
		t.Fatalf("issued %+v, want bob's payout", ps)
	}
	if GetBalance("hive:grief0", "eth").Cmp(big.NewInt(14e16)) != 0 {
		t.Fatalf("grief0 got back %s, want its 14 payouts (Magi-paid)", GetBalance("hive:grief0", "eth"))
	}
	ethInvariant(t, "after the drains")
}

// A queued payout of a swap paid from Hive that its user cancels is held for
// them (never on the Magi balance) and the bot swaps it back to Hive with its
// floor; nothing runs inside the cancel itself.
func TestPayout_CancelledPayoutGoesBackToHive(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
	SetPendingNonce(constants.MaxInFlightWithdrawals)
	asContract(t, rtRouter, "hive:alice", rpNow)
	out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
		RefundTo: "hive:alice", ReturnAsset: "hbd", ReturnMin: "40000"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("%q %v", out, err)
	}
	head, _ := QueueBounds()
	ok, call := true, ""
	poRouterAnswers(&ok, &call)
	defer sdk.StubSetContractCallResponder(nil)
	as(t, "hive:alice", rpNow)
	if err := HandleCancelQueuedWithdrawal(head); err != nil {
		t.Fatal(err)
	}
	if call != "" || getHeldReturn(0) == nil {
		t.Fatalf("the cancel swapped inline (%q) or held nothing", call)
	}
	if err := poBotRetry(t, 0, "1", rpNow); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(call, `"min_amount_out":"40000"`) || !strings.Contains(call, `"asset_out":"hbd"`) {
		t.Fatalf("router call %q", call)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 || QueueLen() != 0 || getHeldReturn(0) != nil {
		t.Fatal("the cancelled payout reached the Magi balance, stayed queued or stayed held")
	}
	ethInvariant(t, "after the cancel")
}

// max_fee bounds what the payout pays, not the signed maximum: a cap between
// the two is accepted (it was refused while the fee was the maximum).
func TestPayout_MaxFeeBoundsWhatItPays(t *testing.T) {
	fee := payoutGasFee(constants.ETHTransferGas, 1e9, poTip)
	_, maxWei, _ := safeGasFee(constants.ETHTransferGas, 1e9, 2, poTip)
	between := new(big.Int).Add(fee, big.NewInt(1))
	if between.Cmp(maxWei) >= 0 {
		t.Fatal("fixture: no room between the fee and the maximum")
	}
	rpBridge(t, ethWei(20), rtRouter)
	if out, err := rtUnmapETH(t, "hive:alice", between.String(), rpNow); err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("max_fee just above the payout fee: %q %v, want issued", out, err)
	}
	rpBridge(t, ethWei(20), rtRouter)
	if _, err := rtUnmapETH(t, "hive:alice", new(big.Int).Sub(fee, big.NewInt(1)).String(), rpNow); err == nil || !strings.Contains(err.Error(), "max_fee") {
		t.Fatalf("max_fee below the payout fee: %v, want refused", err)
	}
}

// return_asset: a payout of a swap paid from Hive whose L1 transfer reverts is
// swapped back to HIVE/HBD and withdrawn to the sender on Hive (THORChain's
// reverse swap), not credited to a Magi balance.

func poReturnPayout(t *testing.T, returnAsset string) *PendingSpend {
	t.Helper()
	rpBridge(t, ethWei(20), rtRouter)
	sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
	asContract(t, rtRouter, "hive:alice", rpNow)
	out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
		RefundTo: "hive:alice", ReturnAsset: returnAsset, ReturnMin: "40000"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("routed unmap with return_asset: %q %v", out, err)
	}
	ps := GetPendingSpend(0)
	if ps.ReturnAsset != returnAsset {
		t.Fatalf("pending spend return_asset %q, want %q", ps.ReturnAsset, returnAsset)
	}
	// The floor scales with what the L1 transaction carries (the fee came out).
	if want := new(big.Int).Div(new(big.Int).Mul(big.NewInt(40000), ps.Amount), big.NewInt(1e16)); ps.ReturnMin == nil || ps.ReturnMin.Cmp(want) != 0 {
		t.Fatalf("pending spend return_min %v, want %s", ps.ReturnMin, want)
	}
	return ps
}

// poBotRetry runs retryPayoutReturn as the bridge's bot (a registered relayer).
func poBotRetry(t *testing.T, id uint64, minOut string, at time.Time) error {
	t.Helper()
	SetRelayer("hive:bot")
	as(t, "hive:bot", at)
	_, err := HandleRetryPayoutReturn(id, minOut)
	return err
}

// A reverted payout is held (nothing swaps inside the confirmSpend anyone can
// wrap); the bot swaps it back to the sender on Hive with the floor, and the
// swap's output is logged for the bot's next quote.
func TestPayout_RevertedPayoutGoesBackToHive(t *testing.T) {
	ps := poReturnPayout(t, "hive")
	var call string
	sdk.StubSetContractCallResponder(func(contractId, method, payload string) *string {
		call = contractId + " " + method + " " + payload
		// The router pulls its allowance (transferFrom into the pool).
		self := "contract:" + sdk.GetEnv().ContractId
		a := GetAllowance(self, "contract:vsc1router", "eth")
		SetAllowance(self, "contract:vsc1router", "eth", new(big.Int))
		DecBalance(self, "eth", a)
		IncBalance("contract:pool", "eth", a)
		r := `{"ok":true,"result":"{\"amount_out\":\"123\"}"}`
		return &r
	})
	defer sdk.StubSetContractCallResponder(nil)
	refundRevertedWithdrawal(ps)
	if call != "" || getHeldReturn(0) == nil {
		t.Fatalf("swapped inside the revert (%q) or not held", call)
	}
	SetRelayer("hive:bot")
	as(t, "hive:bot", rpNow)
	out, err := HandleRetryPayoutReturn(0, "1")
	if err != nil || out != "123" {
		t.Fatalf("retry: %q %v, want the swap's output 123", out, err)
	}
	if !strings.HasPrefix(call, "vsc1router execute ") || !strings.Contains(call, `"asset_out":"hive"`) ||
		!strings.Contains(call, `"recipient":"hive:alice"`) || !strings.Contains(call, `"destination_chain":"HIVE"`) ||
		!strings.Contains(call, `"amount_in":"`+ps.Amount.String()+`"`) ||
		!strings.Contains(call, `"min_amount_out":"`+ps.ReturnMin.String()+`"`) {
		t.Fatalf("router call %q (want the floor %s)", call, ps.ReturnMin)
	}
	logged := false
	for _, l := range sdk.TestLogs() {
		logged = logged || (strings.HasPrefix(l, "payoutreturn|id=0|t=hive:alice|") && strings.HasSuffix(l, "|o=123"))
	}
	if !logged {
		t.Fatalf("no payoutreturn log with the output: %v", sdk.TestLogs())
	}
	self := "contract:" + sdk.GetEnv().ContractId
	if GetBalance("hive:alice", "eth").Sign() != 0 || GetBalance(self, "eth").Sign() != 0 {
		t.Fatalf("alice %s, bridge %s: want nothing left on Magi", GetBalance("hive:alice", "eth"), GetBalance(self, "eth"))
	}
	if GetBalance("contract:pool", "eth").Cmp(ps.Amount) != 0 {
		t.Fatal("the router did not get the refund")
	}
	if GetAllowance(self, "contract:vsc1router", "eth").Sign() != 0 {
		t.Fatal("allowance left behind")
	}
	ethInvariant(t, "after the reverse swap")
}

// poRouterAnswers makes the router refuse (ok=false) or take its allowance
// (ok=true); it records the last call.
func poRouterAnswers(ok *bool, call *string) {
	sdk.StubSetContractCallResponder(func(contractId, method, payload string) *string {
		*call = payload
		if !*ok {
			r := `{"ok":false,"error_code":"x","error":"slippage tolerance exceeded"}`
			return &r
		}
		self := "contract:" + sdk.GetEnv().ContractId
		a := GetAllowance(self, "contract:vsc1router", "eth")
		SetAllowance(self, "contract:vsc1router", "eth", new(big.Int))
		DecBalance(self, "eth", a)
		IncBalance("contract:pool", "eth", a)
		r := `{"ok":true,"result":"{}"}`
		return &r
	})
}

func poNothingOnMagi(t *testing.T, ps *PendingSpend) {
	t.Helper()
	self := "contract:" + sdk.GetEnv().ContractId
	if b := GetBalance(ps.RefundTo, ps.Asset); b.Sign() != 0 {
		t.Fatalf("%s holds %s %s on Magi", ps.RefundTo, b, ps.Asset)
	}
	if GetBalance(self, ps.Asset).Sign() != 0 || GetAllowance(self, "contract:vsc1router", ps.Asset).Sign() != 0 {
		t.Fatal("something left on the bridge's own account")
	}
}

// A failed payout is held for the sender, never credited to a Magi balance
// (owner 11-21: a failure goes to the sender or the recipient only).
func TestPayout_RefusedSwapBackIsHeldNotCredited(t *testing.T) {
	ps := poReturnPayout(t, "hbd")
	ok, call := false, ""
	poRouterAnswers(&ok, &call)
	defer sdk.StubSetContractCallResponder(nil)
	refundRevertedWithdrawal(ps)
	poNothingOnMagi(t, ps)
	if GetBalance(constants.PayoutReturnHoldAccount, "eth").Cmp(ps.Amount) != 0 {
		t.Fatalf("hold %s, want %s", GetBalance(constants.PayoutReturnHoldAccount, "eth"), ps.Amount)
	}
	h := getHeldReturn(0)
	if h == nil || h.To != "hive:alice" || h.ReturnAsset != "hbd" || h.Amount.Cmp(ps.Amount) != 0 || h.Floor.Cmp(ps.ReturnMin) != 0 || h.HeldAt == 0 {
		t.Fatalf("held return %+v", h)
	}
	found := false
	for _, l := range sdk.TestLogs() {
		found = found || l == "payoutreturnheld|id=0|n=0|t=hive:alice|a=eth|d="+ps.Amount.String()+"|ra=hbd|m="+ps.ReturnMin.String()
	}
	if !found {
		t.Fatalf("no payoutreturnheld log: %v", sdk.TestLogs())
	}
	ethInvariant(t, "after the hold")
}

// Only the bot swaps a held return back (a call anyone could make could be
// wrapped and skimmed). For a day it never goes below the floor; then the
// floor drops 5% a day, so nothing waits forever.
func TestPayout_OnlyTheBotSwapsAHeldReturnBack(t *testing.T) {
	ps := poReturnPayout(t, "hbd")
	ok, call := false, ""
	poRouterAnswers(&ok, &call)
	defer sdk.StubSetContractCallResponder(nil)
	refundRevertedWithdrawal(ps)
	as(t, "hive:anyone", rpNow)
	if _, err := HandleRetryPayoutReturn(0, "999999999"); err == nil || !strings.Contains(err.Error(), "only the bridge's bot") {
		t.Fatalf("anyone's retry: %v", err)
	}
	for _, bad := range []string{"", "0", "-5", "x"} {
		if err := poBotRetry(t, 0, bad, rpNow); err == nil {
			t.Fatalf("min_out %q accepted", bad)
		}
	}
	// Under the floor for a day: the floor is used; refused, nothing moves.
	if err := poBotRetry(t, 0, "5", rpNow.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "did not run") {
		t.Fatalf("retry while the router refuses: %v", err)
	}
	if !strings.Contains(call, `"min_amount_out":"`+ps.ReturnMin.String()+`"`) {
		t.Fatalf("router call %q: want the floor while it holds", call)
	}
	if GetBalance(constants.PayoutReturnHoldAccount, "eth").Cmp(ps.Amount) != 0 || getHeldReturn(0) == nil {
		t.Fatal("a refused retry changed the hold")
	}
	// After the first day the floor drops 5% a day; after 21 days it is gone
	// and the bot's own price is used.
	day2 := new(big.Int).Div(new(big.Int).Mul(ps.ReturnMin, big.NewInt(19)), big.NewInt(20))
	if err := poBotRetry(t, 0, "5", rpNow.Add(25*time.Hour)); err == nil {
		t.Fatal("the refused swap back ran")
	}
	if !strings.Contains(call, `"min_amount_out":"`+day2.String()+`"`) {
		t.Fatalf("router call %q: want the floor less 5%% (%s) on the second day", call, day2)
	}
	ok = true
	if err := poBotRetry(t, 0, "5", rpNow.Add(21*24*time.Hour+time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(call, `"min_amount_out":"5"`) || !strings.Contains(call, `"recipient":"hive:alice"`) {
		t.Fatalf("router call %q: want the bot's price once the floor is gone, to alice", call)
	}
	if GetBalance(constants.PayoutReturnHoldAccount, "eth").Sign() != 0 || getHeldReturn(0) != nil {
		t.Fatal("the return is still held")
	}
	if payoutReturnCounter(constants.PayoutReturnHeadKey) != 1 {
		t.Fatalf("head %d, want 1", payoutReturnCounter(constants.PayoutReturnHeadKey))
	}
	poNothingOnMagi(t, ps)
	if err := poBotRetry(t, 0, "5", rpNow.Add(22*24*time.Hour)); err == nil {
		t.Fatal("a sent return was retried again")
	}
	ethInvariant(t, "after the retry")
}

// The sender takes a held return back at a price of their own; nobody else can.
func TestPayout_HeldReturnIsReleasedByItsSenderOnly(t *testing.T) {
	ps := poReturnPayout(t, "hbd")
	ok, call := false, ""
	poRouterAnswers(&ok, &call)
	defer sdk.StubSetContractCallResponder(nil)
	refundRevertedWithdrawal(ps)
	ok = true
	as(t, "hive:bob", rpNow)
	if err := HandleReleasePayoutReturn(0, "100", "", [20]byte{1}, 1); err == nil || !strings.Contains(err.Error(), "only hive:alice") {
		t.Fatalf("bob released alice's return: %v", err)
	}
	asContract(t, rtRouter, "hive:alice", rpNow)
	if err := HandleReleasePayoutReturn(0, "100", "", [20]byte{1}, 1); err == nil {
		t.Fatal("a contract released it with alice as the sender")
	}
	as(t, "hive:alice", rpNow)
	for _, bad := range []string{"", "0", "-5", "x"} {
		if err := HandleReleasePayoutReturn(0, bad, "", [20]byte{1}, 1); err == nil {
			t.Fatalf("min_out %q accepted", bad)
		}
	}
	if err := HandleReleasePayoutReturn(0, "100", "", [20]byte{1}, 1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(call, `"min_amount_out":"100"`) {
		t.Fatalf("router call %q: want alice's own floor", call)
	}
	if getHeldReturn(0) != nil || GetBalance(constants.PayoutReturnHoldAccount, "eth").Sign() != 0 {
		t.Fatal("still held")
	}
	poNothingOnMagi(t, ps)
	ethInvariant(t, "after the release")
}

// No router set: held, not credited. A paused bridge does not run returns.
func TestPayout_NoRouterHoldsAndPauseWaits(t *testing.T) {
	ps := poReturnPayout(t, "hive")
	sdk.StateDeleteObject(constants.RouterContractIdKey)
	refundRevertedWithdrawal(ps)
	poNothingOnMagi(t, ps)
	if h := getHeldReturn(0); h == nil || h.Amount.Cmp(ps.Amount) != 0 {
		t.Fatalf("held %+v", h)
	}
	sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
	sdk.StateSetObject(constants.PausedKey, "1")
	as(t, "hive:alice", rpNow)
	if _, err := HandleRetryPayoutReturn(0, "1"); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatalf("retry while paused: %v", err)
	}
	if err := HandleReleasePayoutReturn(0, "1", "", [20]byte{1}, 1); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatalf("release while paused: %v", err)
	}
	ethInvariant(t, "while held")
}

// The router takes only part: the rest stays held with its share of the floor.
func TestPayout_PartOfASwapBackIsHeld(t *testing.T) {
	ps := poReturnPayout(t, "hbd")
	half := new(big.Int).Div(ps.Amount, big.NewInt(2))
	sdk.StubSetContractCallResponder(func(_, _, _ string) *string {
		self := "contract:" + sdk.GetEnv().ContractId
		a := GetAllowance(self, "contract:vsc1router", "eth")
		SetAllowance(self, "contract:vsc1router", "eth", new(big.Int).Sub(a, half))
		DecBalance(self, "eth", half)
		IncBalance("contract:pool", "eth", half)
		r := `{"ok":true,"result":"{}"}`
		return &r
	})
	defer sdk.StubSetContractCallResponder(nil)
	refundRevertedWithdrawal(ps)
	if err := poBotRetry(t, 0, "1", rpNow); err != nil {
		t.Fatal(err)
	}
	left := new(big.Int).Sub(ps.Amount, half)
	h := getHeldReturn(0)
	if h == nil || h.Amount.Cmp(left) != 0 || h.Floor.Cmp(scaleFloor(ps.ReturnMin, left, ps.Amount)) != 0 {
		t.Fatalf("held %+v, want %s with its share of the floor", h, left)
	}
	poNothingOnMagi(t, ps)
	ethInvariant(t, "after a partial swap back")
}

// Cancelled queued payouts are held; the bot's retries clear them, and the head
// steps past returns sent out of order.
func TestPayout_CancelledPayoutRefusedSwapBackIsHeld(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
	SetPendingNonce(constants.MaxInFlightWithdrawals)
	asContract(t, rtRouter, "hive:alice", rpNow)
	for i := 0; i < 2; i++ {
		if out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
			RefundTo: "hive:alice", ReturnAsset: "hbd", ReturnMin: "40000"}, [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "queued:") {
			t.Fatalf("%q %v", out, err)
		}
	}
	ok, call := true, ""
	poRouterAnswers(&ok, &call)
	defer sdk.StubSetContractCallResponder(nil)
	as(t, "hive:alice", rpNow)
	head, _ := QueueBounds()
	for i := uint64(0); i < 2; i++ {
		if err := HandleCancelQueuedWithdrawal(head + i); err != nil {
			t.Fatal(err)
		}
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 || getHeldReturn(0) == nil || getHeldReturn(1) == nil {
		t.Fatal("a cancelled payout reached the Magi balance or was not held")
	}
	if err := poBotRetry(t, 1, "1", rpNow); err != nil {
		t.Fatal(err)
	}
	if payoutReturnCounter(constants.PayoutReturnHeadKey) != 0 {
		t.Fatal("head moved past a return still held")
	}
	if err := poBotRetry(t, 0, "1", rpNow); err != nil {
		t.Fatal(err)
	}
	if payoutReturnCounter(constants.PayoutReturnHeadKey) != 2 {
		t.Fatalf("head %d, want 2", payoutReturnCounter(constants.PayoutReturnHeadKey))
	}
	ethInvariant(t, "after both returns")
}

func TestPayout_ReturnAssetIsForAContractPayingAHiveSender(t *testing.T) {
	cases := []struct {
		name, caller, refundTo, asset, want string
	}{
		{"a user's own withdrawal", "hive:alice", "", "hive", "return_asset is for a contract"},
		{"refund_to not on Hive", rtRouter, "did:pkh:eip155:1:0x00000000000000000000000000000000000000e3", "hive", "return_asset is for a contract"},
		{"not HIVE or HBD", rtRouter, "hive:alice", "btc", "must be hive or hbd"},
	}
	cases = append(cases, struct{ name, caller, refundTo, asset, want string }{"no floor", rtRouter, "hive:alice", "hive", "positive return_min"})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rpBridge(t, ethWei(20), tc.caller)
			if strings.HasPrefix(tc.caller, "contract:") {
				asContract(t, tc.caller, "hive:alice", rpNow)
			} else {
				as(t, tc.caller, rpNow)
			}
			min := "1"
			if tc.name == "no floor" {
				min = ""
			}
			_, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
				RefundTo: tc.refundTo, ReturnAsset: tc.asset, ReturnMin: min}, [20]byte{1}, 1)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v, want %q", err, tc.want)
			}
		})
	}
}

// getInfo's payout_gas_fee is exactly what a payout then pays, so a wallet can
// show what arrives.
func TestPayout_PayoutGasFeeIsWhatAPayoutPays(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	SetETHGasLimit(60_000)
	quoted := PayoutGasFee("eth", 0)
	if _, err := rtUnmapETH(t, "hive:alice", "", rpNow); err != nil {
		t.Fatal(err)
	}
	if paid := new(big.Int).Sub(big.NewInt(1e16), GetPendingSpend(0).Amount); quoted == nil || paid.Cmp(quoted) != 0 {
		t.Fatalf("quoted %v, paid %s", quoted, paid)
	}
	var tok [20]byte
	tok[19] = 0xc0
	if err := RegisterTokenFull(1, tok, "USDC", 6, 3_000_000, 0, 200_000); err != nil {
		t.Fatal(err)
	}
	SetTokenGasRate("USDC", big.NewInt(1_760_000_000))
	if got := PayoutGasFee("USDC", 0); got == nil || got.Cmp(big.NewInt(400_400)) != 0 {
		t.Fatalf("USDC payout_gas_fee %v, want 400400", got)
	}
	// Priced at the gas_limit the wallet sends: exactly what that payout pays.
	SetPendingNonce(1)
	SetConfirmedNonce(1)
	quoted25 := PayoutGasFee("eth", 25_200)
	asContract(t, rtRouter, "hive:alice", rpNow)
	if _, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
		RefundTo: "hive:alice", GasLimit: 25_200}, [20]byte{1}, 1); err != nil {
		t.Fatal(err)
	}
	if paid := new(big.Int).Sub(big.NewInt(1e16), GetPendingSpend(1).Amount); quoted25 == nil || paid.Cmp(quoted25) != 0 || quoted25.Cmp(quoted) >= 0 {
		t.Fatalf("quoted at 25,200 %v, paid %s (default-priced %s)", quoted25, paid, quoted)
	}
	if PayoutGasFee("eth", constants.MaxPayoutGasLimit+1) != nil {
		t.Fatal("a gas_limit a payout may not ask for was priced")
	}
	if PayoutGasFee("nope", 0) != nil {
		t.Fatal("an unknown asset has no fee")
	}
	as(t, "hive:alice", qfStale)
	if PayoutGasFee("eth", 0) != nil {
		t.Fatal("without a fresh header a payout is refused: no fee")
	}
}

// A rolled payout (its nonce spent by the roll's 0-value self-transfer) of a
// swap paid from Hive goes back to Hive as a revert does, not to the Magi
// balance.
// A payout a roll kept from L1 (its nonce was spent, it can never mine) is
// sent again to the same address. Like every send it pays its own gas out of
// its amount; the reserve only lends the signed maximum's gap and gets the
// unused part back. Nothing goes back or to a Magi balance.
func TestPayout_RolledPayoutIsSentAgain(t *testing.T) {
	ps := poReturnPayout(t, "hbd")
	if !ps.Payout || ps.Attempt != 0 {
		t.Fatalf("issued payout %+v: want Payout, attempt 0", ps)
	}
	routerBefore := GetBalance(rtRouter, "eth")
	called := false
	sdk.StubSetContractCallResponder(func(_, _, _ string) *string { called = true; r := `{"ok":true,"result":"{}"}`; return &r })
	defer sdk.StubSetContractCallResponder(nil)
	refundDroppedWithdrawal(ps, 1)
	if called {
		t.Fatal("a rolled payout was swapped back")
	}
	head, _ := QueueBounds()
	q := GetQueued(head)
	if q == nil || !q.DeductFee || q.Attempt != 1 || q.To != ps.To || q.Amount.Cmp(ps.Amount) != 0 ||
		q.RefundTo != ps.RefundTo || q.ReturnAsset != "hbd" || q.ReturnMin.Cmp(ps.ReturnMin) != 0 {
		t.Fatalf("re-send %+v, want the same payout again (attempt 1)", q)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 || GetBalance(rtRouter, "eth").Cmp(routerBefore) != 0 {
		t.Fatal("the re-send credited or charged someone")
	}
	ethInvariant(t, "after the roll")
	SetPendingNonce(1)
	SetConfirmedNonce(1)
	reserveBefore := getGasReserve()
	if n := drainWith(1, [20]byte{1}, 8); n != 1 {
		t.Fatalf("drained %d", n)
	}
	again := GetPendingSpend(1)
	fee := payoutGasFee(constants.ETHTransferGas, 1e9, 2_000_000_000)
	if again == nil || new(big.Int).Add(again.Amount, fee).Cmp(ps.Amount) != 0 || again.Attempt != 1 || !again.Payout || again.ReturnAsset != "hbd" {
		t.Fatalf("second send %+v: want the value less its own gas %s, attempt 1", again, fee)
	}
	_, maxWei, _ := safeGasFee(constants.ETHTransferGas, 1e9, 2, 2_000_000_000)
	if lent := new(big.Int).Sub(reserveBefore, getGasReserve()); lent.Cmp(new(big.Int).Sub(maxWei, fee)) != 0 {
		t.Fatalf("the reserve lent %s, want only the gap to the signed maximum %s", lent, new(big.Int).Sub(maxWei, fee))
	}
	ethInvariant(t, "after the second send")
}

// The third roll (attempts used up) goes back to the sender: held for the
// bot's swap back, nothing swapped inside the confirmSpend.
func TestPayout_ThirdRollGoesBackToTheSender(t *testing.T) {
	ps := poReturnPayout(t, "hbd")
	ps.Attempt = constants.MaxPayoutAttempts - 1
	ok, call := true, ""
	poRouterAnswers(&ok, &call)
	defer sdk.StubSetContractCallResponder(nil)
	refundDroppedWithdrawal(ps, 1)
	if QueueLen() != 0 || call != "" || getHeldReturn(0) == nil || getHeldReturn(0).ReturnAsset != "hbd" {
		t.Fatalf("queue %d, router call %q, held %+v: want it held after %d sends", QueueLen(), call, getHeldReturn(0), constants.MaxPayoutAttempts)
	}
	poNothingOnMagi(t, ps)
	ethInvariant(t, "after the last roll")
}

// A re-send is not bounced by the queue caps or the rate limit (the value was
// counted when first withdrawn): with the sender's 16 queued and the block's
// withdrawal cap spent it still queues, and the roll's settlement goes on.
func TestPayout_ResendIgnoresTheQueueCapsAndRateLimit(t *testing.T) {
	ps := poReturnPayout(t, "hbd")
	SetPendingNonce(constants.MaxInFlightWithdrawals)
	asContract(t, rtRouter, "hive:alice", rpNow)
	for i := uint64(0); i < constants.MaxQueuedPerAccount; i++ {
		if out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
			RefundTo: "hive:alice", ReturnAsset: "hbd", ReturnMin: "40000"}, [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "queued:") {
			t.Fatalf("fill %d: %q %v", i, out, err)
		}
	}
	if _, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
		RefundTo: "hive:alice", ReturnAsset: "hbd", ReturnMin: "40000"}, [20]byte{1}, 1); err == nil {
		t.Fatal("a 17th withdrawal was queued: the cap is not in force, the test proves nothing")
	}
	called := false
	sdk.StubSetContractCallResponder(func(_, _, _ string) *string { called = true; r := `{"ok":true,"result":"{}"}`; return &r })
	defer sdk.StubSetContractCallResponder(nil)
	queued := QueueLen()
	refundDroppedWithdrawal(ps, 1)
	_, tail := QueueBounds()
	q := GetQueued(tail - 1)
	if called || QueueLen() != queued+1 || q == nil || q.Attempt != 1 || q.Amount.Cmp(ps.Amount) != 0 {
		t.Fatalf("swap back %v, queue %d (was %d), last %+v: want the re-send queued past the cap", called, QueueLen(), queued, q)
	}
	ethInvariant(t, "after the re-send past the cap")
}

// A user's own withdrawal that a roll kept from L1 is refunded to the user as
// before (a Magi sender); only a contract's payout is sent again.
func TestPayout_OwnWithdrawalRollRefundsAsBefore(t *testing.T) {
	rpBridge(t, ethWei(20), "hive:alice")
	as(t, "hive:alice", rpNow)
	if out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth"}, [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("%q %v", out, err)
	}
	ps := GetPendingSpend(0)
	if ps.Payout {
		t.Fatal("an own withdrawal marked as a payout")
	}
	before := GetBalance("hive:alice", "eth")
	refundDroppedWithdrawal(ps, 1)
	if QueueLen() != 0 || GetBalance("hive:alice", "eth").Cmp(new(big.Int).Add(before, ps.Amount)) != 0 {
		t.Fatal("an own withdrawal's roll was not refunded to its owner")
	}
	ethInvariant(t, "after the own roll")
}

// A rolled token payout is sent again and pays its own gas in the token, out
// of its amount, like any payout (the reserve only fronts the ETH).
func TestPayout_RolledTokenPayoutPaysItsOwnGas(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	var tok [20]byte
	tok[19] = 0xc0
	if err := RegisterTokenFull(1, tok, "USDC", 6, 1000, 0, 200_000); err != nil {
		t.Fatal(err)
	}
	SetTokenGasRate("USDC", big.NewInt(1_760_000_000))
	IncBalance(rtRouter, "USDC", big.NewInt(5_000_000))
	s := GetSupply("USDC")
	SetSupply("USDC", Supply{Active: new(big.Int).Add(nz(s.Active), big.NewInt(5_000_000)), User: new(big.Int).Add(nz(s.User), big.NewInt(5_000_000)), Fee: nz(s.Fee)})
	asContract(t, rtRouter, "hive:alice", rpNow)
	if out, err := HandleUnmapERC20(&TransferParams{Amount: "3000000", To: qfTo, Asset: "USDC",
		TokenAddress: "0x00000000000000000000000000000000000000c0", RefundTo: "hive:alice", ReturnAsset: "hbd", ReturnMin: "2000"}, [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("%q %v", out, err)
	}
	ps := GetPendingSpend(0)
	refundDroppedWithdrawal(ps, 1)
	SetPendingNonce(1)
	SetConfirmedNonce(1)
	feeBefore := GetBalance(constants.TokenGasFeeRecipient, "USDC")
	if n := drainWith(1, [20]byte{1}, 8); n != 1 {
		t.Fatalf("drained %d", n)
	}
	again := GetPendingSpend(1)
	paid := new(big.Int).Sub(GetBalance(constants.TokenGasFeeRecipient, "USDC"), feeBefore)
	if again == nil || paid.Sign() <= 0 || new(big.Int).Add(again.Amount, paid).Cmp(ps.Amount) != 0 || again.Attempt != 1 {
		t.Fatalf("second send %+v, token gas fee %s: want %s less its own gas fee", again, paid, ps.Amount)
	}
}

// An ETH payout closed on its inclusion proof keeps where its refund goes back
// to: a revert settled from its receipt later still swaps back to Hive.
func TestPayout_InclusionCloseKeepsTheReturn(t *testing.T) {
	ps := poReturnPayout(t, "hive")
	rec := inclusionClose{Nonce: ps.Nonce, Amount: ps.Amount, From: ps.From, RefundTo: ps.RefundTo,
		ReturnAsset: ps.ReturnAsset, ReturnMin: ps.ReturnMin}
	b, _ := json.Marshal(&rec)
	var back inclusionClose
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if sp := back.spend(); sp.ReturnAsset != "hive" || sp.ReturnMin == nil || sp.ReturnMin.Cmp(ps.ReturnMin) != 0 {
		t.Fatalf("spend from the record: %+v", sp)
	}
}

// A fee-on-top payout that waits in the queue keeps its contract's default cap
// set aside; when it is sent, the unused part goes back to that contract, not
// to the user's Magi balance.
func TestPayout_QueuedFeeOnTopSurplusGoesBackToTheContract(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	SetPendingNonce(constants.MaxInFlightWithdrawals)
	asContract(t, rtRouter, "hive:alice", rpNow)
	routerBefore := GetBalance(rtRouter, "eth")
	if out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", RefundTo: "hive:alice"}, [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("%q %v", out, err)
	}
	SetPendingNonce(0)
	if n := drainWith(1, [20]byte{1}, 8); n != 1 {
		t.Fatalf("drained %d", n)
	}
	fee := payoutGasFee(constants.ETHTransferGas, 1e9, 2_000_000_000)
	paid := new(big.Int).Sub(routerBefore, GetBalance(rtRouter, "eth"))
	if want := new(big.Int).Add(big.NewInt(1e16), new(big.Int).Add(fee, ProofFee("eth"))); paid.Cmp(want) != 0 {
		t.Fatalf("router paid %s net, want amount + payout fee + proof fee %s", paid, want)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 {
		t.Fatal("the unused cap reached alice's Magi balance")
	}
	ethInvariant(t, "after the drain")
}

// The exit when no pool can take a held return back: its sender has the held
// asset itself sent to an Ethereum address they pick, as a payout. Its own
// amount pays the proving fee and the gas, so other senders' held value is
// never touched; nobody else can do it.
func TestPayout_HeldReturnReleasedOnEthereum(t *testing.T) {
	ps := poReturnPayout(t, "hbd")
	ok, call := false, ""
	poRouterAnswers(&ok, &call)
	defer sdk.StubSetContractCallResponder(nil)
	refundRevertedWithdrawal(ps)
	// A second sender's return is held too: the release must not touch it.
	holdPayoutReturn("hive:bob", "eth", ethWei(3), "hbd", big.NewInt(9000), "n=x")
	s := GetSupply("eth")
	SetSupply("eth", Supply{Active: new(big.Int).Add(s.Active, ethWei(3)), User: new(big.Int).Add(s.User, ethWei(3)), Fee: s.Fee})
	SetPendingNonce(0)
	as(t, "hive:bob", rpNow)
	if err := HandleReleasePayoutReturn(0, "", qfTo, [20]byte{1}, 1); err == nil {
		t.Fatal("bob sent alice's return to his address")
	}
	as(t, "hive:alice", rpNow)
	// Return 0 (a 0.01 ETH payout less its fees) is below the minimum ETH
	// withdrawal: this exit has none (it pays its own fees), so it goes out.
	if err := HandleReleasePayoutReturn(0, "", qfTo, [20]byte{1}, 1); err != nil {
		t.Fatalf("a small release: %v", err)
	}
	// A larger return for alice (id 2).
	holdPayoutReturn("hive:alice", "eth", ethWei(50), "hbd", big.NewInt(150000), "n=y")
	s = GetSupply("eth")
	SetSupply("eth", Supply{Active: new(big.Int).Add(s.Active, ethWei(50)), User: new(big.Int).Add(s.User, ethWei(50)), Fee: s.Fee})
	held := ethWei(3) // bob's
	if err := HandleReleasePayoutReturn(2, "", "0x0000000000000000000000000000000000000000", [20]byte{1}, 1); err == nil {
		t.Fatal("released to the zero address")
	}
	if err := HandleReleasePayoutReturn(2, "", qfTo, [20]byte{1}, 1); err != nil {
		t.Fatal(err)
	}
	if getHeldReturn(2) != nil || getHeldReturn(0) != nil || getHeldReturn(1) == nil {
		t.Fatal("wrong returns released")
	}
	if GetBalance(constants.PayoutReturnHoldAccount, "eth").Cmp(held) != 0 {
		t.Fatalf("hold %s, want %s: the others' held value must be untouched", GetBalance(constants.PayoutReturnHoldAccount, "eth"), held)
	}
	var out *PendingSpend
	for n := uint64(0); n < constants.MaxInFlightWithdrawals && out == nil; n++ {
		if p := GetPendingSpend(n); p != nil && strings.EqualFold(p.To, qfTo) && p.From == constants.PayoutReturnHoldAccount {
			out = p
		}
	}
	if out == nil || out.RefundTo != "hive:alice" || out.ReturnAsset != "hbd" || out.ReturnMin == nil || out.ReturnMin.Sign() <= 0 {
		t.Fatalf("the Ethereum release %+v must keep alice as refund_to with its return", out)
	}
	if !strings.EqualFold(out.To, qfTo) {
		t.Fatalf("sent to %s", out.To)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 {
		t.Fatal("something reached alice's Magi balance")
	}
	ethInvariant(t, "after the Ethereum release")
	// It reverts too: back to alice on Hive, or held again; never her balance.
	refundRevertedWithdrawal(out)
	if GetBalance("hive:alice", "eth").Sign() != 0 || getHeldReturn(3) == nil {
		t.Fatal("the reverted release did not go back to the hold")
	}
	ethInvariant(t, "after the release reverted")
}

// A payout's gas_limit is capped (MaxPayoutGasLimit); an own withdrawal keeps
// the bridge's limit.
func TestPayout_GasLimitIsCapped(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	asContract(t, rtRouter, "hive:alice", rpNow)
	_, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
		RefundTo: "hive:alice", GasLimit: constants.MaxPayoutGasLimit + 1}, [20]byte{1}, 1)
	if err == nil || !strings.Contains(err.Error(), "at most 300000") {
		t.Fatalf("payout gas_limit above the cap: %v", err)
	}
	if out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
		RefundTo: "hive:alice", GasLimit: constants.MaxPayoutGasLimit}, [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("payout at the cap: %q %v", out, err)
	}
	IncBalance("hive:alice", "eth", ethWei(30))
	s := GetSupply("eth")
	SetSupply("eth", Supply{Active: new(big.Int).Add(s.Active, ethWei(30)), User: new(big.Int).Add(s.User, ethWei(30)), Fee: s.Fee})
	as(t, "hive:alice", rpNow)
	if _, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", GasLimit: 500_000}, [20]byte{1}, 1); err != nil {
		t.Fatalf("an own withdrawal at 500,000 gas: %v", err)
	}
}

// A queued payout of a Hive-paid swap that the drain refuses for any reason goes
// back to Hive or is held, never to the Magi balance.
func TestPayout_RefundQueuedPayoutIsReturned(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
	SetPendingNonce(constants.MaxInFlightWithdrawals)
	asContract(t, rtRouter, "hive:alice", rpNow)
	if out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
		RefundTo: "hive:alice", ReturnAsset: "hbd", ReturnMin: "40000"}, [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("%q %v", out, err)
	}
	ok, call := false, ""
	poRouterAnswers(&ok, &call)
	defer sdk.StubSetContractCallResponder(nil)
	head, _ := QueueBounds()
	refundQueued(head, GetQueued(head), "test")
	if GetBalance("hive:alice", "eth").Sign() != 0 || getHeldReturn(0) == nil {
		t.Fatal("a refused queued payout reached the Magi balance")
	}
	ethInvariant(t, "after the queue refund")
}

// The Ethereum exit for a held token return (USDC): the token's own address is
// signed, the hold pays for itself, nothing reaches a Magi balance.
func TestPayout_HeldTokenReturnReleasedOnEthereum(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	var tok [20]byte
	tok[19] = 0xc0
	if err := RegisterToken(1, tok, "USDC", 6, 1000); err != nil {
		t.Fatal(err)
	}
	amt := big.NewInt(5_000_000) // 5 USDC
	holdPayoutReturn("hive:alice", "USDC", amt, "hbd", big.NewInt(4000), "n=z")
	s := GetSupply("USDC")
	SetSupply("USDC", Supply{Active: new(big.Int).Add(nz(s.Active), amt), User: new(big.Int).Add(nz(s.User), amt), Fee: nz(s.Fee)})
	as(t, "hive:alice", rpNow)
	if err := HandleReleasePayoutReturn(0, "", qfTo, [20]byte{1}, 1); err != nil {
		t.Fatal(err)
	}
	ps := GetPendingSpend(0)
	if ps == nil || ps.Asset != "USDC" || ps.From != constants.PayoutReturnHoldAccount || ps.RefundTo != "hive:alice" || ps.ReturnAsset != "hbd" {
		t.Fatalf("token release %+v", ps)
	}
	if !strings.EqualFold(ps.TokenAddress, "0x00000000000000000000000000000000000000c0") {
		t.Fatalf("signed token %s, want the USDC contract", ps.TokenAddress)
	}
	if GetBalance(constants.PayoutReturnHoldAccount, "USDC").Sign() != 0 || GetBalance("hive:alice", "USDC").Sign() != 0 {
		t.Fatal("left on the hold or credited to alice")
	}
}

func nz(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return v
}

// SENDER-REFUND-1: a reverted payout of a swap paid with Bitcoin goes back as
// BTC to the sender's Bitcoin address (router destination BTC), or is held for
// that identity, which alone may release it.
const poBtcSender = "did:pkh:bip122:000000000019d6689c085ae165831e93:bc1qf87mytrp3dj9sm2y2yensj3g454n3p6k2t6sr5"

func TestPayout_BitcoinSenderGetsItBackOnBitcoin(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
	asContract(t, rtRouter, "hive:alice", rpNow)
	if _, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
		RefundTo: poBtcSender, ReturnAsset: "hbd", ReturnMin: "40000"}, [20]byte{1}, 1); err == nil || !strings.Contains(err.Error(), "must be btc") {
		t.Fatalf("hbd for a Bitcoin sender: %v", err)
	}
	if _, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
		RefundTo: "hive:alice", ReturnAsset: "btc", ReturnMin: "40000"}, [20]byte{1}, 1); err == nil {
		t.Fatal("btc for a hive: sender was accepted")
	}
	out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", DeductFee: true,
		RefundTo: poBtcSender, ReturnAsset: "btc", ReturnMin: "26000"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("%q %v", out, err)
	}
	ps := GetPendingSpend(0)
	ok, call := false, ""
	poRouterAnswers(&ok, &call)
	defer sdk.StubSetContractCallResponder(nil)
	refundRevertedWithdrawal(ps)
	if call != "" {
		t.Fatalf("swapped inside the revert: %q", call)
	}
	// The bot swaps it back to BTC for the sender's Bitcoin address (refused
	// here: it stays held).
	if err := poBotRetry(t, 0, "1", rpNow); err == nil {
		t.Fatal("the refused swap back ran")
	}
	if !strings.Contains(call, `"asset_out":"btc"`) || !strings.Contains(call, `"destination_chain":"BTC"`) ||
		!strings.Contains(call, `"recipient":"bc1qf87mytrp3dj9sm2y2yensj3g454n3p6k2t6sr5"`) ||
		!strings.Contains(call, `"min_amount_out":"`+ps.ReturnMin.String()+`"`) {
		t.Fatalf("router call %q", call)
	}
	h := getHeldReturn(0)
	if h == nil || h.To != poBtcSender || h.ReturnAsset != "btc" {
		t.Fatalf("held %+v", h)
	}
	if GetBalance(poBtcSender, "eth").Sign() != 0 {
		t.Fatal("credited to the Bitcoin identity's Magi balance")
	}
	as(t, "hive:alice", rpNow)
	if err := HandleReleasePayoutReturn(0, "1", "", [20]byte{1}, 1); err == nil {
		t.Fatal("someone else released it")
	}
	as(t, poBtcSender, rpNow)
	ok = true
	if err := HandleReleasePayoutReturn(0, "1", "", [20]byte{1}, 1); err != nil {
		t.Fatal(err)
	}
	if getHeldReturn(0) != nil {
		t.Fatal("still held")
	}
	ethInvariant(t, "after the Bitcoin return")
}

// poFreshHeader stores an L1 header stamped at `at` as the pricing header.
func poFreshHeader(at time.Time) {
	hdr := (&blocklist.EthBlockHeader{BlockNumber: 100, BaseFeePerGas: 1e9, GasLimit: 30_000_000, Timestamp: uint64(at.Unix()), ChainId: 1}).Serialize()
	sdk.StubSetContractReadResponder(func(contractId, key string) *string {
		switch key {
		case "h":
			h := "100"
			return &h
		case "b-100":
			return &hdr
		}
		return nil
	})
}

// A contract's fee-on-top payout through unmapFrom that queues behind others
// keeps the cap it set aside: a fee that rises within the cap while it waits
// is paid (the unused part goes back to the owner at issue), it is not sent
// back for a one-block snapshot of the fee.
func TestPayout_UnmapFromFeeOnTopKeepsItsCap(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter, "hive:carol")
	SetAllowance("hive:carol", rtRouter, "eth", ethWei(1000))
	SetPendingNonce(constants.MaxInFlightWithdrawals)
	if out, err := rtUnmapETH(t, "hive:alice", "", rpNow); err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("first payout: %q %v", out, err)
	}
	SetPendingNonce(0) // priced now, but queued behind the first
	asContract(t, rtRouter, "hive:carol", rpNow)
	out, err := HandleUnmapFromStatus(&TransferParams{Amount: "10000000000000000", From: "hive:carol", To: qfTo, Asset: "eth"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("unmapFrom: %q %v", out, err)
	}
	_, tail := QueueBounds()
	q := GetQueued(tail - 1)
	exact := payoutETHFee(ETHGasLimit(q.GasLimit), [20]byte{1})
	if q == nil || !q.Payout || q.FeeCap.Cmp(exact) <= 0 {
		t.Fatalf("queued %+v: want a payout keeping a cap above the fee now (%s)", q, exact)
	}
	carol := GetBalance("hive:carol", "eth")
	qcBaseFee(1_300_000_000) // the fee rises 30% while it waits
	if n := drainWith(1, [20]byte{1}, 8); n != 2 || QueueLen() != 0 {
		t.Fatalf("drained %d, queue %d: want both sent", n, QueueLen())
	}
	if GetBalance("hive:carol", "eth").Cmp(carol) <= 0 {
		t.Fatal("the unused part of the cap did not go back to carol")
	}
	ethInvariant(t, "after the drain")
}

// A payout whose own terms cannot pay it now (a token's gas above its
// max_fee) is refused in the request, so the router refunds the swap's sender
// at once; it is not queued to bounce back later.
func TestPayout_UnpayableNowIsRefusedInTheRequest(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	var tok [20]byte
	tok[19] = 0xc0
	if err := RegisterToken(1, tok, "USDC", 6, 1000); err != nil {
		t.Fatal(err)
	}
	IncBalance(rtRouter, "USDC", big.NewInt(5_000_000))
	s := GetSupply("USDC")
	SetSupply("USDC", Supply{Active: new(big.Int).Add(nz(s.Active), big.NewInt(5_000_000)), User: new(big.Int).Add(nz(s.User), big.NewInt(5_000_000)), Fee: nz(s.Fee)})
	asContract(t, rtRouter, "hive:alice", rpNow)
	_, err := HandleUnmapERC20(&TransferParams{Amount: "3000000", To: qfTo, Asset: "USDC", MaxFee: "1",
		TokenAddress: "0x00000000000000000000000000000000000000c0", RefundTo: "hive:alice", ReturnAsset: "hbd", ReturnMin: "2000"}, [20]byte{1}, 1)
	if err == nil || !strings.Contains(err.Error(), "max_fee") {
		t.Fatalf("payout over its own max_fee: %v, want refused", err)
	}
	if QueueLen() != 0 {
		t.Fatalf("queued %d: want nothing queued", QueueLen())
	}
}

// unmapFrom keeps a contract's payout within the payout gas bound, as unmapETH
// does (the reserve fronts part of each payout's signed maximum).
func TestPayout_UnmapFromPayoutGasLimitIsCapped(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter, "hive:carol")
	SetAllowance("hive:carol", rtRouter, "eth", ethWei(1000))
	asContract(t, rtRouter, "hive:carol", rpNow)
	if _, err := HandleUnmapFromStatus(&TransferParams{Amount: "10000000000000000", From: "hive:carol", To: qfTo, Asset: "eth",
		DeductFee: true, GasLimit: constants.MaxPayoutGasLimit + 1}, [20]byte{1}, 1); err == nil || !strings.Contains(err.Error(), "gas_limit") {
		t.Fatalf("a payout over the gas bound: %v", err)
	}
}

// A contract's fee-on-top payout sets aside this block's exact fee when the
// queue is empty; if it cannot issue now after all (the reserve short), it is
// refused rather than queued, where one wei of rise would send it back.
func TestPayout_ExactFeeOnTopIsRefusedRatherThanQueued(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	deductGasReserve(getGasReserve()) // the reserve cannot front the gap now
	asContract(t, rtRouter, "hive:alice", rpNow)
	_, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", RefundTo: "hive:alice"}, [20]byte{1}, 1)
	if err == nil || !strings.Contains(err.Error(), "cannot send this payout now") {
		t.Fatalf("fee on top while the reserve is short: %v, want refused", err)
	}
}
