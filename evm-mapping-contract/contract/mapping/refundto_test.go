package mapping

import (
	"math/big"
	"strings"
	"testing"
	"time"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// A contract (the DEX router settling a swap to Ethereum) withdraws its own
// balance on a user's behalf. Every refund of such a withdrawal used to be
// credited to the contract, which cannot spend it: the user's money was
// stranded. refund_to names the user.

const rtRouter = "contract:vsc1router"

// asContract: the contract is the caller, the user signed the transaction.
func asContract(t *testing.T, contract, user string, now time.Time) {
	t.Helper()
	sdk.StubSetEnvJSON(`{"contract.id":"contract:test","msg.caller":"` + contract + `","msg.sender":"` + user +
		`","msg.required_auths":["` + user + `"],"block.timestamp":"` + now.Format("2006-01-02T15:04:05") + `"}`)
}

func rtUnmapETH(t *testing.T, refundTo, maxFee string, now time.Time) (string, error) {
	t.Helper()
	asContract(t, rtRouter, "hive:alice", now)
	return HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth",
		DeductFee: true, MaxFee: maxFee, RefundTo: refundTo}, [20]byte{1}, 1)
}

func TestRefundTo_OnlyAContractMayNameOne(t *testing.T) {
	rpBridge(t, big.NewInt(0), "hive:alice")
	as(t, "hive:alice", rpNow)
	_, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", RefundTo: "hive:bob"}, [20]byte{1}, 1)
	if err == nil || !strings.Contains(err.Error(), "refund_to is for a contract") {
		t.Fatalf("an account naming another refund address: %v", err)
	}
	asContract(t, rtRouter, "hive:alice", rpNow)
	_, err = HandleUnmapERC20(&TransferParams{Amount: "1000", To: qfTo, Asset: "USDC",
		TokenAddress: "0x00000000000000000000000000000000000000c0", RefundTo: "not an identity"}, [20]byte{1}, 1)
	if err == nil || !strings.Contains(err.Error(), "invalid recipient") {
		t.Fatalf("a malformed refund_to: %v", err)
	}
}

// PAYOUT-1 (owner 11-21: wait and retry): a contract's withdrawal that cannot be
// sent now waits in the queue and is sent when it can; nothing about it lands
// in refund_to's Magi balance meanwhile.
func TestRefundTo_StalePriceQueuesThenSends(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	out, err := rtUnmapETH(t, "hive:alice", "", qfStale)
	if err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("routed unmap at a stale price: %q %v, want queued", out, err)
	}
	head, _ := QueueBounds()
	if q := GetQueued(head); q == nil || !q.Payout || q.RefundTo != "hive:alice" {
		t.Fatalf("queued record %+v, want a payout for alice", q)
	}
	as(t, "hive:alice", rpNow) // a fresh price: the drain sends it
	if n := drainWith(1, [20]byte{1}, 8); n != 1 || QueueLen() != 0 {
		t.Fatalf("drain issued %d, queue %d", n, QueueLen())
	}
	ps := GetPendingSpend(0)
	if fee := payoutGasFee(constants.ETHTransferGas, 1e9, 2_000_000_000); new(big.Int).Sub(big.NewInt(1e16), ps.Amount).Cmp(fee) != 0 {
		t.Fatalf("sent %s, want the amount less the payout fee %s", ps.Amount, fee)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 {
		t.Fatal("something reached alice's Magi balance")
	}
	ethInvariant(t, "after the drain")
}

// An entry a contract queued before PAYOUT-1 keeps its refund_to: its user may
// cancel it, a stranger may not, and the debit goes to the user.
func TestRefundTo_TheUserCancelsALegacyEntry(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	debit := new(big.Int).Mul(big.NewInt(1), big.NewInt(1e16))
	DecBalance(rtRouter, "eth", debit)
	TrackWithdrawal("eth", debit)
	seq := Enqueue(QueuedWithdrawal{From: rtRouter, To: qfTo, Asset: "eth", Amount: debit, Debit: debit, FeeCap: big.NewInt(1), DeductFee: true, RefundTo: "hive:alice"})
	as(t, "hive:mallory", rpNow)
	if err := HandleCancelQueuedWithdrawal(seq); err == nil {
		t.Fatal("a stranger cancelled a routed withdrawal")
	}
	as(t, "hive:alice", rpNow)
	if err := HandleCancelQueuedWithdrawal(seq); err != nil {
		t.Fatalf("alice cancel: %v", err)
	}
	if got := GetBalance("hive:alice", "eth"); got.Cmp(debit) != 0 || QueueLen() != 0 {
		t.Fatalf("alice %s (want %s), queue %d", got, debit, QueueLen())
	}
	ethInvariant(t, "after the cancel")
}

// Issued, the record keeps refund_to, and a proven revert refunds the user.
func TestRefundTo_InFlightRefundGoesToTheUser(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	out, err := rtUnmapETH(t, "hive:alice", "", rpNow)
	if err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("routed unmap: %q %v, want issued", out, err)
	}
	ps := GetPendingSpend(0)
	if ps == nil || ps.RefundTo != "hive:alice" || ps.From != rtRouter {
		t.Fatalf("in-flight record %+v, want refunds to alice", ps)
	}
	routerAfter := GetBalance(rtRouter, "eth")
	refundRevertedWithdrawal(ps)
	if got := GetBalance("hive:alice", "eth"); got.Cmp(ps.Amount) != 0 {
		t.Fatalf("alice %s after the revert refund, want %s", got, ps.Amount)
	}
	if GetBalance(rtRouter, "eth").Cmp(routerAfter) != 0 {
		t.Fatal("the revert refund went to the router")
	}
	// The user may act as the withdrawer (cancel / early expire).
	if !ps.isWithdrawer("hive:alice") || !ps.isWithdrawer(rtRouter) || ps.isWithdrawer("hive:mallory") {
		t.Fatal("isWithdrawer: want the router and alice, not a stranger")
	}
}

// With every slot in flight a contract's withdrawal waits in the queue; each
// user's queued payouts still count against that user's cap.
func TestRefundTo_AllSlotsInFlightQueues(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	SetPendingNonce(constants.MaxInFlightWithdrawals) // every slot in flight
	for i := uint64(0); i < constants.MaxQueuedPerAccount; i++ {
		if out, err := rtUnmapETH(t, "hive:alice", "", rpNow); err != nil || !strings.HasPrefix(out, "queued:") {
			t.Fatalf("alice's routed entry %d: %q %v", i+1, out, err)
		}
	}
	if _, err := rtUnmapETH(t, "hive:alice", "", rpNow); err == nil || !strings.Contains(err.Error(), "withdrawals queued") {
		t.Fatalf("alice's 17th: %v, want her cap (the swap then goes back to its sender)", err)
	}
	if out, err := rtUnmapETH(t, "hive:bob", "", rpNow); err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("bob behind alice's full cap: %q %v", out, err)
	}
}

// A dropped in-flight payout's value goes to refund_to. A fee-on-top payout is
// debited exactly its fee: nothing of a cap is held back to refund later.
func TestRefundTo_DroppedAndFeeOnTopGoToTheUser(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	asContract(t, rtRouter, "hive:alice", rpNow)
	routerBefore := GetBalance(rtRouter, "eth")
	capWei := "5000000000000000" // 0.005 ETH, far above the payout fee
	out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", MaxFee: capWei, RefundTo: "hive:alice"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("routed unmap: %q %v, want issued", out, err)
	}
	ps := GetPendingSpend(0)
	if ps == nil || ps.RefundTo != "hive:alice" {
		t.Fatalf("issued record %+v", ps)
	}
	fee := payoutGasFee(constants.ETHTransferGas, 1e9, 2_000_000_000)
	debited := new(big.Int).Sub(routerBefore, GetBalance(rtRouter, "eth"))
	if want := new(big.Int).Add(big.NewInt(1e16), new(big.Int).Add(fee, ProofFee("eth"))); debited.Cmp(want) != 0 {
		t.Fatalf("router debited %s, want amount + payout fee + proof fee %s", debited, want)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 {
		t.Fatal("something of the fee cap was refunded to a Magi balance")
	}
	// A rolled payout is sent again (paying its own gas), never refunded to a
	// Magi balance.
	refundDroppedWithdrawal(ps, 1)
	head, _ := QueueBounds()
	if q := GetQueued(head); q == nil || q.Attempt != 1 || q.Amount.Cmp(ps.Amount) != 0 || GetBalance("hive:alice", "eth").Sign() != 0 {
		t.Fatalf("rolled payout: queue %+v, alice %s; want it sent again", q, GetBalance("hive:alice", "eth"))
	}
}

// The token path: a routed USDC payout's revert refunds the user too.
func TestRefundTo_TokenWithdrawalRefundsTheUser(t *testing.T) {
	rpBridge(t, ethWei(20), rtRouter)
	asContract(t, rtRouter, "hive:alice", rpNow)
	out, err := HandleUnmapERC20(&TransferParams{Amount: "1000", To: qfTo, Asset: "USDC",
		TokenAddress: "0x00000000000000000000000000000000000000c0", RefundTo: "hive:alice"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("routed USDC unmap: %q %v, want issued", out, err)
	}
	ps := GetPendingSpend(0)
	if ps == nil || ps.RefundTo != "hive:alice" {
		t.Fatalf("issued USDC record %+v, want refunds to alice", ps)
	}
	refundRevertedWithdrawal(ps)
	if got := GetBalance("hive:alice", "USDC"); got.Cmp(ps.Amount) != 0 {
		t.Fatalf("alice USDC %s, want %s back", got, ps.Amount)
	}
}

// A withdrawal without refund_to (every one before this field) refunds its
// withdrawer exactly as before.
func TestRefundTo_AbsentMeansTheWithdrawer(t *testing.T) {
	q := QueuedWithdrawal{From: "hive:u"}
	ps := PendingSpend{From: "hive:u"}
	if q.refundAccount() != "hive:u" || ps.refundAccount() != "hive:u" || !ps.isWithdrawer("hive:u") {
		t.Fatal("absent refund_to must mean the withdrawer")
	}
}
