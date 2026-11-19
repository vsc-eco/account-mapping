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

// QFREEZE-1's refund of an unpayable queued withdrawal goes to refund_to.
func TestRefundTo_QueueRefundGoesToTheUser(t *testing.T) {
	rpBridge(t, big.NewInt(0), rtRouter)
	routerBefore := GetBalance(rtRouter, "eth")
	if out, err := rtUnmapETH(t, "hive:alice", "1", qfStale); err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("routed unmap: %q %v, want queued", out, err)
	}
	head, _ := QueueBounds()
	q := GetQueued(head)
	if q == nil || q.RefundTo != "hive:alice" || q.From != rtRouter {
		t.Fatalf("queued record %+v, want from the router, refunds to alice", q)
	}
	as(t, "hive:alice", rpNow) // fresh price: the 1-wei cap cannot pay -> refund
	drainWith(1, [20]byte{1}, 8)
	if QueueLen() != 0 {
		t.Fatalf("queue %d after the drain, want the entry refunded", QueueLen())
	}
	if got := GetBalance("hive:alice", "eth"); got.Cmp(q.Debit) != 0 {
		t.Fatalf("alice %s, want the debit %s back", got, q.Debit)
	}
	if got := GetBalance(rtRouter, "eth"); new(big.Int).Sub(routerBefore, got).Cmp(q.Debit) != 0 {
		t.Fatalf("router %s, want %s less the debit (nothing refunded to it)", got, routerBefore)
	}
}

// The user a routed withdrawal refunds to may cancel it; a stranger may not.
func TestRefundTo_TheUserCancels(t *testing.T) {
	rpBridge(t, big.NewInt(0), rtRouter)
	if _, err := rtUnmapETH(t, "hive:alice", "", qfStale); err != nil {
		t.Fatal(err)
	}
	head, _ := QueueBounds()
	q := GetQueued(head)
	as(t, "hive:mallory", rpNow)
	if err := HandleCancelQueuedWithdrawal(head); err == nil {
		t.Fatal("a stranger cancelled a routed withdrawal")
	}
	as(t, "hive:alice", rpNow)
	if err := HandleCancelQueuedWithdrawal(head); err != nil {
		t.Fatalf("alice cancel: %v", err)
	}
	if got := GetBalance("hive:alice", "eth"); got.Cmp(q.Debit) != 0 || QueueLen() != 0 {
		t.Fatalf("alice %s (want %s), queue %d", got, q.Debit, QueueLen())
	}
}

// Issued, the record keeps refund_to, and a proven revert refunds the user.
func TestRefundTo_InFlightRefundGoesToTheUser(t *testing.T) {
	rpBridge(t, big.NewInt(0), rtRouter)
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

// Routed withdrawals count against each user's queued cap, not one shared
// router cap a single user could fill for everyone.
func TestRefundTo_QueueCapIsPerUser(t *testing.T) {
	rpBridge(t, big.NewInt(0), rtRouter)
	SetPendingNonce(constants.MaxInFlightWithdrawals) // every slot in flight: requests queue
	for i := uint64(0); i < constants.MaxQueuedPerAccount; i++ {
		if _, err := rtUnmapETH(t, "hive:alice", "", rpNow); err != nil {
			t.Fatalf("alice's routed entry %d: %v", i+1, err)
		}
	}
	if _, err := rtUnmapETH(t, "hive:alice", "", rpNow); err == nil || !strings.Contains(err.Error(), "withdrawals queued") {
		t.Fatalf("alice's 17th: %v, want her cap", err)
	}
	if out, err := rtUnmapETH(t, "hive:bob", "", rpNow); err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("bob behind alice's full cap: %q %v", out, err)
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

// The other two refund paths: the unused part of a fee-on-top cap, returned
// when a QUEUED withdrawal is issued at a lower price (one issued at once is
// debited the exact fee), and a dropped in-flight withdrawal's value.
func TestRefundTo_DroppedAndUnusedFeeGoToTheUser(t *testing.T) {
	rpBridge(t, big.NewInt(0), rtRouter)
	asContract(t, rtRouter, "hive:alice", qfStale) // no fresh price: it queues
	capWei := "5000000000000000"                    // 0.005 ETH, far above the priced fee
	out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", MaxFee: capWei, RefundTo: "hive:alice"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "queued:") {
		t.Fatalf("routed unmap: %q %v, want queued", out, err)
	}
	as(t, "hive:alice", rpNow) // fresh price: the drain issues it
	drainWith(1, [20]byte{1}, 8)
	ps := GetPendingSpend(0)
	if ps == nil || ps.RefundTo != "hive:alice" {
		t.Fatalf("issued record %+v", ps)
	}
	unused := GetBalance("hive:alice", "eth")
	if unused.Sign() <= 0 {
		t.Fatal("the unused part of the fee cap was not returned to alice")
	}
	if GetBalance(rtRouter, "eth").Cmp(new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18))) >= 0 {
		t.Fatal("the router kept its whole balance: the withdrawal debited nothing")
	}
	before := new(big.Int).Set(unused)
	refundDroppedWithdrawal(ps)
	if got := new(big.Int).Sub(GetBalance("hive:alice", "eth"), before); got.Cmp(ps.Amount) != 0 {
		t.Fatalf("dropped refund to alice %s, want %s", got, ps.Amount)
	}
}

// The token path: a routed USDC withdrawal refunds the user too.
func TestRefundTo_TokenWithdrawalRefundsTheUser(t *testing.T) {
	rpBridge(t, big.NewInt(0), rtRouter)
	asContract(t, rtRouter, "hive:alice", qfStale)
	if _, err := HandleUnmapERC20(&TransferParams{Amount: "1000", To: qfTo, Asset: "USDC",
		TokenAddress: "0x00000000000000000000000000000000000000c0", RefundTo: "hive:alice"}, [20]byte{1}, 1); err != nil {
		t.Fatal(err)
	}
	head, _ := QueueBounds()
	if q := GetQueued(head); q == nil || q.RefundTo != "hive:alice" {
		t.Fatalf("queued USDC record %+v, want refunds to alice", q)
	}
	as(t, "hive:alice", rpNow)
	if err := HandleCancelQueuedWithdrawal(head); err != nil {
		t.Fatalf("alice cancels her routed USDC withdrawal: %v", err)
	}
	if got := GetBalance("hive:alice", "USDC"); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("alice USDC %s, want the 1000 back", got)
	}
}
