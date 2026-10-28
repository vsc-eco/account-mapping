package mapping

import (
	"math/big"
	"strconv"
	"testing"
	"time"

	"evm-mapping-contract/sdk"
)

const qfTo = "0x00000000000000000000000000000000000000e2"

// qfStale is a block time more than MaxPricingHeaderAge past rpBridge's header:
// no fresh pricing header, so a 1-wei fee cap is not refused at request
// (failFastOverCap) and the withdrawal is queued.
var qfStale = rpNow.Add(2 * time.Hour)

func qfQueueETH(t *testing.T, user, maxFee string) {
	t.Helper()
	as(t, user, qfStale)
	out, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: qfTo, Asset: "eth", MaxFee: maxFee}, [20]byte{1}, 1)
	if err != nil || out[:7] != "queued:" {
		t.Fatalf("%s: unmap %q, %v; want queued", user, out, err)
	}
}

// QFREEZE-1: 32 queued withdrawals that can never be issued (fee cap 1 wei)
// took every drain's MaxDrainScan budget at the queue head, so no later
// withdrawal was ever issued and only their owners could clear them. As in
// the BTC mapping contract's drain, an entry its own terms cannot pay at the
// current price is refunded in full and removed: 40 of them ahead of an
// honest withdrawal are gone within two drains and the honest one issues.
func TestQFREEZE1_UnpayableQueuedWithdrawalsAreRefundedNotHeld(t *testing.T) {
	var users []string
	for i := 0; i < 41; i++ {
		users = append(users, "hive:g"+strconv.Itoa(i))
	}
	rpBridge(t, big.NewInt(0), users...)
	start := GetBalance(users[0], "eth")
	supply0 := GetSupply("eth")
	for _, u := range users[:40] {
		qfQueueETH(t, u, "1")
	}
	honest := users[40]
	qfQueueETH(t, honest, "")
	if QueueLen() != 41 {
		t.Fatalf("queue %d, want 41", QueueLen())
	}

	as(t, users[0], rpNow) // the pricing header is fresh again
	drainWith(1, [20]byte{1}, 8)
	if QueueLen() != 9 {
		t.Fatalf("after one drain: queue %d, want 9 (MaxDrainScan=32 refunded)", QueueLen())
	}
	drainWith(1, [20]byte{1}, 8)
	ps := GetPendingSpend(0)
	if QueueLen() != 0 || ps == nil || ps.From != honest {
		t.Fatalf("after two drains: queue %d, d-0 %+v; want the 40 refunded and %s issued", QueueLen(), ps, honest)
	}
	for _, u := range users[:40] {
		if got := GetBalance(u, "eth"); got.Cmp(start) != 0 {
			t.Fatalf("%s balance %s after the refund, want %s back in full", u, got, start)
		}
	}
	// Custody and user supply moved only by the honest withdrawal now in flight.
	s := GetSupply("eth")
	spent := new(big.Int).Sub(start, GetBalance(honest, "eth"))
	if want := new(big.Int).Sub(supply0.User, spent); s.User.Cmp(want) != 0 || new(big.Int).Sub(supply0.Active, s.Active).Cmp(spent) != 0 {
		t.Fatalf("supply %+v -> %+v; want both down by the honest debit %s only", supply0, s, spent)
	}
}

// ERC-20: an entry whose max_fee is below the transfer's gas is refunded; one
// that waits on the shared gas reserve stays queued (a top-up issues it).
func TestQFREEZE1_ERC20RefundsOwnCapButWaitsOnTheReserve(t *testing.T) {
	rpBridge(t, big.NewInt(0), "hive:low", "hive:ok")
	usdc := func(u, maxFee string) {
		as(t, u, qfStale)
		if _, err := HandleUnmapERC20(&TransferParams{Amount: "1000", To: qfTo, Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0", MaxFee: maxFee}, [20]byte{1}, 1); err != nil {
			t.Fatalf("%s: %v", u, err)
		}
	}
	before := GetBalance("hive:low", "USDC")
	usdc("hive:low", "1")
	usdc("hive:ok", "")
	as(t, "hive:low", rpNow)
	drainWith(1, [20]byte{1}, 8)
	if got := GetBalance("hive:low", "USDC"); got.Cmp(before) != 0 {
		t.Fatalf("the 1-wei max_fee USDC withdrawal was not refunded: balance %s, want %s", got, before)
	}
	head, _ := QueueBounds()
	if q := GetQueued(head); QueueLen() != 1 || q == nil || q.From != "hive:ok" || GetPendingSpend(0) != nil {
		t.Fatalf("queue %d head %+v; want hive:ok still waiting on the empty gas reserve", QueueLen(), q)
	}
}

// A stale price refunds nothing: no fresh header, no drain.
func TestQFREEZE1_NoRefundOnAStalePrice(t *testing.T) {
	rpBridge(t, big.NewInt(0), "hive:a")
	qfQueueETH(t, "hive:a", "1")
	as(t, "hive:a", qfStale)
	drainWith(1, [20]byte{1}, 8)
	if QueueLen() != 1 {
		t.Fatalf("queue %d after a drain on a stale price, want the entry kept", QueueLen())
	}
}

// The contract owner may cancel any queued withdrawal (BTC: HandleCancelQueuedUnmap);
// the debit goes back to the withdrawal's owner. Anyone else may not.
func TestQFREEZE1_OwnerCanCancelAQueuedWithdrawal(t *testing.T) {
	rpBridge(t, big.NewInt(0), "hive:u", "hive:other")
	sdk.SetTestEnvKey("contract.owner", "hive:owner")
	before := GetBalance("hive:u", "eth")
	qfQueueETH(t, "hive:u", "")
	head, _ := QueueBounds()
	q := GetQueued(head)
	as(t, "hive:other", rpNow)
	if err := HandleCancelQueuedWithdrawal(head); err == nil {
		t.Fatal("a third party cancelled another user's queued withdrawal")
	}
	as(t, "hive:owner", rpNow)
	if err := HandleCancelQueuedWithdrawal(head); err != nil {
		t.Fatalf("owner cancel: %v", err)
	}
	if got := GetBalance("hive:u", "eth"); got.Cmp(before) != 0 || QueueLen() != 0 || GetBalance("hive:owner", "eth").Sign() != 0 {
		t.Fatalf("after the owner's cancel: hive:u %s (want %s), queue %d, owner balance %s; debit %s must go to hive:u", got, before, QueueLen(), GetBalance("hive:owner", "eth"), q.Debit)
	}
}
