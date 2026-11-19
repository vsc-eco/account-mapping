package mapping

import (
	"math/big"
	"strconv"
	"testing"
)

// D-4: ERC-20 withdrawals waiting on the shared gas reserve (below its floor)
// used up MaxDrainScan at the queue head, so an ETH withdrawal behind 32 of
// them was never issued until the reserve was topped up, though an ETH
// withdrawal does not use the reserve. They now do not count against the scan
// budget: the ETH withdrawal behind 40 of them issues on the first drain, and
// the 40 stay queued exactly as before (nothing refunded, balances unchanged).
func TestD4_TokensWaitingOnTheReserveDoNotStarveETH(t *testing.T) {
	var holders []string
	for i := 0; i < 3; i++ {
		holders = append(holders, "hive:t"+strconv.Itoa(i))
	}
	ethUser := "hive:eth"
	rpBridge(t, big.NewInt(0), append(holders, ethUser)...) // gas reserve empty
	before := map[string]*big.Int{}
	for _, u := range holders {
		before[u] = GetBalance(u, "USDC")
	}
	for i := 0; i < 40; i++ {
		u := holders[i/16]
		as(t, u, qfStale)
		if _, err := HandleUnmapERC20(&TransferParams{Amount: "1000", To: qfTo, Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1); err != nil {
			t.Fatalf("usdc unmap %d: %v", i, err)
		}
	}
	qfQueueETH(t, ethUser, "")
	if QueueLen() != 41 {
		t.Fatalf("queue %d, want 40 USDC + 1 ETH", QueueLen())
	}

	as(t, ethUser, rpNow) // a fresh pricing header; the reserve is still empty
	drainWith(1, [20]byte{1}, 8)
	ps := GetPendingSpend(0)
	if ps == nil || ps.Asset != "eth" || ps.From != ethUser {
		t.Fatalf("d-0 %+v; want the ETH withdrawal issued past the 40 waiting USDC ones", ps)
	}
	// QueueLen is tail - head (holes included), so check the entries: the 40
	// USDC ones (seq 0-39) are still queued, the ETH one (seq 40) is gone.
	for seq := uint64(0); seq < 40; seq++ {
		if q := GetQueued(seq); q == nil || q.Asset != "USDC" {
			t.Fatalf("seq %d = %+v; want the USDC withdrawal still waiting", seq, q)
		}
	}
	if q := GetQueued(40); q != nil {
		t.Fatalf("seq 40 = %+v; want the issued ETH withdrawal removed from the queue", q)
	}
	for _, u := range holders {
		n := int64(16)
		if u == holders[2] {
			n = 8
		}
		want := new(big.Int).Sub(before[u], big.NewInt(1000*n))
		if got := GetBalance(u, "USDC"); got.Cmp(want) != 0 {
			t.Fatalf("%s USDC %s, want %s (debited, still queued, nothing refunded)", u, got, want)
		}
	}
}

// D-4, the other wait: mid-rotation, the USDC custody is still at the retiring
// generation (its sweep has not landed, or is wedged), so USDC withdrawals wait
// on the active generation's cover while the reserve is healthy. An ETH
// withdrawal the active generation can already pay issues past 40 of them.
func TestD4_TokensWaitingForTheirSweepDoNotStarveETH(t *testing.T) {
	var holders []string
	for i := 0; i < 3; i++ {
		holders = append(holders, "hive:t"+strconv.Itoa(i))
	}
	ethUser := "hive:eth"
	rpBridge(t, big.NewInt(1e18), append(holders, ethUser)...) // reserve 1 ETH: above the floor
	a01Rotated(t)
	setVaultBook(0, "eth", new(big.Int)) // ETH already swept to the active generation; USDC not
	for i := 0; i < 40; i++ {
		as(t, holders[i/16], qfStale)
		if _, err := HandleUnmapERC20(&TransferParams{Amount: "1000", To: qfTo, Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1); err != nil {
			t.Fatalf("usdc unmap %d: %v", i, err)
		}
	}
	qfQueueETH(t, ethUser, "")
	as(t, ethUser, rpNow)
	drainWith(1, [20]byte{1}, 8)
	ps := GetPendingSpend(0)
	if ps == nil || ps.Asset != "eth" || ps.From != ethUser {
		t.Fatalf("d-0 %+v; want the ETH withdrawal issued past 40 USDC ones waiting for their sweep", ps)
	}
	for seq := uint64(0); seq < 40; seq++ {
		if q := GetQueued(seq); q == nil || q.Asset != "USDC" {
			t.Fatalf("seq %d = %+v; want the USDC withdrawal still waiting", seq, q)
		}
	}
}
