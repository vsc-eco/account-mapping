package mapping

import (
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// rpBridge is a bridge with a fresh 1 gwei pricing header, an active TSS key,
// a 10 ETH user balance for each name, USDC registered (min 1000 units), and
// the ETH reserve at reserveWei inside ETH custody.
func rpBridge(t *testing.T, reserveWei *big.Int, users ...string) {
	t.Helper()
	sdk.ResetStubState()
	sdk.ResetTestState()
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	hdr := (&blocklist.EthBlockHeader{BlockNumber: 100, BaseFeePerGas: 1e9, GasLimit: 30_000_000, Timestamp: uint64(now.Unix()), ChainId: 1}).Serialize()
	sdk.StateSetObject(constants.VerifierContractIdKey, "vsc1verifierstub")
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
	sdk.StubSetTssKey("active,02aa,ecdsa")
	sdk.StateSetObject(constants.TokenRegistryPrefix+"1-00000000000000000000000000000000000000c0", "USDC|6|1000")
	sdk.StateSetObject(constants.AllowedSymbolPrefix+"USDC", "1")
	eth := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18))
	users2 := new(big.Int).Mul(eth, big.NewInt(int64(len(users))))
	for _, u := range users {
		IncBalance(u, "eth", eth)
		IncBalance(u, "USDC", big.NewInt(1_000_000))
	}
	SetSupply("eth", Supply{Active: new(big.Int).Add(users2, reserveWei), User: users2, Fee: new(big.Int)})
	SetSupply("USDC", Supply{Active: big.NewInt(int64(1_000_000 * len(users))), User: big.NewInt(int64(1_000_000 * len(users))), Fee: new(big.Int)})
	if reserveWei.Sign() > 0 {
		addGasReserve(reserveWei)
	}
	as(t, users[0], now)
}

// as makes caller the signer of the next calls.
func as(t *testing.T, caller string, now time.Time) {
	t.Helper()
	sdk.StubSetEnvJSON(`{"contract.id":"contract:test","msg.caller":"` + caller + `","msg.sender":"` + caller +
		`","msg.required_auths":["` + caller + `"],"block.timestamp":"` + now.Format("2006-01-02T15:04:05") + `"}`)
}

var rpNow = time.Date(2026, 10, 27, 12, 0, 1, 0, time.UTC)

func ethUnmap(t *testing.T, user string) (string, error) {
	t.Helper()
	as(t, user, rpNow)
	return HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1)
}

// RP-11: ten users withdraw at once. None is refused: the first
// MaxInFlightWithdrawals are issued (consecutive nonces, one TSS sign each),
// the rest wait in the queue in order, and a head close issues the next.
// Old code: every unmap after the first was refused "withdrawal pending".
func TestRP11_ManyUsersWithdrawAtOnceNoneRefused(t *testing.T) {
	var users []string
	for i := 0; i < 10; i++ {
		users = append(users, "hive:u"+strconv.Itoa(i))
	}
	rpBridge(t, big.NewInt(0), users...)
	for _, u := range users {
		if _, err := ethUnmap(t, u); err != nil {
			t.Fatalf("%s: unmapETH refused: %v", u, err)
		}
	}
	if InFlightWithdrawals() != constants.MaxInFlightWithdrawals || QueueLen() != 2 {
		t.Fatalf("in flight %d queued %d, want %d and 2", InFlightWithdrawals(), QueueLen(), constants.MaxInFlightWithdrawals)
	}
	if n := len(sdk.TestSignRequests()); uint64(n) != constants.MaxInFlightWithdrawals {
		t.Fatalf("%d TSS sign requests, want one per in-flight withdrawal (%d): the cap bounds the vault's sign sessions", n, constants.MaxInFlightWithdrawals)
	}
	for n := uint64(0); n < constants.MaxInFlightWithdrawals; n++ {
		ps := GetPendingSpend(n)
		if ps == nil || ps.From != users[n] {
			t.Fatalf("d-%d = %+v, want %s's withdrawal (FIFO)", n, ps, users[n])
		}
	}
	// The head closes (as confirmSpend does): the next queued issues.
	DeletePendingSpend(0)
	SetConfirmedNonce(1)
	drainWith(1, [20]byte{1})
	if ps := GetPendingSpend(8); ps == nil || ps.From != users[8] || QueueLen() != 1 {
		t.Fatalf("after one head close: d-8=%+v queue=%d, want u8 issued and one left", ps, QueueLen())
	}
}

// RP-11: a queued withdrawal can be taken back in full by its owner only;
// custody and user supply return to where they were.
func TestRP11_CancelQueuedRefundsTheOwnerInFull(t *testing.T) {
	var users []string
	for i := 0; i < 9; i++ {
		users = append(users, "hive:u"+strconv.Itoa(i))
	}
	rpBridge(t, big.NewInt(0), users...)
	for _, u := range users {
		if _, err := ethUnmap(t, u); err != nil {
			t.Fatal(err)
		}
	}
	last := users[8]
	before := GetBalance(last, "eth")
	supplyBefore := GetSupply("eth")
	head, _ := QueueBounds()
	q := GetQueued(head)
	if q == nil || q.From != last || head != 8 {
		t.Fatalf("queue head seq %d = %+v, want seq 8 = %s's withdrawal", head, q, last)
	}
	as(t, "hive:u0", rpNow)
	if err := HandleCancelQueuedWithdrawal(head); err == nil {
		t.Fatal("another user cancelled u8's queued withdrawal")
	}
	as(t, last, rpNow)
	if err := HandleCancelQueuedWithdrawal(head); err != nil {
		t.Fatalf("owner cancel: %v", err)
	}
	if got := new(big.Int).Sub(GetBalance(last, "eth"), before); got.Cmp(q.Debit) != 0 {
		t.Fatalf("cancel refunded %s, want the full debit %s", got, q.Debit)
	}
	s := GetSupply("eth")
	if new(big.Int).Sub(s.Active, supplyBefore.Active).Cmp(q.Debit) != 0 || new(big.Int).Sub(s.User, supplyBefore.User).Cmp(q.Debit) != 0 {
		t.Fatalf("supply after cancel %+v (before %+v), want both up by %s", s, supplyBefore, q.Debit)
	}
	if QueueLen() != 0 || GetQueued(head) != nil {
		t.Fatalf("queue not empty after cancel: len %d", QueueLen())
	}
}

// RP-4: an ETH withdrawal is paid by its owner and needs no gas reserve.
// Old code: refused "insufficient gas reserve" below 0.05 ETH.
func TestRP4_ETHWithdrawalNeedsNoGasReserve(t *testing.T) {
	rpBridge(t, big.NewInt(0), "hive:alice")
	if _, err := ethUnmap(t, "hive:alice"); err != nil {
		t.Fatalf("unmapETH with an empty reserve: %v", err)
	}
	if GetPendingSpend(0) == nil {
		t.Fatal("not issued")
	}
	if getGasReserve().Sign() != 0 {
		t.Fatalf("the ETH withdrawal moved the reserve to %s", getGasReserve())
	}
	// An ERC-20 withdrawal still waits for the reserve (it pays that gas).
	as(t, "hive:alice", rpNow)
	if _, err := HandleUnmapERC20(&TransferParams{Amount: "1000", To: "0x00000000000000000000000000000000000000e2", Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1); err != nil {
		t.Fatalf("unmapERC20 with an empty reserve: %v, want it queued", err)
	}
	if GetPendingSpend(1) != nil || QueueLen() != 1 {
		t.Fatalf("ERC-20 with an empty reserve: d-1=%v queue=%d, want queued until the reserve is funded", GetPendingSpend(1) != nil, QueueLen())
	}
}

// RP-11 + issue-time pricing: an ETH withdrawal reserves its fee cap and gets
// the unused part back when it is priced; custody books the same.
func TestRP11_ETHFeeCapUnusedPartRefundedAtIssue(t *testing.T) {
	rpBridge(t, big.NewInt(0), "hive:alice")
	before := GetBalance("hive:alice", "eth")
	if _, err := ethUnmap(t, "hive:alice"); err != nil {
		t.Fatal(err)
	}
	ps := GetPendingSpend(0)
	// Issued at 1 gwei base: fee = 21000 x (2 x 1 + 2) gwei.
	wantFee := big.NewInt(21_000 * 4_000_000_000)
	if ps == nil || ps.GasCost.Cmp(wantFee) != 0 {
		t.Fatalf("issued fee %v, want %s", ps, wantFee)
	}
	paid := new(big.Int).Sub(before, GetBalance("hive:alice", "eth"))
	if want := new(big.Int).Add(big.NewInt(10_000_000_000_000_000), wantFee); paid.Cmp(want) != 0 {
		t.Fatalf("alice paid %s, want amount + priced fee %s (the unused cap refunded)", paid, want)
	}
}

// USDC-GAS-1: a token registered with its own gas limit is signed with it
// and its reserve charge uses it. Old code: always 65,000.
func TestUSDCGAS1_TokenGasLimitIsUsed(t *testing.T) {
	reserve := new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18))
	rpBridge(t, reserve, "hive:alice")
	var usdc [20]byte
	usdc[19] = 0xc0
	if err := RegisterTokenFull(1, usdc, "USDC", 6, 1000, 0, 80_000); err != nil {
		t.Fatal(err)
	}
	as(t, "hive:alice", rpNow)
	if _, err := HandleUnmapERC20(&TransferParams{Amount: "1000", To: "0x00000000000000000000000000000000000000e2", Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1); err != nil {
		t.Fatal(err)
	}
	ps := GetPendingSpend(0)
	if ps == nil || ps.GasLimit != 80_000 {
		t.Fatalf("pending spend %+v, want gas limit 80000", ps)
	}
	if want := big.NewInt(80_000 * 4_000_000_000); ps.GasCost.Cmp(want) != 0 {
		t.Fatalf("reserve charged %s, want 80000 x 4 gwei = %s", ps.GasCost, want)
	}
	if !strings.Contains(ps.UnsignedTxHex, "830138") { // RLP of 80000 = 0x83 0x01 0x38 0x80
		t.Fatalf("unsigned tx %s does not carry gas 80000", ps.UnsignedTxHex)
	}
}

// RP-11: the queue refuses only beyond MaxQueuedWithdrawals.
func TestRP11_QueueRefusesOnlyWhenFull(t *testing.T) {
	rpBridge(t, big.NewInt(0), "hive:alice")
	sdk.StateSetObject(constants.WithdrawQueueTailKey, strconv.FormatUint(constants.MaxQueuedWithdrawals, 10))
	if _, err := ethUnmap(t, "hive:alice"); err == nil || !strings.Contains(err.Error(), "queue is full") {
		t.Fatalf("unmap with a full queue: %v, want the full refusal", err)
	}
}
