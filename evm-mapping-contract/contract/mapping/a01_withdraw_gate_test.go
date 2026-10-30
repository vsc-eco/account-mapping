package mapping

import (
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// a01Rotated puts the whole custody at a retiring generation 0, as a cut-over
// leaves it before the sweep, with generation 1 active.
func a01Rotated(t *testing.T) {
	t.Helper()
	SaveVaultState(VaultRegistry{
		{Generation: 0, Primary: pubOf(t, testPub1), Status: VaultStatusRetiring, Predecessor: 0},
		{Generation: 1, Primary: pubOf(t, testPub2), Status: VaultStatusActive, Predecessor: 0},
	}, 2, 1)
	setVaultBook(0, "eth", new(big.Int).Set(GetSupply("eth").Active))
	setVaultBook(0, "USDC", new(big.Int).Set(GetSupply("USDC").Active))
}

func signRequestsFor(key string) int {
	n := 0
	for _, r := range sdk.TestSignRequests() {
		if strings.HasPrefix(r, key+",") {
			n++
		}
	}
	return n
}

// A01: while the retiring generation still holds the custody, the new
// generation sends only what reached it; a withdrawal it cannot cover waits in
// the queue (it is not refused) and issues once the funds are there.
func TestA01_WithdrawalWaitsForTheSweep(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	a01Rotated(t)

	status, err := HandleUnmapETH(&TransferParams{Amount: "1000000000000000000", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(status, "queued:") {
		t.Fatalf("ETH withdrawal with the custody at the retiring generation: %q %v, want queued", status, err)
	}
	if signRequestsFor("primaryv1")+signRequestsFor("primary") != 0 {
		t.Fatalf("a signature was requested: %v", sdk.TestSignRequests())
	}
	if DrainWithdrawalQueue(1, 8) != 0 {
		t.Fatal("drain issued a withdrawal the new generation cannot pay")
	}

	// A 2 ETH deposit reaches the new generation: the withdrawal can go.
	TrackDeposit("eth", new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18)), new(big.Int))
	if DrainWithdrawalQueue(1, 8) != 1 {
		t.Fatalf("drain did not issue once the new generation could pay (queue %d)", QueueLen())
	}
	if signRequestsFor("primaryv1") != 1 {
		t.Fatalf("not signed by the active generation's key: %v", sdk.TestSignRequests())
	}

	// ERC-20: the token is all at the retiring generation, so it waits too.
	status, err = HandleUnmapERC20(&TransferParams{Amount: "500000", To: "0x00000000000000000000000000000000000000e2", Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(status, "queued:") {
		t.Fatalf("USDC withdrawal: %q %v, want queued", status, err)
	}
	// The sweep lands: the retiring generation's books are empty.
	setVaultBook(0, "USDC", new(big.Int))
	setVaultBook(0, "eth", new(big.Int))
	if DrainWithdrawalQueue(1, 8) != 1 {
		t.Fatalf("drain did not issue after the sweep (queue %d)", QueueLen())
	}
}

// The ERC-20 transfer's gas is ETH at the new generation's address: covered
// token but uncovered gas waits as well.
func TestA01_TokenWithdrawalNeedsGasAtTheNewGeneration(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	a01Rotated(t)
	setVaultBook(0, "USDC", new(big.Int)) // the token is already swept, the ETH is not
	status, err := HandleUnmapERC20(&TransferParams{Amount: "500000", To: "0x00000000000000000000000000000000000000e2", Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(status, "queued:") {
		t.Fatalf("USDC withdrawal with no ETH at the new generation: %q %v, want queued", status, err)
	}
	setVaultBook(0, "eth", new(big.Int))
	if DrainWithdrawalQueue(1, 8) != 1 {
		t.Fatal("drain did not issue once gas was there")
	}
}

// Without a funded superseded generation nothing changes: the same
// withdrawals issue at once.
func TestA01_NoRotationIssuesAtOnce(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	SaveVaultState(VaultRegistry{
		{Generation: 0, Primary: pubOf(t, testPub1), Status: VaultStatusInactive, Predecessor: 0},
		{Generation: 1, Primary: pubOf(t, testPub2), Status: VaultStatusActive, Predecessor: 0},
	}, 2, 1)
	status, err := HandleUnmapETH(&TransferParams{Amount: "1000000000000000000", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(status, "issued:") {
		t.Fatalf("%q %v, want issued", status, err)
	}
	if v, _ := sdk.TestStateGet(constants.QueuedDebitExactKey); v != "" && QueueLen() != 0 {
		t.Fatal("queue touched")
	}
}

// With the queue empty a request issues at once when the new generation can pay
// it: its own debit (taken from the custody before it issues) counts.
func TestA01_ImmediateIssueCountsItsOwnDebit(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	a01Rotated(t)
	TrackDeposit("eth", new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18)), new(big.Int)) // reached generation 1
	status, err := HandleUnmapETH(&TransferParams{Amount: "1000000000000000000", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(status, "issued:") {
		t.Fatalf("%q %v, want issued at once from the new generation's 2 ETH", status, err)
	}
}

// The replace cooldown of the new generation's nonce 0 is its own, not the
// retired generation's nonce 0.
func TestA01_ReplaceCooldownIsPerGeneration(t *testing.T) {
	sdk.ResetTestState()
	sdk.StubClearTssKeys()
	if k := replaceCooldownKey(0); k != constants.ReplaceWithdrawalLastKey+"0" {
		t.Fatalf("pre-rotation key %q", k)
	}
	SaveVaultState(VaultRegistry{
		{Generation: 0, Primary: pubOf(t, testPub1), Status: VaultStatusRetiring, Predecessor: 0},
		{Generation: 1, Primary: pubOf(t, testPub2), Status: VaultStatusActive, Predecessor: 0},
	}, 2, 1)
	if k := replaceCooldownKey(0); k != constants.ReplaceWithdrawalLastKey+"1-0" {
		t.Fatalf("generation 1 key %q", k)
	}
}
