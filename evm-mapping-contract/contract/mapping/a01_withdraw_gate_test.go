package mapping

import (
	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

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
// retired generation's nonce 0; a retiring generation's in-flight withdrawal
// keeps its own generation's key.
func TestA01_ReplaceCooldownIsPerGeneration(t *testing.T) {
	sdk.ResetTestState()
	sdk.StubClearTssKeys()
	if k := replaceCooldownKey(&PendingSpend{}, 0); k != constants.ReplaceWithdrawalLastKey+"0" {
		t.Fatalf("pre-rotation key %q", k)
	}
	SaveVaultState(VaultRegistry{
		{Generation: 0, Primary: pubOf(t, testPub1), Status: VaultStatusRetiring, Predecessor: 0},
		{Generation: 1, Primary: pubOf(t, testPub2), Status: VaultStatusActive, Predecessor: 0},
	}, 2, 1)
	gen1 := &PendingSpend{VaultAtQueue: crypto.AddressToHex(a01Addr(t, testAdr2))}
	if k := replaceCooldownKey(gen1, 0); k != constants.ReplaceWithdrawalLastKey+"1-0" {
		t.Fatalf("generation 1 key %q", k)
	}
	gen0 := &PendingSpend{VaultAtQueue: crypto.AddressToHex(a01Addr(t, testAdr1))}
	if k := replaceCooldownKey(gen0, 0); k != constants.ReplaceWithdrawalLastKey+"0" {
		t.Fatalf("retiring generation 0 key %q", k)
	}
}

// C4-REFUND-1: a fee-on-top ETH withdrawal waiting for the new generation is
// credited its unused fee once, when it issues, not on every drain that finds
// it uncovered (each of which used to credit it again: unbacked ETH).
func TestA01_WaitingWithdrawalRefundsItsUnusedFeeOnce(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	a01Rotated(t)
	status, err := HandleUnmapETH(&TransferParams{Amount: "1000000000000000000", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(status, "queued:") {
		t.Fatalf("%q %v, want queued", status, err)
	}
	queued := GetBalance("hive:alice", "eth")
	// The base fee halves while it waits: issued, it uses less than its cap.
	cheaper := (&blocklist.EthBlockHeader{BlockNumber: 100, BaseFeePerGas: 5e8, GasLimit: 30_000_000,
		Timestamp: uint64(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC).Unix()), ChainId: 1}).Serialize()
	sdk.StubSetContractReadResponder(func(_, key string) *string {
		switch key {
		case "h":
			h := "100"
			return &h
		case "b-100":
			return &cheaper
		}
		return nil
	})
	for i := 0; i < 3; i++ {
		if DrainWithdrawalQueue(1, 8) != 0 {
			t.Fatal("issued while the new generation cannot pay")
		}
	}
	if got := GetBalance("hive:alice", "eth"); got.Cmp(queued) != 0 {
		t.Fatalf("balance %s after drains that issued nothing, want %s", got, queued)
	}
	TrackDeposit("eth", new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18)), new(big.Int))
	if DrainWithdrawalQueue(1, 8) != 1 {
		t.Fatal("not issued once covered")
	}
	issued := GetBalance("hive:alice", "eth")
	if issued.Cmp(queued) <= 0 {
		t.Fatalf("no unused fee returned at issue: %s", issued)
	}
	if DrainWithdrawalQueue(1, 8) != 0 || GetBalance("hive:alice", "eth").Cmp(issued) != 0 {
		t.Fatal("credited again after it issued")
	}
}

// rotatedWithInFlight is a bridge whose generation 0 issued a withdrawal for
// alice and was then superseded by generation 1 with it still in flight. It
// returns both addresses.
func rotatedWithInFlight(t *testing.T) (gen0, gen1 [20]byte) {
	t.Helper()
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice", "hive:bob")
	gen0, gen1 = a01Addr(t, testAdr1), a01Addr(t, testAdr2)
	SaveVaultState(VaultRegistry{{Generation: 0, Primary: pubOf(t, testPub1), Status: VaultStatusActive, Predecessor: 0}}, 1, 0)
	sdk.StubSetTssKeyFor("primary", "active,"+testPub1+",ecdsa,1,1")
	status, err := HandleUnmapETH(&TransferParams{Amount: "1000000000000000000", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, gen0, 1)
	if err != nil || !strings.HasPrefix(status, "issued:") {
		t.Fatalf("generation 0 withdrawal: %q %v", status, err)
	}
	if _, _, err := MintNextGeneration(100); err != nil {
		t.Fatal(err)
	}
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,1")
	if _, _, _, err := ActivatePendingGeneration(100); err != nil {
		t.Fatalf("cut-over with a withdrawal in flight: %v", err)
	}
	return gen0, gen1
}

// ROT-HALT-1: the cut-over does not wait for generation 0's in-flight
// withdrawal. Its key re-signs it (not the new key); new withdrawals wait for
// the hand-off and then go from generation 1 at nonce 0.
func TestA01_CutOverWithAWithdrawalInFlight(t *testing.T) {
	gen0, gen1 := rotatedWithInFlight(t)
	if h, held := WithdrawNonceHolder(); !held || h != 0 || GetPendingNonce() != 1 {
		t.Fatalf("holder %d %v, pending nonce %d", h, held, GetPendingNonce())
	}
	if c, _ := WithdrawCeiling(0); c != 1 || SweepNonce(0) != 1 {
		t.Fatalf("ceiling %d sweep nonce %d, want 1", c, SweepNonce(0))
	}
	// Bob's withdrawal waits even with generation 1 funded: the nonces are
	// generation 0's until its withdrawal settles.
	setVaultBook(0, "eth", new(big.Int))
	TrackDeposit("eth", new(big.Int).Mul(big.NewInt(5), big.NewInt(1e18)), new(big.Int))
	sdk.StubSetEnvJSON(`{"contract.id":"contract:test","msg.caller":"hive:bob","msg.sender":"hive:bob","msg.required_auths":["hive:bob"],"block.timestamp":"2026-10-27T12:00:00"}`)
	status, err := HandleUnmapETH(&TransferParams{Amount: "1000000000000000000", To: "0x00000000000000000000000000000000000000e3", Asset: "eth"}, gen1, 1)
	if err != nil || !strings.HasPrefix(status, "queued:") {
		t.Fatalf("bob's withdrawal during the hand-off: %q %v, want queued", status, err)
	}
	if DrainWithdrawalQueue(1, 8) != 0 {
		t.Fatal("issued at a nonce generation 0 still holds")
	}
	// Generation 0's withdrawal is re-priced: by its own key, its extra gas
	// (A14) out of generation 0's books (it burns at generation 0's address).
	before := signRequestsFor("primary")
	setVaultBook(0, "eth", wei("1000000000000000000"))
	reserve := getGasReserve()
	if err := HandleReplaceWithdrawal(gen1, 1); err != nil {
		t.Fatal(err)
	}
	charged := new(big.Int).Sub(reserve, getGasReserve())
	if charged.Sign() <= 0 || new(big.Int).Sub(wei("1000000000000000000"), VaultBook(0, "eth")).Cmp(charged) != 0 {
		t.Fatalf("replacement gas %s, generation 0 eth book %s: want the gas out of both", charged, VaultBook(0, "eth"))
	}
	if signRequestsFor("primary") != before+1 || signRequestsFor("primaryv1") != 0 {
		t.Fatalf("replacement signed by %v, want generation 0's key", sdk.TestSignRequests())
	}
	if ps := GetPendingSpend(0); ps == nil || ps.VaultAtQueue != crypto.AddressToHex(gen0) {
		t.Fatalf("replacement record %+v", ps)
	}
	// It settles: the nonces go to generation 1 and bob's withdrawal issues
	// there at nonce 0.
	ps := GetPendingSpend(0)
	NonceAdvance(ps, 1)
	DeletePendingSpend(0)
	if DrainWithdrawalQueue(1, 8) != 1 {
		t.Fatal("not issued after the hand-off")
	}
	bob := GetPendingSpend(0)
	if bob == nil || bob.VaultAtQueue != crypto.AddressToHex(gen1) || signRequestsFor("primaryv1") != 1 || GetPendingNonce() != 1 {
		t.Fatalf("bob's withdrawal %+v, sign requests %v", bob, sdk.TestSignRequests())
	}
	if _, held := WithdrawNonceHolder(); held {
		t.Fatal("holder kept after the hand-off")
	}
}

// A refunded in-flight withdrawal of a superseded generation is booked back to
// it (the funds never left its address), except ETH after its proven ETH
// sweep, which carried that ETH to the active generation.
func TestA01_RefundOfARetiringWithdrawalIsBookedToIt(t *testing.T) {
	rotatedWithInFlight(t)
	ps := GetPendingSpend(0)
	book := VaultBook(0, "eth")
	refundDroppedWithdrawal(ps)
	if got := new(big.Int).Sub(VaultBook(0, "eth"), book); got.Cmp(ps.Amount) != 0 {
		t.Fatalf("booked %s back to generation 0, want %s", got, ps.Amount)
	}
	rotatedWithInFlight(t)
	ps = GetPendingSpend(0)
	sdk.StateSetObject(constants.ETHSweptPrefix+"0", "1")
	book = VaultBook(0, "eth")
	refundDroppedWithdrawal(ps)
	if VaultBook(0, "eth").Cmp(book) != 0 {
		t.Fatal("ETH booked to generation 0 after its ETH sweep took it")
	}
	// The active generation's own refunds book nothing.
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	SaveVaultState(VaultRegistry{{Generation: 0, Primary: pubOf(t, testPub1), Status: VaultStatusActive, Predecessor: 0}}, 1, 0)
	bookSpendRefund(&PendingSpend{VaultAtQueue: crypto.AddressToHex(a01Addr(t, testAdr1)), Asset: "eth"}, big.NewInt(5))
	if VaultBook(0, "eth").Sign() != 0 {
		t.Fatal("an active generation's refund was booked")
	}
}

// A superseded generation with a withdrawal still in flight is not empty: it
// is neither retired nor does it let a new key be minted (NN#3).
func TestA01_InFlightKeepsTheGenerationOpen(t *testing.T) {
	rotatedWithInFlight(t)
	for _, a := range vaultAssets() {
		setVaultBook(0, a, new(big.Int))
	}
	if out, _ := ReconcileRetiringVaults(11155111); out != "retire: no generation transitions" {
		t.Fatalf("retired with a withdrawal in flight: %q", out)
	}
	if funded, _ := AnyFundedSupersededGen(); !funded {
		t.Fatal("NN#3 ignores the in-flight withdrawal")
	}
	if holdsInFlightWithdrawals(1) {
		t.Fatal("generation 1 counted as holding generation 0's withdrawals")
	}
}

// ROT-HALT-1: generation 0's withdrawal that never mines is rolled by
// generation 0's key after the cut-over (a 0-value transfer to its own
// address), so its nonce is spent and the sweeps after it can mine.
func TestA01_RetiringGenerationRollsItsOwnWithdrawal(t *testing.T) {
	gen0, gen1 := rotatedWithInFlight(t)
	late := uint64(100) + uint64(constants.WithdrawalRollWindow)
	hdr := (&blocklist.EthBlockHeader{BlockNumber: late, BaseFeePerGas: 1e9, GasLimit: 30_000_000,
		Timestamp: uint64(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC).Unix()), ChainId: 1}).Serialize()
	sdk.StubSetContractReadResponder(func(_, key string) *string {
		switch key {
		case "h":
			h := strconv.FormatUint(late, 10)
			return &h
		case "b-" + strconv.FormatUint(late, 10):
			return &hdr
		}
		return nil
	})
	before := signRequestsFor("primary")
	if err := HandleRollWithdrawal(0, gen1, 1); err != nil {
		t.Fatalf("roll of generation 0's withdrawal after the cut-over: %v", err)
	}
	ps := GetPendingSpend(0)
	to, value, _, err := decodeUnsignedEIP1559(hexBytes(ps.UnsignedTxHex))
	if err != nil || !ps.Rolled || to != gen0 || value.Sign() != 0 {
		t.Fatalf("roll tx to %x value %v rolled %v: want a 0-value transfer to generation 0", to, value, ps.Rolled)
	}
	if signRequestsFor("primary") != before+1 || signRequestsFor("primaryv1") != 0 {
		t.Fatalf("roll signed by %v, want generation 0's key", sdk.TestSignRequests())
	}
	// A spend from an address no generation holds is still refused.
	ps.VaultAtQueue = "0x00000000000000000000000000000000000000ff"
	StorePendingSpend(*ps)
	if err := HandleRollWithdrawal(0, gen1, 1); err == nil {
		t.Fatal("rolled a withdrawal from an unknown address")
	}
}

// The recount advances on every drain, so a queue left from before the
// upgrade is counted with no one calling activateKey.
func TestA01_DrainStepsTheRecount(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	n := int(constants.MaxQueueWalk) + 1
	for i := 0; i < n; i++ {
		sdk.StateSetObject(queueKey(uint64(i)), `{"seq":`+strconv.Itoa(i)+`,"from":"hive:a","to":"0x00000000000000000000000000000000000000e2","asset":"eth","amount":1,"debit":2}`)
	}
	sdk.StateSetObject(constants.WithdrawQueueTailKey, strconv.Itoa(n))
	sdk.StateDeleteObject(constants.QueuedDebitExactKey)
	sdk.StubSetTssKey("") // nothing can issue: only the recount moves
	DrainWithdrawalQueue(1, 8)
	DrainWithdrawalQueue(1, 8)
	if !queuedDebitExact() || QueuedDebit("eth").Cmp(big.NewInt(int64(2*n))) != 0 {
		t.Fatalf("after two drains: exact %v, queued debit %s, want %d", queuedDebitExact(), QueuedDebit("eth"), 2*n)
	}
}

// A withdrawal generation 0 issued before its cut-over reverts on L1 after it:
// confirmSpend refunds the withdrawer and books the value back to generation
// 0, where it still is.
func TestA01_RevertedRetiringWithdrawalIsBookedToIt(t *testing.T) {
	w := newRollWorld(t)
	defer sdk.ResetStubState()
	var pub CompressedPubKey
	copy(pub[:], secp256k1.PrivKeyFromBytes(mustHex(t, rollVaultPriv)).PubKey().SerializeCompressed())
	SaveVaultState(VaultRegistry{
		{Generation: 0, Primary: pub, Status: VaultStatusDraining, Predecessor: 0},
		{Generation: 1, Primary: pubOf(t, testPub2), Status: VaultStatusActive, Predecessor: 0},
	}, 2, 1)
	if err := HandleConfirmSpend(w.mine(101, GetPendingSpend(0).UnsignedTxHex, 0), 1); err != nil {
		t.Fatal(err)
	}
	if GetBalance("hive:alice", "eth").Cmp(big.NewInt(1e18)) != 0 || VaultBook(0, "eth").Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("refund %s, generation 0 eth book %s: want 1 ETH each", GetBalance("hive:alice", "eth"), VaultBook(0, "eth"))
	}
}

// Activation does not snapshot the books from a queue not yet counted: it
// refuses until the recount (stepped by drains, or by activateKey itself in
// the wasm export) has finished.
func TestA01_ActivationWaitsForTheRecount(t *testing.T) {
	lifecycleBridge(t)
	genesisActive(t)
	n := int(constants.MaxQueueWalk) + 1
	for i := 0; i < n; i++ {
		sdk.StateSetObject(queueKey(uint64(i)), `{"seq":`+strconv.Itoa(i)+`,"from":"hive:a","to":"0x00000000000000000000000000000000000000e2","asset":"eth","amount":1,"debit":1}`)
	}
	sdk.StateSetObject(constants.WithdrawQueueTailKey, strconv.Itoa(n))
	sdk.StateDeleteObject(constants.QueuedDebitExactKey)
	MintNextGeneration(10)
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,1")
	_, _, _, err := ActivatePendingGeneration(11)
	mustErr(t, err, "counting")
	if v, _ := ActiveVault(); v.Generation != 0 {
		t.Fatal("activated on an uncounted queue")
	}
}

// Defense in depth behind NN#3 (createKey refuses while generation 0 still
// holds in-flight withdrawals): a second cut-over in that window is refused,
// so the withdrawal nonces never belong to two generations.
func TestA01_SecondCutOverWaitsForTheFirstHandOff(t *testing.T) {
	rotatedWithInFlight(t)
	if _, _, err := MintNextGeneration(100); err != nil { // bypassing createKey's NN#3
		t.Fatal(err)
	}
	sdk.StubSetTssKeyFor("primaryv2", "active,"+testPub3+",ecdsa,1,1")
	_, _, _, err := ActivatePendingGeneration(100)
	mustErr(t, err, "still hold the withdrawal nonces")
	if h, _ := WithdrawNonceHolder(); h != 0 {
		t.Fatalf("holder %d", h)
	}
}
