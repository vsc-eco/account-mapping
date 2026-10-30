package mapping

import (
	"math/big"
	"strconv"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

func wei(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(s)
	}
	return v
}

// lifecycleBridge is a fresh contract with a USDC token registered and no key.
func lifecycleBridge(t *testing.T) {
	t.Helper()
	sdk.ResetTestState()
	sdk.StubClearTssKeys()
	if err := RegisterTokenFull(1, [20]byte{0xa0}, "usdc", 6, 10_000_000, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func mustErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want it to contain %q", err, want)
	}
}

// genesisActive mints and activates generation 0 with key testPub1.
func genesisActive(t *testing.T) {
	t.Helper()
	if gen, name, err := MintNextGeneration(5); err != nil || gen != 0 || name != "primary" {
		t.Fatalf("genesis mint: %d %s %v", gen, name, err)
	}
	sdk.StubSetTssKeyFor("primary", "active,"+testPub1+",ecdsa,1,0")
	if g, _, had, err := ActivatePendingGeneration(6); err != nil || g != 0 || had {
		t.Fatalf("genesis activate: %d %v %v", g, had, err)
	}
}

func TestA01_GenesisCeremony(t *testing.T) {
	lifecycleBridge(t)
	if _, _, err := MintNextGeneration(5); err != nil {
		t.Fatal(err)
	}
	if _, _, err := MintNextGeneration(5); err == nil {
		t.Fatal("a second keygen while one is pending")
	}
	// Keygen not done, then not ecdsa: no activation.
	_, _, _, err := ActivatePendingGeneration(6)
	mustErr(t, err, "not an active ecdsa key")
	sdk.StubSetTssKeyFor("primary", "active,"+testPub1+",eddsa,1")
	_, _, _, err = ActivatePendingGeneration(6)
	mustErr(t, err, "not an active ecdsa key")
	// Agreed key, no verified check signature: refused (BRK-2).
	sdk.StubSetTssKeyFor("primary", "active,"+testPub1+",ecdsa,0")
	_, _, _, err = ActivatePendingGeneration(6)
	mustErr(t, err, "check signature")
	sdk.StubSetTssKeyFor("primary", "active,"+testPub1+",ecdsa")
	_, _, _, err = ActivatePendingGeneration(6)
	mustErr(t, err, "check signature")
	// A genesis key the old contract already checked (attestVault) may activate.
	sdk.StateSetObject(constants.VaultCheckedKey, testPub1)
	if g, _, had, err := ActivatePendingGeneration(6); err != nil || g != 0 || had {
		t.Fatalf("genesis with attestVault: %d %v %v", g, had, err)
	}
	v, ok := ActiveVault()
	if !ok || v.Primary != pubOf(t, testPub1) || v.ActivatedHeight != 6 || v.CreatedHeight != 5 {
		t.Fatalf("active after genesis: %+v %v", v, ok)
	}
	if addr, ok := TssVaultAddress(); !ok || addr != mustAddr(t, testAdr1) {
		t.Fatal("vault address is not the genesis key's")
	}
}

func mustAddr(t *testing.T, h string) [20]byte {
	t.Helper()
	v := Vault{Generation: 99}
	switch h {
	case testAdr1:
		v.Primary = pubOf(t, testPub1)
	case testAdr2:
		v.Primary = pubOf(t, testPub2)
	case testAdr3:
		v.Primary = pubOf(t, testPub3)
	}
	a, ok := GenAddress(&v)
	if !ok {
		t.Fatal("no address")
	}
	return a
}

func TestA01_RotationGates(t *testing.T) {
	lifecycleBridge(t)
	genesisActive(t)

	// The successor binds to the active generation.
	gen, name, err := MintNextGeneration(10)
	if err != nil || gen != 1 || name != "primaryv1" {
		t.Fatalf("rotation mint: %d %s %v", gen, name, err)
	}
	vaults, _, _, _ := LoadVaultState()
	if vaults[1].Predecessor != 0 || vaults[1].Status != VaultStatusPending {
		t.Fatalf("successor: %+v", vaults[1])
	}

	// Checked but not yet reshared: the old generation keeps serving (VR2-12).
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,0")
	_, _, _, err = ActivatePendingGeneration(11)
	mustErr(t, err, "reshared")
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1")
	_, _, _, err = ActivatePendingGeneration(11)
	mustErr(t, err, "reshared")
	// Reshared but never checked: refused; the attestVault shortcut is genesis-only.
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,0,1")
	sdk.StateSetObject(constants.VaultCheckedKey, testPub2)
	_, _, _, err = ActivatePendingGeneration(11)
	mustErr(t, err, "check signature")

	// ROT-HALT-1: a withdrawal in flight does not hold the cut-over back.
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,1")
	SetPendingNonce(4)
	SetConfirmedNonce(3)

	// Nothing changed by the refusals.
	if v, _ := ActiveVault(); v.Generation != 0 {
		t.Fatalf("active moved on a refused activation: %+v", v)
	}

	g, retired, had, err := ActivatePendingGeneration(11)
	if err != nil || g != 1 || retired != 0 || !had {
		t.Fatalf("rotation: %d %d %v %v", g, retired, had, err)
	}
	vaults, next, active, _ := LoadVaultState()
	if active != 1 || next != 2 || vaults[0].Status != VaultStatusRetiring || vaults[0].RetiredHeight != 11 ||
		vaults[1].Status != VaultStatusActive || vaults[1].Primary != pubOf(t, testPub2) {
		t.Fatalf("after rotation: %+v next %d active %d", vaults, next, active)
	}
	// Generation 0 keeps the nonces for its in-flight withdrawal, and its
	// sweeps start after it; new withdrawals wait for the hand-off.
	if h, held := WithdrawNonceHolder(); !held || h != 0 || GetPendingNonce() != 4 || GetConfirmedNonce() != 3 {
		t.Fatalf("holder %d %v, nonces %d/%d", h, held, GetConfirmedNonce(), GetPendingNonce())
	}
	if c, ok := WithdrawCeiling(0); !ok || c != 4 || SweepNonce(0) != 4 {
		t.Fatalf("ceiling %d %v, sweep nonce %d", c, ok, SweepNonce(0))
	}
	if !withdrawalNoncesHeld() || !holdsInFlightWithdrawals(0) {
		t.Fatal("new withdrawals not held while generation 0's is in flight")
	}
	SetConfirmedNonce(4) // it settles
	if withdrawalNoncesHeld() || holdsInFlightWithdrawals(0) {
		t.Fatal("no hand-off once generation 0's withdrawal settled")
	}
	if _, held := WithdrawNonceHolder(); held {
		t.Fatal("holder kept after the hand-off")
	}
	// The new address starts at nonce 0; the retiring one sweeps from its own.
	if GetPendingNonce() != 0 || GetConfirmedNonce() != 0 || SweepNonce(0) != 4 {
		t.Fatalf("nonces: pending %d confirmed %d sweep %d", GetPendingNonce(), GetConfirmedNonce(), SweepNonce(0))
	}
	if ActiveKeyName() != "primaryv1" {
		t.Fatalf("active key %s", ActiveKeyName())
	}
	if addr, ok := TssVaultAddress(); !ok || addr != mustAddr(t, testAdr2) {
		t.Fatal("vault address did not move to the new generation")
	}
}

func TestA01_RetiringSnapshotBooksTheCustody(t *testing.T) {
	lifecycleBridge(t)
	genesisActive(t)
	SetSupply("eth", Supply{Active: wei("5000000000000000000"), User: wei("4900000000000000000"), Fee: new(big.Int)})
	SetSupply("usdc", Supply{Active: wei("700000000"), User: wei("700000000"), Fee: new(big.Int)})
	// Two queued withdrawals: debited from the custody, still at the vault.
	Enqueue(QueuedWithdrawal{From: "hive:a", To: "0x00000000000000000000000000000000000000e2", Asset: "eth",
		Amount: wei("1000000000000000000"), Debit: wei("1001000000000000000")})
	Enqueue(QueuedWithdrawal{From: "hive:b", To: "0x00000000000000000000000000000000000000e3", Asset: "usdc",
		Amount: wei("50000000"), Debit: wei("50000000")})

	MintNextGeneration(10)
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,1")
	if _, _, _, err := ActivatePendingGeneration(11); err != nil {
		t.Fatal(err)
	}
	if got := VaultBook(0, "eth"); got.Cmp(wei("6001000000000000000")) != 0 {
		t.Fatalf("eth book %s, want custody 5 + queued 1.001", got)
	}
	if got := VaultBook(0, "usdc"); got.Cmp(wei("750000000")) != 0 {
		t.Fatalf("usdc book %s, want 700 + queued 50", got)
	}
	if funded, _ := AnyFundedSupersededGen(); !funded {
		t.Fatal("NN#3 does not see the funded retiring generation")
	}
	if _, _, err := MintNextGeneration(12); err != nil {
		t.Fatal("minting itself is not gated (createKey checks NN#3):", err)
	}
}

// ROT-HALT-1: a queue written before the counters existed is counted a bounded
// walk at a time, never by waiting for it to empty; entries queued or removed
// meanwhile keep the count right.
func TestA01_LegacyQueueIsRecountedInSteps(t *testing.T) {
	lifecycleBridge(t)
	genesisActive(t)
	n := int(constants.MaxQueueWalk) + 6
	sum := big.NewInt(0)
	for i := 0; i < n; i++ {
		sdk.StateSetObject(queueKey(uint64(i)), `{"seq":`+strconv.Itoa(i)+`,"from":"hive:a","to":"0x00000000000000000000000000000000000000e2","asset":"eth","amount":1,"debit":`+strconv.Itoa(i+1)+`}`)
		sum.Add(sum, big.NewInt(int64(i+1)))
	}
	sdk.StateSetObject(constants.WithdrawQueueTailKey, strconv.Itoa(n))
	sdk.StateDeleteObject(constants.QueuedDebitExactKey)
	if StepQueuedDebitRecount() {
		t.Fatalf("one step walked all %d entries, more than MaxQueueWalk", n)
	}
	Enqueue(QueuedWithdrawal{From: "hive:b", To: "0x00000000000000000000000000000000000000e3", Asset: "eth", Amount: big.NewInt(1), Debit: big.NewInt(1000)})
	RemoveQueued(0, GetQueued(0))                     // walked: its 1 was counted
	RemoveQueued(uint64(n-1), GetQueued(uint64(n-1))) // not walked yet: its n never is
	if !StepQueuedDebitRecount() {
		t.Fatal("the second step did not finish the walk")
	}
	want := new(big.Int).Sub(sum, big.NewInt(int64(1+n)))
	want.Add(want, big.NewInt(1000))
	if got := QueuedDebit("eth"); got.Cmp(want) != 0 {
		t.Fatalf("queued debit %s after the recount, want %s", got, want)
	}
	MintNextGeneration(10)
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,1")
	if _, _, _, err := ActivatePendingGeneration(11); err != nil {
		t.Fatal(err)
	}
}

func TestA01_SnapshotRefusesBooksAboveTheCustody(t *testing.T) {
	lifecycleBridge(t)
	genesisActive(t)
	SetSupply("eth", Supply{Active: wei("100"), User: wei("100"), Fee: new(big.Int)})
	// A superseded generation booked more than the whole custody: inconsistent.
	vaults, next, active, _ := LoadVaultState()
	vaults = append(vaults, Vault{Generation: 7, Status: VaultStatusDraining, Predecessor: 6})
	SaveVaultState(vaults, next, active)
	setVaultBook(7, "eth", wei("150"))
	if g, _, err := MintNextGeneration(10); err != nil || g != 1 {
		t.Fatalf("mint: %d %v", g, err)
	}
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,1")
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("activation booked a negative balance")
		}
	}()
	ActivatePendingGeneration(11)
}

func TestA01_DiscardAndRenew(t *testing.T) {
	lifecycleBridge(t)
	genesisActive(t)
	MintNextGeneration(10)
	if g, err := DiscardPendingGeneration(); err != nil || g != 1 {
		t.Fatalf("discard: %d %v", g, err)
	}
	if _, err := DiscardPendingGeneration(); err == nil {
		t.Fatal("discarded twice")
	}
	// The number is not reused.
	if g, name, _ := MintNextGeneration(12); g != 2 || name != "primaryv2" {
		t.Fatalf("re-mint got gen %d %s, want 2", g, name)
	}

	// Renew: fund-holding generations only; an unrenewable one is reported.
	vaults, next, active, _ := LoadVaultState()
	vaults = append(vaults, Vault{Generation: 3, Status: VaultStatusPurged, Predecessor: 2},
		Vault{Generation: 4, Status: VaultStatusDraining, Predecessor: 3})
	SaveVaultState(vaults, next, active)
	sdk.StubSetTssKeyFor("primaryv4", "retired,"+testPub3+",ecdsa")
	ren, skip, err := RenewableVaultKeyNames()
	if err != nil || len(ren) != 1 || ren[0] != "primary" || len(skip) != 1 || skip[0] != "primaryv4" {
		t.Fatalf("renewable %v skipped %v %v", ren, skip, err)
	}
}

// A generation activates only with the key the ceremony produced: a registered
// key that the TSS group now reports differently is refused, and a successor
// must descend from the active generation.
func TestA01_KeyAndLineageGuards(t *testing.T) {
	lifecycleBridge(t)
	// Legacy unchecked "primary" folds Pending with its key pinned.
	sdk.StubSetTssKeyFor("primary", "active,"+testPub1+",ecdsa")
	if _, _, err := MintNextGeneration(5); err == nil {
		t.Fatal("minted over a folded pending genesis")
	}
	sdk.StubSetTssKeyFor("primary", "active,"+testPub2+",ecdsa,1")
	_, _, _, err := ActivatePendingGeneration(6)
	mustErr(t, err, "does not match the TSS ceremony output")
	sdk.StubSetTssKeyFor("primary", "active,"+testPub1+",ecdsa,1")
	if _, _, _, err := ActivatePendingGeneration(6); err != nil {
		t.Fatal(err)
	}

	// Broken lineage: a pending successor that names another predecessor.
	MintNextGeneration(10)
	vaults, next, active, _ := LoadVaultState()
	vaults[1].Predecessor = 7
	SaveVaultState(vaults, next, active)
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,1")
	_, _, _, err = ActivatePendingGeneration(11)
	mustErr(t, err, "broken lineage")
}

// Guards that only matter in states other guards usually hide: a second keygen
// while a rotation's is pending, a genesis vault next to an active one, and the
// queued-debit counter after a removal.
func TestA01_IsolatedGuards(t *testing.T) {
	lifecycleBridge(t)
	genesisActive(t)
	MintNextGeneration(10)
	if _, _, err := MintNextGeneration(10); err == nil {
		t.Fatal("a second keygen while a rotation's is pending")
	}

	// A genesis-marked pending vault cannot activate beside an active one.
	lifecycleBridge(t)
	genesisActive(t)
	vaults, _, active, _ := LoadVaultState()
	vaults = append(vaults, Vault{Generation: 1, Predecessor: 1, Status: VaultStatusPending})
	SaveVaultState(vaults, 2, active)
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,1")
	_, _, _, err := ActivatePendingGeneration(11)
	mustErr(t, err, "genesis vault cannot activate")

	// A removed queue entry leaves the snapshot.
	lifecycleBridge(t)
	genesisActive(t)
	SetSupply("usdc", Supply{Active: wei("100"), User: wei("100"), Fee: new(big.Int)})
	q := QueuedWithdrawal{From: "hive:a", To: "0x00000000000000000000000000000000000000e2", Asset: "usdc", Amount: wei("30"), Debit: wei("30")}
	Enqueue(q)
	q.Amount, q.Debit = wei("20"), wei("20")
	seq := Enqueue(q)
	RemoveQueued(seq, GetQueued(seq))
	MintNextGeneration(10)
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,1")
	if _, _, _, err := ActivatePendingGeneration(11); err != nil {
		t.Fatal(err)
	}
	if got := VaultBook(0, "usdc"); got.Cmp(wei("130")) != 0 {
		t.Fatalf("usdc book %s, want 100 + the one queued 30", got)
	}
}
