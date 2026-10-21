package mapping

import (
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// ALLOW-1: the allowance key joined owner and spender with "-", which Hive
// names contain, so hive:alice approving the spender "bob-hive:mallory" wrote
// hive:alice-bob's allowance for hive:mallory, and mallory took alice-bob's
// funds (proven on the bridge wasm 2026-10-21). The spender is now checked and
// the key uses "|".
func TestALLOW1_CraftedSpenderCannotForgeAnotherOwnersAllowance(t *testing.T) {
	sdk.ResetTestState()
	defer sdk.ResetTestState()
	IncBalance("hive:alice-bob", "eth", big.NewInt(1e18))

	sdk.SetTestCaller("hive:alice")
	err := HandleApprove(&AllowanceParams{Spender: "bob-hive:mallory", Amount: "1000000000000000000", Asset: "eth"})
	if err == nil || !strings.Contains(err.Error(), "invalid spender") {
		t.Fatalf("approve(spender=bob-hive:mallory) = %v, want an invalid spender refusal", err)
	}

	sdk.SetTestCaller("hive:mallory")
	if err := HandleTransferFrom(&TransferParams{From: "hive:alice-bob", To: "hive:mallory", Amount: "1000000000000000000", Asset: "eth"}); err == nil {
		t.Fatal("mallory spent hive:alice-bob's balance without an allowance from hive:alice-bob")
	}
	if got := GetBalance("hive:alice-bob", "eth"); got.Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("victim balance %s, want 1e18", got)
	}
}

// The key itself no longer collides, even for a spender string that got stored
// without the check: alice's allowance for "bob-hive:mallory" and alice-bob's
// allowance for hive:mallory are different keys.
func TestALLOW1_AllowanceKeysOfDifferentOwnersNeverCollide(t *testing.T) {
	a := allowanceKey("hive:alice", "bob-hive:mallory", "eth")
	b := allowanceKey("hive:alice-bob", "hive:mallory", "eth")
	if a == b {
		t.Fatalf("allowance keys collide: %q", a)
	}
}

// The checked spender still accepts every kind of Magi identity.
func TestALLOW1_ValidSpendersAreAccepted(t *testing.T) {
	for _, spender := range []string{"hive:bob", "hive:alice-bob", "did:pkh:eip155:1:0x00000000000000000000000000000000000000e2", "contract:vsc1BdrQ6EtbQ64rq2PkPd21x4MaLnVRcJj85d", "system:fr_balance"} {
		sdk.ResetTestState()
		sdk.SetTestCaller("hive:alice")
		if err := HandleApprove(&AllowanceParams{Spender: spender, Amount: "1", Asset: "eth"}); err != nil {
			t.Errorf("approve(spender=%s) refused: %v", spender, err)
		}
		if err := HandleIncreaseAllowance(&AllowanceParams{Spender: spender, Amount: "1", Asset: "eth"}); err != nil {
			t.Errorf("increaseAllowance(spender=%s) refused: %v", spender, err)
		}
		if err := HandleDecreaseAllowance(&AllowanceParams{Spender: spender, Amount: "1", Asset: "eth"}); err != nil {
			t.Errorf("decreaseAllowance(spender=%s) refused: %v", spender, err)
		}
	}
	sdk.ResetTestState()
}

func TestALLOW1_EveryAllowanceWriterChecksTheSpender(t *testing.T) {
	for name, op := range map[string]func() error{
		"approve":           func() error { return HandleApprove(&AllowanceParams{Spender: "bob-hive:mallory", Amount: "1", Asset: "eth"}) },
		"increaseAllowance": func() error { return HandleIncreaseAllowance(&AllowanceParams{Spender: "bob-hive:mallory", Amount: "1", Asset: "eth"}) },
		"decreaseAllowance": func() error { return HandleDecreaseAllowance(&AllowanceParams{Spender: "bob-hive:mallory", Amount: "1", Asset: "eth"}) },
	} {
		sdk.ResetTestState()
		sdk.SetTestCaller("hive:alice")
		if err := op(); err == nil || !strings.Contains(err.Error(), "invalid spender") {
			t.Errorf("%s with a crafted spender = %v, want an invalid spender refusal", name, err)
		}
	}
	sdk.ResetTestState()
}

// A5: a transfer to something that is not a Magi identity parked the funds at a
// key nobody can sign for.
func TestA5_TransferRefusesMalformedRecipients(t *testing.T) {
	for _, to := range []string{"", "bob", "not an address", "hive:Alice", "hive:ab", "did:pkh:eip155:1:0xzz", "did:pkh:eip155:11155111:0x00000000000000000000000000000000000000e2"} {
		for name, op := range map[string]func() error{
			"transfer":     func() error { return HandleTransfer(&TransferParams{To: to, Amount: "100", Asset: "eth"}) },
			"transferFrom": func() error { return HandleTransferFrom(&TransferParams{From: "hive:alice", To: to, Amount: "100", Asset: "eth"}) },
		} {
			sdk.ResetTestState()
			sdk.SetTestCaller("hive:alice")
			IncBalance("hive:alice", "eth", big.NewInt(1000))
			SetAllowance("hive:alice", "hive:alice", "eth", big.NewInt(1000))
			if err := op(); err == nil || !strings.Contains(err.Error(), "invalid recipient") {
				t.Errorf("%s(to=%q) = %v, want an invalid recipient refusal", name, to, err)
			}
			if got := GetBalance("hive:alice", "eth"); got.Cmp(big.NewInt(1000)) != 0 {
				t.Errorf("%s(to=%q) debited the sender: %s", name, to, got)
			}
		}
	}
	sdk.ResetTestState()
}

// A5: a deposit_to / swap_to that is not a Magi identity leaves the deposit with
// the depositor (the L1 calldata is final, so refusing would strand the ETH).
func TestA5_MalformedDepositDestinationCreditsTheDepositor(t *testing.T) {
	sdk.ResetTestState()
	defer sdk.ResetTestState()
	var sender [20]byte
	sender[19] = 0xd1
	for _, instr := range [][]string{{"deposit_to=bob-hive:mallory"}, {"deposit_to=not an address"}, {"swap_to=hive:Alice", "asset_out=hbd"}} {
		dest := routeDeposit(sender, instr, "eth", big.NewInt(1000), 1)
		if strings.Contains(dest, "mallory") || strings.Contains(dest, "not an") || dest == "" {
			t.Errorf("instructions %v routed the deposit to %q, want the depositor", instr, dest)
		}
	}
	if dest := routeDeposit(sender, []string{"deposit_to=hive:bob"}, "eth", big.NewInt(1000), 1); dest != "hive:bob" {
		t.Errorf("a valid deposit_to=hive:bob routed to %q", dest)
	}
}

// A5: with a router registered, a swap_to that is not a Magi identity must not
// reach the router; the deposit stays with the depositor.
func TestA5_MalformedSwapRecipientNeverReachesTheRouter(t *testing.T) {
	sdk.ResetStubState()
	defer sdk.ResetStubState()
	sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
	calls := 0
	sdk.StubSetContractCallResponder(func(contractId, method, payload string) *string {
		calls++
		ok := `{"ok":true,"result":"{}"}`
		return &ok
	})
	var sender [20]byte
	sender[19] = 0xd1
	dest := routeDeposit(sender, []string{"swap_to=hive:Alice", "asset_out=hbd"}, "eth", big.NewInt(1000), 1)
	if calls != 0 {
		t.Errorf("router called %d times for swap_to=hive:Alice", calls)
	}
	if dest == "" || strings.Contains(dest, "Alice") {
		t.Errorf("deposit routed to %q, want the depositor", dest)
	}
	// Control: a valid swap_to does reach the router.
	routeDeposit(sender, []string{"swap_to=hive:bob", "asset_out=hbd"}, "eth", big.NewInt(1000), 1)
	if calls != 1 {
		t.Errorf("router calls after a valid swap_to = %d, want 1", calls)
	}
}
