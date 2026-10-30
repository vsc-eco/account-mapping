package mapping

import (
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

// C6 / E21: a deposit is credited to the node's canonical identity for the
// depositor (did:pkh:eip155:1: and the EIP-55 address) on every L1 chain, the
// identity the gateway credits HBD (RC) to and the node can authenticate.
func TestC6E21_DepositIsCreditedToTheCanonicalIdentity(t *testing.T) {
	sdk.ResetTestState()
	defer sdk.ResetTestState()
	sender, _ := crypto.HexToAddress("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
	const want = "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	for _, chainId := range []uint64{1, 11155111, 8453} {
		if got := routeDeposit(sender, nil, "eth", big.NewInt(1000), chainId); got != want {
			t.Errorf("chain %d: deposit credited to %s, want %s", chainId, got, want)
		}
	}
}

// C6: every casing of one Ethereum address reaches one balance, so the user is
// never split between the identity the bridge credits and the one they sign as.
func TestC6_AllCasingsOfAnAddressShareOneBalance(t *testing.T) {
	sdk.ResetTestState()
	defer sdk.ResetTestState()
	const canon = "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	const lower = "did:pkh:eip155:1:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	IncBalance(canon, "eth", big.NewInt(1000))
	if got := GetBalance(lower, "eth"); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("lowercase identity sees %s, want 1000", got)
	}
	sdk.SetTestCaller(lower)
	if err := HandleTransfer(&TransferParams{To: "hive:bob", Amount: "400", Asset: "eth"}); err != nil {
		t.Fatalf("transfer signed with the lowercase identity: %v", err)
	}
	if got := GetBalance(canon, "eth"); got.Cmp(big.NewInt(600)) != 0 {
		t.Fatalf("canonical balance %s after a 400 transfer, want 600", got)
	}
	// A transfer to the other casing lands on the same balance.
	sdk.SetTestCaller("hive:bob")
	if err := HandleTransfer(&TransferParams{To: lower, Amount: "100", Asset: "eth"}); err != nil {
		t.Fatal(err)
	}
	if got := GetBalance(canon, "eth"); got.Cmp(big.NewInt(700)) != 0 {
		t.Fatalf("canonical balance %s after receiving 100 at the lowercase casing, want 700", got)
	}
	// Allowances and relayer entries follow the same identity.
	SetAllowance(canon, lower, "eth", big.NewInt(5))
	if got := GetAllowance(lower, canon, "eth"); got.Cmp(big.NewInt(5)) != 0 {
		t.Fatalf("allowance across casings = %s, want 5", got)
	}
	SetRelayer(lower)
	if !IsWhitelistedRelayer(canon) {
		t.Fatal("relayer registered under one casing is not found under the other")
	}
}

// C6: the original withdrawer is recognised under any casing of their address
// (cancelMyWithdrawal; expireWithdrawal's early-cancel gate). The calls still
// fail later, on the absent drop proof; the identity gate must not be what
// refuses them.
func TestC6_OriginalWithdrawerIsRecognisedUnderAnyCasing(t *testing.T) {
	const canon = "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	const lower = "did:pkh:eip155:1:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	for name, op := range map[string]func() error{
		"cancelMyWithdrawal": func() error { return HandleCancelMyWithdrawal(0, L1ProofOfDrop{}, 1) },
		"expireWithdrawal":   func() error { return HandleExpireWithdrawal(0, L1ProofOfDrop{}, 1) },
	} {
		sdk.ResetTestState()
		StorePendingSpend(PendingSpend{Nonce: 0, Amount: big.NewInt(1), From: canon, To: "0x00000000000000000000000000000000000000e2", Asset: "eth", BlockHeight: 1 << 40, VaultAtQueue: "0x0100000000000000000000000000000000000000"})
		SetPendingNonce(1)
		sdk.SetTestCaller(lower)
		err := op()
		if err != nil && (strings.Contains(err.Error(), "only the original withdrawer") || strings.Contains(err.Error(), "caller is not original withdrawer")) {
			t.Errorf("%s signed with the lowercase casing of the withdrawer: %v", name, err)
		}
		// Control: a different identity is refused at the gate.
		sdk.SetTestCaller("hive:mallory")
		if err := op(); err == nil || !(strings.Contains(err.Error(), "only the original withdrawer") || strings.Contains(err.Error(), "caller is not original withdrawer")) {
			t.Errorf("%s by another identity = %v, want the original-withdrawer refusal", name, err)
		}
	}
	sdk.ResetTestState()
}
