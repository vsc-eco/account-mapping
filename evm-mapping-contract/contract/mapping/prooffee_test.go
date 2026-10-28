package mapping

import (
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
)

// The proving fee: a deposit pays it out of its credit and a withdrawal on top
// of its debit, to hive:altera.app as an ordinary Magi balance. Supply does not
// move (the recipient's balance is user supply), and an unset fee charges
// nothing.

func feeBalance(asset string) *big.Int { return GetBalance(constants.ProofFeeRecipient, asset) }

func TestPROOFFEE_UnsetChargesNothing(t *testing.T) {
	w := newRP7World(t)
	n, _, nodes := w.mine(1, depositLog(DepositContractAddress(rp7Vault), rp7User, [20]byte{}, big.NewInt(1e18), "hive:bob"))
	if err := mapContract(n, nodes, 0); err != nil {
		t.Fatal(err)
	}
	if got := GetBalance("hive:bob", "eth"); got.Cmp(big.NewInt(99e16)) != 0 || feeBalance("eth").Sign() != 0 {
		t.Fatalf("no fee set: hive:bob %s, fee account %s; want 0.99 ETH and nothing", got, feeBalance("eth"))
	}
}

// MagiDeposit, ETH and token: the recipient gets the credit less the fee.
func TestPROOFFEE_ContractDepositsPayTheFee(t *testing.T) {
	w := newRP7World(t)
	SetProofFee("eth", big.NewInt(1e14))
	SetProofFee("USDC", big.NewInt(100_000))
	dc := DepositContractAddress(rp7Vault)
	n, _, nodes := w.mine(1, depositLog(dc, rp7User, [20]byte{}, big.NewInt(1e18), "hive:bob"))
	if err := mapContract(n, nodes, 0); err != nil {
		t.Fatal(err)
	}
	if got := GetBalance("hive:bob", "eth"); got.Cmp(big.NewInt(99e16-1e14)) != 0 || feeBalance("eth").Cmp(big.NewInt(1e14)) != 0 {
		t.Fatalf("ETH: hive:bob %s, fee account %s; want 0.99 ETH less 1e14 and 1e14", got, feeBalance("eth"))
	}
	if s := GetSupply("eth"); s.User.Cmp(big.NewInt(99e16)) != 0 {
		t.Fatalf("ETH user supply %s, want 0.99 ETH (credit + fee)", s.User)
	}
	n, _, nodes = w.mine(1, transferLog(rp7USDC, rp7User, rp7Vault, 3_000_000), depositLog(dc, rp7User, rp7USDC, big.NewInt(3_000_000), "hive:bob"))
	if err := mapContract(n, nodes, 1); err != nil {
		t.Fatal(err)
	}
	if got := GetBalance("hive:bob", "USDC"); got.Cmp(big.NewInt(2_900_000)) != 0 || feeBalance("USDC").Cmp(big.NewInt(100_000)) != 0 {
		t.Fatalf("USDC: hive:bob %s, fee account %s; want 2900000 and 100000", got, feeBalance("USDC"))
	}
	if s := GetSupply("USDC"); s.User.Cmp(big.NewInt(3_000_000)) != 0 || s.Active.Cmp(big.NewInt(3_000_000)) != 0 {
		t.Fatalf("USDC supply %+v, want 3000000 user and active", s)
	}
}

func TestPROOFFEE_ERC20DepositPaysTheFee(t *testing.T) {
	w := newRP7World(t)
	SetProofFee("USDC", big.NewInt(100_000))
	n, _, nodes := w.mine(1, transferLog(rp7USDC, rp7User, rp7Vault, 3_000_000))
	if err := mapERC20B64(n, nodes, 0); err != nil {
		t.Fatal(err)
	}
	if got := GetBalance(crypto.AddressToDID(rp7User), "USDC"); got.Cmp(big.NewInt(2_900_000)) != 0 || feeBalance("USDC").Cmp(big.NewInt(100_000)) != 0 {
		t.Fatalf("sender %s, fee account %s; want 2900000 and 100000", got, feeBalance("USDC"))
	}
}

// A credit smaller than the fee is paid in full as the fee, never a negative credit.
func TestPROOFFEE_ACreditSmallerThanTheFeeIsAllFee(t *testing.T) {
	rpBridge(t, big.NewInt(0), "hive:x")
	SetProofFee("eth", big.NewInt(500))
	if left := takeDepositProofFee("eth", big.NewInt(300)); left.Sign() != 0 || feeBalance("eth").Cmp(big.NewInt(300)) != 0 {
		t.Fatalf("credit 300 under a fee of 500: left %s, fee account %s; want 0 and 300", left, feeBalance("eth"))
	}
}

// A withdrawal pays the fee on top of the same debit it pays without one.
func TestPROOFFEE_WithdrawalsPayTheFeeOnTop(t *testing.T) {
	rpBridge(t, big.NewInt(0), "hive:a", "hive:b")
	before := GetBalance("hive:b", "eth")
	if _, err := ethUnmap(t, "hive:b"); err != nil {
		t.Fatal(err)
	}
	plain := new(big.Int).Sub(before, GetBalance("hive:b", "eth"))
	SetProofFee("eth", big.NewInt(1e14))
	supply := GetSupply("eth").User
	before = GetBalance("hive:a", "eth")
	if _, err := ethUnmap(t, "hive:a"); err != nil {
		t.Fatal(err)
	}
	paid := new(big.Int).Sub(before, GetBalance("hive:a", "eth"))
	if want := new(big.Int).Add(plain, big.NewInt(1e14)); paid.Cmp(want) != 0 || feeBalance("eth").Cmp(big.NewInt(1e14)) != 0 {
		t.Fatalf("hive:a paid %s, fee account %s; want %s (the same withdrawal's %s plus the fee) and 1e14", paid, feeBalance("eth"), want, plain)
	}
	// User supply falls by the withdrawal's debit only: the fee stays user supply.
	if got := GetSupply("eth").User; new(big.Int).Sub(supply, got).Cmp(plain) != 0 {
		t.Fatalf("user supply fell %s, want %s", new(big.Int).Sub(supply, got), plain)
	}

	// Without the fee on top of the debit the withdrawal is refused and nothing moves.
	rpBridge(t, big.NewInt(0), "hive:c")
	SetProofFee("eth", big.NewInt(1e14))
	SetBalance("hive:c", "eth", plain)
	if _, err := ethUnmap(t, "hive:c"); err == nil || !strings.Contains(err.Error(), "insufficient balance") {
		t.Fatalf("a balance that covers the withdrawal but not the fee: %v, want refused", err)
	}
	if GetBalance("hive:c", "eth").Cmp(plain) != 0 || feeBalance("eth").Sign() != 0 {
		t.Fatalf("after the refusal: hive:c %s, fee account %s; want both unchanged", GetBalance("hive:c", "eth"), feeBalance("eth"))
	}
}

func TestPROOFFEE_TokenWithdrawalPaysTheFeeOnTop(t *testing.T) {
	rpBridge(t, big.NewInt(1e18), "hive:a")
	SetProofFee("USDC", big.NewInt(20_000))
	as(t, "hive:a", rpNow)
	params := &TransferParams{Amount: "500000", To: "0x00000000000000000000000000000000000000e2", Asset: "USDC",
		TokenAddress: "0x00000000000000000000000000000000000000c0"}
	if _, err := HandleUnmapERC20(params, [20]byte{1}, 1); err != nil {
		t.Fatal(err)
	}
	if got := GetBalance("hive:a", "USDC"); got.Cmp(big.NewInt(1_000_000-500_000-20_000)) != 0 || feeBalance("USDC").Cmp(big.NewInt(20_000)) != 0 {
		t.Fatalf("hive:a %s, fee account %s; want 480000 and 20000", got, feeBalance("USDC"))
	}
	// 480,000 left: a 470,000 withdrawal plus the 20,000 fee does not fit.
	params.Amount = "470000"
	if _, err := HandleUnmapERC20(params, [20]byte{1}, 1); err == nil {
		t.Fatal("a token withdrawal whose fee does not fit was taken")
	}
	if GetBalance("hive:a", "USDC").Cmp(big.NewInt(480_000)) != 0 || feeBalance("USDC").Cmp(big.NewInt(20_000)) != 0 {
		t.Fatal("the refused token withdrawal moved balances")
	}
}

// unmapFrom: the owner pays the fee, and the spender's allowance must cover it.
func TestPROOFFEE_UnmapFromNeedsTheAllowanceToCoverTheFee(t *testing.T) {
	rpBridge(t, big.NewInt(1e18), "hive:owner1", "hive:spender")
	SetProofFee("USDC", big.NewInt(20_000))
	as(t, "hive:owner1", rpNow)
	params := &TransferParams{Amount: "500000", From: "hive:owner1", To: "0x00000000000000000000000000000000000000e2",
		Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}
	SetAllowance("hive:owner1", "hive:spender", "USDC", big.NewInt(500_000))
	as(t, "hive:spender", rpNow)
	if _, err := HandleUnmapFromStatus(params, [20]byte{1}, 1); err == nil || !strings.Contains(err.Error(), "insufficient allowance") {
		t.Fatalf("allowance for the amount but not the fee: %v, want refused", err)
	}
	if GetBalance("hive:owner1", "USDC").Cmp(big.NewInt(1_000_000)) != 0 || feeBalance("USDC").Sign() != 0 {
		t.Fatal("the refused unmapFrom moved balances")
	}
	SetAllowance("hive:owner1", "hive:spender", "USDC", big.NewInt(520_000))
	if _, err := HandleUnmapFromStatus(params, [20]byte{1}, 1); err != nil {
		t.Fatal(err)
	}
	if GetBalance("hive:owner1", "USDC").Cmp(big.NewInt(480_000)) != 0 || feeBalance("USDC").Cmp(big.NewInt(20_000)) != 0 ||
		GetAllowance("hive:owner1", "hive:spender", "USDC").Sign() != 0 || GetBalance("hive:spender", "USDC").Cmp(big.NewInt(1_000_000)) != 0 {
		t.Fatalf("owner %s, fee account %s, allowance left %s, spender %s; want 480000, 20000, 0 and the spender untouched",
			GetBalance("hive:owner1", "USDC"), feeBalance("USDC"), GetAllowance("hive:owner1", "hive:spender", "USDC"), GetBalance("hive:spender", "USDC"))
	}
}

// The fee pays for the proving a request causes: a queued withdrawal that is
// cancelled gets its debit back but not the fee.
func TestPROOFFEE_IsNotRefundedWithACancelledWithdrawal(t *testing.T) {
	rpBridge(t, big.NewInt(0), "hive:u")
	SetProofFee("eth", big.NewInt(1e14))
	before := GetBalance("hive:u", "eth")
	qfQueueETH(t, "hive:u", "")
	head, _ := QueueBounds()
	as(t, "hive:u", rpNow)
	if err := HandleCancelQueuedWithdrawal(head); err != nil {
		t.Fatal(err)
	}
	if got := GetBalance("hive:u", "eth"); new(big.Int).Sub(before, got).Cmp(big.NewInt(1e14)) != 0 || feeBalance("eth").Cmp(big.NewInt(1e14)) != 0 {
		t.Fatalf("after the cancel hive:u is down %s, fee account %s; want both 1e14", new(big.Int).Sub(before, got), feeBalance("eth"))
	}
}
