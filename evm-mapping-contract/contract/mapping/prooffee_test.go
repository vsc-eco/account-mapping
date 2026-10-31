package mapping

import (
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
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

// A11: an ERC-20 withdrawal pays the L1 gas the ETH reserve fronts for it in
// the token, at the owner's rate, out of what it sends, to the operator; at
// most half the token's minimum withdrawal. Unset, nothing is charged.
func TestA11_TokenWithdrawalPaysItsGasInTheToken(t *testing.T) {
	issue := func(rate string) (*PendingSpend, *big.Int) {
		t.Helper()
		rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
		sdk.StateSetObject(constants.TokenRegistryPrefix+"1-00000000000000000000000000000000000000c0", "USDC|6|2000000") // min 2 USDC
		if rate != "" {
			r, _ := new(big.Int).SetString(rate, 10)
			SetTokenGasRate("USDC", r)
		}
		IncBalance("hive:alice", "USDC", big.NewInt(3_000_000))
		TrackDeposit("USDC", big.NewInt(3_000_000), new(big.Int))
		before := new(big.Int).Set(GetSupply("USDC").Active)
		sdk.SetTestCaller("hive:alice")
		status, err := HandleUnmapERC20(&TransferParams{Amount: "3000000", To: "0x00000000000000000000000000000000000000e2", Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1)
		if err != nil || !strings.HasPrefix(status, "issued:") {
			t.Fatalf("unmapERC20: %q %v", status, err)
		}
		return GetPendingSpend(0), new(big.Int).Sub(before, GetSupply("USDC").Active)
	}
	// 65,000 gas at 2x the 1 gwei base fee + 2 gwei tip = 2.6e14 wei; at 3,000
	// USDC per ETH that is 0.78 USDC.
	ps, out := issue("3000000000")
	_, _, data, _ := decodeUnsignedEIP1559(hexBytes(ps.UnsignedTxHex))
	sent := new(big.Int).SetBytes(data[36:68])
	if sent.Cmp(big.NewInt(2_220_000)) != 0 || ps.Amount.Cmp(sent) != 0 {
		t.Fatalf("sends %s (record %s), want 3 USDC less the 0.78 USDC gas fee", sent, ps.Amount)
	}
	if got := GetBalance(constants.TokenGasFeeRecipient, "USDC"); got.Cmp(big.NewInt(780_000)) != 0 {
		t.Fatalf("operator got %s, want 780000", got)
	}
	if out.Cmp(sent) != 0 {
		t.Fatalf("custody fell by %s, want only what left (%s): the fee stays in custody", out, sent)
	}
	// Rounded up: 2.6e14 wei at 3,000.000001 USDC per ETH is 780,000.00026.
	issue("3000000001")
	if got := GetBalance(constants.TokenGasFeeRecipient, "USDC"); got.Cmp(big.NewInt(780_001)) != 0 {
		t.Fatalf("operator got %s, want 780001 (rounded up)", got)
	}
	// A rate far off is capped at half the minimum withdrawal.
	ps, _ = issue("3000000000000")
	if got := GetBalance(constants.TokenGasFeeRecipient, "USDC"); got.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Fatalf("capped fee %s, want 1000000 (half the 2 USDC minimum)", got)
	}
	_ = ps
	// No rate: no fee.
	ps, _ = issue("")
	if ps.Amount.Cmp(big.NewInt(3_000_000)) != 0 || GetBalance(constants.TokenGasFeeRecipient, "USDC").Sign() != 0 {
		t.Fatalf("no rate: sends %s, operator %s", ps.Amount, GetBalance(constants.TokenGasFeeRecipient, "USDC"))
	}
}

// A11: a queued ERC-20 withdrawal whose gas fee came to its whole amount (its
// token's minimum withdrawal raised since it was queued, so the cap with it) is
// refunded in full, not sent for nothing.
func TestA11_GasFeeNotBelowTheAmountIsRefunded(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	reg := constants.TokenRegistryPrefix + "1-00000000000000000000000000000000000000c0"
	sdk.StateSetObject(reg, "USDC|6|2000000")
	IncBalance("hive:alice", "USDC", big.NewInt(3_000_000))
	TrackDeposit("USDC", big.NewInt(3_000_000), new(big.Int))
	SetPendingNonce(constants.MaxInFlightWithdrawals) // it queues
	sdk.SetTestCaller("hive:alice")
	if status, err := HandleUnmapERC20(&TransferParams{Amount: "3000000", To: "0x00000000000000000000000000000000000000e2", Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1); err != nil || !strings.HasPrefix(status, "queued:") {
		t.Fatalf("unmapERC20: %q %v", status, err)
	}
	before := GetBalance("hive:alice", "USDC")
	sdk.StateSetObject(reg, "USDC|6|10000000") // min 10 USDC: the cap is now 5
	SetTokenGasRate("USDC", new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	SetPendingNonce(0)
	if drainWith(1, [20]byte{1}, 8) != 0 || GetPendingSpend(0) != nil {
		t.Fatal("issued a withdrawal its gas fee eats whole")
	}
	if got := new(big.Int).Sub(GetBalance("hive:alice", "USDC"), before); got.Cmp(big.NewInt(3_000_000)) != 0 || QueueLen() != 0 {
		t.Fatalf("refunded %s, queue %d: want the 3 USDC back and the entry gone", got, QueueLen())
	}
}
