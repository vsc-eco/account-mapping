package mapping

import (
	"math/big"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// Supply semantics per the product spec:
//
//   Active — exact custody (max theoretical spend); L1 gas paid is debited,
//            never parked in Fee.
//   Fee    — Magi-internal revenue fees only. None exist today → always 0.
//   User   — Σ of all Magi account balances (contracts count as users).
//
// For eth, the gas reserve sits outside the user/fee attribution:
//   Active("eth") == User + Fee + gasReserve.

// ethInvariant asserts Active == User + Fee + reserve for the eth supply.
func ethInvariant(t *testing.T, label string) {
	t.Helper()
	s := GetSupply("eth")
	want := new(big.Int).Add(s.User, s.Fee)
	want.Add(want, getGasReserve())
	if s.Active.Cmp(want) != 0 {
		t.Fatalf("%s: Active(eth) != User+Fee+reserve: Active=%s User=%s Fee=%s reserve=%s",
			label, s.Active, s.User, s.Fee, getGasReserve())
	}
	if s.Fee.Sign() != 0 {
		t.Fatalf("%s: Fee must stay 0 (no Magi revenue fees exist): got %s", label, s.Fee)
	}
}

// TestSupply_DepositTaxGoesToReserveNotFee — the 1% ETH deposit tax is
// reserve provisioning, not a Magi fee: Active gets the full deposit, User
// the net credit, Fee stays 0, and the reserve counter absorbs the tax.
func TestSupply_DepositTaxGoesToReserveNotFee(t *testing.T) {
	sdk.ResetTestStateStore()

	deposit := big.NewInt(1_000_000_000_000_000_000) // 1 ETH in wei
	gasTax := new(big.Int).Div(
		new(big.Int).Mul(deposit, big.NewInt(constants.GasReserveDepositTaxBps)),
		big.NewInt(10000),
	)
	userNet := new(big.Int).Sub(deposit, gasTax)

	// Mirror HandleMap's eth deposit accounting.
	addGasReserve(gasTax)
	IncBalance("hive:alice", "eth", userNet)
	TrackDeposit("eth", userNet, gasTax)

	s := GetSupply("eth")
	if s.Active.Cmp(deposit) != 0 {
		t.Fatalf("Active must equal the FULL deposit (custody): want %s, got %s", deposit, s.Active)
	}
	if s.User.Cmp(userNet) != 0 {
		t.Fatalf("User must equal the net credit: want %s, got %s", userNet, s.User)
	}
	if got := getGasReserve(); got.Cmp(gasTax) != 0 {
		t.Fatalf("reserve must hold the tax: want %s, got %s", gasTax, got)
	}
	ethInvariant(t, "after deposit")
}

// TestSupply_UnmapRoundtrips walks the three withdrawal outcomes for the
// fee-on-top ETH path and checks the invariant at every step:
//
//	unmap    → Active/User -= value+fee
//	success  → no further movement
//	reverted → +value back (gas stays spent, borne by the withdrawer)
//	dropped  → +value back (E9: only Type-A mined-reverted proofs are accepted,
//	           so the gas was paid; value only, never the fee)
func TestSupply_UnmapRoundtrips(t *testing.T) {
	value := big.NewInt(500_000)
	fee := big.NewInt(42_000)
	debit := new(big.Int).Add(value, fee)

	seed := func() {
		sdk.ResetTestStateStore()
		IncBalance("hive:alice", "eth", debit)
		TrackDeposit("eth", debit, new(big.Int))
		ethInvariant(t, "seeded")
		// Unmap: user pays value+fee; custody will shrink by the same.
		DecBalance("hive:alice", "eth", debit)
		TrackWithdrawal("eth", debit)
		ethInvariant(t, "after unmap")
	}

	t.Run("success_leaves_nothing", func(t *testing.T) {
		seed()
		s := GetSupply("eth")
		if s.Active.Sign() != 0 || s.User.Sign() != 0 {
			t.Fatalf("after successful unmap supply must be empty: Active=%s User=%s", s.Active, s.User)
		}
	})

	t.Run("reverted_refunds_value_only", func(t *testing.T) {
		seed()
		// Mirror HandleConfirmSpend's failure branch.
		IncBalance("hive:alice", "eth", value)
		s := GetSupply("eth")
		s.Active.Add(s.Active, value)
		s.User.Add(s.User, value)
		SetSupply("eth", s)
		ethInvariant(t, "after reverted refund")
		// The user bore the gas: net position is -fee.
		if got := GetBalance("hive:alice", "eth"); got.Cmp(value) != 0 {
			t.Fatalf("reverted refund: want balance %s, got %s", value, got)
		}
	})

	t.Run("dropped_refunds_value_only", func(t *testing.T) {
		seed()
		refundDroppedWithdrawal(&PendingSpend{
			Amount: value, From: "hive:alice", Asset: "eth", GasCost: fee,
		})
		ethInvariant(t, "after dropped refund")
		// E9 (RV re-verify): the only drop proof the verifier accepts is Type-A
		// (mined, reverted) — the tx mined and the L1 gas was genuinely paid, so
		// only the VALUE comes back, never the fee (matches the reverted branch
		// above). The pre-fix refund of value+fee was a slow drain a withdrawer
		// could farm with reverting withdrawals.
		if got := GetBalance("hive:alice", "eth"); got.Cmp(value) != 0 {
			t.Fatalf("dropped refund must return value only: want %s, got %s", value, got)
		}
		s := GetSupply("eth")
		if s.Active.Cmp(value) != 0 || s.User.Cmp(value) != 0 {
			t.Fatalf("dropped refund must restore supply by value only: Active=%s User=%s want %s", s.Active, s.User, value)
		}
	})
}

// TestSupply_ERC20GasComesFromEthCustody — an ERC-20 unmap debits the token
// supply by the bare amount, and books the L1 gas against BOTH the reserve
// counter and Active("eth").
func TestSupply_ERC20GasComesFromEthCustody(t *testing.T) {
	sdk.ResetTestStateStore()

	reserve := big.NewInt(1_000_000)
	gasCost := big.NewInt(40_000)
	tokens := big.NewInt(777)

	// Seed: reserve backed by eth custody, user holds tokens.
	sdk.StateSetObject(constants.GasReserveKey, reserve.String())
	SetSupply("eth", Supply{Active: new(big.Int).Set(reserve), User: new(big.Int), Fee: new(big.Int)})
	IncBalance("hive:alice", "usdc", tokens)
	TrackDeposit("usdc", tokens, new(big.Int))
	ethInvariant(t, "seeded")

	// Mirror the ERC-20 unmap charges.
	DecBalance("hive:alice", "usdc", tokens)
	TrackWithdrawal("usdc", tokens)
	deductGasReserve(gasCost)
	TrackReserveSpend(gasCost)
	ethInvariant(t, "after erc20 unmap")

	wantEth := new(big.Int).Sub(reserve, gasCost)
	if got := GetSupply("eth").Active; got.Cmp(wantEth) != 0 {
		t.Fatalf("Active(eth) must shrink by the reserve spend: want %s, got %s", wantEth, got)
	}
	sTok := GetSupply("usdc")
	if sTok.Active.Sign() != 0 || sTok.User.Sign() != 0 {
		t.Fatalf("token supply must be empty after unmap: Active=%s User=%s", sTok.Active, sTok.User)
	}
}

// TestSupply_ToReserveDepositFundsReserveAndActive — a native-ETH deposit
// carrying to_reserve routes the WHOLE amount into both the reserve counter and
// Active("eth"), crediting no user. This is the proof-backed reserve-funding
// path (HandleMap's to_reserve branch) that replaces a bare setGasReserve
// write: because Active grows alongside the reserve, a subsequent ERC-20 reserve
// spend (TrackReserveSpend) proceeds instead of aborting — the divergence that
// a setGasReserve-only seed (Active=0) would have caused.
func TestSupply_ToReserveDepositFundsReserveAndActive(t *testing.T) {
	sdk.ResetTestStateStore()

	fund := big.NewInt(constants.MinGasReserve) // 0.05 ETH

	// Mirror HandleMap's to_reserve branch: addGasReserve + TrackDeposit(0, fund).
	addGasReserve(fund)
	TrackDeposit("eth", new(big.Int), fund)

	if got := getGasReserve(); got.Cmp(fund) != 0 {
		t.Fatalf("reserve must hold the full to_reserve amount: want %s, got %s", fund, got)
	}
	s := GetSupply("eth")
	if s.Active.Cmp(fund) != 0 {
		t.Fatalf("Active(eth) must grow by the to_reserve amount: want %s, got %s", fund, s.Active)
	}
	if s.User.Sign() != 0 {
		t.Fatalf("to_reserve must NOT credit any user: got User=%s", s.User)
	}
	ethInvariant(t, "after to_reserve deposit")

	// The payoff: an ERC-20 reserve spend now proceeds (Active >= gasCost),
	// where a bare setGasReserve seed (Active=0) would have aborted here.
	gasCost := big.NewInt(3_900_000_000_000_000)
	deductGasReserve(gasCost)
	TrackReserveSpend(gasCost) // must NOT abort
	ethInvariant(t, "after erc20 reserve spend")
}
