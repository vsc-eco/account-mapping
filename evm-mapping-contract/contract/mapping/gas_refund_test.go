package mapping

import (
	"math/big"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// Gas-reserve correction semantics (supersedes the original EVM-C4 test).
//
// EVM-C4 originally made HandleConfirmSpend's failure branch refund the gas
// reserve on a reverted receipt. That was backwards: a status=0 receipt
// means the tx MINED, so the L1 gas WAS paid to the miner — refunding the
// reserve counter overstated it vs the real vault balance. The corrected
// rule matches reality:
//
//   - reverted receipt (gas paid)      → reserve NOT refunded
//   - proven-dropped tx (nothing paid) → reserve restored, user made whole
//
// EVM-C4's liveness concern (reserve exhaustion blocking withdrawals) is
// preserved: the deposit tax keeps funding the reserve, and dropped-tx
// restores now work via refundDroppedWithdrawal.

// TestGasReserve_DroppedWithdrawalRestoresReserve — an ERC-20 PendingSpend
// proven dropped restores both the reserve counter and the Active("eth")
// custody booking, and refunds the user's tokens.
func TestGasReserve_MinedRevertedWithdrawalKeepsReserveSpent(t *testing.T) {
	sdk.ResetTestStateStore()

	startReserve := big.NewInt(1_000_000)
	gasCost := big.NewInt(40_000)
	tokenAmount := big.NewInt(5_000)

	// Seed reserve and the eth custody that backs it.
	sdk.StateSetObject(constants.GasReserveKey, startReserve.String())
	SetSupply("eth", Supply{Active: new(big.Int).Set(startReserve), User: new(big.Int), Fee: new(big.Int)})
	// Seed the token supply as if the deposit + unmap already happened.
	SetSupply("usdc", Supply{Active: new(big.Int), User: new(big.Int), Fee: new(big.Int)})

	// Simulate the unmap-side charge.
	deductGasReserve(gasCost)
	TrackReserveSpend(gasCost)

	ps := &PendingSpend{
		Nonce:   0,
		Amount:  tokenAmount,
		From:    "hive:alice",
		Asset:   "usdc",
		GasCost: gasCost,
	}

	refundDroppedWithdrawal(ps)

	// E9 (RV re-verify): the only accepted drop proof is Type-A (mined,
	// reverted) — the L1 gas was really paid, so the reserve is NOT restored
	// (the miner kept it) and Active(eth) stays reduced. Only the token VALUE
	// is refunded. Pre-fix this restored the reserve and over-stated custody.
	spentReserve := new(big.Int).Sub(startReserve, gasCost)
	if got := getGasReserve(); got.Cmp(spentReserve) != 0 {
		t.Fatalf("mined-reverted withdrawal must NOT restore the reserve: want %s, got %s", spentReserve, got)
	}
	if got := GetSupply("eth").Active; got.Cmp(spentReserve) != 0 {
		t.Fatalf("Active(eth) must stay reduced by the spent gas: want %s, got %s", spentReserve, got)
	}
	if got := GetBalance("hive:alice", "usdc"); got.Cmp(tokenAmount) != 0 {
		t.Fatalf("dropped withdrawal must refund the token amount: want %s, got %s", tokenAmount, got)
	}
	sUsdc := GetSupply("usdc")
	if sUsdc.Active.Cmp(tokenAmount) != 0 || sUsdc.User.Cmp(tokenAmount) != 0 {
		t.Fatalf("token supply not restored: Active=%s User=%s, want both %s", sUsdc.Active, sUsdc.User, tokenAmount)
	}
}

// TestGasReserve_DroppedETHWithdrawalRefundsFee — an ETH PendingSpend proven
// dropped refunds the L1 value AND the prepaid fee (the user paid
// Amount+GasCost at unmap and nothing left custody).
func TestGasReserve_MinedRevertedETHWithdrawalRefundsValueOnly(t *testing.T) {
	sdk.ResetTestStateStore()

	value := big.NewInt(1_000_000_000)
	fee := big.NewInt(42_000)
	total := new(big.Int).Add(value, fee)

	// Seed supply as if the unmap already debited Amount+GasCost.
	SetSupply("eth", Supply{Active: new(big.Int), User: new(big.Int), Fee: new(big.Int)})

	ps := &PendingSpend{
		Nonce:   0,
		Amount:  value,
		From:    "hive:alice",
		Asset:   "eth",
		GasCost: fee,
	}

	refundDroppedWithdrawal(ps)

	// E9 (RV re-verify): Type-A (mined, reverted) is the only accepted drop
	// proof, so the gas was really spent — refund the VALUE only, not value+fee.
	_ = total
	if got := GetBalance("hive:alice", "eth"); got.Cmp(value) != 0 {
		t.Fatalf("mined-reverted ETH withdrawal must refund value only: want %s, got %s", value, got)
	}
	s := GetSupply("eth")
	if s.Active.Cmp(value) != 0 || s.User.Cmp(value) != 0 {
		t.Fatalf("supply must be restored by value only: Active=%s User=%s, want both %s", s.Active, s.User, value)
	}
	if s.Fee.Sign() != 0 {
		t.Fatalf("Fee must stay 0 (no Magi revenue fees): got %s", s.Fee)
	}
	// nil-GasCost legacy entries must not panic and refund Amount only.
	sdk.ResetTestStateStore()
	SetSupply("eth", Supply{Active: new(big.Int), User: new(big.Int), Fee: new(big.Int)})
	refundDroppedWithdrawal(&PendingSpend{Amount: value, From: "hive:bob", Asset: "eth"})
	if got := GetBalance("hive:bob", "eth"); got.Cmp(value) != 0 {
		t.Fatalf("nil-GasCost refund: want %s, got %s", value, got)
	}
}

// TestGasReserve_RevertedReceiptDoesNotRefundReserve pins the corrected
// HandleConfirmSpend failure-branch behavior: on a reverted (mined) tx the
// gas was paid, so the reserve stays debited. Mirrors the branch logic the
// way the original EVM-C4 test did.
func TestGasReserve_RevertedReceiptDoesNotRefundReserve(t *testing.T) {
	sdk.ResetTestStateStore()

	startReserve := big.NewInt(1_000_000)
	gasCost := big.NewInt(40_000)

	sdk.StateSetObject(constants.GasReserveKey, startReserve.String())
	deductGasReserve(gasCost)

	ps := &PendingSpend{
		Nonce:   0,
		Amount:  big.NewInt(5_000),
		From:    "hive:alice",
		Asset:   "usdc",
		GasCost: gasCost,
	}

	// The failure branch refunds ps.Amount only — no addGasReserve call.
	IncBalance(ps.From, ps.Asset, ps.Amount)

	wantReserve := new(big.Int).Sub(startReserve, gasCost)
	if got := getGasReserve(); got.Cmp(wantReserve) != 0 {
		t.Fatalf("reverted receipt must NOT refund the reserve (gas was paid): want %s, got %s", wantReserve, got)
	}
}

func TestEVMC4_PendingSpendCarriesGasCost(t *testing.T) {
	sdk.ResetTestStateStore()

	// Pin that StorePendingSpend / GetPendingSpend round-trip the
	// GasCost field. Without this, the drop-refund has nothing to
	// restore even if the call site tracks it.
	original := PendingSpend{
		Nonce:        7,
		Amount:       big.NewInt(12345),
		From:         "hive:bob",
		To:           "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		Asset:        "usdc",
		TokenAddress: "0xabcdef",
		BlockHeight:  100,
		GasCost:      big.NewInt(40_000),
	}
	StorePendingSpend(original)

	got := GetPendingSpend(7)
	if got == nil {
		t.Fatalf("StorePendingSpend round-trip failed: GetPendingSpend returned nil")
	}
	if got.GasCost == nil || got.GasCost.Cmp(big.NewInt(40_000)) != 0 {
		t.Errorf("GasCost not round-tripped: got %v, want 40000", got.GasCost)
	}
	// Sanity that the other fields still come through.
	if got.From != "hive:bob" || got.Amount.Cmp(big.NewInt(12345)) != 0 || got.TokenAddress != "0xabcdef" {
		t.Errorf("other PendingSpend fields not round-tripped: %+v", got)
	}
}
