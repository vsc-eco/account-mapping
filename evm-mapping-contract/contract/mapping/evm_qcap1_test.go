package mapping

import (
	"math/big"
	"strings"
	"testing"
	"time"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// EVM-QCAP-1 (testnet 11-13 14:51): an ETH withdrawal requested during a
// rotation set aside the exact fee of the moment (it expected to issue at
// once), was queued instead (A01: the new generation could not pay it yet),
// and was refunded when the queue drained because the base fee had moved from
// 16 to 24 wei: "fee ... above the cap ...". As the BTC mapping contract's
// queued unmap (WQ-1), the request's authorization (max_fee, else the default
// cap) is the limit, and a rise inside it is charged at issue.

const qcTo = "0x00000000000000000000000000000000000000e2"

// qcBaseFee swaps the pricing header for one at baseFee (fresh, same height).
func qcBaseFee(baseFee uint64) {
	hdr := (&blocklist.EthBlockHeader{BlockNumber: 100, BaseFeePerGas: baseFee, GasLimit: 30_000_000,
		Timestamp: uint64(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC).Unix()), ChainId: 1}).Serialize()
	sdk.StubSetContractReadResponder(func(_, key string) *string {
		switch key {
		case "h":
			h := "100"
			return &h
		case "b-100":
			return &hdr
		}
		return nil
	})
}

func qcFee(baseFee uint64) *big.Int {
	_, fee, err := safeGasFee(constants.ETHTransferGas, baseFee, 2, 2_000_000_000)
	if err != nil {
		panic(err)
	}
	return fee
}

// qcQueue requests a 1 ETH withdrawal as the bridge's first user while the
// custody sits at the retiring generation, so it is queued.
func qcQueue(t *testing.T, p TransferParams) {
	t.Helper()
	p.Amount, p.To, p.Asset = "1000000000000000000", qcTo, "eth"
	status, err := HandleUnmapETH(&p, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(status, "queued:") {
		t.Fatalf("unmapETH during the rotation: %q %v, want queued", status, err)
	}
}

// qcCover lets the new generation pay (a deposit reaches it).
func qcCover() {
	TrackDeposit("eth", new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18)), new(big.Int))
}

// The testnet case: fee on top, no max_fee, base fee up 50% while it waits.
// Develop refunds it; now it issues and the owner pays the real fee.
func TestEVMQCAP1_QueuedWithdrawalIssuesWhenTheFeeRises(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	a01Rotated(t)
	start := GetBalance("hive:alice", "eth")
	supply0 := GetSupply("eth")
	qcQueue(t, TransferParams{})
	queued := GetBalance("hive:alice", "eth")
	if setAside := new(big.Int).Sub(start, queued); setAside.Cmp(new(big.Int).Add(big.NewInt(1e18), new(big.Int).Add(qcFee(1e9), ProofFee("eth")))) != 0 {
		t.Fatalf("request debited %s, want 1 ETH + the fee at 1 gwei %s + the proof fee", setAside, qcFee(1e9))
	}

	qcBaseFee(1_500_000_000)
	qcCover()
	if n := DrainWithdrawalQueue(1, 8); n != 1 {
		t.Fatalf("drain issued %d after a 50%% base fee rise, want 1 (develop refunds it: EVM-QCAP-1)", n)
	}
	ps := GetPendingSpend(0)
	if ps == nil || ps.GasCost.Cmp(qcFee(1_500_000_000)) != 0 || ps.Amount.Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("issued spend %+v, want value 1 ETH and the fee at 1.5 gwei %s", ps, qcFee(1_500_000_000))
	}
	rise := new(big.Int).Sub(qcFee(1_500_000_000), qcFee(1e9))
	if got := GetBalance("hive:alice", "eth"); new(big.Int).Sub(queued, got).Cmp(rise) != 0 {
		t.Fatalf("balance %s -> %s at issue, want the rise %s charged", queued, got, rise)
	}
	// Custody and user supply: down by exactly what alice paid in all.
	paid := new(big.Int).Sub(start, GetBalance("hive:alice", "eth"))
	s := GetSupply("eth")
	dep := new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18)) // qcCover's deposit
	if new(big.Int).Sub(new(big.Int).Add(supply0.User, dep), s.User).Cmp(paid) != 0 || new(big.Int).Sub(new(big.Int).Add(supply0.Active, dep), s.Active).Cmp(paid) != 0 {
		t.Fatalf("supply %+v -> %+v, want both down by %s", supply0, s, paid)
	}
}

// The caller's own max_fee stays a hard limit: a rise past it is refunded in full.
func TestEVMQCAP1_RiseAboveTheCallersMaxFeeIsRefunded(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	a01Rotated(t)
	start := GetBalance("hive:alice", "eth")
	qcQueue(t, TransferParams{MaxFee: qcFee(1_200_000_000).String()})
	qcBaseFee(1_500_000_000)
	qcCover()
	if n := DrainWithdrawalQueue(1, 8); n != 0 || QueueLen() != 0 {
		t.Fatalf("issued %d, queue %d; want it refunded and removed", n, QueueLen())
	}
	if got, want := GetBalance("hive:alice", "eth"), new(big.Int).Sub(start, ProofFee("eth")); got.Cmp(want) != 0 {
		t.Fatalf("balance %s, want %s (all back but the proof fee)", got, want)
	}
}

// With no max_fee the default cap at request is the limit: twice the issue
// fee (4 x base + 4 gwei tip), never below gas x DefaultETHFeeCapFloorGwei.
// At a 1 gwei request that is the 20 gwei floor, the fee at a 9 gwei base: a
// rise to 10 gwei is refunded, not charged.
func TestEVMQCAP1_RiseAboveTheDefaultCapIsRefunded(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	a01Rotated(t)
	start := GetBalance("hive:alice", "eth")
	limit := defaultETHFeeCap(constants.ETHTransferGas)
	qcQueue(t, TransferParams{})
	if qcFee(10_000_000_000).Cmp(limit) <= 0 || qcFee(9_000_000_000).Cmp(limit) > 0 {
		t.Fatalf("default cap %s: want the fee at 9 gwei (%s) inside it and at 10 gwei (%s) past it", limit, qcFee(9_000_000_000), qcFee(10_000_000_000))
	}
	qcBaseFee(10_000_000_000)
	qcCover()
	if n := DrainWithdrawalQueue(1, 8); n != 0 || QueueLen() != 0 {
		t.Fatalf("issued %d, queue %d; want it refunded", n, QueueLen())
	}
	if got, want := GetBalance("hive:alice", "eth"), new(big.Int).Sub(start, ProofFee("eth")); got.Cmp(want) != 0 {
		t.Fatalf("balance %s, want %s", got, want)
	}
}

// A netted fee comes out of the amount: a rise within the limit issues with
// less value sent and nothing more taken from the balance.
func TestEVMQCAP1_DeductFeeRiseIssuesNetted(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	a01Rotated(t)
	qcQueue(t, TransferParams{DeductFee: true})
	queued := GetBalance("hive:alice", "eth")
	qcBaseFee(1_500_000_000)
	qcCover()
	if n := DrainWithdrawalQueue(1, 8); n != 1 {
		t.Fatalf("issued %d, want 1", n)
	}
	ps := GetPendingSpend(0)
	if want := new(big.Int).Sub(big.NewInt(1e18), qcFee(1_500_000_000)); ps == nil || ps.Amount.Cmp(want) != 0 {
		t.Fatalf("spend %+v, want value %s (1 ETH less the fee at 1.5 gwei)", ps, want)
	}
	if got := GetBalance("hive:alice", "eth"); got.Cmp(queued) != 0 {
		t.Fatalf("balance %s -> %s, want nothing more taken", queued, got)
	}
}

// The rise is refunded, not charged, when the balance cannot cover it.
func TestEVMQCAP1_BalanceShortOfTheRiseRefunds(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	a01Rotated(t)
	qcQueue(t, TransferParams{})
	left := GetBalance("hive:alice", "eth")
	DecBalance("hive:alice", "eth", left) // spent everything else meanwhile
	qcBaseFee(1_500_000_000)
	qcCover()
	if n := DrainWithdrawalQueue(1, 8); n != 0 || QueueLen() != 0 {
		t.Fatalf("issued %d, queue %d; want refunded", n, QueueLen())
	}
	if got, want := GetBalance("hive:alice", "eth"), new(big.Int).Add(big.NewInt(1e18), qcFee(1e9)); got.Cmp(want) != 0 {
		t.Fatalf("balance %s, want the whole debit %s back", got, want)
	}
}

// A contract's withdrawal (refund_to) is never charged later: a rise refunds it.
func TestEVMQCAP1_ContractWithdrawalRiseRefunds(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	a01Rotated(t)
	IncBalance("contract:router", "eth", new(big.Int).Mul(big.NewInt(3), big.NewInt(1e18)))
	s := GetSupply("eth")
	add := new(big.Int).Mul(big.NewInt(3), big.NewInt(1e18))
	SetSupply("eth", Supply{Active: new(big.Int).Add(s.Active, add), User: new(big.Int).Add(s.User, add), Fee: s.Fee})
	setVaultBook(0, "eth", new(big.Int).Set(GetSupply("eth").Active))
	sdk.StubSetEnvJSON(`{"contract.id":"contract:test","msg.caller":"contract:router","msg.sender":"hive:alice",` +
		`"msg.required_auths":["hive:alice"],"block.timestamp":"2026-10-27T12:00:01"}`)
	routerStart := GetBalance("contract:router", "eth")
	aliceStart := GetBalance("hive:alice", "eth")
	qcQueue(t, TransferParams{RefundTo: "hive:alice"})
	head, _ := QueueBounds()
	if q := GetQueued(head); q == nil || q.ChargeRise {
		t.Fatalf("contract withdrawal queued as %+v, want ChargeRise false", q)
	}
	debit := new(big.Int).Sub(routerStart, GetBalance("contract:router", "eth"))
	qcBaseFee(1_500_000_000)
	qcCover()
	if n := DrainWithdrawalQueue(1, 8); n != 0 || QueueLen() != 0 {
		t.Fatalf("issued %d, queue %d; want refunded", n, QueueLen())
	}
	refunded := new(big.Int).Sub(GetBalance("hive:alice", "eth"), aliceStart)
	if want := new(big.Int).Sub(debit, ProofFee("eth")); refunded.Cmp(want) != 0 {
		t.Fatalf("refund_to got %s, want the debit %s", refunded, want)
	}
}

// An entry queued before this fix has no MaxFee: its FeeCap stays the limit.
func TestEVMQCAP1_LegacyEntryKeepsItsFeeCapAsTheLimit(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice")
	a01Rotated(t)
	qcQueue(t, TransferParams{})
	head, _ := QueueBounds()
	q := GetQueued(head)
	q.MaxFee, q.ChargeRise = nil, false // as develop stored it
	RemoveQueued(head, q)
	Enqueue(*q)
	qcBaseFee(1_500_000_000)
	qcCover()
	if n := DrainWithdrawalQueue(1, 8); n != 0 || QueueLen() != 0 {
		t.Fatalf("legacy entry issued %d, queue %d; want refunded as before", n, QueueLen())
	}
}

// A spender's withdrawal (unmapFrom) is never charged later: the owner's
// allowance covered only the debit, so a fee on top that rose is refunded.
func TestEVMQCAP1_SpenderWithdrawalRiseRefunds(t *testing.T) {
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), "hive:alice", "hive:spender")
	a01Rotated(t)
	SetAllowance("hive:alice", "hive:spender", "eth", new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18)))
	as(t, "hive:spender", rpNow)
	aliceStart := GetBalance("hive:alice", "eth")
	status, err := HandleUnmapFromStatus(&TransferParams{From: "hive:alice", Amount: "1000000000000000000", To: qcTo, Asset: "eth"}, [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(status, "queued:") {
		t.Fatalf("unmapFrom: %q %v, want queued", status, err)
	}
	qcBaseFee(1_500_000_000)
	qcCover()
	if n := DrainWithdrawalQueue(1, 8); n != 0 || QueueLen() != 0 {
		t.Fatalf("issued %d, queue %d; want refunded", n, QueueLen())
	}
	if got, want := GetBalance("hive:alice", "eth"), new(big.Int).Sub(aliceStart, ProofFee("eth")); got.Cmp(want) != 0 {
		t.Fatalf("alice %s, want %s: nothing beyond the allowance taken", got, want)
	}
}
