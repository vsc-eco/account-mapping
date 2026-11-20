package mapping

import (
	"math/big"
	"testing"
)

// FLOOR-1 (owner 11-20): an ERC-20 withdrawal may spend the gas reserve down
// to MinGasReserve (0.01 ETH), kept for the rotation sweeps' gas. With 0.02 ETH
// in the reserve it is issued (old 0.05 floor: queued); under 0.01 it waits.
func TestFLOOR1_ERC20WithdrawalSpendsTheReserveDownToTheFloor(t *testing.T) {
	usdc := &TransferParams{Amount: "1000", To: "0x00000000000000000000000000000000000000e2", Asset: "USDC",
		TokenAddress: "0x00000000000000000000000000000000000000c0"}

	rpBridge(t, big.NewInt(20_000_000_000_000_000), "hive:alice") // 0.02 ETH reserve
	as(t, "hive:alice", rpNow)
	if _, err := HandleUnmapERC20(usdc, [20]byte{1}, 1); err != nil {
		t.Fatalf("unmapERC20 with 0.02 ETH in the reserve: %v", err)
	}
	if GetPendingSpend(0) == nil || QueueLen() != 0 {
		t.Fatalf("with 0.02 ETH in the reserve: d-0=%v queue=%d, want issued at once", GetPendingSpend(0) != nil, QueueLen())
	}

	rpBridge(t, big.NewInt(9_000_000_000_000_000), "hive:bob") // 0.009 ETH, under the floor
	as(t, "hive:bob", rpNow)
	if _, err := HandleUnmapERC20(usdc, [20]byte{1}, 1); err != nil {
		t.Fatalf("unmapERC20 with 0.009 ETH in the reserve: %v, want it queued", err)
	}
	if GetPendingSpend(0) != nil || QueueLen() != 1 {
		t.Fatalf("under the floor: d-0=%v queue=%d, want queued until a top-up", GetPendingSpend(0) != nil, QueueLen())
	}
}
