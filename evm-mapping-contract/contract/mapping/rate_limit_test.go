package mapping

import (
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

func ethWei(milli int64) *big.Int { return new(big.Int).Mul(big.NewInt(milli), big.NewInt(1e15)) }

// P2 (BTC-C3 parity): withdrawals of one asset debit at most its cap per Hive
// block; over it the withdrawal is refused (the caller aborts and the runtime
// reverts it), and the next block starts from zero.
func TestP2_ETHWithdrawalsAreCappedPerHiveBlock(t *testing.T) {
	rpBridge(t, ethWei(1000), "hive:alice")
	SetMaxWithdrawPerBlock("eth", ethWei(25)) // 0.025 ETH per block
	sdk.SetTestBlockHeight(500)
	w := func() error {
		_, err := HandleUnmapETH(&TransferParams{Amount: "10000000000000000", To: "0x00000000000000000000000000000000000000e2", Asset: "eth", DeductFee: true}, [20]byte{1}, 1)
		return err
	}
	if err := w(); err != nil { // 0.010
		t.Fatalf("first: %v", err)
	}
	if err := w(); err != nil { // 0.020
		t.Fatalf("second: %v", err)
	}
	if err := w(); err == nil || !strings.Contains(err.Error(), "withdrawal rate limit") { // 0.030 > 0.025
		t.Fatalf("third in the same block: %v, want the rate-limit refusal", err)
	}
	as(t, "hive:alice", rpNow)
	sdk.SetTestBlockHeight(501)
	if err := w(); err != nil {
		t.Fatalf("next block: %v", err)
	}
}

// "0" turns the limit off; the ERC-20 default is 100,000 whole tokens.
func TestP2_OffAndTokenDefault(t *testing.T) {
	rpBridge(t, ethWei(1000), "hive:alice")
	sdk.SetTestBlockHeight(700)
	if got := maxWithdrawPerBlock("USDC", 6); got.Cmp(big.NewInt(100_000_000_000)) != 0 {
		t.Fatalf("USDC default %s, want 100000 * 10^6", got)
	}
	if got := maxWithdrawPerBlock("eth", 18); got.String() != constants.DefaultMaxWithdrawPerBlockETHWei {
		t.Fatalf("ETH default %s", got)
	}
	SetMaxWithdrawPerBlock("USDC", big.NewInt(400_000))
	tok := func(amt string) error {
		_, err := HandleUnmapERC20(&TransferParams{Amount: amt, To: "0x00000000000000000000000000000000000000e2", Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1)
		return err
	}
	if err := tok("300000"); err != nil {
		t.Fatalf("first token withdrawal: %v", err)
	}
	if err := tok("200000"); err == nil || !strings.Contains(err.Error(), "withdrawal rate limit") {
		t.Fatalf("over the token cap: %v, want the rate-limit refusal", err)
	}
	SetMaxWithdrawPerBlock("USDC", big.NewInt(0))
	if err := tok("200000"); err != nil {
		t.Fatalf("with the limit off: %v", err)
	}
}

// The accumulator is a fixed 40 bytes whatever it holds, so a withdrawal
// rewrites it at the same length and pays no state-growth charge (the BTC
// contract's 16-byte accumulator, widened for wei). Real-wasm: GLAM-1's first
// unmapETH stays inside the 10,000 RC free tier.
func TestP2_AccumulatorIsFixedWidth(t *testing.T) {
	rpBridge(t, ethWei(1000), "hive:alice") // alice holds 10 ETH
	SetMaxWithdrawPerBlock("eth", ethWei(25_000)) // 25 ETH
	width := func(when string) {
		t.Helper()
		v, _ := sdk.TestStateGet(constants.WithdrawBlockAccPrefix + "eth")
		if len(v) != withdrawAccLen {
			t.Fatalf("%s: accumulator is %d bytes, want %d", when, len(v), withdrawAccLen)
		}
	}
	w := func(amount string) {
		t.Helper()
		if _, err := HandleUnmapETH(&TransferParams{Amount: amount, To: "0x00000000000000000000000000000000000000e2", Asset: "eth", DeductFee: true}, [20]byte{1}, 1); err != nil {
			t.Fatalf("unmap %s: %v", amount, err)
		}
	}
	sdk.SetTestBlockHeight(9)
	w("10000000000000000") // 0.01 ETH: a small amount
	width("small amount")
	h, acc := loadWithdrawAccumulator("eth")
	if h != 9 || acc.Sign() <= 0 {
		t.Fatalf("stored block %d amount %s", h, acc)
	}
	as(t, "hive:alice", rpNow)
	sdk.SetTestBlockHeight(1 << 40) // a large height, next block
	w("9000000000000000000") // 9 ETH: a large amount
	width("large amount, later block")
	if h, acc2 := loadWithdrawAccumulator("eth"); h != 1<<40 || acc2.Cmp(acc) <= 0 {
		t.Fatalf("stored block %d amount %s after the second block", h, acc2)
	}
}

// registerToken creates the token's accumulator; registering it again (a gas
// limit or revert fee update) keeps what the current block has debited.
func TestP2_RegisterTokenCreatesAndKeepsTheAccumulator(t *testing.T) {
	rpBridge(t, ethWei(1000), "hive:alice") // its USDC record is written directly, as for a token registered before P2
	key := constants.WithdrawBlockAccPrefix + "USDC"
	if v, ok := sdk.TestStateGet(key); ok && v != "" {
		t.Fatalf("fixture already holds a USDC accumulator %q", v)
	}
	var addr [20]byte
	addr[19] = 0xc0
	if err := RegisterTokenFull(1, addr, "USDC", 6, 1000, 0, 0); err != nil {
		t.Fatalf("register USDC: %v", err)
	}
	if v, _ := sdk.TestStateGet(key); len(v) != withdrawAccLen {
		t.Fatalf("USDC accumulator after registration is %d bytes, want %d", len(v), withdrawAccLen)
	}
	SetMaxWithdrawPerBlock("USDC", big.NewInt(400_000))
	sdk.SetTestBlockHeight(800)
	tok := func(amt string) error {
		_, err := HandleUnmapERC20(&TransferParams{Amount: amt, To: "0x00000000000000000000000000000000000000e2", Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1)
		return err
	}
	if err := tok("300000"); err != nil {
		t.Fatalf("first token withdrawal: %v", err)
	}
	if err := RegisterTokenFull(1, addr, "USDC", 6, 1000, 0, 120_000); err != nil {
		t.Fatalf("re-register USDC: %v", err)
	}
	if err := tok("200000"); err == nil || !strings.Contains(err.Error(), "withdrawal rate limit") {
		t.Fatalf("after a re-registration in the same block: %v, want the rate-limit refusal (the block's debit kept)", err)
	}
}
