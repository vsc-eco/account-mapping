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
