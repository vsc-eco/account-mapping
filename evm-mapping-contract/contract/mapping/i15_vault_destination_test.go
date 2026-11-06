package mapping

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/sdk"
)

func hexAddr(a [20]byte) string { return "0x" + hex.EncodeToString(a[:]) }

// I-15, testnet 11-04: unmapETH (and unmapERC20, unmapFrom: only the zero
// address was refused) paid a withdrawal to the vault's own address, where it
// is never credited back (a map from a vault address is errOwnTransfer), so
// the user lost it. The BTC contract refuses its change address the same way.
func TestI15_NoWithdrawalToTheVault(t *testing.T) {
	vault := [20]byte{0: 0x1}
	other := [20]byte{0: 0x2}
	for name, call := range map[string]func(to [20]byte) error{
		"unmapETH": func(to [20]byte) error {
			_, err := HandleUnmapETH(&TransferParams{To: hexAddr(to), Asset: "eth", Amount: "10000000000000000"}, vault, 1)
			return err
		},
		"unmapERC20": func(to [20]byte) error {
			_, err := HandleUnmapERC20(&TransferParams{To: hexAddr(to), Asset: "usdc", Amount: "10000000", TokenAddress: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"}, vault, 1)
			return err
		},
		"unmapFrom": func(to [20]byte) error {
			var st string
			return unmapFrom(&TransferParams{From: "hive:alice", To: hexAddr(to), Asset: "eth", Amount: "10000000000000000"}, vault, 1, &st)
		},
	} {
		sdk.ResetTestState()
		sdk.SetTestCaller("hive:alice")
		SetBalance("hive:alice", "eth", big.NewInt(1_000_000_000_000_000_000))
		usdc, _ := hex.DecodeString("1c7d4b196cb0c7b01d743fbc6116a902379c7238")
		if err := RegisterTokenFull(1, [20]byte(usdc), "usdc", 6, 1_000_000, 0, 0); err != nil {
			t.Fatal(err)
		}
		SetBalance("hive:alice", "usdc", big.NewInt(100_000_000))
		if err := call(vault); err == nil || !strings.Contains(err.Error(), "vault's own addresses") {
			t.Fatalf("%s to the vault: %v, want the vault-destination refusal", name, err)
		}
		// another destination gets past this check (it may fail or abort
		// later on what this test does not set up, but not on this)
		var errOther error
		func() {
			defer func() { _ = recover() }() // an sdk.Abort further down is past the check
			errOther = call(other)
		}()
		if errOther != nil && strings.Contains(errOther.Error(), "vault's own addresses") {
			t.Fatalf("%s to another address refused as the vault: %v", name, errOther)
		}
	}
}

// During a rotation every fund-holding generation's address is the vault's:
// a withdrawal to the retiring one is refused too (the BTC guard checks only
// the active change address; I-15 widens both).
func TestI15_NoWithdrawalToARetiringGeneration(t *testing.T) {
	w := newMigWorld(t)
	sdk.SetTestCaller("hive:alice")
	SetBalance("hive:alice", "eth", big.NewInt(1_000_000_000_000_000_000))
	for _, to := range [][20]byte{w.gen0, w.gen1} {
		_, err := HandleUnmapETH(&TransferParams{To: hexAddr(to), Asset: "eth", Amount: "10000000000000000"}, w.gen1, 1)
		if err == nil || !strings.Contains(err.Error(), "vault's own addresses") {
			t.Fatalf("unmapETH to generation address %x: %v, want the vault-destination refusal", to, err)
		}
	}
}
