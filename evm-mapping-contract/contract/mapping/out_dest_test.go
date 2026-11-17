package mapping

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/sdk"
)

// EVM-OUT-DEST-1 (testnet 11-17): a withdrawal to MagiDeposit, the address a
// wallet shows for deposits, was accepted. MagiDeposit cannot pay out what it
// holds: a token transfer to it succeeds and stays there for good. Token
// withdrawals to it are refused (unmapERC20, and unmapFrom of a token).
func TestOutDest_NoTokenWithdrawalToTheDepositContract(t *testing.T) {
	vault := [20]byte{0: 0x1}
	other := [20]byte{0: 0x2}
	dep := DepositContractAddress(vault)
	const usdcHex = "1c7d4b196cb0c7b01d743fbc6116a902379c7238"
	for name, call := range map[string]func(to [20]byte) error{
		"unmapERC20": func(to [20]byte) error {
			_, err := HandleUnmapERC20(&TransferParams{To: hexAddr(to), Asset: "usdc", Amount: "10000000", TokenAddress: "0x" + usdcHex}, vault, 1)
			return err
		},
		"unmapFrom of a token": func(to [20]byte) error {
			var st string
			return unmapFrom(&TransferParams{From: "hive:alice", To: hexAddr(to), Asset: "usdc", Amount: "10000000", TokenAddress: "0x" + usdcHex}, vault, 1, &st)
		},
	} {
		sdk.ResetTestState()
		sdk.SetTestCaller("hive:alice")
		usdc, _ := hex.DecodeString(usdcHex)
		if err := RegisterTokenFull(1, [20]byte(usdc), "usdc", 6, 1_000_000, 0, 0); err != nil {
			t.Fatal(err)
		}
		SetBalance("hive:alice", "usdc", big.NewInt(100_000_000))
		if err := call(dep); err == nil || !strings.Contains(err.Error(), "deposit contract") {
			t.Fatalf("%s to the vault's MagiDeposit: %v, want the deposit-contract refusal", name, err)
		}
		var errOther error
		func() {
			defer func() { _ = recover() }() // an sdk.Abort further down is past the check
			errOther = call(other)
		}()
		if errOther != nil && strings.Contains(errOther.Error(), "deposit contract") {
			t.Fatalf("%s to another address refused as the deposit contract: %v", name, errOther)
		}
	}
}

// An ETH withdrawal to MagiDeposit is left to L1 (it reverts there and is
// refunded): the check is not on the ETH path, whose RC has no room for it.
// This pins that the ETH path is unchanged.
func TestOutDest_ETHWithdrawalPathHasNoDepositContractCheck(t *testing.T) {
	vault := [20]byte{0: 0x1}
	sdk.ResetTestState()
	if err := refuseVaultDestination(DepositContractAddress(vault), vault, false); err != nil {
		t.Fatalf("the ETH path refused the deposit contract: %v", err)
	}
	if err := refuseVaultDestination(vault, vault, false); err == nil {
		t.Fatal("the ETH path must still refuse the vault itself")
	}
}

// During a rotation the superseded generation still holds funds and its
// MagiDeposit still forwards to it: a token withdrawal to either generation's
// MagiDeposit is refused.
func TestOutDest_NoTokenWithdrawalToARetiringGenerationsDepositContract(t *testing.T) {
	w := newMigWorld(t)
	for _, gen := range [][20]byte{w.gen0, w.gen1} {
		err := refuseVaultDestination(DepositContractAddress(gen), w.gen1, true)
		if err == nil || !strings.Contains(err.Error(), "deposit contract") {
			t.Fatalf("token withdrawal to the MagiDeposit of generation address %x: %v, want the deposit-contract refusal", gen, err)
		}
		if err := refuseVaultDestination(DepositContractAddress(gen), w.gen1, false); err != nil {
			t.Fatalf("ETH path refused the MagiDeposit of generation %x: %v", gen, err)
		}
	}
}
