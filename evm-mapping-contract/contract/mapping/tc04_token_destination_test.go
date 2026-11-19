package mapping

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/sdk"
)

// TC04-1 (testnet 11-12, from THORChain's evm-null-address-outbound test):
// unmapERC20 and unmapFrom paid a token withdrawal to the token contract
// itself. A token without a self-transfer guard keeps the tokens at its own
// address forever; USDC reverts, so the reserve fronts the gas of a payout that
// cannot land. Both paths now refuse it at request, like the zero address and
// the vault's own addresses (I-15).
func TestTC041_NoTokenWithdrawalToTheTokenContract(t *testing.T) {
	vault := [20]byte{0: 0x1}
	usdc, _ := hex.DecodeString("1c7d4b196cb0c7b01d743fbc6116a902379c7238")
	token := [20]byte(usdc)
	other := [20]byte{0: 0x2}
	calls := map[string]func(to string) error{
		"unmapERC20": func(to string) error {
			_, err := HandleUnmapERC20(&TransferParams{To: to, Asset: "usdc", Amount: "10000000", TokenAddress: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"}, vault, 1)
			return err
		},
		"unmapFrom": func(to string) error {
			var st string
			return unmapFrom(&TransferParams{From: "hive:alice", To: to, Asset: "usdc", Amount: "10000000", TokenAddress: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"}, vault, 1, &st)
		},
	}
	setup := func(t *testing.T) {
		t.Helper()
		sdk.ResetTestState()
		sdk.SetTestCaller("hive:alice")
		SetBalance("hive:alice", "eth", big.NewInt(1_000_000_000_000_000_000))
		if err := RegisterTokenFull(1, token, "usdc", 6, 1_000_000, 0, 0); err != nil {
			t.Fatal(err)
		}
		SetBalance("hive:alice", "usdc", big.NewInt(100_000_000))
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			// the token's address in either case is refused, and nothing is debited
			for _, to := range []string{hexAddr(token), "0x1C7D4B196CB0C7B01D743FBC6116A902379C7238"} {
				setup(t)
				if err := call(to); err == nil || !strings.Contains(err.Error(), "token contract itself") {
					t.Fatalf("%s to the token contract %s: %v, want the token-destination refusal", name, to, err)
				}
				if got := GetBalance("hive:alice", "usdc"); got.Cmp(big.NewInt(100_000_000)) != 0 {
					t.Fatalf("%s refused but the usdc balance moved: %s", name, got)
				}
			}
			// another destination gets past this check (it may fail or abort
			// later on what this test does not set up, but not on this)
			setup(t)
			var errOther error
			func() {
				defer func() { _ = recover() }() // an sdk.Abort further down is past the check
				errOther = call(hexAddr(other))
			}()
			if errOther != nil && strings.Contains(errOther.Error(), "token contract itself") {
				t.Fatalf("%s to another address refused as the token: %v", name, errOther)
			}
		})
	}
}

// An ETH withdrawal to a token's address is not this case (no tokens move; a
// contract without a payable fallback reverts and the withdrawal is refunded,
// F13), so unmapETH does not refuse it.
func TestTC041_ETHToATokenAddressIsNotRefusedAsTheToken(t *testing.T) {
	vault := [20]byte{0: 0x1}
	usdc, _ := hex.DecodeString("1c7d4b196cb0c7b01d743fbc6116a902379c7238")
	sdk.ResetTestState()
	sdk.SetTestCaller("hive:alice")
	SetBalance("hive:alice", "eth", big.NewInt(1_000_000_000_000_000_000))
	if err := RegisterTokenFull(1, [20]byte(usdc), "usdc", 6, 1_000_000, 0, 0); err != nil {
		t.Fatal(err)
	}
	var err error
	func() {
		defer func() { _ = recover() }()
		_, err = HandleUnmapETH(&TransferParams{To: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238", Asset: "eth", Amount: "10000000000000000"}, vault, 1)
	}()
	if err != nil && strings.Contains(err.Error(), "token contract itself") {
		t.Fatalf("unmapETH to a token address refused as the token: %v", err)
	}
}
