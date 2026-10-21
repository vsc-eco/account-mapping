package mapping

import (
	"encoding/hex"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// RV-1: unmapFrom debited params.Asset but signed a transfer of
// params.TokenAddress, so a spender with an allowance on a cheap token could
// name it as the asset and withdraw a valuable token from the vault. The
// debited asset must be the withdrawn token's registered symbol.
func TestRV1_UnmapFromBindsTheAssetToTheToken(t *testing.T) {
	sdk.ResetStubState()
	t.Cleanup(sdk.ResetStubState)

	const chainId uint64 = 1
	const height uint64 = 100
	hdrKey := constants.BlockPrefix + uintToStr(height)
	sdk.StateSetObject(constants.VerifierContractIdKey, "vsc1verifierstub")
	sdk.StubSetContractReadResponder(func(contractId, key string) *string {
		if contractId != "vsc1verifierstub" {
			return nil
		}
		var out string
		switch key {
		case constants.LastHeightKey:
			out = uintToStr(height)
		case hdrKey:
			out = serializeHeader(height, chainId, [32]byte{}, [32]byte{}, [32]byte{})
		default:
			return nil
		}
		return &out
	})

	var cheap, valuable [20]byte
	cheap[19], valuable[19] = 0x01, 0x02
	RegisterToken(chainId, cheap, "CHEAP", 6, 1)
	RegisterToken(chainId, valuable, "WBTC", 8, 1)

	sdk.StubSetTssKey("active,02aa,ecdsa")
	sdk.SetTestCaller("hive:spender")
	unmap := func(asset string) error {
		return HandleUnmapFrom(&TransferParams{
			Amount: "1000000", From: "hive:carol", To: "0x00000000000000000000000000000000000000e2",
			Asset: asset, TokenAddress: "0x" + hex.EncodeToString(valuable[:]),
		}, [20]byte{0xaa}, chainId)
	}
	const mismatch = "asset does not match the token's registered symbol"
	if err := unmap("CHEAP"); err == nil || !strings.Contains(err.Error(), mismatch) {
		t.Fatalf("unmapFrom of WBTC debiting CHEAP: err = %v, want %q", err, mismatch)
	}
	// The token's own symbol gets past the binding (it then fails on allowance).
	if err := unmap("WBTC"); err != nil && strings.Contains(err.Error(), mismatch) {
		t.Fatalf("unmapFrom of WBTC debiting WBTC was refused as a mismatch: %v", err)
	}
}
