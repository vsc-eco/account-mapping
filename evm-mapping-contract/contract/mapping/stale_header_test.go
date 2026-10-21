package mapping

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// LOW 10: a new withdrawal is not priced from an L1 header more than
// MaxPricingHeaderAge older than the L2 block time.
func TestLOW10_StaleHeaderRefusesNewWithdrawals(t *testing.T) {
	headerTime := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	setup := func(blockTime string) {
		sdk.ResetStubState()
		sdk.StateSetObject(constants.VerifierContractIdKey, "vsc1verifierstub")
		hdr := (&blocklist.EthBlockHeader{BlockNumber: 100, BaseFeePerGas: 1e9, GasLimit: 30_000_000, Timestamp: uint64(headerTime.Unix()), ChainId: 1}).Serialize()
		sdk.StubSetContractReadResponder(func(contractId, key string) *string {
			switch key {
			case "h":
				h := "100"
				return &h
			case "b-100":
				return &hdr
			}
			return nil
		})
		env := `{"contract.id":"contract:test","msg.caller":"hive:alice","msg.sender":"hive:alice","msg.required_auths":["hive:alice"]`
		if blockTime != "" {
			env += `,"block.timestamp":"` + blockTime + `"`
		}
		sdk.StubSetEnvJSON(env + `}`)
		sdk.StubSetTssKey("active,02aa,ecdsa")
		sdk.StateSetObject(constants.TokenRegistryPrefix+"1-00000000000000000000000000000000000000c0", "USDC|6|1000")
		sdk.StateSetObject(constants.AllowedSymbolPrefix+"USDC", "1")
	}
	at := func(age time.Duration) string { return headerTime.Add(age).Format("2006-01-02T15:04:05") }
	ops := map[string]func() error{
		"unmapETH": func() error {
			_, err := HandleUnmapETH(&TransferParams{Amount: "100000000000000000", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1)
			return err
		},
		"unmapERC20": func() error {
			_, err := HandleUnmapERC20(&TransferParams{Amount: "1000000", To: "0x00000000000000000000000000000000000000e2", Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1)
			return err
		},
		"unmapFrom": func() error {
			return HandleUnmapFrom(&TransferParams{Amount: "100000000000000000", From: "hive:carol", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1)
		},
	}
	stale := func(err error) bool { return err != nil && strings.Contains(err.Error(), "s old") }
	for name, op := range ops {
		setup(at(time.Duration(constants.MaxPricingHeaderAge+1) * time.Second))
		if err := op(); !stale(err) {
			t.Errorf("%s with a header %ds old: %v, want the stale-header refusal", name, constants.MaxPricingHeaderAge+1, err)
		}
		for _, bt := range []string{at(time.Duration(constants.MaxPricingHeaderAge-1) * time.Second), ""} {
			setup(bt)
			if err := op(); stale(err) {
				t.Errorf("%s (block time %q) refused as stale: %v", name, bt, err)
			}
		}
	}
	sdk.ResetStubState()
	_ = strconv.Itoa
}
