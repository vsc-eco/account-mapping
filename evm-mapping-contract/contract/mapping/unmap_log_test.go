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

// A12: an unmap left no log, so an indexer could not see who withdrew what or
// what the L1 fee was. Each unmap now emits one pipe-delimited "unmap" event in
// the BTC contract's style.
func TestA12_UnmapsLogTheirFee(t *testing.T) {
	headerTime := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	setup := func() {
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
		sdk.StubSetEnvJSON(`{"contract.id":"contract:test","msg.caller":"hive:alice","msg.sender":"hive:alice","msg.required_auths":["hive:alice"]}`)
		sdk.StubSetTssKey("active,02aa,ecdsa")
		sdk.StateSetObject(constants.TokenRegistryPrefix+"1-00000000000000000000000000000000000000c0", "USDC|6|1000")
		sdk.StateSetObject(constants.AllowedSymbolPrefix+"USDC", "1")
		IncBalance("hive:alice", "eth", big.NewInt(5e18))
		IncBalance("hive:alice", "USDC", big.NewInt(5_000_000))
		IncBalance("hive:carol", "eth", big.NewInt(5e18))
		SetAllowance("hive:carol", "hive:alice", "eth", big.NewInt(5e18))
		IncBalance("hive:carol", "USDC", big.NewInt(5_000_000))
		SetAllowance("hive:carol", "hive:alice", "USDC", big.NewInt(5_000_000))
		sdk.StateSetObject(constants.GasReserveKey, "1000000000000000000")
		SetSupply("eth", Supply{Active: big.NewInt(9e18), User: big.NewInt(9e18), Fee: new(big.Int)})
		SetSupply("USDC", Supply{Active: big.NewInt(5_000_000), User: big.NewInt(5_000_000), Fee: new(big.Int)})
	}
	for name, tc := range map[string]struct {
		op   func() error
		want []string
	}{
		"unmapETH": {func() error {
			_, err := HandleUnmapETH(&TransferParams{Amount: "100000000000000000", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1)
			return err
		}, []string{"|f=hive:alice|", "|a=eth|", "|gs=user"}},
		"unmapERC20": {func() error {
			_, err := HandleUnmapERC20(&TransferParams{Amount: "1000000", To: "0x00000000000000000000000000000000000000e2", Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1)
			return err
		}, []string{"|f=hive:alice|", "|a=USDC|", "|d=1000000|", "|s=1000000|", "|gs=reserve"}},
		"unmapFrom": {func() error {
			return HandleUnmapFrom(&TransferParams{Amount: "100000000000000000", From: "hive:carol", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1)
		}, []string{"|f=hive:carol|", "|a=eth|", "|gs=user"}},
		"unmapFrom ERC-20": {func() error {
			return HandleUnmapFrom(&TransferParams{Amount: "1000000", From: "hive:carol", To: "0x00000000000000000000000000000000000000e2", Asset: "USDC", TokenAddress: "0x00000000000000000000000000000000000000c0"}, [20]byte{1}, 1)
		}, []string{"|f=hive:carol|", "|a=USDC|", "|d=1000000|", "|gs=reserve"}},
	} {
		setup()
		if err := tc.op(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got []string
		for _, l := range sdk.TestLogs() {
			if strings.HasPrefix(l, "unmap|") {
				got = append(got, l)
			}
		}
		if len(got) != 1 {
			t.Fatalf("%s: unmap logs %q, want exactly one", name, got)
		}
		ps := GetPendingSpend(0)
		line := got[0]
		for _, w := range append(tc.want, "unmap|n=0|", "|t=0x00000000000000000000000000000000000000e2|", "|s="+ps.Amount.String()+"|", "|g="+ps.GasCost.String()+"|") {
			if !strings.Contains(line, w) {
				t.Errorf("%s: log %q lacks %q", name, line, w)
			}
		}
		if tc.want[1] == "|a=eth|" {
			// ETH: the user pays value + fee, so the debit is s + g.
			d := new(big.Int).Add(ps.Amount, ps.GasCost).String()
			if !strings.Contains(line, "|d="+d+"|") {
				t.Errorf("%s: log %q, want the debit d=%s (value + fee)", name, line, d)
			}
		}
	}
	sdk.ResetStubState()
}
