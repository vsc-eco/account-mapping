package mapping

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strconv"
	"testing"
	"time"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// LOW 10 (RP-11 form): a withdrawal is never priced from an L1 header more than
// MaxPricingHeaderAge older than the L2 block time. A request made while the
// newest header is stale is accepted and QUEUED: nothing is priced, signed or
// given a nonce. With a fresh header it issues at once, and a queued request
// issues on the next drain priced from the FRESH header.
func TestLOW10_StaleHeaderQueuesInsteadOfPricing(t *testing.T) {
	headerTime := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	newest := "100"
	setup := func(blockTime string) {
		sdk.ResetStubState()
		sdk.ResetTestState()
		newest = "100"
		sdk.StateSetObject(constants.VerifierContractIdKey, "vsc1verifierstub")
		old := (&blocklist.EthBlockHeader{BlockNumber: 100, BaseFeePerGas: 1e9, GasLimit: 30_000_000, Timestamp: uint64(headerTime.Unix()), ChainId: 1}).Serialize()
		fresh := (&blocklist.EthBlockHeader{BlockNumber: 200, BaseFeePerGas: 7e9, GasLimit: 30_000_000, Timestamp: uint64(headerTime.Add(2 * time.Hour).Unix()), ChainId: 1}).Serialize()
		sdk.StubSetContractReadResponder(func(contractId, key string) *string {
			switch key {
			case "h":
				h := newest
				return &h
			case "b-100":
				return &old
			case "b-200":
				return &fresh
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
		eth := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18))
		IncBalance("hive:alice", "eth", eth)
		IncBalance("hive:carol", "eth", eth)
		IncBalance("hive:alice", "USDC", big.NewInt(5_000_000))
		SetAllowance("hive:carol", "hive:alice", "eth", eth)
		SetSupply("eth", Supply{Active: new(big.Int).Mul(eth, big.NewInt(3)), User: new(big.Int).Mul(eth, big.NewInt(2)), Fee: new(big.Int)})
		SetSupply("USDC", Supply{Active: big.NewInt(5_000_000), User: big.NewInt(5_000_000), Fee: new(big.Int)})
		addGasReserve(eth) // reserve for the ERC-20 gas, inside Active
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
	for name, op := range ops {
		// Stale: accepted and queued, nothing priced, signed or numbered.
		setup(at(time.Duration(constants.MaxPricingHeaderAge+1) * time.Second))
		if err := op(); err != nil {
			t.Fatalf("%s with a stale header: %v, want it accepted into the queue", name, err)
		}
		if GetPendingNonce() != 0 || GetPendingSpend(0) != nil || len(sdk.TestSignRequests()) != 0 || QueueLen() != 1 {
			t.Fatalf("%s with a stale header: np=%d d-0=%v signs=%d queue=%d, want queued only", name, GetPendingNonce(), GetPendingSpend(0) != nil, len(sdk.TestSignRequests()), QueueLen())
		}
		// The header catches up (block 200, base fee 7 gwei, fresh at the
		// stub's block time): the next drain issues it priced from that header.
		newest = "200"
		sdk.StubSetEnvJSON(`{"contract.id":"contract:test","msg.caller":"hive:bob","msg.sender":"hive:bob","msg.required_auths":["hive:bob"],"block.timestamp":"` + at(2*time.Hour+time.Minute) + `"}`)
		DrainWithdrawalQueue1(t, [20]byte{1})
		ps := GetPendingSpend(0)
		if ps == nil || GetPendingNonce() != 1 || QueueLen() != 0 || len(sdk.TestSignRequests()) != 1 {
			t.Fatalf("%s after the header caught up: d-0=%v np=%d queue=%d signs=%d, want issued", name, ps != nil, GetPendingNonce(), QueueLen(), len(sdk.TestSignRequests()))
		}
		tx, err := hex.DecodeString(ps.UnsignedTxHex)
		if err != nil || !bytes.Contains(tx, feeCapRLP(2*7e9+2e9)) {
			t.Errorf("%s issued with a fee cap not from the fresh 7 gwei header: %s", name, ps.UnsignedTxHex)
		}
		// Fresh from the start: issued at once.
		for _, bt := range []string{at(time.Duration(constants.MaxPricingHeaderAge-1) * time.Second), ""} {
			setup(bt)
			if err := op(); err != nil {
				t.Fatalf("%s (block time %q): %v", name, bt, err)
			}
			if GetPendingSpend(0) == nil || QueueLen() != 0 {
				t.Errorf("%s (block time %q): d-0=%v queue=%d, want issued at once", name, bt, GetPendingSpend(0) != nil, QueueLen())
			}
		}
	}
	sdk.ResetStubState()
	_ = strconv.Itoa
}

// DrainWithdrawalQueue1 drains against an explicit vault (the stubs carry no
// E23 attestation, so TssVaultAddress has none).
func DrainWithdrawalQueue1(t *testing.T, vault [20]byte) {
	t.Helper()
	drainWith(1, vault, 8)
}

// feeCapRLP is the RLP encoding of a gasFeeCap value, to find it in an
// unsigned EIP-1559 tx.
func feeCapRLP(v uint64) []byte {
	b := new(big.Int).SetUint64(v).Bytes()
	return append([]byte{0x80 + byte(len(b))}, b...)
}
