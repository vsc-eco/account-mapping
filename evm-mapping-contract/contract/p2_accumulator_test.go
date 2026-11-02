package main

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/admin"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// P2: initContract creates the ETH withdrawal accumulator at its fixed width,
// so no user's first withdrawal pays to create it.
func TestP2_InitCreatesTheETHAccumulator(t *testing.T) {
	const owner = "hive:magi.bridge.owner"
	sdk.ResetTestState()
	sdk.SetTestEnvKey("contract.owner", owner)
	sdk.SetTestCaller(owner)
	in := `{"chain_id":11155111}`
	if admin.FastTimelockBuild {
		in = `{"is_testnet":true,"chain_id":11155111}`
	}
	initContract(&in)
	v, ok := sdk.TestStateGet(constants.WithdrawBlockAccPrefix + constants.NativeAsset)
	if !ok || len(v) != 40 || v != string(make([]byte, 40)) {
		t.Fatalf("ETH accumulator after init = %q (%d bytes), want 40 zero bytes", v, len(v))
	}
}

// The cap must fit the accumulator's 32-byte amount: 2^256-1 is accepted,
// 2^256 is refused and writes nothing.
func TestP2_CapAbove256BitsIsRefused(t *testing.T) {
	sdk.ResetTestStateStore()
	dispatch := func(amount string) (abort interface{}) {
		defer func() { abort = recover() }()
		dispatchAdmin("setMaxWithdrawPerBlock", []byte(`{"asset":"eth","amount":"`+amount+`"}`))
		return nil
	}
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	if a := dispatch(max.String()); a != nil {
		t.Fatalf("2^256-1 refused: %v", a)
	}
	over := new(big.Int).Lsh(big.NewInt(1), 256)
	if a := dispatch(over.String()); a == nil || !strings.Contains(fmt.Sprint(a), "2^256-1") {
		t.Fatalf("2^256 accepted (abort %v)", a)
	}
	if v, _ := sdk.TestStateGet(constants.MaxWithdrawPerBlockPrefix + "eth"); v != max.String() {
		t.Fatalf("cap after the refused set = %q, want the earlier 2^256-1", v)
	}
}
