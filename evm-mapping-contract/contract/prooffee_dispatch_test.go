package main

import (
	"fmt"
	"strings"
	"testing"

	"evm-mapping-contract/contract/admin"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/mapping"
	"evm-mapping-contract/sdk"
)

// setProofFee: only an asset the bridge holds, at most half its smallest
// creditable deposit (so a compromised owner key cannot take deposits through
// it); 0 removes the fee.
func TestPROOFFEE_SetProofFeeIsBounded(t *testing.T) {
	sdk.ResetTestStateStore()
	sdk.StateSetObject(constants.ChainIdKey, "11155111")
	dispatch := func(action, payload string) (abort interface{}) {
		defer func() { abort = recover() }()
		dispatchAdmin(action, []byte(payload))
		return nil
	}
	if a := dispatch("registerToken", `{"address":"0x1c7d4b196cb0c7b01d743fbc6116a902379c7238","symbol":"usdc","decimals":6,"min_withdrawal":10000000}`); a != nil {
		t.Fatalf("registerToken: %v", a)
	}
	for _, c := range []struct {
		asset, amount, abort string
		set                  int64 // the fee stored after; -1: unchanged
	}{
		{"eth", "500000000000000", "", 500_000_000_000_000}, // half of 0.001 ETH
		{"eth", "500000000000001", "above half", -1},
		{"usdc", "150000", "", 150_000}, // floor 1 USDC: up to 500000
		{"usdc", "500001", "above half", -1},
		{"usdc", "-1", "non-negative integer", -1},
		{"usdc", "1.5", "non-negative integer", -1},
		{"dai", "1", "unknown asset", -1},
		{"usdc", "0", "", 0},
	} {
		before := mapping.ProofFee(c.asset).Int64()
		a := dispatch("setProofFee", fmt.Sprintf(`{"asset":"%s","amount":"%s"}`, c.asset, c.amount))
		if c.abort == "" && a != nil || c.abort != "" && (a == nil || !strings.Contains(fmt.Sprint(a), c.abort)) {
			t.Fatalf("setProofFee %s %s: abort %v, want %q", c.asset, c.amount, a, c.abort)
		}
		want := c.set
		if want < 0 {
			want = before
		}
		if got := mapping.ProofFee(c.asset).Int64(); got != want {
			t.Fatalf("after setProofFee %s %s the fee is %d, want %d", c.asset, c.amount, got, want)
		}
	}
	if tl, err := admin.TimelockFor("setProofFee"); err != nil || tl != admin.TimelockOperational {
		t.Fatalf("setProofFee timelock %d, %v; want the operational one", tl, err)
	}
	if sdk.StateGetObject(constants.ProofFeePrefix+"usdc") != nil {
		t.Fatal("a fee of 0 left its key behind")
	}
}

// registerToken keeps a token's proving fee under its cap: a new
// min_withdrawal that would put the fee above half the minimum deposit is
// refused, so raising the minimum, setting a large fee and lowering the
// minimum again cannot leave a fee that takes whole deposits.
func TestPROOFFEE_RegisterTokenKeepsTheFeeUnderItsCap(t *testing.T) {
	sdk.ResetTestStateStore()
	sdk.StateSetObject(constants.ChainIdKey, "11155111")
	dispatch := func(action, payload string) (abort interface{}) {
		defer func() { abort = recover() }()
		dispatchAdmin(action, []byte(payload))
		return nil
	}
	register := func(minWithdrawal int64) interface{} {
		return dispatch("registerToken", fmt.Sprintf(`{"address":"0x1c7d4b196cb0c7b01d743fbc6116a902379c7238","symbol":"usdc","decimals":6,"min_withdrawal":%d}`, minWithdrawal))
	}
	setFee := func(amount string) {
		t.Helper()
		if a := dispatch("setProofFee", `{"asset":"usdc","amount":"`+amount+`"}`); a != nil {
			t.Fatalf("setProofFee %s: %v", amount, a)
		}
	}
	floor := func() int64 { return mapping.ProofFeeFloor("usdc").Int64() }
	if a := register(10_000_000); a != nil {
		t.Fatalf("registerToken: %v", a)
	}
	setFee("500000") // exactly half the 1 USDC floor
	for _, c := range []struct {
		minWithdrawal int64
		abort         bool
	}{
		{10_000_000, false}, // the fee is exactly at its cap
		{0, false},          // 0 is the 10 USDC default
		{9_999_990, true},   // floor 999,999: cap 499,999
		{1_000_000, true},
		{20_000_000, false},
	} {
		before := floor()
		a := register(c.minWithdrawal)
		if c.abort != (a != nil) || a != nil && !strings.Contains(fmt.Sprint(a), "lower the fee first") {
			t.Fatalf("registerToken min_withdrawal %d with a fee of 500000: abort %v, want abort=%v", c.minWithdrawal, a, c.abort)
		}
		if a != nil && floor() != before {
			t.Fatalf("a refused registerToken moved the floor from %d to %d", before, floor())
		}
	}
	// The sequence the check closes: a high minimum, a fee valid against it,
	// then the minimum lowered again.
	if a := register(constants.MaxTokenMinWithdrawal); a != nil {
		t.Fatal(a)
	}
	setFee("50000000000000")
	if a := register(10_000_000); a == nil {
		t.Fatal("lowering min_withdrawal under a 50M USDC proving fee was taken")
	}
	setFee("400000")
	if a := register(10_000_000); a != nil {
		t.Fatalf("lowering min_withdrawal once the fee fits: %v", a)
	}
	// A token with no fee is never refused for it.
	setFee("0")
	if a := register(1); a != nil {
		t.Fatalf("a token without a proving fee: %v", a)
	}
}
