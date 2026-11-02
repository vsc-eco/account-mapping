package main

import (
	"encoding/json"
	"evm-mapping-contract/contract/mapping"
	"evm-mapping-contract/sdk"
	"strings"
	"testing"
)

// End-to-end reproduction of pentest finding F3.
//
// Bug: the getInfo wasmexport returned nil unconditionally:
//
//   //go:wasmexport getInfo
//   func getInfo(_ *string) *string { return nil }
//
// The DEX router (and any other contract that needs to register
// an ETH-bridged asset) calls `sdk.ContractCall(mapping, "getInfo", "")`
// and expects back a JSON of {"name":"Ether","symbol":"ETH","decimals":"18"}.
// nil breaks that registration outright — see dex-router-v2/main.go:
//
//   if infoResult == nil {
//       ce.CustomAbort(... "failed to query getInfo on mapping contract")
//   }
//
// This test calls getInfo through its real entry point and asserts:
//
//   pre-fix: result is nil — the DEX router's null-check fails.
//   post-fix: result is a JSON document with the three required
//             fields and the values matching ETH's canonical
//             metadata.

func TestF3_GetInfoReturnsEthMetadata(t *testing.T) {
	res := getInfo(nil)
	if res == nil {
		t.Fatal("F3 leak: getInfo returned nil; downstream contracts cannot register the ETH asset")
	}

	var info struct {
		Name     string `json:"name"`
		Symbol   string `json:"symbol"`
		Decimals string `json:"decimals"`
	}
	if err := json.Unmarshal([]byte(*res), &info); err != nil {
		t.Fatalf("getInfo response is not valid JSON: %v\n  body: %q", err, *res)
	}

	if info.Symbol == "" {
		t.Errorf("getInfo: symbol must not be empty (DEX router compares it against the registered name)")
	}
	if info.Decimals == "" {
		t.Errorf("getInfo: decimals must not be empty (DEX router parses with strconv.Atoi)")
	}
	if info.Name == "" {
		t.Errorf("getInfo: name must not be empty")
	}

	// The mapping contract is the ETH bridge — pin the canonical
	// metadata so a future "fix" doesn't accidentally swap symbols.
	if !strings.EqualFold(info.Symbol, "ETH") {
		t.Errorf("expected symbol ETH, got %q", info.Symbol)
	}
	if info.Decimals != "18" {
		t.Errorf("expected decimals \"18\" (ETH), got %q", info.Decimals)
	}
}

// SP-0b: the DEX router registers a mapped asset by name and requires the
// symbol getInfo returns to equal it. With only ETH here, USDC could never be
// registered on the router, so no USDC pool could be routed (and an EVM
// deposit-and-swap to USDC always fell back to an unswapped credit). getInfo
// now answers for the token a payload names.
func TestSP0b_GetInfoAnswersForARegisteredToken(t *testing.T) {
	sdk.ResetStubState()
	usdc := [20]byte{0x1c, 0x7d, 0x4b, 0x19}
	if err := mapping.RegisterToken(11155111, usdc, "usdc", 6, 1); err != nil {
		t.Fatal(err)
	}
	read := func(payload *string) (sym, dec string) {
		t.Helper()
		var info struct {
			Symbol   string `json:"symbol"`
			Decimals string `json:"decimals"`
		}
		res := getInfo(payload)
		if res == nil {
			t.Fatal("nil getInfo")
		}
		if err := json.Unmarshal([]byte(*res), &info); err != nil {
			t.Fatalf("bad json %q: %v", *res, err)
		}
		return info.Symbol, info.Decimals
	}
	p := func(s string) *string { return &s }

	if s, d := read(p(`{"symbol":"usdc"}`)); s != "usdc" || d != "6" {
		t.Fatalf("usdc: %s/%s, want usdc/6", s, d)
	}
	for _, in := range []*string{nil, p(""), p(`{"symbol":"eth"}`), p(`{"symbol":"dai"}`), p(`not json`), p(`{"symbol":""}`)} {
		if s, d := read(in); s != "ETH" || d != "18" {
			t.Fatalf("payload %v: %s/%s, want the ETH default", in, s, d)
		}
	}
}
