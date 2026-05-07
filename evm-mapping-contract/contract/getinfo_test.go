package main

import (
	"encoding/json"
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
