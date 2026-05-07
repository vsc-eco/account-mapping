package main

import (
	"strings"
	"testing"

	"evm-mapping-contract/contract/mapping"
)

// End-to-end reproduction of pentest finding F2.
//
// Bug: every wasmexport in main.go discarded the error returned by
// json.Unmarshal. Garbage input was silently parsed into a
// zero-valued struct and the handler ran on garbage. The pentest
// confirmed an identical downstream "vault address not configured"
// error for completely-invalid JSON ("NOT_VALID_JSON_AT_ALL{{{")
// and for valid-but-incomplete JSON — the contract had no way to
// distinguish them.
//
// This test drives the actual wasmexport entry point and asserts:
//
//   pre-fix: garbage JSON does NOT produce a json-tagged abort.
//            Either the contract continues silently into the
//            handler with a zero-valued struct, or it aborts with
//            an unrelated downstream error.
//
//   post-fix: garbage JSON aborts immediately with a json-tagged
//             error so callers can tell parse errors apart from
//             business-logic errors.
//
// sdk.Revert is panic-wrapped in the unit-test stub
// (see sdk/sdk_stub.go) so abort paths are observable here.

func TestF2_WasmExportRejectsGarbageJSON(t *testing.T) {
	garbage := "NOT_VALID_JSON_AT_ALL{{{"
	var panicValue interface{}
	func() {
		defer func() { panicValue = recover() }()
		_ = mapDeposit(&garbage)
	}()

	if panicValue == nil {
		t.Fatalf("F2 leak: garbage JSON did not abort the wasmexport")
	}
	msg, _ := panicValue.(string)
	if !strings.Contains(strings.ToLower(msg), "json") {
		t.Fatalf(
			"F2 fix not in effect: garbage JSON aborted but with a non-JSON error.\n"+
				"  panic: %v\n"+
				"  expected message mentioning 'json' so callers can tell parse errors\n"+
				"  apart from business-logic errors.",
			panicValue)
	}
}

// Sanity: a valid TransferParams JSON should NOT trip the new
// guard. Whatever happens downstream (vault not configured, etc.)
// is fine — the test only cares that the abort message is NOT
// a json-tagged one.
func TestF2_ValidJSONReachesHandler(t *testing.T) {
	valid := `{"to":"hive:bob","amount":"100","asset":"eth"}`
	var panicValue interface{}
	func() {
		defer func() { panicValue = recover() }()
		_ = transfer(&valid)
	}()

	if panicValue == nil {
		// transfer with no setup will likely still abort somewhere
		// downstream; if not, that's also fine.
		return
	}
	msg, _ := panicValue.(string)
	if strings.Contains(strings.ToLower(msg), "json") {
		t.Errorf("valid JSON triggered a json-tagged abort: %v", panicValue)
	}
}

// Compile-time sanity: keep the mapping package imported so the
// test file fails fast if struct names drift.
var _ = mapping.TransferParams{}
