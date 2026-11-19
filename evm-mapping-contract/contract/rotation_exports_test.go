package main

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/mapping"
	"evm-mapping-contract/sdk"
)

const (
	rotOwner = "hive:magi.bridge.owner"
	rotPub1  = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	rotPub2  = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)

func rotCall(f func(*string) *string, in string) (out, msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg, _ = r.(string)
			if msg == "" {
				msg = "panic"
			}
		}
	}()
	if p := f(&in); p != nil {
		out = *p
	}
	return out, ""
}

// A01: the rotation ceremony is the owner's, called directly (the TSS ceremony,
// not the owner, decides the key); the operational ops are the owner's or the
// appointed operator's.
func TestA01_RotationExports(t *testing.T) {
	sdk.ResetStubState()
	sdk.StubClearTssKeys()
	defer sdk.ResetStubState()
	sdk.SetTestEnvKey("contract.owner", rotOwner)

	// Not the owner: refused.
	sdk.SetTestCaller("hive:mallory")
	for name, f := range map[string]func(*string) *string{
		"createKey": createKey, "activateKey": activateKey, "discardPendingKey": discardPendingKey,
		"renewKey": renewKey, "setVaultOperator": setVaultOperator,
	} {
		if _, msg := rotCall(f, ""); !strings.Contains(msg, "owner") {
			t.Fatalf("%s by a stranger: %q, want refused", name, msg)
		}
	}
	// The owner's posting key is not enough either.
	sdk.SetTestPostingCaller(rotOwner)
	if _, msg := rotCall(createKey, ""); !strings.Contains(msg, "active authority") {
		t.Fatalf("createKey with a posting signature: %q", msg)
	}

	sdk.SetTestCaller(rotOwner)
	out, msg := rotCall(createKey, "")
	if msg != "" || !strings.Contains(out, "generation 0, key primary") {
		t.Fatalf("genesis createKey: %q %q", out, msg)
	}
	if keys := sdk.TestCreatedKeys(); len(keys) != 1 || keys[0] != "primary,ecdsa,365" {
		t.Fatalf("keys requested %v", keys)
	}
	sdk.StubSetTssKeyFor("primary", "active,"+rotPub1+",ecdsa,1")
	if out, msg := rotCall(activateKey, ""); msg != "" || out != "activated generation 0" {
		t.Fatalf("activate genesis: %q %q", out, msg)
	}

	// Rotation: mint gen 1, activate it; gen 0 retires holding the custody.
	mapping.SetSupply("eth", mapping.Supply{Active: wei(t, "1000"), User: wei(t, "1000"), Fee: wei(t, "0")})
	if _, msg := rotCall(createKey, ""); msg != "" {
		t.Fatal(msg)
	}
	sdk.StubSetTssKeyFor("primaryv1", "active,"+rotPub2+",ecdsa,1,1")
	if out, msg := rotCall(activateKey, ""); msg != "" || !strings.Contains(out, "generation 0 now retiring") {
		t.Fatalf("activate rotation: %q %q", out, msg)
	}
	// NN#3: gen 0 still holds the ETH, so no further generation.
	if _, msg := rotCall(createKey, ""); !strings.Contains(msg, "NN#3") {
		t.Fatalf("createKey while gen 0 is funded: %q", msg)
	}
	if !strings.Contains(proposeExecuteMsg(t, "createKey"), "timelock") {
		t.Fatal("the timelocked createKey path executed at once")
	}

	// vaultInfo: both generations, gen 0's book.
	out, _ = rotCall(vaultInfo, "")
	var info struct {
		Active      *uint32 `json:"active"`
		Generations []struct {
			Generation uint32            `json:"generation"`
			Status     string            `json:"status"`
			Key        string            `json:"key"`
			Address    string            `json:"address"`
			Books      map[string]string `json:"books"`
		} `json:"generations"`
	}
	if err := json.Unmarshal([]byte(out), &info); err != nil || info.Active == nil || *info.Active != 1 || len(info.Generations) != 2 {
		t.Fatalf("vaultInfo %s: %v", out, err)
	}
	if g := info.Generations[0]; g.Status != "retiring" || g.Key != "primary" || g.Books["eth"] != "1000" ||
		!strings.EqualFold(g.Address, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf") {
		t.Fatalf("gen 0 info %+v", g)
	}
	if g := info.Generations[1]; g.Status != "active" || g.Key != "primaryv1" || g.Books != nil {
		t.Fatalf("gen 1 info %+v", g)
	}

	// The vault operator: set, and cleared with an empty input.
	if _, msg := rotCall(setVaultOperator, "not-an-account"); msg == "" {
		t.Fatal("an invalid operator was accepted")
	}
	if _, msg := rotCall(setVaultOperator, "hive:magi.bot"); msg != "" {
		t.Fatal(msg)
	}
	if v, _ := sdk.TestStateGet(constants.VaultOperatorKey); v != "hive:magi.bot" {
		t.Fatalf("operator %q", v)
	}
	if _, msg := rotCall(setVaultOperator, ""); msg != "" {
		t.Fatal(msg)
	}
	if _, ok := sdk.TestStateGet(constants.VaultOperatorKey); ok {
		t.Fatal("operator not cleared")
	}
}

func wei(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("bad amount %s", s)
	}
	return v
}

func proposeExecuteMsg(t *testing.T, action string) string {
	t.Helper()
	out, msg := rotCall(propose, `{"action":"`+action+`","payload_hex":""}`)
	if msg != "" {
		return "propose: " + msg
	}
	var resp struct {
		ProposalId uint64 `json:"proposal_id"`
	}
	_ = json.Unmarshal([]byte(out), &resp)
	_, msg = rotCall(execute, `{"proposal_id":`+jsonUint(resp.ProposalId)+`}`)
	return msg
}
