package main

import (
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// setVault stored whatever string it was given. A typo made vault() zero, so
// deposits reverted, and every unmap after it snapshotted VaultAtQueue=0x0,
// which confirmSpend and expireWithdrawal both refuse: the single withdrawal
// queue was wedged until another timelocked setVault.
func TestSetVaultRejectsWhatIsNotAnAddress(t *testing.T) {
	abortOf := func(payload string) (msg string) {
		defer func() {
			if r := recover(); r != nil {
				msg, _ = r.(string)
				if msg == "" {
					msg = "panic"
				}
			}
		}()
		dispatchAdmin("setVault", []byte(payload))
		return ""
	}
	for _, bad := range []string{
		`"0xabc"`, // too short
		`"0x00000000000000000000000000000000000000zz"`, // not hex
		`"0x0000000000000000000000000000000000000000"`, // zero
		`"vault"`,
	} {
		sdk.ResetTestState()
		if msg := abortOf(bad); !strings.Contains(msg, "setVault") {
			t.Errorf("setVault(%s): abort = %q, want a setVault refusal", bad, msg)
		}
		if got := sdk.StateGetObject(constants.VaultAddressKey); got != nil {
			t.Errorf("setVault(%s) stored %q", bad, *got)
		}
	}

	sdk.ResetTestState()
	if msg := abortOf(`"0xCAFEBABECAFEBABECAFEBABECAFEBABECAFEBABE"`); msg != "" {
		t.Fatalf("a valid vault address was refused: %s", msg)
	}
	if got := sdk.StateGetObject(constants.VaultAddressKey); got == nil || *got != "0xcafebabecafebabecafebabecafebabecafebabe" {
		stored := "nothing"
		if got != nil {
			stored = *got
		}
		t.Fatalf("stored vault = %s, want the canonical lowercase address", stored)
	}
	sdk.ResetTestState()
}
