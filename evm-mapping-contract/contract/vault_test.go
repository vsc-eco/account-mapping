package main

import (
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

// A18: the vault is the TSS primary key's address. setVault let an owner key
// (or a typo) point deposits at an address the bridge cannot spend from, and
// registerPublicKey stored a key nothing read; both actions are gone.
func TestA18_VaultComesFromTheTssKey(t *testing.T) {
	sdk.ResetStubState()
	defer sdk.ResetStubState()
	sdk.StubSetTssKey("active,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,ecdsa")
	if v := vault(); v != ([20]byte{}) {
		t.Fatalf("vault() before the key's check signature = %x, want zero (E23)", v)
	}
	sdk.StateSetObject(constants.VaultCheckedKey, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	v := vault()
	if got := crypto.AddressToHex(v); !strings.EqualFold(got, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf") {
		t.Fatalf("vault() = %s, want the key's address", got)
	}
	sdk.StubSetTssKey("created")
	if v := vault(); v != ([20]byte{}) {
		t.Fatalf("vault() before keygen = %x, want zero", v)
	}
}

func TestA18_SetVaultAndRegisterPublicKeyAreGone(t *testing.T) {
	sdk.ResetStubState()
	defer sdk.ResetStubState()
	for _, action := range []string{"setVault", "registerPublicKey"} {
		msg := func() (msg string) {
			defer func() {
				if r := recover(); r != nil {
					msg, _ = r.(string)
					if msg == "" {
						msg = "panic"
					}
				}
			}()
			dispatchAdmin(action, []byte(`"0xCAFEBABECAFEBABECAFEBABECAFEBABECAFEBABE"`))
			return ""
		}()
		if !strings.Contains(msg, "unknown action") {
			t.Errorf("dispatchAdmin(%s) = %q, want unknown action", action, msg)
		}
	}
}
