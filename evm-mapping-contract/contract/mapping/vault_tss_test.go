package mapping

import (
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

const (
	tssPubG    = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" // key 1
	tssAddrG   = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
	tssPubTwo  = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" // key 2
	tssAddrTwo = "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"
)

func vaultHex(t *testing.T) (string, bool) {
	t.Helper()
	addr, ok := TssVaultAddress()
	return crypto.AddressToHex(addr), ok
}

// A18: the vault is the address of the TSS primary key, for a key that holds
// it (active, or deprecated and renewable), and nothing otherwise.
func TestA18_VaultIsTheTssKeysAddress(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want string // "" = no vault
	}{
		{"active," + tssPubG + ",ecdsa", tssAddrG},
		{"active,0x" + strings.ToUpper(tssPubG) + ",ecdsa", tssAddrG},
		{"active," + tssPubG + ",ecdsa,1,1", tssAddrG}, // BRK-2 / 0.11.0 extra fields
		{"deprecated," + tssPubG + ",ecdsa", tssAddrG},
		{"created", ""},
		{"", ""},
		{"deleted," + tssPubG + ",ecdsa", ""},
		{"retired," + tssPubG + ",ecdsa", ""},
		{"active," + tssPubG + ",eddsa", ""},
		{"active,zz,ecdsa", ""},
		{"active,020000000000000000000000000000000000000000000000000000000000000005,ecdsa", ""},
	} {
		sdk.ResetStubState()
		sdk.StubSetTssKey(tc.key)
		got, ok := vaultHex(t)
		if tc.want == "" {
			if ok {
				t.Errorf("key %q: vault %s, want none", tc.key, got)
			}
			continue
		}
		if !ok || !strings.EqualFold(got, tc.want) {
			t.Errorf("key %q: vault %s (ok=%v), want %s", tc.key, got, ok, tc.want)
		}
	}
	sdk.ResetStubState()
}

// The address is cached per public key; a new key (rotation) gets its own
// address, never the cached one.
func TestA18_VaultCacheIsPerKey(t *testing.T) {
	sdk.ResetStubState()
	defer sdk.ResetStubState()
	sdk.StubSetTssKey("active," + tssPubG + ",ecdsa")
	if got, _ := vaultHex(t); !strings.EqualFold(got, tssAddrG) {
		t.Fatalf("vault %s, want %s", got, tssAddrG)
	}
	if c := sdk.StateGetObject(constants.VaultKeyCacheKey); c == nil || !strings.EqualFold(*c, tssPubG+"|"+tssAddrG) {
		t.Fatalf("cache = %v, want %s|%s", c, tssPubG, tssAddrG)
	}
	// The cache is read: a planted entry for the same key is what comes back.
	sdk.StateSetObject(constants.VaultKeyCacheKey, tssPubG+"|0x00000000000000000000000000000000000000c1")
	if got, _ := vaultHex(t); got != "0x00000000000000000000000000000000000000c1" {
		t.Fatalf("vault %s, want the cached address", got)
	}
	// A different key ignores the entry and replaces it.
	sdk.StubSetTssKey("active," + tssPubTwo + ",ecdsa")
	if got, _ := vaultHex(t); !strings.EqualFold(got, tssAddrTwo) {
		t.Fatalf("after rotation vault %s, want %s", got, tssAddrTwo)
	}
	if c := sdk.StateGetObject(constants.VaultKeyCacheKey); c == nil || !strings.HasPrefix(*c, tssPubTwo+"|") {
		t.Fatalf("cache after rotation = %v", c)
	}
}
