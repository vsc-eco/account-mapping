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

// verifyVault marks pubHex's check signature verified (E23), as attestVault
// does.
func verifyVault(pubHex string) { sdk.StateSetObject(constants.VaultCheckedKey, pubHex) }

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
		if parts := strings.Split(tc.key, ","); len(parts) > 1 { // E23: verified, so only A18's rules decide
			verifyVault(strings.ToLower(strings.TrimPrefix(parts[1], "0x")))
		}
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

// The address is cached per generation and public key; a new generation (a
// rotation, A01) gets its own address, never a cached one.
func TestA18_VaultCacheIsPerKey(t *testing.T) {
	sdk.ResetStubState()
	sdk.StubClearTssKeys()
	defer sdk.ResetStubState()
	sdk.StubSetTssKey("active," + tssPubG + ",ecdsa")
	verifyVault(tssPubG)
	if got, _ := vaultHex(t); !strings.EqualFold(got, tssAddrG) {
		t.Fatalf("vault %s, want %s", got, tssAddrG)
	}
	cacheKey := constants.VaultAddrCachePrefix + "0"
	if c := sdk.StateGetObject(cacheKey); c == nil || !strings.EqualFold(*c, tssPubG+"|"+tssAddrG) {
		t.Fatalf("cache = %v, want %s|%s", c, tssPubG, tssAddrG)
	}
	// The cache is read: a planted entry for the same key is what comes back.
	sdk.StateSetObject(cacheKey, tssPubG+"|0x00000000000000000000000000000000000000c1")
	if got, _ := vaultHex(t); got != "0x00000000000000000000000000000000000000c1" {
		t.Fatalf("vault %s, want the cached address", got)
	}
	// A rotation to a new generation's key: no vault move until it activates,
	// then the new generation's own address and cache entry.
	if _, _, err := MintNextGeneration(10); err != nil {
		t.Fatal(err)
	}
	sdk.StubSetTssKeyFor("primaryv1", "active,"+tssPubTwo+",ecdsa,1,1")
	if got, _ := vaultHex(t); got != "0x00000000000000000000000000000000000000c1" {
		t.Fatalf("a pending generation moved the vault to %s", got)
	}
	if _, _, _, err := ActivatePendingGeneration(11); err != nil {
		t.Fatal(err)
	}
	if got, _ := vaultHex(t); !strings.EqualFold(got, tssAddrTwo) {
		t.Fatalf("after rotation vault %s, want %s", got, tssAddrTwo)
	}
	if c := sdk.StateGetObject(constants.VaultAddrCachePrefix + "1"); c == nil || !strings.HasPrefix(*c, tssPubTwo+"|") {
		t.Fatalf("cache after rotation = %v", c)
	}
}
