package mapping

import (
	"encoding/hex"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

// Compressed public keys of the secp256k1 private keys 1, 2 and 3, and their
// Ethereum addresses (standard test vectors).
const (
	testPub1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	testPub2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	testPub3 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	testAdr1 = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	testAdr2 = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf"
	testAdr3 = "0x6813eb9362372eef6200f3b1dbc3f819671cba69"
)

func pubOf(t *testing.T, h string) CompressedPubKey {
	t.Helper()
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != 33 {
		t.Fatalf("bad test pubkey %s", h)
	}
	var p CompressedPubKey
	copy(p[:], raw)
	return p
}

// goldenVaultEntry is one registry entry: generation 2, primary = testPub1, zero
// backup, Draining, predecessor 1, heights 10/20/30/40. The node test
// (go-vsc-node lib/btcvault) decodes the same bytes; a layout drift on either
// side breaks one of the two.
const goldenVaultEntry = "00000002" + testPub1 +
	"000000000000000000000000000000000000000000000000000000000000000000" +
	"03" + "00000001" + "0000000a" + "00000014" + "0000001e" + "00000028"

func TestA01_VaultRegistryLayout(t *testing.T) {
	v := VaultRegistry{{
		Generation: 2, Primary: pubOf(t, testPub1), Status: VaultStatusDraining, Predecessor: 1,
		CreatedHeight: 10, ActivatedHeight: 20, RetiredHeight: 30, InactiveHeight: 40,
	}}
	raw := MarshalVaultRegistry(v)
	if len(raw) != VaultEntrySize || hex.EncodeToString(raw) != goldenVaultEntry {
		t.Fatalf("entry = %x\nwant    %s", raw, goldenVaultEntry)
	}
	back, err := UnmarshalVaultRegistry(append(raw, raw...))
	if err != nil || len(back) != 2 || back[1] != v[0] {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	if _, err := UnmarshalVaultRegistry(raw[:90]); err == nil {
		t.Fatal("a short entry decoded")
	}
}

func TestA01_VaultKeyNames(t *testing.T) {
	for gen, want := range map[uint32]string{0: "primary", 1: "primaryv1", 12: "primaryv12"} {
		if got := VaultKeyName(gen); got != want {
			t.Fatalf("VaultKeyName(%d) = %q, want %q", gen, got, want)
		}
	}
}

func TestA01_FoldLegacyKey(t *testing.T) {
	// No key: nothing to fold.
	sdk.ResetTestState()
	sdk.StubClearTssKeys()
	if FoldLegacyKeyIfNeeded(true) {
		t.Fatal("folded with no key")
	}
	if _, ok := sdk.TestStateGet(constants.VaultRegistryKey); ok {
		t.Fatal("registry written with no key")
	}

	// A key that has passed the vault check folds Active: the running vault
	// keeps its address and keeps signing.
	sdk.ResetTestState()
	sdk.StubSetTssKeyFor("primary", "active,"+testPub1+",ecdsa")
	sdk.StateSetObject(constants.VaultCheckedKey, testPub1)
	if !FoldLegacyKeyIfNeeded(false) {
		t.Fatal("verified legacy key not folded")
	}
	vaults, next, active, _ := LoadVaultState()
	if len(vaults) != 1 || vaults[0].Status != VaultStatusActive || vaults[0].Primary != pubOf(t, testPub1) ||
		!isGenesisVault(&vaults[0]) || next != 1 || active != 0 {
		t.Fatalf("fold: %+v next %d active %d", vaults, next, active)
	}
	if FoldLegacyKeyIfNeeded(true) {
		t.Fatal("fold ran twice")
	}

	// A key that never passed the check is not folded by a reader (no vault
	// until it is checked), and folds Pending in a ceremony op, so it activates
	// through activateKey's checks like any new generation.
	sdk.ResetTestState()
	sdk.StubSetTssKeyFor("primary", "active,"+testPub1+",ecdsa")
	if FoldLegacyKeyIfNeeded(false) {
		t.Fatal("a reader folded an unchecked key")
	}
	FoldLegacyKeyIfNeeded(true)
	if vaults, _, _, _ := LoadVaultState(); len(vaults) != 1 || vaults[0].Status != VaultStatusPending {
		t.Fatalf("unverified fold: %+v", vaults)
	}

	// Not ecdsa, created (no pubkey yet), malformed pubkey: no fold.
	for _, info := range []string{"active," + testPub1 + ",eddsa", "created,,ecdsa", "active,02abcd,ecdsa", "retired," + testPub1 + ",ecdsa"} {
		sdk.ResetTestState()
		sdk.StubSetTssKeyFor("primary", info)
		if FoldLegacyKeyIfNeeded(true) {
			t.Fatalf("folded %q", info)
		}
	}

	// A populated registry is never clobbered.
	sdk.ResetTestState()
	SaveVaultState(VaultRegistry{{Generation: 3, Predecessor: 3, Status: VaultStatusPending}}, 4, 0)
	sdk.StubSetTssKeyFor("primary", "active,"+testPub1+",ecdsa")
	if FoldLegacyKeyIfNeeded(true) {
		t.Fatal("fold over a populated registry")
	}
}

func TestA01_GenAddressAndFundHoldingSet(t *testing.T) {
	sdk.ResetTestState()
	sdk.StubClearTssKeys()
	SaveVaultState(VaultRegistry{
		{Generation: 0, Primary: pubOf(t, testPub1), Status: VaultStatusInactive, Predecessor: 0},
		{Generation: 1, Primary: pubOf(t, testPub2), Status: VaultStatusPurged, Predecessor: 0},
		{Generation: 2, Primary: pubOf(t, testPub3), Status: VaultStatusActive, Predecessor: 1},
		{Generation: 3, Status: VaultStatusPending, Predecessor: 2},
	}, 4, 2)

	gens := FundHoldingGens()
	if len(gens) != 2 {
		t.Fatalf("fund-holding gens = %+v, want active 2 then inactive 0", gens)
	}
	if gens[0].Generation != 2 || crypto.AddressToHex(gens[0].Address) != testAdr3 {
		t.Fatalf("first = gen %d %s, want the active gen 2 %s", gens[0].Generation, crypto.AddressToHex(gens[0].Address), testAdr3)
	}
	if gens[1].Generation != 0 || crypto.AddressToHex(gens[1].Address) != testAdr1 {
		t.Fatalf("second = gen %d %s, want inactive gen 0 %s", gens[1].Generation, crypto.AddressToHex(gens[1].Address), testAdr1)
	}
	// Purged (address retired) and Pending (no key) are not credited.
	for _, g := range gens {
		if g.Generation == 1 || g.Generation == 3 {
			t.Fatalf("gen %d is fund-holding", g.Generation)
		}
	}

	if v, ok := ActiveVault(); !ok || v.Generation != 2 || ActiveKeyName() != "primaryv2" {
		t.Fatalf("active = %+v %v name %s", v, ok, ActiveKeyName())
	}

	// The cache is keyed by public key: a stale entry for another key is ignored.
	sdk.StateSetObject(constants.VaultAddrCachePrefix+"2", testPub1+"|"+testAdr1)
	v := Vault{Generation: 2, Primary: pubOf(t, testPub3)}
	if addr, ok := GenAddress(&v); !ok || crypto.AddressToHex(addr) != testAdr3 {
		t.Fatalf("stale cache served %s", crypto.AddressToHex(addr))
	}
	if c, _ := sdk.TestStateGet(constants.VaultAddrCachePrefix + "2"); !strings.HasPrefix(c, testPub3+"|") {
		t.Fatalf("cache not rewritten: %q", c)
	}
	if _, ok := GenAddress(&Vault{Generation: 9}); ok {
		t.Fatal("zero key has an address")
	}
}

// The registry memo hands each caller its own copy: one that changes what it
// read and then neither saves nor aborts cannot change what the next reader
// in the same call sees.
func TestA01_RegistryMemoIsCopied(t *testing.T) {
	sdk.ResetTestState()
	SaveVaultState(VaultRegistry{{Generation: 0, Primary: pubOf(t, testPub1), Status: VaultStatusActive}}, 1, 0)
	v, _, _, _ := LoadVaultState()
	v[0].Status = VaultStatusPurged
	if again, _, _, _ := LoadVaultState(); again[0].Status != VaultStatusActive {
		t.Fatalf("status %v after a reader changed its copy", again[0].Status)
	}
}
