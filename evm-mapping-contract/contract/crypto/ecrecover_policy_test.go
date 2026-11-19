package crypto

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// E6: the node (go-vsc-node develop) has no `crypto.ecrecover_strict` or
// `crypto.ecrecover_canonical` import, and a wasm importing them fails every
// call with "failed to register wasm buffer: unknown import". The low-S policy
// therefore runs in the contract, over the plain `crypto.ecrecover` import.
// These tests pin that policy. The stub's recovery (dcrd RecoverCompact)
// accepts high-S, so without the in-contract check a high-S twin passes
// EcrecoverStrict here, as it would on any host that doesn't enforce low-S.

var policyN = secp256k1.S256().N

func policyFixture(t *testing.T) (hash []byte, v byte, r, s []byte, want [20]byte) {
	t.Helper()
	keyBytes, _ := hex.DecodeString("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	key := secp256k1.PrivKeyFromBytes(keyBytes)
	hash = nativeKeccak256([]byte("e6 ecrecover policy"))
	sig := ecdsa.SignCompact(key, hash, false) // [27+recid][r][s], low-S
	return hash, sig[0] - 27, sig[1:33], sig[33:65], pubKeyToAddress(key.PubKey())
}

func scalar32(x *big.Int) []byte {
	out := make([]byte, 32)
	x.FillBytes(out)
	return out
}

func TestE6_EcrecoverStrict(t *testing.T) {
	hash, v, r, s, want := policyFixture(t)
	highS := scalar32(new(big.Int).Sub(policyN, new(big.Int).SetBytes(s)))

	got, err := EcrecoverStrict(hash, v, r, s)
	if err != nil || got != want {
		t.Fatalf("low-S: got %s err=%v, want %s", AddressToHex(got), err, AddressToHex(want))
	}
	if got, err := EcrecoverStrict(hash, v^1, r, highS); err == nil {
		t.Fatalf("high-S twin accepted (recovered %s); strict must reject it", AddressToHex(got))
	}
	for name, bad := range map[string][]byte{
		"s=0":   make([]byte, 32),
		"s=N":   scalar32(policyN),
		"s=N+1": scalar32(new(big.Int).Add(policyN, big.NewInt(1))),
	} {
		if _, err := EcrecoverStrict(hash, v, r, bad); err == nil {
			t.Fatalf("%s accepted; strict must reject it", name)
		}
	}
	if _, err := EcrecoverStrict(hash, v, make([]byte, 32), s); err == nil {
		t.Fatal("r=0 accepted; strict must reject it")
	}
}

func TestE6_EcrecoverCanonical(t *testing.T) {
	hash, v, r, s, want := policyFixture(t)
	highS := scalar32(new(big.Int).Sub(policyN, new(big.Int).SetBytes(s)))

	got, err := EcrecoverCanonical(hash, v, r, s)
	if err != nil || got != want {
		t.Fatalf("low-S: got %s err=%v, want %s", AddressToHex(got), err, AddressToHex(want))
	}
	got, err = EcrecoverCanonical(hash, v^1, r, highS)
	if err != nil || got != want {
		t.Fatalf("high-S twin: got %s err=%v, want %s (same signer)", AddressToHex(got), err, AddressToHex(want))
	}
	// s >= N must be refused, not folded into a valid-looking low-S value.
	for name, bad := range map[string][]byte{
		"s=0":   make([]byte, 32),
		"s=N":   scalar32(policyN),
		"s=N+1": scalar32(new(big.Int).Add(policyN, big.NewInt(1))),
	} {
		if got, err := EcrecoverCanonical(hash, v, r, bad); err == nil {
			t.Fatalf("%s accepted (recovered %s); canonical must reject it", name, AddressToHex(got))
		}
	}
}
