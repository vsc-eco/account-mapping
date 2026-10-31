package mapping

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// checkSig signs the vault check message for pubHex with private key priv
// and returns r||s||v (v 0/1).
func checkSig(priv byte, contractId string, chainId uint64, pubHex string) string {
	key := secp256k1.PrivKeyFromBytes(append(make([]byte, 31), priv))
	c := ecdsa.SignCompact(key, VaultCheckDigest(contractId, chainId, pubHex), true) // [27+4+v][r][s]
	return hex.EncodeToString(append(append([]byte{}, c[1:65]...), c[0]-31))
}

func callErr(f func() error) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg, _ = r.(string)
		}
	}()
	if err := f(); err != nil {
		return err.Error()
	}
	return ""
}

// E23: an active primary key is not a vault until it has signed the check
// message; the signature puts it live, and nothing else does.
func TestE23_VaultGoesLiveOnlyOnTheKeysCheckSignature(t *testing.T) {
	const cid = "contract:test" // the stub env's contract id
	sdk.ResetStubState()
	defer sdk.ResetStubState()
	sdk.StubSetTssKey("active," + tssPubG + ",ecdsa")
	if _, ok := TssVaultAddress(); ok {
		t.Fatal("an unverified key is a vault")
	}

	// requestVaultCheck asks the key to sign the check message for this contract and chain.
	if msg := callErr(func() error { return HandleRequestVaultCheck(11155111) }); msg != "" {
		t.Fatal(msg)
	}
	want := "primary," + hex.EncodeToString(VaultCheckDigest(cid, 11155111, tssPubG))
	if got := sdk.TestSignRequests(); len(got) != 1 || got[0] != want {
		t.Fatalf("sign requests %v, want [%s]", got, want)
	}

	good := checkSig(1, cid, 11155111, tssPubG)
	sig, _ := hex.DecodeString(good)
	n := secp256k1.S256().N
	s := new(big.Int).SetBytes(sig[32:64])
	high := append(append(append([]byte{}, sig[:32]...), new(big.Int).Sub(n, s).FillBytes(make([]byte, 32))...), sig[64]^1)
	for name, bad := range map[string]string{
		"another key":          checkSig(2, cid, 11155111, tssPubG),
		"another contract":     checkSig(1, "vsc1other", 11155111, tssPubG),
		"another chain":        checkSig(1, cid, 1, tssPubG),
		"the same sig, high-S": hex.EncodeToString(high),
		"short":                good[:128],
		"v out of range":       good[:128] + "05",
		"not hex":              strings.Repeat("zz", 65),
	} {
		if msg := callErr(func() error { return HandleAttestVault(bad, 11155111) }); msg == "" {
			t.Errorf("%s: attestVault accepted", name)
		}
		if _, ok := TssVaultAddress(); ok {
			t.Fatalf("%s: the vault went live", name)
		}
	}

	// v as 0/1 or as 27/28.
	for i, v := range []string{good, good[:128] + hex.EncodeToString([]byte{27 + sig[64]})} {
		sdk.StateDeleteObject(constants.VaultCheckedKey)
		if msg := callErr(func() error { return HandleAttestVault(v, 11155111) }); msg != "" {
			t.Fatalf("attestVault(v=%s): %s", v[128:], msg)
		}
		// A01: attestVault itself puts the checked key in the registry and
		// caches its address, so the first deposit pays for neither.
		if c := sdk.StateGetObject(constants.VaultAddrCachePrefix + "0"); i == 0 && (c == nil || !strings.HasSuffix(strings.ToLower(*c), strings.ToLower(tssAddrG))) {
			t.Fatalf("address cache right after attest: %v", c)
		}
		if got, _ := vaultHex(t); !strings.EqualFold(got, tssAddrG) {
			t.Fatalf("vault after attest (v=%s) = %s, want %s", v[128:], got, tssAddrG)
		}
	}
	if logs := sdk.TestLogs(); len(logs) == 0 || !strings.Contains(logs[len(logs)-1], "vault|a=") {
		t.Fatalf("no vault log: %v", logs)
	}

	// Verified: a second request is refused, a second attest is a no-op.
	if msg := callErr(func() error { return HandleRequestVaultCheck(11155111) }); !strings.Contains(msg, "already verified") {
		t.Fatalf("request after verification = %q", msg)
	}
	if msg := callErr(func() error { return HandleAttestVault(good, 11155111) }); msg != "" {
		t.Fatalf("attest after verification = %q", msg)
	}

	// A key that is not active can be neither checked nor attested.
	for _, key := range []string{"created", "deprecated," + tssPubTwo + ",ecdsa", "active," + tssPubTwo + ",eddsa"} {
		sdk.ResetStubState()
		sdk.StubSetTssKey(key)
		if msg := callErr(func() error { return HandleRequestVaultCheck(1) }); !strings.Contains(msg, "not active") {
			t.Errorf("request with key %q = %q", key, msg)
		}
		if msg := callErr(func() error { return HandleAttestVault(checkSig(2, cid, 1, tssPubTwo), 1) }); !strings.Contains(msg, "not active") {
			t.Errorf("attest with key %q = %q", key, msg)
		}
	}
}

// The check message is the EIP-191 personal_sign digest of a fixed text, so
// any wallet library can reproduce it.
func TestE23_CheckDigestIsPersonalSign(t *testing.T) {
	msg := "magi evm vault check-signature v1:vsc1bridge:11155111:" + tssPubG
	want := sdk.Keccak256([]byte("\x19Ethereum Signed Message:\n" + "120" + msg))
	if len(msg) != 120 {
		t.Fatalf("message is %d bytes", len(msg))
	}
	if got := VaultCheckDigest("vsc1bridge", 11155111, tssPubG); hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("digest %x, want %x", got, want)
	}
}
