package crypto

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

func nativeKeccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

func nativeEcrecover(hash []byte, v byte, r, s []byte) ([20]byte, error) {
	var addr [20]byte
	sig := make([]byte, 65)
	sig[0] = v
	copy(sig[1:33], r)
	copy(sig[33:65], s)
	pubKey, _, err := ecdsa.RecoverCompact(sig, hash)
	if err != nil {
		return addr, err
	}
	uncompressed := pubKey.SerializeUncompressed()
	addrHash := nativeKeccak256(uncompressed[1:])
	copy(addr[:], addrHash[12:])
	return addr, nil
}

func pubKeyToAddress(pubKey *secp256k1.PublicKey) [20]byte {
	var addr [20]byte
	uncompressed := pubKey.SerializeUncompressed()
	addrHash := nativeKeccak256(uncompressed[1:])
	copy(addr[:], addrHash[12:])
	return addr
}

func TestKeccak256(t *testing.T) {
	got := hex.EncodeToString(nativeKeccak256([]byte("hello")))
	want := "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
	if got != want {
		t.Fatalf("keccak256('hello') = %s, want %s", got, want)
	}
}

func TestKeccak256Empty(t *testing.T) {
	got := hex.EncodeToString(nativeKeccak256([]byte{}))
	want := "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if got != want {
		t.Fatalf("keccak256('') = %s, want %s", got, want)
	}
}

func TestKeccak256TransferEventSig(t *testing.T) {
	got := hex.EncodeToString(nativeKeccak256([]byte("Transfer(address,address,uint256)")))
	want := "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	if got != want {
		t.Fatalf("Transfer event sig = %s, want %s", got, want)
	}
}

func TestEcrecover(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)

	expectedAddr := pubKeyToAddress(privKey.PubKey())
	knownAddr := "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
	if !strings.EqualFold(AddressToHex(expectedAddr), knownAddr) {
		t.Fatalf("derived %s != known %s", AddressToHex(expectedAddr), knownAddr)
	}

	msgHash := nativeKeccak256([]byte("test message"))
	sig := ecdsa.SignCompact(privKey, msgHash, false)

	recovered, err := nativeEcrecover(msgHash, sig[0], sig[1:33], sig[33:65])
	if err != nil {
		t.Fatal(err)
	}
	if recovered != expectedAddr {
		t.Fatalf("ecrecover: got %s, want %s", AddressToHex(recovered), AddressToHex(expectedAddr))
	}
}

// C6 / E21: the credited identity is the node's did:pkh:eip155:1: with the
// EIP-55 address, on every L1 chain.
func TestAddressToDID(t *testing.T) {
	addr, _ := HexToAddress("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
	want := "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	if did := AddressToDID(addr); did != want {
		t.Fatalf("got %s, want %s", did, want)
	}
}

// The EIP-55 specification's test vectors.
func TestChecksumHexMatchesEIP55(t *testing.T) {
	for _, want := range []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
		"0x52908400098527886E0F7030069857D2E4169EE7",
		"0x8617E340B3D01FA5F11F306F4090FD50E238070D",
		"0xde709f2102306220921060314715629080e2fb77",
		"0x27b1fdb04752bbc536007a920d24acb045561c26",
	} {
		addr, err := HexToAddress(want)
		if err != nil {
			t.Fatal(err)
		}
		if got := ChecksumHex(addr); got != want {
			t.Errorf("ChecksumHex = %s, want %s", got, want)
		}
	}
}

// Every casing of a did:pkh:eip155:1 identity is the same key holder and
// canonicalizes to one string; other identities pass through untouched.
func TestCanonicalIdentity(t *testing.T) {
	const canon = "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	for _, in := range []string{
		canon,
		"did:pkh:eip155:1:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
		"did:pkh:eip155:1:0XF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266",
		"DID:PKH:EIP155:1:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
		"did:pkh:eip155:1:f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
	} {
		if got := CanonicalIdentity(in); got != canon {
			t.Errorf("CanonicalIdentity(%s) = %s, want %s", in, got, canon)
		}
	}
	for _, in := range []string{"hive:alice", "contract:vsc1x", "did:pkh:eip155:11155111:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "did:pkh:eip155:1:0xzz", ""} {
		if got := CanonicalIdentity(in); got != in {
			t.Errorf("CanonicalIdentity(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestHexToAddress(t *testing.T) {
	addr, err := HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0Ce3606eB48")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(addr[:]) != "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" {
		t.Fatalf("address mismatch: %x", addr)
	}
}
