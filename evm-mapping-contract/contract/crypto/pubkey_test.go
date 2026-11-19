package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

// A18: vectors from go-ethereum (crypto.CompressPubkey / FromECDSAPub /
// PubkeyToAddress) for keys 1, 2, 3, 7, 1000003, n-1 and n-1000003, so both
// Y parities of a compressed key are covered.
var pubkeyVectors = []struct{ compressed, uncompressed, address string }{
	{"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"},
	{"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a", "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"},
	{"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672", "0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69"},
	{"025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc", "045cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da", "0xd41c057fd1c78805AAC12B0A94a405c0461A6FBb"},
	{"02d53c88a0a81f9c3a80638fa81e477625d49aca04568139072c87a36e47ecb96a", "04d53c88a0a81f9c3a80638fa81e477625d49aca04568139072c87a36e47ecb96ac7555f5887a6f3f73b9abd2822c83a43e4f55c5cfb7a15b32db14821f87cb3a2", "0x83e08a127e7775bBFF35487e8217C548fa852f33"},
	{"0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777", "0x80C0dbf239224071c59dD8970ab9d542E3414aB2"},
	{"03d53c88a0a81f9c3a80638fa81e477625d49aca04568139072c87a36e47ecb96a", "04d53c88a0a81f9c3a80638fa81e477625d49aca04568139072c87a36e47ecb96a38aaa0a778590c08c46542d7dd37c5bc1b0aa3a30485ea4cd24eb7dd0783488d", "0xe683b0565F59eb73fEF6050cc9d04d4e0deeaF09"},
}

func TestA18_PubkeyAddressMatchesGoEthereum(t *testing.T) {
	for _, v := range pubkeyVectors {
		for _, enc := range []string{v.compressed, v.uncompressed} {
			pub, _ := hex.DecodeString(enc)
			addr, err := PubkeyAddress(pub)
			if err != nil {
				t.Errorf("PubkeyAddress(%s): %v", enc[:8], err)
				continue
			}
			if got := AddressToHex(addr); !strings.EqualFold(got, v.address) {
				t.Errorf("PubkeyAddress(%s...) = %s, want %s", enc[:8], got, v.address)
			}
		}
	}
}

func TestA18_PubkeyAddressRefusesWhatIsNotAKey(t *testing.T) {
	for name, enc := range map[string]string{
		"X not on the curve": "020000000000000000000000000000000000000000000000000000000000000005",
		"X not below p":      "02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
		"bad prefix":         "0579be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"short":              "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817",
		"uncompressed 0x02":  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
		"empty":              "",
	} {
		pub, _ := hex.DecodeString(enc)
		if addr, err := PubkeyAddress(pub); err == nil {
			t.Errorf("%s: PubkeyAddress = %s, want an error", name, AddressToHex(addr))
		}
	}
}
