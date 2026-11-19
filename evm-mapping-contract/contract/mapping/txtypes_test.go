package mapping

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
)

// E18: deposits sent as EIP-2930 (type 1) and EIP-4844 (type 3) transactions
// parse and recover their real sender. Vectors signed by go-ethereum v1.14.12
// (types.NewCancunSigner, chain 11155111) with a non-empty access list and two
// blob hashes, so the nested lists the signing hash re-encodes are exercised,
// and calldata (the deposit instructions are read from it).
// Type 4 is covered on the wasm runtime (go-ethereum 1.14 cannot build it).
func TestE18_TypedDepositsRecoverTheirSender(t *testing.T) {
	const sender = "0x4ed6a0c84697cc1630558b74ade088e7e09e5d09"
	vault, _ := crypto.HexToAddress("0x00000000000000000000000000000000000000fa")
	for name, v := range map[string]struct {
		raw   string
		nonce uint64
	}{
		"type1": {"01f8e083aa36a7038506fc23ac00829c409400000000000000000000000000000000000000fa880de0b6b3a7640000936465706f7369745f746f3d686976653a626f62f85bf8599400000000000000000000000000000000000000c0f842a00100000000000000000000000000000000000000000000000000000000000000a0020000000000000000000000000000000000000000000000000000000000000001a00330786a092a0a3cf563069e90dda0fec4b5f307da81617e733f8c59ca397a88a077e36e2ce505a59bde98830105e60daf9f36c1587b9dee6c558d5286e10f3924", 3},
		"type3": {"03f9012e83aa36a704843b9aca008506fc23ac00829c409400000000000000000000000000000000000000fa880de0b6b3a7640000936465706f7369745f746f3d686976653a626f62f85bf8599400000000000000000000000000000000000000c0f842a00100000000000000000000000000000000000000000000000000000000000000a00200000000000000000000000000000000000000000000000000000000000000843b9aca00f842a00100000000000000000000000000000000000000000000000000000000000000a0010200000000000000000000000000000000000000000000000000000000000001a0cb6d0ec76e98aeb12059accff9c5b8a7c51d738db4c301750104277b0cd7df6da07c218dee548cb8af5eafa629f8d492ff4ce83a0c652500016641525575419b80", 4},
	} {
		raw, _ := hex.DecodeString(v.raw)
		tx, err := parseTransaction(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tx.ChainId != 11155111 || tx.Nonce != v.nonce || tx.To != vault || new(big.Int).SetBytes(tx.Value).Cmp(big.NewInt(1e18)) != 0 ||
			string(tx.Data) != "deposit_to=hive:bob" {
			t.Fatalf("%s: parsed chain=%d nonce=%d to=%x value=%x data=%q", name, tx.ChainId, tx.Nonce, tx.To, tx.Value, tx.Data)
		}
		got, err := crypto.EcrecoverCanonical(computeTxSighash(raw, tx), 27+tx.V, padTo32(tx.R), padTo32(tx.S))
		if err != nil {
			t.Fatalf("%s: ecrecover: %v", name, err)
		}
		if crypto.AddressToHex(got) != sender {
			t.Fatalf("%s: recovered %s, want %s", name, crypto.AddressToHex(got), sender)
		}
	}
}

func TestE18_MalformedTypedTxsAreRefused(t *testing.T) {
	type1, _ := hex.DecodeString("01f8cd83aa36a7038506fc23ac008275309400000000000000000000000000000000000000fa880de0b6b3a764000080f85bf8599400000000000000000000000000000000000000c0f842a00100000000000000000000000000000000000000000000000000000000000000a0020000000000000000000000000000000000000000000000000000000000000080a0b01af0d5f844f7f4215284e48756f51512e1470f178ea04de60ee9dd0a07c301a00b83dbae678a52fa18725d1bfc4a1db3df2938846620da9ca6c3e9d8d485f026")
	items, _ := rlp.DecodeList(type1[1:])
	enc := func(its []rlp.Item) []byte {
		out := make([][]byte, len(its))
		for i, it := range its {
			out[i] = reencodeItem(it)
		}
		return rlp.EncodeList(out...)
	}
	cases := map[string][]byte{
		"type 1 with a field missing": append([]byte{1}, enc(items[:10])...),
		"type 1 with an extra field":  append([]byte{1}, enc(append(append([]rlp.Item{}, items...), rlp.Item{Data: []byte{1}}))...),
		"type 1 read as type 3":       append([]byte{3}, type1[1:]...),
		"unknown type 5":              append([]byte{5}, type1[1:]...),
	}
	bad := append([]rlp.Item{}, items...)
	bad[8] = rlp.Item{Data: []byte{2}} // yParity 2
	cases["yParity 2"] = append([]byte{1}, enc(bad)...)
	for name, raw := range cases {
		if _, err := parseTransaction(raw); err == nil {
			t.Errorf("%s: parsed without error", name)
		} else if !strings.Contains(err.Error(), "tx") {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
}
