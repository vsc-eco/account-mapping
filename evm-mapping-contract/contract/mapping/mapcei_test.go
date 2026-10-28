package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// mapceiTx is an EIP-155 legacy tx paying value to the vault with calldata,
// signed by a fixed test key.
func mapceiTx(t *testing.T, value *big.Int, data []byte) []byte {
	t.Helper()
	priv := secp256k1.PrivKeyFromBytes(bytesOf(t, "4646464646464646464646464646464646464646464646464646464646464646"))
	const chainId = 11155111
	body := func(v, r, s []byte) []byte {
		return rlp.EncodeList(rlp.EncodeUint64(0), rlp.EncodeBigInt(big.NewInt(1e9)), rlp.EncodeUint64(100_000),
			rlp.EncodeAddress(rp7Vault), rlp.EncodeBigInt(value), rlp.EncodeBytes(data), v, r, s)
	}
	sighash := crypto.Keccak256(body(rlp.EncodeUint64(chainId), rlp.EncodeUint64(0), rlp.EncodeUint64(0)))
	sig := dcrecdsa.SignCompact(priv, sighash, false)
	rec := sig[0] - 27
	if sig[0] >= 31 {
		rec = sig[0] - 31
	}
	return body(rlp.EncodeUint64(chainId*2+35+uint64(rec)), rlp.EncodeBytes(sig[1:33]), rlp.EncodeBytes(sig[33:65]))
}

func bytesOf(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// MAP-CEI-1: an ETH deposit with swap instructions calls the router before
// the map returns. A contract on the router's path (a pool or token the
// router's owner registered) that calls map again with the same deposit must
// find it already processed: the deposit is credited and its supply tracked
// once, never twice.
func TestMAPCEI1_ARouterReenteringMapCannotCreditTheDepositTwice(t *testing.T) {
	w := newRP7World(t)
	raw := mapceiTx(t, big.NewInt(1e18), []byte("swap_to=hive:bob&asset_out=hbd&min_amount_out=1"))
	txRoot, txNodes := buildSingleLeafMPT(raw)
	receipt := append([]byte{0x02}, rlp.EncodeList(rlp.EncodeUint64(1), rlp.EncodeUint64(30_000),
		rlp.EncodeBytes(make([]byte, 256)), rlp.EncodeList())...)
	rcRoot, rcNodes := buildSingleLeafMPT(receipt)
	w.n++
	w.headers[w.n] = (&blocklist.EthBlockHeader{BlockNumber: w.n, TransactionsRoot: txRoot, ReceiptsRoot: rcRoot,
		BaseFeePerGas: 1e9, GasLimit: 30_000_000, ChainId: 11155111}).Serialize()
	req := VerificationRequest{BlockHeight: w.n, TxIndex: 1, DepositType: "eth",
		RawHex: hex.EncodeToString(raw), MerkleProofHex: hex.EncodeToString(concatBytes(txNodes)),
		ReceiptProof: base64.StdEncoding.EncodeToString(concatBytes(rcNodes))}

	sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
	var inner error
	calls := 0
	sdk.StubSetContractCallResponder(func(contractId, method, payload string) *string {
		calls++
		if calls == 1 {
			inner = HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111)
		}
		ok := `{"ok":true,"result":"{}"}`
		return &ok
	})
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err != nil {
		t.Fatalf("the deposit itself: %v", err)
	}
	if inner == nil || !strings.Contains(inner.Error(), "already") {
		t.Fatalf("map re-entered from the router's swap: %v, want refused as already processed", inner)
	}
	if calls != 1 {
		t.Fatalf("router called %d times, want once", calls)
	}
	// 1 ETH less the 1% reserve share is user supply once, held by the bridge
	// for the router's swap (the stub router took nothing).
	if s := GetSupply("eth"); s.User.Cmp(big.NewInt(99e16)) != 0 {
		t.Fatalf("user supply %s after one 1 ETH deposit, want 0.99 ETH", s.User)
	}
	if self := GetBalance("contract:"+sdk.GetEnv().ContractId, "eth"); self.Cmp(big.NewInt(99e16)) != 0 {
		t.Fatalf("the bridge holds %s for the swap, want the one deposit's 0.99 ETH", self)
	}
}
