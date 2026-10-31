package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
)

// FAILDEP-1: a native ETH deposit is credited only if its tx succeeded. The
// tx is real: phase C1's reserve deposit on Sepolia (0xb732..b64f), which
// reverted out of gas creating the vault's account (Glamsterdam) and moved
// nothing; rp7Vault is that vault. Old code minted 0.04975 ETH for it.
const faildep1RawTx = "02f88183aa36a780843b9aca008504a817c8008275309488cbba6b5e5d2c20d9cfc55f3b2fc18d073ccf1487b0bf5c859360008c746f5f726573657276653d31c080a04b2d2c6c71f3e406a86d353facecb80c8ec37cac1b7cffd6058828944a8f4c6aa007e686f07c30fe48a457a1376b340734b948f7431b1612c4b53d935dadf3cf2c"

const faildep1Value = "49750000000000000" // 0.04975 ETH, calldata to_reserve=1

// faildep1Block plants the tx at index 1 and a type-2 receipt with status
// (none when status < 0) in a new block, and returns the map request.
func faildep1Block(w *rp7World, status int) (VerificationRequest, [][]byte) {
	raw, _ := hex.DecodeString(faildep1RawTx)
	txRoot, txNodes := buildSingleLeafMPT(raw)
	receipt := append([]byte{0x02}, rlp.EncodeList(rlp.EncodeUint64(uint64(max(status, 0))), rlp.EncodeUint64(30_000),
		rlp.EncodeBytes(make([]byte, 256)), rlp.EncodeList())...)
	rcRoot, rcNodes := buildSingleLeafMPT(receipt)
	w.n++
	w.headers[w.n] = (&blocklist.EthBlockHeader{BlockNumber: w.n, TransactionsRoot: txRoot, ReceiptsRoot: rcRoot,
		BaseFeePerGas: 1e9, GasLimit: 30_000_000, ChainId: 11155111}).Serialize()
	req := VerificationRequest{BlockHeight: w.n, TxIndex: 1, DepositType: "eth",
		RawHex: hex.EncodeToString(raw), MerkleProofHex: hex.EncodeToString(concatBytes(txNodes))}
	if status >= 0 {
		req.ReceiptProof = base64.StdEncoding.EncodeToString(concatBytes(rcNodes))
	}
	return req, rcNodes
}

func faildep1Reserve() string {
	if v := sdk.StateGetObject(constants.GasReserveKey); v != nil {
		return *v
	}
	return ""
}

func TestFAILDEP1_RevertedETHDepositIsNotCredited(t *testing.T) {
	w := newRP7World(t)
	req, _ := faildep1Block(w, 0)
	err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111)
	if err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("a reverted deposit was accepted or refused for another reason: %v (reserve %q)", err, faildep1Reserve())
	}
	if r := faildep1Reserve(); r != "" && r != "0" {
		t.Fatalf("reserve %q after a reverted deposit", r)
	}
}

func TestFAILDEP1_SucceededETHDepositIsCredited(t *testing.T) {
	w := newRP7World(t)
	req, _ := faildep1Block(w, 1)
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err != nil {
		t.Fatalf("a succeeded deposit was refused: %v", err)
	}
	if r := faildep1Reserve(); r != faildep1Value {
		t.Fatalf("reserve %q, want %s", r, faildep1Value)
	}
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err == nil {
		t.Fatal("the same deposit mapped twice")
	}
}

func TestFAILDEP1_ETHDepositNeedsAReceiptProof(t *testing.T) {
	w := newRP7World(t)
	req, _ := faildep1Block(w, -1)
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err == nil || !strings.Contains(err.Error(), "receipt_proof") {
		t.Fatalf("a deposit without a receipt proof: %v", err)
	}
}

// The receipt must be the one at the tx's index in the same block: a success
// receipt from another block does not prove this tx.
func TestFAILDEP1_ReceiptFromAnotherBlockIsRefused(t *testing.T) {
	w := newRP7World(t)
	_, okNodes := faildep1Block(w, 1)
	req, _ := faildep1Block(w, 0)
	req.ReceiptProof = base64.StdEncoding.EncodeToString(concatBytes(okNodes))
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err == nil {
		t.Fatalf("a reverted deposit was credited with another block's success receipt (reserve %q)", faildep1Reserve())
	}
	if r := faildep1Reserve(); r != "" && r != "0" {
		t.Fatalf("reserve %q", r)
	}
}
