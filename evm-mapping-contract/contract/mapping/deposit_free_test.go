package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// DEPOSIT-FREE-1 (owner 11-20: "deposits free like btc"): a deposit is
// credited in full on every path, with a proving fee set: no gas-reserve
// share and no proving fee. The BTC bridge charges nothing on deposits (its
// fee reserve is funded by top-ups) and THORChain charges only outbound.
// The MagiDeposit and ERC-20 paths are in prooffee_test.go and rp7_test.go;
// this is the plain ETH transfer to the vault (handlers.go, "eth").
func TestDEPOSITFREE1_PlainETHDepositIsCreditedInFull(t *testing.T) {
	w := newRP7World(t)
	SetProofFee("eth", big.NewInt(1e14))
	raw := mapceiTx(t, big.NewInt(1e18), nil)
	txRoot, txNodes := buildSingleLeafMPT(raw)
	receipt := append([]byte{0x02}, rlp.EncodeList(rlp.EncodeUint64(1), rlp.EncodeUint64(21_000),
		rlp.EncodeBytes(make([]byte, 256)), rlp.EncodeList())...)
	rcRoot, rcNodes := buildSingleLeafMPT(receipt)
	w.n++
	w.headers[w.n] = (&blocklist.EthBlockHeader{BlockNumber: w.n, TransactionsRoot: txRoot, ReceiptsRoot: rcRoot,
		BaseFeePerGas: 1e9, GasLimit: 30_000_000, ChainId: 11155111}).Serialize()
	req := VerificationRequest{BlockHeight: w.n, TxIndex: 1, DepositType: "eth",
		RawHex: hex.EncodeToString(raw), MerkleProofHex: hex.EncodeToString(concatBytes(txNodes)),
		ReceiptProof: base64.StdEncoding.EncodeToString(concatBytes(rcNodes))}
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err != nil {
		t.Fatalf("the deposit: %v", err)
	}
	priv := secp256k1.PrivKeyFromBytes(bytesOf(t, "4646464646464646464646464646464646464646464646464646464646464646"))
	sender, err := crypto.PubkeyAddress(priv.PubKey().SerializeUncompressed())
	if err != nil {
		t.Fatal(err)
	}
	depositor := crypto.AddressToDID(sender)
	if got := GetBalance(depositor, "eth"); got.Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("depositor holds %s, want the whole 1 ETH", got)
	}
	if feeBalance("eth").Sign() != 0 {
		t.Fatalf("fee account %s after a deposit, want nothing", feeBalance("eth"))
	}
	if getGasReserve().Sign() != 0 {
		t.Fatalf("reserve %s after a deposit, want 0", getGasReserve())
	}
	if s := GetSupply("eth"); s.User.Cmp(big.NewInt(1e18)) != 0 || s.Active.Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("supply %+v, want 1 ETH user and active", s)
	}
	if got := getRefundable(depositor, "eth"); got.Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("refundable %s, want the whole 1 ETH", got)
	}
	ethInvariant(t, "after a free deposit")
}
