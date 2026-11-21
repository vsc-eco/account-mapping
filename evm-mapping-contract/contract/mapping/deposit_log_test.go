package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// DEPOSIT-LOG-1: every credited deposit writes one
// "map|t=<to>|f=<0x sender>|a=<amount>|as=<asset>|bn=<L1 block>|ti=<tx index>"
// line (the BTC bridge's "map|t=|f=|a=" plus asset and place), so an indexer
// can list a deposit under the account it was credited to.

// The deposit lines written since the log had `mark` entries (resetting the
// test state would also drop the world's headers and registry).
func depositLogs(mark int) []string {
	var out []string
	logs := sdk.TestLogs()
	if mark > len(logs) {
		mark = len(logs)
	}
	for _, l := range logs[mark:] {
		if strings.HasPrefix(l, "map|") {
			out = append(out, l)
		}
	}
	return out
}

func wantOneDepositLog(t *testing.T, mark int, want string) {
	t.Helper()
	got := depositLogs(mark)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("deposit log lines %q, want exactly [%q]", got, want)
	}
}

// A plain ETH transfer to the vault; calldata may carry instructions.
func mineETHTransfer(t *testing.T, w *rp7World, value *big.Int, data []byte) VerificationRequest {
	t.Helper()
	raw := mapceiTx(t, value, data)
	txRoot, txNodes := buildSingleLeafMPT(raw)
	receipt := append([]byte{0x02}, rlp.EncodeList(rlp.EncodeUint64(1), rlp.EncodeUint64(21_000),
		rlp.EncodeBytes(make([]byte, 256)), rlp.EncodeList())...)
	rcRoot, rcNodes := buildSingleLeafMPT(receipt)
	w.n++
	w.headers[w.n] = (&blocklist.EthBlockHeader{BlockNumber: w.n, TransactionsRoot: txRoot, ReceiptsRoot: rcRoot,
		BaseFeePerGas: 1e9, GasLimit: 30_000_000, ChainId: 11155111}).Serialize()
	return VerificationRequest{BlockHeight: w.n, TxIndex: 1, DepositType: "eth",
		RawHex: hex.EncodeToString(raw), MerkleProofHex: hex.EncodeToString(concatBytes(txNodes)),
		ReceiptProof: base64.StdEncoding.EncodeToString(concatBytes(rcNodes))}
}

func mapceiSender(t *testing.T) [20]byte {
	t.Helper()
	priv := secp256k1.PrivKeyFromBytes(bytesOf(t, "4646464646464646464646464646464646464646464646464646464646464646"))
	sender, err := crypto.PubkeyAddress(priv.PubKey().SerializeUncompressed())
	if err != nil {
		t.Fatal(err)
	}
	return sender
}

func TestDEPOSITLOG1_PlainETHToItsSender(t *testing.T) {
	w := newRP7World(t)
	mark := len(sdk.TestLogs())
	req := mineETHTransfer(t, w, big.NewInt(1e18), nil)
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err != nil {
		t.Fatal(err)
	}
	s := mapceiSender(t)
	wantOneDepositLog(t, mark, "map|t="+crypto.AddressToDID(s)+"|f="+crypto.AddressToHex(s)+
		"|a=1000000000000000000|as=eth|bn="+strconv.FormatUint(req.BlockHeight, 10)+"|ti=1")
}

func TestDEPOSITLOG1_PlainETHToADepositToInstruction(t *testing.T) {
	w := newRP7World(t)
	mark := len(sdk.TestLogs())
	req := mineETHTransfer(t, w, big.NewInt(2e16), []byte("deposit_to=hive:bob"))
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err != nil {
		t.Fatal(err)
	}
	if GetBalance("hive:bob", "eth").Cmp(big.NewInt(2e16)) != 0 {
		t.Fatal("hive:bob was not credited")
	}
	wantOneDepositLog(t, mark, "map|t=hive:bob|f="+crypto.AddressToHex(mapceiSender(t))+
		"|a=20000000000000000|as=eth|bn="+strconv.FormatUint(req.BlockHeight, 10)+"|ti=1")
}

func TestDEPOSITLOG1_MagiDepositETHAndToken(t *testing.T) {
	w := newRP7World(t)
	dc := DepositContractAddress(rp7Vault)
	mark := len(sdk.TestLogs())
	n, _, nodes := w.mine(1, depositLog(dc, rp7User, [20]byte{}, big.NewInt(1e18), "hive:bob"))
	if err := mapContract(n, nodes, 0); err != nil {
		t.Fatal(err)
	}
	wantOneDepositLog(t, mark, "map|t=hive:bob|f="+crypto.AddressToHex(rp7User)+
		"|a=1000000000000000000|as=eth|bn="+strconv.FormatUint(n, 10)+"|ti=1")

	mark = len(sdk.TestLogs())
	n, _, nodes = w.mine(1, transferLog(rp7USDC, rp7User, rp7Vault, 3_000_000),
		depositLog(dc, rp7User, rp7USDC, big.NewInt(3_000_000), "hive:bob"))
	if err := mapContract(n, nodes, 1); err != nil {
		t.Fatal(err)
	}
	// The asset is written lower-case whatever the registry's symbol case.
	wantOneDepositLog(t, mark, "map|t=hive:bob|f="+crypto.AddressToHex(rp7User)+
		"|a=3000000|as=usdc|bn="+strconv.FormatUint(n, 10)+"|ti=1")
}

func TestDEPOSITLOG1_PlainERC20ToItsSender(t *testing.T) {
	w := newRP7World(t)
	wallet := [20]byte{0: 0x5a, 19: 0xfe}
	mark := len(sdk.TestLogs())
	n, receipt, nodes := w.mine(1, transferLog(rp7USDC, wallet, rp7Vault, 5_000_000))
	if err := mapERC20(n, receipt, nodes, 0); err != nil {
		t.Fatal(err)
	}
	wantOneDepositLog(t, mark, "map|t="+crypto.AddressToDID(wallet)+"|f="+crypto.AddressToHex(wallet)+
		"|a=5000000|as=usdc|bn="+strconv.FormatUint(n, 10)+"|ti=1")
}

func TestDEPOSITLOG1_NoLineWhenNothingIsCredited(t *testing.T) {
	// A gas-reserve top-up credits nobody.
	w := newRP7World(t)
	mark := len(sdk.TestLogs())
	req := mineETHTransfer(t, w, big.NewInt(5e16), []byte("to_reserve=1"))
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err != nil {
		t.Fatal(err)
	}
	if got := depositLogs(mark); len(got) != 0 {
		t.Fatalf("a reserve top-up wrote %q", got)
	}
	// A refused (repeat) map writes nothing either.
	dc := DepositContractAddress(rp7Vault)
	n, _, nodes := w.mine(1, depositLog(dc, rp7User, [20]byte{}, big.NewInt(1e18), "hive:bob"))
	if err := mapContract(n, nodes, 0); err != nil {
		t.Fatal(err)
	}
	mark = len(sdk.TestLogs())
	if err := mapContract(n, nodes, 0); err == nil {
		t.Fatal("a repeat map was accepted")
	}
	if got := depositLogs(mark); len(got) != 0 {
		t.Fatalf("a refused repeat map wrote %q", got)
	}
}

// The line names the identity as the balance is keyed (CanonicalIdentity):
// a lower-case did:pkh:eip155 recipient is credited, and so listed, under
// its checksummed form.
func TestDEPOSITLOG1_LogsTheCanonicalIdentity(t *testing.T) {
	w := newRP7World(t)
	dc := DepositContractAddress(rp7Vault)
	lower := "did:pkh:eip155:1:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
	checksummed := "did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
	mark := len(sdk.TestLogs())
	n, _, nodes := w.mine(1, depositLog(dc, rp7User, [20]byte{}, big.NewInt(1e18), lower))
	if err := mapContract(n, nodes, 0); err != nil {
		t.Fatal(err)
	}
	if GetBalance(checksummed, "eth").Cmp(big.NewInt(1e18)) != 0 {
		t.Fatal("the checksummed identity was not credited")
	}
	wantOneDepositLog(t, mark, "map|t="+checksummed+"|f="+crypto.AddressToHex(rp7User)+
		"|a=1000000000000000000|as=eth|bn="+strconv.FormatUint(n, 10)+"|ti=1")
}

func TestDEPOSITLOG1_AFieldCannotBreakTheLine(t *testing.T) {
	if got := logField("system:x|f=0xevil|a=999\nmap|t=y"); strings.ContainsAny(got, "|\n\r") {
		t.Fatalf("logField left a delimiter: %q", got)
	}
}
