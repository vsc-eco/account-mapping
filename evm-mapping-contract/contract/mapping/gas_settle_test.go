package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// EVM-FEE-1 fixture on the D3 world: one ETH withdrawal of 1 ETH (nonce 0),
// signed with a 250,000 gas limit at fee cap 40 gwei / tip 2 gwei, prepaid
// 250,000 x 40 gwei = 0.01 ETH by hive:alice. Mined in a block whose base fee is
// 1 gwei, so the effective price is 3 gwei.
const (
	gsLimit  = 250_000
	gsFeeCap = 40_000_000_000
	gsTip    = 2_000_000_000
	gsPrice  = 3_000_000_000 // 1 gwei base (rollWorld headers) + 2 gwei tip
)

var gsPrepaid = new(big.Int).Mul(big.NewInt(gsLimit), big.NewInt(gsFeeCap)) // 0.01 ETH

func newGasWorld(t *testing.T, asset string) *rollWorld {
	t.Helper()
	w := newRollWorld(t)
	to, _ := crypto.HexToAddress("0x00000000000000000000000000000000000000e2")
	var unsigned []byte
	ps := GetPendingSpend(0)
	ps.GasCost = new(big.Int).Set(gsPrepaid)
	if asset == constants.NativeAsset {
		unsigned = BuildETHWithdrawalTxGas(1, 0, gsTip, gsFeeCap, to, big.NewInt(1e18), gsLimit)
	} else {
		token, _ := crypto.HexToAddress("0x00000000000000000000000000000000000000c0")
		unsigned = BuildERC20WithdrawalTxGas(1, 0, gsTip, gsFeeCap, token, to, big.NewInt(1e18), gsLimit)
		ps.Asset, ps.TokenAddress = asset, "0x00000000000000000000000000000000000000c0"
	}
	ps.UnsignedTxHex = hex.EncodeToString(unsigned)
	StorePendingSpend(*ps)
	// Custody and supply as if the withdrawal had been requested: the vault
	// still holds the prepaid fee; the books took it out at request.
	SetSupply("eth", Supply{Active: big.NewInt(5e18), User: big.NewInt(5e18), Fee: new(big.Int)})
	sdk.StateSetObject(constants.GasReserveKey, "100000000000000000")
	return w
}

// mineAt plants the withdrawal at txIndex of block n with the given cumulative
// gas, after a first transaction that used prevGas (txIndex 1), and returns
// the confirmSpend request plus a proof of the receipt before it.
func (w *rollWorld) mineAt(n uint64, txIndex uint64, status, prevCum, cum uint64, logs ...[]byte) (*ConfirmSpendRequest, string) {
	w.t.Helper()
	ps := GetPendingSpend(0)
	unsigned, _ := hex.DecodeString(ps.UnsignedTxHex)
	priv := secp256k1.PrivKeyFromBytes(mustHex(w.t, rollVaultPriv))
	sig := dcrecdsa.SignCompact(priv, ComputeSighash(unsigned), false)
	signed, err := AttachSignature(unsigned, (sig[0]-27)&3, sig[1:33], sig[33:65])
	if err != nil {
		w.t.Fatal(err)
	}
	receipt := func(st, c uint64, lg ...[]byte) []byte {
		return append([]byte{0x02}, rlp.EncodeList(rlp.EncodeUint64(st), rlp.EncodeUint64(c), rlp.EncodeBytes(make([]byte, 256)), rlp.EncodeList(lg...))...)
	}
	key := func(i uint64) []byte { return nibbles(rlp.EncodeUint64(i)) }
	txRoot, txNodes := trie([]trieKV{{key(txIndex), signed}})
	rkv := []trieKV{{key(txIndex), receipt(status, cum, logs...)}}
	if txIndex > 0 {
		rkv = append(rkv, trieKV{key(txIndex - 1), receipt(1, prevCum)})
	}
	rcRoot, rcNodes := trie(rkv)
	w.header(n, txRoot, rcRoot)
	w.last = n
	req := &ConfirmSpendRequest{IntentNonce: 0, IntentTo: ps.To, IntentAmount: ps.Amount.String(),
		IntentAsset: ps.Asset, BlockHeight: n, TxIndex: txIndex,
		TxProof:      base64.StdEncoding.EncodeToString(txNodes),
		ReceiptProof: base64.StdEncoding.EncodeToString(rcNodes)}
	return req, base64.StdEncoding.EncodeToString(rcNodes)
}

func wantBig(t *testing.T, what string, got *big.Int, want *big.Int) {
	t.Helper()
	if got.Cmp(want) != 0 {
		t.Fatalf("%s = %s, want %s", what, got, want)
	}
}

func gsUnused(gasUsed int64) *big.Int {
	return new(big.Int).Sub(gsPrepaid, new(big.Int).Mul(big.NewInt(gasUsed), big.NewInt(gsPrice)))
}

// The block's first transaction: settled at confirmSpend, the user gets back
// everything above 21,000 x 3 gwei.
func TestEVMFee1_FirstTxInBlockRefundsTheUserAtConfirm(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	req, _ := w.mineAt(150, 0, 1, 0, 21_000)
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	want := gsUnused(21_000) // 0.01 - 0.000063 ETH
	wantBig(t, "alice refund", GetBalance("hive:alice", "eth"), want)
	s := GetSupply("eth")
	wantBig(t, "Active", s.Active, new(big.Int).Add(big.NewInt(5e18), want))
	wantBig(t, "User", s.User, new(big.Int).Add(big.NewInt(5e18), want))
	wantBig(t, "reserve", getGasReserve(), big.NewInt(1e17))
	if sdk.StateGetObject(gasSettleKey(0)) != nil || len(gasSettleList()) != 0 {
		t.Fatal("index 0 must settle at once, no record")
	}
	if sdk.StateGetObject(gasReserveExtraKey(0)) != nil || sdk.StateGetObject(gasTokenFeeKey(0)) != nil {
		t.Fatal("gx-/gt- must go with the pending spend")
	}
}

// Later in the block: confirmSpend records it; refundWithdrawalGas with the
// previous receipt settles gas used = cumulative difference, exactly once.
func TestEVMFee1_LaterTxSettlesWithThePreviousReceipt(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	req, rc := w.mineAt(150, 1, 1, 50_000, 50_000+207_391)
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 {
		t.Fatal("nothing refunded before the settlement")
	}
	if l := gasSettleList(); len(l) != 1 || l[0] != "0" {
		t.Fatalf("open settlements %v, want [0]", l)
	}
	if err := HandleRefundWithdrawalGas(&RefundWithdrawalGasParams{Nonce: 0, ReceiptProof: rc}); err != nil {
		t.Fatal(err)
	}
	wantBig(t, "alice refund", GetBalance("hive:alice", "eth"), gsUnused(207_391))
	if sdk.StateGetObject(gasSettleKey(0)) != nil || len(gasSettleList()) != 0 {
		t.Fatal("record not cleared")
	}
	if err := HandleRefundWithdrawalGas(&RefundWithdrawalGasParams{Nonce: 0, ReceiptProof: rc}); err == nil {
		t.Fatal("a second settlement must be refused")
	}
}

// A proof that is not of the previous receipt in that block is refused and
// settles nothing.
func TestEVMFee1_WrongPreviousReceiptIsRefused(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	req, _ := w.mineAt(150, 1, 1, 50_000, 71_000)
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	// A proof from another block (only index 0 of a different trie).
	_, other := trie([]trieKV{{nibbles(rlp.EncodeUint64(0)), append([]byte{0x02}, rlp.EncodeList(rlp.EncodeUint64(1), rlp.EncodeUint64(70_999), rlp.EncodeBytes(make([]byte, 256)), rlp.EncodeList())...)}})
	if err := HandleRefundWithdrawalGas(&RefundWithdrawalGasParams{Nonce: 0, ReceiptProof: base64.StdEncoding.EncodeToString(other)}); err == nil {
		t.Fatal("a foreign receipt proof must be refused")
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 || len(gasSettleList()) != 1 {
		t.Fatal("a refused settlement must change nothing")
	}
}

// A fee bump raised the prepaid gas from the reserve: the user pays the real
// cost up to their own prepaid fee, the reserve gets the rest of the unused.
func TestEVMFee1_FeeBumpSplitsTheRefundUserFirst(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	ps := GetPendingSpend(0)
	extra := big.NewInt(4_000_000_000_000_000) // 0.004 ETH from the reserve
	ps.GasCost = new(big.Int).Add(gsPrepaid, extra)
	StorePendingSpend(*ps)
	addSpendReserveExtra(0, extra) // as chargeResignGas books it
	req, _ := w.mineAt(150, 0, 1, 0, 21_000)
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	wantBig(t, "alice refund", GetBalance("hive:alice", "eth"), gsUnused(21_000))
	wantBig(t, "reserve", getGasReserve(), new(big.Int).Add(big.NewInt(1e17), extra))
}

// ERC-20: the reserve fronted the gas and gets the unused back; the token gas
// fee the user paid comes back pro rata from its recipient.
func TestEVMFee1_TokenWithdrawalRefundsTheReserveAndTheTokenFee(t *testing.T) {
	w := newGasWorld(t, "usdc")
	defer sdk.ResetStubState()
	ps := GetPendingSpend(0)
	setSpendTokenGasFee(0, big.NewInt(1_000_000)) // 1 USDC paid for gsPrepaid of gas, as issueQueued books it
	IncBalance(constants.TokenGasFeeRecipient, "usdc", big.NewInt(1_000_000))
	tokenAddr, _ := crypto.HexToAddress(ps.TokenAddress)
	vault, _ := crypto.HexToAddress(ps.VaultAtQueue)
	to, _ := crypto.HexToAddress(ps.To)
	logs := transferLog(tokenAddr, vault, to, ps.Amount.Int64())
	req, _ := w.mineAt(150, 0, 1, 0, 50_000, logs)
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	unused := gsUnused(50_000)
	wantBig(t, "reserve", getGasReserve(), new(big.Int).Add(big.NewInt(1e17), unused))
	wantTok := new(big.Int).Div(new(big.Int).Mul(big.NewInt(1_000_000), unused), gsPrepaid)
	wantBig(t, "alice usdc refund", GetBalance("hive:alice", "usdc"), wantTok)
	if GetBalance("hive:alice", "eth").Sign() != 0 {
		t.Fatal("a token withdrawal's gas was not the user's ETH")
	}
}

// Paused: the withdrawal still settles, the refund waits for the unpause (A04).
func TestEVMFee1_PausedRecordsThenRefundsAfterUnpause(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	sdk.StateSetObject(constants.PausedKey, "1")
	req, _ := w.mineAt(150, 0, 1, 0, 21_000)
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 || len(gasSettleList()) != 1 {
		t.Fatal("paused: no refund yet, one record")
	}
	if err := HandleRefundWithdrawalGas(&RefundWithdrawalGasParams{Nonce: 0}); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatalf("refund while paused: %v", err)
	}
	sdk.StateDeleteObject(constants.PausedKey)
	if err := HandleRefundWithdrawalGas(&RefundWithdrawalGasParams{Nonce: 0}); err != nil {
		t.Fatal(err)
	}
	wantBig(t, "alice refund", GetBalance("hive:alice", "eth"), gsUnused(21_000))
}

// A reverted ETH withdrawal: the value comes back as before, and the unused
// gas too (the revert burned only what it used).
func TestEVMFee1_RevertedWithdrawalAlsoRefundsUnusedGas(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	req, _ := w.mineAt(150, 0, 0, 0, 30_000)
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	wantBig(t, "alice balance", GetBalance("hive:alice", "eth"), new(big.Int).Add(big.NewInt(1e18), gsUnused(30_000)))
}

// The effective price: base + tip, never above the fee cap.
func TestEVMFee1_EffectivePrice(t *testing.T) {
	for _, c := range []struct{ tip, cap, base, want uint64 }{
		{2, 40, 1, 3}, {2, 40, 39, 40}, {2, 40, 50, 40}, {0, 0, 5, 0}, {7, 7, 0, 7},
	} {
		if got := effectiveGasPrice(&ParsedTx{GasTipCap: c.tip, GasFeeCap: c.cap}, c.base); got != c.want {
			t.Fatalf("tip %d cap %d base %d: %d, want %d", c.tip, c.cap, c.base, got, c.want)
		}
	}
}
