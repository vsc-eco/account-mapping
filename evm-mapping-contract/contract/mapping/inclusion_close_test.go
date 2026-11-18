package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"sort"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// CONFIRM-RECEIPT-CAP-1: an ETH withdrawal closes on its inclusion proof when
// confirmSpend comes without a receipt proof, and settleWithdrawalReceipt
// settles it later from that receipt.

// stateDiff lists every key whose presence or value differs between a and b.
func stateDiff(a, b map[string]string) []string {
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		va, oka := a[k]
		vb, okb := b[k]
		if oka != okb || va != vb {
			out = append(out, k+": "+va+" | "+vb)
		}
	}
	sort.Strings(out)
	return out
}

// confirmThenGas is today's path: confirmSpend with the receipt, then (later
// in the block) refundWithdrawalGas with the previous receipt.
func confirmThenGas(t *testing.T, req *ConfirmSpendRequest, prev string) {
	t.Helper()
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatalf("confirmSpend with the receipt: %v", err)
	}
	if req.TxIndex > 0 {
		if err := HandleRefundWithdrawalGas(&RefundWithdrawalGasParams{Nonce: 0, ReceiptProof: prev}); err != nil {
			t.Fatalf("refundWithdrawalGas: %v", err)
		}
	}
}

// closeThenSettle is the new path: confirmSpend without the receipt, then
// settleWithdrawalReceipt with it, then refundWithdrawalGas as above.
func closeThenSettle(t *testing.T, req *ConfirmSpendRequest, prev string) {
	t.Helper()
	receipt := req.ReceiptProof
	req.ReceiptProof = ""
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatalf("confirmSpend without the receipt: %v", err)
	}
	if GetConfirmedNonce() != 1 || GetPendingSpend(0) != nil {
		t.Fatalf("not closed: nonce %d", GetConfirmedNonce())
	}
	if sdk.StateGetObject(inclusionCloseKey(req.BlockHeight, req.TxIndex)) == nil {
		t.Fatal("no inclusion-close record")
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 {
		t.Fatal("nothing may be refunded before the receipt is shown")
	}
	if err := HandleSettleWithdrawalReceipt(&SettleWithdrawalReceiptParams{BlockHeight: req.BlockHeight, TxIndex: req.TxIndex, ReceiptProof: receipt}); err != nil {
		t.Fatalf("settleWithdrawalReceipt: %v", err)
	}
	if sdk.StateGetObject(inclusionCloseKey(req.BlockHeight, req.TxIndex)) != nil {
		t.Fatal("record left after the settlement")
	}
	if req.TxIndex > 0 {
		if err := HandleRefundWithdrawalGas(&RefundWithdrawalGasParams{Nonce: 0, ReceiptProof: prev}); err != nil {
			t.Fatalf("refundWithdrawalGas: %v", err)
		}
	}
}

// Closing on inclusion and settling from the receipt leaves exactly the state
// a confirmSpend with the receipt leaves: paid or reverted, first in its block
// or later.
func TestRCAP1_CloseThenSettleEndsAsTheReceiptConfirm(t *testing.T) {
	for _, c := range []struct {
		name           string
		status, txIdx  uint64
		prevCum, cum   uint64
		wantAliceAbove *big.Int
	}{
		{"paid first in block", 1, 0, 0, 21_000, nil},
		{"paid later in block", 1, 1, 50_000, 50_000 + 207_391, nil},
		{"reverted first in block", 0, 0, 0, 30_000, big.NewInt(1e18)},
		{"reverted later in block", 0, 1, 50_000, 80_000, big.NewInt(1e18)},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newGasWorld(t, constants.NativeAsset)
			req, prev := w.mineAt(150, c.txIdx, c.status, c.prevCum, c.cum)
			confirmThenGas(t, req, prev)
			want := sdk.TestStateCopy()
			wantAlice := GetBalance("hive:alice", "eth")
			sdk.ResetStubState()

			w = newGasWorld(t, constants.NativeAsset)
			req, prev = w.mineAt(150, c.txIdx, c.status, c.prevCum, c.cum)
			closeThenSettle(t, req, prev)
			got := sdk.TestStateCopy()
			defer sdk.ResetStubState()

			if d := stateDiff(want, got); len(d) != 0 {
				t.Fatalf("state differs from the receipt confirm:\n%s", strings.Join(d, "\n"))
			}
			if wantAlice.Sign() <= 0 {
				t.Fatal("the fixture refunds nothing: the comparison proves nothing")
			}
			if c.wantAliceAbove != nil && wantAlice.Cmp(c.wantAliceAbove) <= 0 {
				t.Fatalf("a reverted withdrawal must refund its 1 ETH: alice %s", wantAlice)
			}
		})
	}
}

// A token withdrawal is confirmed from its receipt only (A36): without it
// confirmSpend is refused and changes nothing.
func TestRCAP1_TokenWithdrawalNeedsItsReceipt(t *testing.T) {
	w := newGasWorld(t, "usdc")
	defer sdk.ResetStubState()
	ps := GetPendingSpend(0)
	tokenAddr, _ := crypto.HexToAddress(ps.TokenAddress)
	vault, _ := crypto.HexToAddress(ps.VaultAtQueue)
	to, _ := crypto.HexToAddress(ps.To)
	req, _ := w.mineAt(150, 0, 1, 0, 50_000, transferLog(tokenAddr, vault, to, ps.Amount.Int64()))
	req.ReceiptProof = ""
	before := sdk.TestStateCopy()
	err := HandleConfirmSpend(req, 1)
	if err == nil || !strings.Contains(err.Error(), "receipt_proof required") {
		t.Fatalf("token withdrawal closed without its receipt: %v", err)
	}
	if d := stateDiff(before, sdk.TestStateCopy()); len(d) != 0 {
		t.Fatalf("a refused confirm changed state:\n%s", strings.Join(d, "\n"))
	}
}

// settleWithdrawalReceipt settles only the recorded withdrawal, from its own
// receipt, once; a revert refund waits for the unpause.
func TestRCAP1_SettleRefusals(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	req, _ := w.mineAt(150, 0, 0, 0, 30_000)
	receipt := req.ReceiptProof
	req.ReceiptProof = ""
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	settle := func(h, i uint64, proof string) error {
		return HandleSettleWithdrawalReceipt(&SettleWithdrawalReceiptParams{BlockHeight: h, TxIndex: i, ReceiptProof: proof})
	}
	unchanged := func(what string) {
		t.Helper()
		if GetBalance("hive:alice", "eth").Sign() != 0 || sdk.StateGetObject(inclusionCloseKey(150, 0)) == nil {
			t.Fatalf("%s changed something", what)
		}
	}
	if err := settle(150, 1, receipt); err == nil {
		t.Fatal("settled at an index with no record")
	}
	if err := settle(151, 0, receipt); err == nil {
		t.Fatal("settled at a block with no record")
	}
	// A reverted receipt from another block (a trie of its own, one gas unit
	// apart) is refused.
	_, other := trie([]trieKV{{nibbles(rlp.EncodeUint64(0)), append([]byte{0x02}, rlp.EncodeList(rlp.EncodeUint64(0),
		rlp.EncodeUint64(29_999), rlp.EncodeBytes(make([]byte, 256)), rlp.EncodeList())...)}})
	if err := settle(150, 0, base64.StdEncoding.EncodeToString(other)); err == nil {
		t.Fatal("a foreign receipt proof settled")
	}
	unchanged("a foreign receipt")
	if err := settle(150, 0, ""); err == nil {
		t.Fatal("an empty receipt proof settled")
	}
	unchanged("an empty receipt proof")
	sdk.StateSetObject(constants.PausedKey, "1")
	if err := settle(150, 0, receipt); err != errRefundWhilePaused {
		t.Fatalf("revert refund while paused: %v", err)
	}
	unchanged("a paused revert settlement")
	sdk.StateDeleteObject(constants.PausedKey)
	if err := settle(150, 0, receipt); err != nil {
		t.Fatal(err)
	}
	if GetBalance("hive:alice", "eth").Cmp(big.NewInt(1e18)) <= 0 {
		t.Fatalf("revert not refunded: alice %s", GetBalance("hive:alice", "eth"))
	}
	if err := settle(150, 0, receipt); err == nil {
		t.Fatal("a second settlement must be refused")
	}
}

// The verifier prunes stored headers; the record keeps the receipts root, so a
// revert stays refundable after its header is gone.
func TestRCAP1_SettleOutlivesThePrunedHeader(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	req, _ := w.mineAt(150, 0, 0, 0, 30_000)
	receipt := req.ReceiptProof
	req.ReceiptProof = ""
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	delete(w.headers, 150)
	if err := HandleSettleWithdrawalReceipt(&SettleWithdrawalReceiptParams{BlockHeight: 150, TxIndex: 0, ReceiptProof: receipt}); err != nil {
		t.Fatalf("settlement after the header was pruned: %v", err)
	}
	if GetBalance("hive:alice", "eth").Cmp(big.NewInt(1e18)) <= 0 {
		t.Fatalf("revert not refunded: alice %s", GetBalance("hive:alice", "eth"))
	}
}

// A close on inclusion is not pause-gated, as a paid confirm is not (D8); a
// paid settlement while paused records the gas for later, as confirmSpend does.
func TestRCAP1_PausedCloseAndPaidSettle(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	req, _ := w.mineAt(150, 0, 1, 0, 21_000)
	receipt := req.ReceiptProof
	req.ReceiptProof = ""
	sdk.StateSetObject(constants.PausedKey, "1")
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatalf("close while paused: %v", err)
	}
	if err := HandleSettleWithdrawalReceipt(&SettleWithdrawalReceiptParams{BlockHeight: 150, TxIndex: 0, ReceiptProof: receipt}); err != nil {
		t.Fatalf("paid settlement while paused: %v", err)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 || len(gasSettleList()) != 1 {
		t.Fatalf("paused: want the gas recorded, not refunded (alice %s, open %v)", GetBalance("hive:alice", "eth"), gasSettleList())
	}
}

// A proven roll (D3) refunds as before when confirmSpend comes without a
// receipt: the roll branch runs first and keeps no record.
func TestRCAP1_RollStillRefundsWithoutReceipt(t *testing.T) {
	w := newRollWorld(t)
	defer sdk.ResetStubState()
	w.last = 100 + constants.WithdrawalRollWindow
	w.header(w.last, [32]byte{}, [32]byte{})
	if err := w.roll(); err != nil {
		t.Fatal(err)
	}
	req := w.mine(w.last+1, GetPendingSpend(0).UnsignedTxHex, 1)
	req.ReceiptProof = ""
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatalf("confirmSpend for the mined roll: %v", err)
	}
	if GetBalance("hive:alice", "eth").Cmp(big.NewInt(1e18)) != 0 || GetConfirmedNonce() != 1 {
		t.Fatalf("roll not refunded: alice %s n=%d", GetBalance("hive:alice", "eth"), GetConfirmedNonce())
	}
	if sdk.StateGetObject(inclusionCloseKey(req.BlockHeight, req.TxIndex)) != nil {
		t.Fatal("a roll keeps no inclusion record")
	}
}

// The attack: a recipient that logs 10 KB. The confirm carrying the receipt is
// over the node's 8,192-byte payload cap; without it the withdrawal closes
// well under the cap.
func TestRCAP1_OversizedReceiptClosesUnderTheCap(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	to, _ := crypto.HexToAddress(GetPendingSpend(0).To)
	big := rlp.EncodeList(rlp.EncodeBytes(to[:]), rlp.EncodeList(), rlp.EncodeBytes(make([]byte, 10_000)))
	req, _ := w.mineAt(150, 0, 1, 0, 120_000, big)
	full, _ := json.Marshal(req)
	if len(full) <= 8192 {
		t.Fatalf("fixture: the confirm with the receipt is %d bytes, not over the cap", len(full))
	}
	req.ReceiptProof = ""
	short, _ := json.Marshal(req)
	if len(short) > 8192 {
		t.Fatalf("the confirm without the receipt is %d bytes, over the cap", len(short))
	}
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatalf("close on inclusion: %v", err)
	}
	if GetConfirmedNonce() != 1 || GetPendingSpend(0) != nil {
		t.Fatal("the queue did not move")
	}
	t.Logf("confirm with receipt %d B, without %d B", len(full), len(short))
}

// Only the withdrawal itself closes on inclusion: a vault transaction at its
// nonce with another amount or destination is refused and changes nothing.
func TestRCAP1_OnlyTheWithdrawalItselfCloses(t *testing.T) {
	for _, c := range []struct {
		name, to string
		amount   int64
		want     string
	}{
		{"other amount", "0x00000000000000000000000000000000000000e2", 2e18, "amount does not match"},
		{"other destination", "0x00000000000000000000000000000000000000e3", 1e18, "destination does not match"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newGasWorld(t, constants.NativeAsset)
			defer sdk.ResetStubState()
			ps := GetPendingSpend(0)
			orig := ps.UnsignedTxHex
			to, _ := crypto.HexToAddress(c.to)
			ps.UnsignedTxHex = hex.EncodeToString(BuildETHWithdrawalTxGas(1, 0, gsTip, gsFeeCap, to, big.NewInt(c.amount), gsLimit))
			StorePendingSpend(*ps)
			req, _ := w.mineAt(150, 0, 1, 0, 21_000)
			ps.UnsignedTxHex = orig
			StorePendingSpend(*ps)
			req.ReceiptProof = ""
			before := sdk.TestStateCopy()
			err := HandleConfirmSpend(req, 1)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
			if d := stateDiff(before, sdk.TestStateCopy()); len(d) != 0 {
				t.Fatalf("a refused confirm changed state:\n%s", strings.Join(d, "\n"))
			}
		})
	}
}

func rcapVaultPub(t *testing.T) CompressedPubKey {
	var pub CompressedPubKey
	copy(pub[:], secp256k1.PrivKeyFromBytes(mustHex(t, rollVaultPriv)).PubKey().SerializeCompressed())
	return pub
}

// rcapSuperseded: the withdrawal's generation 0 is superseded and draining,
// still holding the nonces; a fee bump drew 0.003 ETH from the reserve; its
// refunds go to hive:dave.
func rcapSuperseded(t *testing.T, swept bool) {
	SaveVaultState(VaultRegistry{
		{Generation: 0, Primary: rcapVaultPub(t), Status: VaultStatusDraining, Predecessor: 0},
		{Generation: 1, Primary: pubOf(t, testPub2), Status: VaultStatusActive, Predecessor: 0},
	}, 2, 1)
	sdk.StateSetObject(constants.WithdrawNonceHolderKey, "0")
	setVaultBook(0, "eth", big.NewInt(2e18))
	if swept {
		sdk.StateSetObject(constants.ETHSweptPrefix+"0", "120")
	}
	ps := GetPendingSpend(0)
	ps.RefundTo = "hive:dave"
	ps.GasCost = new(big.Int).Add(ps.GasCost, big.NewInt(3e15))
	StorePendingSpend(*ps)
	addSpendReserveExtra(0, big.NewInt(3e15))
}

var rcapCases = []struct {
	name                 string
	status, idx, pc, cum uint64
}{
	{"paid first", 1, 0, 0, 21_000}, {"paid later", 1, 1, 50_000, 71_000},
	{"reverted first", 0, 0, 0, 30_000}, {"reverted later", 0, 1, 50_000, 80_000},
}

// The equivalence above, with generation books: a superseded generation
// (swept or not), a reserve-funded fee bump and a refund account.
func TestRCAP1_EquivalenceOnASupersededGeneration(t *testing.T) {
	for _, swept := range []bool{false, true} {
		for _, c := range rcapCases {
			w := newGasWorld(t, constants.NativeAsset)
			rcapSuperseded(t, swept)
			req, prev := w.mineAt(150, c.idx, c.status, c.pc, c.cum)
			confirmThenGas(t, req, prev)
			want := sdk.TestStateCopy()
			sdk.ResetStubState()

			w = newGasWorld(t, constants.NativeAsset)
			rcapSuperseded(t, swept)
			req, prev = w.mineAt(150, c.idx, c.status, c.pc, c.cum)
			closeThenSettle(t, req, prev)
			got := sdk.TestStateCopy()
			sdk.ResetStubState()
			if d := stateDiff(want, got); len(d) != 0 {
				t.Errorf("swept=%v %s: differs:\n%s", swept, c.name, strings.Join(d, "\n"))
			}
		}
	}
}

// A rotation between the close and the settlement leaves the books the
// receipt confirm (before the rotation) leaves.
func TestRCAP1_EquivalenceAcrossARotation(t *testing.T) {
	setup := func() *rollWorld {
		w := newGasWorld(t, constants.NativeAsset)
		SaveVaultState(VaultRegistry{{Generation: 0, Primary: rcapVaultPub(t), Status: VaultStatusActive, Predecessor: 0}}, 1, 0)
		sdk.StateSetObject(constants.QueuedDebitExactKey, "1")
		return w
	}
	rotate := func() {
		if _, _, err := MintNextGeneration(200); err != nil {
			t.Fatal(err)
		}
		sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,1")
		if _, _, _, err := ActivatePendingGeneration(200); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range rcapCases {
		w := setup()
		req, prev := w.mineAt(150, c.idx, c.status, c.pc, c.cum)
		confirmThenGas(t, req, prev)
		rotate()
		want := sdk.TestStateCopy()
		sdk.ResetStubState()

		w = setup()
		req, prev = w.mineAt(150, c.idx, c.status, c.pc, c.cum)
		receipt := req.ReceiptProof
		req.ReceiptProof = ""
		if err := HandleConfirmSpend(req, 1); err != nil {
			t.Fatal(err)
		}
		rotate()
		if err := HandleSettleWithdrawalReceipt(&SettleWithdrawalReceiptParams{BlockHeight: 150, TxIndex: c.idx, ReceiptProof: receipt}); err != nil {
			t.Fatal(err)
		}
		if c.idx > 0 {
			if err := HandleRefundWithdrawalGas(&RefundWithdrawalGasParams{Nonce: 0, ReceiptProof: prev}); err != nil {
				t.Fatal(err)
			}
		}
		got := sdk.TestStateCopy()
		sdk.ResetStubState()
		if d := stateDiff(want, got); len(d) != 0 {
			t.Errorf("%s: differs:\n%s", c.name, strings.Join(d, "\n"))
		}
	}
}

// A04: a pause may be for a suspect verifier. A close while paused keeps no
// receipts root, so a header forged then cannot refund once it is fixed: the
// settlement verifies against the stored (fixed) header.
func TestRCAP1_PausedCloseKeepsNoRoot(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	real, _ := w.mineAt(150, 0, 1, 0, 21_000)
	realHdr := w.headers[150]
	forged, _ := w.mineAt(150, 0, 0, 0, 21_000) // the suspect verifier's header: the withdrawal reverted
	forgedReceipt := forged.ReceiptProof
	forged.ReceiptProof = ""
	sdk.StateSetObject(constants.PausedKey, "1")
	if err := HandleConfirmSpend(forged, 1); err != nil {
		t.Fatalf("close while paused: %v", err)
	}
	w.headers[150] = realHdr // the incident is fixed
	sdk.StateDeleteObject(constants.PausedKey)
	if err := HandleSettleWithdrawalReceipt(&SettleWithdrawalReceiptParams{BlockHeight: 150, TxIndex: 0, ReceiptProof: forgedReceipt}); err == nil {
		t.Fatal("a receipt of the forged header refunded after the fix")
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 {
		t.Fatalf("refunded: alice %s", GetBalance("hive:alice", "eth"))
	}
	if err := HandleSettleWithdrawalReceipt(&SettleWithdrawalReceiptParams{BlockHeight: 150, TxIndex: 0, ReceiptProof: real.ReceiptProof}); err != nil {
		t.Fatalf("settlement with the real receipt: %v", err)
	}
	wantBig(t, "alice (gas refund only)", GetBalance("hive:alice", "eth"), gsUnused(21_000))

	// With the header gone, a close while paused waits for it.
	w = newGasWorld(t, constants.NativeAsset)
	req, _ := w.mineAt(150, 0, 0, 0, 30_000)
	receipt := req.ReceiptProof
	req.ReceiptProof = ""
	sdk.StateSetObject(constants.PausedKey, "1")
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	sdk.StateDeleteObject(constants.PausedKey)
	hdr := w.headers[150]
	delete(w.headers, 150)
	if err := HandleSettleWithdrawalReceipt(&SettleWithdrawalReceiptParams{BlockHeight: 150, TxIndex: 0, ReceiptProof: receipt}); err != ErrBlockNotFound {
		t.Fatalf("paused close without its header: %v, want ErrBlockNotFound", err)
	}
	w.headers[150] = hdr
	if err := HandleSettleWithdrawalReceipt(&SettleWithdrawalReceiptParams{BlockHeight: 150, TxIndex: 0, ReceiptProof: receipt}); err != nil {
		t.Fatal(err)
	}
}

// A stored header that differs from the root the close kept refuses the
// settlement: the record waits for the verifier to be put right.
func TestRCAP1_ChangedHeaderRefusesTheSettlement(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	req, _ := w.mineAt(150, 0, 1, 0, 21_000)
	realHdr := w.headers[150]
	other, _ := w.mineAt(150, 0, 0, 0, 21_000)
	otherHdr := w.headers[150]
	w.headers[150] = realHdr
	receipt := req.ReceiptProof
	req.ReceiptProof = ""
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	w.headers[150] = otherHdr // header 150 now has another receipts root
	for _, proof := range []string{receipt, other.ReceiptProof} {
		err := HandleSettleWithdrawalReceipt(&SettleWithdrawalReceiptParams{BlockHeight: 150, TxIndex: 0, ReceiptProof: proof})
		if err == nil || !strings.Contains(err.Error(), "differs") {
			t.Fatalf("settled against a changed header: %v", err)
		}
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 || sdk.StateGetObject(inclusionCloseKey(150, 0)) == nil {
		t.Fatal("a refused settlement changed something")
	}
}

// The close lets the withdrawal's generation stop counting as funded, so it
// can be purged before a revert is settled. A purged generation never
// ETH-swept holds that value at its retired address: the refund is refused
// (crediting it would back a balance with nothing). Swept, the sweep carried
// it and the refund goes ahead.
func TestRCAP1_NoRefundIntoAPurgedUnsweptGeneration(t *testing.T) {
	for _, swept := range []bool{false, true} {
		w := newGasWorld(t, constants.NativeAsset)
		SaveVaultState(VaultRegistry{
			{Generation: 0, Primary: rcapVaultPub(t), Status: VaultStatusDraining, Predecessor: 0},
			{Generation: 1, Primary: pubOf(t, testPub2), Status: VaultStatusActive, Predecessor: 0},
		}, 2, 1)
		sdk.StateSetObject(constants.WithdrawNonceHolderKey, "0")
		req, _ := w.mineAt(150, 0, 0, 0, 30_000)
		receipt := req.ReceiptProof
		req.ReceiptProof = ""
		if err := HandleConfirmSpend(req, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := ReconcileRetiringVaults(1); err != nil {
			t.Fatal(err)
		}
		w.last = 150 + 216_000 + 7_200 + 1
		if _, err := ReconcileRetiringVaults(1); err != nil {
			t.Fatal(err)
		}
		if g, purged := purgedSpendGen(&PendingSpend{VaultAtQueue: GetPendingSpendVault(t, w)}); !purged || g != 0 {
			t.Fatalf("fixture: generation 0 not purged (%d %v)", g, purged)
		}
		if swept {
			sdk.StateSetObject(constants.ETHSweptPrefix+"0", "151")
		}
		active := GetSupply("eth").Active
		err := HandleSettleWithdrawalReceipt(&SettleWithdrawalReceiptParams{BlockHeight: 150, TxIndex: 0, ReceiptProof: receipt})
		if !swept {
			if err == nil || !strings.Contains(err.Error(), "purged") {
				t.Fatalf("refund into a purged unswept generation: %v", err)
			}
			if GetBalance("hive:alice", "eth").Sign() != 0 || GetSupply("eth").Active.Cmp(active) != 0 || sdk.StateGetObject(inclusionCloseKey(150, 0)) == nil {
				t.Fatal("a refused settlement changed something")
			}
		} else if err != nil || GetBalance("hive:alice", "eth").Cmp(big.NewInt(1e18)) <= 0 {
			t.Fatalf("swept generation: settle %v, alice %s", err, GetBalance("hive:alice", "eth"))
		}
		sdk.ResetStubState()
	}
}

// A paid withdrawal of a generation purged unswept settles without its gas:
// the unused gas is at the retired address too.
func TestRCAP1_NoGasRefundFromAPurgedUnsweptGeneration(t *testing.T) {
	w := newGasWorld(t, constants.NativeAsset)
	defer sdk.ResetStubState()
	SaveVaultState(VaultRegistry{
		{Generation: 0, Primary: rcapVaultPub(t), Status: VaultStatusDraining, Predecessor: 0},
		{Generation: 1, Primary: pubOf(t, testPub2), Status: VaultStatusActive, Predecessor: 0},
	}, 2, 1)
	sdk.StateSetObject(constants.WithdrawNonceHolderKey, "0")
	req, _ := w.mineAt(150, 0, 1, 0, 21_000)
	receipt := req.ReceiptProof
	req.ReceiptProof = ""
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileRetiringVaults(1); err != nil {
		t.Fatal(err)
	}
	w.last = 150 + 216_000 + 7_200 + 1
	if _, err := ReconcileRetiringVaults(1); err != nil {
		t.Fatal(err)
	}
	reserve := getGasReserve()
	if err := HandleSettleWithdrawalReceipt(&SettleWithdrawalReceiptParams{BlockHeight: 150, TxIndex: 0, ReceiptProof: receipt}); err != nil {
		t.Fatal(err)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 || getGasReserve().Cmp(reserve) != 0 {
		t.Fatalf("gas credited from a purged unswept generation: alice %s, reserve %s -> %s", GetBalance("hive:alice", "eth"), reserve, getGasReserve())
	}
	if sdk.StateGetObject(inclusionCloseKey(150, 0)) != nil {
		t.Fatal("record left")
	}
}

// GetPendingSpendVault is the vault address the fixture's withdrawal names.
func GetPendingSpendVault(t *testing.T, w *rollWorld) string {
	t.Helper()
	return senderAddrFromPriv(t, rollVaultPriv)
}
