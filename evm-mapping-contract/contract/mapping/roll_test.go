package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strconv"
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

// D3 fixture: one ETH withdrawal (nonce 0, 1 ETH to 0x..e2) queued at L1 block
// 100 from the vault key below, a verifier holding the headers in `headers`,
// and the newest verified height in *last.
const rollVaultPriv = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

type rollWorld struct {
	t       *testing.T
	vault   [20]byte
	last    uint64
	headers map[uint64]string
	l2      uint64
}

func newRollWorld(t *testing.T) *rollWorld {
	t.Helper()
	sdk.ResetStubState()
	w := &rollWorld{t: t, last: 100, headers: map[uint64]string{}, l2: 1000}
	vaultHex := senderAddrFromPriv(t, rollVaultPriv)
	w.vault, _ = crypto.HexToAddress(vaultHex)
	w.header(100, [32]byte{}, [32]byte{})
	sdk.StateSetObject(constants.VerifierContractIdKey, "vsc1verifierstub")
	sdk.StubSetContractReadResponder(func(contractId, key string) *string {
		if key == constants.LastHeightKey {
			h := strconv.FormatUint(w.last, 10)
			return &h
		}
		if strings.HasPrefix(key, constants.BlockPrefix) {
			n, _ := strconv.ParseUint(strings.TrimPrefix(key, constants.BlockPrefix), 10, 64)
			if h, ok := w.headers[n]; ok {
				return &h
			}
		}
		return nil
	})
	w.caller("hive:carol")
	sdk.StubSetTssKey("active,02aa,ecdsa")
	to, _ := crypto.HexToAddress("0x00000000000000000000000000000000000000e2")
	orig := BuildETHWithdrawalTx(1, 0, 2_000_000_000, 40_000_000_000, to, big.NewInt(1e18))
	StorePendingSpend(PendingSpend{Nonce: 0, Amount: big.NewInt(1e18), From: "hive:alice", To: "0x00000000000000000000000000000000000000e2",
		Asset: "eth", UnsignedTxHex: hex.EncodeToString(orig), BlockHeight: 100, VaultAtQueue: vaultHex})
	SetConfirmedNonce(0)
	SetPendingNonce(1)
	SetSupply("eth", Supply{Active: new(big.Int), User: new(big.Int), Fee: new(big.Int)})
	return w
}

func (w *rollWorld) caller(c string) {
	sdk.StubSetEnvJSON(`{"contract.id":"contract:test","msg.caller":"` + c + `","msg.sender":"` + c +
		`","msg.required_auths":["` + c + `"],"block.height":` + strconv.FormatUint(w.l2, 10) + `}`)
}

func (w *rollWorld) header(n uint64, txRoot, receiptsRoot [32]byte) {
	w.headers[n] = (&blocklist.EthBlockHeader{BlockNumber: n, TransactionsRoot: txRoot, ReceiptsRoot: receiptsRoot,
		BaseFeePerGas: 1e9, GasLimit: 30_000_000, ChainId: 1}).Serialize()
}

func (w *rollWorld) roll() error { return HandleRollWithdrawal(0, w.vault, 1) }

// mine signs unsigned (hex) with the vault key and plants it at TxIndex 1 of
// L1 block n with a receipt of the given status; returns the confirmSpend
// request for it.
func (w *rollWorld) mine(n uint64, unsignedHex string, status uint64, logs ...[]byte) *ConfirmSpendRequest {
	w.t.Helper()
	unsigned, _ := hex.DecodeString(unsignedHex)
	priv := secp256k1.PrivKeyFromBytes(mustHex(w.t, rollVaultPriv))
	sig := dcrecdsa.SignCompact(priv, ComputeSighash(unsigned), false)
	signed, err := AttachSignature(unsigned, (sig[0]-27)&3, sig[1:33], sig[33:65])
	if err != nil {
		w.t.Fatal(err)
	}
	txRoot, txNodes := buildSingleLeafMPT(signed)
	receipt := rlp.EncodeList(rlp.EncodeUint64(status), rlp.EncodeUint64(21000), rlp.EncodeBytes(make([]byte, 256)), rlp.EncodeList(logs...))
	rcRoot, rcNodes := buildSingleLeafMPT(append([]byte{0x02}, receipt...))
	w.header(n, txRoot, rcRoot)
	w.last = n
	return &ConfirmSpendRequest{IntentNonce: 0, IntentTo: "0x00000000000000000000000000000000000000e2", IntentAmount: "1000000000000000000",
		IntentAsset: "eth", BlockHeight: n, TxIndex: 1,
		TxProof:      base64.StdEncoding.EncodeToString(concatBytes(txNodes)),
		ReceiptProof: base64.StdEncoding.EncodeToString(concatBytes(rcNodes))}
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// D3: a withdrawal that never mines can be rolled once the verified L1 chain is
// WithdrawalRollWindow blocks past it, by anyone, and not before.
func TestD3_RollOpensAfterTheL1Window(t *testing.T) {
	w := newRollWorld(t)
	defer sdk.ResetStubState()
	w.last = 100 + constants.WithdrawalRollWindow - 1
	w.header(w.last, [32]byte{}, [32]byte{})
	if err := w.roll(); err == nil || !strings.Contains(err.Error(), "can be rolled from L1 block") {
		t.Fatalf("roll inside the window = %v, want refused", err)
	}
	w.last++
	w.header(w.last, [32]byte{}, [32]byte{})
	if err := w.roll(); err != nil {
		t.Fatalf("roll after the window: %v", err)
	}
	ps := GetPendingSpend(0)
	if ps == nil || !ps.Rolled {
		t.Fatalf("pending spend after the roll: %+v", ps)
	}
	raw, _ := hex.DecodeString(ps.UnsignedTxHex)
	items, _ := rlp.DecodeList(raw[1:])
	if len(items) != 9 || items[1].AsUint64() != 0 || !bytesEqual(items[5].AsBytes(), w.vault[:]) || len(items[6].AsBytes()) != 0 || len(items[7].AsBytes()) != 0 {
		t.Fatalf("roll tx is not a 0-value self-transfer at nonce 0: %s", ps.UnsignedTxHex)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 || GetConfirmedNonce() != 0 {
		t.Fatal("rolling refunded or advanced the queue before anything mined")
	}
}

// The roll mining spends the nonce, so the withdrawal can never mine: the
// value goes back to the withdrawer and the queue moves on.
func TestD3_RollMinedRefundsTheWithdrawer(t *testing.T) {
	w := newRollWorld(t)
	defer sdk.ResetStubState()
	w.last = 100 + constants.WithdrawalRollWindow
	w.header(w.last, [32]byte{}, [32]byte{})
	if err := w.roll(); err != nil {
		t.Fatal(err)
	}
	req := w.mine(w.last+1, GetPendingSpend(0).UnsignedTxHex, 1)
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatalf("confirmSpend for the mined roll: %v", err)
	}
	if got := GetBalance("hive:alice", "eth"); got.Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("withdrawer balance %s, want the 1 ETH back", got)
	}
	if GetConfirmedNonce() != 1 || GetPendingSpend(0) != nil {
		t.Fatalf("queue not advanced: n=%d", GetConfirmedNonce())
	}
	if s := GetSupply("eth"); s.Active.Cmp(big.NewInt(1e18)) != 0 || s.User.Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("supply not restored: %+v", s)
	}
}

// If the withdrawal mines after all, it settles as usual: nothing refunded.
func TestD3_WithdrawalMinedAfterARollSettlesNormally(t *testing.T) {
	w := newRollWorld(t)
	defer sdk.ResetStubState()
	orig := GetPendingSpend(0).UnsignedTxHex
	w.last = 100 + constants.WithdrawalRollWindow
	w.header(w.last, [32]byte{}, [32]byte{})
	if err := w.roll(); err != nil {
		t.Fatal(err)
	}
	if err := HandleConfirmSpend(w.mine(w.last+1, orig, 1), 1); err != nil {
		t.Fatalf("confirmSpend for the mined withdrawal: %v", err)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 || GetConfirmedNonce() != 1 {
		t.Fatalf("withdrawal mined after the roll: balance %s n=%d, want no refund and n=1", GetBalance("hive:alice", "eth"), GetConfirmedNonce())
	}
}

// A rolled ERC-20 withdrawal that mines after all is also a 0-value transfer
// signed by the vault at that nonce, but to the token contract: it settles as
// usual, and only a 0-value transfer to the vault itself is the roll. Without
// the destination check the token transfer would be refunded as well: paid
// out on L1 and credited back on Magi.
func TestD3_ERC20WithdrawalMinedAfterARollIsNotRefunded(t *testing.T) {
	w := newRollWorld(t)
	defer sdk.ResetStubState()
	token, _ := crypto.HexToAddress("0x00000000000000000000000000000000000000a0")
	to, _ := crypto.HexToAddress("0x00000000000000000000000000000000000000e2")
	amount := big.NewInt(5_000_000)
	orig := hex.EncodeToString(BuildERC20WithdrawalTx(1, 0, 2_000_000_000, 40_000_000_000, token, to, amount))
	StorePendingSpend(PendingSpend{Nonce: 0, Amount: amount, From: "hive:alice", To: "0x00000000000000000000000000000000000000e2",
		Asset: "usdc", TokenAddress: "0x00000000000000000000000000000000000000a0", UnsignedTxHex: orig, BlockHeight: 100,
		VaultAtQueue: senderAddrFromPriv(t, rollVaultPriv), GasCost: big.NewInt(0)})
	SetSupply("usdc", Supply{Active: new(big.Int), User: new(big.Int), Fee: new(big.Int)})
	w.last = 100 + constants.WithdrawalRollWindow
	w.header(w.last, [32]byte{}, [32]byte{})
	if err := w.roll(); err != nil {
		t.Fatal(err)
	}
	if !GetPendingSpend(0).Rolled {
		t.Fatal("the withdrawal was not marked rolled")
	}
	req := w.mine(w.last+1, orig, 1, rp7Log(token, word32(amount), TransferEventSig[:], addrTopic(w.vault), addrTopic(to)))
	req.IntentAsset, req.IntentAmount = "usdc", amount.String()
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatalf("confirmSpend for the mined ERC-20 withdrawal: %v", err)
	}
	if got := GetBalance("hive:alice", "usdc"); got.Sign() != 0 {
		t.Fatalf("withdrawer credited %s although the token transfer mined", got)
	}
	if GetConfirmedNonce() != 1 || GetPendingSpend(0) != nil {
		t.Fatalf("queue not advanced: n=%d", GetConfirmedNonce())
	}
}

// Without a roll, a 0-value self-transfer at the nonce is not a settlement.
func TestD3_SelfTransferWithoutARollIsRefused(t *testing.T) {
	w := newRollWorld(t)
	defer sdk.ResetStubState()
	self := BuildETHWithdrawalTx(1, 0, 4_000_000_000, 100_000_000_000, w.vault, big.NewInt(0))
	err := HandleConfirmSpend(w.mine(150, hex.EncodeToString(self), 1), 1)
	if err == nil || GetBalance("hive:alice", "eth").Sign() != 0 || GetConfirmedNonce() != 0 {
		t.Fatalf("self-transfer without a roll: err %v, balance %s, n=%d; want refused", err, GetBalance("hive:alice", "eth"), GetConfirmedNonce())
	}
}

func TestD3_RollGates(t *testing.T) {
	ready := func(w *rollWorld) {
		w.last = 100 + constants.WithdrawalRollWindow
		w.header(w.last, [32]byte{}, [32]byte{})
	}
	for name, tc := range map[string]struct {
		setup func(w *rollWorld)
		call  func(w *rollWorld) error
		want  string
	}{
		"paused":         {func(w *rollWorld) { sdk.StateSetObject(constants.PausedKey, "1") }, (*rollWorld).roll, "paused"},
		"not the head":   {nil, func(w *rollWorld) error { return HandleRollWithdrawal(1, w.vault, 1) }, "not the confirmed-nonce head"},
		"vault changed":  {nil, func(w *rollWorld) error { return HandleRollWithdrawal(0, [20]byte{9}, 1) }, "no longer holds the vault"},
		"key not active": {func(w *rollWorld) { sdk.StubSetTssKey("deprecated,02aa,ecdsa") }, (*rollWorld).roll, "not active"},
		"no pending":     {func(w *rollWorld) { DeletePendingSpend(0) }, (*rollWorld).roll, "no pending spend"},
	} {
		w := newRollWorld(t)
		ready(w)
		if tc.setup != nil {
			tc.setup(w)
		}
		if err := tc.call(w); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: roll = %v, want %q", name, err, tc.want)
		}
	}

	// Re-sign only after the cooldown; replaceWithdrawal is refused once rolled.
	w := newRollWorld(t)
	ready(w)
	if err := w.roll(); err != nil {
		t.Fatal(err)
	}
	w.l2 += constants.ReplaceWithdrawalCooldown - 1
	w.caller("hive:carol")
	if err := w.roll(); err == nil || !strings.Contains(err.Error(), "cooldown") {
		t.Errorf("second roll inside the cooldown = %v", err)
	}
	w.l2++
	w.caller("hive:carol")
	if err := w.roll(); err != nil {
		t.Errorf("second roll after the cooldown: %v", err)
	}
	if err := HandleReplaceWithdrawal(w.vault, 1); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("replaceWithdrawal on a rolled withdrawal = %v, want refused", err)
	}
	sdk.ResetStubState()
}

// Only a 0-value, no-data self-transfer is the roll: a withdrawal whose
// destination is the vault itself settles as that withdrawal.
func TestD3_OnlyAZeroValueSelfTransferIsTheRoll(t *testing.T) {
	w := newRollWorld(t)
	defer sdk.ResetStubState()
	ps := GetPendingSpend(0)
	ps.To = crypto.AddressToHex(w.vault)
	ps.UnsignedTxHex = hex.EncodeToString(BuildETHWithdrawalTx(1, 0, 2_000_000_000, 40_000_000_000, w.vault, big.NewInt(1e18)))
	StorePendingSpend(*ps)
	toVault := ps.UnsignedTxHex
	w.last = 100 + constants.WithdrawalRollWindow
	w.header(w.last, [32]byte{}, [32]byte{})
	if err := w.roll(); err != nil {
		t.Fatal(err)
	}
	req := w.mine(w.last+1, toVault, 1)
	req.IntentTo = ps.To
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatalf("confirmSpend: %v", err)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 || GetConfirmedNonce() != 1 {
		t.Fatalf("a 1 ETH withdrawal to the vault was taken for the roll: balance %s n=%d", GetBalance("hive:alice", "eth"), GetConfirmedNonce())
	}
}

// E22: the expireWithdrawal window is counted in L1 blocks. It compared the
// L1 queue height with the Hive height, which on every network is far above
// it, so a stranger could always expire a fresh withdrawal.
func TestE22_ExpireWindowIsCountedInL1Blocks(t *testing.T) {
	w := newRollWorld(t)
	defer sdk.ResetStubState()
	w.l2 = 106_000_000 // a Hive height
	w.caller("hive:carol")
	w.last = 100 + constants.WithdrawalExpiryWindow - 1
	w.header(w.last, [32]byte{}, [32]byte{})
	err := HandleExpireWithdrawal(0, L1ProofOfDrop{Type: L1ProofTypeRevertedReceipt}, 1)
	if err == nil || !strings.Contains(err.Error(), "window not elapsed") {
		t.Fatalf("a stranger inside the L1 window: %v, want the window refusal", err)
	}
	// Past the window the gate opens (the proof is still required).
	w.last++
	w.header(w.last, [32]byte{}, [32]byte{})
	err = HandleExpireWithdrawal(0, L1ProofOfDrop{Type: L1ProofTypeRevertedReceipt}, 1)
	if err == nil || strings.Contains(err.Error(), "window not elapsed") {
		t.Fatalf("a stranger past the L1 window: %v, want the gate open and the proof checked", err)
	}
}

// dropProof is the reverted-receipt proof of drop for the confirmSpend request
// req (its tx mined and reverted).
func dropProof(req *ConfirmSpendRequest, nonce uint64) L1ProofOfDrop {
	return L1ProofOfDrop{Type: L1ProofTypeRevertedReceipt, BlockHeight: req.BlockHeight, TxIndex: req.TxIndex, TxNonce: nonce,
		ReceiptProof: req.ReceiptProof, TxProof: req.TxProof}
}

// A24: clearing or cancelling a withdrawal whose tx is proven reverted signs
// nothing (its nonce is spent on L1, a self-transfer there could never mine);
// a replacement or a roll with the signing key not active is refused before
// anything is stored (the host would drop the sign request and the stored tx
// would stand unsigned).
func TestA24_ResignsNeedAnActiveKeyAndProvenDropsSignNothing(t *testing.T) {
	defer sdk.ResetStubState()
	w := newRollWorld(t)
	w.caller("hive:alice")
	before := len(sdk.TestSignRequests())
	proof := dropProof(w.mine(101, GetPendingSpend(0).UnsignedTxHex, 0), 0)
	if err := HandleCancelMyWithdrawal(0, proof, 1); err != nil {
		t.Fatalf("cancelMyWithdrawal with a proven revert: %v", err)
	}
	if n := len(sdk.TestSignRequests()) - before; n != 0 || GetBalance("hive:alice", "eth").Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("%d sign requests, balance %s: want none and the value refunded", n, GetBalance("hive:alice", "eth"))
	}

	w = newRollWorld(t)
	sdk.StubSetTssKey("deprecated,02aa,ecdsa")
	stored := GetPendingSpend(0).UnsignedTxHex
	if err := HandleReplaceWithdrawal([20]byte{}, 1); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("replace with the key deprecated: %v", err)
	}
	if GetPendingSpend(0).UnsignedTxHex != stored || sdk.StateGetObject(replaceCooldownKey(GetPendingSpend(0), 0)) != nil {
		t.Fatal("a refused replace stored a tx or started the cooldown")
	}
	w.last = 100 + constants.WithdrawalRollWindow
	w.header(w.last, [32]byte{}, [32]byte{})
	if err := w.roll(); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("roll with the key deprecated: %v", err)
	}
}

// A14: a replacement or a roll may burn more L1 gas than the withdrawal
// prepaid; the extra comes from the gas reserve (and the custody) when it is
// signed, never more than once per price, and a roll is not refused when the
// reserve is short (the debt is logged).
func TestA14_ResignGasIsBooked(t *testing.T) {
	defer sdk.ResetStubState()
	w := newRollWorld(t)
	sdk.StateSetObject(constants.GasReserveKey, "1000000000000000") // 0.001 ETH
	SetSupply("eth", Supply{Active: wei("1000000000000000"), User: new(big.Int), Fee: new(big.Int)})
	ps := GetPendingSpend(0)
	ps.GasCost = big.NewInt(84_000_000_000_000) // 21,000 gas at 4 gwei, prepaid
	StorePendingSpend(*ps)
	if err := HandleReplaceWithdrawal([20]byte{}, 1); err != nil {
		t.Fatal(err)
	}
	// 3x the 1 gwei base fee + 4 gwei tip = 7 gwei: 147e12 max, 63e12 more.
	if got := getGasReserve(); got.Cmp(wei("937000000000000")) != 0 {
		t.Fatalf("reserve %s after the replacement, want 937000000000000", got)
	}
	if got := GetSupply("eth").Active; got.Cmp(wei("937000000000000")) != 0 {
		t.Fatalf("custody %s, want the replacement gas out of it", got)
	}
	if got := GetPendingSpend(0).GasCost; got.Cmp(big.NewInt(147_000_000_000_000)) != 0 {
		t.Fatalf("prepaid %s, want 147e12", got)
	}
	// The roll at the same price can burn no more: nothing more is booked.
	w.last = 100 + constants.WithdrawalRollWindow
	w.header(w.last, [32]byte{}, [32]byte{})
	w.l2 += constants.ReplaceWithdrawalCooldown
	w.caller("hive:carol")
	if err := w.roll(); err != nil {
		t.Fatal(err)
	}
	if got := getGasReserve(); got.Cmp(wei("937000000000000")) != 0 {
		t.Fatalf("reserve %s after a roll at the same price", got)
	}

	// A short reserve: the roll goes through, the reserve is emptied, the debt
	// is logged.
	w = newRollWorld(t)
	sdk.StateSetObject(constants.GasReserveKey, "1000")
	SetSupply("eth", Supply{Active: wei("1000"), User: new(big.Int), Fee: new(big.Int)})
	w.last = 100 + constants.WithdrawalRollWindow
	w.header(w.last, [32]byte{}, [32]byte{})
	if err := w.roll(); err != nil {
		t.Fatalf("roll with a short reserve: %v", err)
	}
	logs := sdk.TestLogs()
	if getGasReserve().Sign() != 0 || len(logs) == 0 || !strings.Contains(strings.Join(logs, "\n"), "gasdebt|n=0|v=146999999999000") {
		t.Fatalf("reserve %s, logs %v: want it emptied and the rest logged", getGasReserve(), logs)
	}
}
