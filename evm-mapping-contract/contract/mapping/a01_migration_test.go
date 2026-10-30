package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// migWorld is a bridge whose generation 0 key is secp256k1 private key 1 (so
// the test can sign gen 0's sweeps) and generation 1 key is private key 2.
type migWorld struct {
	t       *testing.T
	headers map[uint64]string
	n       uint64
	now     time.Time
	usdc    [20]byte
	gen0    [20]byte
	gen1    [20]byte
}

func newMigWorld(t *testing.T) *migWorld {
	t.Helper()
	sdk.ResetStubState()
	sdk.ResetTestState()
	sdk.StubClearTssKeys()
	w := &migWorld{t: t, headers: map[uint64]string{}, n: 1000, now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		usdc: [20]byte{19: 0xc0}, gen0: a01Addr(t, testAdr1), gen1: a01Addr(t, testAdr2)}
	w.plainHeader(w.n)
	sdk.StateSetObject(constants.VerifierContractIdKey, "vsc1verifierstub")
	sdk.StubSetContractReadResponder(func(_, key string) *string {
		if key == constants.LastHeightKey {
			h := strconv.FormatUint(w.n, 10)
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
	sdk.StubSetEnvJSON(`{"contract.id":"contract:test","msg.caller":"hive:op","msg.sender":"hive:op","msg.required_auths":["hive:op"],"block.timestamp":"` +
		w.now.Format("2006-01-02T15:04:05") + `"}`)
	if err := RegisterTokenFull(1, w.usdc, "usdc", 6, 10_000_000, 0, 0); err != nil {
		t.Fatal(err)
	}
	// Custody: 3 ETH of users + a 0.5 ETH reserve, 500 USDC.
	SetSupply("eth", Supply{Active: wei("3500000000000000000"), User: wei("3000000000000000000"), Fee: new(big.Int)})
	addGasReserve(wei("500000000000000000"))
	SetSupply("usdc", Supply{Active: wei("500000000"), User: wei("500000000"), Fee: new(big.Int)})

	// Genesis gen 0, then rotate to gen 1 (checked and reshared).
	MintNextGeneration(uint32(w.n))
	sdk.StubSetTssKeyFor("primary", "active,"+testPub1+",ecdsa,1,1")
	if _, _, _, err := ActivatePendingGeneration(uint32(w.n)); err != nil {
		t.Fatal(err)
	}
	MintNextGeneration(uint32(w.n))
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,1")
	if _, _, _, err := ActivatePendingGeneration(uint32(w.n)); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *migWorld) hdr(n uint64, state, txs, rcs [32]byte) {
	w.headers[n] = (&blocklist.EthBlockHeader{BlockNumber: n, StateRoot: state, TransactionsRoot: txs, ReceiptsRoot: rcs,
		BaseFeePerGas: 1e9, GasLimit: 30_000_000, Timestamp: uint64(w.now.Unix()), ChainId: 1}).Serialize()
}

func (w *migWorld) plainHeader(n uint64) { w.hdr(n, [32]byte{}, [32]byte{}, [32]byte{}) }

// advance moves the newest header n blocks on.
func (w *migWorld) advance(blocks uint64) {
	w.n += blocks
	w.plainHeader(w.n)
}

// sign signs an unsigned sweep with the given private key (1 = gen 0).
func (w *migWorld) sign(unsignedHex string, priv byte) []byte {
	w.t.Helper()
	unsigned, _ := hex.DecodeString(unsignedHex)
	k := make([]byte, 32)
	k[31] = priv
	sig := dcrecdsa.SignCompact(secp256k1.PrivKeyFromBytes(k), ComputeSighash(unsigned), false)
	signed, err := AttachSignature(unsigned, (sig[0]-27)&3, sig[1:33], sig[33:65])
	if err != nil {
		w.t.Fatal(err)
	}
	return signed
}

// mine plants signed at TxIndex 1 of a new block with a receipt of status and
// logs, and returns the confirmSweep request.
func (w *migWorld) mine(gen uint32, nonce uint64, signed []byte, status uint64, logs ...[]byte) *ConfirmSweepRequest {
	txRoot, txNodes := buildSingleLeafMPT(signed)
	receipt := append([]byte{0x02}, rlp.EncodeList(rlp.EncodeUint64(status), rlp.EncodeUint64(60_000),
		rlp.EncodeBytes(make([]byte, 256)), rlp.EncodeList(logs...))...)
	rcRoot, rcNodes := buildSingleLeafMPT(receipt)
	w.n++
	w.hdr(w.n, [32]byte{}, txRoot, rcRoot)
	return &ConfirmSweepRequest{Gen: gen, Nonce: nonce, BlockHeight: w.n, TxIndex: 1,
		TxProof: base64.StdEncoding.EncodeToString(concatBytes(txNodes)), ReceiptProof: base64.StdEncoding.EncodeToString(concatBytes(rcNodes))}
}

// accountProof plants a header whose state trie holds one account and returns
// its proof.
func (w *migWorld) accountProof(addr [20]byte, nonce uint64, balance *big.Int) *AccountProof {
	acct := rlp.EncodeList(rlp.EncodeUint64(nonce), rlp.EncodeBigInt(balance), rlp.EncodeBytes(make([]byte, 32)), rlp.EncodeBytes(make([]byte, 32)))
	leaf := rlp.EncodeList(rlp.EncodeBytes(append([]byte{0x20}, crypto.Keccak256(addr[:])...)), rlp.EncodeBytes(acct))
	var root [32]byte
	copy(root[:], crypto.Keccak256(leaf))
	w.n++
	w.hdr(w.n, root, [32]byte{}, [32]byte{})
	return &AccountProof{BlockHeight: w.n, Proof: base64.StdEncoding.EncodeToString(leaf)}
}

func lastSign(t *testing.T) string {
	t.Helper()
	r := sdk.TestSignRequests()
	if len(r) == 0 {
		t.Fatal("no sign request")
	}
	return r[len(r)-1]
}

// tokenGasNow is what planTokenSweeps prices gen's token sweeps at now.
func tokenGasNow(t *testing.T, gen uint32) *big.Int {
	t.Helper()
	header, err := pricingHeader()
	if err != nil {
		t.Fatal(err)
	}
	_, gas, _, err := planTokenSweeps(1, gen, header)
	if err != nil {
		t.Fatal(err)
	}
	return gas
}

// covers reports whether the active generation can pay a withdrawal of amount
// in asset now (with ethGas of L1 gas for a token).
func covers(asset string, amount, ethGas *big.Int) bool {
	return activeGenCovers(&QueuedWithdrawal{}, true, asset, amount, ethGas)
}

func TestA01_FullMigration(t *testing.T) {
	w := newMigWorld(t)
	if VaultBook(0, "eth").Cmp(wei("3500000000000000000")) != 0 || VaultBook(0, "usdc").Cmp(wei("500000000")) != 0 {
		t.Fatalf("books after the cut-over: eth %s usdc %s", VaultBook(0, "eth"), VaultBook(0, "usdc"))
	}
	if funded, _ := AnyFundedSupersededGen(); !funded {
		t.Fatal("NN#3 does not hold")
	}
	oneEth, someUsdc, usdcGas := wei("1000000000000000000"), wei("1000000"), wei("300000000000000")
	if covers("eth", oneEth, nil) || covers("usdc", someUsdc, usdcGas) {
		t.Fatal("the new generation pays before anything reached it")
	}

	// 1. Every sweep in one batch: ETH first (it holds the most), then USDC.
	if _, err := HandleMigrateVault(1, nil); err == nil || !strings.Contains(err.Error(), "eth_proof") {
		t.Fatalf("batch without the ETH proof: %v", err)
	}
	keep := new(big.Int).Mul(tokenGasNow(t, 0), big.NewInt(SweepGasHeadroom))
	ethBook := VaultBook(0, "eth")
	stray := wei("10000000000000000") // 0.01 ETH nobody mapped
	balance := new(big.Int).Add(ethBook, stray)
	if _, err := HandleMigrateVault(1, w.accountProof(w.gen0, 1, balance)); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("a proof at the wrong nonce: %v", err)
	}
	signsBefore := len(sdk.TestSignRequests())
	out, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, balance))
	if err != nil || !strings.HasPrefix(out, "sweep 0-0 eth ") || !strings.Contains(out, "; sweep 0-1 usdc 500000000") {
		t.Fatalf("batch: %q %v", out, err)
	}
	if n := len(sdk.TestSignRequests()) - signsBefore; n != 2 || !strings.HasPrefix(lastSign(t), "primary,") {
		t.Fatalf("%d sign requests, last by %s: want both sweeps signed by the retiring key at once", n, lastSign(t))
	}
	e, u := GetSweep(0, 0), GetSweep(0, 1)
	if e == nil || u == nil || e.Kind != "eth" || u.Kind != "token" || e.To != crypto.AddressToHex(w.gen1) || u.To != e.To {
		t.Fatalf("records %+v %+v", e, u)
	}
	want := new(big.Int).Sub(balance, wei(e.GasCost))
	want.Sub(want, keep)
	if wei(e.Versions[0].Value).Cmp(want) != 0 {
		t.Fatalf("ETH sweep value %s, want the proven balance less its gas and twice the USDC sweep's gas (%s)", e.Versions[0].Value, want)
	}
	vaults, _, _, _ := LoadVaultState()
	if vaults[0].Status != VaultStatusDraining || SweepNonce(0) != 2 {
		t.Fatalf("gen 0 status %v sweep nonce %d after the batch", vaults[0].Status, SweepNonce(0))
	}
	// ETH of a gen-0 withdrawal refunded from now on went with this sweep.
	booked := VaultBook(0, "eth")
	bookSpendRefund(&PendingSpend{VaultAtQueue: crypto.AddressToHex(w.gen0), Asset: "eth"}, wei("5"))
	if VaultBook(0, "eth").Cmp(booked) != 0 {
		t.Fatal("refunded ETH booked to gen 0 after its proven ETH sweep")
	}
	if out, _ := HandleMigrateVault(1, nil); !strings.Contains(out, "in flight") {
		t.Fatalf("second batch while one is open: %q", out)
	}

	// 2. The ETH sweep stalls behind a fee spike and is re-driven; the
	// re-driven version mines.
	if _, err := HandleRedriveSweep(0, 0, 1); err == nil {
		t.Fatal("re-drive before the window")
	}
	w.advance(SweepRedriveL1Blocks)
	if _, err := HandleRedriveSweep(0, 0, 1); err != nil {
		t.Fatal(err)
	}
	e = GetSweep(0, 0)
	if len(e.Versions) != 2 || e.Versions[1].FeeCap <= e.Versions[0].FeeCap || wei(e.Versions[1].Value).Cmp(wei(e.Versions[0].Value)) >= 0 {
		t.Fatalf("re-drive versions %+v", e.Versions)
	}
	if err := HandleConfirmSweep(w.mine(0, 0, w.sign(e.Versions[1].Unsigned, 1), 1), 1); err != nil {
		t.Fatal(err)
	}
	// ETH withdrawals resume now, with the USDC sweep still out.
	if !covers("eth", oneEth, nil) {
		t.Fatal("ETH withdrawals still wait after the ETH sweep settled")
	}
	if covers("usdc", someUsdc, usdcGas) {
		t.Fatal("USDC paid by the new generation before its sweep settled")
	}
	if VaultBook(0, "eth").Cmp(new(big.Int).Sub(keep, wei(u.GasCost))) != 0 {
		t.Fatalf("eth book %s after the ETH sweep, want the gas kept back less the USDC sweep's", VaultBook(0, "eth"))
	}

	// 3. Attacks on the USDC settlement: a tx not of the sweep, the wrong
	// signer, a status-1 receipt without the Transfer (A36).
	forged := w.sign(hex.EncodeToString(BuildERC20WithdrawalTxGas(1, 1, sweepTipCap, u.Versions[0].FeeCap, w.usdc, [20]byte{0xee}, wei("500000000"), 0)), 1)
	if err := HandleConfirmSweep(w.mine(0, 1, forged, 1), 1); err == nil {
		t.Fatal("a tx paying another address settled the sweep")
	}
	if err := HandleConfirmSweep(w.mine(0, 1, w.sign(u.Versions[0].Unsigned, 2), 1), 1); err == nil {
		t.Fatal("a tx signed by another key settled the sweep")
	}
	if err := HandleConfirmSweep(w.mine(0, 1, w.sign(u.Versions[0].Unsigned, 1), 1), 1); err != nil {
		t.Fatal(err)
	}
	if VaultBook(0, "usdc").Sign() == 0 || sweepReverts(0, "usdc") != 1 {
		t.Fatalf("status 1 without the Transfer was taken as paid (A36): book %s reverts %d", VaultBook(0, "usdc"), sweepReverts(0, "usdc"))
	}

	// The retry needs no proof: its gas is the ETH kept back.
	if out, err := HandleMigrateVault(1, nil); err != nil || out != "sweep 0-2 usdc 500000000" {
		t.Fatalf("retry: %q %v", out, err)
	}
	u = GetSweep(0, 2)
	transfer := rp7Log(w.usdc, word32(wei("500000000")), TransferEventSig[:], addrTopic(w.gen0), addrTopic(w.gen1))
	if err := HandleConfirmSweep(w.mine(0, 2, w.sign(u.Versions[0].Unsigned, 1), 1, transfer), 1); err != nil {
		t.Fatal(err)
	}
	if VaultBook(0, "usdc").Sign() != 0 || GetSweep(0, 2) != nil || !covers("usdc", someUsdc, usdcGas) {
		t.Fatalf("usdc book %s after the sweep", VaultBook(0, "usdc"))
	}

	// 4. A late deposit lands at gen 0; it and the unspent kept-back gas go in
	// the next ETH sweep (proof after the last sweep mined).
	late := wei("20000000000000000")
	addVaultBook(0, "eth", late)
	left := VaultBook(0, "eth")
	if _, err := HandleMigrateVault(1, nil); err == nil || !strings.Contains(err.Error(), "eth_proof") {
		t.Fatalf("late ETH without a proof: %v", err)
	}
	out, err = HandleMigrateVault(1, w.accountProof(w.gen0, 3, left))
	if err != nil || !strings.HasPrefix(out, "sweep 0-3 eth") || strings.Contains(out, ";") {
		t.Fatalf("late deposit sweep: %q %v", out, err)
	}
	if err := HandleConfirmSweep(w.mine(0, 3, w.sign(GetSweep(0, 3).Versions[0].Unsigned, 1), 1), 1); err != nil {
		t.Fatal(err)
	}
	if funded, _ := AnyFundedSupersededGen(); funded {
		t.Fatalf("gen 0 still funded: eth %s usdc %s", VaultBook(0, "eth"), VaultBook(0, "usdc"))
	}

	// 5. Retire: inactive, purged only after the grace.
	if out, _ := ReconcileRetiringVaults(11155111); !strings.Contains(out, "inactivated=0") {
		t.Fatalf("retire: %q", out)
	}
	if out, _ := ReconcileRetiringVaults(11155111); out != "retire: no generation transitions" {
		t.Fatalf("purged before the grace: %q", out)
	}
	w.advance(uint64(constants.VaultPurgeReorgL1Blocks))
	if out, _ := ReconcileRetiringVaults(11155111); !strings.Contains(out, "purged=0") {
		t.Fatalf("not purged after the grace: %q", out)
	}
	if gens := FundHoldingGens(); len(gens) != 1 || gens[0].Generation != 1 {
		t.Fatalf("fund-holding after the purge: %+v", gens)
	}
}

// ROT-WINDOW-EVM: a token whose transfer reverts every time never holds the
// ETH back: ETH withdrawals resume after the first batch settles, and the token
// waits alone for its retries and the owner's write-off.
func TestA01_RevertingTokenDoesNotHoldTheETH(t *testing.T) {
	w := newMigWorld(t)
	out, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, VaultBook(0, "eth")))
	if err != nil || !strings.Contains(out, "; sweep 0-1 usdc") {
		t.Fatalf("batch: %q %v", out, err)
	}
	// The token sweep (nonce 1) reverts; the ETH sweep (nonce 0) mines.
	if err := HandleConfirmSweep(w.mine(0, 1, w.sign(GetSweep(0, 1).Versions[0].Unsigned, 1), 0), 1); err != nil {
		t.Fatal(err)
	}
	if err := HandleConfirmSweep(w.mine(0, 0, w.sign(GetSweep(0, 0).Versions[0].Unsigned, 1), 1), 1); err != nil {
		t.Fatal(err)
	}
	if !covers("eth", wei("1000000000000000000"), nil) {
		t.Fatal("a reverting token held ETH withdrawals")
	}
	// The second try reverts too; then the token is the owner's.
	if out, err := HandleMigrateVault(1, nil); err != nil || out != "sweep 0-2 usdc 500000000" {
		t.Fatalf("retry: %q %v", out, err)
	}
	if err := HandleConfirmSweep(w.mine(0, 2, w.sign(GetSweep(0, 2).Versions[0].Unsigned, 1), 0), 1); err != nil {
		t.Fatal(err)
	}
	if out, _ := HandleMigrateVault(1, nil); !strings.Contains(out, "write-off") {
		t.Fatalf("after two reverts: %q", out)
	}
}

// A generation holding only tokens and too little ETH to send any beyond their
// gas: the proof builds the token sweeps alone.
func TestA01_TokensAloneWhenNoETHBeyondTheirGas(t *testing.T) {
	w := newMigWorld(t)
	keep := new(big.Int).Mul(tokenGasNow(t, 0), big.NewInt(SweepGasHeadroom))
	setVaultBook(0, "eth", new(big.Int).Add(keep, big.NewInt(1)))
	out, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, VaultBook(0, "eth")))
	if err != nil || out != "sweep 0-0 usdc 500000000" {
		t.Fatalf("tokens alone: %q %v", out, err)
	}
	// Proven balance below the token gas: nothing is built.
	w = newMigWorld(t)
	setVaultBook(0, "eth", keep)
	if out, _ := HandleMigrateVault(1, w.accountProof(w.gen0, 0, big.NewInt(1))); !strings.Contains(out, "too little ETH") || GetSweep(0, 0) != nil {
		t.Fatalf("tokens without the gas on L1: %q", out)
	}
}

// A late deposit to an Inactive generation books it and the next reconcile
// returns it to Draining, so it is swept and never purged with funds.
func TestA01_LateDepositRevivesAnInactiveGeneration(t *testing.T) {
	w := newMigWorld(t)
	setVaultBook(0, "eth", new(big.Int))
	setVaultBook(0, "usdc", new(big.Int))
	ReconcileRetiringVaults(11155111)
	addVaultBook(0, "usdc", wei("1000000"))
	w.advance(uint64(constants.VaultPurgeReorgL1Blocks) + 10)
	out, _ := ReconcileRetiringVaults(11155111)
	if !strings.Contains(out, "reverted-to-draining=0") || strings.Contains(out, "purged") {
		t.Fatalf("late deposit: %q", out)
	}
}

func TestA01_DustAndTokenWriteOff(t *testing.T) {
	w := newMigWorld(t)
	// ETH dust: a few gwei left, no tokens: the ETH proof says dust, and the
	// write-off takes it from the reserve.
	setVaultBook(0, "usdc", new(big.Int))
	dust := wei("1000")
	setVaultBook(0, "eth", dust)
	if out, _ := HandleMigrateVault(1, w.accountProof(w.gen0, 0, dust)); !strings.Contains(out, "dust") {
		t.Fatalf("dust migrate: %q", out)
	}
	reserve := getGasReserve()
	if out, err := HandleWriteOffDust(); err != nil || !strings.Contains(out, "wrote off 1000") {
		t.Fatalf("writeOffDust: %q %v", out, err)
	}
	if VaultBook(0, "eth").Sign() != 0 || getGasReserve().Cmp(new(big.Int).Sub(reserve, dust)) != 0 {
		t.Fatal("dust not written off against the reserve")
	}

	// A token whose transfers keep reverting is left for the owner.
	w2 := newMigWorld(t)
	setVaultBook(0, "eth", new(big.Int).Mul(tokenGasNow(t, 0), big.NewInt(SweepGasHeadroom)))
	if _, err := HandleWriteOffToken(0, "usdc"); err == nil {
		t.Fatal("token write-off before any revert")
	}
	for n := uint64(0); n < MaxSweepReverts; n++ {
		if _, err := HandleMigrateVault(1, nil); err != nil {
			t.Fatal(err)
		}
		if err := HandleConfirmSweep(w2.mine(0, n, w2.sign(GetSweep(0, n).Versions[0].Unsigned, 1), 0), 1); err != nil {
			t.Fatal(err)
		}
	}
	if out, _ := HandleMigrateVault(1, nil); !strings.Contains(out, "write-off") {
		t.Fatalf("migrate after the reverts: %q", out)
	}
	if _, err := HandleWriteOffToken(0, "usdc"); err != nil {
		t.Fatal(err)
	}
	if VaultBook(0, "usdc").Sign() != 0 || GetSupply("usdc").Active.Sign() != 0 {
		t.Fatalf("token write-off: book %s custody %s", VaultBook(0, "usdc"), GetSupply("usdc").Active)
	}
}

// The successor must have been reshared since its keygen before funds move.
func TestA01_MigrationWaitsForTheSuccessorsReshare(t *testing.T) {
	newMigWorld(t)
	sdk.StubSetTssKeyFor("primaryv1", "active,"+testPub2+",ecdsa,1,0")
	if _, err := HandleMigrateVault(1, nil); err == nil || !strings.Contains(err.Error(), "reshared") {
		t.Fatalf("migrate into an unreshared successor: %v", err)
	}
}

// ActiveVaultOrNil is a test convenience.
func ActiveVaultOrNil() (*Vault, bool) {
	v, ok := ActiveVault()
	if !ok {
		return nil, false
	}
	return &v, true
}

// NN#1 layer 1: a sweep pays the successor and nothing else, whatever shape an
// attacker gives it.
func TestA01_SweepMustPayOnlyTheSuccessor(t *testing.T) {
	succ := a01Addr(t, testAdr2)
	other := [20]byte{0xee}
	token := [20]byte{19: 0xc0}
	ok := [][]byte{
		BuildETHWithdrawalTxGas(1, 0, 1, 2, succ, big.NewInt(5), 21000),
		BuildERC20WithdrawalTxGas(1, 0, 1, 2, token, succ, big.NewInt(5), 0),
	}
	for _, tx := range ok {
		if err := assertSweepPaysSuccessor(tx, succ); err != nil {
			t.Fatalf("a successor sweep was refused: %v", err)
		}
	}
	approve := append([]byte{0x09, 0x5e, 0xa7, 0xb3}, make([]byte, 64)...)
	copy(approve[16:36], succ[:])
	bad := map[string][]byte{
		"ETH to another address":      BuildETHWithdrawalTxGas(1, 0, 1, 2, other, big.NewInt(5), 21000),
		"token to another address":    BuildERC20WithdrawalTxGas(1, 0, 1, 2, token, other, big.NewInt(5), 0),
		"ETH value with calldata":     buildEIP1559Tx(1, 0, 1, 2, 60000, succ, big.NewInt(5), []byte{1, 2, 3}),
		"approve, not transfer":       buildEIP1559Tx(1, 0, 1, 2, 60000, token, big.NewInt(0), approve),
		"zero value, no calldata":     buildEIP1559Tx(1, 0, 1, 2, 21000, succ, big.NewInt(0), nil),
		"legacy (not EIP-1559)":       append([]byte{0x01}, BuildETHWithdrawalTxGas(1, 0, 1, 2, succ, big.NewInt(5), 21000)[1:]...),
		"trailing bytes after the tx": append(BuildERC20WithdrawalTxGas(1, 0, 1, 2, token, succ, big.NewInt(5), 0), 0),
		"transfer calldata too long":  buildEIP1559Tx(1, 0, 1, 2, 60000, token, big.NewInt(0), append(BuildERC20Calldata(succ), 0)),
	}
	for name, tx := range bad {
		if err := assertSweepPaysSuccessor(tx, succ); err == nil {
			t.Errorf("%s passed the successor assertion", name)
		}
	}
}

// Guards that the full run passes through without tripping.
func TestA01_MigrationRefusals(t *testing.T) {
	// A retiring address without the ETH for its token sweep: nothing built.
	w := newMigWorld(t)
	setVaultBook(0, "eth", wei("1"))
	if out, err := HandleMigrateVault(1, nil); err != nil || !strings.Contains(out, "too little ETH") || GetSweep(0, 0) != nil {
		t.Fatalf("token sweep without gas: %q %v", out, err)
	}
	vaults, _, _, _ := LoadVaultState()
	if vaults[0].Status != VaultStatusRetiring {
		t.Fatalf("status %v: flipped to draining with nothing built", vaults[0].Status)
	}

	// The ETH proof may not predate the newest booked deposit.
	w = newMigWorld(t)
	setVaultBook(0, "usdc", new(big.Int))
	old := w.accountProof(w.gen0, 0, VaultBook(0, "eth"))
	noteBookedHeight(0, old.BlockHeight+1)
	if _, err := HandleMigrateVault(1, old); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("a stale balance proof: %v", err)
	}

	// A re-drive raises the fee cap by at least 10%, for either kind.
	w = newMigWorld(t)
	if _, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, VaultBook(0, "eth"))); err != nil {
		t.Fatal(err)
	}
	w.advance(SweepRedriveL1Blocks)
	for n := uint64(0); n < 2; n++ {
		if _, err := HandleRedriveSweep(0, n, 1); err != nil {
			t.Fatal(err)
		}
		v := GetSweep(0, n).Versions
		if v[1].FeeCap < v[0].FeeCap+v[0].FeeCap/10+1 || v[1].TipCap < v[0].TipCap+v[0].TipCap/10+1 {
			t.Fatalf("sweep %d re-drive fees %+v: below the 10%% replacement bump", n, v)
		}
	}

	// A funded superseded generation does not go inactive.
	w = newMigWorld(t)
	if out, _ := ReconcileRetiringVaults(11155111); out != "retire: no generation transitions" {
		t.Fatalf("reconcile of a funded generation: %q", out)
	}

	// No ETH dust write-off while a token is still booked.
	w = newMigWorld(t)
	setVaultBook(0, "eth", wei("1000"))
	if out, _ := HandleWriteOffDust(); out != "no dust to write off" {
		t.Fatalf("write-off with a token still booked: %q", out)
	}
}

// BuildERC20Calldata is transfer(to, 5) calldata.
func BuildERC20Calldata(to [20]byte) []byte {
	_, _, data, _ := decodeUnsignedEIP1559(BuildERC20WithdrawalTxGas(1, 0, 1, 2, [20]byte{1}, to, big.NewInt(5), 0))
	return data
}

// ETH that can still pay for its own sweep is never written off.
func TestA01_SweepableETHIsNotDust(t *testing.T) {
	newMigWorld(t)
	setVaultBook(0, "usdc", new(big.Int))
	setVaultBook(0, "eth", wei("1000000000000000000"))
	if out, _ := HandleWriteOffDust(); out != "no dust to write off" {
		t.Fatalf("1 ETH written off as dust: %q", out)
	}
}

// Edge cases of the batch's ETH booking and gas checks.
func TestA01_BatchEdges(t *testing.T) {
	// Proof shows ETH but the books hold less than the token gas: a status,
	// not an underflow abort.
	w := newMigWorld(t)
	gas := tokenGasNow(t, 0)
	setVaultBook(0, "eth", new(big.Int).Sub(gas, big.NewInt(1)))
	keep := new(big.Int).Mul(gas, big.NewInt(SweepGasHeadroom))
	if out, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, keep)); err != nil || !strings.Contains(out, "too little ETH") {
		t.Fatalf("books below the token gas: %q %v", out, err)
	}

	// The reserve pays every sweep's gas: enough for the token sweep but not
	// the ETH sweep's too, nothing is built.
	w = newMigWorld(t)
	sdk.StateSetObject(constants.GasReserveKey, new(big.Int).Add(tokenGasNow(t, 0), big.NewInt(1)).String())
	if out, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, VaultBook(0, "eth"))); err != nil || !strings.Contains(out, "gas reserve below") || GetSweep(0, 0) != nil {
		t.Fatalf("reserve short of the batch: %q %v", out, err)
	}

	// L1 holds less than the books: the books move only what the sweep sends.
	w = newMigWorld(t)
	short := wei("2000000000000000000")
	if _, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, short)); err != nil {
		t.Fatal(err)
	}
	if r := GetSweep(0, 0); r.Booked != r.Versions[0].Value {
		t.Fatalf("booked %s, sends %s: the books must not move more than L1 does", r.Booked, r.Versions[0].Value)
	}

	// Books short of the token gas, a large unbooked balance: the ETH goes,
	// the tokens wait for their gas to be booked (no underflow abort).
	w = newMigWorld(t)
	setVaultBook(0, "eth", big.NewInt(1))
	out, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, wei("1000000000000000000")))
	if err != nil || !strings.HasPrefix(out, "sweep 0-0 eth ") || !strings.Contains(out, "too little ETH") || GetSweep(0, 1) != nil {
		t.Fatalf("stray ETH with the books short of the token gas: %q %v", out, err)
	}

	// Books between the token gas and what is kept back: the booking floors at
	// zero (a negative one would raise the book on confirmation).
	w = newMigWorld(t)
	gas = tokenGasNow(t, 0)
	header, _ := pricingHeader()
	_, ethCost, _ := safeGasFee(defaultETHGasLimit(), header.BaseFeePerGas, 2, sweepTipCap)
	// The ETH sweep's gas, the token gas, and half of it again: less than the
	// twice-over kept back.
	book := new(big.Int).Add(ethCost, gas)
	book.Add(book, new(big.Int).Div(gas, big.NewInt(2)))
	setVaultBook(0, "eth", book)
	if _, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, wei("1000000000000000000"))); err != nil {
		t.Fatal(err)
	}
	if r := GetSweep(0, 0); r.Kind != "eth" || r.Booked != "0" || GetSweep(0, 1) == nil {
		t.Fatalf("ETH record %+v, token sweep %v", r, GetSweep(0, 1) != nil)
	}
	before := VaultBook(0, "eth")
	if err := HandleConfirmSweep(w.mine(0, 0, w.sign(GetSweep(0, 0).Versions[0].Unsigned, 1), 1), 1); err != nil {
		t.Fatal(err)
	}
	if VaultBook(0, "eth").Cmp(before) != 0 {
		t.Fatalf("eth book %s -> %s on confirming a sweep that booked nothing", before, VaultBook(0, "eth"))
	}

	// Books below what is kept back, a large unbooked balance: the sweep
	// sends the stray ETH and books nothing (never a negative booking).
	w = newMigWorld(t)
	setVaultBook(0, "usdc", new(big.Int))
	setVaultBook(0, "eth", big.NewInt(1))
	if _, err := HandleMigrateVault(1, w.accountProof(w.gen0, 0, wei("1000000000000000000"))); err != nil {
		t.Fatal(err)
	}
	r := GetSweep(0, 0)
	if r.Booked != "0" {
		t.Fatalf("booked %s with 1 wei on the books", r.Booked)
	}
	if err := HandleConfirmSweep(w.mine(0, 0, w.sign(r.Versions[0].Unsigned, 1), 1), 1); err != nil {
		t.Fatal(err)
	}
	if VaultBook(0, "eth").Sign() < 0 || VaultBook(0, "eth").Cmp(big.NewInt(1)) > 0 {
		t.Fatalf("eth book %s after sweeping stray ETH", VaultBook(0, "eth"))
	}
}
