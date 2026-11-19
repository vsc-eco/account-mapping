package mapping

import (
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
)

func nibbles(b []byte) []byte {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, c>>4, c&0x0f)
	}
	return out
}

// accountLeaf is the leaf of addr's account below a branch (63 key nibbles).
func accountLeaf(addr [20]byte, bal *big.Int, nibs []byte) []byte {
	acct := rlp.EncodeList(rlp.EncodeUint64(0), rlp.EncodeBigInt(bal), rlp.EncodeBytes(make([]byte, 32)), rlp.EncodeBytes(make([]byte, 32)))
	path := []byte{0x30 | nibs[0]} // hex-prefix: leaf, odd length
	for i := 1; i+1 < len(nibs); i += 2 {
		path = append(path, nibs[i]<<4|nibs[i+1])
	}
	return rlp.EncodeList(rlp.EncodeBytes(path), rlp.EncodeBytes(acct))
}

// twoAccounts stores a header at a new height whose state holds a and b (a
// branch and two leaves) and returns one proof per address at it.
func (w *migWorld) twoAccounts(a [20]byte, balA *big.Int, b [20]byte, balB *big.Int) (*AccountProof, *AccountProof) {
	w.t.Helper()
	ka, kb := nibbles(crypto.Keccak256(a[:])), nibbles(crypto.Keccak256(b[:]))
	if ka[0] == kb[0] {
		w.t.Fatal("fixture: the two keys share their first nibble")
	}
	la, lb := accountLeaf(a, balA, ka[1:]), accountLeaf(b, balB, kb[1:])
	items := make([][]byte, 17)
	for i := range items {
		items[i] = rlp.EncodeBytes(nil)
	}
	items[ka[0]] = rlp.EncodeBytes(crypto.Keccak256(la))
	items[kb[0]] = rlp.EncodeBytes(crypto.Keccak256(lb))
	branch := rlp.EncodeList(items...)
	var root [32]byte
	copy(root[:], crypto.Keccak256(branch))
	for _, n := range []struct {
		addr [20]byte
		leaf []byte
	}{{a, la}, {b, lb}} {
		if _, err := mpt.VerifyProof(root, crypto.Keccak256(n.addr[:]), [][]byte{branch, n.leaf}); err != nil {
			w.t.Fatalf("fixture trie does not verify: %v", err)
		}
	}
	w.n++
	w.hdr(w.n, root, [32]byte{}, [32]byte{})
	enc := func(leaf []byte) *AccountProof {
		return &AccountProof{BlockHeight: w.n, Proof: base64.StdEncoding.EncodeToString(append(append([]byte{}, branch...), leaf...))}
	}
	return enc(la), enc(lb)
}

// C2: every fund-holding generation proven at one header; a shortfall over
// the gap halts ("si"), a later full custody lifts it; partial proofs wait.
func TestC2_CustodyProofHaltsAndLifts(t *testing.T) {
	w := newMigWorld(t) // gen 0 retiring, gen 1 active; booked custody 3.5 ETH
	prove := func(gen uint32, p *AccountProof) (string, error) {
		return HandleProveCustody(&ProveCustodyParams{Gen: gen, Proof: p})
	}
	both := func(b0, b1 string) (string, error) {
		t.Helper()
		p0, p1 := w.twoAccounts(w.gen0, wei(b0), w.gen1, wei(b1))
		if out, err := prove(1, p1); err != nil || !strings.Contains(out, "1 of 2") {
			t.Fatalf("first generation: %q %v", out, err)
		}
		return prove(0, p0)
	}

	if out, err := both("1000000000000000000", "2500000000000000000"); err != nil || SolvencyHalted() || !strings.Contains(out, "custody held") {
		t.Fatalf("3.5 ETH held for 3.5 booked: %q %v halted=%v", out, err, SolvencyHalted())
	}
	if _, ok := sdk.TestStateGet(constants.CustodyProofKey); ok {
		t.Fatal("a completed proof was kept")
	}
	if out, err := both("1000000000000000000", "2450000000000000000"); err != nil || SolvencyHalted() {
		t.Fatalf("0.05 ETH short (the gap): %q %v halted=%v", out, err, SolvencyHalted())
	}
	if out, err := both("1000000000000000000", "2400000000000000000"); err != nil || !SolvencyHalted() || !strings.Contains(out, "short") {
		t.Fatalf("0.1 ETH short: %q %v halted=%v", out, err, SolvencyHalted())
	}
	found := false
	for _, l := range sdk.TestLogs() {
		found = found || strings.HasPrefix(l, "security|evm-custody-short|")
	}
	if !found {
		t.Fatal("no security log for the shortfall")
	}
	if _, err := both("1000000000000000000", "2500000000000000000"); err != nil || SolvencyHalted() {
		t.Fatalf("custody back: %v halted=%v", err, SolvencyHalted())
	}
	if _, ok := sdk.TestStateGet(constants.SolvencyHaltKey); ok {
		t.Fatal("lifted by writing a value, not by deletion (the node reads any value as a halt)")
	}
}

// Proofs that would let a prover fake or block the result are refused.
func TestC2_CustodyProofRefusals(t *testing.T) {
	w := newMigWorld(t)
	prove := func(gen uint32, p *AccountProof) error {
		_, err := HandleProveCustody(&ProveCustodyParams{Gen: gen, Proof: p})
		return err
	}
	// assembling at a newer header: an older one cannot discard it
	old0, _ := w.twoAccounts(w.gen0, wei("1000000000000000000"), w.gen1, wei("2500000000000000000"))
	_, new1 := w.twoAccounts(w.gen0, wei("1000000000000000000"), w.gen1, wei("2500000000000000000"))
	if err := prove(1, new1); err != nil {
		t.Fatal(err)
	}
	if err := prove(0, old0); err == nil || !strings.Contains(err.Error(), "being assembled") {
		t.Fatalf("an older header than the one being assembled: %v", err)
	}
	// older than the newest credited deposit
	p0, _ := w.twoAccounts(w.gen0, wei("1"), w.gen1, wei("1"))
	noteCreditedDeposit(p0.BlockHeight + 1)
	if err := prove(0, p0); err == nil || !strings.Contains(err.Error(), "newest credited deposit") {
		t.Fatalf("a proof older than a credited deposit: %v", err)
	}
	// a generation that holds nothing
	_, p1 := w.twoAccounts(w.gen0, wei("1"), w.gen1, wei("1"))
	if err := prove(7, p1); err == nil || !strings.Contains(err.Error(), "holds no funds") {
		t.Fatalf("an unknown generation: %v", err)
	}
	// a proof for the wrong address fails verification, it is not a zero
	if err := prove(0, p1); err != nil && strings.Contains(err.Error(), "being assembled") {
		t.Fatal("fixture")
	} else if err == nil {
		t.Fatal("gen 1's proof was accepted as gen 0's")
	}
	// the owner's switch
	SetCustodyCheck(false)
	if err := prove(1, p1); err == nil || !strings.Contains(err.Error(), "off") {
		t.Fatalf("custody check off: %v", err)
	}
	SetCustodyCheck(true)
	if err := prove(1, p1); err != nil {
		t.Fatalf("custody check back on: %v", err)
	}
}

// A generation whose address never received anything is proven absent: 0.
// The owner's switch lifts a halt.
func TestC2_ProvenAbsenceAndSwitchLiftsTheHalt(t *testing.T) {
	w := newMigWorld(t)
	only1 := w.accountProof(w.gen1, 0, wei("3500000000000000000")) // a trie with gen 1 alone
	for _, gen := range []uint32{1, 0} {
		if _, err := HandleProveCustody(&ProveCustodyParams{Gen: gen, Proof: only1}); err != nil {
			t.Fatalf("gen %d: %v", gen, err)
		}
	}
	if SolvencyHalted() {
		t.Fatal("gen 0 proven absent (0) and gen 1 holding the whole book: halted")
	}
	short := w.accountProof(w.gen1, 0, wei("1000000000000000000"))
	for _, gen := range []uint32{1, 0} {
		if _, err := HandleProveCustody(&ProveCustodyParams{Gen: gen, Proof: short}); err != nil {
			t.Fatalf("gen %d: %v", gen, err)
		}
	}
	if !SolvencyHalted() {
		t.Fatal("2.5 ETH short: not halted")
	}
	SetCustodyCheck(false)
	if SolvencyHalted() {
		t.Fatal("switching the check off left the halt")
	}
}
