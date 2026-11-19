package mapping

import (
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
)

// codeProof plants a header whose state trie holds addr with the given code
// hash and returns its proof.
func (w *migWorld) codeProof(addr [20]byte, codeHash []byte) *AttestDepositContractParams {
	acct := rlp.EncodeList(rlp.EncodeUint64(1), rlp.EncodeBigInt(new(big.Int)), rlp.EncodeBytes(emptyTrieRoot[:]), rlp.EncodeBytes(codeHash))
	leaf := rlp.EncodeList(rlp.EncodeBytes(append([]byte{0x20}, crypto.Keccak256(addr[:])...)), rlp.EncodeBytes(acct))
	var root [32]byte
	copy(root[:], crypto.Keccak256(leaf))
	w.n++
	w.hdr(w.n, root, [32]byte{}, [32]byte{})
	return &AttestDepositContractParams{BlockHeight: w.n, Proof: base64.StdEncoding.EncodeToString(leaf)}
}

var someCodeHash = crypto.Keccak256([]byte("magideposit runtime"))

// I-28: depositAddress names the active generation's MagiDeposit only once
// its code is proven; a proof showing no code, a proof for another address
// and a proof at an unstored header are refused; a second attestation is a
// no-op.
func TestI28_DepositAddressIsShownOnlyOnceItsCodeIsProven(t *testing.T) {
	w := newMigWorld(t)
	if _, ok := ActiveDepositAddress(); ok {
		t.Fatal("depositAddress named a MagiDeposit nobody proved deployed")
	}
	dc := DepositContractAddress(w.gen1)

	// The address exists but has no code (an EOA's code hash).
	p := w.codeProof(dc, emptyCodeHash)
	p.Gen = 1
	if _, err := HandleAttestDepositContract(p); err == nil || !strings.Contains(err.Error(), "no code") {
		t.Fatalf("attested an address with no code: %v", err)
	}
	if DepositContractAttested(1) {
		t.Fatal("recorded an attestation the proof did not support")
	}
	// Code, but at another address than gen 1's MagiDeposit.
	p = w.codeProof(DepositContractAddress(w.gen0), someCodeHash)
	p.Gen = 1
	if _, err := HandleAttestDepositContract(p); err == nil {
		t.Fatal("attested gen 1 with a proof of gen 0's MagiDeposit")
	}
	// A header the bridge does not hold.
	if _, err := HandleAttestDepositContract(&AttestDepositContractParams{Gen: 1, BlockHeight: w.n + 50, Proof: p.Proof}); err == nil {
		t.Fatal("attested at an unstored header")
	}
	if _, ok := ActiveDepositAddress(); ok {
		t.Fatal("depositAddress shown after refused attestations")
	}

	p = w.codeProof(dc, someCodeHash)
	p.Gen = 1
	out, err := HandleAttestDepositContract(p)
	if err != nil || !strings.Contains(out, "attested MagiDeposit") {
		t.Fatalf("attest: %q %v", out, err)
	}
	if got, ok := ActiveDepositAddress(); !ok || got != dc {
		t.Fatalf("depositAddress after the attestation: %x %v, want %x", got, ok, dc)
	}
	if out, err := HandleAttestDepositContract(p); err != nil || !strings.Contains(out, "already attested") {
		t.Fatalf("second attestation: %q %v", out, err)
	}
}

// A rotation hides the deposit address again until the NEW generation's
// MagiDeposit is proven; a pending generation can be attested before its
// activation (its TSS key's address), so the address is ready at activation.
func TestI28_EachGenerationIsAttestedOnItsOwn(t *testing.T) {
	w := newMigWorld(t)
	p := w.codeProof(DepositContractAddress(w.gen1), someCodeHash)
	p.Gen = 1
	if _, err := HandleAttestDepositContract(p); err != nil {
		t.Fatal(err)
	}
	gen2, _, err := MintNextGeneration(uint32(w.n))
	if err != nil {
		t.Fatal(err)
	}
	// Before keygen the pending generation has no address to prove.
	if _, err := HandleAttestDepositContract(&AttestDepositContractParams{Gen: gen2, BlockHeight: w.n, Proof: p.Proof}); err == nil {
		t.Fatal("attested a generation with no key yet")
	}
	sdk.StubSetTssKeyFor(VaultKeyName(gen2), "active,"+testPub3+",ecdsa,1,1")
	addr3, _ := crypto.HexToAddress(testAdr3)
	p2 := w.codeProof(DepositContractAddress(addr3), someCodeHash)
	p2.Gen = gen2
	if _, err := HandleAttestDepositContract(p2); err != nil {
		t.Fatalf("attest the pending generation: %v", err)
	}
	if got, _ := ActiveDepositAddress(); got != DepositContractAddress(w.gen1) {
		t.Fatalf("before activation the address is still gen 1's: %x", got)
	}
	if _, _, _, err := ActivatePendingGeneration(uint32(w.n)); err != nil {
		t.Fatal(err)
	}
	if got, ok := ActiveDepositAddress(); !ok || got != DepositContractAddress(addr3) {
		t.Fatalf("after activation: %x %v, want gen %d's", got, ok, gen2)
	}

	// Activated without an attestation: hidden.
	gen3, _, err := MintNextGeneration(uint32(w.n))
	if err != nil {
		t.Fatal(err)
	}
	sdk.StubSetTssKeyFor(VaultKeyName(gen3), "active,"+testPub1+",ecdsa,1,1")
	if _, _, _, err := ActivatePendingGeneration(uint32(w.n)); err != nil {
		t.Skipf("gen 3 activation not possible in this world (%v); the rotation case above stands", err)
	}
	if _, ok := ActiveDepositAddress(); ok {
		t.Fatal("a new generation's MagiDeposit was shown without an attestation")
	}
}
