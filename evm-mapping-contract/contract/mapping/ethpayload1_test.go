package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// ETH-PAYLOAD-1: a native ETH deposit may be proven by tx_proof (base64 tx-trie
// nodes, the leaf is the tx) instead of raw_hex + merkle_proof_hex, which carry
// the tx four times over in hex. Same tx, same checks, same observed key.

// ethPayload1TxProof turns a legacy request into its tx_proof form.
func ethPayload1TxProof(t *testing.T, req VerificationRequest) VerificationRequest {
	t.Helper()
	nodes, err := hex.DecodeString(req.MerkleProofHex)
	if err != nil {
		t.Fatal(err)
	}
	req.TxProof = base64.StdEncoding.EncodeToString(nodes)
	req.RawHex, req.MerkleProofHex = "", ""
	return req
}

func TestETHPAYLOAD1_TxProofMapsTheSameDeposit(t *testing.T) {
	w := newRP7World(t)
	legacy, _ := faildep1Block(w, 1)
	req := ethPayload1TxProof(t, legacy)
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err != nil {
		t.Fatalf("tx_proof deposit refused: %v", err)
	}
	if r := faildep1Reserve(); r != faildep1Value {
		t.Fatalf("reserve %q, want %s (the same credit as the legacy form)", r, faildep1Value)
	}
	// One deposit, one credit, whichever form comes second.
	if err := HandleMap(&MapParams{TxData: legacy}, rp7Vault, 11155111); err == nil || !strings.Contains(err.Error(), "already processed") {
		t.Fatalf("the legacy form of a deposit mapped by tx_proof: %v", err)
	}
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err == nil {
		t.Fatal("the same tx_proof deposit mapped twice")
	}
	if r := faildep1Reserve(); r != faildep1Value {
		t.Fatalf("reserve %q after the replays, want %s", r, faildep1Value)
	}
}

func TestETHPAYLOAD1_LegacyFirstThenTxProofIsRefused(t *testing.T) {
	w := newRP7World(t)
	legacy, _ := faildep1Block(w, 1)
	if err := HandleMap(&MapParams{TxData: legacy}, rp7Vault, 11155111); err != nil {
		t.Fatalf("legacy deposit refused: %v", err)
	}
	if err := HandleMap(&MapParams{TxData: ethPayload1TxProof(t, legacy)}, rp7Vault, 11155111); err == nil || !strings.Contains(err.Error(), "already processed") {
		t.Fatalf("the tx_proof form of a deposit mapped by the legacy form: %v", err)
	}
}

func TestETHPAYLOAD1_TamperedTxProofIsRefused(t *testing.T) {
	w := newRP7World(t)
	legacy, _ := faildep1Block(w, 1)
	req := ethPayload1TxProof(t, legacy)
	b, _ := base64.StdEncoding.DecodeString(req.TxProof)
	b[len(b)-40] ^= 0x01 // inside the leaf: the tx's signature
	req.TxProof = base64.StdEncoding.EncodeToString(b)
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err == nil {
		t.Fatalf("a tampered tx_proof was accepted (reserve %q)", faildep1Reserve())
	}
	req.TxProof = "%%%not-base64"
	if err := HandleMap(&MapParams{TxData: req}, rp7Vault, 11155111); err == nil || !strings.Contains(err.Error(), "tx_proof") {
		t.Fatalf("a non-base64 tx_proof: %v", err)
	}
	if r := faildep1Reserve(); r != "" && r != "0" {
		t.Fatalf("reserve %q after refused proofs", r)
	}
}

// FAILDEP-1 still holds on the new form: a reverted tx credits nothing.
func TestETHPAYLOAD1_RevertedDepositByTxProofIsNotCredited(t *testing.T) {
	w := newRP7World(t)
	legacy, _ := faildep1Block(w, 0)
	err := HandleMap(&MapParams{TxData: ethPayload1TxProof(t, legacy)}, rp7Vault, 11155111)
	if err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("a reverted deposit by tx_proof: %v (reserve %q)", err, faildep1Reserve())
	}
}
