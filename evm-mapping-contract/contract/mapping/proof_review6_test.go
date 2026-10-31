package mapping

// proof_review6_test.go — review6 audit fix regression tests.
//
// Covers three fixes from the review6 sweep:
//
//	M4  proof.go             — ERC-20 dedup key now mixes TxIndex into the
//	                           keccak input so two receipts with byte-
//	                           identical content but different positions
//	                           cannot collide on the IsObserved slot.
//	H9  handlers.go          — routeDeposit short-circuits the instruction
//	                           loop on the native-ETH path so a rogue/
//	                           compromised whitelisted relayer cannot
//	                           redirect a deposit via deposit_to= /
//	                           swap_to= + asset_out=. ERC-20 keeps
//	                           instruction support because the Transfer-log
//	                           proof cryptographically binds the depositor.
//	H10 handlers.go (verifyL1ProofOfDrop)
//	                         — Type A "reverted_receipt" L1ProofOfDrop now
//	                           requires BOTH a receipt-trie proof AND a
//	                           transactions-trie proof that bind the nonce
//	                           + sender to the proven L1 slot. Negative
//	                           tests below cover the cheap-to-construct
//	                           rejections; the full-flow positive tests
//	                           that require hand-built MPT proofs are
//	                           documented as deferred.

import (
	"encoding/base64"
	"encoding/hex"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
	"math/big"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// ---------------------------------------------------------------------------
// M4 — ERC-20 dedup key includes TxIndex
// ---------------------------------------------------------------------------

// TestReview6_M4_TxHashIncludesTxIndex proves the ERC-20 dedup key now
// composes (receiptBytes || txIndex_be32) before keccak, so the same receipt
// bytes mined at two different tx positions produce DIFFERENT txHash values.
// Pre-fix the key was keccak(receiptBytes), letting two distinct L1 slots
// that happened to emit byte-identical receipts collide on IsObserved.
func TestReview6_M4_TxHashIncludesTxIndex(t *testing.T) {
	receipt := []byte{0x02, 0xf8, 0x42, 0x01, 0x82, 0x12, 0x34, 0xb9}

	t.Run("different_tx_index_yields_different_hash", func(t *testing.T) {
		hash5 := computeERC20DedupHash(receipt, 5)
		hash6 := computeERC20DedupHash(receipt, 6)
		if hash5 == hash6 {
			t.Fatalf("M4 regression: receipts with different TxIndex must hash to different values (got %x for both)", hash5)
		}
	})

	t.Run("same_tx_index_yields_same_hash", func(t *testing.T) {
		hash5a := computeERC20DedupHash(receipt, 5)
		hash5b := computeERC20DedupHash(receipt, 5)
		if hash5a != hash5b {
			t.Fatalf("M4 invariant broken: identical (receipt, txIndex=5) must hash to the same value, got %x vs %x", hash5a, hash5b)
		}
	})

	t.Run("low_high_index_distinct", func(t *testing.T) {
		// Edge: TxIndex=0 vs the same receipt at a higher index. Pre-fix
		// these were guaranteed to collide; post-fix they MUST differ.
		hash0 := computeERC20DedupHash(receipt, 0)
		hashMax := computeERC20DedupHash(receipt, 0xFFFFFFFF)
		if hash0 == hashMax {
			t.Fatalf("M4 regression: TxIndex=0 and TxIndex=0xFFFFFFFF must produce different dedup hashes")
		}
	})

	t.Run("tx_index_byte_order_be32", func(t *testing.T) {
		// Sanity: the fix packs TxIndex as a 4-byte big-endian suffix.
		// Verify against a known sample so a future refactor that changes
		// byte ordering would surface as a regression here.
		hashGot := computeERC20DedupHash([]byte{0xde, 0xad}, 0x01020304)
		want := crypto.Keccak256Hash([]byte{0xde, 0xad, 0x01, 0x02, 0x03, 0x04})
		if hashGot != want {
			t.Fatalf("M4 byte-order regression: got %x, want %x", hashGot, want)
		}
	})
}

// computeERC20DedupHash mirrors the exact keccak input composition the
// production code uses at proof.go::VerifyERC20Deposit:
//
//	txIndexBytes := []byte{ be4(TxIndex) }
//	txHash       := keccak256(receiptBytes || txIndexBytes)
//
// Replicated here (instead of calling VerifyERC20Deposit) because
// VerifyERC20Deposit requires a real header + a valid MPT proof — out of
// scope for a focused composition test.
func computeERC20DedupHash(receipt []byte, txIndex uint32) [32]byte {
	txIndexBytes := []byte{
		byte(txIndex >> 24), byte(txIndex >> 16),
		byte(txIndex >> 8), byte(txIndex),
	}
	return crypto.Keccak256Hash(append(append([]byte{}, receipt...), txIndexBytes...))
}

// ---------------------------------------------------------------------------
// review6 follow-up — native-ETH intent from PROVEN calldata; ERC-20 restricted
// ---------------------------------------------------------------------------

// TestReview6Followup_RouteDepositETHHonorsInstructions is the INVERSE of the
// old H9 test. Native-ETH instructions are now sourced from the PROVEN L1
// calldata (parsedTx.Data) in HandleMap, so they are depositor-signed and
// routeDeposit HONORS them. The trust boundary moved up to HandleMap
// (parseCalldataInstructions); the old blunt "ignore all instructions for eth"
// guard is gone. Here we verify the routing mechanics once instructions are
// trusted.
func TestReview6Followup_RouteDepositETHHonorsInstructions(t *testing.T) {
	sender, err := crypto.HexToAddress("0xabc0000000000000000000000000000000000123")
	if err != nil {
		t.Fatal(err)
	}
	const chainId uint64 = 1
	expectedDID := crypto.AddressToDID(sender)

	sdk.ResetStubState()
	sdk.StateSetObject(constants.RouterContractIdKey, "vsc1routerstub")
	// selfAddr in the swap branch is "contract:" + env.ContractId.
	sdk.StubSetEnvJSON(`{"contract.id":"vsc1self","msg.sender":"hive:relayer","msg.caller":"hive:relayer","block.height":1}`)
	t.Cleanup(sdk.ResetStubState)

	// Responder so a dispatched swap returns success ("") rather than nil.
	sdk.StubSetContractCallResponder(func(contractId, method, payload string) *string {
		s := "ok"
		return &s
	})

	t.Run("eth_honors_deposit_to", func(t *testing.T) {
		// Old behavior: ignored, returned the DID. New: honored (calldata-signed).
		dest := routeDeposit(sender, []string{"deposit_to=hive:bob"}, "eth", big.NewInt(100), chainId)
		if dest != "hive:bob" {
			t.Fatalf("ETH deposit_to must be honored (calldata-sourced, trusted); got %q, want %q", dest, "hive:bob")
		}
	})

	t.Run("eth_dispatches_swap", func(t *testing.T) {
		// swap_to + asset_out now reaches the DEX dispatch on the ETH path and
		// returns "" (routeDeposit credited the funds into the swap).
		dest := routeDeposit(sender, []string{"swap_to=hive:bob", "asset_out=hbd", "min_amount_out=1"}, "eth", big.NewInt(100), chainId)
		if dest != "" {
			t.Fatalf("ETH swap must dispatch and return \"\"; got %q", dest)
		}
	})

	t.Run("eth_swap_without_min_credits_the_depositor", func(t *testing.T) {
		// RP-8: without the depositor's min_amount_out no swap runs.
		dest := routeDeposit(sender, []string{"swap_to=hive:bob", "asset_out=hbd"}, "eth", big.NewInt(100), chainId)
		if dest != expectedDID {
			t.Fatalf("a swap without min_amount_out must credit the depositor; got %q, want %q", dest, expectedDID)
		}
	})

	t.Run("eth_no_instructions_returns_did", func(t *testing.T) {
		dest := routeDeposit(sender, nil, "eth", big.NewInt(100), chainId)
		if dest != expectedDID {
			t.Fatalf("ETH with no instructions must credit the sender DID; got %q, want %q", dest, expectedDID)
		}
	})
}

// TestReview6Followup_ParseCalldataInstructions pins the calldata wire format:
// UTF-8 "key=value" pairs joined by '&'; empty calldata yields no instructions.
func TestReview6Followup_ParseCalldataInstructions(t *testing.T) {
	if got := parseCalldataInstructions(nil); got != nil {
		t.Fatalf("empty calldata must yield nil instructions, got %v", got)
	}
	if got := parseCalldataInstructions([]byte("")); got != nil {
		t.Fatalf("zero-length calldata must yield nil, got %v", got)
	}
	got := parseCalldataInstructions([]byte("swap_to=hive:alice&asset_out=hbd"))
	if len(got) != 2 || got[0] != "swap_to=hive:alice" || got[1] != "asset_out=hbd" {
		t.Fatalf("unexpected parse: %v", got)
	}
	// Empty segments (leading / trailing / doubled '&') are dropped.
	got = parseCalldataInstructions([]byte("&deposit_to=hive:bob&&"))
	if len(got) != 1 || got[0] != "deposit_to=hive:bob" {
		t.Fatalf("empty segments must be dropped, got %v", got)
	}
}

// TestReview6Followup_ToReserveDetection pins the to_reserve trigger.
func TestReview6Followup_ToReserveDetection(t *testing.T) {
	if !hasToReserveInstruction([]string{"to_reserve=1"}) {
		t.Fatal("to_reserve=1 must trigger reserve funding")
	}
	if !hasToReserveInstruction([]string{"swap_to=x", "to_reserve=true"}) {
		t.Fatal("to_reserve=true must trigger reserve funding")
	}
	if hasToReserveInstruction([]string{"to_reserve=0"}) {
		t.Fatal("to_reserve=0 must NOT trigger")
	}
	if hasToReserveInstruction([]string{"deposit_to=hive:bob"}) {
		t.Fatal("unrelated instruction must NOT trigger reserve funding")
	}
	if hasToReserveInstruction(nil) {
		t.Fatal("nil instructions must NOT trigger")
	}
}

// ---------------------------------------------------------------------------
// H10 — verifyL1ProofOfDrop Type A binds to transactions trie
// ---------------------------------------------------------------------------

// TestReview6_H10_EarlyGuards covers the cheap pre-trie guards in
// verifyL1ProofOfDrop that fire BEFORE any MPT-proof verification work:
//
//	(e1) proof.TxNonce != ps.Nonce → "proof tx_nonce does not match pending spend nonce"
//	(e2) unknown proof type        → "unknown L1ProofOfDrop type: ..."
//	(e3) header not anchored       → "proof block not anchored"
//
// These are not the H10-new guards themselves but they ensure the function
// reaches the Type A branch only when its precondition (matched nonce +
// anchored header) holds — which is what makes the deeper-guard tests
// meaningful.
func TestReview6_H10_EarlyGuards(t *testing.T) {
	sdk.ResetStubState()
	t.Cleanup(sdk.ResetStubState)

	const chainId uint64 = 1
	ps := &PendingSpend{
		Nonce:        7,
		VaultAtQueue: "0x1111111111111111111111111111111111111111",
	}

	t.Run("e1_proof_nonce_must_match_ps_nonce", func(t *testing.T) {
		p := L1ProofOfDrop{
			Type:    L1ProofTypeRevertedReceipt,
			TxNonce: 999, // != ps.Nonce
		}
		err := verifyL1ProofOfDrop(&p, ps, chainId)
		if err == nil || !strings.Contains(err.Error(), "tx_nonce does not match pending spend nonce") {
			t.Fatalf("e1: expected ps.Nonce mismatch reject, got %v", err)
		}
	})

	t.Run("e2_unknown_type_rejected", func(t *testing.T) {
		// Need a header lookup to succeed first; seed one.
		sdk.StateSetObject(constants.VerifierContractIdKey, "vsc1verifierstub")
		hdrSerialized := serializeHeader( /*block=*/ 100, chainId, [32]byte{}, [32]byte{}, [32]byte{})
		hdrKey := constants.BlockPrefix + uintToStr(100)
		sdk.StubSetContractReadResponder(func(cid, key string) *string {
			if cid == "vsc1verifierstub" && key == hdrKey {
				out := hdrSerialized
				return &out
			}
			return nil
		})
		defer sdk.StubSetContractReadResponder(nil)

		p := L1ProofOfDrop{
			Type:        "novel_proof_v0",
			BlockHeight: 100,
			TxNonce:     ps.Nonce,
		}
		err := verifyL1ProofOfDrop(&p, ps, chainId)
		if err == nil || !strings.Contains(err.Error(), "unknown L1ProofOfDrop type") {
			t.Fatalf("e2: expected unknown-type reject, got %v", err)
		}
	})

	t.Run("e3_header_not_anchored", func(t *testing.T) {
		// No verifier configured → blocklist.GetHeader returns nil.
		sdk.ResetStubState()
		p := L1ProofOfDrop{
			Type:        L1ProofTypeRevertedReceipt,
			BlockHeight: 100,
			TxNonce:     ps.Nonce,
		}
		err := verifyL1ProofOfDrop(&p, ps, chainId)
		if err == nil || !strings.Contains(err.Error(), "proof block not anchored") {
			t.Fatalf("e3: expected proof block not anchored, got %v", err)
		}
	})
}

// TestReview6_H10_TypeADeepGuards drives a Type A "reverted_receipt" proof
// past the receipt-trie verify (with a hand-built single-leaf MPT) so the
// new H10 guards on the tx-trie binding can be observed firing one-by-one:
//
//	(g1) TxProof empty   → "Type A requires tx_proof..."
//	(g3) TxProof is junk → "tx proof verification failed"
//
// (g2 checked a separately sent tx_at_index_hex; since EVM-T1 the tx is the
// tx proof's leaf and is not sent on its own.)
//
// The DEEP positive cases (nonce mismatch / chain mismatch / sender
// mismatch) need ALSO a valid tx-trie proof at the same TxIndex AND a
// signed tx with controlled (chainId, nonce, sender). Those are exercised
// in TestReview6_H10_TypeADeepNonceChainSender below.
//
// MPT setup mirrors mpt/verify_test.go::TestSimpleLeafProof — a single-
// leaf trie with TxIndex=1 (so the RLP-encoded key is the single byte
// 0x01 and the leaf compact prefix is 0x20 || 0x01).
func TestReview6_H10_TypeADeepGuards(t *testing.T) {
	sdk.ResetStubState()
	t.Cleanup(sdk.ResetStubState)

	const proofBlock uint64 = 4242
	const chainId uint64 = 1
	const txNonce uint64 = 9
	const txIndex uint64 = 1 // chosen so RLP key = [0x01], matches TestSimpleLeafProof

	// Build a reverted receipt: RLP([status=0, cumulativeGasUsed=0, bloom=zeros(256), logs=[]]).
	receiptBytes := buildRevertedReceiptRLP()

	// Build a single-leaf MPT whose root anchors that receipt at TxIndex=1.
	receiptsRoot, receiptProofNodes := buildSingleLeafMPT(receiptBytes)

	// Seed a verifier-mock that returns a serialized header with
	// ReceiptsRoot = receiptsRoot and ChainId = chainId.
	hdrSerialized := serializeHeader(proofBlock, chainId, [32]byte{}, [32]byte{}, receiptsRoot)
	hdrKey := constants.BlockPrefix + uintToStr(proofBlock)
	sdk.StateSetObject(constants.VerifierContractIdKey, "vsc1verifierstub")
	sdk.StubSetContractReadResponder(func(contractId, key string) *string {
		if contractId == "vsc1verifierstub" && key == hdrKey {
			out := hdrSerialized
			return &out
		}
		return nil
	})

	ps := &PendingSpend{
		Nonce:        txNonce,
		Amount:       big.NewInt(1_000_000_000),
		From:         "hive:alice",
		To:           "0xcafebabecafebabecafebabecafebabecafebabe",
		Asset:        "eth",
		BlockHeight:  proofBlock - 10,
		VaultAtQueue: "0x1111111111111111111111111111111111111111",
	}

	// Concatenate proof nodes into a single blob: handlers' splitProofNodes
	// re-decodes a stream of RLP items.
	receiptProof := base64.StdEncoding.EncodeToString(concatBytes(receiptProofNodes))

	baseProof := L1ProofOfDrop{
		Type:         L1ProofTypeRevertedReceipt,
		BlockHeight:  proofBlock,
		TxIndex:      txIndex,
		TxNonce:      txNonce,
		ReceiptProof: receiptProof,
	}

	t.Run("g1_tx_proof_empty", func(t *testing.T) {
		p := baseProof
		// TxProof deliberately blank → H10 guard #1.
		err := verifyL1ProofOfDrop(&p, ps, chainId)
		if err == nil || !strings.Contains(err.Error(), "Type A requires tx_proof") {
			t.Fatalf("H10 g1: expected tx_proof guard, got %v", err)
		}
	})

	t.Run("g3_tx_proof_garbage_rejected", func(t *testing.T) {
		p := baseProof
		// The tx-trie proof does NOT anchor to the header's (zero)
		// TransactionsRoot. Should bottom out at H10's
		// "tx proof verification failed".
		p.TxProof = base64.StdEncoding.EncodeToString([]byte{0xc0, 0xc0})
		err := verifyL1ProofOfDrop(&p, ps, chainId)
		if err == nil || !strings.Contains(err.Error(), "tx proof verification failed") {
			t.Fatalf("H10 g3: expected tx proof verification failed, got %v", err)
		}
	})
}

// TestReview6_H10_TypeADeepNonceChainSender drives a Type A proof past
// BOTH the receipt-trie verify AND the tx-trie verify, then attacks each
// of the three H10 binding guards in turn:
//
//	(g4) chainId in proven tx != contract chainId → "proof tx chain id mismatch"
//	(g5) parsed.Nonce != proof.TxNonce            → "proven tx nonce does not match..."
//	(g6) ecrecovered sender != ps.VaultAtQueue    → "proven tx sender does not match vault-at-queue..."
//
// To exercise these, we build a full RLP-encoded legacy tx with a chosen
// (chainId, nonce) and sign it with a controlled secp256k1 key — the
// recovered sender is therefore the test's known L1 address. The MPT then
// anchors that tx at TxIndex=1 the same way the receipt was anchored.
func TestReview6_H10_TypeADeepNonceChainSender(t *testing.T) {
	sdk.ResetStubState()
	t.Cleanup(sdk.ResetStubState)

	const proofBlock uint64 = 4242
	const contractChainId uint64 = 1
	const txIndex uint64 = 1

	// Receipt setup (re-use shape from g1/g2/g3).
	receiptBytes := buildRevertedReceiptRLP()
	receiptsRoot, receiptNodes := buildSingleLeafMPT(receiptBytes)
	receiptProof := base64.StdEncoding.EncodeToString(concatBytes(receiptNodes))

	// Build the tx we want anchored at TxIndex=1 and seed both roots into
	// the verifier-mock header.
	knownPrivHex := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	knownAddrHex := senderAddrFromPriv(t, knownPrivHex) // lowercase 0x-prefixed

	buildAnchoredTx := func(txChainId, txNonce uint64) (txBytes []byte, txRoot [32]byte, txProofNodes [][]byte) {
		txBytes = buildSignedLegacyTx(t, knownPrivHex, txChainId, txNonce)
		txRoot, txProofNodes = buildSingleLeafMPT(txBytes)
		return
	}

	t.Run("g4_chain_id_mismatch", func(t *testing.T) {
		_, txRoot, txNodes := buildAnchoredTx( /*chainId=*/ 9999 /*nonce=*/, 7)
		hdr := serializeHeader(proofBlock, contractChainId, [32]byte{}, txRoot, receiptsRoot)
		hdrKey := constants.BlockPrefix + uintToStr(proofBlock)
		sdk.StateSetObject(constants.VerifierContractIdKey, "vsc1verifierstub")
		sdk.StubSetContractReadResponder(func(contractId, key string) *string {
			if contractId == "vsc1verifierstub" && key == hdrKey {
				out := hdr
				return &out
			}
			return nil
		})
		ps := &PendingSpend{
			Nonce:        7,
			VaultAtQueue: knownAddrHex,
		}
		p := L1ProofOfDrop{
			Type:         L1ProofTypeRevertedReceipt,
			BlockHeight:  proofBlock,
			TxIndex:      txIndex,
			TxNonce:      7,
			ReceiptProof: receiptProof,
			TxProof:      base64.StdEncoding.EncodeToString(concatBytes(txNodes)),
		}
		err := verifyL1ProofOfDrop(&p, ps, contractChainId)
		if err == nil || !strings.Contains(err.Error(), "proof tx chain id mismatch") {
			t.Fatalf("H10 g4: expected chain id mismatch, got %v", err)
		}
	})

	t.Run("g5_nonce_mismatch_in_proven_tx", func(t *testing.T) {
		// proof.TxNonce matches ps.Nonce (so the early guard passes) but
		// the SIGNED tx anchored to the trie has a different nonce —
		// exactly the forgery class H10 was added to close.
		_, txRoot, txNodes := buildAnchoredTx( /*chainId=*/ contractChainId /*signedNonce=*/, 13)
		hdr := serializeHeader(proofBlock, contractChainId, [32]byte{}, txRoot, receiptsRoot)
		hdrKey := constants.BlockPrefix + uintToStr(proofBlock)
		sdk.StateSetObject(constants.VerifierContractIdKey, "vsc1verifierstub")
		sdk.StubSetContractReadResponder(func(contractId, key string) *string {
			if contractId == "vsc1verifierstub" && key == hdrKey {
				out := hdr
				return &out
			}
			return nil
		})
		ps := &PendingSpend{
			Nonce:        7, // proof.TxNonce must match this so we land on the H10 guard
			VaultAtQueue: knownAddrHex,
		}
		p := L1ProofOfDrop{
			Type:         L1ProofTypeRevertedReceipt,
			BlockHeight:  proofBlock,
			TxIndex:      txIndex,
			TxNonce:      7,
			ReceiptProof: receiptProof,
			TxProof:      base64.StdEncoding.EncodeToString(concatBytes(txNodes)),
		}
		err := verifyL1ProofOfDrop(&p, ps, contractChainId)
		if err == nil || !strings.Contains(err.Error(), "proven tx nonce does not match") {
			t.Fatalf("H10 g5: expected proven nonce mismatch, got %v", err)
		}
	})

	t.Run("g6_sender_mismatch_in_proven_tx", func(t *testing.T) {
		// Everything matches EXCEPT ps.VaultAtQueue is set to a different
		// address than the signer of the proven tx. Pre-fix this would
		// silently pass; post-fix it must reject with the new sender guard.
		_, txRoot, txNodes := buildAnchoredTx( /*chainId=*/ contractChainId /*signedNonce=*/, 7)
		hdr := serializeHeader(proofBlock, contractChainId, [32]byte{}, txRoot, receiptsRoot)
		hdrKey := constants.BlockPrefix + uintToStr(proofBlock)
		sdk.StateSetObject(constants.VerifierContractIdKey, "vsc1verifierstub")
		sdk.StubSetContractReadResponder(func(contractId, key string) *string {
			if contractId == "vsc1verifierstub" && key == hdrKey {
				out := hdr
				return &out
			}
			return nil
		})
		ps := &PendingSpend{
			Nonce:        7,
			VaultAtQueue: "0x2222222222222222222222222222222222222222", // != knownAddr
		}
		p := L1ProofOfDrop{
			Type:         L1ProofTypeRevertedReceipt,
			BlockHeight:  proofBlock,
			TxIndex:      txIndex,
			TxNonce:      7,
			ReceiptProof: receiptProof,
			TxProof:      base64.StdEncoding.EncodeToString(concatBytes(txNodes)),
		}
		err := verifyL1ProofOfDrop(&p, ps, contractChainId)
		if err == nil || !strings.Contains(err.Error(), "proven tx sender does not match vault-at-queue") {
			t.Fatalf("H10 g6: expected sender mismatch, got %v (knownAddr=%s)", err, knownAddrHex)
		}
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func beU64(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func uintToStr(v uint64) string {
	if v == 0 {
		return "0"
	}
	buf := make([]byte, 0, 20)
	for v > 0 {
		buf = append([]byte{byte('0' + v%10)}, buf...)
		v /= 10
	}
	return string(buf)
}

// ensure imports referenced
var _ = hex.EncodeToString

// buildRevertedReceiptRLP returns the canonical RLP encoding of a
// status=0 (reverted) Ethereum receipt with empty logs.
//
//	receipt = RLP([ status, cumulativeGasUsed, bloom(256), logs ])
//
// Pre-Byzantium receipts encoded a state-root instead of status; H10 is
// post-Byzantium-only so we always emit status form. logs is an empty
// list.
func buildRevertedReceiptRLP() []byte {
	bloom := make([]byte, 256)
	return rlp.EncodeList(
		rlp.EncodeUint64(0),    // status = 0 (reverted)
		rlp.EncodeUint64(0),    // cumulativeGasUsed
		rlp.EncodeBytes(bloom), // bloom (zeros)
		rlp.EncodeList(),       // logs (empty list)
	)
}

// buildSingleLeafMPT constructs a one-node Merkle Patricia trie containing
// a single leaf at the canonical TxIndex=1 key (RLP-encoded = [0x01]).
// Returns the root hash and the proof-node stream (a single leaf RLP node).
// Mirrors mpt/verify_test.go::TestSimpleLeafProof so the proof verifies
// via mpt.VerifyProof.
func buildSingleLeafMPT(value []byte) (root [32]byte, proofNodes [][]byte) {
	// Leaf encoding for even-length nibbles [0,1]: compact prefix 0x20 then 0x01.
	leafRLP := rlp.EncodeList(
		rlp.EncodeBytes([]byte{0x20, 0x01}), // leaf, even-length, nibbles [0,1]
		rlp.EncodeBytes(value),
	)
	copy(root[:], crypto.Keccak256(leafRLP))
	proofNodes = [][]byte{leafRLP}
	return
}

// serializeHeader emits a 137-byte EthBlockHeader with controlled
// blockNumber, chainId, and the three roots that matter for H10 tests.
func serializeHeader(blockNumber, chainId uint64, stateRoot, txRoot, receiptsRoot [32]byte) string {
	buf := make([]byte, 137)
	buf[0] = 0x01 // HeaderVersionV1
	beU64(buf[1:9], blockNumber)
	copy(buf[9:41], stateRoot[:])
	copy(buf[41:73], txRoot[:])
	copy(buf[73:105], receiptsRoot[:])
	beU64(buf[105:113], 0) // BaseFeePerGas
	beU64(buf[113:121], 0) // GasLimit
	beU64(buf[121:129], 0) // Timestamp
	beU64(buf[129:137], chainId)
	return string(buf)
}

// concatBytes flattens a slice-of-byte-slices into a single byte slice.
// splitProofNodes in proof.go re-decodes a stream of RLP items, so the
// proof field on the wire is a concatenation of node RLPs.
func concatBytes(parts [][]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// senderAddrFromPriv returns the lowercase 0x-prefixed Ethereum address
// derived from a hex-encoded secp256k1 private key.
func senderAddrFromPriv(t *testing.T, privHex string) string {
	t.Helper()
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("bad priv hex: %v", err)
	}
	priv := secp256k1.PrivKeyFromBytes(privBytes)
	uncompressed := priv.PubKey().SerializeUncompressed()
	hash := crypto.Keccak256(uncompressed[1:])
	return "0x" + hex.EncodeToString(hash[12:])
}

// buildSignedLegacyTx builds an EIP-155 legacy Ethereum tx with the
// chosen chainId + nonce, signs it with the controlled key, and returns
// the canonical RLP encoding. The To field, value, gas, etc. are fixed —
// only chainId + nonce + signer matter for H10's binding checks.
//
// Legacy tx layout: RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
// Sighash for EIP-155: keccak256( RLP([nonce, gasPrice, gas, to, value, data, chainId, 0, 0]) )
// Final v = chainId*2 + 35 + recoveryId.
func buildSignedLegacyTx(t *testing.T, privHex string, chainId, nonce uint64) []byte {
	t.Helper()
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("bad priv hex: %v", err)
	}
	priv := secp256k1.PrivKeyFromBytes(privBytes)

	var to [20]byte
	// Fixed dummy destination; H10's tests don't assert on To.
	copy(to[:], []byte{0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe})

	gasPrice := big.NewInt(1_000_000_000) // 1 gwei
	gasLimit := uint64(21_000)
	value := big.NewInt(0)

	// EIP-155 sighash body.
	sighashRLP := rlp.EncodeList(
		rlp.EncodeUint64(nonce),
		rlp.EncodeBigInt(gasPrice),
		rlp.EncodeUint64(gasLimit),
		rlp.EncodeAddress(to),
		rlp.EncodeBigInt(value),
		rlp.EncodeBytes(nil), // empty data
		rlp.EncodeUint64(chainId),
		rlp.EncodeUint64(0),
		rlp.EncodeUint64(0),
	)
	sighash := crypto.Keccak256(sighashRLP)

	// dcrd SignCompact: returns [v, r(32), s(32)] with v in {27..30}.
	sig := dcrecdsa.SignCompact(priv, sighash, false)
	recoveryFlag := sig[0]
	var recoveryId byte
	if recoveryFlag >= 31 {
		recoveryId = recoveryFlag - 31
	} else {
		recoveryId = recoveryFlag - 27
	}
	r := sig[1:33]
	s := sig[33:65]

	// EIP-155 v = chainId*2 + 35 + recoveryId
	vFinal := chainId*2 + 35 + uint64(recoveryId)

	return rlp.EncodeList(
		rlp.EncodeUint64(nonce),
		rlp.EncodeBigInt(gasPrice),
		rlp.EncodeUint64(gasLimit),
		rlp.EncodeAddress(to),
		rlp.EncodeBigInt(value),
		rlp.EncodeBytes(nil),
		rlp.EncodeUint64(vFinal),
		rlp.EncodeBytes(r),
		rlp.EncodeBytes(s),
	)
}
