package mpt

import (
	"testing"

	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
)

// End-to-end reproduction of pentest finding EVM-C6.
//
// Bug: in VerifyProof, when a proof entry is < 32 bytes and not
// the root, the hash check is silently skipped:
//
//   nodeHash := crypto.Keccak256(nodeRLP)
//   if !bytes.Equal(nodeHash, expectedHash) {
//       if len(nodeRLP) >= 32 || i == 0 {
//           return nil, ErrRootMismatch
//       }
//       // <-- otherwise: silently fall through. Inline node check missing.
//   }
//
// In real MPT, an inline node reference IS the raw RLP bytes, not
// the hash. The fix is to compare nodeRLP to expectedHash directly
// when len(nodeRLP) < 32 (and i > 0).
//
// Pre-fix the missing check lets an attacker substitute one
// inline node for any other RLP-valid inline node — anywhere a
// branch child slot points to short bytes, the proof can be
// rewritten without disturbing the parent's stored reference.

func TestEVMC6_InlineNodeBytesMustMatchParentReference(t *testing.T) {
	// Build a branch whose child[0xa] points to a 5-byte value
	// (not a real hash, not a real inline list — the smallest
	// thing that exercises the unchecked path).
	parentRefBytes := []byte("ABCDE")

	branchChildren := make([][]byte, 17)
	for i := 0; i < 17; i++ {
		branchChildren[i] = rlp.EncodeBytes(nil)
	}
	branchChildren[0x0a] = rlp.EncodeBytes(parentRefBytes)
	branchRLP := rlp.EncodeList(branchChildren...)

	var root [32]byte
	copy(root[:], crypto.Keccak256(branchRLP))

	// Build a different short RLP list as proof[1] — bytes don't
	// match parentRefBytes, but len(rlpEncoding) < 32 so pre-fix
	// the hash check was silently skipped. Make it a leaf node so
	// the verifier returns a value successfully.
	//
	//   leaf := [path, value]
	//   path = 0x20 (leaf, even, no nibbles — matches an empty
	//          remaining key after the branch ate one nibble)
	// Leaf at compact path [0x30] = leaf, odd, nibbles=[0x0].
	// The branch eats nibble 0xa from the key, leaving nibble 0x0
	// remaining, which this leaf consumes. Value is "X".
	leafRLP := rlp.EncodeList(
		rlp.EncodeBytes([]byte{0x30}),
		rlp.EncodeBytes([]byte("X")),
	)
	if len(leafRLP) >= 32 {
		t.Fatalf("test setup invariant: forged inline proof must be <32 bytes, got %d", len(leafRLP))
	}

	// Key 0xa0 = nibbles [0xa, 0x0]. Branch eats 0xa, leaf
	// matches the remaining 0x0 → value "X".
	key := []byte{0xa0}

	val, err := VerifyProof(root, key, [][]byte{branchRLP, leafRLP})
	if err == nil {
		t.Fatalf(
			"EVM-C6 leak: VerifyProof returned %q for an inline-position proof "+
				"entry whose bytes do NOT match the parent's stored reference. "+
				"An attacker who can craft a short alternative node can forge "+
				"proofs for any branch slot that holds short bytes.",
			val)
	}
	if err != ErrRootMismatch {
		// Other errors are acceptable post-fix as long as we
		// don't return a value successfully — but ErrRootMismatch
		// is the canonical answer for "this node doesn't match
		// what the parent committed to."
		t.Logf("post-fix error %v (acceptable; we just need rejection)", err)
	}
}
