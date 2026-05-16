package mpt

import (
	"bytes"
	"errors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
	"testing"
)

func TestKeyToNibbles(t *testing.T) {
	nibbles := keyToNibbles([]byte{0xab, 0xcd})
	expected := []byte{0x0a, 0x0b, 0x0c, 0x0d}
	if !bytes.Equal(nibbles, expected) {
		t.Fatalf("got %v, want %v", nibbles, expected)
	}
}

func TestCompactToNibbles(t *testing.T) {
	tests := []struct {
		name    string
		compact []byte
		nibbles []byte
		isLeaf  bool
	}{
		{"extension_even", []byte{0x00, 0xab}, []byte{0x0a, 0x0b}, false},
		{"extension_odd", []byte{0x1a, 0xbc}, []byte{0x0a, 0x0b, 0x0c}, false},
		{"leaf_even", []byte{0x20, 0xab}, []byte{0x0a, 0x0b}, true},
		{"leaf_odd", []byte{0x3a, 0xbc}, []byte{0x0a, 0x0b, 0x0c}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nibbles, isLeaf := compactToNibbles(tt.compact)
			if isLeaf != tt.isLeaf {
				t.Fatalf("isLeaf=%v, want %v", isLeaf, tt.isLeaf)
			}
			if !bytes.Equal(nibbles, tt.nibbles) {
				t.Fatalf("nibbles=%v, want %v", nibbles, tt.nibbles)
			}
		})
	}
}

// TestSimpleLeafProof builds a minimal trie with one leaf and verifies the proof.
func TestSimpleLeafProof(t *testing.T) {
	// Key nibbles: [0, 1] from byte [0x01]
	// Compact leaf encoding for even-length nibbles [0, 1]: prefix 0x20, then 0x01
	value := []byte("hello")
	leafRLP := rlp.EncodeList(
		rlp.EncodeBytes([]byte{0x20, 0x01}), // leaf, even, nibbles=[0,1]
		rlp.EncodeBytes(value),
	)

	var root [32]byte
	copy(root[:], crypto.Keccak256(leafRLP))

	key := []byte{0x01} // nibbles [0, 1]

	result, err := VerifyProof(root, key, [][]byte{leafRLP})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, value) {
		t.Fatalf("got %s, want %s", result, value)
	}
}

// TestBranchAndLeafProof builds a branch node pointing to a leaf.
func TestBranchAndLeafProof(t *testing.T) {
	// Leaf at nibble path [5] with value "world"
	value := []byte("world")
	leafRLP := rlp.EncodeList(
		rlp.EncodeBytes([]byte{0x35}), // leaf, odd, nibble=5
		rlp.EncodeBytes(value),
	)
	leafHash := crypto.Keccak256(leafRLP)

	// Branch node: child at index 0xa points to leafHash
	branchChildren := make([][]byte, 17)
	for i := 0; i < 17; i++ {
		branchChildren[i] = rlp.EncodeBytes(nil) // empty
	}
	branchChildren[0x0a] = rlp.EncodeBytes(leafHash) // child at nibble 0xa
	branchRLP := rlp.EncodeList(branchChildren...)

	var root [32]byte
	copy(root[:], crypto.Keccak256(branchRLP))

	// Key: nibbles [0xa, 5] = byte [0xa5]
	key := []byte{0xa5}

	result, err := VerifyProof(root, key, [][]byte{branchRLP, leafRLP})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, value) {
		t.Fatalf("got %s, want %s", result, value)
	}
}

// TestWrongRootFails verifies that a wrong root hash is rejected.
func TestWrongRootFails(t *testing.T) {
	leafRLP := rlp.EncodeList(
		rlp.EncodeBytes([]byte{0x31}),
		rlp.EncodeBytes([]byte("hello")),
	)

	var wrongRoot [32]byte // all zeros
	_, err := VerifyProof(wrongRoot, []byte{0x01}, [][]byte{leafRLP})
	if !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got %v", err)
	}
}

// TestEmptyProofFails verifies empty proof is rejected.
func TestEmptyProofFails(t *testing.T) {
	var root [32]byte
	_, err := VerifyProof(root, []byte{0x01}, nil)
	if !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected ErrInvalidProof, got %v", err)
	}
}

// TestTooManyNodesFails verifies proof length limit.
func TestTooManyNodesFails(t *testing.T) {
	var root [32]byte
	proof := make([][]byte, MaxProofNodes+1)
	for i := range proof {
		proof[i] = []byte{0xc0} // empty list
	}
	_, err := VerifyProof(root, []byte{0x01}, proof)
	if !errors.Is(err, ErrProofTooLong) {
		t.Fatalf("expected ErrProofTooLong, got %v", err)
	}
}
