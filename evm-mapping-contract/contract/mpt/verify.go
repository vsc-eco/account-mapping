package mpt

import (
	"bytes"
	"errors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
)

var (
	ErrInvalidProof  = errors.New("mpt: invalid proof")
	ErrProofTooLong  = errors.New("mpt: proof exceeds max nodes")
	ErrRootMismatch  = errors.New("mpt: root hash mismatch")
	ErrKeyNotFound   = errors.New("mpt: key not found in proof")
)

const MaxProofNodes = 20

// VerifyProof verifies that value is stored at key in the trie with the given root.
// proof is a list of RLP-encoded trie nodes from root to leaf.
func VerifyProof(root [32]byte, key []byte, proof [][]byte) ([]byte, error) {
	if len(proof) == 0 {
		return nil, ErrInvalidProof
	}
	if len(proof) > MaxProofNodes {
		return nil, ErrProofTooLong
	}

	nibbles := keyToNibbles(key)
	nibbleIdx := 0
	expectedHash := root[:]

	for i, nodeRLP := range proof {
		// Pentest finding EVM-C6: inline nodes (< 32 bytes that are
		// not the root) are referenced by their raw bytes, not by
		// their keccak256 hash. The previous code SKIPPED the hash
		// check entirely in that case, allowing an attacker who
		// could craft any RLP-valid short alternative to substitute
		// it freely.
		//
		// What the parent actually committed to is recorded in
		// expectedHash: 32 bytes for a hash reference, fewer bytes
		// for an inline reference. The check switches on that
		// length, NOT on the length of nodeRLP — the parent's
		// commitment is what defines the rule.
		if i > 0 && len(expectedHash) < 32 {
			if !bytes.Equal(nodeRLP, expectedHash) {
				return nil, ErrRootMismatch
			}
		} else {
			nodeHash := crypto.Keccak256(nodeRLP)
			if !bytes.Equal(nodeHash, expectedHash) {
				return nil, ErrRootMismatch
			}
		}

		node, err := rlp.DecodeList(nodeRLP)
		if err != nil {
			return nil, ErrInvalidProof
		}

		switch len(node) {
		case 17:
			// Branch node: 16 children + value
			if nibbleIdx >= len(nibbles) {
				// Key exhausted at branch — value is in node[16]
				return node[16].AsBytes(), nil
			}
			childIdx := nibbles[nibbleIdx]
			nibbleIdx++

			child := node[childIdx]
			if child.Data == nil && !child.IsList {
				return nil, ErrKeyNotFound
			}
			if len(child.Data) == 32 {
				expectedHash = child.Data
			} else if child.IsList {
				// Inline node — next iteration won't hash-check
				// This shouldn't happen in a valid proof (inline nodes are embedded)
				return nil, ErrInvalidProof
			} else if len(child.Data) == 0 {
				return nil, ErrKeyNotFound
			} else {
				expectedHash = child.Data
			}

		case 2:
			// Extension or leaf node
			pathItem := node[0]
			path := pathItem.AsBytes()
			if len(path) == 0 {
				return nil, ErrInvalidProof
			}

			// Decode compact (hex-prefix) encoding
			decodedNibbles, isLeaf := compactToNibbles(path)

			// Check remaining key matches the node's path
			remaining := nibbles[nibbleIdx:]
			if len(decodedNibbles) > len(remaining) {
				return nil, ErrKeyNotFound
			}
			for j, n := range decodedNibbles {
				if remaining[j] != n {
					return nil, ErrKeyNotFound
				}
			}
			nibbleIdx += len(decodedNibbles)

			if isLeaf {
				// Leaf node — value is node[1]
				if nibbleIdx != len(nibbles) {
					return nil, ErrKeyNotFound
				}
				return node[1].AsBytes(), nil
			}

			// Extension node — follow to next node
			child := node[1]
			if len(child.Data) == 32 {
				expectedHash = child.Data
			} else {
				expectedHash = child.Data
			}

		default:
			return nil, ErrInvalidProof
		}
	}

	return nil, ErrInvalidProof
}

// keyToNibbles converts a byte key to nibbles (4 bits each).
func keyToNibbles(key []byte) []byte {
	nibbles := make([]byte, len(key)*2)
	for i, b := range key {
		nibbles[i*2] = b >> 4
		nibbles[i*2+1] = b & 0x0f
	}
	return nibbles
}

// compactToNibbles decodes hex-prefix (compact) encoding used in Ethereum MPT.
// Returns the nibble path and whether it's a leaf node.
// HP encoding: first nibble flags: bit 1 = leaf, bit 0 = odd length
func compactToNibbles(compact []byte) ([]byte, bool) {
	if len(compact) == 0 {
		return nil, false
	}

	firstNibble := compact[0] >> 4
	isLeaf := firstNibble >= 2
	isOdd := firstNibble%2 == 1

	var nibbles []byte
	if isOdd {
		nibbles = append(nibbles, compact[0]&0x0f)
	}
	for _, b := range compact[1:] {
		nibbles = append(nibbles, b>>4, b&0x0f)
	}
	return nibbles, isLeaf
}

// RLPEncodeKey encodes a trie key (transaction/receipt index) to the RLP format
// used as the MPT key. In Ethereum, the key is RLP(uint(index)).
func RLPEncodeKey(index uint64) []byte {
	return rlp.EncodeUint64(index)
}
