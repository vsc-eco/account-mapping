package blocklist

import (
	"encoding/hex"
	"strings"
	"testing"

	"evm-mapping-contract/contract/crypto"
)

// End-to-end reproduction of pentest finding EVM-C2.
//
// Bug: HandleAddBlocks stores oracle-supplied headers verbatim
// without any chain-linkage check. EthBlockHeader has no ParentHash
// field; the BLS quorum (verified at the transaction-pool layer)
// is the only protection. If 2/3 of validators collude — or a
// single oracle is compromised and can produce an arbitrary
// individual header — they can submit fake headers, then fake
// deposit proofs against those headers, and steal vault funds.
//
// Compare with the BTC bridge which does PoW + parent-chain
// linkage at blocklist.go:140-151 in utxo-mapping. EVM mapping
// has neither. The fix introduces an in-contract parent_hash
// chain: each new header carries a ParentHash that must equal
// the keccak256 of the serialized previous tip.
//
// Pre-fix: HandleAddBlocks accepts any sequence of headers
// without checking how they link.
// Post-fix: a header that doesn't reference the previous tip
// by hash is rejected with a parent-hash error.

func TestEVMC2_AddBlocksRejectsBrokenParentChain(t *testing.T) {
	// Seed: block 100. The hash this seed exposes via Keccak256
	// of its Serialize() output is what block 101 must reference
	// in ParentHash.
	seed := AddBlockEntry{
		BlockNumber:      100,
		StateRoot:        strings.Repeat("a1", 32),
		TransactionsRoot: strings.Repeat("b2", 32),
		ReceiptsRoot:     strings.Repeat("c3", 32),
		BaseFeePerGas:    1000000000,
		GasLimit:         30000000,
		Timestamp:        2_000_000_000,
	}
	if err := HandleSeedBlock(&seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Build block 101 with a wrong parent hash (random bytes).
	wrongParent := strings.Repeat("ff", 32)
	add := &AddBlocksParams{
		Blocks: []AddBlockEntry{
			{
				BlockNumber:      101,
				ParentHash:       wrongParent,
				StateRoot:        strings.Repeat("d4", 32),
				TransactionsRoot: strings.Repeat("e5", 32),
				ReceiptsRoot:     strings.Repeat("f6", 32),
				BaseFeePerGas:    1100000000,
				GasLimit:         30000000,
				Timestamp:        2_000_000_012,
			},
		},
	}

	err := HandleAddBlocks(add)
	if err == nil {
		t.Fatalf(
			"EVM-C2 leak: HandleAddBlocks accepted a block whose parent_hash " +
				"does not match the previous tip's hash. Oracle compromise / " +
				"validator collusion can submit any header chain.")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "parent") {
		t.Errorf("expected parent-hash mismatch error, got: %v", err)
	}
}

func TestEVMC2_AddBlocksAcceptsCorrectParentChain(t *testing.T) {
	// Seed and then a valid extension must continue to work.
	seed := AddBlockEntry{
		BlockNumber:      200,
		StateRoot:        strings.Repeat("11", 32),
		TransactionsRoot: strings.Repeat("22", 32),
		ReceiptsRoot:     strings.Repeat("33", 32),
		BaseFeePerGas:    1000000000,
		GasLimit:         30000000,
		Timestamp:        2_100_000_000,
	}
	if err := HandleSeedBlock(&seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Compute the expected parent hash from the seed header's
	// serialized form.
	prevHeader := GetHeader(200)
	if prevHeader == nil {
		t.Fatalf("expected seeded header to be retrievable")
	}
	expectedParent := crypto.Keccak256Hash([]byte(prevHeader.Serialize()))

	add := &AddBlocksParams{
		Blocks: []AddBlockEntry{
			{
				BlockNumber:      201,
				ParentHash:       hex.EncodeToString(expectedParent[:]),
				StateRoot:        strings.Repeat("44", 32),
				TransactionsRoot: strings.Repeat("55", 32),
				ReceiptsRoot:     strings.Repeat("66", 32),
				BaseFeePerGas:    1100000000,
				GasLimit:         30000000,
				Timestamp:        2_100_000_012,
			},
		},
	}

	if err := HandleAddBlocks(add); err != nil {
		t.Fatalf("EVM-C2 fix over-aggressive: a correctly-chained block was rejected: %v", err)
	}

	// Verify the tip moved.
	if got := GetLastHeight(); got != 201 {
		t.Errorf("expected last height 201, got %d", got)
	}
}
