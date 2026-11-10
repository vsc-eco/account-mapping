package mapping

import (
	"math/big"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// STALE-BOOK-1: once a superseded generation's ETH sweep was built from a
// balance proven at block P, an ETH deposit mined at or before P went with that
// sweep, so mapping it later must not grow the generation's book (the book
// would never empty and NN#3 would refuse every later rotation). A deposit
// mined after P is still at the old address and is booked. Tokens are swept by
// book, so a token deposit is always booked.
func TestStaleBook1_PreProofETHDepositIsNotBookedToTheSweptGeneration(t *testing.T) {
	sdk.ResetStubState()
	sdk.ResetTestState()
	gen := fundHoldingGen{Vault: Vault{Generation: 0, Status: VaultStatusRetiring}, Address: [20]byte{1}}
	at := func(l1 uint64) *depositTargetSet {
		return &depositTargetSet{gens: []fundHoldingGen{gen}, matched: gen.Address, l1: l1}
	}
	one := big.NewInt(1e18)

	// No ETH sweep yet: booked as before.
	at(100).book(constants.NativeAsset, one)
	if b := VaultBook(0, constants.NativeAsset); b.Cmp(one) != 0 {
		t.Fatalf("before any sweep: book %s, want 1e18", b)
	}

	// The ETH sweep is built from a proof at block 103.
	sdk.StateSetObject(constants.ETHSweptPrefix+"0", "103")
	at(102).book(constants.NativeAsset, one) // mined before the proof: went with the sweep
	at(103).book(constants.NativeAsset, one) // mined in the proof block: went with the sweep
	if b := VaultBook(0, constants.NativeAsset); b.Cmp(one) != 0 {
		t.Fatalf("deposits at or before the proof block were booked: book %s, want 1e18", b)
	}
	at(104).book(constants.NativeAsset, one) // mined after the proof: still at the old address
	if b := VaultBook(0, constants.NativeAsset); b.Cmp(big.NewInt(2e18)) != 0 {
		t.Fatalf("deposit after the proof block: book %s, want 2e18", b)
	}
	at(102).book("USDC", big.NewInt(5_000_000)) // tokens are swept by book
	if b := VaultBook(0, "USDC"); b.Cmp(big.NewInt(5_000_000)) != 0 {
		t.Fatalf("token deposit: book %s, want 5000000", b)
	}

	// A marker written before the proof block was kept ("1") books as before.
	sdk.ResetStubState()
	sdk.ResetTestState()
	sdk.StateSetObject(constants.ETHSweptPrefix+"0", "1")
	at(102).book(constants.NativeAsset, one)
	if b := VaultBook(0, constants.NativeAsset); b.Cmp(one) != 0 {
		t.Fatalf("legacy marker: book %s, want 1e18", b)
	}
}
