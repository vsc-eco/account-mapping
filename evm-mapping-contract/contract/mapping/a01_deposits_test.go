package mapping

import (
	"encoding/hex"
	"math/big"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// a01Registry gives the rp7 world four generations. Generation 0 is Draining
// at rp7Vault (its address planted in the cache, so the real Sepolia deposit
// tx to rp7Vault lands on a superseded generation); 1 Active at testAdr2; 2
// Purged at testAdr3; 3 Pending.
func a01Registry(t *testing.T, gen0Status VaultStatus) {
	t.Helper()
	var fake CompressedPubKey
	fake[0] = 0x02
	fake[32] = 0x01
	SaveVaultState(VaultRegistry{
		{Generation: 0, Primary: fake, Status: gen0Status, Predecessor: 0},
		{Generation: 1, Primary: pubOf(t, testPub2), Status: VaultStatusActive, Predecessor: 0},
		{Generation: 2, Primary: pubOf(t, testPub3), Status: VaultStatusPurged, Predecessor: 0},
		{Generation: 3, Status: VaultStatusPending, Predecessor: 1},
	}, 4, 1)
	sdk.StateSetObject(constants.VaultAddrCachePrefix+"0", hex.EncodeToString(fake[:])+"|0x"+hex.EncodeToString(rp7Vault[:]))
}

func a01Addr(t *testing.T, h string) [20]byte {
	t.Helper()
	b, _ := hex.DecodeString(h[2:])
	var a [20]byte
	copy(a[:], b)
	return a
}

// A01: a deposit is credited at any fund-holding generation's address or
// MagiDeposit, and a superseded generation's book grows by what reached it.
func TestA01_DepositsReachEveryFundHoldingGeneration(t *testing.T) {
	for _, st := range []VaultStatus{VaultStatusDraining, VaultStatusInactive, VaultStatusRetiring} {
		w := newRP7World(t)
		a01Registry(t, st)
		active := a01Addr(t, testAdr2)
		purged := a01Addr(t, testAdr3)

		// ERC-20 to the active generation: credited, no book (derived).
		n, rc, nodes := w.mine(1, transferLog(rp7USDC, rp7User, active, 5_000_000))
		if err := mapERC20(n, rc, nodes, 0); err != nil {
			t.Fatalf("%v: token deposit to the active generation: %v", st, err)
		}
		if b := VaultBook(1, "USDC"); b.Sign() != 0 {
			t.Fatalf("%v: active generation booked %s", st, b)
		}

		// ERC-20 to the superseded generation: credited and booked.
		n, rc, nodes = w.mine(1, transferLog(rp7USDC, rp7User, rp7Vault, 7_000_000))
		if err := mapERC20(n, rc, nodes, 0); err != nil {
			t.Fatalf("%v: late token deposit: %v", st, err)
		}
		if b := VaultBook(0, "USDC"); b.Cmp(big.NewInt(7_000_000)) != 0 {
			t.Fatalf("%v: superseded book %s, want 7000000", st, b)
		}
		if s := GetSupply("USDC"); s.Active.Cmp(big.NewInt(12_000_000)) != 0 {
			t.Fatalf("%v: supply %s, want both deposits", st, s.Active)
		}

		// A purged generation's address is retired: not credited.
		n, rc, nodes = w.mine(1, transferLog(rp7USDC, rp7User, purged, 9_000_000))
		if err := mapERC20(n, rc, nodes, 0); err == nil {
			t.Fatalf("%v: a deposit to a purged generation was credited", st)
		}

		// MagiDeposit of the superseded generation, then of the active one.
		n, _, nodes = w.mine(1, depositLog(DepositContractAddress(rp7Vault), rp7User, [20]byte{}, big.NewInt(3e16), "hive:bob"))
		if err := mapContract(n, nodes, 0); err != nil {
			t.Fatalf("%v: MagiDeposit of the superseded generation: %v", st, err)
		}
		if b := VaultBook(0, "eth"); b.Cmp(big.NewInt(3e16)) != 0 {
			t.Fatalf("%v: eth book %s after a MagiDeposit deposit", st, b)
		}
		n, _, nodes = w.mine(1, depositLog(DepositContractAddress(active), rp7User, [20]byte{}, big.NewInt(4e16), "hive:bob"))
		if err := mapContract(n, nodes, 0); err != nil {
			t.Fatalf("%v: MagiDeposit of the active generation: %v", st, err)
		}
		if b := VaultBook(0, "eth"); b.Cmp(big.NewInt(3e16)) != 0 {
			t.Fatalf("%v: the active generation's deposit was booked to generation 0 (%s)", st, b)
		}
		n, _, nodes = w.mine(1, depositLog(DepositContractAddress(purged), rp7User, [20]byte{}, big.NewInt(4e16), "hive:bob"))
		if err := mapContract(n, nodes, 0); err == nil {
			t.Fatalf("%v: a purged generation's MagiDeposit was credited", st)
		}

		// A native ETH deposit (the real Sepolia tx to rp7Vault) books its whole value.
		req, _ := faildep1Block(w, 1)
		if err := HandleMap(&MapParams{TxData: req}, active, 11155111); err != nil {
			t.Fatalf("%v: native ETH to the superseded generation: %v", st, err)
		}
		want := new(big.Int).Add(big.NewInt(3e16), wei(faildep1Value))
		if b := VaultBook(0, "eth"); b.Cmp(want) != 0 {
			t.Fatalf("%v: eth book %s, want %s", st, b, want)
		}
	}
}

// Without a registry the vault the caller passes is the one target, as before.
func TestA01_NoRegistryKeepsTheSingleVault(t *testing.T) {
	w := newRP7World(t)
	n, rc, nodes := w.mine(1, transferLog(rp7USDC, rp7User, rp7Vault, 5_000_000))
	if err := mapERC20(n, rc, nodes, 0); err != nil {
		t.Fatal(err)
	}
	n, rc, nodes = w.mine(1, transferLog(rp7USDC, rp7User, a01Addr(t, testAdr2), 5_000_000))
	if err := mapERC20(n, rc, nodes, 0); err == nil {
		t.Fatal("a deposit to another address was credited")
	}
}
