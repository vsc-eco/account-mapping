package mapping

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"evm-mapping-contract/contract/crypto"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/sdk"
)

// D8: a pause must not block confirmSpend, which only records an L1 fact. Here
// the call still fails (there is no pending withdrawal), but never on the pause.
func TestD8_ConfirmSpendIsNotPauseGated(t *testing.T) {
	sdk.ResetTestState()
	defer sdk.ResetTestState()
	sdk.StateSetObject(constants.PausedKey, "1")
	err := HandleConfirmSpend(&ConfirmSpendRequest{}, 1)
	if err != nil && strings.Contains(err.Error(), "paused") {
		t.Fatalf("confirmSpend refused by the pause: %v", err)
	}
	// Control: the pause still stops new withdrawals.
	sdk.SetTestCaller("hive:alice")
	if _, err := HandleUnmapETH(&TransferParams{Amount: "1", To: "0x00000000000000000000000000000000000000e2", Asset: "eth"}, [20]byte{1}, 1); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatalf("unmapETH while paused = %v, want the pause refusal", err)
	}
}

// erc20RollWorld is newRollWorld with the withdrawal an ERC-20 one: 5 USDC to
// 0x..e2 through token 0x..a0.
func erc20RollWorld(t *testing.T) (*rollWorld, [20]byte, [20]byte, *big.Int) {
	w := newRollWorld(t)
	token, _ := crypto.HexToAddress("0x00000000000000000000000000000000000000a0")
	to, _ := crypto.HexToAddress("0x00000000000000000000000000000000000000e2")
	amount := big.NewInt(5_000_000)
	StorePendingSpend(PendingSpend{Nonce: 0, Amount: amount, From: "hive:alice", To: "0x00000000000000000000000000000000000000e2",
		Asset: "usdc", TokenAddress: "0x00000000000000000000000000000000000000a0",
		UnsignedTxHex: hex.EncodeToString(BuildERC20WithdrawalTx(1, 0, 2_000_000_000, 40_000_000_000, token, to, amount)),
		BlockHeight:   100, VaultAtQueue: senderAddrFromPriv(t, rollVaultPriv), GasCost: big.NewInt(0)})
	SetSupply("usdc", Supply{Active: new(big.Int), User: new(big.Int), Fee: new(big.Int)})
	return w, token, to, amount
}

// A04: while paused, confirmSpend still settles a paid withdrawal (it credits
// nothing) but no proof-based refund credits anyone until the unpause.
func TestA04_PausedRefundsWait(t *testing.T) {
	defer sdk.ResetStubState()
	// A reverted ETH withdrawal: refused while paused, refunded after.
	w := newRollWorld(t)
	sdk.StateSetObject(constants.PausedKey, "1")
	req := w.mine(101, GetPendingSpend(0).UnsignedTxHex, 0)
	if err := HandleConfirmSpend(req, 1); err == nil || !strings.Contains(err.Error(), "A04") {
		t.Fatalf("refund while paused: %v", err)
	}
	if GetBalance("hive:alice", "eth").Sign() != 0 || GetConfirmedNonce() != 0 {
		t.Fatal("a refused refund changed state")
	}
	sdk.StateDeleteObject(constants.PausedKey)
	if err := HandleConfirmSpend(req, 1); err != nil || GetBalance("hive:alice", "eth").Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("refund after the unpause: %v, balance %s", err, GetBalance("hive:alice", "eth"))
	}

	// A paid withdrawal settles while paused.
	w = newRollWorld(t)
	sdk.StateSetObject(constants.PausedKey, "1")
	if err := HandleConfirmSpend(w.mine(101, GetPendingSpend(0).UnsignedTxHex, 1), 1); err != nil || GetConfirmedNonce() != 1 {
		t.Fatalf("settlement while paused: %v n=%d", err, GetConfirmedNonce())
	}

	// A rolled withdrawal whose roll mined: its refund waits too.
	w = newRollWorld(t)
	w.last = 100 + constants.WithdrawalRollWindow
	w.header(w.last, [32]byte{}, [32]byte{})
	if err := w.roll(); err != nil {
		t.Fatal(err)
	}
	sdk.StateSetObject(constants.PausedKey, "1")
	if err := HandleConfirmSpend(w.mine(w.last+1, GetPendingSpend(0).UnsignedTxHex, 1), 1); err == nil || !strings.Contains(err.Error(), "A04") {
		t.Fatalf("rolled-back refund while paused: %v", err)
	}
}

// A36: an ERC-20 withdrawal is paid only with its Transfer log; a token that
// returns false (status 1, nothing moved) is refunded, and a Transfer of
// another amount or to another recipient is not taken as payment.
func TestA36_TokenWithdrawalNeedsItsTransfer(t *testing.T) {
	defer sdk.ResetStubState()
	for name, log := range map[string]func(w *rollWorld, token, to [20]byte, amt *big.Int) [][]byte{
		"no log": func(*rollWorld, [20]byte, [20]byte, *big.Int) [][]byte { return nil },
		"another amount": func(w *rollWorld, token, to [20]byte, amt *big.Int) [][]byte {
			return [][]byte{rp7Log(token, word32(new(big.Int).Sub(amt, big.NewInt(1))), TransferEventSig[:], addrTopic(w.vault), addrTopic(to))}
		},
		"another recipient": func(w *rollWorld, token, _ [20]byte, amt *big.Int) [][]byte {
			return [][]byte{rp7Log(token, word32(amt), TransferEventSig[:], addrTopic(w.vault), addrTopic([20]byte{0xee}))}
		},
		"another token": func(w *rollWorld, _, to [20]byte, amt *big.Int) [][]byte {
			return [][]byte{rp7Log([20]byte{0xbb}, word32(amt), TransferEventSig[:], addrTopic(w.vault), addrTopic(to))}
		},
	} {
		w, token, to, amt := erc20RollWorld(t)
		req := w.mine(101, GetPendingSpend(0).UnsignedTxHex, 1, log(w, token, to, amt)...)
		req.IntentAsset, req.IntentAmount = "usdc", amt.String()
		if err := HandleConfirmSpend(req, 1); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if GetBalance("hive:alice", "usdc").Cmp(amt) != 0 || GetConfirmedNonce() != 1 {
			t.Errorf("%s: withdrawer holds %s (want the %s refunded), n=%d", name, GetBalance("hive:alice", "usdc"), amt, GetConfirmedNonce())
		}
	}
	// With its Transfer it settles, nothing refunded.
	w, token, to, amt := erc20RollWorld(t)
	req := w.mine(101, GetPendingSpend(0).UnsignedTxHex, 1, rp7Log(token, word32(amt), TransferEventSig[:], addrTopic(w.vault), addrTopic(to)))
	req.IntentAsset, req.IntentAmount = "usdc", amt.String()
	if err := HandleConfirmSpend(req, 1); err != nil || GetBalance("hive:alice", "usdc").Sign() != 0 || GetConfirmedNonce() != 1 {
		t.Fatalf("paid withdrawal: %v, balance %s n=%d", err, GetBalance("hive:alice", "usdc"), GetConfirmedNonce())
	}
}

// A35 + N-01: a reverted ERC-20 withdrawal is refunded less its revert fee
// whichever path proves the revert (confirmSpend, or the withdrawer's own
// cancelMyWithdrawal with the same receipt, which used to refund it all), and
// the fee goes to RevertFeeRecipient, not the contract owner. A rolled
// withdrawal (stuck, never reverted) is refunded in full.
func TestA35N01_RevertFeeOnEveryProvenRevert(t *testing.T) {
	defer sdk.ResetStubState()
	fee := big.NewInt(1_000_000)
	for _, path := range []string{"confirmSpend", "cancelMyWithdrawal"} {
		w, _, _, amt := erc20RollWorld(t)
		sdk.SetTestEnvKey("contract.owner", "hive:owner")
		ps := GetPendingSpend(0)
		ps.RevertFee = fee
		StorePendingSpend(*ps)
		req := w.mine(101, ps.UnsignedTxHex, 0)
		req.IntentAsset, req.IntentAmount = "usdc", amt.String()
		var err error
		if path == "confirmSpend" {
			err = HandleConfirmSpend(req, 1)
		} else {
			w.caller("hive:alice")
			err = HandleCancelMyWithdrawal(0, dropProof(req, 0), 1)
		}
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		want := new(big.Int).Sub(amt, fee)
		if GetBalance("hive:alice", "usdc").Cmp(want) != 0 || GetBalance(constants.RevertFeeRecipient, "usdc").Cmp(fee) != 0 || GetBalance("hive:owner", "usdc").Sign() != 0 {
			t.Errorf("%s: withdrawer %s (want %s), fee recipient %s (want %s), owner %s (want 0)", path,
				GetBalance("hive:alice", "usdc"), want, GetBalance(constants.RevertFeeRecipient, "usdc"), fee, GetBalance("hive:owner", "usdc"))
		}
	}
	// Rolled (stuck, not reverted): no revert fee.
	w, _, _, amt := erc20RollWorld(t)
	ps := GetPendingSpend(0)
	ps.RevertFee = fee
	StorePendingSpend(*ps)
	w.last = 100 + constants.WithdrawalRollWindow
	w.header(w.last, [32]byte{}, [32]byte{})
	if err := w.roll(); err != nil {
		t.Fatal(err)
	}
	req := w.mine(w.last+1, GetPendingSpend(0).UnsignedTxHex, 1)
	req.IntentAsset, req.IntentAmount = "usdc", amt.String()
	if err := HandleConfirmSpend(req, 1); err != nil {
		t.Fatal(err)
	}
	if GetBalance("hive:alice", "usdc").Cmp(amt) != 0 || GetBalance(constants.RevertFeeRecipient, "usdc").Sign() != 0 {
		t.Fatalf("rolled: withdrawer %s, fee recipient %s: want the whole amount back and no fee", GetBalance("hive:alice", "usdc"), GetBalance(constants.RevertFeeRecipient, "usdc"))
	}
}
