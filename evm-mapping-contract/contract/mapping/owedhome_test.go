package mapping

import (
	"math/big"
	"slices"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

// A deposit swap that does not complete (and a contract's payout for the account
// that comes back) is owed home: held on OwedHomeHoldAccount, never on the
// address's Magi balance, and the bot sends it back to the address on
// Ethereum. A plain deposit stays refundable on the balance but is not owed:
// Altera's deposit for an Ethereum login is a plain transfer, and it must stay
// on Magi.

func ohSender() ([20]byte, string, string) {
	var a [20]byte
	a[19] = 0xd2
	return a, crypto.AddressToDID(a), crypto.AddressToHex(a)
}

func TestOwedHome_FailedDepositSwapIsOwedAPlainDepositIsNot(t *testing.T) {
	sender, did, _ := ohSender()
	sdk.ResetStubState()
	sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
	sdk.StubSetContractCallResponder(func(_, _, _ string) *string {
		r := `{"ok":false,"error":"min_amount_out not met"}`
		return &r
	})
	defer sdk.ResetStubState()
	plain, failed, unrun := big.NewInt(2e16), big.NewInt(1e16), big.NewInt(5e15)
	if dest, held := routeDeposit(sender, nil, "eth", plain, 1); dest != did || held {
		t.Fatalf("plain deposit: %s held=%v", dest, held)
	}
	if getRefundable(did, "eth").Cmp(plain) != 0 || getOwedHome(did, "eth").Sign() != 0 {
		t.Fatalf("plain deposit: refundable %s owed %s, want %s / 0", getRefundable(did, "eth"), getOwedHome(did, "eth"), plain)
	}
	if dest, held := routeDeposit(sender, []string{"swap_to=hive:bob", "asset_out=hbd", "min_amount_out=999999"}, "eth", failed, 1); dest != did || !held {
		t.Fatalf("failed swap: %s held=%v, want %s held", dest, held, did)
	}
	if getRefundable(did, "eth").Cmp(plain) != 0 || getOwedHome(did, "eth").Cmp(failed) != 0 {
		t.Fatalf("failed swap: refundable %s owed %s, want the plain only / 1e16", getRefundable(did, "eth"), getOwedHome(did, "eth"))
	}
	if l := owedHomeList(); len(l) != 1 || l[0] != "eth|"+did {
		t.Fatalf("owed list %v", l)
	}
	// A swap with no min_amount_out never runs (RP-8): also owed home.
	if _, held := routeDeposit(sender, []string{"swap_to=hive:bob", "asset_out=hbd"}, "eth", unrun, 1); !held {
		t.Fatal("an unrun swap was not held")
	}
	if getOwedHome(did, "eth").Cmp(big.NewInt(15e15)) != 0 || len(owedHomeList()) != 1 {
		t.Fatalf("owed %s, list %v", getOwedHome(did, "eth"), owedHomeList())
	}
	// deposit_to (explicit) is where its sender put it: neither.
	if dest, held := routeDeposit(sender, []string{"deposit_to=hive:bob", "swap_to=hive:bob", "asset_out=hbd", "min_amount_out=1"}, "eth", failed, 1); dest != "hive:bob" || held {
		t.Fatalf("explicit: %s held=%v", dest, held)
	}
	if getOwedHome(did, "eth").Cmp(big.NewInt(15e15)) != 0 || getOwedHome("hive:bob", "eth").Sign() != 0 {
		t.Fatal("an explicit deposit_to was marked owed")
	}
}

// ohHold holds amount owed home to did, with the supply booked.
func ohHold(did string, amount *big.Int) {
	holdOwedHome(did, "eth", amount)
	s := GetSupply("eth")
	SetSupply("eth", Supply{Active: new(big.Int).Add(s.Active, amount), User: new(big.Int).Add(s.User, amount), Fee: s.Fee})
}

// sendHome owed=1 sends what is owed from the hold, all of it; the address's
// Magi balance (a plain deposit) is not touched, not even for the proof fee.
func TestOwedHome_SendHomeOwedSendsFromTheHold(t *testing.T) {
	_, did, addr := ohSender()
	rpBridge(t, ethWei(20), did, "hive:keeper")
	SetRelayer("hive:keeper") // the bridge's bot
	start := GetBalance(did, "eth") // 10 ETH, refundable as a plain deposit
	markRefundable(did, "eth", start)
	ohHold(did, big.NewInt(2e16)) // 0.02 ETH owed (a failed swap)
	if GetBalance(did, "eth").Cmp(start) != 0 || GetBalance(constants.OwedHomeHoldAccount, "eth").Cmp(big.NewInt(2e16)) != 0 {
		t.Fatal("the owed amount was credited to the address's balance")
	}
	as(t, "hive:keeper", rpNow)
	out, err := HandleSendHome("address="+addr+"&asset=eth&owed=1", [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("sendHome owed: %q %v", out, err)
	}
	if GetBalance(did, "eth").Cmp(start) != 0 || getRefundable(did, "eth").Cmp(start) != 0 {
		t.Fatalf("balance %s refundable %s: the plain deposit must be untouched", GetBalance(did, "eth"), getRefundable(did, "eth"))
	}
	if GetBalance(constants.OwedHomeHoldAccount, "eth").Sign() != 0 || getOwedHome(did, "eth").Sign() != 0 || len(owedHomeList()) != 0 {
		t.Fatalf("hold %s owed %s list %v after sending it home", GetBalance(constants.OwedHomeHoldAccount, "eth"), getOwedHome(did, "eth"), owedHomeList())
	}
	ps := GetPendingSpend(0)
	if ps.From != constants.OwedHomeHoldAccount || ps.RefundTo != did || !strings.EqualFold(ps.To, addr) {
		t.Fatalf("owed send %+v", ps)
	}
	if want := new(big.Int).Sub(big.NewInt(2e16), ProofFee("eth")); new(big.Int).Add(ps.Amount, payoutGasFee(constants.ETHTransferGas, 1e9, 2_000_000_000)).Cmp(want) != 0 {
		t.Fatalf("sent %s: want 0.02 ETH less the proof fee and the payout fee", ps.Amount)
	}
	if _, err := HandleSendHome("address="+addr+"&asset=eth&owed=1", [20]byte{1}, 1); err == nil {
		t.Fatal("a second owed sendHome had nothing to send and must be refused")
	}
	ethInvariant(t, "after the owed sendHome")
}

// A plain sendHome sends the balance's refundable deposit and leaves what is
// held owed home alone.
func TestOwedHome_PlainSendHomeLeavesTheHeldOwed(t *testing.T) {
	_, did, addr := ohSender()
	rpBridge(t, ethWei(20), did, "hive:keeper")
	SetRelayer("hive:keeper") // the bridge's bot
	DecBalance(did, "eth", GetBalance(did, "eth"))
	s := GetSupply("eth")
	SetSupply("eth", Supply{Active: new(big.Int).Sub(s.Active, s.User), User: new(big.Int), Fee: s.Fee})
	IncBalance(did, "eth", big.NewInt(3e16))
	TrackDeposit("eth", big.NewInt(3e16), new(big.Int))
	markRefundable(did, "eth", big.NewInt(3e16))
	ohHold(did, big.NewInt(2e16))
	as(t, "hive:keeper", rpNow)
	if _, err := HandleSendHome("address="+addr+"&asset=eth", [20]byte{1}, 1); err != nil {
		t.Fatal(err)
	}
	if getRefundable(did, "eth").Sign() != 0 || getOwedHome(did, "eth").Cmp(big.NewInt(2e16)) != 0 ||
		GetBalance(constants.OwedHomeHoldAccount, "eth").Cmp(big.NewInt(2e16)) != 0 || len(owedHomeList()) != 1 {
		t.Fatalf("refundable %s owed %s hold %s list %v", getRefundable(did, "eth"), getOwedHome(did, "eth"), GetBalance(constants.OwedHomeHoldAccount, "eth"), owedHomeList())
	}
	ethInvariant(t, "after the plain sendHome")
}

// A contract's payout for the account that comes back is held and owed home,
// never credited; the account's own withdrawal to its own address is credited
// and refundable; a Magi sender (hive:) gets its own back.
func TestOwedHome_ContractPayoutBackIsHeld(t *testing.T) {
	_, did, addr := ohSender()
	sdk.ResetStubState()
	defer sdk.ResetStubState()
	var tok [20]byte
	tok[19] = 0xc0
	if err := RegisterToken(1, tok, "USDC", 6, 1000); err != nil {
		t.Fatal(err)
	}
	creditWithdrawalRefund(rtRouter, "0x00000000000000000000000000000000000000e9", did, "USDC", big.NewInt(7000), true)
	if getOwedHome(did, "USDC").Cmp(big.NewInt(7000)) != 0 || GetBalance(did, "USDC").Sign() != 0 ||
		GetBalance(constants.OwedHomeHoldAccount, "USDC").Cmp(big.NewInt(7000)) != 0 || getRefundable(did, "USDC").Sign() != 0 {
		t.Fatalf("contract payout back: owed %s balance %s hold %s", getOwedHome(did, "USDC"), GetBalance(did, "USDC"), GetBalance(constants.OwedHomeHoldAccount, "USDC"))
	}
	creditWithdrawalRefund(did, addr, did, "eth", big.NewInt(2e16), true)
	if getOwedHome(did, "eth").Sign() != 0 || getRefundable(did, "eth").Cmp(big.NewInt(2e16)) != 0 || GetBalance(did, "eth").Cmp(big.NewInt(2e16)) != 0 {
		t.Fatal("an own withdrawal back must be credited and refundable, not owed")
	}
	creditWithdrawalRefund(rtRouter, addr, "hive:alice", "eth", big.NewInt(2e16), true)
	if GetBalance("hive:alice", "eth").Cmp(big.NewInt(2e16)) != 0 || len(owedHomeList()) != 1 {
		t.Fatalf("a Magi sender's payout back: balance %s list %v", GetBalance("hive:alice", "eth"), owedHomeList())
	}
}

func TestOwedHome_ListIsBounded(t *testing.T) {
	sdk.ResetStubState()
	defer sdk.ResetStubState()
	for i := 0; i < constants.MaxOwedHomeList+5; i++ {
		var a [20]byte
		a[18], a[19] = byte(i>>8), byte(i)+1
		recordOwedHome(crypto.AddressToDID(a), "eth", big.NewInt(1e16))
	}
	if n := len(owedHomeList()); n != constants.MaxOwedHomeList {
		t.Fatalf("list holds %d, want the cap %d", n, constants.MaxOwedHomeList)
	}
}

// THORChain's refund rule: an owed amount that cannot pay its own proving fee
// is not sent (ETH to the gas reserve); anything above it is listed and goes
// home, below the 0.01 ETH minimum a withdrawal needs.
func TestOwedHome_BelowItsProofFeeIsKeptAsFee(t *testing.T) {
	_, did, addr := ohSender()
	rpBridge(t, ethWei(20), did, "hive:keeper")
	SetRelayer("hive:keeper") // the bridge's bot
	SetProofFee("eth", big.NewInt(2e15))
	reserve := getGasReserve()
	ohHold(did, big.NewInt(1e15)) // 0.001 ETH: not above its 0.002 proof fee
	if getOwedHome(did, "eth").Sign() != 0 || len(owedHomeList()) != 0 || GetBalance(constants.OwedHomeHoldAccount, "eth").Sign() != 0 {
		t.Fatalf("dust: owed %s list %v hold %s", getOwedHome(did, "eth"), owedHomeList(), GetBalance(constants.OwedHomeHoldAccount, "eth"))
	}
	if got := new(big.Int).Sub(getGasReserve(), reserve); got.Cmp(big.NewInt(1e15)) != 0 {
		t.Fatalf("reserve took %s, want the 0.001 ETH", got)
	}
	ethInvariant(t, "after the dust")
	ohHold(did, big.NewInt(6e15)) // 0.006 ETH: above its fee, below the 0.01 minimum
	if l := owedHomeList(); len(l) != 1 || l[0] != "eth|"+did {
		t.Fatalf("above its fee: list %v", l)
	}
	as(t, "hive:keeper", rpNow)
	if out, err := HandleSendHome("address="+addr+"&asset=eth&owed=1", [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("0.006 ETH owed: %q %v, want sent home", out, err)
	}
	ethInvariant(t, "after the send")
}

// An owed send that reverts on Ethereum comes back to the hold, owed again;
// after MaxOwedHomeReverts it stays held but leaves the bot's list (so the
// keeper does not burn it in gas), and a hand-made sendHome still sends it.
func TestOwedHome_RevertedOwedSendIsHeldAndStopsRetrying(t *testing.T) {
	_, did, addr := ohSender()
	rpBridge(t, ethWei(20), did, "hive:keeper")
	SetRelayer("hive:keeper") // the bridge's bot
	ohHold(did, big.NewInt(5e16))
	as(t, "hive:keeper", rpNow)
	for i := 1; i <= constants.MaxOwedHomeReverts; i++ {
		if _, err := HandleSendHome("address="+addr+"&asset=eth&owed=1", [20]byte{1}, 1); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		ps := GetPendingSpend(GetPendingNonce() - 1)
		refundRevertedWithdrawal(ps)
		if GetBalance(did, "eth").Cmp(ethWei(10_000)) != 0 {
			t.Fatalf("revert %d reached the balance: %s", i, GetBalance(did, "eth"))
		}
		if getOwedHome(did, "eth").Sign() <= 0 || owedHomeReverts(did, "eth") != uint64(i) {
			t.Fatalf("revert %d: owed %s reverts %d", i, getOwedHome(did, "eth"), owedHomeReverts(did, "eth"))
		}
		listed := len(owedHomeList()) == 1
		if listed != (i < constants.MaxOwedHomeReverts) {
			t.Fatalf("revert %d: listed=%v", i, listed)
		}
	}
	if GetBalance(constants.OwedHomeHoldAccount, "eth").Cmp(getOwedHome(did, "eth")) != 0 {
		t.Fatal("the hold does not match the record")
	}
	if out, err := HandleSendHome("address="+addr+"&asset=eth&owed=1", [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("a hand-made send after the stop: %q %v", out, err)
	}
	ethInvariant(t, "after the reverts")
}

// An entry that becomes sendable while the list is full is queued and moves
// into the list when an entry leaves it; a queued entry no longer sendable
// (sent home meanwhile) is dropped, not listed.
func TestOwedHome_OverflowRefillsTheList(t *testing.T) {
	sdk.ResetStubState()
	defer sdk.ResetStubState()
	did := func(i int) string {
		var a [20]byte
		a[18], a[19] = byte(i>>8), byte(i)+1
		return crypto.AddressToDID(a)
	}
	for i := 0; i < constants.MaxOwedHomeList+3; i++ {
		recordOwedHome(did(i), "eth", big.NewInt(1e16))
	}
	if n := len(owedHomeList()); n != constants.MaxOwedHomeList {
		t.Fatalf("list %d", n)
	}
	if h, tl := overflowBound(constants.OwedHomeOverflowHeadKey), overflowBound(constants.OwedHomeOverflowTailKey); tl-h != 3 {
		t.Fatalf("overflow %d..%d, want 3 queued", h, tl)
	}
	// Adding more to a queued entry does not queue it twice.
	recordOwedHome(did(constants.MaxOwedHomeList), "eth", big.NewInt(1e16))
	if tl := overflowBound(constants.OwedHomeOverflowTailKey); tl != 3 {
		t.Fatalf("queued twice: tail %d", tl)
	}
	// The second queued entry is sent home by someone meanwhile.
	setOwedHome(did(constants.MaxOwedHomeList+1), "eth", new(big.Int))
	// One listed entry leaves (sent home): the first queued one takes its slot.
	setOwedHome(did(0), "eth", new(big.Int))
	l := owedHomeList()
	if len(l) != constants.MaxOwedHomeList || !slices.Contains(l, "eth|"+did(constants.MaxOwedHomeList)) {
		t.Fatalf("after one exit: %d listed, first queued listed %v", len(l), slices.Contains(l, "eth|"+did(constants.MaxOwedHomeList)))
	}
	// The next exit skips the stale queued entry and lists the third.
	setOwedHome(did(1), "eth", new(big.Int))
	l = owedHomeList()
	if slices.Contains(l, "eth|"+did(constants.MaxOwedHomeList+1)) || !slices.Contains(l, "eth|"+did(constants.MaxOwedHomeList+2)) {
		t.Fatal("refill listed a stale entry or missed a live one")
	}
	if overflowBound(constants.OwedHomeOverflowTailKey) != 0 {
		t.Fatal("the emptied queue keeps its bounds")
	}
}

// A plain sendHome a contract makes for someone's deposit is not a payout: a
// contract in between does not let a stranger charge the no-refund fee.
func TestOwedHome_ContractCalledPlainSendHomeIsNotAPayout(t *testing.T) {
	_, did, addr := ohSender()
	rpBridge(t, ethWei(20), did, "hive:keeper")
	SetRelayer("hive:keeper") // the bridge's bot
	SetETHGasLimit(60_000)
	markRefundable(did, "eth", big.NewInt(2e16))
	asContract(t, "contract:vsc1griefer", "hive:mallory", rpNow)
	if out, err := HandleSendHome("address="+addr+"&asset=eth", [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("%q %v", out, err)
	}
	_, maxWei, _ := safeGasFee(60_000, 1e9, 2, 2_000_000_000)
	if got := new(big.Int).Sub(big.NewInt(2e16), GetPendingSpend(0).Amount); got.Cmp(maxWei) != 0 {
		t.Fatalf("charged %s up front, want the refundable maximum %s (user-withdrawal terms)", got, maxWei)
	}
	if v := sdk.StateGetObject(gasReserveExtraKey(0)); v != nil {
		t.Fatalf("recorded as a payout (gx-0 = %s)", *v)
	}
}

// An owed-home send (an Ethereum-paid swap's way back) that a roll kept from
// L1 is sent again to the same address, paying its own gas out of the amount;
// nothing reaches the address's Magi balance or the hold.
func TestOwedHome_RolledOwedSendIsSentAgain(t *testing.T) {
	_, did, addr := ohSender()
	rpBridge(t, ethWei(20), did, "hive:keeper")
	SetRelayer("hive:keeper") // the bridge's bot
	start := GetBalance(did, "eth")
	ohHold(did, big.NewInt(5e16))
	as(t, "hive:keeper", rpNow)
	if out, err := HandleSendHome("address="+addr+"&asset=eth&owed=1", [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("sendHome owed: %q %v", out, err)
	}
	ps := GetPendingSpend(0)
	if !ps.Payout {
		t.Fatalf("an owed-home send is not a payout: %+v", ps)
	}
	refundDroppedWithdrawal(ps, 1)
	if GetBalance(did, "eth").Cmp(start) != 0 || GetBalance(constants.OwedHomeHoldAccount, "eth").Sign() != 0 || getOwedHome(did, "eth").Sign() != 0 {
		t.Fatalf("balance %s hold %s owed %s: the roll went back instead of out", GetBalance(did, "eth"),
			GetBalance(constants.OwedHomeHoldAccount, "eth"), getOwedHome(did, "eth"))
	}
	ethInvariant(t, "after the roll")
	SetPendingNonce(1)
	SetConfirmedNonce(1)
	if QueueLen() == 1 {
		if n := drainWith(1, [20]byte{1}, 8); n != 1 {
			t.Fatalf("drained %d", n)
		}
	}
	again := GetPendingSpend(1)
	fee := payoutGasFee(constants.ETHTransferGas, 1e9, 2_000_000_000)
	if again == nil || new(big.Int).Add(again.Amount, fee).Cmp(ps.Amount) != 0 || !strings.EqualFold(again.To, addr) || again.RefundTo != did || again.Attempt != 1 {
		t.Fatalf("second send %+v, want %s less its own gas %s to %s again", again, ps.Amount, fee, addr)
	}
	ethInvariant(t, "after the second send")
}

// An owed send goes out now or not at all: when the bridge cannot send it
// (every slot in flight) it is refused, nothing is charged (no proof fee lost
// to a queue round trip), no revert is counted, and it stays held and listed.
// Only the bot or the address may send it.
func TestOwedHome_SentNowOrNotAtAll(t *testing.T) {
	_, did, addr := ohSender()
	rpBridge(t, ethWei(20), did, "hive:keeper")
	ohHold(did, big.NewInt(5e16))
	as(t, "hive:stranger", rpNow)
	if _, err := HandleSendHome("address="+addr+"&asset=eth&owed=1&gas_limit=300000", [20]byte{1}, 1); err == nil || !strings.Contains(err.Error(), "bridge's bot") {
		t.Fatalf("a stranger sent it: %v", err)
	}
	SetRelayer("hive:keeper")
	SetPendingNonce(constants.MaxInFlightWithdrawals) // nothing can issue now
	as(t, "hive:keeper", rpNow)
	if out, err := HandleSendHome("address="+addr+"&asset=eth&owed=1", [20]byte{1}, 1); err == nil {
		t.Fatalf("queued an owed send: %q", out)
	}
	// On chain the refused call reverts whole (nothing queued or charged); this
	// stub keeps what was written before the refusal, so only the count is read.
	if owedHomeReverts(did, "eth") != 0 {
		t.Fatalf("reverts %d: a refusal is not the address's revert", owedHomeReverts(did, "eth"))
	}
}

// A listed record that a raised proof fee leaves unable to pay it is taken off
// the bot's list by the keeper's sendHome (no longer refused forever), and
// stays held for its address.
func TestOwedHome_RaisedFeeDelistsInsteadOfFailing(t *testing.T) {
	_, did, addr := ohSender()
	rpBridge(t, ethWei(20), did, "hive:keeper")
	SetRelayer("hive:keeper") // the bridge's bot
	ohHold(did, big.NewInt(11e15))
	if len(owedHomeList()) != 1 {
		t.Fatalf("not listed: %v", owedHomeList())
	}
	SetProofFee("eth", big.NewInt(2e16)) // the owner raises it above what is owed
	as(t, "hive:keeper", rpNow)
	out, err := HandleSendHome("address="+addr+"&asset=eth&owed=1", [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "held:") {
		t.Fatalf("sendHome below sendable: %q %v, want a no-op that delists", out, err)
	}
	if len(owedHomeList()) != 0 || getOwedHome(did, "eth").Cmp(big.NewInt(11e15)) != 0 ||
		GetBalance(constants.OwedHomeHoldAccount, "eth").Cmp(big.NewInt(11e15)) != 0 {
		t.Fatalf("list %v owed %s hold %s", owedHomeList(), getOwedHome(did, "eth"), GetBalance(constants.OwedHomeHoldAccount, "eth"))
	}
	ethInvariant(t, "after the delisting")
}

// A record waiting in the overflow is not queued twice when more is owed to
// it, and leaves the overflow (marker cleared) when it moves into the list.
func TestOwedHome_OverflowIsNotQueuedTwice(t *testing.T) {
	sdk.ResetStubState()
	defer sdk.ResetStubState()
	var dids []string
	for i := 0; i < constants.MaxOwedHomeList+1; i++ {
		var a [20]byte
		a[18], a[19] = byte(i>>8), byte(i)+1
		dids = append(dids, crypto.AddressToDID(a))
		recordOwedHome(dids[i], "eth", big.NewInt(2e16))
	}
	last := dids[constants.MaxOwedHomeList]
	recordOwedHome(last, "eth", big.NewInt(2e16)) // more owed while it waits
	if h, tl := overflowBound(constants.OwedHomeOverflowHeadKey), overflowBound(constants.OwedHomeOverflowTailKey); tl-h != 1 {
		t.Fatalf("overflow holds %d entries, want 1", tl-h)
	}
	setOwedHome(dids[0], "eth", new(big.Int)) // one leaves the list: refill
	l := owedHomeList()
	if len(l) != constants.MaxOwedHomeList || l[len(l)-1] != "eth|"+last {
		t.Fatalf("after the refill the list ends %v", l[len(l)-1])
	}
	if sdk.StateGetObject(constants.OwedHomeQueuedMarkPrefix+"eth|"+last) != nil {
		t.Fatal("the overflow marker stayed after the entry moved into the list")
	}
}

// sendHome owed=1 takes a gas_limit for an ETH send (a contract wallet needs
// more than a transfer), within the payout bound; not for a token.
func TestOwedHome_OwedSendCarriesItsGasLimit(t *testing.T) {
	_, did, addr := ohSender()
	rpBridge(t, ethWei(20), did, "hive:keeper")
	SetRelayer("hive:keeper") // the bridge's bot
	ohHold(did, big.NewInt(5e16))
	as(t, "hive:keeper", rpNow)
	if _, err := HandleSendHome("address="+addr+"&asset=eth&owed=1&gas_limit=300001", [20]byte{1}, 1); err == nil {
		t.Fatal("a gas_limit over the payout bound was taken")
	}
	if _, err := HandleSendHome("address="+addr+"&asset=USDC&owed=1&gas_limit=60000", [20]byte{1}, 1); err == nil {
		t.Fatal("a gas_limit on a token send was taken")
	}
	out, err := HandleSendHome("address="+addr+"&asset=eth&owed=1&gas_limit=60000", [20]byte{1}, 1)
	if err != nil || !strings.HasPrefix(out, "issued:") {
		t.Fatalf("%q %v", out, err)
	}
	if ps := GetPendingSpend(0); ps.GasLimit != 60_000 {
		t.Fatalf("signed with gas limit %d, want 60000", ps.GasLimit)
	}
	ethInvariant(t, "after the send")
}

// Membership is read from state: a record taken off the list by a raised fee,
// which the owner then lowers, is listed again when more is owed to it.
func TestOwedHome_LoweredFeeListsOnTheNextChange(t *testing.T) {
	_, did, addr := ohSender()
	rpBridge(t, ethWei(20), did, "hive:keeper")
	SetRelayer("hive:keeper") // the bridge's bot
	ohHold(did, big.NewInt(11e15))
	SetProofFee("eth", big.NewInt(2e16))
	as(t, "hive:keeper", rpNow)
	if out, err := HandleSendHome("address="+addr+"&asset=eth&owed=1", [20]byte{1}, 1); err != nil || !strings.HasPrefix(out, "held:") || len(owedHomeList()) != 0 {
		t.Fatalf("delisting: %q %v list %v", out, err, owedHomeList())
	}
	SetProofFee("eth", big.NewInt(1)) // lowered again
	ohHold(did, big.NewInt(1e14))
	if l := owedHomeList(); len(l) != 1 || l[0] != "eth|"+did {
		t.Fatalf("after the fee fell and more was owed: list %v", l)
	}
	ethInvariant(t, "after the relisting")
}
