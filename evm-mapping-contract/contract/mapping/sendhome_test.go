package mapping

import (
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

// A deposit that lands on its sender's own account by default is refundable:
// that account has no RC unless it holds HBD, so sendHome (anyone, paying the
// RC) must be able to return it to the address it came from.

func shSender() [20]byte {
	var a [20]byte
	a[19] = 0xd7
	return a
}

func TestSendHome_RouteDepositMarksOnlyTheDefaultFallback(t *testing.T) {
	sender := shSender()
	did := crypto.AddressToDID(sender)
	amt := big.NewInt(5_000)
	cases := []struct {
		name       string
		instr      []string
		router     string // "" none, "fail", "ok-pulls-nothing"
		dest       string
		refundable int64
		owed       bool // held and owed home (credited to the hold, not dest)
	}{
		{"no instruction (a CEX send)", nil, "", did, 5_000, false},
		{"explicit deposit_to", []string{"deposit_to=hive:alice"}, "", "hive:alice", 0, false},
		{"swap without min: held, owed home", []string{"swap_to=hive:bob", "asset_out=hbd"}, "fail", did, 0, true},
		{"swap fails at the router: held, owed home", []string{"swap_to=hive:bob", "asset_out=hbd", "min_amount_out=9"}, "fail", did, 0, true},
		{"swap to deposit_to fails: explicit, not refundable", []string{"deposit_to=hive:alice", "swap_to=hive:bob", "asset_out=hbd", "min_amount_out=9"}, "fail", "hive:alice", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sdk.ResetStubState()
			sdk.ResetTestState()
			if c.router != "" {
				sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
				sdk.StubSetContractCallResponder(func(contractId, method, payload string) *string {
					r := `{"ok":false,"error":"reverted"}`
					return &r
				})
			}
			got, held := routeDeposit(sender, c.instr, "eth", amt, 1)
			if got != c.dest || held != c.owed {
				t.Fatalf("dest %q held=%v, want %q held=%v", got, held, c.dest, c.owed)
			}
			if o := getOwedHome(did, "eth").Sign() > 0; o != c.owed {
				t.Fatalf("owed home %v, want %v", o, c.owed)
			}
			if r := getRefundable(did, "eth"); r.Int64() != c.refundable {
				t.Fatalf("refundable %s, want %d", r, c.refundable)
			}
		})
	}
	sdk.ResetStubState()
}

func TestSendHome_SwapTellsTheRouterTheDepositor(t *testing.T) {
	sdk.ResetStubState()
	sdk.ResetTestState()
	sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
	var sent string
	sdk.StubSetContractCallResponder(func(contractId, method, payload string) *string {
		sent = payload
		r := `{"ok":false,"error":"reverted"}`
		return &r
	})
	routeDeposit(shSender(), []string{"swap_to=hive:bob", "asset_out=hbd", "min_amount_out=9"}, "eth", big.NewInt(5_000), 1)
	want := `"return_address":{"chain":"MAGI","address":"` + crypto.AddressToDID(shSender()) + `"}`
	if !strings.Contains(sent, want) {
		t.Fatalf("router got %s, want it to carry %s", sent, want)
	}
	sdk.ResetStubState()
}

func TestSendHome_WithdrawalRefundsMarkedOnlyWhenNothingChanges(t *testing.T) {
	did := crypto.AddressToDID(shSender())
	own := crypto.AddressToHex(shSender())
	cases := []struct {
		name, from, to, account string
		marked, held            bool
	}{
		{"a contract withdrew for the account: held, owed home", "contract:vsc1router", "0x00000000000000000000000000000000000000e2", did, false, true},
		{"the account withdrew to its own address", did, own, did, true, false},
		{"the account withdrew elsewhere", did, "0x00000000000000000000000000000000000000e2", did, false, false},
		{"a hive account (a Magi sender): credited", "contract:vsc1router", own, "hive:alice", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sdk.ResetStubState()
			sdk.ResetTestState()
			creditWithdrawalRefund(c.from, c.to, c.account, "eth", big.NewInt(777), true)
			if got := getRefundable(c.account, "eth").Sign() > 0; got != c.marked {
				t.Fatalf("marked %v, want %v", got, c.marked)
			}
			if held := GetBalance(constants.OwedHomeHoldAccount, "eth").Sign() > 0; held != c.held {
				t.Fatalf("held %v, want %v", held, c.held)
			}
			if onBalance := GetBalance(c.account, "eth").Sign() > 0; onBalance == c.held {
				t.Fatalf("on the account's balance %v, held %v", onBalance, c.held)
			}
		})
	}
	sdk.ResetStubState()
}

func TestSendHome_AnyoneReturnsItToTheAddressItself(t *testing.T) {
	holder := crypto.AddressToDID(shSender())
	addr := crypto.AddressToHex(shSender())
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), holder, "hive:keeper")
	as(t, "hive:keeper", time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	SaveVaultState(VaultRegistry{{Generation: 0, Primary: pubOf(t, testPub1), Status: VaultStatusActive}}, 1, 0)

	// Nothing recorded: refused, nothing moves.
	before := GetBalance(holder, "eth")
	if _, err := HandleSendHome("address="+addr+"&asset=eth", [20]byte{1}, 1); err == nil {
		t.Fatal("sendHome with nothing refundable must be refused")
	}
	if GetBalance(holder, "eth").Cmp(before) != 0 {
		t.Fatal("a refused sendHome moved funds")
	}

	oneEth := big.NewInt(1e18)
	markRefundable(holder, "eth", oneEth)
	keeperBefore := GetBalance("hive:keeper", "eth")
	status, err := HandleSendHome("address="+addr+"&asset=eth", [20]byte{1}, 1)
	if err != nil {
		t.Fatalf("sendHome: %v", err)
	}
	if !strings.HasPrefix(status, "issued:") { // PAYOUT-1: sendHome is sent at once or refused
		t.Fatalf("status %q", status)
	}
	debited := new(big.Int).Sub(before, GetBalance(holder, "eth"))
	if debited.Sign() <= 0 || debited.Cmp(new(big.Int).Add(oneEth, ProofFee("eth"))) > 0 {
		t.Fatalf("debited %s from the refunded account, want at most 1 ETH + proof fee", debited)
	}
	if GetBalance("hive:keeper", "eth").Cmp(keeperBefore) != 0 {
		t.Fatal("the caller's own balance must not move")
	}
	if strings.HasPrefix(status, "issued:") {
		n, _ := strconv.ParseUint(strings.TrimPrefix(status, "issued:"), 10, 64)
		ps := GetPendingSpend(n)
		if ps == nil || !strings.EqualFold(ps.To, addr) || ps.From != holder {
			t.Fatalf("withdrawal %+v, want from %s to %s", ps, holder, addr)
		}
	}
	if r := getRefundable(holder, "eth"); r.Sign() != 0 {
		t.Fatalf("refundable left %s after returning all of it", r)
	}
	sdk.ResetStubState()
}

// A token goes home under the symbol it is registered with (USDC here): the
// ledger's balance keys and token index are case-sensitive. The sendHome input
// used to be lowercased, so a token registered in capitals could never go home.
func TestSendHome_ATokenGoesHomeUnderItsRegisteredSymbol(t *testing.T) {
	holder := crypto.AddressToDID(shSender())
	addr := crypto.AddressToHex(shSender())
	rpBridge(t, ethWei(20), holder, "hive:keeper") // holder: 1,000,000 USDC (6 decimals); the reserve fronts the gas
	var tok [20]byte
	tok[19] = 0xc0
	if err := RegisterToken(1, tok, "USDC", 6, 1000); err != nil {
		t.Fatal(err)
	}
	as(t, "hive:keeper", time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	SaveVaultState(VaultRegistry{{Generation: 0, Primary: pubOf(t, testPub1), Status: VaultStatusActive}}, 1, 0)

	// What a plain USDC transfer to the vault records (handleMap, ERC-20 branch).
	markRefundable(holder, "USDC", big.NewInt(500_000))
	before := GetBalance(holder, "USDC")
	keeperBefore := GetBalance("hive:keeper", "USDC")

	if _, err := HandleSendHome("address="+addr+"&asset=usdc", [20]byte{1}, 1); err == nil {
		t.Fatal("a symbol in another case names no refund and must be refused")
	}
	status, err := HandleSendHome("address="+addr+"&asset=USDC", [20]byte{1}, 1)
	if err != nil {
		t.Fatalf("sendHome USDC: %v", err)
	}
	if !strings.HasPrefix(status, "issued:") { // PAYOUT-1: sendHome is sent at once or refused
		t.Fatalf("status %q", status)
	}
	debited := new(big.Int).Sub(before, GetBalance(holder, "USDC"))
	want := new(big.Int).Add(big.NewInt(500_000), ProofFee("USDC"))
	if debited.Cmp(want) != 0 {
		t.Fatalf("debited %s, want the refund + proof fee %s", debited, want)
	}
	if GetBalance("hive:keeper", "USDC").Cmp(keeperBefore) != 0 {
		t.Fatal("the caller's own balance must not move")
	}
	if r := getRefundable(holder, "USDC"); r.Sign() != 0 {
		t.Fatalf("refundable left %s after returning all of it", r)
	}
	if r := getRefundable(holder, "eth"); r.Sign() != 0 {
		t.Fatalf("an ETH record appeared: %s", r)
	}
	sdk.ResetStubState()
}

func TestSendHome_EthInAnyCase(t *testing.T) {
	holder := crypto.AddressToDID(shSender())
	addr := crypto.AddressToHex(shSender())
	rpBridge(t, new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18)), holder, "hive:keeper")
	as(t, "hive:keeper", time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	SaveVaultState(VaultRegistry{{Generation: 0, Primary: pubOf(t, testPub1), Status: VaultStatusActive}}, 1, 0)
	markRefundable(holder, "eth", big.NewInt(1e17))
	if _, err := HandleSendHome("address="+addr+"&asset=ETH", [20]byte{1}, 1); err != nil {
		t.Fatalf("sendHome ETH: %v", err)
	}
	if r := getRefundable(holder, "eth"); r.Sign() != 0 {
		t.Fatalf("refundable left %s", r)
	}
	sdk.ResetStubState()
}

// A swap the router refuses is credited to the sender as before, and the bridge
// now logs why (the BTC mapping contract's swaprefund line, for the EVM side).
func TestRouteDeposit_FailedSwapLogsTheReason(t *testing.T) {
	did := crypto.AddressToDID(shSender())
	cases := []struct{ name, outcome, want string }{
		{"the router's error text", `{"ok":false,"error":"slippage tolerance exceeded"}`, "swapfail|t=" + did + "|a=eth|d=5000|r=reverted: slippage tolerance exceeded"},
		{"no error text", `{"ok":false}`, "swapfail|t=" + did + "|a=eth|d=5000|r=reverted"},
		{"pipes and newlines cannot break the log fields", `{"ok":false,"error":"a|b\nc"}`, "swapfail|t=" + did + "|a=eth|d=5000|r=reverted: a b c"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sdk.ResetStubState()
			sdk.ResetTestState()
			sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
			sdk.StubSetContractCallResponder(func(contractId, method, payload string) *string {
				r := c.outcome
				return &r
			})
			if got, _ := routeDeposit(shSender(), []string{"swap_to=hive:bob", "asset_out=hbd", "min_amount_out=9"}, "eth", big.NewInt(5_000), 1); got != did {
				t.Fatalf("dest %q, want the sender %q", got, did)
			}
			found := false
			for _, l := range sdk.TestLogs() {
				if l == c.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("log %q not written; logs: %q", c.want, sdk.TestLogs())
			}
		})
	}
	// A swap that runs writes no swapfail line.
	sdk.ResetStubState()
	sdk.ResetTestState()
	sdk.StateSetObject(constants.RouterContractIdKey, "vsc1router")
	sdk.StubSetContractCallResponder(func(contractId, method, payload string) *string {
		r := `{"ok":true,"result":"{}"}`
		return &r
	})
	routeDeposit(shSender(), []string{"swap_to=hive:bob", "asset_out=hbd", "min_amount_out=9"}, "eth", big.NewInt(5_000), 1)
	for _, l := range sdk.TestLogs() {
		if strings.HasPrefix(l, "swapfail|") {
			t.Fatalf("a swap that ran logged %q", l)
		}
	}
	sdk.ResetStubState()
}
