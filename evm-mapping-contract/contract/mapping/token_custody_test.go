package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
)

// ---- a minimal Merkle Patricia trie builder for fixtures ----

type trieKV struct{ path, val []byte } // path in nibbles

func hexPrefix(nibs []byte, leaf bool) []byte {
	flag := byte(0)
	if leaf {
		flag = 2
	}
	var out []byte
	if len(nibs)%2 == 1 {
		out = append(out, (flag+1)<<4|nibs[0])
		nibs = nibs[1:]
	} else {
		out = append(out, flag<<4)
	}
	for i := 0; i+1 < len(nibs); i += 2 {
		out = append(out, nibs[i]<<4|nibs[i+1])
	}
	return out
}

func trieRef(node []byte) []byte {
	if len(node) < 32 {
		return node // embedded
	}
	return rlp.EncodeBytes(crypto.Keccak256(node))
}

// buildTrie encodes the trie of kvs (equal-length paths) and appends every
// node to nodes.
func buildTrie(kvs []trieKV, nodes *[][]byte) []byte {
	var n []byte
	switch {
	case len(kvs) == 1:
		n = rlp.EncodeList(rlp.EncodeBytes(hexPrefix(kvs[0].path, true)), rlp.EncodeBytes(kvs[0].val))
	default:
		cp := 0
		for cp < len(kvs[0].path) {
			same := true
			for _, kv := range kvs[1:] {
				same = same && kv.path[cp] == kvs[0].path[cp]
			}
			if !same {
				break
			}
			cp++
		}
		if cp > 0 {
			rest := make([]trieKV, len(kvs))
			for i, kv := range kvs {
				rest[i] = trieKV{kv.path[cp:], kv.val}
			}
			n = rlp.EncodeList(rlp.EncodeBytes(hexPrefix(kvs[0].path[:cp], false)), trieRef(buildTrie(rest, nodes)))
			break
		}
		groups := map[byte][]trieKV{}
		for _, kv := range kvs {
			groups[kv.path[0]] = append(groups[kv.path[0]], trieKV{kv.path[1:], kv.val})
		}
		items := make([][]byte, 17)
		for i := range items {
			items[i] = rlp.EncodeBytes(nil)
			if g, ok := groups[byte(i)]; ok && i < 16 {
				items[i] = trieRef(buildTrie(g, nodes))
			}
		}
		n = rlp.EncodeList(items...)
	}
	*nodes = append(*nodes, n)
	return n
}

// trie returns the root and every node (a proof for any key in it).
func trie(kvs []trieKV) ([32]byte, []byte) {
	var nodes [][]byte
	rootNode := buildTrie(kvs, &nodes)
	var root [32]byte
	copy(root[:], crypto.Keccak256(rootNode))
	return root, concatBytes(nodes)
}

const usdcGap = "1000000" // 1 USDC

// tokenState plants a header whose state holds the token contract (and an
// unrelated contract) with a storage trie of the given balance words at
// slot, and returns the token's account proof and a storage proof. A zero
// word is not stored (Ethereum deletes zero slots).
func (w *migWorld) tokenState(token [20]byte, slot uint64, words map[[20]byte]*big.Int) (*AccountProof, string) {
	w.t.Helper()
	var skv []trieKV
	for holder, word := range words {
		if word.Sign() == 0 {
			continue
		}
		key := crypto.Keccak256(TokenBalanceSlotKey(holder, slot))
		skv = append(skv, trieKV{nibbles(key), rlp.EncodeBytes(word.Bytes())})
	}
	sroot, snodes := emptyTrieRoot, []byte(nil)
	if len(skv) > 0 {
		sroot, snodes = trie(skv)
	}
	return w.stateWith(token, sroot), base64.StdEncoding.EncodeToString(snodes)
}

// stateWith plants a header whose state holds contract addr with storage
// root sroot, beside an unrelated account, and returns addr's proof.
func (w *migWorld) stateWith(addr [20]byte, sroot [32]byte) *AccountProof {
	w.t.Helper()
	acct := func(sr [32]byte) []byte {
		return rlp.EncodeList(rlp.EncodeUint64(1), rlp.EncodeBigInt(new(big.Int)), rlp.EncodeBytes(sr[:]), rlp.EncodeBytes(make([]byte, 32)))
	}
	other := [20]byte{0: 0xee, 19: 0x01}
	root, nodes := trie([]trieKV{
		{nibbles(crypto.Keccak256(addr[:])), acct(sroot)},
		{nibbles(crypto.Keccak256(other[:])), acct(emptyTrieRoot)},
	})
	w.n++
	w.hdr(w.n, root, [32]byte{}, [32]byte{})
	return &AccountProof{BlockHeight: w.n, Proof: base64.StdEncoding.EncodeToString(nodes)}
}

func tokenWorld(t *testing.T) *migWorld {
	t.Helper()
	w := newMigWorld(t) // books 500 USDC, gens 0 and 1
	if err := SetTokenCustody(&SetTokenCustodyParams{Asset: "usdc", Slot: 9, Bits: 255, Gap: usdcGap}); err != nil {
		t.Fatal(err)
	}
	return w
}

// proveUsdc proves the token root then gen 1 and gen 0; the last result.
func (w *migWorld) proveUsdc(g0, g1 *big.Int) (string, error) {
	w.t.Helper()
	acct, sp := w.tokenState(w.usdc, 9, map[[20]byte]*big.Int{w.gen0: g0, w.gen1: g1, {19: 0x77}: wei("999000000")})
	if _, err := HandleProveTokenRoot(&ProveTokenRootParams{Asset: "usdc", Proof: acct}); err != nil {
		return "", err
	}
	out, err := HandleProveTokenCustody(&ProveTokenCustodyParams{Asset: "usdc", Gen: 1, BlockHeight: acct.BlockHeight, StorageProof: sp})
	if err != nil {
		return "", err
	}
	if !strings.Contains(out, "1 of 2") {
		w.t.Fatalf("first generation: %q", out)
	}
	return HandleProveTokenCustody(&ProveTokenCustodyParams{Asset: "usdc", Gen: 0, BlockHeight: acct.BlockHeight, StorageProof: sp})
}

func (w *migWorld) proveEth(b0, b1 string) (string, error) {
	w.t.Helper()
	p0, p1 := w.twoAccounts(w.gen0, wei(b0), w.gen1, wei(b1))
	if _, err := HandleProveCustody(&ProveCustodyParams{Gen: 1, Proof: p1}); err != nil {
		return "", err
	}
	return HandleProveCustody(&ProveCustodyParams{Gen: 0, Proof: p0})
}

func stateHas(key string) bool {
	_, ok := sdk.TestStateGet(key)
	return ok
}

// A token's custody: held, more than the gap short (its flag, "si", a
// security log naming it), then held again lifts both by deletion.
func TestTC_TokenCustodyHaltsAndLifts(t *testing.T) {
	w := tokenWorld(t)
	if out, err := w.proveUsdc(wei("200000000"), wei("300000000")); err != nil || SolvencyHalted() || !strings.Contains(out, "custody held") || !strings.Contains(out, "(usdc)") {
		t.Fatalf("500 USDC held for 500 booked: %q %v halted=%v", out, err, SolvencyHalted())
	}
	if stateHas(constants.TokenCustodyProofPrefix + "usdc") {
		t.Fatal("a completed token proof was kept")
	}
	if _, err := w.proveUsdc(wei("200000000"), wei("299000000")); err != nil || SolvencyHalted() {
		t.Fatalf("1 USDC short (the gap): %v halted=%v", err, SolvencyHalted())
	}
	out, err := w.proveUsdc(wei("200000000"), wei("298999999"))
	if err != nil || !SolvencyHalted() || !AssetShort("usdc") || !strings.Contains(out, "custody short") {
		t.Fatalf("just over the gap short: %q %v halted=%v", out, err, SolvencyHalted())
	}
	found := false
	for _, l := range sdk.TestLogs() {
		found = found || strings.HasPrefix(l, "security|evm-custody-short|a=usdc|")
	}
	if !found {
		t.Fatal("no security log naming usdc")
	}
	if _, err := w.proveUsdc(wei("0"), wei("500000000")); err != nil || SolvencyHalted() || AssetShort("usdc") {
		t.Fatalf("custody back: %v halted=%v", err, SolvencyHalted())
	}
	if stateHas(constants.SolvencyHaltKey) || stateHas(constants.AssetShortPrefix+"usdc") {
		t.Fatal("lifted by writing a value, not by deletion")
	}
}

// One asset's held verdict never lifts another asset's halt, both ways.
func TestTC_OneAssetNeverLiftsAnother(t *testing.T) {
	w := tokenWorld(t)
	// USDC short, ETH held: still halted.
	if _, err := w.proveUsdc(wei("0"), wei("100000000")); err != nil || !SolvencyHalted() {
		t.Fatalf("usdc short: %v", err)
	}
	if out, err := w.proveEth("1000000000000000000", "2500000000000000000"); err != nil || !strings.Contains(out, "custody held") {
		t.Fatalf("eth held: %q %v", out, err)
	}
	if !SolvencyHalted() || !AssetShort("usdc") {
		t.Fatal("ETH's held proof lifted USDC's halt")
	}
	// ETH short too, then USDC held: ETH keeps it.
	if _, err := w.proveEth("0", "1000000000000000000"); err != nil || !AssetShort(constants.NativeAsset) {
		t.Fatalf("eth short: %v", err)
	}
	if _, err := w.proveUsdc(wei("0"), wei("500000000")); err != nil || AssetShort("usdc") {
		t.Fatalf("usdc held: %v", err)
	}
	if !SolvencyHalted() {
		t.Fatal("USDC's held proof lifted ETH's halt")
	}
	// ETH held: nothing short, lifted.
	if out, err := w.proveEth("1000000000000000000", "2500000000000000000"); err != nil || SolvencyHalted() {
		t.Fatalf("both held: %q %v halted=%v", out, err, SolvencyHalted())
	}
}

// A bridge updated from the ETH-only proof may hold "si" with no per-asset
// flag: it is ETH's, so a token's held verdict leaves it, ETH's lifts it.
func TestTC_LegacyHaltIsEths(t *testing.T) {
	w := tokenWorld(t)
	sdk.StateSetObject(constants.SolvencyHaltKey, "900")
	if _, err := w.proveUsdc(wei("200000000"), wei("300000000")); err != nil {
		t.Fatal(err)
	}
	if !SolvencyHalted() {
		t.Fatal("a USDC proof lifted the legacy (ETH) halt")
	}
	if v, _ := sdk.TestStateGet(constants.AssetShortPrefix + constants.NativeAsset); v != "900" {
		t.Fatalf("legacy halt not adopted as ETH's: %q", v)
	}
	if _, err := w.proveEth("1000000000000000000", "2500000000000000000"); err != nil || SolvencyHalted() {
		t.Fatalf("ETH held: %v halted=%v", err, SolvencyHalted())
	}
}

// ETH's verdict text and log are C2's, unchanged (the bot and alerts read them).
func TestTC_EthVerdictTextUnchanged(t *testing.T) {
	w := tokenWorld(t)
	out, err := w.proveEth("0", "1000000000000000000")
	if err != nil || !strings.HasPrefix(out, "custody short at block ") || strings.Contains(out, "(eth)") {
		t.Fatalf("eth short text: %q %v", out, err)
	}
	found := false
	for _, l := range sdk.TestLogs() {
		found = found || strings.HasPrefix(l, "security|evm-custody-short|h=")
	}
	if !found {
		t.Fatal("eth security log changed")
	}
}

// USDC v2.2 keeps its blacklist flag in bit 255: masked, a blacklisted vault
// with little USDC reads short; unmasked (bits 256) the flag would read as
// a huge balance and hide the shortfall.
func TestTC_FlagBitMasked(t *testing.T) {
	w := tokenWorld(t)
	flag := new(big.Int).Lsh(big.NewInt(1), 255)
	g1 := new(big.Int).Add(flag, wei("100000000"))
	if _, err := w.proveUsdc(wei("0"), g1); err != nil || !AssetShort("usdc") {
		t.Fatalf("flagged 100 USDC of 500 booked: %v short=%v", err, AssetShort("usdc"))
	}
	g1 = new(big.Int).Add(flag, wei("500000000"))
	if _, err := w.proveUsdc(wei("0"), g1); err != nil || AssetShort("usdc") {
		t.Fatalf("flagged 500 USDC of 500 booked: %v short=%v", err, AssetShort("usdc"))
	}
}

// A generation the token never paid is proven absent: 0. A token contract
// with no storage at all needs no storage proof: every balance is 0.
func TestTC_ProvenAbsenceAndEmptyStorage(t *testing.T) {
	w := tokenWorld(t)
	if _, err := w.proveUsdc(wei("0"), wei("500000000")); err != nil || SolvencyHalted() {
		t.Fatalf("gen 0 absent, gen 1 the whole book: %v halted=%v", err, SolvencyHalted())
	}
	acct := w.stateWith(w.usdc, emptyTrieRoot)
	if _, err := HandleProveTokenRoot(&ProveTokenRootParams{Asset: "usdc", Proof: acct}); err != nil {
		t.Fatal(err)
	}
	for _, gen := range []uint32{1, 0} {
		if _, err := HandleProveTokenCustody(&ProveTokenCustodyParams{Asset: "usdc", Gen: gen, BlockHeight: acct.BlockHeight}); err != nil {
			t.Fatalf("gen %d on empty storage: %v", gen, err)
		}
	}
	if !AssetShort("usdc") {
		t.Fatal("empty token storage with 500 USDC booked: not short")
	}
}

// Proofs that would let a prover fake or block the result are refused.
func TestTC_Refusals(t *testing.T) {
	w := newMigWorld(t)
	acct, sp := w.tokenState(w.usdc, 9, map[[20]byte]*big.Int{w.gen1: wei("500000000")})
	root := func(p *AccountProof) error {
		_, err := HandleProveTokenRoot(&ProveTokenRootParams{Asset: "usdc", Proof: p})
		return err
	}
	bal := func(gen uint32, h uint64, sp string) (string, error) {
		return HandleProveTokenCustody(&ProveTokenCustodyParams{Asset: "usdc", Gen: gen, BlockHeight: h, StorageProof: sp})
	}
	if err := root(acct); err == nil || !strings.Contains(err.Error(), "no custody setting") {
		t.Fatalf("a token without a setting: %v", err)
	}
	if err := SetTokenCustody(&SetTokenCustodyParams{Asset: "usdc", Slot: 9, Bits: 255, Gap: usdcGap}); err != nil {
		t.Fatal(err)
	}
	if _, err := HandleProveTokenRoot(&ProveTokenRootParams{Asset: "dai", Proof: acct}); err == nil {
		t.Fatal("an unregistered token was proven")
	}
	// another contract's storage presented as the token's: the token's own
	// account is not in that state, so there is no root (not a zero root)
	fake := w.stateWith([20]byte{19: 0xfa}, [32]byte{1})
	if err := root(fake); err == nil {
		t.Fatal("a state without the token contract gave a storage root")
	}
	if _, err := bal(1, acct.BlockHeight, sp); err == nil || !strings.Contains(err.Error(), "proveTokenRoot") {
		t.Fatalf("a balance without the root: %v", err)
	}
	// a newer root being assembled: an older one is refused; the same one
	// keeps the balances proven so far
	newer, sp2 := w.tokenState(w.usdc, 9, map[[20]byte]*big.Int{w.gen1: wei("500000000")})
	if err := root(newer); err != nil {
		t.Fatal(err)
	}
	if err := root(acct); err == nil || !strings.Contains(err.Error(), "being assembled") {
		t.Fatalf("an older root than the one assembled: %v", err)
	}
	if _, err := bal(1, acct.BlockHeight, sp); err == nil || !strings.Contains(err.Error(), "proveTokenRoot") {
		t.Fatalf("a balance at another height than the root's: %v", err)
	}
	if out, err := bal(1, newer.BlockHeight, sp2); err != nil || !strings.Contains(out, "1 of 2") {
		t.Fatalf("gen 1: %q %v", out, err)
	}
	if err := root(newer); err != nil {
		t.Fatal(err)
	}
	if out, err := bal(0, newer.BlockHeight, sp2); err != nil || !strings.Contains(out, "custody held") {
		t.Fatalf("a repeated same-height root discarded gen 1: %q %v", out, err)
	}
	// a storage proof from another token's trie fails (root mismatch)
	_, otherSp := w.tokenState(w.usdc, 9, map[[20]byte]*big.Int{w.gen1: wei("1")})
	again, sp3 := w.tokenState(w.usdc, 9, map[[20]byte]*big.Int{w.gen1: wei("500000000")})
	if err := root(again); err != nil {
		t.Fatal(err)
	}
	if _, err := bal(1, again.BlockHeight, otherSp); err == nil {
		t.Fatal("a storage proof of another trie was accepted")
	}
	if _, err := bal(7, again.BlockHeight, sp3); err == nil || !strings.Contains(err.Error(), "holds no funds") {
		t.Fatalf("an unknown generation: %v", err)
	}
	// a changed setting discards the proof being assembled
	if out, err := bal(1, again.BlockHeight, sp3); err != nil || !strings.Contains(out, "1 of 2") {
		t.Fatalf("gen 1: %q %v", out, err)
	}
	if err := SetTokenCustody(&SetTokenCustodyParams{Asset: "usdc", Slot: 9, Bits: 255, Gap: "0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := bal(0, again.BlockHeight, sp3); err == nil || !strings.Contains(err.Error(), "proveTokenRoot") {
		t.Fatalf("a proof assembled under the old setting survived: %v", err)
	}
	// older than the newest credited deposit
	late, _ := w.tokenState(w.usdc, 9, map[[20]byte]*big.Int{w.gen1: wei("1")})
	noteCreditedDeposit(late.BlockHeight + 1)
	if err := root(late); err == nil || !strings.Contains(err.Error(), "newest credited deposit") {
		t.Fatalf("a root older than a credited deposit: %v", err)
	}
	// the owner's switch
	w.n += 10
	final, _ := w.tokenState(w.usdc, 9, map[[20]byte]*big.Int{w.gen1: wei("1")})
	SetCustodyCheck(false)
	if err := root(final); err == nil || !strings.Contains(err.Error(), "off") {
		t.Fatalf("custody check off: %v", err)
	}
	SetCustodyCheck(true)
	if err := root(final); err != nil {
		t.Fatalf("custody check back on: %v", err)
	}
}

// Switching the check off lifts every asset's flag and "si", and drops every
// token proof being assembled.
func TestTC_SwitchOffClearsEveryAsset(t *testing.T) {
	w := tokenWorld(t)
	if _, err := w.proveUsdc(wei("0"), wei("1")); err != nil || !AssetShort("usdc") {
		t.Fatalf("usdc short: %v", err)
	}
	if _, err := w.proveEth("0", "1"); err != nil || !AssetShort(constants.NativeAsset) {
		t.Fatalf("eth short: %v", err)
	}
	acct, _ := w.tokenState(w.usdc, 9, map[[20]byte]*big.Int{w.gen1: wei("1")})
	if _, err := HandleProveTokenRoot(&ProveTokenRootParams{Asset: "usdc", Proof: acct}); err != nil {
		t.Fatal(err)
	}
	SetCustodyCheck(false)
	for _, k := range []string{constants.SolvencyHaltKey, constants.AssetShortPrefix + "usdc",
		constants.AssetShortPrefix + constants.NativeAsset, constants.TokenCustodyProofPrefix + "usdc"} {
		if stateHas(k) {
			t.Fatalf("%s kept after the switch went off", k)
		}
	}
}

func TestTC_SetTokenCustodyValidation(t *testing.T) {
	newMigWorld(t)
	for _, p := range []*SetTokenCustodyParams{
		nil,
		{Asset: "dai", Slot: 9},
		{Asset: constants.NativeAsset, Slot: 9},
		{Asset: "usdc", Slot: 9, Bits: 257},
		{Asset: "usdc", Slot: 9, Gap: "-1"},
		{Asset: "usdc", Slot: 9, Gap: "1.5"},
	} {
		if err := SetTokenCustody(p); err == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
	if stateHas(constants.TokenCustodyConfigPrefix + "usdc") {
		t.Fatal("a refused setting was written")
	}
	if err := SetTokenCustody(&SetTokenCustodyParams{Asset: "usdc", Slot: 9}); err != nil {
		t.Fatal(err)
	}
	if cfg, ok := GetTokenCustody("usdc"); !ok || cfg.Slot != 9 || cfg.Bits != 256 || cfg.Gap.Sign() != 0 {
		t.Fatalf("defaults: %+v %v", cfg, ok)
	}
}

// Real data: Ethereum mainnet USDC (FiatToken v2.2) at block 26,330,745. The
// token's account proof gives the storage root the RPC reported, and slot 9
// masked to 255 bits gives balanceOf for a blacklisted holder with a balance,
// a blacklisted holder with none, a plain holder and a never-used address
// (proven absent). Unmasked, the blacklisted words are not balanceOf.
func TestTC_MainnetUsdcSlot9(t *testing.T) {
	raw, err := os.ReadFile("testdata/usdc_mainnet_storage_proof.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Block        uint64   `json:"block"`
		StateRoot    string   `json:"stateRoot"`
		Token        string   `json:"token"`
		StorageHash  string   `json:"storageHash"`
		AccountProof []string `json:"accountProof"`
		Holders      []struct {
			Address     string   `json:"address"`
			Word        string   `json:"word"`
			Proof       []string `json:"proof"`
			BalanceOf   string   `json:"balanceOf"`
			Blacklisted bool     `json:"blacklisted"`
		} `json:"holders"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	cat := func(nodes []string) string {
		var b []byte
		for _, n := range nodes {
			d, err := hex.DecodeString(strings.TrimPrefix(n, "0x"))
			if err != nil {
				t.Fatal(err)
			}
			b = append(b, d...)
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	h32 := func(s string) (out [32]byte) {
		b, _ := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		copy(out[:], b)
		return
	}
	w := newMigWorld(t)
	w.hdr(fx.Block, h32(fx.StateRoot), [32]byte{}, [32]byte{})
	token, err := crypto.HexToAddress(fx.Token)
	if err != nil {
		t.Fatal(err)
	}
	ap := &AccountProof{BlockHeight: fx.Block, Proof: cat(fx.AccountProof)}
	t.Logf("mainnet USDC: account proof %d base64 bytes, storage proof %d", len(ap.Proof), len(cat(fx.Holders[0].Proof)))
	root, err := provenStorageRoot(ap, token)
	if err != nil {
		t.Fatal(err)
	}
	if root != h32(fx.StorageHash) {
		t.Fatalf("storage root %x, the RPC said %s", root, fx.StorageHash)
	}
	masked := TokenCustodyConfig{Slot: 9, Bits: 255}
	unmasked := TokenCustodyConfig{Slot: 9, Bits: 256}
	sawFlag, sawAbsent := false, false
	for _, hd := range fx.Holders {
		holder, _ := crypto.HexToAddress(hd.Address)
		sp := cat(hd.Proof)
		got, err := provenTokenBalance(root, holder, masked, sp)
		if err != nil {
			t.Fatalf("%s: %v", hd.Address, err)
		}
		if got.String() != hd.BalanceOf {
			t.Fatalf("%s: slot 9 / 255 bits = %s, balanceOf = %s", hd.Address, got, hd.BalanceOf)
		}
		full, err := provenTokenBalance(root, holder, unmasked, sp)
		if err != nil {
			t.Fatal(err)
		}
		if hd.Blacklisted {
			sawFlag = true
			if full.Cmp(got) == 0 {
				t.Fatalf("%s: blacklisted but the word has no flag", hd.Address)
			}
		}
		if hd.Word == "0x0" {
			sawAbsent = true
		}
		// the proof for one holder does not prove another's balance
		other := holder
		other[0] ^= 0xff
		if v, err := provenTokenBalance(root, other, masked, sp); err == nil && v.Sign() != 0 {
			t.Fatalf("%s's proof gave another address %s", hd.Address, v)
		}
	}
	if !sawFlag || !sawAbsent {
		t.Fatalf("fixture lost its cases: flag=%v absent=%v", sawFlag, sawAbsent)
	}
	// the wrong slot proves nothing: an error or 0, never someone's word
	h0, _ := crypto.HexToAddress(fx.Holders[0].Address)
	if v, err := provenTokenBalance(root, h0, TokenCustodyConfig{Slot: 0, Bits: 255}, cat(fx.Holders[0].Proof)); err == nil && v.Sign() != 0 {
		t.Fatalf("slot 0 read %s", v)
	}
}
