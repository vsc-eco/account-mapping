package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
	"strings"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
)

// C2 for ERC-20s: the custody proof of a registered token (USDC). An ETH
// balance is in the vault address's account; a token balance is a storage
// word of the token contract (its balances mapping at the holder's key), so a
// token is proven in two steps at one stored (ZK-verified) header:
//
//   1. proveTokenRoot {asset, proof}: the token contract's account proof
//      gives its storage root at that header (kept under "tcp-{asset}").
//   2. proveTokenCustody {asset, gen, block_height, storage_proof}: each
//      fund-holding generation's balance word, proven against that root.
//
// (A mainnet token account proof and a storage proof do not fit one 8 KB call
// together.) Once every fund-holding generation has a balance at the header,
// the sum is compared with the token's booked custody Supply(asset).Active,
// exactly as for ETH: more than the token's gap short sets the asset's short
// flag and "si" (the nodes stop the bridge's vault keysigns), and a later
// complete proof showing the custody clears the asset's flag; "si" is lifted
// when no asset is short. The fairness argument is ETH's: a withdrawal is
// debited from the book when requested, a deposit is booked only after its
// block and the header is no older than the newest credited deposit's block,
// and a sweep moves the token between addresses that are all summed.
//
// Where the token keeps a holder's balance is the owner's per-token setting
// (setTokenCustody, operational timelock): the mapping's slot index, how many
// low bits of the stored word are the balance (USDC v2.2 keeps its blacklist
// flag in bit 255: 255 bits), and the gap. A token without it cannot be
// proven. A wrong slot reads every balance as 0 and halts (fail closed); the
// owner fixes the setting or turns the check off (setCustodyCheck).

// TokenCustodyConfig is where a token keeps a holder's balance, and the gap.
type TokenCustodyConfig struct {
	Slot uint64
	Bits uint64
	Gap  *big.Int
}

// SetTokenCustodyParams is setTokenCustody's payload.
type SetTokenCustodyParams struct {
	Asset string `json:"asset"`
	Slot  uint64 `json:"slot"`
	Bits  uint64 `json:"bits"` // 0 = 256
	Gap   string `json:"gap"`  // base units; "" = 0
}

// ProveTokenRootParams: the token contract's account proof.
type ProveTokenRootParams struct {
	Asset string        `json:"asset"`
	Proof *AccountProof `json:"proof"`
}

// ProveTokenCustodyParams: one generation's balance word, proven against the
// token's storage root at BlockHeight (proveTokenRoot first).
type ProveTokenCustodyParams struct {
	Asset        string `json:"asset"`
	Gen          uint32 `json:"gen"`
	BlockHeight  uint64 `json:"block_height"`
	StorageProof string `json:"storage_proof"` // base64, concatenated storage-trie nodes
}

func tokenCustodyConfigKey(asset string) string {
	return constants.TokenCustodyConfigPrefix + asset
}

// SetTokenCustody records where a registered token keeps balances.
func SetTokenCustody(p *SetTokenCustodyParams) error {
	if p == nil {
		return ce.NewContractError(ce.ErrInput, "setTokenCustody: payload required")
	}
	if t, _ := TokenBySymbol(p.Asset); t == nil {
		return ce.NewContractError(ce.ErrInput, "setTokenCustody: "+p.Asset+" is not a registered token")
	}
	bits := p.Bits
	if bits == 0 {
		bits = 256
	}
	if bits > 256 {
		return ce.NewContractError(ce.ErrInput, "setTokenCustody: bits must be 1..256")
	}
	gap := new(big.Int)
	if p.Gap != "" {
		if _, ok := gap.SetString(p.Gap, 10); !ok || gap.Sign() < 0 {
			return ce.NewContractError(ce.ErrInput, "setTokenCustody: gap must be a non-negative integer")
		}
	}
	sdk.StateSetObject(tokenCustodyConfigKey(p.Asset),
		strconv.FormatUint(p.Slot, 10)+"|"+strconv.FormatUint(bits, 10)+"|"+gap.String())
	// A changed setting invalidates a proof being assembled under the old one.
	sdk.StateDeleteObject(constants.TokenCustodyProofPrefix + p.Asset)
	return nil
}

// GetTokenCustody returns a token's custody setting, if it has one.
func GetTokenCustody(asset string) (TokenCustodyConfig, bool) {
	v := sdk.StateGetObject(tokenCustodyConfigKey(asset))
	if v == nil {
		return TokenCustodyConfig{}, false
	}
	f := strings.Split(*v, "|")
	if len(f) != 3 {
		return TokenCustodyConfig{}, false
	}
	slot, err1 := strconv.ParseUint(f[0], 10, 64)
	bits, err2 := strconv.ParseUint(f[1], 10, 64)
	gap, ok := new(big.Int).SetString(f[2], 10)
	if err1 != nil || err2 != nil || !ok || bits == 0 || bits > 256 {
		return TokenCustodyConfig{}, false
	}
	return TokenCustodyConfig{Slot: slot, Bits: bits, Gap: gap}, true
}

// tokenCustodyProof is a token proof being assembled: the header, the token's
// storage root there, and the generations proven so far.
type tokenCustodyProof struct {
	height uint64
	root   [32]byte
	bals   map[uint32]*big.Int
}

func loadTokenCustodyProof(asset string) (tokenCustodyProof, bool) {
	cp := tokenCustodyProof{bals: map[uint32]*big.Int{}}
	s := sdk.StateGetObject(constants.TokenCustodyProofPrefix + asset)
	if s == nil {
		return cp, false
	}
	f := strings.SplitN(*s, "|", 3)
	if len(f) != 3 {
		return cp, false
	}
	h, err := strconv.ParseUint(f[0], 10, 64)
	root, rerr := hex.DecodeString(f[1])
	if err != nil || rerr != nil || len(root) != 32 {
		return cp, false
	}
	cp.height = h
	copy(cp.root[:], root)
	for _, e := range strings.Split(f[2], ",") {
		g, w, ok := strings.Cut(e, ":")
		if !ok {
			continue
		}
		gen, gerr := strconv.ParseUint(g, 10, 32)
		bal, okb := new(big.Int).SetString(w, 10)
		if gerr == nil && okb {
			cp.bals[uint32(gen)] = bal
		}
	}
	return cp, true
}

func saveTokenCustodyProof(asset string, cp tokenCustodyProof, gens []fundHoldingGen) {
	parts := make([]string, 0, len(cp.bals))
	for _, g := range gens { // registry order: deterministic
		if b, ok := cp.bals[g.Generation]; ok {
			parts = append(parts, strconv.FormatUint(uint64(g.Generation), 10)+":"+b.String())
		}
	}
	sdk.StateSetObject(constants.TokenCustodyProofPrefix+asset,
		strconv.FormatUint(cp.height, 10)+"|"+hex.EncodeToString(cp.root[:])+"|"+strings.Join(parts, ","))
}

// tokenAddress is a registered token's L1 address.
func tokenAddress(asset string) ([20]byte, error) {
	t, addrHex := TokenBySymbol(asset)
	if t == nil {
		return [20]byte{}, ce.NewContractError(ce.ErrInput, asset+" is not a registered token")
	}
	return crypto.HexToAddress(addrHex)
}

// tokenCustodyPreconditions: the check is on, the token has a setting, and h
// is no older than the newest credited deposit's block.
func tokenCustodyPreconditions(asset string, h uint64) (TokenCustodyConfig, error) {
	if sdk.StateGetObject(constants.CustodyCheckOffKey) != nil {
		return TokenCustodyConfig{}, ce.NewContractError(ce.ErrIntent, "the custody check is off (setCustodyCheck)")
	}
	cfg, ok := GetTokenCustody(asset)
	if !ok {
		return TokenCustodyConfig{}, ce.NewContractError(ce.ErrIntent, asset+" has no custody setting (setTokenCustody)")
	}
	if d := CreditedDepositBlock(); h < d {
		return TokenCustodyConfig{}, ce.NewContractError(ce.ErrIntent, "proof at block "+strconv.FormatUint(h, 10)+
			" is older than the newest credited deposit's block "+strconv.FormatUint(d, 10))
	}
	return cfg, nil
}

// HandleProveTokenRoot starts (or restarts at a newer header) a token's
// custody proof with the token contract's storage root.
func HandleProveTokenRoot(p *ProveTokenRootParams) (string, error) {
	if p == nil || p.Proof == nil || p.Asset == "" {
		return "", ce.NewContractError(ce.ErrInput, "proveTokenRoot: asset and proof required")
	}
	h := p.Proof.BlockHeight
	if _, err := tokenCustodyPreconditions(p.Asset, h); err != nil {
		return "", err
	}
	addr, err := tokenAddress(p.Asset)
	if err != nil {
		return "", err
	}
	cur, ok := loadTokenCustodyProof(p.Asset)
	if ok && cur.height > h {
		return "", ce.NewContractError(ce.ErrIntent, "a "+p.Asset+" custody proof at block "+
			strconv.FormatUint(cur.height, 10)+" is being assembled: prove at that block or a newer one")
	}
	root, err := provenStorageRoot(p.Proof, addr)
	if err != nil {
		return "", err
	}
	hs := strconv.FormatUint(h, 10)
	if ok && cur.height == h {
		// The same header has one storage root: keep the balances proven so
		// far (a repeated root proof must not discard another prover's work).
		return p.Asset + " storage root at block " + hs + " already proven", nil
	}
	saveTokenCustodyProof(p.Asset, tokenCustodyProof{height: h, root: root, bals: map[uint32]*big.Int{}}, nil)
	return p.Asset + " storage root at block " + hs + ": prove each generation's balance", nil
}

// provenStorageRoot is a contract account's storage root at the proof's
// header. A contract the state does not hold has no storage to prove.
func provenStorageRoot(p *AccountProof, addr [20]byte) ([32]byte, error) {
	header, raw, err := accountProofInput(p)
	if err != nil {
		return [32]byte{}, err
	}
	val, err := mpt.VerifyProof(header, crypto.Keccak256(addr[:]), splitProofNodes(raw))
	if err != nil {
		return [32]byte{}, prefixErr(err, "token account proof")
	}
	items, err := rlp.DecodeList(val)
	if err != nil || len(items) != 4 {
		return [32]byte{}, ce.NewContractError(ce.ErrInput, "token account proof: not an account record")
	}
	sr := items[2].AsBytes()
	if len(sr) != 32 {
		return [32]byte{}, ce.NewContractError(ce.ErrInput, "token account proof: bad storage root")
	}
	var root [32]byte
	copy(root[:], sr)
	return root, nil
}

// accountProofInput is the state root of the proof's stored header and the
// decoded proof nodes.
func accountProofInput(p *AccountProof) ([32]byte, []byte, error) {
	header := blocklist.GetHeader(p.BlockHeight)
	if header == nil {
		return [32]byte{}, nil, ErrBlockNotFound
	}
	raw, err := base64.StdEncoding.DecodeString(p.Proof)
	if err != nil || len(raw) == 0 {
		return [32]byte{}, nil, ce.NewContractError(ce.ErrInput, "account_proof must be base64 (concatenated state-trie nodes)")
	}
	return header.StateRoot, raw, nil
}

// TokenBalanceSlotKey is the storage key of holder's entry in a mapping at
// slot: keccak256(pad32(holder) ++ pad32(slot)), Solidity's layout.
func TokenBalanceSlotKey(holder [20]byte, slot uint64) []byte {
	buf := make([]byte, 64)
	copy(buf[12:32], holder[:])
	new(big.Int).SetUint64(slot).FillBytes(buf[32:64])
	return crypto.Keccak256(buf)
}

// emptyTrieRoot is the root of an empty trie, keccak256(rlp("")): a
// contract with no storage.
var emptyTrieRoot = [32]byte{
	0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
	0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
}

// prefixErr names where a proof failed without editing a shared sentinel
// error (ce.Prepend rewrites the error it is given).
func prefixErr(err error, prefix string) error {
	if c, ok := err.(*ce.ContractError); ok {
		return ce.NewContractError(c.Symbol, prefix+": "+c.Msg)
	}
	return ce.NewContractError(ce.ErrInput, prefix+": "+err.Error())
}

// provenTokenBalance is holder's balance word, masked to cfg.Bits, proven
// against root. A key the storage trie does not hold is 0, and so is every
// key of an empty storage trie (no proof nodes needed).
func provenTokenBalance(root [32]byte, holder [20]byte, cfg TokenCustodyConfig, proof string) (*big.Int, error) {
	if root == emptyTrieRoot {
		return new(big.Int), nil
	}
	raw, err := base64.StdEncoding.DecodeString(proof)
	if err != nil || len(raw) == 0 {
		return nil, ce.NewContractError(ce.ErrInput, "storage_proof must be base64 (concatenated storage-trie nodes)")
	}
	key := crypto.Keccak256(TokenBalanceSlotKey(holder, cfg.Slot))
	val, err := mpt.VerifyProof(root, key, splitProofNodes(raw))
	if err != nil {
		if errors.Is(err, mpt.ErrKeyNotFound) {
			return new(big.Int), nil
		}
		return nil, prefixErr(err, "storage proof")
	}
	// A storage value is the RLP string of the word, leading zeros dropped.
	item, _, err := rlp.Decode(val)
	if err != nil {
		return nil, ce.NewContractError(ce.ErrInput, "storage proof: bad value")
	}
	word := item.AsBytes()
	if len(word) > 32 {
		return nil, ce.NewContractError(ce.ErrInput, "storage proof: value longer than a word")
	}
	bal := new(big.Int).SetBytes(word)
	if cfg.Bits < 256 {
		mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(cfg.Bits)), big.NewInt(1))
		bal.And(bal, mask)
	}
	return bal, nil
}

// HandleProveTokenCustody records one generation's token balance and, once
// every fund-holding generation has one at the header, sets or clears the
// token's short flag.
func HandleProveTokenCustody(p *ProveTokenCustodyParams) (string, error) {
	if p == nil || p.Asset == "" {
		return "", ce.NewContractError(ce.ErrInput, "proveTokenCustody: asset, gen, block_height and storage_proof required")
	}
	cfg, err := tokenCustodyPreconditions(p.Asset, p.BlockHeight)
	if err != nil {
		return "", err
	}
	cp, ok := loadTokenCustodyProof(p.Asset)
	if !ok || cp.height != p.BlockHeight {
		return "", ce.NewContractError(ce.ErrIntent, "no "+p.Asset+" storage root at block "+
			strconv.FormatUint(p.BlockHeight, 10)+": proveTokenRoot at that block first")
	}
	gens := FundHoldingGens()
	var gen *fundHoldingGen
	for i := range gens {
		if gens[i].Generation == p.Gen {
			gen = &gens[i]
		}
	}
	if gen == nil {
		return "", ce.NewContractError(ce.ErrInput, "proveTokenCustody: generation "+strconv.FormatUint(uint64(p.Gen), 10)+" holds no funds")
	}
	bal, err := provenTokenBalance(cp.root, gen.Address, cfg, p.StorageProof)
	if err != nil {
		return "", err
	}
	cp.bals[p.Gen] = bal
	held := new(big.Int)
	for _, g := range gens {
		b, ok := cp.bals[g.Generation]
		if !ok {
			saveTokenCustodyProof(p.Asset, cp, gens)
			return p.Asset + " custody proof at block " + strconv.FormatUint(cp.height, 10) + ": " +
				strconv.Itoa(len(cp.bals)) + " of " + strconv.Itoa(len(gens)) + " generations", nil
		}
		held.Add(held, b)
	}
	sdk.StateDeleteObject(constants.TokenCustodyProofPrefix + p.Asset)
	return custodyVerdict(p.Asset, cp.height, held, GetSupply(p.Asset).Active, cfg.Gap), nil
}

// custodyVerdict compares what an asset's vault addresses hold with its
// booked custody and sets or clears the asset's short flag (and "si").
func custodyVerdict(asset string, h uint64, held, book, gap *big.Int) string {
	adoptLegacyHalt()
	// ETH keeps C2's exact text and log; a token's carry its symbol.
	hs, tag, logTag := strconv.FormatUint(h, 10), "", ""
	if asset != constants.NativeAsset {
		tag, logTag = " ("+asset+")", "|a="+asset
	}
	short := new(big.Int).Sub(book, held)
	if short.Cmp(gap) > 0 {
		setAssetShort(asset, hs)
		sdk.Log("security|evm-custody-short" + logTag + "|h=" + hs + "|held=" + held.String() + "|book=" + book.String())
		return "custody short at block " + hs + tag + ": held " + held.String() + " < booked " + book.String()
	}
	if clearAssetShort(asset) {
		sdk.Log("custody|solvent" + logTag + "|h=" + hs + "|held=" + held.String() + "|book=" + book.String())
	}
	return "custody held at block " + hs + tag + ": " + held.String() + " for booked " + book.String()
}

// adoptLegacyHalt: a bridge updated from the ETH-only custody proof may hold
// "si" with no per-asset flag; only ETH could have set it, so it is ETH's.
// Without this a token's held verdict would find no short asset and lift it.
func adoptLegacyHalt() {
	v := sdk.StateGetObject(constants.SolvencyHaltKey)
	if v == nil || *v == "" {
		return
	}
	for _, a := range vaultAssets() {
		if AssetShort(a) {
			return
		}
	}
	sdk.StateSetObject(constants.AssetShortPrefix+constants.NativeAsset, *v)
}

// AssetShort reports whether the newest complete proof found asset short.
func AssetShort(asset string) bool {
	v := sdk.StateGetObject(constants.AssetShortPrefix + asset)
	return v != nil && *v != ""
}

func setAssetShort(asset, h string) {
	if !AssetShort(asset) {
		sdk.StateSetObject(constants.AssetShortPrefix+asset, h)
	}
	if !SolvencyHalted() {
		sdk.StateSetObject(constants.SolvencyHaltKey, h)
	}
}

// clearAssetShort clears asset's flag and lifts "si" once no asset is short.
// It reports whether anything was lifted.
func clearAssetShort(asset string) bool {
	was := AssetShort(asset)
	sdk.StateDeleteObject(constants.AssetShortPrefix + asset)
	for _, a := range vaultAssets() {
		if AssetShort(a) {
			return was
		}
	}
	if SolvencyHalted() {
		sdk.StateDeleteObject(constants.SolvencyHaltKey)
		return true
	}
	return was
}
