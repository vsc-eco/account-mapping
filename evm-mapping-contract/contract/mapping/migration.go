package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"

	"evm-mapping-contract/contract/abi"
	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
)

// A01 migration: a superseded generation's funds move to the active one, so its
// key is left holding nothing. The BTC contract sweeps UTXOs (migration.go);
// here a sweep is an Ethereum transaction from the retiring address: one ERC-20
// transfer per token, then the ETH. Each is SIGNED by the retiring
// generation's key and PAYS the active generation's address, and nothing else:
// that is asserted here (consensus-executed) and again by the node before it
// lends a share of the retiring key (output scoping), as for BTC.
//
// All of a generation's sweeps are built in one batch at consecutive nonces,
// ETH first, with the token sweeps' gas kept back at the retiring address (see
// HandleMigrateVault): THORChain sweeps ETH last so a vault never holds tokens
// and no ETH (it once did, "until someone donated ETH"); keeping the gas back
// meets that and lets every asset land in one settle cycle. A retiring
// generation short of ETH for its token sweeps is topped up with an ordinary
// to_reserve deposit to its address (credited and booked like any late
// deposit). Sweep gas comes from the gas reserve, booked as ERC-20 withdrawal
// gas is. One batch in flight per generation at a time.
//
// The ETH sweep moves the PROVEN balance, less the gas kept back: an account
// proof against a stored header's state root, at the nonce of the
// generation's next sweep (so every earlier sweep has mined) and no older than
// its newest booked deposit (so the proof sees every booked wei). Stray ETH
// nobody mapped moves with it.

// SweepVersion is one signed version of a sweep. A re-drive signs a new version
// at the same nonce with a higher fee; only one can mine, and settlement
// accepts whichever did.
type SweepVersion struct {
	Value    string `json:"value"`    // ETH value of the tx (wei); "0" for a token sweep
	Unsigned string `json:"unsigned"` // hex of 0x02 || rlp(unsigned tx); its keccak is the sighash
	TipCap   uint64 `json:"tip"`
	FeeCap   uint64 `json:"fee_cap"`
}

// SweepRecord is an open migration sweep (ms-{gen}-{nonce}). The node reads
// Versions[].Unsigned to scope the retiring key's signatures.
type SweepRecord struct {
	Gen      uint32         `json:"gen"`
	Nonce    uint64         `json:"nonce"`
	Kind     string         `json:"kind"`  // "token" or "eth"
	Asset    string         `json:"asset"` // token symbol, or "eth"
	Token    string         `json:"token,omitempty"`
	Amount   string         `json:"amount"` // token units moved (token sweep)
	To       string         `json:"to"`     // the successor's address
	Gas      uint64         `json:"gas"`
	GasCost  string         `json:"gas_cost"` // booked from the reserve, all versions
	Booked   string         `json:"booked,omitempty"`
	BuiltL1  uint64         `json:"built_l1"`
	Versions []SweepVersion `json:"versions"`
}

const (
	sweepKindToken = "token"
	sweepKindETH   = "eth"
	sweepTipCap    = uint64(2_000_000_000) // 2 gwei, as withdrawals
	// SweepRedriveL1Blocks is how long a sweep version stays out before it may be
	// re-driven at a higher fee.
	SweepRedriveL1Blocks = uint64(32)
	// MaxSweepReverts is how many reverted transfers of one token a generation
	// takes before migration stops trying it (an owner write-off is then due).
	MaxSweepReverts = 2
)

func sweepKey(gen uint32, nonce uint64) string {
	return strconv.FormatUint(uint64(gen), 10) + constants.DirPathDelimiter + strconv.FormatUint(nonce, 10)
}

// GetSweep loads an open sweep record.
func GetSweep(gen uint32, nonce uint64) *SweepRecord {
	s := sdk.StateGetObject(constants.MigrationSweepPrefix + sweepKey(gen, nonce))
	if s == nil || *s == "" {
		return nil
	}
	var r SweepRecord
	if json.Unmarshal([]byte(*s), &r) != nil {
		return nil
	}
	return &r
}

func putSweep(r *SweepRecord) {
	b, err := json.Marshal(r)
	if err != nil {
		sdk.Abort("sweep record marshal failed")
	}
	k := sweepKey(r.Gen, r.Nonce)
	sdk.StateSetObject(constants.MigrationSweepPrefix+k, string(b))
	for _, o := range openSweeps() {
		if o == k {
			return
		}
	}
	sdk.StateSetObject(constants.MigrationSweepsKey, strings.Join(append(openSweeps(), k), "|"))
}

func closeSweep(r *SweepRecord) {
	k := sweepKey(r.Gen, r.Nonce)
	sdk.StateDeleteObject(constants.MigrationSweepPrefix + k)
	var keep []string
	for _, o := range openSweeps() {
		if o != k {
			keep = append(keep, o)
		}
	}
	if len(keep) == 0 {
		sdk.StateDeleteObject(constants.MigrationSweepsKey)
		return
	}
	sdk.StateSetObject(constants.MigrationSweepsKey, strings.Join(keep, "|"))
}

func sweepRevertKey(gen uint32, asset string) string {
	return "msx" + constants.DirPathDelimiter + strconv.FormatUint(uint64(gen), 10) + constants.DirPathDelimiter + asset
}

func sweepReverts(gen uint32, asset string) int {
	if s := sdk.StateGetObject(sweepRevertKey(gen, asset)); s != nil {
		n, _ := strconv.Atoi(*s)
		return n
	}
	return 0
}

// tokenBySymbol returns a registered token's address and info.
func tokenBySymbol(chainId uint64, symbol string) ([20]byte, *TokenInfo, bool) {
	ref := sdk.StateGetObject(constants.TokenSymbolPrefix + symbol)
	if ref == nil {
		return [20]byte{}, nil, false
	}
	i := strings.IndexByte(*ref, '-')
	if i < 0 {
		return [20]byte{}, nil, false
	}
	addr, err := crypto.HexToAddress((*ref)[i+1:])
	if err != nil {
		return [20]byte{}, nil, false
	}
	info := getTokenInfo(chainId, addr)
	return addr, info, info != nil
}

// AccountProof is an eth_getProof account proof of a generation's address at a
// stored header.
type AccountProof struct {
	BlockHeight uint64 `json:"block_height"`
	Proof       string `json:"account_proof"` // base64, concatenated state-trie nodes
}

// ProvenAccount returns an address's nonce and balance at a stored header. An
// account the trie does not hold is a fresh one: nonce 0, balance 0.
func ProvenAccount(p *AccountProof, addr [20]byte) (uint64, *big.Int, error) {
	header := blocklist.GetHeader(p.BlockHeight)
	if header == nil {
		return 0, nil, ErrBlockNotFound
	}
	raw, err := base64.StdEncoding.DecodeString(p.Proof)
	if err != nil || len(raw) == 0 {
		return 0, nil, ce.NewContractError(ce.ErrInput, "account_proof must be base64 (concatenated state-trie nodes)")
	}
	val, err := mpt.VerifyProof(header.StateRoot, crypto.Keccak256(addr[:]), splitProofNodes(raw))
	if err != nil {
		return 0, nil, ce.Prepend(err, "account proof")
	}
	if len(val) == 0 {
		return 0, new(big.Int), nil
	}
	items, err := rlp.DecodeList(val)
	if err != nil || len(items) != 4 {
		return 0, nil, ce.NewContractError(ce.ErrInput, "account proof: not an account record")
	}
	nonce, err := items[0].AsUint64Checked()
	if err != nil {
		return 0, nil, ce.NewContractError(ce.ErrInput, "account proof: bad nonce")
	}
	return nonce, new(big.Int).SetBytes(items[1].AsBytes()), nil
}

func lastBookedKey(gen uint32) string {
	return "vbh" + constants.DirPathDelimiter + strconv.FormatUint(uint64(gen), 10)
}

// noteBookedHeight remembers the newest L1 block whose deposit was booked to a
// superseded generation: an ETH sweep's balance proof must not be older.
func noteBookedHeight(gen uint32, l1 uint64) {
	if l1 > lastBookedHeight(gen) {
		sdk.StateSetObject(lastBookedKey(gen), strconv.FormatUint(l1, 10))
	}
}

func lastBookedHeight(gen uint32) uint64 {
	if s := sdk.StateGetObject(lastBookedKey(gen)); s != nil {
		n, _ := strconv.ParseUint(*s, 10, 64)
		return n
	}
	return 0
}

// migrationTarget is the first funded Retiring, else Draining, generation (BTC
// SHADOW R0: an empty one never shadows a funded one) and the active successor.
func migrationTarget() (target *Vault, successor *Vault, vaults VaultRegistry, err error) {
	FoldLegacyKeyIfNeeded(false)
	vaults, _, _, err = LoadVaultState()
	if err != nil {
		return nil, nil, nil, err
	}
	for _, want := range []VaultStatus{VaultStatusRetiring, VaultStatusDraining} {
		for i := range vaults {
			if vaults[i].Status == want && genFunded(vaults[i].Generation) {
				target = &vaults[i]
				break
			}
		}
		if target != nil {
			break
		}
	}
	for i := range vaults {
		if vaults[i].Status == VaultStatusActive {
			successor = &vaults[i]
		}
	}
	return target, successor, vaults, nil
}

// HandleMigrateVault builds the sweeps of a superseded generation, all of them
// at once (ROT-WINDOW-EVM): the ETH sweep at the generation's next nonce, then
// one transfer per token at the nonces after it. They sign in the same TSS
// sign interval and settle in one L1 finality and header cycle. Withdrawals
// wait for the active generation to hold what they pay (activeGenCovers), so
// sweeping one asset per cycle kept them waiting one settle cycle per asset
// (about 30 min each on mainnet), and a token that kept reverting held the
// ETH, and with it every withdrawal's gas, behind it.
//
// The ETH goes first, less SweepGasHeadroom times the token sweeps' gas, which
// stays at the retiring address to pay them (THORChain's reason for sweeping
// ETH last, met by keeping the gas back instead). A token sweep can then
// revert, or be re-driven, without holding up the ETH.
//
// It returns a status: the sweeps built, or why nothing was (benign states
// return a status, not an error, so a driver can poll it). ethProof is needed
// whenever the generation's booked ETH is more than the gas its token sweeps
// keep back.
func HandleMigrateVault(chainId uint64, ethProof *AccountProof) (string, error) {
	target, successor, _, err := migrationTarget()
	if err != nil {
		return "", err
	}
	if target == nil {
		return "nothing to migrate", nil
	}
	if successor == nil {
		return "", ce.NewContractError(ce.ErrTransaction, "no active successor vault to migrate into")
	}
	// No funds move into the successor until its key has been handed on by a
	// reshare since its keygen (BTC migrateVault; TssGetKey field 5).
	if p := tssKeyParts(VaultKeyName(successor.Generation)); !(len(p) >= 5 && p[0] == "active" && p[4] == "1") {
		return "", ce.NewContractError(ce.ErrTransaction,
			"the active generation's key has not been reshared since its keygen: migration waits for its first reshare")
	}
	gen := target.Generation
	if hasOpenSweep(gen) {
		return "sweep in flight for generation " + strconv.FormatUint(uint64(gen), 10), nil
	}
	successorAddr, ok := GenAddress(successor)
	if !ok {
		return "", ce.NewContractError(ce.ErrTransaction, "the active generation has no address")
	}
	retiringAddr, ok := GenAddress(target)
	if !ok {
		return "", ce.NewContractError(ce.ErrTransaction, "the retiring generation has no address")
	}
	header, err := pricingHeader()
	if err != nil {
		return "", err
	}
	plans, tokenGas, stuck, err := planTokenSweeps(chainId, gen, header)
	if err != nil {
		return "", err
	}
	keep := new(big.Int).Mul(tokenGas, big.NewInt(SweepGasHeadroom))
	ethBook := VaultBook(gen, constants.NativeAsset)
	genStr := strconv.FormatUint(uint64(gen), 10)

	var eth *ethSweepPlan
	if ethProof == nil {
		if ethBook.Cmp(keep) > 0 {
			return "", ce.NewContractError(ce.ErrInput, "the ETH sweep is next: send eth_proof (an account proof of the retiring address)")
		}
		if len(plans) == 0 {
			if stuck != "" {
				return stuckTokenStatus(gen, stuck), nil
			}
			return "nothing to migrate", nil
		}
		// Token sweeps alone: a retry after a revert, or a token that arrived
		// after the ETH left. Their gas is the ETH kept back for them.
		if ethBook.Cmp(tokenGas) < 0 {
			return tooLittleGasStatus(gen, retiringAddr, tokenGas), nil
		}
	} else {
		var balance *big.Int
		eth, balance, err = planETHSweep(gen, retiringAddr, ethProof, keep, header)
		if err != nil {
			return "", err
		}
		if eth == nil {
			if len(plans) == 0 {
				if stuck != "" {
					return stuckTokenStatus(gen, stuck), nil
				}
				return "generation " + genStr + " holds no more ETH than one sweep's gas: dust, for writeOffDust", nil
			}
			// No ETH beyond the token gas: the token sweeps go alone, paid from
			// what the proof shows is there.
			if ethBook.Cmp(tokenGas) < 0 || balance.Cmp(tokenGas) < 0 {
				return tooLittleGasStatus(gen, retiringAddr, tokenGas), nil
			}
		}
	}

	note := ""
	if eth != nil && len(plans) > 0 && new(big.Int).Sub(ethBook, eth.cost).Cmp(tokenGas) < 0 {
		// The proof shows ETH the books do not hold (stray), and the books are
		// short of the token gas: the ETH goes now, keeping the gas back on L1;
		// the tokens follow once their gas is booked (a to_reserve top-up).
		plans, tokenGas = nil, new(big.Int)
		note = "; " + tooLittleGasStatus(gen, retiringAddr, keep)
	}
	total := new(big.Int).Set(tokenGas)
	if eth != nil {
		total.Add(total, eth.cost)
	}
	if getGasReserve().Cmp(total) < 0 {
		return "gas reserve below the sweeps' gas (" + total.String() + " wei): migration waits for a reserve top-up", nil
	}

	nonce := SweepNonce(gen)
	var built []string
	if eth != nil {
		built = append(built, buildETHSweep(chainId, gen, nonce, successorAddr, eth))
		nonce++
	}
	for i := range plans {
		built = append(built, buildTokenSweep(chainId, gen, nonce, successorAddr, &plans[i]))
		nonce++
	}
	setSweepNonce(gen, nonce)
	markDraining(gen)
	return strings.Join(built, "; ") + note, nil
}

// SweepGasHeadroom is how many times its token sweeps' gas a generation keeps
// back from its ETH sweep. Each re-drive raises a sweep's fee cap by 10%, so
// twice the gas covers about seven re-drives of every token sweep; the rest is
// swept with the generation's leftover ETH once they settle.
const SweepGasHeadroom = 2

type tokenSweepPlan struct {
	sym    string
	token  [20]byte
	amount *big.Int
	gas    uint64
	limit  uint64 // the token's registered gas limit (0: default)
	feeCap uint64
	cost   *big.Int
}

// planTokenSweeps prices a transfer of every token the generation holds, in
// registration order, and sums their gas. A token whose transfers reverted
// MaxSweepReverts times is left out and named in stuck.
func planTokenSweeps(chainId uint64, gen uint32, header *blocklist.EthBlockHeader) ([]tokenSweepPlan, *big.Int, string, error) {
	var plans []tokenSweepPlan
	gas := new(big.Int)
	stuck := ""
	for _, sym := range RegisteredSymbols() {
		amt := VaultBook(gen, sym)
		if amt.Sign() <= 0 {
			continue
		}
		if sweepReverts(gen, sym) >= MaxSweepReverts {
			if stuck == "" {
				stuck = sym
			}
			continue
		}
		tokenAddr, info, ok := tokenBySymbol(chainId, sym)
		if !ok {
			return nil, nil, "", ce.NewContractError(ce.ErrStateAccess, "registered symbol "+sym+" has no token record")
		}
		g := TokenGasLimit(info.GasLimit)
		feeCap, cost, err := safeGasFee(g, header.BaseFeePerGas, 2, sweepTipCap)
		if err != nil {
			return nil, nil, "", err
		}
		plans = append(plans, tokenSweepPlan{sym: sym, token: tokenAddr, amount: amt, gas: g, limit: info.GasLimit, feeCap: feeCap, cost: cost})
		gas.Add(gas, cost)
	}
	return plans, gas, stuck, nil
}

func stuckTokenStatus(gen uint32, sym string) string {
	return "generation " + strconv.FormatUint(uint64(gen), 10) + " holds " + sym + " whose transfers reverted " +
		strconv.Itoa(MaxSweepReverts) + " times: an owner write-off is needed"
}

func tooLittleGasStatus(gen uint32, from [20]byte, gas *big.Int) string {
	return "generation " + strconv.FormatUint(uint64(gen), 10) + " holds too little ETH for its token sweeps' gas (" +
		gas.String() + " wei): top it up with a to_reserve deposit to " + crypto.AddressToHex(from)
}

type ethSweepPlan struct {
	value  *big.Int
	keep   *big.Int // the token sweeps' gas, kept back at the retiring address
	gas    uint64
	feeCap uint64
	cost   *big.Int
}

// planETHSweep proves the retiring address's balance at the generation's next
// nonce and prices the ETH sweep: everything less its own gas and keep. The
// plan is nil when nothing is left to send; the proven balance is returned
// either way.
func planETHSweep(gen uint32, from [20]byte, p *AccountProof, keep *big.Int, header *blocklist.EthBlockHeader) (*ethSweepPlan, *big.Int, error) {
	nonce := SweepNonce(gen)
	if p.BlockHeight < lastBookedHeight(gen) {
		return nil, nil, ce.NewContractError(ce.ErrInput, "the balance proof is older than the generation's newest booked deposit")
	}
	provenNonce, balance, err := ProvenAccount(p, from)
	if err != nil {
		return nil, nil, err
	}
	if provenNonce != nonce {
		return nil, nil, ce.NewContractError(ce.ErrInput, "the balance proof is at L1 nonce "+strconv.FormatUint(provenNonce, 10)+
			", the generation's next sweep is nonce "+strconv.FormatUint(nonce, 10)+": prove a block after its last sweep mined")
	}
	gas := defaultETHGasLimit()
	feeCap, cost, err := safeGasFee(gas, header.BaseFeePerGas, 2, sweepTipCap)
	if err != nil {
		return nil, nil, err
	}
	value := new(big.Int).Sub(balance, cost)
	value.Sub(value, keep)
	if value.Sign() <= 0 {
		return nil, balance, nil
	}
	return &ethSweepPlan{value: value, keep: keep, gas: gas, feeCap: feeCap, cost: cost}, balance, nil
}

func buildETHSweep(chainId uint64, gen uint32, nonce uint64, successor [20]byte, e *ethSweepPlan) string {
	unsigned := BuildETHWithdrawalTxGas(chainId, nonce, sweepTipCap, e.feeCap, successor, e.value, e.gas)
	if err := assertSweepPaysSuccessor(unsigned, successor); err != nil {
		ce.CustomAbort(err)
	}
	deductGasReserve(e.cost)
	TrackReserveSpend(e.cost)
	addVaultBook(gen, constants.NativeAsset, new(big.Int).Neg(minBig(e.cost, VaultBook(gen, constants.NativeAsset))))
	// The books move what the generation holds less the token gas kept back,
	// and never more than the transaction sends.
	booked := new(big.Int).Sub(VaultBook(gen, constants.NativeAsset), e.keep)
	if booked.Sign() < 0 {
		booked.SetInt64(0)
	}
	booked = minBig(booked, e.value)
	r := &SweepRecord{
		Gen: gen, Nonce: nonce, Kind: sweepKindETH, Asset: constants.NativeAsset,
		To: crypto.AddressToHex(successor), Gas: e.gas, GasCost: e.cost.String(),
		Booked:   booked.String(),
		BuiltL1:  blocklist.GetLastHeight(),
		Versions: []SweepVersion{{Value: e.value.String(), Unsigned: hex.EncodeToString(unsigned), TipCap: sweepTipCap, FeeCap: e.feeCap}},
	}
	putSweep(r)
	sdk.TssSignKey(VaultKeyName(gen), ComputeSighash(unsigned))
	sdk.Log("sweep|g=" + strconv.FormatUint(uint64(gen), 10) + "|n=" + strconv.FormatUint(nonce, 10) + "|a=eth|v=" + e.value.String() + "|to=" + r.To)
	return "sweep " + sweepKey(gen, nonce) + " eth " + e.value.String()
}

func buildTokenSweep(chainId uint64, gen uint32, nonce uint64, successor [20]byte, t *tokenSweepPlan) string {
	unsigned := BuildERC20WithdrawalTxGas(chainId, nonce, sweepTipCap, t.feeCap, t.token, successor, t.amount, t.limit)
	if err := assertSweepPaysSuccessor(unsigned, successor); err != nil {
		ce.CustomAbort(err)
	}
	// The gas is the retiring address's ETH, booked from the reserve.
	deductGasReserve(t.cost)
	TrackReserveSpend(t.cost)
	addVaultBook(gen, constants.NativeAsset, new(big.Int).Neg(t.cost))
	r := &SweepRecord{
		Gen: gen, Nonce: nonce, Kind: sweepKindToken, Asset: t.sym, Token: crypto.AddressToHex(t.token),
		Amount: t.amount.String(), To: crypto.AddressToHex(successor), Gas: t.gas, GasCost: t.cost.String(),
		BuiltL1:  blocklist.GetLastHeight(),
		Versions: []SweepVersion{{Value: "0", Unsigned: hex.EncodeToString(unsigned), TipCap: sweepTipCap, FeeCap: t.feeCap}},
	}
	putSweep(r)
	sdk.TssSignKey(VaultKeyName(gen), ComputeSighash(unsigned))
	sdk.Log("sweep|g=" + strconv.FormatUint(uint64(gen), 10) + "|n=" + strconv.FormatUint(nonce, 10) + "|a=" + t.sym + "|v=" + r.Amount + "|to=" + r.To)
	return "sweep " + sweepKey(gen, nonce) + " " + t.sym + " " + r.Amount
}

// markDraining moves a Retiring generation to Draining once its first sweep is
// built (BTC: the first tranche flips it).
func markDraining(gen uint32) {
	vaults, nextGen, activeGen, err := LoadVaultState()
	if err != nil {
		return
	}
	for i := range vaults {
		if vaults[i].Generation == gen && vaults[i].Status == VaultStatusRetiring {
			vaults[i].Status = VaultStatusDraining
			SaveVaultState(vaults, nextGen, activeGen)
			return
		}
	}
}

func minBig(a, b *big.Int) *big.Int {
	if a.Cmp(b) < 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
}

// assertSweepPaysSuccessor decodes a sweep tx as the node will and requires that
// it pays only the successor: an ETH transfer to it with no data, or a zero-value
// ERC-20 transfer(successor, x). NN#1 layer 1.
func assertSweepPaysSuccessor(unsigned []byte, successor [20]byte) error {
	to, value, data, err := decodeUnsignedEIP1559(unsigned)
	if err != nil {
		return err
	}
	if value.Sign() > 0 {
		if to != successor || len(data) != 0 {
			return ce.NewContractError(ce.ErrTransaction, "sweep does not pay the successor vault (NN#1)")
		}
		return nil
	}
	if len(data) != 68 || !bytesEqual(data[0:4], abi.TransferSelector) {
		return ce.NewContractError(ce.ErrTransaction, "sweep is not an ERC-20 transfer (NN#1)")
	}
	var padded [32]byte
	copy(padded[12:], successor[:])
	if !bytesEqual(data[4:36], padded[:]) {
		return ce.NewContractError(ce.ErrTransaction, "sweep transfer does not pay the successor vault (NN#1)")
	}
	return nil
}

// decodeUnsignedEIP1559 reads to, value and data of 0x02 || rlp(unsigned tx).
func decodeUnsignedEIP1559(unsigned []byte) ([20]byte, *big.Int, []byte, error) {
	var to [20]byte
	if len(unsigned) < 2 || unsigned[0] != 0x02 {
		return to, nil, nil, errors.New("not an EIP-1559 transaction")
	}
	whole, n, err := rlp.Decode(unsigned[1:])
	if err != nil || n != len(unsigned)-1 || !whole.IsList || len(whole.Children) != 9 {
		return to, nil, nil, errors.New("malformed EIP-1559 transaction")
	}
	items := whole.Children
	t := items[5].AsBytes()
	if len(t) != 20 {
		return to, nil, nil, errors.New("transaction has no 20-byte destination")
	}
	copy(to[:], t)
	return to, new(big.Int).SetBytes(items[6].AsBytes()), items[7].AsBytes(), nil
}

// ConfirmSweepRequest proves a sweep's transaction mined.
type ConfirmSweepRequest struct {
	Gen          uint32 `json:"gen"`
	Nonce        uint64 `json:"nonce"`
	BlockHeight  uint64 `json:"block_height"`
	TxIndex      uint64 `json:"tx_index"`
	TxProof      string `json:"tx_proof"`      // base64 tx-trie nodes, leaf = the raw tx
	ReceiptProof string `json:"receipt_proof"` // base64 receipt-trie nodes, leaf = the receipt
}

// HandleConfirmSweep settles a mined sweep. Permissionless and not
// pause-gated, as confirmSpend: it records an L1 fact and authorizes nothing.
//
// Mined with status 1, the transfer moved: the retiring generation's book drops
// by what left (a token amount, after the receipt's Transfer log shows it went
// to the successor, A36; or for ETH, everything booked at the build). Status 0:
// nothing moved but the gas; a token that reverts MaxSweepReverts times is left
// for an owner write-off.
func HandleConfirmSweep(req *ConfirmSweepRequest, chainId uint64) error {
	r := GetSweep(req.Gen, req.Nonce)
	if r == nil {
		return ce.NewContractError(ce.ErrIntent, "no open sweep "+sweepKey(req.Gen, req.Nonce))
	}
	if req.BlockHeight <= r.BuiltL1 {
		return ce.NewContractError(ce.ErrIntent, "confirmation block must be after the sweep was built")
	}
	header := blocklist.GetHeader(req.BlockHeight)
	if header == nil {
		return ErrBlockNotFound
	}
	txRaw, err := base64.StdEncoding.DecodeString(req.TxProof)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "tx_proof is not base64")
	}
	key := rlp.EncodeUint64(req.TxIndex)
	txBytes, err := mpt.VerifyProof(header.TransactionsRoot, key, splitProofNodes(txRaw))
	if err != nil {
		return ce.Prepend(err, "tx proof")
	}
	tx, err := parseTransaction(txBytes)
	if err != nil {
		return ce.Prepend(err, "parse proven tx")
	}
	if tx.Nonce != r.Nonce || tx.ChainId != chainId {
		return ce.NewContractError(ce.ErrTransaction, "tx nonce or chain does not match the sweep")
	}
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return err
	}
	var from [20]byte
	found := false
	for i := range vaults {
		if vaults[i].Generation == r.Gen {
			from, found = GenAddress(&vaults[i])
		}
	}
	if !found {
		return ce.NewContractError(ce.ErrStateAccess, "the sweep's generation has no address")
	}
	sender, err := crypto.EcrecoverStrict(computeTxSighash(txBytes, tx), 27+tx.V, padTo32(tx.R), padTo32(tx.S))
	if err != nil || sender != from {
		return ce.NewContractError(ce.ErrTransaction, "tx not signed by the retiring generation")
	}
	// The mined tx must be one of the signed versions: same destination and
	// data, and a value one of them carries.
	var mined *SweepVersion
	for i := range r.Versions {
		vto, vval, vdata, derr := decodeUnsignedEIP1559(hexBytes(r.Versions[i].Unsigned))
		if derr == nil && vto == tx.To && bytesEqual(vdata, tx.Data) && vval.Cmp(new(big.Int).SetBytes(tx.Value)) == 0 {
			mined = &r.Versions[i]
			break
		}
	}
	if mined == nil {
		return ce.NewContractError(ce.ErrTransaction, "tx does not match any signed version of the sweep")
	}

	rcRaw, err := base64.StdEncoding.DecodeString(req.ReceiptProof)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "receipt_proof is not base64")
	}
	receipt, err := mpt.VerifyProof(header.ReceiptsRoot, key, splitProofNodes(rcRaw))
	if err != nil {
		return ce.Prepend(err, "receipt proof")
	}
	body := receipt
	if len(body) > 0 && body[0] <= 0x7f {
		body = body[1:]
	}
	items, err := rlp.DecodeList(body)
	if err != nil || len(items) < 4 {
		return ce.NewContractError(ce.ErrInput, "invalid receipt RLP")
	}
	succeeded := items[0].AsUint64() == 1
	to, _ := crypto.HexToAddress(r.To)
	if succeeded && r.Kind == sweepKindToken {
		amt, _ := new(big.Int).SetString(r.Amount, 10)
		logs, lerr := parseReceiptLogs(receipt)
		if lerr != nil || !receiptHasTransfer(logs, tx.To, from, to, amt) {
			// A36: status 1 without the transfer (a token that returns false).
			succeeded = false
		}
	}

	if succeeded {
		if r.Kind == sweepKindToken {
			amt, _ := new(big.Int).SetString(r.Amount, 10)
			addVaultBook(r.Gen, r.Asset, new(big.Int).Neg(amt))
		} else {
			booked, _ := new(big.Int).SetString(r.Booked, 10)
			addVaultBook(r.Gen, constants.NativeAsset, new(big.Int).Neg(minBig(booked, VaultBook(r.Gen, constants.NativeAsset))))
		}
		sdk.Log("sweepok|g=" + strconv.FormatUint(uint64(r.Gen), 10) + "|n=" + strconv.FormatUint(r.Nonce, 10) + "|a=" + r.Asset + "|v=" + mined.Value)
	} else {
		if r.Kind == sweepKindToken {
			sdk.StateSetObject(sweepRevertKey(r.Gen, r.Asset), strconv.Itoa(sweepReverts(r.Gen, r.Asset)+1))
		}
		sdk.Log("sweepfail|g=" + strconv.FormatUint(uint64(r.Gen), 10) + "|n=" + strconv.FormatUint(r.Nonce, 10) + "|a=" + r.Asset)
	}
	closeSweep(r)
	return nil
}

func receiptHasTransfer(logs []ParsedLog, token, from, to [20]byte, amt *big.Int) bool {
	for _, l := range logs {
		if l.Address != token || len(l.Topics) < 3 || l.Topics[0] != TransferEventSig || len(l.Data) != 32 {
			continue
		}
		f, ok1 := topicAddress(l.Topics[1])
		t, ok2 := topicAddress(l.Topics[2])
		if ok1 && ok2 && f == from && t == to && new(big.Int).SetBytes(l.Data).Cmp(amt) == 0 {
			return true
		}
	}
	return false
}

func hexBytes(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// HandleRedriveSweep re-signs a stuck sweep at the same nonce with a fee at
// least 10% higher (EIP-1559 replacement) after SweepRedriveL1Blocks. The extra
// gas is booked from the reserve; an ETH sweep sends that much less.
func HandleRedriveSweep(gen uint32, nonce uint64, chainId uint64) (string, error) {
	r := GetSweep(gen, nonce)
	if r == nil {
		return "", ce.NewContractError(ce.ErrIntent, "no open sweep "+sweepKey(gen, nonce))
	}
	l1 := blocklist.GetLastHeight()
	if l1 < r.BuiltL1+SweepRedriveL1Blocks {
		return "", ce.NewContractError(ce.ErrIntent, "sweep was (re)built at L1 "+strconv.FormatUint(r.BuiltL1, 10)+
			": re-drive from L1 "+strconv.FormatUint(r.BuiltL1+SweepRedriveL1Blocks, 10))
	}
	header, err := pricingHeader()
	if err != nil {
		return "", err
	}
	last := r.Versions[len(r.Versions)-1]
	tip := last.TipCap + last.TipCap/10 + 1
	feeCap, _, err := safeGasFee(r.Gas, header.BaseFeePerGas, 2, tip)
	if err != nil {
		return "", err
	}
	if min := last.FeeCap + last.FeeCap/10 + 1; feeCap < min {
		feeCap = min
	}
	extra := new(big.Int).Mul(new(big.Int).SetUint64(r.Gas), new(big.Int).SetUint64(feeCap-last.FeeCap))
	if getGasReserve().Cmp(extra) < 0 {
		return "", ce.NewContractError(ce.ErrIntent, "gas reserve below the re-drive's extra gas")
	}
	to, _ := crypto.HexToAddress(r.To)
	var unsigned []byte
	value := new(big.Int)
	if r.Kind == sweepKindToken {
		if VaultBook(gen, constants.NativeAsset).Cmp(extra) < 0 {
			return "", ce.NewContractError(ce.ErrIntent, "the retiring address holds too little ETH for the higher fee")
		}
		tokenAddr, _ := crypto.HexToAddress(r.Token)
		amt, _ := new(big.Int).SetString(r.Amount, 10)
		unsigned = BuildERC20WithdrawalTxGas(chainId, nonce, tip, feeCap, tokenAddr, to, amt, r.Gas)
		addVaultBook(gen, constants.NativeAsset, new(big.Int).Neg(extra))
	} else {
		value.SetString(last.Value, 10)
		value.Sub(value, extra)
		if value.Sign() <= 0 {
			return "", ce.NewContractError(ce.ErrIntent, "the higher fee would take the whole ETH sweep")
		}
		unsigned = BuildETHWithdrawalTxGas(chainId, nonce, tip, feeCap, to, value, r.Gas)
	}
	if err := assertSweepPaysSuccessor(unsigned, to); err != nil {
		return "", err
	}
	deductGasReserve(extra)
	TrackReserveSpend(extra)
	cost, _ := new(big.Int).SetString(r.GasCost, 10)
	r.GasCost = cost.Add(cost, extra).String()
	r.BuiltL1 = l1
	r.Versions = append(r.Versions, SweepVersion{Value: value.String(), Unsigned: hex.EncodeToString(unsigned), TipCap: tip, FeeCap: feeCap})
	putSweep(r)
	sdk.TssSignKey(VaultKeyName(gen), ComputeSighash(unsigned))
	return "re-drove sweep " + sweepKey(gen, nonce) + " at fee cap " + strconv.FormatUint(feeCap, 10), nil
}
