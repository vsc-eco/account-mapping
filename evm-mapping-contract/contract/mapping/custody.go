package mapping

import (
	"errors"
	"math/big"
	"strconv"
	"strings"

	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/sdk"
)

// C2 — the EVM bridge's custody proof: THORChain's solvency check
// (handler_solvency_helpers.go insolvencyCheck: the vault's book against what
// the chain shows, halt when short, lift when a later check is solvent) for
// the bridge's ETH. Anyone proves, at one stored (ZK-verified) header, the ETH
// balance of every fund-holding generation's address. When the sum is more
// than DefaultCustodyGapWei below the booked custody Supply("eth").Active, the
// bridge sets "si" and the nodes stop lending shares for its vault keysigns,
// as for a proven theft ("th"; the evacuation sweep stays signable); a later
// complete proof showing the custody lifts it.
//
// Why the sum is a fair test at any header H no older than the newest
// credited deposit's block: the custody book is debited for a withdrawal
// (amount plus its gas at the estimate) when it is requested, before the L1
// transaction can mine; refunds and restores book back only value that never
// left the vault; a deposit is booked only after its block, and H is at least
// that block; a sweep between generations moves ETH between addresses that
// are all summed at the same header. So an honest bridge's addresses hold at
// least the book, less in-flight sweep gas, at every such H.
//
// Each generation is proven in its own call (two mainnet account proofs do
// not fit one 8 KB call); the proofs are kept until every fund-holding
// generation has one at the same header. A proof at an older header than the
// one being assembled is refused, so nobody can keep discarding another
// prover's progress. Permissionless and not pause-gated (a shortfall during a
// pause must still halt). Tokens: token_custody.go (storage proofs).

// ProveCustodyParams: one generation's account proof.
type ProveCustodyParams struct {
	Gen   uint32        `json:"gen"`
	Proof *AccountProof `json:"proof"`
}

type custodyProof struct {
	height uint64
	bals   map[uint32]*big.Int
}

func loadCustodyProof() custodyProof {
	cp := custodyProof{bals: map[uint32]*big.Int{}}
	s := sdk.StateGetObject(constants.CustodyProofKey)
	if s == nil {
		return cp
	}
	h, rest, _ := strings.Cut(*s, "|")
	cp.height, _ = strconv.ParseUint(h, 10, 64)
	for _, e := range strings.Split(rest, ",") {
		g, w, ok := strings.Cut(e, ":")
		if !ok {
			continue
		}
		gen, err := strconv.ParseUint(g, 10, 32)
		bal, okb := new(big.Int).SetString(w, 10)
		if err == nil && okb {
			cp.bals[uint32(gen)] = bal
		}
	}
	return cp
}

func saveCustodyProof(cp custodyProof, gens []fundHoldingGen) {
	parts := make([]string, 0, len(cp.bals))
	for _, g := range gens { // registry order: deterministic
		if b, ok := cp.bals[g.Generation]; ok {
			parts = append(parts, strconv.FormatUint(uint64(g.Generation), 10)+":"+b.String())
		}
	}
	sdk.StateSetObject(constants.CustodyProofKey, strconv.FormatUint(cp.height, 10)+"|"+strings.Join(parts, ","))
}

// CreditedDepositBlock is the newest L1 block a credited deposit came from.
func CreditedDepositBlock() uint64 {
	if s := sdk.StateGetObject(constants.CreditedDepositBlockKey); s != nil {
		n, _ := strconv.ParseUint(*s, 10, 64)
		return n
	}
	return 0
}

// noteCreditedDeposit records block as the newest credited deposit's when it is.
func noteCreditedDeposit(block uint64) {
	if block > CreditedDepositBlock() {
		sdk.StateSetObject(constants.CreditedDepositBlockKey, strconv.FormatUint(block, 10))
	}
}

// provenBalance is addr's ETH at the proof's header; a proven absence is 0.
func provenBalance(p *AccountProof, addr [20]byte) (*big.Int, error) {
	_, bal, err := ProvenAccount(p, addr)
	if err != nil {
		if errors.Is(err, mpt.ErrKeyNotFound) {
			return new(big.Int), nil
		}
		return nil, err
	}
	return bal, nil
}

// SolvencyHalted reports whether a custody proof found the bridge short.
func SolvencyHalted() bool {
	v := sdk.StateGetObject(constants.SolvencyHaltKey)
	return v != nil && *v != ""
}

// HandleProveCustody records one generation's proven ETH and, once every
// fund-holding generation has one at the same header, sets or lifts the halt.
func HandleProveCustody(p *ProveCustodyParams) (string, error) {
	if p == nil || p.Proof == nil {
		return "", ce.NewContractError(ce.ErrInput, "proveCustody: gen and proof required")
	}
	if sdk.StateGetObject(constants.CustodyCheckOffKey) != nil {
		return "", ce.NewContractError(ce.ErrIntent, "the custody check is off (setCustodyCheck)")
	}
	h := p.Proof.BlockHeight
	if d := CreditedDepositBlock(); h < d {
		return "", ce.NewContractError(ce.ErrIntent, "proof at block "+strconv.FormatUint(h, 10)+
			" is older than the newest credited deposit's block "+strconv.FormatUint(d, 10))
	}
	gens := FundHoldingGens()
	var gen *fundHoldingGen
	for i := range gens {
		if gens[i].Generation == p.Gen {
			gen = &gens[i]
		}
	}
	if gen == nil {
		return "", ce.NewContractError(ce.ErrInput, "proveCustody: generation "+strconv.FormatUint(uint64(p.Gen), 10)+" holds no funds")
	}
	bal, err := provenBalance(p.Proof, gen.Address)
	if err != nil {
		return "", err
	}
	cp := loadCustodyProof()
	if cp.height > h {
		return "", ce.NewContractError(ce.ErrIntent, "a custody proof at block "+strconv.FormatUint(cp.height, 10)+
			" is being assembled: prove at that block or a newer one")
	}
	if cp.height < h {
		cp = custodyProof{height: h, bals: map[uint32]*big.Int{}}
	}
	cp.bals[p.Gen] = bal
	held := new(big.Int)
	for _, g := range gens {
		b, ok := cp.bals[g.Generation]
		if !ok {
			saveCustodyProof(cp, gens)
			return "custody proof at block " + strconv.FormatUint(h, 10) + ": " +
				strconv.Itoa(len(cp.bals)) + " of " + strconv.Itoa(len(gens)) + " generations", nil
		}
		held.Add(held, b)
	}
	sdk.StateDeleteObject(constants.CustodyProofKey)
	gap, _ := new(big.Int).SetString(constants.DefaultCustodyGapWei, 10)
	return custodyVerdict(constants.NativeAsset, h, held, GetSupply(constants.NativeAsset).Active, gap), nil
}

// SetCustodyCheck is the owner's switch: off refuses custody proofs (ETH and
// tokens) and lifts every custody halt; on resumes.
func SetCustodyCheck(on bool) {
	if on {
		sdk.StateDeleteObject(constants.CustodyCheckOffKey)
		return
	}
	sdk.StateSetObject(constants.CustodyCheckOffKey, "1")
	sdk.StateDeleteObject(constants.SolvencyHaltKey)
	sdk.StateDeleteObject(constants.CustodyProofKey)
	for _, a := range vaultAssets() {
		sdk.StateDeleteObject(constants.AssetShortPrefix + a)
		sdk.StateDeleteObject(constants.TokenCustodyProofPrefix + a)
	}
}
