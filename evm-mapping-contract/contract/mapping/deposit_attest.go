package mapping

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strconv"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
)

// I-28 (testnet 11-04): after a rotation depositAddress() named the new
// generation's MagiDeposit before anyone had deployed it, and MagiDeposit has
// no receive, fallback or flush (l1-deposit/src/MagiDeposit.sol): ETH sent to
// that address before its deployment stays there for good, never credited.
// A generation's MagiDeposit is now shown only once its code is proven on L1:
// attestDepositContract takes an account proof of the CREATE2 address at a
// stored header and records it. A CREATE2 address commits to its init code
// (constants/deposit_code.go), so code at it is MagiDeposit for that vault.
// THORChain (one permanent router) and Across (permanent SpokePools) never
// point a depositor at a contract that is not there; gating activateKey
// instead (as BTC's BRK-2 gates on a check signature) would stall a rotation
// on a manual deploy.

// emptyCodeHash is keccak256 of empty code: an account with no contract.
var emptyCodeHash, _ = hex.DecodeString("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

// AttestDepositContractParams proves generation Gen's MagiDeposit has code.
type AttestDepositContractParams struct {
	Gen         uint32 `json:"gen"`
	BlockHeight uint64 `json:"block_height"`
	Proof       string `json:"account_proof"` // base64, concatenated state-trie nodes
}

func depositContractAttestedKey(gen uint32) string {
	return constants.DepositContractAttestedPrefix + strconv.FormatUint(uint64(gen), 10)
}

// DepositContractAttested reports whether gen's MagiDeposit has been proven
// to have code.
func DepositContractAttested(gen uint32) bool {
	v := sdk.StateGetObject(depositContractAttestedKey(gen))
	return v != nil && *v != ""
}

// provenHasCode reports whether addr holds contract code at the proof's
// stored header. An account the trie does not hold has none.
func provenHasCode(blockHeight uint64, proof string, addr [20]byte) (bool, error) {
	header := blocklist.GetHeader(blockHeight)
	if header == nil {
		return false, ErrBlockNotFound
	}
	raw, err := base64.StdEncoding.DecodeString(proof)
	if err != nil || len(raw) == 0 {
		return false, ce.NewContractError(ce.ErrInput, "account_proof must be base64 (concatenated state-trie nodes)")
	}
	val, err := mpt.VerifyProof(header.StateRoot, crypto.Keccak256(addr[:]), splitProofNodes(raw))
	if err != nil {
		return false, ce.Prepend(err, "account proof")
	}
	if len(val) == 0 {
		return false, nil
	}
	items, err := rlp.DecodeList(val)
	if err != nil || len(items) != 4 {
		return false, ce.NewContractError(ce.ErrInput, "account proof: not an account record")
	}
	codeHash := items[3].AsBytes()
	if len(codeHash) != 32 {
		return false, ce.NewContractError(ce.ErrInput, "account proof: bad code hash")
	}
	return !bytes.Equal(codeHash, emptyCodeHash), nil
}

// genKeyAddress is generation gen's vault address: its recorded key's, or for
// a pending generation (keygen done, not yet active) its TSS key's.
func genKeyAddress(gen uint32) ([20]byte, bool) {
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return [20]byte{}, false
	}
	for i := range vaults {
		v := vaults[i]
		if v.Generation != gen {
			continue
		}
		if addr, ok := GenAddress(&v); ok {
			return addr, true
		}
		if v.Status == VaultStatusPending {
			if pub, ok := tssKeyPub(VaultKeyName(gen), "active"); ok {
				if addr, err := crypto.PubkeyAddress(pub[:]); err == nil {
					return addr, true
				}
			}
		}
		return [20]byte{}, false
	}
	return [20]byte{}, false
}

// HandleAttestDepositContract records that generation p.Gen's MagiDeposit has
// code at a stored header. Permissionless: it records only what the proof
// shows; calling it again is a no-op.
func HandleAttestDepositContract(p *AttestDepositContractParams) (string, error) {
	if p == nil {
		return "", ce.NewContractError(ce.ErrInput, "attestDepositContract: gen, block_height and account_proof required")
	}
	if DepositContractAttested(p.Gen) {
		return "MagiDeposit of generation " + strconv.FormatUint(uint64(p.Gen), 10) + " already attested", nil
	}
	vault, ok := genKeyAddress(p.Gen)
	if !ok {
		return "", ce.NewContractError(ce.ErrIntent, "generation "+strconv.FormatUint(uint64(p.Gen), 10)+" has no key address yet")
	}
	dc := DepositContractAddress(vault)
	has, err := provenHasCode(p.BlockHeight, p.Proof, dc)
	if err != nil {
		return "", err
	}
	if !has {
		return "", ce.NewContractError(ce.ErrIntent, "no code at "+crypto.ChecksumHex(dc)+" at L1 "+strconv.FormatUint(p.BlockHeight, 10)+
			": deploy MagiDeposit for "+crypto.ChecksumHex(vault)+" first (CREATE2 proxy, salt 0)")
	}
	sdk.StateSetObject(depositContractAttestedKey(p.Gen), strconv.FormatUint(p.BlockHeight, 10))
	return "attested MagiDeposit " + crypto.ChecksumHex(dc) + " of generation " + strconv.FormatUint(uint64(p.Gen), 10) +
		" at L1 " + strconv.FormatUint(p.BlockHeight, 10), nil
}

// ActiveDepositAddress is the active generation's MagiDeposit address once its
// code is attested; ok=false otherwise (depositAddress then answers "").
func ActiveDepositAddress() ([20]byte, bool) {
	v, ok := ActiveVault()
	if !ok || !DepositContractAttested(v.Generation) {
		return [20]byte{}, false
	}
	addr, ok := GenAddress(&v)
	if !ok {
		return [20]byte{}, false
	}
	return DepositContractAddress(addr), true
}
