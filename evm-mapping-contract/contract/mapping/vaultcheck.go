package mapping

import (
	"encoding/hex"
	"strconv"
	"strings"

	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

// E23: the vault is the primary key's address (A18), but a key the TSS group
// agreed on whose committee cannot actually sign would keep every deposit
// sent to it, and unlike the BTC vault (CSV backup key) the EVM vault has no
// other way out. BTC's BRK-2 activates a vault generation only after its key
// has produced a verified check signature; here the contract does the same:
// the vault exists (TssVaultAddress) only once the key has signed
// VaultCheckDigest and someone has shown that signature with attestVault.
// Both steps are permissionless: only the key's committee can produce it.

// primaryKeyPub returns the primary key's public key hex when it is an ecdsa
// key that is active, or (unless activeOnly) deprecated.
func primaryKeyPub(activeOnly bool) (string, bool) {
	parts := strings.Split(sdk.TssGetKey("primary"), ",")
	if len(parts) < 3 || parts[2] != "ecdsa" {
		return "", false
	}
	if parts[0] != "active" && (activeOnly || parts[0] != "deprecated") {
		return "", false
	}
	return strings.ToLower(strings.TrimPrefix(parts[1], "0x")), true
}

func vaultVerified(pubHex string) bool {
	v := sdk.StateGetObject(constants.VaultCheckedKey)
	return v != nil && *v == pubHex
}

// VaultCheckDigest is what the primary key signs to show its committee can
// sign: a personal_sign (EIP-191) digest of a text naming this contract, its
// L1 chain and the key. The 0x19 prefix means it is never an L1 transaction's
// sighash, so the signature cannot move funds.
func VaultCheckDigest(contractId string, chainId uint64, pubHex string) []byte {
	msg := "magi evm vault check-signature v1:" + contractId + ":" + strconv.FormatUint(chainId, 10) + ":" + pubHex
	return crypto.Keccak256([]byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(msg)) + msg))
}

// HandleRequestVaultCheck asks the primary key's committee to sign the check
// message. The node keeps one request per message, so a repeat is free.
func HandleRequestVaultCheck(chainId uint64) error {
	pubHex, ok := primaryKeyPub(true)
	if !ok {
		return ce.NewContractError(ce.ErrAuth, "TSS key is not active")
	}
	if vaultVerified(pubHex) {
		return ce.NewContractError(ce.ErrInput, "vault already verified")
	}
	sdk.TssSignKey("primary", VaultCheckDigest(sdk.GetEnv().ContractId, chainId, pubHex))
	return nil
}

// HandleAttestVault puts the vault live once sigHex (65 bytes, r||s||v) over
// the check message recovers, low-S, to the primary key's address.
func HandleAttestVault(sigHex string, chainId uint64) error {
	pubHex, ok := primaryKeyPub(true)
	if !ok {
		return ce.NewContractError(ce.ErrAuth, "TSS key is not active")
	}
	if vaultVerified(pubHex) {
		return nil
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return ce.NewContractError(ce.ErrStateAccess, "TSS key is not hex")
	}
	addr, err := crypto.PubkeyAddress(pub)
	if err != nil {
		return ce.WrapContractError(ce.ErrStateAccess, err, "TSS key")
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil || len(sig) != 65 {
		return ce.NewContractError(ce.ErrInput, "signature must be 65 bytes hex (r, s, v)")
	}
	v := sig[64]
	if v >= 27 {
		v -= 27
	}
	if v > 1 {
		return ce.NewContractError(ce.ErrInput, "signature v must be 0, 1, 27 or 28")
	}
	got, err := crypto.EcrecoverStrict(VaultCheckDigest(sdk.GetEnv().ContractId, chainId, pubHex), v, sig[0:32], sig[32:64])
	if err != nil || got != addr {
		return ce.NewContractError(ce.ErrAuth, "not the primary key's signature over the vault check message")
	}
	sdk.StateSetObject(constants.VaultCheckedKey, pubHex)
	sdk.Log("vault|a=" + crypto.AddressToHex(addr) + "|k=" + pubHex)
	activateCheckedGenesis()
	return nil
}

// activateCheckedGenesis activates a pending genesis generation 0 (the "primary"
// key) once attestVault has verified its check signature, as the BTC contract's
// genesis vault activates as soon as its key is proven (A01). A rotation's
// generations activate only through activateKey. A failure leaves generation 0
// pending for activateKey to retry; the attestation itself stands. Otherwise
// the active generation is read now (ActiveVault folds a checked key not yet
// in the registry) and its address cached, so the first deposit does not pay
// for either (~2k RC).
func activateCheckedGenesis() {
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return
	}
	i := firstVaultWithStatus(vaults, VaultStatusPending)
	if i >= 0 && vaults[i].Generation == 0 && isGenesisVault(&vaults[i]) {
		if _, _, _, err := ActivatePendingGeneration(L1Height()); err != nil {
			sdk.Log("vault|genesis-pending|" + err.Error())
		}
		return
	}
	if v, ok := ActiveVault(); ok {
		GenAddress(&v)
	}
}
