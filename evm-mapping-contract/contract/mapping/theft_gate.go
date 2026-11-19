package mapping

import (
	"strconv"

	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

// P1 THEFT-HALT-EVM (BTC parity: btc-mapping-contract theft_gate.go,
// reportUnauthorizedSpend + clearTheftHalt). The BTC contract lets anyone prove
// with SPV that a registered vault coin was spent by a transaction it did not
// authorize; it then sets "th" and every node stops issuing BTC vault keysigns.
//
// An EVM vault is an account: every transaction it sends uses its next nonce,
// so the contract's own counters say how many transactions it ever authorized
// from each generation's address (authorizedNonceCount): the withdrawal nonces
// while the generation was active (they restart at 0 for each new active
// address), and the sweep nonces after its cut-over (they start at its
// withdrawal ceiling). Re-drives, replacements and roll-backs re-sign an
// already authorized nonce; the vault check signs a message, not a
// transaction. So a vault address whose nonce, proven by an account proof
// against a ZK-verified header, is ABOVE its authorized count has sent a
// transaction the contract never asked for: a stolen or rogue key. That is the
// report. It moves no funds and sets only the flag the node reads ("th", the
// same key as the BTC contract's); it is permissionless and not pause-gated
// (a theft during a pause must still halt). Clearing it is the owner's
// deliberate call (clearTheftHalt, immediate like unpause).
//
// A proof at an older header shows a lower nonce, so it can only fail to
// report, never report falsely; the counters only grow.

// authorizedNonceCount is how many L1 transactions the contract has authorized
// from generation v's address.
func authorizedNonceCount(v *Vault) uint64 {
	switch {
	case v.Status == VaultStatusActive:
		if _, held := WithdrawNonceHolder(); held {
			return 0 // a superseded generation still holds the withdrawal nonces
		}
		return GetPendingNonce()
	case isSupersededStatus(v.Status) || v.Status == VaultStatusPurged:
		n := SweepNonce(v.Generation)
		if c, ok := WithdrawCeiling(v.Generation); ok && c > n {
			n = c
		}
		return n
	default: // pending: it has authorized nothing
		return 0
	}
}

// ReportUnauthorizedSpendParams: the generation and an account proof of its
// address at a stored header.
type ReportUnauthorizedSpendParams struct {
	Gen   uint32        `json:"gen"`
	Proof *AccountProof `json:"proof"`
}

// HandleReportUnauthorizedSpend sets the theft halt when the proven nonce of
// the generation's address is above what the contract authorized.
func HandleReportUnauthorizedSpend(p *ReportUnauthorizedSpendParams) (string, error) {
	if p == nil || p.Proof == nil {
		return "", ce.NewContractError(ce.ErrInput, "reportUnauthorizedSpend: gen and proof required")
	}
	FoldLegacyKeyIfNeeded(false)
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return "", err
	}
	var v *Vault
	for i := range vaults {
		if vaults[i].Generation == p.Gen {
			v = &vaults[i]
			break
		}
	}
	if v == nil {
		return "", ce.NewContractError(ce.ErrInput, "reportUnauthorizedSpend: no generation "+strconv.FormatUint(uint64(p.Gen), 10))
	}
	addr, ok := GenAddress(v)
	if !ok {
		return "", ce.NewContractError(ce.ErrInput, "reportUnauthorizedSpend: the generation has no key address")
	}
	nonce, _, err := ProvenAccount(p.Proof, addr)
	if err != nil {
		return "", err
	}
	auth := authorizedNonceCount(v)
	if nonce <= auth {
		return "", ce.NewContractError(ce.ErrIntent, "no unauthorized spend: proven nonce "+
			strconv.FormatUint(nonce, 10)+" <= authorized "+strconv.FormatUint(auth, 10))
	}
	sdk.StateSetObject(constants.TheftHaltKey, "1")
	sdk.Log("security|evm-theft-halt|gen=" + strconv.FormatUint(uint64(p.Gen), 10) + "|addr=" + crypto.AddressToHex(addr) +
		"|nonce=" + strconv.FormatUint(nonce, 10) + "|authorized=" + strconv.FormatUint(auth, 10) +
		"|block=" + strconv.FormatUint(p.Proof.BlockHeight, 10))
	return "theft halt set: generation " + strconv.FormatUint(uint64(p.Gen), 10) + " sent " +
		strconv.FormatUint(nonce-auth, 10) + " transaction(s) the bridge never authorized", nil
}

// TheftHalted reports whether the theft halt is set.
func TheftHalted() bool {
	s := sdk.StateGetObject(constants.TheftHaltKey)
	return s != nil && *s != ""
}

// ClearTheftHalt removes the flag (owner). Cleared by DELETION: the node reads
// any non-empty value as a halt (consensus_version.go refreshBtcTheftHalt rule).
func ClearTheftHalt() {
	sdk.StateDeleteObject(constants.TheftHaltKey)
}
