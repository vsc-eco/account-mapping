package crypto

import (
	"encoding/hex"
	ce "evm-mapping-contract/contract/contracterrors"
	"strings"

	"evm-mapping-contract/sdk"
)

func Keccak256(data []byte) []byte {
	return sdk.Keccak256(data)
}

func Keccak256Hash(data []byte) [32]byte {
	var result [32]byte
	copy(result[:], Keccak256(data))
	return result
}

// Ecrecover is the legacy wrapper kept for source-compat with existing
// call sites. It applies no low-S rule (the node's plain
// `crypto.ecrecover`). New contract code should use EcrecoverStrict
// (SYSTEM) or EcrecoverCanonical (USER) for explicit per-site policy.
func Ecrecover(hash []byte, v byte, r, s []byte) ([20]byte, error) {
	return ecrecoverDispatch(hash, v, r, s, sdk.Ecrecover)
}

// EcrecoverStrict — CRIT #11 site 4 REJECT-path wrapper. Returns an
// error (via the host) if s > N/2. Use at SYSTEM signature sites where
// malleable sigs must never be accepted (e.g. vault TSS-sig verify).
func EcrecoverStrict(hash []byte, v byte, r, s []byte) ([20]byte, error) {
	return ecrecoverDispatch(hash, v, r, s, sdk.EcrecoverStrict)
}

// EcrecoverCanonical — CRIT #11 site 4 NORMALIZE-path wrapper. Accepts
// high-S sigs by canonicalizing host-side. Use at USER signature sites
// where legacy wallets may legitimately emit high-S (e.g. ETH deposit
// verify in proof.go) AND callers downstream dedup by signature bytes.
func EcrecoverCanonical(hash []byte, v byte, r, s []byte) ([20]byte, error) {
	return ecrecoverDispatch(hash, v, r, s, sdk.EcrecoverCanonical)
}

func ecrecoverDispatch(
	hash []byte,
	v byte,
	r, s []byte,
	hostFn func([]byte, []byte) ([]byte, error),
) ([20]byte, error) {
	var addr [20]byte
	if len(hash) != 32 {
		return addr, ce.NewContractError(ce.ErrTransaction, "hash must be 32 bytes")
	}
	if len(r) != 32 || len(s) != 32 {
		return addr, ce.NewContractError(ce.ErrTransaction, "r and s must be 32 bytes")
	}

	sig := make([]byte, 65)
	copy(sig[0:32], r)
	copy(sig[32:64], s)
	if v >= 27 {
		sig[64] = v - 27
	} else {
		sig[64] = v
	}

	recovered, err := hostFn(hash, sig)
	if err != nil {
		return addr, ce.WrapContractError(ce.ErrTransaction, err, "ecrecover")
	}
	if len(recovered) != 20 {
		return addr, ce.NewContractError(ce.ErrTransaction, "ecrecover returned invalid address")
	}
	copy(addr[:], recovered)
	return addr, nil
}

func AddressToHex(addr [20]byte) string {
	return "0x" + hex.EncodeToString(addr[:])
}

// L2IdentityPrefix is the did:pkh namespace the Magi node authenticates
// (go-vsc-node lib/dids EthDIDPrefix): an Ethereum key's L2 identity is
// did:pkh:eip155:1:<address> whichever L1 chain this bridge reads.
const L2IdentityPrefix = "did:pkh:eip155:1:"

// AddressToDID is the L2 identity of an L1 address: did:pkh:eip155:1: and the
// EIP-55 address, the identity the node authenticates, the gateway credits
// (EvmAddressChecksumHeight) and charges RC to.
//
// C6 / E21: this used to build did:pkh:eip155:<chainId>:<lowercase>. On any
// chain but 1 that is a DID the node cannot parse, so nobody could sign as the
// credited identity; on chain 1 it split one user in two (ETH on the lowercase
// DID, HBD and RC on the EIP-55 one), and the user could withdraw under neither.
func AddressToDID(addr [20]byte) string {
	return L2IdentityPrefix + ChecksumHex(addr)
}

// ChecksumHex is the EIP-55 mixed-case hex of addr, with the 0x prefix.
func ChecksumHex(addr [20]byte) string {
	lower := []byte(hex.EncodeToString(addr[:]))
	h := Keccak256(lower)
	for i, c := range lower {
		if c < 'a' || c > 'f' {
			continue
		}
		nib := h[i/2] >> 4
		if i%2 == 1 {
			nib = h[i/2] & 0x0f
		}
		if nib >= 8 {
			lower[i] = c - ('a' - 'A')
		}
	}
	return "0x" + string(lower)
}

// CanonicalIdentity rewrites a did:pkh:eip155:1 identity in any letter case
// (the node verifies its signature case-insensitively, so every casing is the
// same key holder) to AddressToDID's form; any other identity is returned as
// is. Every state key the contract builds from an identity goes through it, so
// one Ethereum address has one balance, allowance and relayer entry.
func CanonicalIdentity(id string) string {
	if len(id) <= len(L2IdentityPrefix) || !strings.EqualFold(id[:len(L2IdentityPrefix)], L2IdentityPrefix) {
		return id
	}
	hexAddr := id[len(L2IdentityPrefix):]
	if strings.HasPrefix(hexAddr, "0X") { // the node accepts either prefix case
		hexAddr = "0x" + hexAddr[2:]
	}
	addr, err := HexToAddress(hexAddr)
	if err != nil {
		return id
	}
	return AddressToDID(addr)
}

// SameIdentity reports whether a and b are the same identity once canonical.
func SameIdentity(a, b string) bool {
	return CanonicalIdentity(a) == CanonicalIdentity(b)
}

func HexToAddress(s string) ([20]byte, error) {
	var addr [20]byte
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 40 {
		return addr, ce.NewContractError(ce.ErrInput, "invalid address length")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return addr, ce.WrapContractError(ce.ErrInvalidHex, err, "address decode")
	}
	copy(addr[:], b)
	return addr, nil
}
