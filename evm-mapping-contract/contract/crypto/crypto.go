package crypto

import (
	"encoding/hex"
	"errors"
	ce "evm-mapping-contract/contract/contracterrors"
	"math/big"
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

var (
	secp256k1P, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	secp256k1SqrtE = new(big.Int).Rsh(new(big.Int).Add(secp256k1P, big.NewInt(1)), 2) // (p+1)/4, as p = 3 mod 4
)

// PubkeyAddress is the Ethereum address of a secp256k1 public key, given as 33
// compressed bytes (how the node's TSS stores ECDSA keys) or 65 uncompressed
// bytes (0x04 || X || Y): keccak256(X || Y)[12:]. A compressed key is
// decompressed on the curve and refused if its X is not on it.
func PubkeyAddress(pub []byte) ([20]byte, error) {
	var xy []byte
	switch {
	case len(pub) == 65 && pub[0] == 4:
		xy = pub[1:]
	case len(pub) == 33 && (pub[0] == 2 || pub[0] == 3):
		x := new(big.Int).SetBytes(pub[1:])
		if x.Cmp(secp256k1P) >= 0 {
			return [20]byte{}, errors.New("public key X out of range")
		}
		y2 := new(big.Int).Exp(x, big.NewInt(3), secp256k1P)
		y2.Add(y2, big.NewInt(7)).Mod(y2, secp256k1P)
		y := new(big.Int).Exp(y2, secp256k1SqrtE, secp256k1P)
		if new(big.Int).Exp(y, big.NewInt(2), secp256k1P).Cmp(y2) != 0 {
			return [20]byte{}, errors.New("public key is not on secp256k1")
		}
		if y.Bit(0) != uint(pub[0]&1) {
			y.Sub(secp256k1P, y)
		}
		xy = make([]byte, 64)
		x.FillBytes(xy[:32])
		y.FillBytes(xy[32:])
	default:
		return [20]byte{}, errors.New("unsupported public key encoding")
	}
	var addr [20]byte
	copy(addr[:], Keccak256(xy)[12:])
	return addr, nil
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
