package sdk

import (
	"encoding/hex"
	"errors"
	"math/big"
)

// secp256k1N is the secp256k1 group order; secp256k1HalfN is N/2, the
// low-S bound (EIP-2). The node only provides the plain `crypto.ecrecover`
// import, so the strict and canonical policies below are applied here,
// before that import is called.
var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1HalfN = new(big.Int).Rsh(secp256k1N, 1)
)

// sigS returns s from an r[32] + s[32] + v[1] signature, rejecting the
// signature if r or s is outside [1, N-1].
func sigS(sig []byte) (*big.Int, error) {
	if len(sig) != 65 {
		return nil, errors.New("sig must be 65 bytes (r+s+v)")
	}
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	if r.Sign() == 0 || r.Cmp(secp256k1N) >= 0 || s.Sign() == 0 || s.Cmp(secp256k1N) >= 0 {
		return nil, errors.New("signature r or s out of range")
	}
	return s, nil
}

// Keccak256 computes the Keccak-256 hash via the host runtime.
// Input and output are raw byte slices (not hex-encoded).
func Keccak256(data []byte) []byte {
	input := hex.EncodeToString(data)
	result := cryptoKeccak256(&input)
	if result == nil {
		return nil
	}
	out, _ := hex.DecodeString(*result)
	return out
}

// Ecrecover recovers the public key address from a hash and signature.
// hash must be 32 bytes, sig must be 65 bytes (r[32] + s[32] + v[1]).
// Returns the 20-byte Ethereum address.
//
// This is the node's plain `crypto.ecrecover`: it applies no low-S rule.
// Signature sites use EcrecoverStrict or EcrecoverCanonical instead.
func Ecrecover(hash []byte, sig []byte) ([]byte, error) {
	hashHex := hex.EncodeToString(hash)
	sigHex := hex.EncodeToString(sig)
	result := cryptoEcrecover(&hashHex, &sigHex)
	if result == nil {
		return nil, nil
	}
	return hex.DecodeString(*result)
}

// EcrecoverStrict is the REJECT-on-high-S ecrecover. Use this for
// SYSTEM signature sites where malleable sigs must NEVER be accepted
// (e.g. vault TSS-sig verification inside HandleConfirmSpend).
// CRIT #11 site 4.
func EcrecoverStrict(hash []byte, sig []byte) ([]byte, error) {
	s, err := sigS(sig)
	if err != nil {
		return nil, err
	}
	if s.Cmp(secp256k1HalfN) > 0 {
		return nil, errors.New("high-S signature rejected")
	}
	return Ecrecover(hash, sig)
}

// EcrecoverCanonical is the NORMALIZE-to-low-S ecrecover. Use this for
// USER signature sites where legacy wallets may emit high-S (e.g. ETH
// deposit verify in proof.go). A high-S sig is replaced by its low-S
// twin (S' = N - S, recovery id flipped), which recovers the same key.
// CRIT #11 site 4.
func EcrecoverCanonical(hash []byte, sig []byte) ([]byte, error) {
	s, err := sigS(sig)
	if err != nil {
		return nil, err
	}
	if s.Cmp(secp256k1HalfN) > 0 {
		low := make([]byte, 65)
		copy(low, sig)
		new(big.Int).Sub(secp256k1N, s).FillBytes(low[32:64])
		low[64] ^= 1
		sig = low
	}
	return Ecrecover(hash, sig)
}

// RlpDecode decodes RLP-encoded data via the host runtime.
// Returns the JSON string representation of decoded items.
func RlpDecode(data []byte) string {
	input := hex.EncodeToString(data)
	result := cryptoRlpDecode(&input)
	if result == nil {
		return ""
	}
	return *result
}
