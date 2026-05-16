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

func Ecrecover(hash []byte, v byte, r, s []byte) ([20]byte, error) {
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

	recovered, err := sdk.Ecrecover(hash, sig)
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

func AddressToDID(addr [20]byte, chainId uint64) string {
	return "did:pkh:eip155:1:" + AddressToHex(addr)
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
