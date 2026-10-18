package crypto

import (
	"encoding/hex"
	ce "evm-mapping-contract/contract/contracterrors"
	"strconv"
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

// AddressToDID — W4 Cluster B CRIT #6 Site 3 + CRIT #29 forward-proof:
// the chainId is now read from contract state and threaded into the
// did:pkh literal. Previously hardcoded "did:pkh:eip155:1:" which produced
// mainnet-prefixed DIDs even on testnet. Site 11 (evm-mapping.wasm data
// section) auto-changes when this Go literal changes — recompile the WASM
// and the rodata segment will drop the "eip155:1:" string; CID changes;
// operator runbook P5 covers redeploy logistics.
//
// Migration policy (CRIT-FIX-MAP §11.3): NEW DIDs use correct chainId
// after this change; OLD testnet DIDs still have `:1:` literal. Testnet
// redeploy wipes DID registry; mainnet is fresh deploy so all DIDs are
// chainId-correct from genesis.
func AddressToDID(addr [20]byte, chainId uint64) string {
	return "did:pkh:eip155:" + strconv.FormatUint(chainId, 10) + ":" + AddressToHex(addr)
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
