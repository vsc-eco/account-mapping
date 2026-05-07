//go:build !gc.custom

package sdk

import (
	"encoding/hex"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

//go:wasmimport sdk console.log
func log(s *string) *string { return nil }

func Log(s string) {
	log(&s)
}

// In-memory test state. The production wasm runtime persists each
// contract's StateSetObject calls; the previous test stub silently
// dropped them, so any handler that round-trips state through
// StateSetObject + StateGetObject couldn't be exercised end-to-end
// in unit tests. Persist them here so the contract can be driven
// like a normal data structure.
var testStateStore = map[string]string{}

// ResetTestStateStore clears the in-memory state between tests
// that need a clean slate.
func ResetTestStateStore() {
	testStateStore = map[string]string{}
}

//go:wasmimport sdk db.set_object
func stateSetObject(key *string, value *string) *string {
	if key != nil && value != nil {
		testStateStore[*key] = *value
	}
	return nil
}

//go:wasmimport sdk db.get_object
func stateGetObject(key *string) *string {
	if key == nil {
		return nil
	}
	v, ok := testStateStore[*key]
	if !ok {
		return nil
	}
	return &v
}

//go:wasmimport sdk db.rm_object
func stateDeleteObject(key *string) *string {
	if key != nil {
		delete(testStateStore, *key)
	}
	return nil
}

//go:wasmimport sdk ephem_db.set_object
func ephemStateSetObject(key *string, value *string) *string { return nil }

//go:wasmimport sdk ephem_db.get_object
func ephemStateGetObject(contractId *string, key *string) *string { return nil }

//go:wasmimport sdk ephem_db.rm_object
func ephemStateDeleteObject(key *string) *string { return nil }

//go:wasmimport sdk system.get_env
func getEnv(arg *string) *string { return nil }

//go:wasmimport sdk system.get_env_key
func getEnvKey(arg *string) *string { return nil }

//go:wasmimport sdk system.verify_address
func verifyAddress(arg *string) *string { return nil }

//go:wasmimport sdk hive.get_balance
func getBalance(arg1 *string, arg2 *string) *string { return nil }

//go:wasmimport sdk hive.draw
func hiveDraw(arg1 *string, arg2 *string) *string { return nil }

//go:wasmimport sdk hive.draw_from
func hiveDrawFrom(arg1 *string, arg2 *string, arg3 *string) *string { return nil }

//go:wasmimport sdk hive.transfer
func hiveTransfer(arg1 *string, arg2 *string, arg3 *string) *string { return nil }

//go:wasmimport sdk hive.withdraw
func hiveWithdraw(arg1 *string, arg2 *string, arg3 *string) *string { return nil }

//go:wasmimport sdk contracts.read
func contractRead(contractId *string, key *string) *string { return nil }

//go:wasmimport sdk contracts.call
func contractCall(contractId *string, method *string, payload *string, options *string) *string {
	return nil
}

//go:wasmimport sdk tss_v2.create_key
func tssCreateKey(keyId *string, algo *string, epochs *string) *string { return nil }

//go:wasmimport sdk tss_v2.renew_key
func tssRenewKey(keyId *string, epochs *string) *string { return nil }

//go:wasmimport sdk tss.sign_key
func tssSignKey(keyId *string, msgId *string) *string { return nil }

//go:wasmimport sdk tss.get_key
func tssGetKey(keyId *string) *string { return nil }

// var envMap = []string{
// 	"contract.id",
// 	"tx.origin",
// 	"tx.id",
// 	"tx.index",
// 	"tx.op_index",
// 	"block.id",
// 	"block.height",
// 	"block.timestamp",
// }

func cryptoKeccak256(hexData *string) *string {
	data, _ := hex.DecodeString(*hexData)
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	result := hex.EncodeToString(h.Sum(nil))
	return &result
}

func cryptoEcrecover(hashHex *string, sigHex *string) *string {
	hash, _ := hex.DecodeString(*hashHex)
	sig, _ := hex.DecodeString(*sigHex)
	if len(sig) != 65 {
		return nil
	}
	// Convert from r[32]+s[32]+v[1] to v[1]+r[32]+s[32] for RecoverCompact
	// go-ethereum format: v is 0 or 1. dcrd RecoverCompact: v is 27 or 28.
	compactSig := make([]byte, 65)
	compactSig[0] = sig[64] + 27 // convert 0/1 → 27/28 for RecoverCompact
	copy(compactSig[1:33], sig[0:32]) // r
	copy(compactSig[33:65], sig[32:64]) // s
	pubKey, _, err := ecdsa.RecoverCompact(compactSig, hash)
	if err != nil {
		return nil
	}
	uncompressed := pubKey.SerializeUncompressed()
	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:])
	addr := hex.EncodeToString(h.Sum(nil)[12:])
	return &addr
}

func cryptoRlpDecode(hexData *string) *string { return nil }

//go:wasmimport env abort
func abort(msg, file *string, line, column *int32) { return }

// In the production wasm runtime, revert halts contract execution
// just like abort. The previous unit-test stub silently returned,
// which made every ce.CustomAbort with a Symbol invisible to tests
// and effectively let unit-test code continue past abort points.
// Panic with the symbol-tagged message to mirror production halt
// semantics so tests can observe (and recover from) the abort.
//
//go:wasmimport env revert
func revert(msg, symbol *string) {
	m := ""
	if msg != nil {
		m = *msg
	}
	if symbol != nil && *symbol != "" {
		m = *symbol + ": " + m
	}
	panic(m)
}
