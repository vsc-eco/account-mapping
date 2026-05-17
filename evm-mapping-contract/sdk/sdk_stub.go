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

// review2 (test harness): this file is the non-wasm (!gc.custom) build.
// The real contract uses runtime_imports.go (//go:build gc.custom). The
// previous no-op stubs made every stateful handler untestable (state was
// a black hole, getEnv() nil-deref'd). Back them with an in-memory store
// + settable env so review2 A/B tests can exercise real handler logic.
// See test helpers (ResetTestState/SetTestCaller/...) at end of file.

var testState = map[string]string{}
var testEphem = map[string]string{}
var testEnvJSON = `{"contract.id":"contract:test","msg.caller":"system","msg.sender":"system","msg.required_auths":["system"]}`
var testEnvKeys = map[string]string{}

func stateSetObject(key *string, value *string) *string { testState[*key] = *value; return nil }

func stateGetObject(key *string) *string {
	if v, ok := testState[*key]; ok {
		return &v
	}
	return nil
}

func stateDeleteObject(key *string) *string { delete(testState, *key); return nil }

func ephemStateSetObject(key *string, value *string) *string { testEphem[*key] = *value; return nil }

func ephemStateGetObject(contractId *string, key *string) *string {
	if v, ok := testEphem[*key]; ok {
		return &v
	}
	return nil
}

func ephemStateDeleteObject(key *string) *string { delete(testEphem, *key); return nil }

func getEnv(arg *string) *string { return &testEnvJSON }

func getEnvKey(arg *string) *string {
	if v, ok := testEnvKeys[*arg]; ok {
		return &v
	}
	return nil
}

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
	compactSig[0] = sig[64] + 27        // convert 0/1 → 27/28 for RecoverCompact
	copy(compactSig[1:33], sig[0:32])   // r
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

//go:wasmimport env revert
func revert(msg, symbol *string) { return }

// ---- review2 test harness helpers (non-wasm / !gc.custom build only) ----

// ResetTestState clears in-memory contract state and restores the
// default env. Call at the start of every stateful test.
func ResetTestState() {
	testState = map[string]string{}
	testEphem = map[string]string{}
	testEnvKeys = map[string]string{}
	testEnvJSON = `{"contract.id":"contract:test","msg.caller":"system","msg.sender":"system","msg.required_auths":["system"]}`
}

// SetTestEnv sets the caller and sender for subsequent handler calls.
func SetTestEnv(caller, sender string) {
	testEnvJSON = `{"contract.id":"contract:test","msg.caller":"` + caller +
		`","msg.sender":"` + sender + `","msg.required_auths":["` + sender + `"]}`
}

// SetTestCaller is shorthand for SetTestEnv(addr, addr).
func SetTestCaller(addr string) { SetTestEnv(addr, addr) }

// SetTestEnvKey sets a getEnvKey value (e.g. "contract.owner").
func SetTestEnvKey(key, value string) { testEnvKeys[key] = value }

// TestStateGet returns a raw state value (ok=false if absent).
func TestStateGet(key string) (string, bool) { v, ok := testState[key]; return v, ok }

// TestStateLen returns the number of stored state keys.
func TestStateLen() int { return len(testState) }
