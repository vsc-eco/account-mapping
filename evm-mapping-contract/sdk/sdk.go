package sdk

import (
	"encoding/hex"
	"strconv"

	tinyjson "github.com/CosmWasm/tinyjson"
)

// Aborts the contract execution
func Abort(msg string) {
	ln := int32(0)
	abort(&msg, nil, &ln, &ln)
	panic(msg)
}

// Reverts the transaction and abort execution in the same way as Abort().
func Revert(msg string, symbol string) {
	revert(&msg, &symbol)
}

// Set a value by key in the contract state
func StateSetObject(key string, value string) {
	stateSetObject(&key, &value)
}

// Get a value by key from the contract state
func StateGetObject(key string) *string {
	// DEVNET-FOUND host-vs-stub fix: the real WASM host returns a non-nil EMPTY
	// string for an ABSENT key (execution-context GetState -> Ok("") when the
	// store has no value), whereas the unit-test stub returns nil. Contracts are
	// written + unit-tested against nil-for-absent, so a bare `!= nil` presence
	// check (e.g. IsObserved) reads TRUE for every unset key, and an
	// `if data == nil { return DEFAULT }` getter (e.g. chainId's default 1) never
	// returns its non-zero default. Normalize "" -> nil so every nil-check
	// behaves as written. The contract never stores an intentional empty value
	// (verified: no StateSetObject(k,"")), so this is lossless.
	v := stateGetObject(&key)
	if v == nil || *v == "" {
		return nil
	}
	return v
}

// Delete or unset a value by key in the contract state
func StateDeleteObject(key string) {
	stateDeleteObject(&key)
}

// Set a value by key in the ephemeral contract state
func EphemStateSetObject(key string, value string) {
	ephemStateSetObject(&key, &value)
}

// Get a value by key from the ephemeral contract state
func EphemStateGetObject(contractId string, key string) *string {
	// Same host-vs-stub "" -> nil normalization as StateGetObject (above).
	v := ephemStateGetObject(&contractId, &key)
	if v == nil || *v == "" {
		return nil
	}
	return v
}

// Delete or unset a value by key in the ephemeral contract state
func EphemStateDeleteObject(key string) {
	ephemStateDeleteObject(&key)
}

// Get current execution environment variables
func GetEnv() Env {
	envStr := *getEnv(nil)
	env := Env{}
	tinyjson.Unmarshal([]byte(envStr), &env)
	envMap := EnvMap{}
	tinyjson.Unmarshal([]byte(envStr), &envMap)

	requiredAuths := make([]Address, 0)
	if auths, ok := envMap["msg.required_auths"].([]interface{}); ok {
		for _, auth := range auths {
			if addr, ok := auth.(string); ok {
				requiredAuths = append(requiredAuths, Address(addr))
			}
		}
	}
	requiredPostingAuths := make([]Address, 0)
	if auths, ok := envMap["msg.required_posting_auths"].([]interface{}); ok {
		for _, auth := range auths {
			if addr, ok := auth.(string); ok {
				requiredPostingAuths = append(requiredPostingAuths, Address(addr))
			}
		}
	}

	senderAddr := ""
	if s, ok := envMap["msg.sender"].(string); ok {
		senderAddr = s
	}
	if senderAddr == "" {
		Abort("msg.sender is missing from environment")
	}

	env.Sender = Sender{
		Address:              Address(senderAddr),
		RequiredAuths:        requiredAuths,
		RequiredPostingAuths: requiredPostingAuths,
	}
	return env
}

// Get current execution environment variables as json string
func GetEnvStr() string {
	return *getEnv(nil)
}

// Get current execution environment variable by a key
func GetEnvKey(key string) *string {
	return getEnvKey(&key)
}

// VerifyAddress asks the runtime to validate an address and returns its type.
// Returns one of: "user:hive", "user:evm", "key", "contract", "system", "unknown".
func VerifyAddress(addr string) string {
	return *verifyAddress(&addr)
}

// Get balance of an account
func GetBalance(address Address, asset Asset) int64 {
	addr := address.String()
	as := asset.String()
	balStr := *getBalance(&addr, &as)
	bal, err := strconv.ParseInt(balStr, 10, 64)
	if err != nil {
		panic(err)
	}
	return bal
}

// Transfer assets from caller account to the contract up to the limit specified in `intents`. The transaction must be signed using active authority for Hive accounts.
func HiveDraw(amount int64, asset Asset) {
	amt := strconv.FormatInt(amount, 10)
	as := asset.String()
	hiveDraw(&amt, &as)
}

func HiveDrawFrom(from Address, amount int64, asset Asset) {
	frm := from.String()
	amt := strconv.FormatInt(amount, 10)
	as := asset.String()
	hiveDrawFrom(&frm, &amt, &as)
}

// Transfer assets from the contract to another account.
func HiveTransfer(to Address, amount int64, asset Asset) {
	toaddr := to.String()
	amt := strconv.FormatInt(amount, 10)
	as := asset.String()
	hiveTransfer(&toaddr, &amt, &as)
}

// Unmap assets from the contract to a specified Hive account.
func HiveWithdraw(to Address, amount int64, asset Asset) {
	toaddr := to.String()
	amt := strconv.FormatInt(amount, 10)
	as := asset.String()
	hiveWithdraw(&toaddr, &amt, &as)
}

// Get a value by key from the contract state of another contract
func ContractStateGet(contractId string, key string) *string {
	return contractRead(&contractId, &key)
}

// Call another contract
func ContractCall(contractId string, method string, payload string, options *ContractCallOptions) *string {
	optStr := ""
	if options != nil {
		optByte, err := tinyjson.Marshal(options)
		if err != nil {
			Revert("could not serialize options", "sdk_error")
		}
		optStr = string(optByte)
	}
	return contractCall(&contractId, &method, &payload, &optStr)
}

func TssCreateKey(keyId string, algo string, epochs uint64) string {
	if algo != "ecdsa" && algo != "eddsa" {
		Abort("algo must be ecdsa or eddsa")
	}
	epochsStr := strconv.FormatUint(epochs, 10)
	return *tssCreateKey(&keyId, &algo, &epochsStr)
}

func TssRenewKey(keyId string, additionalEpochs uint64) string {
	epochsStr := strconv.FormatUint(additionalEpochs, 10)
	return *tssRenewKey(&keyId, &epochsStr)
}

func TssGetKey(keyId string) string {
	return *tssGetKey(&keyId)
}

func TssSignKey(keyId string, bytes []byte) {
	byteStr := hex.EncodeToString(bytes)

	tssSignKey(&keyId, &byteStr)
}
