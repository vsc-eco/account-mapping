package mapping

import (
	"encoding/json"
	"evm-mapping-contract/contract/abi"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
	"math/big"
	"strconv"
)

func GetConfirmedNonce() uint64 {
	data := sdk.StateGetObject(constants.NonceConfirmedKey)
	if data == nil {
		return 0
	}
	v, _ := strconv.ParseUint(*data, 10, 64)
	return v
}

func SetConfirmedNonce(n uint64) {
	sdk.StateSetObject(constants.NonceConfirmedKey, strconv.FormatUint(n, 10))
}

func GetPendingNonce() uint64 {
	data := sdk.StateGetObject(constants.NoncePendingKey)
	if data == nil {
		return 0
	}
	v, _ := strconv.ParseUint(*data, 10, 64)
	return v
}

func SetPendingNonce(n uint64) {
	sdk.StateSetObject(constants.NoncePendingKey, strconv.FormatUint(n, 10))
}

func HasPendingWithdrawal() bool {
	return GetPendingNonce() > GetConfirmedNonce()
}

// PendingSpend — LOCKED 8-field struct (W1 D-F-3 + W4 Step 3, v19 §AQ + v20 §BE,
// coordinated with Cluster E). VaultAtQueue is the vault L1 address SNAPSHOT
// at unmapETH/unmapERC20/unmapFrom queue time, stored as a 0x-prefixed
// 20-byte hex string. HandleConfirmSpend ecrecovers against this snapshot
// (NOT the current vault) to close HIGH #29 (setVault orphans pending).
//
// Storage format is JSON (v18 §AE migration from pipe-delimited positional).
// Pre-upgrade pipe-delimited entries are NOT migrated — testnet operators
// clear all ps-* keys per W0 P0 / Cluster E clearTestnetState before
// update_contract; mainnet is a fresh deploy so no migration window.
//
// TokenAddress is DROPPED (renamed+retyped to VaultAtQueue per W4 Step 3
// "rename-and-retype, not an addition") — token information for ERC-20
// receipts is recovered from constants.TxSpendsPrefix entries written
// by future versions, or via the unsigned tx hex itself. ERC-20 handler
// path now carries TokenAddress in PendingSpend as well; see field below.
//
// big.Int/wei DENOMINATION (replaces the W4 Cluster A Step 3b gwei scaling):
//   - When Asset == "eth", Amount is in full WEI (1 ETH = 1e18 wei). It is a
//     *big.Int, so there is no int64 ceiling — whale withdrawals fit exactly
//     (HIGH #38 closed structurally) and NO sub-gwei dust is dropped: the L1
//     unsigned tx value equals Amount verbatim.
//   - When Asset != "eth" (any ERC-20 / native token), Amount is in the
//     token-native unit (USDC = 6 decimals). NO scaling applied.
//   - JSON round-trips via *big.Int's marshaler (a decimal number token);
//     GetPendingSpend defends against a nil Amount on legacy/garbage reads.
type PendingSpend struct {
	Nonce         uint64   `json:"nonce"`
	Amount        *big.Int `json:"amount"`
	From          string   `json:"from"`
	To            string   `json:"to"`
	Asset         string   `json:"asset"`
	UnsignedTxHex string   `json:"unsigned_tx_hex"`
	BlockHeight   uint64   `json:"block_height"`
	VaultAtQueue  string   `json:"vault_at_queue"`
	// TokenAddress is kept for ERC-20 confirmSpend validation (the receipt
	// proof needs to know which token contract the tx targeted). This is
	// NOT one of the 8 cross-cluster-coordinated fields — it is an
	// internal contract field and the JSON tag is omitempty so the field
	// is absent for ETH withdrawals.
	TokenAddress string `json:"token_address,omitempty"`
	// GasCost is the gas-reserve amount (full wei) deducted when this
	// withdrawal was submitted. Refunded by HandleConfirmSpend's failure
	// branch (pentest finding EVM-C4). *big.Int + omitempty so ETH paths
	// (which charge the fee to the user balance, not the reserve) leave it
	// nil and absent; JSON marshal/unmarshal carry it automatically.
	GasCost *big.Int `json:"gas_cost,omitempty"`
	// Rolled is set by rollWithdrawal (D3): UnsignedTxHex is then a 0-value
	// self-transfer at Nonce, and confirmSpend accepts either that or the
	// withdrawal itself, whichever mined.
	Rolled bool `json:"rolled,omitempty"`
}

func StorePendingSpend(ps PendingSpend) {
	key := constants.TxSpendsPrefix + strconv.FormatUint(ps.Nonce, 10)
	// v18 §AE: switch from pipe-delimited positional to JSON. Adding the
	// VaultAtQueue field would silently break the positional parser for
	// pre-upgrade entries (len(fields)==7 path), so the storage format
	// changes atomically with the new field. EVM-C4's GasCost rides along
	// in the JSON automatically (tagged field).
	jsonBytes, err := json.Marshal(ps)
	if err != nil {
		sdk.Revert("pendingSpend marshal failed", "storePendingSpend")
		return
	}
	sdk.StateSetObject(key, string(jsonBytes))
}

func GetPendingSpend(nonce uint64) *PendingSpend {
	key := constants.TxSpendsPrefix + strconv.FormatUint(nonce, 10)
	data := sdk.StateGetObject(key)
	if data == nil {
		return nil
	}
	ps := &PendingSpend{}
	if err := json.Unmarshal([]byte(*data), ps); err != nil {
		// Defensive: if a pre-upgrade pipe-delimited entry somehow
		// survived testnet state clearing, JSON unmarshal will fail.
		// Returning nil routes the caller to "no pending spend" rather
		// than silently producing a zero-VaultAtQueue PendingSpend.
		return nil
	}
	// Defensive: a legacy/garbage entry missing the amount field leaves
	// Amount nil; normalize to zero so downstream big.Int arithmetic
	// (refunds, Cmp, supply restore) never nil-panics.
	if ps.Amount == nil {
		ps.Amount = new(big.Int)
	}
	ps.Nonce = nonce
	return ps
}

func DeletePendingSpend(nonce uint64) {
	key := constants.TxSpendsPrefix + strconv.FormatUint(nonce, 10)
	sdk.StateDeleteObject(key)
}

// BuildETHWithdrawalTx constructs an EIP-1559 transaction for native ETH withdrawal.
func BuildETHWithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap uint64, to [20]byte, amount *big.Int) []byte {
	return buildEIP1559Tx(chainId, nonce, gasTipCap, gasFeeCap, constants.ETHTransferGas, to, amount, nil)
}

// BuildERC20WithdrawalTx constructs an EIP-1559 transaction calling ERC-20 transfer.
func BuildERC20WithdrawalTx(
	chainId, nonce, gasTipCap, gasFeeCap uint64,
	tokenAddr, recipient [20]byte,
	amount *big.Int,
) []byte {
	calldata := abi.EncodeTransfer(recipient, amount)
	return buildEIP1559Tx(
		chainId,
		nonce,
		gasTipCap,
		gasFeeCap,
		constants.ERC20TransferGas,
		tokenAddr,
		big.NewInt(0),
		calldata,
	)
}

func buildEIP1559Tx(chainId, nonce, gasTipCap, gasFeeCap, gas uint64, to [20]byte, value *big.Int, data []byte) []byte {
	unsignedRLP := rlp.EncodeList(
		rlp.EncodeUint64(chainId),
		rlp.EncodeUint64(nonce),
		rlp.EncodeUint64(gasTipCap),
		rlp.EncodeUint64(gasFeeCap),
		rlp.EncodeUint64(gas),
		rlp.EncodeAddress(to),
		rlp.EncodeBigInt(value),
		rlp.EncodeBytes(data),
		rlp.EncodeList(), // empty access list
	)
	// EIP-1559 sighash: keccak256(0x02 || unsignedRLP)
	return append([]byte{0x02}, unsignedRLP...)
}

// ComputeSighash computes the hash to sign for an EIP-1559 transaction.
func ComputeSighash(unsignedTxWithPrefix []byte) []byte {
	return crypto.Keccak256(unsignedTxWithPrefix)
}

// AttachSignature creates the final signed transaction from the unsigned tx and signature.
func AttachSignature(unsignedTxWithPrefix []byte, v byte, r, s []byte) ([]byte, error) {
	if len(unsignedTxWithPrefix) < 2 || unsignedTxWithPrefix[0] != 0x02 {
		return nil, ce.NewContractError(ce.ErrInput, "not an EIP-1559 tx")
	}

	// Decode the unsigned list
	items, err := rlp.DecodeList(unsignedTxWithPrefix[1:])
	if err != nil {
		return nil, err
	}
	if len(items) != 9 {
		return nil, ce.NewContractError(ce.ErrInput, "expected 9 unsigned fields")
	}

	// Re-encode with signature: 9 unsigned fields + v, r, s
	encodedItems := make([][]byte, 12)
	for i := 0; i < 9; i++ {
		if items[i].IsList {
			encodedItems[i] = rlp.EncodeList()
		} else {
			encodedItems[i] = rlp.EncodeBytes(items[i].AsBytes())
		}
	}
	encodedItems[9] = rlp.EncodeUint64(uint64(v))
	encodedItems[10] = rlp.EncodeBytes(r)
	encodedItems[11] = rlp.EncodeBytes(s)

	signedRLP := rlp.EncodeList(encodedItems...)
	return append([]byte{0x02}, signedRLP...), nil
}

// NonceAdvance — W4 Cluster E §11.1 / D-E-6 LOCKED. Compare-and-set helper
// shared between HandleClearNonce (CRIT #27) and HandleExpireWithdrawal
// (CRIT #26). Both paths can advance the confirmed nonce; without a CAS,
// a same-block race would advance the counter twice and skip a subsequent
// withdrawal nonce (queue jam).
//
// Semantics: nonce advances by `by` IFF GetConfirmedNonce() == ps.Nonce
// AND the PendingSpend at ps.Nonce still exists in state. If either
// precondition fails (the other path already won), this is a no-op and
// returns false. Callers SHOULD treat false as "another handler already
// advanced — nothing more to do here" — NOT as an error.
//
// ARCHITECTURAL ASSUMPTION (B-E-3 fix — REQUIRED COMMENT per W4 Step 5):
// this mutex relies on sequential L2 transaction execution within Magi
// blocks. The Magi state engine processes transactions one at a time
// within a block — two concurrent WASM contract calls CANNOT interleave
// mid-execution. If Magi ever introduces concurrent WASM dispatch, this
// CAS must be replaced with a state-level lock (e.g., a "nonce_lock"
// state key with optimistic concurrency).
// Source: modules/state-processing/transactions.go (sequential tx
// dispatch verified by W3-TSS implementation pass).
func NonceAdvance(ps *PendingSpend, by uint64) bool {
	if ps == nil {
		return false
	}
	currentNonce := GetConfirmedNonce()
	if currentNonce != ps.Nonce {
		return false
	}
	// Re-read PendingSpend by nonce; if a concurrent path already deleted
	// it, treat as "another path advanced first" and become a no-op.
	if GetPendingSpend(currentNonce) == nil {
		return false
	}
	SetConfirmedNonce(currentNonce + by)
	return true
}

func splitPipe(s string) []string {
	result := make([]string, 0, 6)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}
