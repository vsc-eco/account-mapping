package mapping

import (
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

type PendingSpend struct {
	Nonce        uint64
	Amount       int64
	From         string
	To           string
	Asset        string
	TokenAddress string
	UnsignedTxHex  string
	BlockHeight  uint64
}

func StorePendingSpend(ps PendingSpend) {
	key := constants.TxSpendsPrefix + strconv.FormatUint(ps.Nonce, 10)
	data := ps.From + "|" + ps.To + "|" + ps.Asset + "|" +
		strconv.FormatInt(ps.Amount, 10) + "|" +
		ps.UnsignedTxHex + "|" +
		strconv.FormatUint(ps.BlockHeight, 10) + "|" +
		ps.TokenAddress
	sdk.StateSetObject(key, data)
}

func GetPendingSpend(nonce uint64) *PendingSpend {
	key := constants.TxSpendsPrefix + strconv.FormatUint(nonce, 10)
	data := sdk.StateGetObject(key)
	if data == nil {
		return nil
	}
	ps := &PendingSpend{Nonce: nonce}
	fields := splitPipe(*data)
	if len(fields) < 6 {
		return nil
	}
	ps.From = fields[0]
	ps.To = fields[1]
	ps.Asset = fields[2]
	ps.Amount, _ = strconv.ParseInt(fields[3], 10, 64)
	ps.UnsignedTxHex = fields[4]
	ps.BlockHeight, _ = strconv.ParseUint(fields[5], 10, 64)
	if len(fields) >= 7 {
		ps.TokenAddress = fields[6]
	}
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
func BuildERC20WithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap uint64, tokenAddr, recipient [20]byte, amount *big.Int) []byte {
	calldata := abi.EncodeTransfer(recipient, amount)
	return buildEIP1559Tx(chainId, nonce, gasTipCap, gasFeeCap, constants.ERC20TransferGas, tokenAddr, big.NewInt(0), calldata)
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

