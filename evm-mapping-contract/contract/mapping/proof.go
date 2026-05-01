package mapping

import (
	"encoding/hex"
	"evm-mapping-contract/contract/blocklist"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
)

var (
	ErrBlockNotFound   = ce.NewContractError(ce.ErrStateAccess, "block header not found")
	ErrProofFailed     = ce.NewContractError(ce.ErrTransaction, "proof verification failed")
	ErrNotVaultDeposit = ce.NewContractError(ce.ErrIntent, "transaction is not a deposit to vault")
	ErrAlreadyObserved = ce.NewContractError(ce.ErrIntent, "deposit already processed")
	ErrInvalidToken    = ce.NewContractError(ce.ErrIntent, "token not registered")
)

// keccak256("Transfer(address,address,uint256)") = ddf252ad...
var transferEventSigBytes, _ = hex.DecodeString("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
var TransferEventSig = func() [32]byte { var h [32]byte; copy(h[:], transferEventSigBytes); return h }()

// VerifyETHDeposit verifies a native ETH deposit via transaction inclusion proof.
// Returns the sender address, deposit amount (wei as big-endian bytes), and the tx hash.
func VerifyETHDeposit(req *VerificationRequest, vaultAddress [20]byte) ([20]byte, []byte, [32]byte, error) {
	var sender [20]byte
	var txHash [32]byte

	header := blocklist.GetHeader(req.BlockHeight)
	if header == nil {
		return sender, nil, txHash, ErrBlockNotFound
	}

	rawBytes, err := hex.DecodeString(req.RawHex)
	if err != nil {
		return sender, nil, txHash, ce.WrapContractError(ce.ErrInvalidHex, err, "raw_hex")
	}

	proofBytes, err := hex.DecodeString(req.MerkleProofHex)
	if err != nil {
		return sender, nil, txHash, ce.WrapContractError(ce.ErrInvalidHex, err, "merkle_proof_hex")
	}

	proof := splitProofNodes(proofBytes)
	key := mpt.RLPEncodeKey(req.TxIndex)

	value, err := mpt.VerifyProof(header.TransactionsRoot, key, proof)
	if err != nil {
		return sender, nil, txHash, ErrProofFailed
	}

	// Verify the proven value matches the raw TX
	if !bytesEqual(value, rawBytes) {
		return sender, nil, txHash, ErrProofFailed
	}

	// Compute TX hash for observed tracking
	txHash = crypto.Keccak256Hash(rawBytes)

	// Check not already observed
	if IsObserved(req.BlockHeight, txHash, uint16(req.TxIndex)) {
		return sender, nil, txHash, ErrAlreadyObserved
	}

	// Parse the transaction to extract to, value, and signature
	parsedTx, err := parseTransaction(rawBytes)
	if err != nil {
		return sender, nil, txHash, err
	}

	// Verify destination is vault
	if parsedTx.To != vaultAddress {
		return sender, nil, txHash, ErrNotVaultDeposit
	}

	// Recover sender via ecrecover
	sighash := computeTxSighash(rawBytes, parsedTx)
	recoveryV := byte(27 + parsedTx.V)
	rPadded := padTo32(parsedTx.R)
	sPadded := padTo32(parsedTx.S)

	sender, err = crypto.Ecrecover(sighash, recoveryV, rPadded, sPadded)
	if err != nil {
		return sender, nil, txHash, ce.Prepend(err, "ecrecover failed")
	}
	if sender == ([20]byte{}) {
		return sender, nil, txHash, ce.NewContractError(ce.ErrTransaction, "ecrecover returned zero address")
	}

	// Mark as observed
	MarkObserved(req.BlockHeight, txHash, uint16(req.TxIndex))

	return sender, parsedTx.Value, txHash, nil
}

// VerifyERC20Deposit verifies an ERC-20 deposit via receipt inclusion proof.
// Returns the sender address, token amount (big-endian bytes), and the tx hash.
func VerifyERC20Deposit(
	req *VerificationRequest,
	vaultAddress [20]byte,
	tokenAddr [20]byte,
) ([20]byte, []byte, [32]byte, error) {
	var sender [20]byte
	var txHash [32]byte

	header := blocklist.GetHeader(req.BlockHeight)
	if header == nil {
		return sender, nil, txHash, ErrBlockNotFound
	}

	receiptBytes, err := hex.DecodeString(req.RawHex)
	if err != nil {
		return sender, nil, txHash, ce.WrapContractError(ce.ErrInvalidHex, err, "raw_hex")
	}

	proofBytes, err := hex.DecodeString(req.MerkleProofHex)
	if err != nil {
		return sender, nil, txHash, ce.WrapContractError(ce.ErrInvalidHex, err, "merkle_proof_hex")
	}

	proof := splitProofNodes(proofBytes)
	key := mpt.RLPEncodeKey(req.TxIndex)

	value, err := mpt.VerifyProof(header.ReceiptsRoot, key, proof)
	if err != nil {
		return sender, nil, txHash, ErrProofFailed
	}

	if !bytesEqual(value, receiptBytes) {
		return sender, nil, txHash, ErrProofFailed
	}

	txHash = crypto.Keccak256Hash(receiptBytes)

	if IsObserved(req.BlockHeight, txHash, uint16(req.LogIndex)) {
		return sender, nil, txHash, ErrAlreadyObserved
	}

	// Parse receipt and find the Transfer event at LogIndex
	logs, err := parseReceiptLogs(receiptBytes)
	if err != nil {
		return sender, nil, txHash, err
	}

	if req.LogIndex > 10000 || int(req.LogIndex) >= len(logs) {
		return sender, nil, txHash, ce.NewContractError(ce.ErrInput, "log_index out of range")
	}

	log := logs[req.LogIndex]

	// Verify: log.Address == tokenAddress
	if log.Address != tokenAddr {
		return sender, nil, txHash, ErrInvalidToken
	}

	// Verify: topics[0] == Transfer event signature
	if len(log.Topics) < 3 {
		return sender, nil, txHash, ce.NewContractError(ce.ErrInput, "insufficient topics for Transfer event")
	}
	if log.Topics[0] != TransferEventSig {
		return sender, nil, txHash, ce.NewContractError(ce.ErrIntent, "not a Transfer event")
	}

	// topics[2] == vault address (padded to 32 bytes)
	var vaultPadded [32]byte
	copy(vaultPadded[12:], vaultAddress[:])
	if log.Topics[2] != vaultPadded {
		return sender, nil, txHash, ErrNotVaultDeposit
	}

	// Sender from topics[1] (padded address)
	copy(sender[:], log.Topics[1][12:])
	if sender == ([20]byte{}) {
		return sender, nil, txHash, ce.NewContractError(ce.ErrIntent, "zero-address sender (mint event, not a deposit)")
	}

	// Amount from log.Data (uint256, big-endian)
	amount := log.Data

	MarkObserved(req.BlockHeight, txHash, uint16(req.LogIndex))

	return sender, amount, txHash, nil
}

// parseTransaction decodes an RLP-encoded Ethereum transaction.
// Handles both legacy and EIP-1559 (type 2) transactions.
func parseTransaction(raw []byte) (*ParsedTx, error) {
	if len(raw) == 0 {
		return nil, ce.NewContractError(ce.ErrInput, "empty transaction")
	}

	// EIP-2718 typed transaction: first byte is the type
	if raw[0] <= 0x7f {
		txType := raw[0]
		if txType == 2 {
			return parseEIP1559Tx(raw[1:])
		}
		return nil, ce.NewContractError(ce.ErrInput, "unsupported tx type")
	}

	// Legacy transaction
	return parseLegacyTx(raw)
}

func parseEIP1559Tx(data []byte) (*ParsedTx, error) {
	items, err := rlp.DecodeList(data)
	if err != nil {
		return nil, err
	}
	// EIP-1559: [chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data, accessList, v, r, s]
	if len(items) < 12 {
		return nil, ce.NewContractError(ce.ErrInput, "invalid EIP-1559 tx: too few fields")
	}

	tx := &ParsedTx{
		ChainId: items[0].AsUint64(),
		Nonce:   items[1].AsUint64(),
		Value:   items[6].AsBytes(),
		Data:    items[7].AsBytes(),
		V:       byte(items[9].AsUint64()),
		R:       items[10].AsBytes(),
		S:       items[11].AsBytes(),
	}
	toBytes := items[5].AsBytes()
	if len(toBytes) == 20 {
		copy(tx.To[:], toBytes)
	}
	return tx, nil
}

func parseLegacyTx(data []byte) (*ParsedTx, error) {
	items, err := rlp.DecodeList(data)
	if err != nil {
		return nil, err
	}
	// Legacy: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
	if len(items) < 9 {
		return nil, ce.NewContractError(ce.ErrInput, "invalid legacy tx: too few fields")
	}

	v := items[6].AsUint64()
	parsed := &ParsedTx{
		Nonce: items[0].AsUint64(),
		Value: items[4].AsBytes(),
		Data:  items[5].AsBytes(),
		R:     items[7].AsBytes(),
		S:     items[8].AsBytes(),
	}

	// EIP-155: v = chainId * 2 + 35 + recovery_id
	if v >= 35 {
		parsed.ChainId = (v - 35) / 2
		parsed.V = byte((v - 35) % 2)
	} else {
		parsed.V = byte(v - 27)
	}

	toBytes := items[3].AsBytes()
	if len(toBytes) == 20 {
		copy(parsed.To[:], toBytes)
	}
	return parsed, nil
}

func reencodeItem(item rlp.Item) []byte {
	if !item.IsList {
		return rlp.EncodeBytes(item.AsBytes())
	}
	children := make([][]byte, len(item.Children))
	for i, child := range item.Children {
		children[i] = reencodeItem(child)
	}
	return rlp.EncodeList(children...)
}

func computeTxSighash(raw []byte, tx *ParsedTx) []byte {
	// For EIP-1559: sighash = keccak256(0x02 || RLP([chainId, nonce, ...fields without v,r,s]))
	// For legacy EIP-155: sighash = keccak256(RLP([nonce, gasPrice, gas, to, value, data, chainId, 0, 0]))
	// We compute from the raw bytes by re-decoding without the signature fields
	// For simplicity in v1, we just hash the full raw (the ecrecover will validate)
	// TODO: implement proper sighash computation for full correctness
	if len(raw) > 0 && raw[0] == 2 {
		// EIP-1559: strip type byte, decode list, re-encode without last 3 items
		items, err := rlp.DecodeList(raw[1:])
		if err != nil || len(items) < 12 {
			return crypto.Keccak256(raw)
		}
		unsigned := make([][]byte, 9)
		for i := 0; i < 9; i++ {
			if items[i].IsList {
				unsigned[i] = reencodeItem(items[i])
			} else {
				unsigned[i] = rlp.EncodeBytes(items[i].AsBytes())
			}
		}
		unsignedRLP := rlp.EncodeList(unsigned...)
		return crypto.Keccak256(append([]byte{0x02}, unsignedRLP...))
	}
	// Legacy EIP-155
	items, err := rlp.DecodeList(raw)
	if err != nil || len(items) < 9 {
		return crypto.Keccak256(raw)
	}
	chainIdBytes := rlp.EncodeUint64(tx.ChainId)
	empty := rlp.EncodeBytes(nil)
	unsigned := rlp.EncodeList(
		rlp.EncodeBytes(items[0].AsBytes()), // nonce
		rlp.EncodeBytes(items[1].AsBytes()), // gasPrice
		rlp.EncodeBytes(items[2].AsBytes()), // gas
		rlp.EncodeBytes(items[3].AsBytes()), // to
		rlp.EncodeBytes(items[4].AsBytes()), // value
		rlp.EncodeBytes(items[5].AsBytes()), // data
		chainIdBytes,                        // chainId
		empty,                               // 0
		empty,                               // 0
	)
	return crypto.Keccak256(unsigned)
}

func parseReceiptLogs(receiptRLP []byte) ([]ParsedLog, error) {
	data := receiptRLP
	// Strip EIP-2718 type prefix (0x01 access list, 0x02 EIP-1559)
	if len(data) > 0 && data[0] <= 0x7f {
		data = data[1:]
	}
	items, err := rlp.DecodeList(data)
	if err != nil {
		return nil, err
	}
	// Receipt: [status, cumulativeGasUsed, bloom, logs]
	if len(items) < 4 {
		return nil, ce.NewContractError(ce.ErrInput, "invalid receipt: too few fields")
	}
	if !items[3].IsList {
		return nil, ce.NewContractError(ce.ErrInput, "receipt logs should be a list")
	}

	logs := make([]ParsedLog, 0, len(items[3].Children))
	for _, logItem := range items[3].Children {
		if !logItem.IsList || len(logItem.Children) < 3 {
			continue
		}
		var pl ParsedLog
		addrBytes := logItem.Children[0].AsBytes()
		if len(addrBytes) == 20 {
			copy(pl.Address[:], addrBytes)
		}
		if logItem.Children[1].IsList {
			for _, topicItem := range logItem.Children[1].Children {
				var topic [32]byte
				topicBytes := topicItem.AsBytes()
				copy(topic[32-len(topicBytes):], topicBytes)
				pl.Topics = append(pl.Topics, topic)
			}
		}
		pl.Data = logItem.Children[2].AsBytes()
		logs = append(logs, pl)
	}
	return logs, nil
}

func splitProofNodes(data []byte) [][]byte {
	// Proof nodes are concatenated RLP items. Decode each one sequentially.
	nodes := make([][]byte, 0)
	offset := 0
	for offset < len(data) {
		_, end, err := rlp.Decode(data[offset:])
		if err != nil {
			break
		}
		nodes = append(nodes, data[offset:offset+end])
		offset += end
	}
	return nodes
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
