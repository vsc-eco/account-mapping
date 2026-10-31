package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
)

var (
	ErrBlockNotFound   = ce.NewContractError(ce.ErrStateAccess, "block header not found")
	ErrProofFailed     = ce.NewContractError(ce.ErrTransaction, "proof verification failed")
	ErrNotVaultDeposit = ce.NewContractError(ce.ErrInput, "transaction is not a deposit to vault")
	ErrAlreadyObserved = ce.NewContractError(ce.ErrInput, "deposit already processed")
	ErrInvalidToken    = ce.NewContractError(ce.ErrInput, "token not registered")
	// W4 Cluster B CRIT #6 Sites 1+2: explicit error for wrong-chain
	// deposit proofs. The L1 trie proof can be valid AND the parsed tx
	// can be well-formed, yet the tx may have been mined on a different
	// chain. Without this check, an attacker could replay a chain-X tx
	// against the chain-Y bridge state.
	ErrChainIdMismatch = ce.NewContractError(ce.ErrInput, "tx chain id does not match contract chain id")
)

// keccak256("Transfer(address,address,uint256)") = ddf252ad...
var transferEventSigBytes, _ = hex.DecodeString("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
var TransferEventSig = func() [32]byte { var h [32]byte; copy(h[:], transferEventSigBytes); return h }()

// VerifyETHDeposit verifies a native ETH deposit via transaction inclusion proof.
// Returns the sender address, deposit amount (wei as big-endian bytes), and the tx hash.
// W4 Cluster B CRIT #6 Site 1: chainId threaded in so the parsed tx's
// ChainId field is cross-checked BEFORE ecrecover spends cycles. Pre-fix
// a chain-X tx could be replayed against the chain-Y bridge state.
//
// A01: isVault reports whether an address is one of the vault's fund-holding
// generations (the caller records which one matched).
func VerifyETHDeposit(
	req *VerificationRequest,
	isVault func([20]byte) bool,
	chainId uint64,
) ([20]byte, []byte, []byte, [32]byte, error) {
	var sender [20]byte
	var txHash [32]byte

	header := blocklist.GetHeader(req.BlockHeight)
	if header == nil {
		return sender, nil, nil, txHash, ErrBlockNotFound
	}

	rawBytes, err := hex.DecodeString(req.RawHex)
	if err != nil {
		return sender, nil, nil, txHash, ce.WrapContractError(ce.ErrInvalidHex, err, "raw_hex")
	}

	proofBytes, err := hex.DecodeString(req.MerkleProofHex)
	if err != nil {
		return sender, nil, nil, txHash, ce.WrapContractError(ce.ErrInvalidHex, err, "merkle_proof_hex")
	}

	proof := splitProofNodes(proofBytes)
	key := mpt.RLPEncodeKey(req.TxIndex)

	value, err := mpt.VerifyProof(header.TransactionsRoot, key, proof)
	if err != nil {
		return sender, nil, nil, txHash, ErrProofFailed
	}

	// Verify the proven value matches the raw TX
	if !bytesEqual(value, rawBytes) {
		return sender, nil, nil, txHash, ErrProofFailed
	}

	// Compute TX hash for observed tracking
	txHash = crypto.Keccak256Hash(rawBytes)

	// Check not already observed
	if IsObserved(req.BlockHeight, txHash, uint16(req.TxIndex)) {
		return sender, nil, nil, txHash, ErrAlreadyObserved
	}

	// Parse the transaction to extract to, value, and signature
	parsedTx, err := parseTransaction(rawBytes)
	if err != nil {
		return sender, nil, nil, txHash, err
	}

	// W4 Cluster B CRIT #6 Site 1: reject wrong-chain deposit proofs.
	// trie-proof binds rawBytes -> on-chain root; parseTransaction decodes
	// ChainId from the canonical RLP; this check rejects cross-chain replay
	// BEFORE ecrecover spends any cycles.
	if parsedTx.ChainId != chainId {
		return sender, nil, nil, txHash, ErrChainIdMismatch
	}

	// Verify destination is vault
	if !isVault(parsedTx.To) {
		return sender, nil, nil, txHash, ErrNotVaultDeposit
	}

	// FAILDEP-1: the tx must have succeeded. A reverted tx is in the block but
	// moved no value; under Glamsterdam (EIP-8037) a transfer that creates the
	// vault's account reverts at 21,000 gas, so before the first deposit anyone
	// could mint by "sending" ETH they keep. The receipt at the same index
	// (base64 proof, leaf = the receipt) must have status 1 (parseReceiptLogs).
	if req.ReceiptProof == "" {
		return sender, nil, nil, txHash, ce.NewContractError(ce.ErrInput, "an eth deposit needs receipt_proof (its status proves the value moved)")
	}
	rcptProof, err := base64.StdEncoding.DecodeString(req.ReceiptProof)
	if err != nil || len(rcptProof) == 0 {
		return sender, nil, nil, txHash, ce.NewContractError(ce.ErrInput, "receipt_proof must be base64 (concatenated receipt-trie MPT nodes)")
	}
	receipt, err := mpt.VerifyProof(header.ReceiptsRoot, key, splitProofNodes(rcptProof))
	if err != nil {
		return sender, nil, nil, txHash, ErrProofFailed
	}
	if _, err := parseReceiptLogs(receipt); err != nil {
		return sender, nil, nil, txHash, ce.Prepend(err, "eth deposit receipt")
	}

	// Recover sender via ecrecover
	sighash := computeTxSighash(rawBytes, parsedTx)
	recoveryV := byte(27 + parsedTx.V)
	rPadded := padTo32(parsedTx.R)
	sPadded := padTo32(parsedTx.S)

	// CRIT #11 site 5 (USER, NORMALIZE): post-EIP-2 L1 blocks cannot carry
	// high-S signatures, so EcrecoverCanonical accepts the same low-S
	// envelope SYSTEM sigs require.
	sender, err = crypto.EcrecoverCanonical(sighash, recoveryV, rPadded, sPadded)
	if err != nil {
		return sender, nil, nil, txHash, ce.Prepend(err, "ecrecover failed")
	}
	if sender == ([20]byte{}) {
		return sender, nil, nil, txHash, ce.NewContractError(ce.ErrTransaction, "ecrecover returned zero address")
	}

	// CRIT #8 / W4 Cluster A: MarkObserved is NOT called here. HandleMap
	// performs MarkObserved AFTER instruction routing + IncBalance + supply
	// accounting succeed, so a failure later in the pipeline does not
	// permanently consume the observed slot for this (blockHeight, txHash, idx).
	//
	// big.Int/wei migration: native ETH is accounted in full wei. The parsed
	// L1 tx value (big-endian wei) is returned verbatim — no gwei truncation
	// boundary. HandleMap reconstructs it via big.Int.SetBytes and credits the
	// exact wei amount.
	return sender, parsedTx.Value, parsedTx.Data, txHash, nil
}

// VerifyERC20Deposit verifies an ERC-20 deposit via receipt inclusion proof.
// Returns the sender address, token amount (big-endian bytes), and the tx hash.
// W4 Cluster B CRIT #6 Site 2: chainId threaded so the stored header's
// ChainId field is cross-checked. Pre-fix the receipt-trie proof could be
// valid but the underlying block could have come from a different chain.
//
// A01: isVault reports whether an address is one of the vault's fund-holding
// generations (the caller records which one matched).
func VerifyERC20Deposit(
	req *VerificationRequest,
	isVault func([20]byte) bool,
	tokenAddr [20]byte,
	chainId uint64,
) ([20]byte, []byte, [32]byte, error) {
	var sender [20]byte
	var txHash [32]byte

	header := blocklist.GetHeader(req.BlockHeight)
	if header == nil {
		return sender, nil, txHash, ErrBlockNotFound
	}

	// W4 Cluster B CRIT #6 Site 2: ERC-20 receipt path reads chainId from
	// the stored block header (since the receipt itself has no chainId
	// field). Reject wrong-chain receipts BEFORE any further work.
	if header.ChainId != chainId {
		return sender, nil, txHash, ErrChainIdMismatch
	}

	// ERC20-PAYLOAD-1: the receipt proof may come base64 with the receipt as
	// its leaf (receipt_proof, EVM-T1), or hex with the receipt sent again
	// (raw_hex + merkle_proof_hex). The hex form carries the receipt four
	// times over in the payload, so under the 8,192-byte cap a deposit in a
	// tx with more than ~5 logs (an aggregator, a batch payout) could never be
	// mapped; base64 fits ~4x the receipt. Both prove the same receipt and use
	// the same observed key, so one cannot map a deposit the other did.
	var receiptBytes []byte
	key := mpt.RLPEncodeKey(req.TxIndex)
	if req.ReceiptProof != "" {
		proofBytes, err := base64.StdEncoding.DecodeString(req.ReceiptProof)
		if err != nil || len(proofBytes) == 0 {
			return sender, nil, txHash, ce.NewContractError(ce.ErrInput, "receipt_proof must be base64 (concatenated receipt-trie MPT nodes)")
		}
		value, err := mpt.VerifyProof(header.ReceiptsRoot, key, splitProofNodes(proofBytes))
		if err != nil {
			return sender, nil, txHash, ErrProofFailed
		}
		receiptBytes = value
	} else {
		raw, err := hex.DecodeString(req.RawHex)
		if err != nil {
			return sender, nil, txHash, ce.WrapContractError(ce.ErrInvalidHex, err, "raw_hex")
		}
		proofBytes, err := hex.DecodeString(req.MerkleProofHex)
		if err != nil {
			return sender, nil, txHash, ce.WrapContractError(ce.ErrInvalidHex, err, "merkle_proof_hex")
		}
		value, err := mpt.VerifyProof(header.ReceiptsRoot, key, splitProofNodes(proofBytes))
		if err != nil {
			return sender, nil, txHash, ErrProofFailed
		}
		if !bytesEqual(value, raw) {
			return sender, nil, txHash, ErrProofFailed
		}
		receiptBytes = raw
	}

	// review6 M4: dedup key was previously keccak(receiptBytes), which is
	// stable per receipt but not strictly anchored to the (block, txIndex)
	// position the MPT proof verified against. Mix the proven TxIndex into
	// the keying material so two L1 txs that ever produced byte-identical
	// receipts cannot collide on the observed slot. BlockHeight is already
	// part of the IsObserved key, so this triple uniquely identifies the
	// receipt-trie leaf.
	txIndexBytes := []byte{
		byte(req.TxIndex >> 24), byte(req.TxIndex >> 16),
		byte(req.TxIndex >> 8), byte(req.TxIndex),
	}
	txHash = crypto.Keccak256Hash(append(receiptBytes, txIndexBytes...))

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
		return sender, nil, txHash, ce.NewContractError(ce.ErrInput, "not a Transfer event")
	}

	// topics[2] == vault address (padded to 32 bytes).
	// review6 closure (WM-CR-7 companion): explicit canonical-encoding
	// check on the vault topic too. We construct the canonical padded
	// vault here, so the equality check below already catches non-canon
	// high bytes; documented for clarity.
	vaultAddress, canonical := topicAddress(log.Topics[2])
	if !canonical || !isVault(vaultAddress) {
		return sender, nil, txHash, ErrNotVaultDeposit
	}

	// Sender from topics[1] (padded address).
	//
	// review6 closure (WM-CR-7 / F11): an EVM Transfer event topic is a
	// 32-byte left-zero-padded 20-byte address. The canonical encoding
	// MUST have topics[1][0:12] == 0. Pre-fix, only the low 20 bytes were
	// copied — a malformed receipt with non-zero upper 12 bytes would
	// silently pass through and the sender would be the truncated low
	// 20 bytes. Reject any non-canonical topic so a forged-receipt path
	// (oracle-fed pre-H2) can't impersonate the depositor via the unused
	// upper bytes.
	for i := 0; i < 12; i++ {
		if log.Topics[1][i] != 0 {
			return sender, nil, txHash, errors.New("malformed sender topic: non-zero high bytes")
		}
	}
	copy(sender[:], log.Topics[1][12:])
	if sender == ([20]byte{}) {
		return sender, nil, txHash, ce.NewContractError(
			ce.ErrTransaction,
			"zero-address sender (mint event, not a deposit)",
		)
	}

	// RP-7: a transfer that paid a MagiDeposit deposit is credited to the
	// recipient its Deposit log names (deposit_type "contract"), never here
	// to the sender as well.
	if transferPaysAContractDeposit(logs, int(req.LogIndex), vaultAddress) {
		return sender, nil, txHash, ce.NewContractError(ce.ErrInput,
			"this transfer paid a MagiDeposit deposit: map its Deposit log (deposit_type contract)")
	}

	amount, err := transferLogAmount(log.Data)
	if err != nil {
		return sender, nil, txHash, err
	}

	// CRIT #8 / W4 Cluster A: MarkObserved is NOT called here. The caller
	// (HandleMap) records the observed slot only after the full deposit
	// pipeline succeeds.
	return sender, amount, txHash, nil
}

// transferLogAmount reads the amount of an ERC-20 Transfer log. A standard
// Transfer carries exactly one uint256 word; anything else (a non-standard or
// upgraded token) is refused, so the credit can never exceed what the word
// says (as confirmSpend and the MagiDeposit path already bound it). A06.
func transferLogAmount(data []byte) ([]byte, error) {
	if len(data) != 32 {
		return nil, ce.NewContractError(ce.ErrInput, "Transfer data must be one 32-byte amount")
	}
	return data, nil
}

// parseTransaction decodes an RLP-encoded Ethereum transaction: legacy, or an
// EIP-2718 typed transaction of type 1, 2, 3 or 4.
//
// E18: types 1 (EIP-2930), 3 (EIP-4844) and 4 (EIP-7702) used to be refused, so
// ETH a user sent to the vault in one of them was never credited and had no
// recovery path. A deposit's proof is the same for every type (inclusion in
// the proven tx trie, and its receipt's success status, FAILDEP-1), so these
// types are accepted like type 2.
func parseTransaction(raw []byte) (*ParsedTx, error) {
	if len(raw) == 0 {
		return nil, ce.NewContractError(ce.ErrInput, "empty transaction")
	}
	if raw[0] <= 0x7f {
		layout, ok := typedTxLayouts(raw[0])
		if !ok {
			return nil, ce.NewContractError(ce.ErrInput, "unsupported tx type: only legacy and types 1-4 are accepted")
		}
		return parseTypedTx(raw[1:], layout)
	}
	return parseLegacyTx(raw)
}

// typedTxLayout is where an EIP-2718 typed transaction keeps the fields this
// contract reads. The signature (yParity, r, s) is always the last three.
type typedTxLayout struct {
	name                  string
	fields, to, value, in int
}

func typedTxLayouts(txType byte) (typedTxLayout, bool) {
	switch txType {
	case 1: // [chainId, nonce, gasPrice, gas, to, value, data, accessList, yParity, r, s]
		return typedTxLayout{"EIP-2930", 11, 4, 5, 6}, true
	case 2: // [chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data, accessList, yParity, r, s]
		return typedTxLayout{"EIP-1559", 12, 5, 6, 7}, true
	case 3: // [... accessList, maxFeePerBlobGas, blobVersionedHashes, yParity, r, s]
		return typedTxLayout{"EIP-4844", 14, 5, 6, 7}, true
	case 4: // [... accessList, authorizationList, yParity, r, s]
		return typedTxLayout{"EIP-7702", 13, 5, 6, 7}, true
	}
	return typedTxLayout{}, false
}

func parseTypedTx(data []byte, l typedTxLayout) (*ParsedTx, error) {
	items, err := rlp.DecodeList(data)
	if err != nil {
		return nil, err
	}
	if len(items) != l.fields {
		return nil, ce.NewContractError(ce.ErrInput, "invalid "+l.name+" tx: wrong field count")
	}

	// MED-27 (M21-15): decode the security-critical integer fields through the
	// checked path so a forged >8-byte chainId/nonce/v is rejected rather than
	// silently truncated to its low 8 bytes (which could be made to alias the
	// contract chainId and slip past the downstream ChainId == chainId check).
	chainId, err := items[0].AsUint64Checked()
	if err != nil {
		return nil, errors.New("invalid " + l.name + " tx: chainId field oversized/non-canonical")
	}
	nonce, err := items[1].AsUint64Checked()
	if err != nil {
		return nil, errors.New("invalid " + l.name + " tx: nonce field oversized/non-canonical")
	}
	vVal, err := items[l.fields-3].AsUint64Checked()
	if err != nil || vVal > 1 {
		return nil, errors.New("invalid " + l.name + " tx: yParity field not 0 or 1")
	}
	tx := &ParsedTx{
		ChainId: chainId,
		Nonce:   nonce,
		Value:   items[l.value].AsBytes(),
		Data:    items[l.in].AsBytes(),
		V:       byte(vVal),
		R:       items[l.fields-2].AsBytes(),
		S:       items[l.fields-1].AsBytes(),
	}
	toBytes := items[l.to].AsBytes()
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

	// MED-27 (M21-15): legacy v carries chainId via EIP-155 (v = chainId*2 +
	// 35 + recovery). A >8-byte v would silently truncate and yield a wrong
	// derived chainId that the downstream equality check could miss. Reject
	// oversized/non-canonical v and nonce instead of wrapping.
	v, err := items[6].AsUint64Checked()
	if err != nil {
		return nil, errors.New("invalid legacy tx: v field oversized/non-canonical")
	}
	nonce, err := items[0].AsUint64Checked()
	if err != nil {
		return nil, errors.New("invalid legacy tx: nonce field oversized/non-canonical")
	}
	parsed := &ParsedTx{
		Nonce: nonce,
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
	// Typed (EIP-2718): sighash = keccak256(type || RLP(every field before the
	// signature)). Legacy EIP-155: keccak256(RLP([nonce, gasPrice, gas, to,
	// value, data, chainId, 0, 0])).
	if len(raw) > 0 && raw[0] <= 0x7f {
		items, err := rlp.DecodeList(raw[1:])
		if err != nil || len(items) < 3 {
			return crypto.Keccak256(raw)
		}
		unsigned := make([][]byte, len(items)-3)
		for i := range unsigned {
			if items[i].IsList {
				unsigned[i] = reencodeItem(items[i])
			} else {
				unsigned[i] = rlp.EncodeBytes(items[i].AsBytes())
			}
		}
		return crypto.Keccak256(append([]byte{raw[0]}, rlp.EncodeList(unsigned...)...))
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
	// review6 closure (WM-CR-10 / M71): reject receipts whose status field
	// is not 1 (success). EVM receipts from reverted txs may still carry
	// logs from partially-executed inner frames; parsing them and using
	// them in deposit verification is an audit-flagged surface. Drop
	// status!=1 here so no downstream caller has to remember to check.
	status := items[0].AsUint64()
	if status != 1 {
		return nil, errors.New("receipt status != success (reverted or missing)")
	}
	if !items[3].IsList {
		return nil, ce.NewContractError(ce.ErrInput, "receipt logs should be a list")
	}

	logs := make([]ParsedLog, 0, len(items[3].Children))
	for _, logItem := range items[3].Children {
		// review6 closure (LOW-5 / F15): a malformed log entry shifts
		// subsequent LogIndex positions and silently confuses
		// LogIndex-keyed dedup. Hard-reject the whole receipt rather
		// than skipping the bad entry. Strictness is correct here —
		// any well-formed receipt has well-formed log entries.
		if !logItem.IsList || len(logItem.Children) < 3 {
			return nil, errors.New("malformed log entry in receipt")
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
	//
	// MED-19 (M18-D7/D8) + MED-66 (T2-7/CF-EVM-4) site 1: enforce the
	// previously-dead constants.MaxMPTProofNodes HERE — the earliest point a
	// caller-supplied proof blob is split — so an attacker cannot force an
	// unbounded node COUNT. The COUNT cap (20) is the real DoS bound:
	// mpt.VerifyProof re-checks it (MaxProofNodes=20) at verify.go:132.
	//
	// R2-1 (fix-round-2) + round3 C-RV (comment correction): the previous
	// constants.MaxMPTNodeSize=4096 per-node SIZE cap is REMOVED (and the now-
	// dead constant deleted). It wrongly rejected legitimate ERC-20 RECEIPT-trie
	// LEAF nodes: a receipt carrying ~20+ Transfer/other logs RLP-encodes well
	// past 4096 bytes, so VerifyERC20Deposit (and the confirmSpend receipt
	// proof) would reject the proof and the deposit would become permanently
	// unprovable — funds stuck on L1.
	//
	// The REAL ingress bound on the whole proof blob is the node's contract-
	// payload cap, MAX_CONTRACT_PAYLOAD_SIZE = 8192 bytes, which every node
	// checks before execution (go-vsc-node state-processing); it is below the
	// transaction pool's MAX_TX_SIZE = 16384 (EVM-T1). The earlier comment's "20 * 64 KB / maxItemSize=
	// 65536" framing was WRONG: the RLP codec's per-item maxItemSize=65536 is an
	// internal codec ceiling, not the DoS bound — no proof blob admitted to the
	// contract can approach 20*64 KB because the payload is capped at 8 KB
	// upstream. The COUNT cap (20) stays as the in-contract bound that limits
	// per-call verify work; the payload cap bounds the total bytes.
	nodes := make([][]byte, 0)
	offset := 0
	for offset < len(data) {
		if len(nodes) >= constants.MaxMPTProofNodes {
			break
		}
		_, end, err := rlp.Decode(data[offset:])
		if err != nil {
			break
		}
		nodes = append(nodes, data[offset:offset+end])
		offset += end
	}
	// round3 P2C-3: reject the proof blob if it was not fully consumed. Leftover
	// bytes mean either a decode error mid-stream, trailing garbage, or MORE than
	// MaxMPTProofNodes concatenated items — all malformed. Previously the loop
	// silently returned the parsed prefix (which mpt.VerifyProof would usually
	// reject anyway, but only by coincidence of root-mismatch). Failing here
	// makes the rejection explicit and deterministic; a well-formed proof always
	// consumes exactly len(data) within the node-count cap. A legitimate caller
	// never sends trailing bytes (the wire blob is a pure node concatenation).
	if offset != len(data) {
		return nil
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
