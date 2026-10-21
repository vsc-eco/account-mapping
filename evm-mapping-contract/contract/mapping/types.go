package mapping

type MapParams struct {
	TxData       VerificationRequest `json:"tx_data"`
	Instructions []string            `json:"instructions"`
}

type VerificationRequest struct {
	BlockHeight    uint64 `json:"block_height"`
	TxIndex        uint64 `json:"tx_index"`
	RawHex         string `json:"raw_hex"`
	MerkleProofHex string `json:"merkle_proof_hex"`
	LogIndex       uint64 `json:"log_index"`
	TokenAddress   string `json:"token_address"`
	DepositType    string `json:"deposit_type"` // "eth" or "erc20"
}

type TransferParams struct {
	Amount       string `json:"amount"`
	To           string `json:"to"`
	From         string `json:"from"`
	Asset        string `json:"asset"`
	TokenAddress string `json:"token_address"`
	DeductFee    bool   `json:"deduct_fee"`
	MaxFee       string `json:"max_fee"`
}

type AllowanceParams struct {
	Spender string `json:"spender"`
	Amount  string `json:"amount"`
	Asset   string `json:"asset"`
}

type RegisterTokenParams struct {
	Address       string `json:"address"`
	Symbol        string `json:"symbol"`
	Decimals      uint8  `json:"decimals"`
	MinWithdrawal int64  `json:"min_withdrawal"`
}

type TokenInfo struct {
	Symbol        string `json:"symbol"`
	Decimals      uint8  `json:"decimals"`
	MinWithdrawal int64  `json:"min_withdrawal"`
}

// ConfirmSpendRequest carries both tx and receipt proofs for withdrawal
// confirmation. W4 Cluster E CRIT #5 + HIGH #13 (D-E-1 + D-E-2 LOCKED): the
// payload is 8 TOP-LEVEL fields: 4 proof legs + 4 intent reference fields.
//
// EVM-T1: the proofs travel as base64 and the tx and receipt are not sent on
// their own. They are the leaves the two proofs prove, so the contract takes
// them from mpt.VerifyProof. With hex proofs and both leaves sent twice, a
// confirmSpend for a withdrawal mined late in a large L1 block went over the
// node's 8,192-byte contract-payload cap (MAX_CONTRACT_PAYLOAD_SIZE), failed on
// every node, and froze every withdrawal behind it (only one may be pending).
// Adding the intent fields lets the contract verify the TSS-signed L1 tx
// matches the on-chain PendingSpend (closes HIGH #13: TSS quorum can sign
// arbitrary L1 tx). Validation order in HandleConfirmSpend per D-E-2:
//  1. Entry-point intent binding (all 4 IntentX must equal PendingSpend)
//  2. recoveredSender == ps.VaultAtQueue (snapshotted vault from Cluster F)
//  3. parsedTx.To / parsedTx.Value / asset binding (defense-in-depth)
//
// Wire-format authority: `confirmSpendSchema()` wasmexport in main.go
// returns this struct's canonical schema JSON for bot startup introspection.
type ConfirmSpendRequest struct {
	// Proof legs
	BlockHeight  uint64 `json:"block_height"`
	TxIndex      uint64 `json:"tx_index"`
	TxProof      string `json:"tx_proof"`      // base64: concatenated tx-trie MPT nodes, leaf = the raw tx
	ReceiptProof string `json:"receipt_proof"` // base64: concatenated receipt-trie MPT nodes, leaf = the receipt
	// Intent reference (4 NEW — HIGH #13 D-E-1). Contract MUST verify all 4
	// match the looked-up PendingSpend BEFORE proof verification.
	IntentNonce  uint64 `json:"intent_nonce"`  // PendingSpend.Nonce
	IntentTo     string `json:"intent_to"`     // PendingSpend.To
	IntentAmount string `json:"intent_amount"` // PendingSpend.Amount as a decimal-wei string (big.Int/wei migration — JSON-number precision is unsafe for >2^53 wei across non-Go bots)
	IntentAsset  string `json:"intent_asset"`  // PendingSpend.Asset
}

// L1ProofOfDrop — W4 Cluster E CRIT #26 + CRIT #27 (D-E-4 LOCKED).
//
// SHIPPED STATE (DS-F2 round4): Type A is the ONLY accepted proof shape.
// Type B is DISABLED pending team review (LOCKED-D-E-4). See verifyL1ProofOfDrop
// in handlers.go for the H-SM2 explanation: a higher-nonce tx proves the
// original nonce was CONSUMED but NOT that it was dropped (vs. succeeded),
// so Type B admits double-spend and requires a full wire-format redesign.
// Bot implementations MUST use Type A exclusively.
//
//  - Type A "reverted-receipt" (ACTIVE): receipt-trie MPT proof showing the
//    L1 tx at the cleared/expired nonce was mined with `status=0` (reverted).
//    Reuses the receipt-trie infrastructure from HandleConfirmSpend (CRIT #1).
//    Vault-sender binding via ecrecover against ps.VaultAtQueue.
//
//  - Type B "block_inclusion_without_tx" (DISABLED — LOCKED-D-E-4): wire fields
//    are still present in this struct for forward-compatibility with a future
//    sound redefinition, but verifyL1ProofOfDrop returns an error for this type.
//    Do NOT use in production until team review removes the disable gate.
//
// LOCKED wire format (this manifest — closes the W1 deferral flagged in
// MILO-REVIEW §1 Cluster E CONCERNS):
//
//	{
//	  "type":              "reverted_receipt" | "block_inclusion_without_tx",
//	  "block_height":      uint64,            // finalized L1 height of the proof
//	  "tx_index":          uint64,            // tx index for type A; unused for type B (disabled)
//	  "tx_nonce":          uint64,            // L1 nonce being proven cleared (== ps.Nonce)
//	  // Type A only, empty for type B. base64, and the receipt and tx are the
//	  // proven leaves (EVM-T1: the same 8,192-byte cap as ConfirmSpendRequest)
//	  "receipt_proof":     "...",             // concatenated receipt-trie MPT nodes; leaf = receipt with status=0
//	  "tx_proof":          "...",             // concatenated tx-trie MPT nodes at the same tx_index; leaf = raw tx
//	  // Type B fields (present for forward-compat; ignored while disabled)
//	  "tx_at_index_hex":   "0x...",
//	  "tx_proof_hex":      "0x...",
//	  "vault_nonce_proof_hex": "0x..."
//	}
//
// Verification path (Type A only — Type B is disabled):
//  - Type A: blocklist.GetHeader(BlockHeight) → header.ReceiptsRoot →
//    mpt.VerifyProof(rcptRoot, rlp(TxIndex), proofNodes) → receipt.Status == 0
//    AND receipt's parsed nonce field MUST equal TxNonce. Reject otherwise.
//    ecrecover binds the proven tx's sender to ps.VaultAtQueue.
//
// Mainnet/testnet posture: Type A requires a header already anchored via the
// ZK light client (per the ZK architecture note above). The bot MUST NOT
// supply a header that has not been ingested by HandleAddBlocks.
type L1ProofOfDrop struct {
	Type               string `json:"type"`                      // "reverted_receipt" or "block_inclusion_without_tx"
	BlockHeight        uint64 `json:"block_height"`              // finalized L1 height
	TxIndex            uint64 `json:"tx_index"`                  // index within block
	TxNonce            uint64 `json:"tx_nonce"`                  // L1 nonce being cleared
	ReceiptProof       string `json:"receipt_proof,omitempty"`   // type A, base64
	TxProof            string `json:"tx_proof,omitempty"`        // type A, base64
	TxAtIndexHex       string `json:"tx_at_index_hex,omitempty"` // type B
	TxProofHex         string `json:"tx_proof_hex,omitempty"`
	VaultNonceProofHex string `json:"vault_nonce_proof_hex,omitempty"` // optional safety hint (type B)
}

// L1ProofTypeRevertedReceipt / L1ProofTypeBlockInclusion — canonical type
// strings. Implementing handlers compare against these constants; do NOT
// inline string literals.
const (
	L1ProofTypeRevertedReceipt = "reverted_receipt"
	L1ProofTypeBlockInclusion  = "block_inclusion_without_tx"
)

// W4 Cluster E payload structs for the new wasmexports. The handler-side
// JSON unmarshal sites are in main.go; payload shape is part of the wire
// contract surfaced via confirmSpendSchema-style introspection (lifecycle
// payloads do NOT have their own introspection export — the proof shape
// is documented in this file and via the W1/W4 manifests).

// ClearNonceParams — W4 Cluster E B-E-4 + S-E-v17-2 (clearNonce wasmexport
// shape change). Pre-fix wasmexport ignored its input with `_ *string`,
// making the proof unreachable. Post-fix takes this struct via the
// propose/execute payload bytes.
type ClearNonceParams struct {
	Proof L1ProofOfDrop `json:"proof"`
}

// ExpireWithdrawalParams — W4 Cluster E CRIT #26 (D-E-3). Nonce names the
// confirmed-head withdrawal to expire; proof is MANDATORY on ALL paths
// (DS-F2 round4 / F3b fix). The window governs only WHO may call (pre-window:
// original withdrawer only; post-window: anyone), not WHETHER proof is
// required. Omitting proof risks refunding a withdrawal that actually succeeded
// on L1 (double-spend); any caller must supply a Type-A L1ProofOfDrop.
type ExpireWithdrawalParams struct {
	Nonce uint64        `json:"nonce"`
	Proof L1ProofOfDrop `json:"proof"`
}

// CancelMyWithdrawalParams — W4 Cluster E CRIT #26 companion. Proof
// MANDATORY (must NOT race in-flight L1 tx confirmation).
type CancelMyWithdrawalParams struct {
	Nonce uint64        `json:"nonce"`
	Proof L1ProofOfDrop `json:"proof"`
}

// Parsed EIP-1559 transaction fields
type ParsedTx struct {
	ChainId uint64
	Nonce   uint64
	To      [20]byte
	Value   []byte // big-endian uint256
	Data    []byte
	V       byte
	R       []byte
	S       []byte
}

// DexInstruction for swap routing
type DexInstruction struct {
	Type             string `json:"type"`
	Version          string `json:"version"`
	AssetIn          string `json:"asset_in"`
	AmountIn         string `json:"amount_in"`
	AssetOut         string `json:"asset_out"`
	Recipient        string `json:"recipient"`
	DestinationChain string `json:"destination_chain"`
	// A8 (DX-H5 on BTC): the depositor's slippage floor, passed to the router
	// unchanged; the router and the DEX enforce it.
	MinAmountOut *string `json:"min_amount_out,omitempty"`
}

// Parsed receipt log
type ParsedLog struct {
	Address [20]byte
	Topics  [][32]byte
	Data    []byte
}
