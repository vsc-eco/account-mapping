package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
)

// CONFIRM-RECEIPT-CAP-1 (audit 11-18): a withdrawal was closed only by
// confirmSpend with the proof of its receipt, and that proof's leaf is the
// whole receipt, logs included. An ETH withdrawal to a contract that logs a
// few KB in receive() mines successfully, but its confirmSpend is over the
// node's 8 KB payload cap. Nothing else could clear its nonce (clearNonce and
// expireWithdrawal need a reverted receipt), so every withdrawal after it
// waited for good.
//
// The BTC bridge closes a payout on the payout transaction's inclusion proof
// alone. So does an ETH withdrawal now, when confirmSpend comes without a
// receipt proof: the transaction proof's leaf is our own signed transaction
// (its nonce, signer, destination and amount are checked as before), which a
// recipient cannot make larger. Unlike a Bitcoin transaction an EVM one can
// mine and revert, so the closed withdrawal is kept until
// settleWithdrawalReceipt settles it from its receipt: a reverted receipt
// refunds the value, and either status settles the gas, as confirmSpend would
// have. A reverted transaction keeps no logs, so its receipt always fits: a
// revert is always refundable afterwards. Only a withdrawal whose own receipt
// is too big is never settled, and then only its unused gas stays unrefunded
// (the withdrawer's share and what fee bumps drew from the reserve). Tokens
// keep needing their receipt (A36: the token's Transfer log).
//
// The close keeps the receipts root of the block it mined in, so the value
// side of a settlement outlives the verifier's pruning of that header (the gas
// of a withdrawal later in its block is still settled by refundWithdrawalGas,
// which reads the header). A close while the bridge is paused keeps no root:
// a pause may be for a suspect verifier (A04), and a root saved then would
// outlive the fix of a forged header; that close is settled against the stored
// header only. A stored header always wins over a saved root, and a different
// one refuses the settlement.

// inclusionClose is an ETH withdrawal closed on its inclusion proof: what
// refundRevertedWithdrawal and finishWithdrawalGas read of its pending spend,
// and, for a close while not paused, the receipts root of its block.
type inclusionClose struct {
	Nonce        uint64   `json:"n"`
	Amount       *big.Int `json:"a"`
	From         string   `json:"f"`
	To           string   `json:"t"`
	RefundTo     string   `json:"r,omitempty"`
	Vault        string   `json:"v"`
	GasCost      *big.Int `json:"c,omitempty"`
	UserGas      *big.Int `json:"u,omitempty"`
	Price        uint64   `json:"p"`
	ReceiptsRoot string   `json:"rr"`
}

func (c *inclusionClose) spend() *PendingSpend {
	return &PendingSpend{Nonce: c.Nonce, Amount: c.Amount, From: c.From, To: c.To, Asset: constants.NativeAsset,
		VaultAtQueue: c.Vault, RefundTo: c.RefundTo, GasCost: c.GasCost}
}

func inclusionCloseKey(block, txIndex uint64) string {
	return constants.InclusionClosePrefix + strconv.FormatUint(block, 10) + constants.DirPathDelimiter + strconv.FormatUint(txIndex, 10)
}

// closeOnInclusion closes the pending spend ps, mined as tx at req's block and
// index, as paid, and keeps it for settleWithdrawalReceipt. HandleConfirmSpend
// has verified the transaction and its fields.
func closeOnInclusion(ps *PendingSpend, tx *ParsedTx, header *blocklist.EthBlockHeader, req *ConfirmSpendRequest) error {
	if ps.Asset != constants.NativeAsset {
		return ce.NewContractError(ce.ErrInput, "receipt_proof required: a token withdrawal is confirmed from its receipt")
	}
	userGas, _ := spendGasShares(ps) // before DeletePendingSpend clears the reserve's share
	rec := inclusionClose{Nonce: ps.Nonce, Amount: ps.Amount, From: ps.From, To: ps.To, RefundTo: ps.RefundTo,
		Vault: ps.VaultAtQueue, GasCost: ps.GasCost, UserGas: userGas, Price: effectiveGasPrice(tx, header.BaseFeePerGas)}
	if !isPaused() {
		rec.ReceiptsRoot = hex.EncodeToString(header.ReceiptsRoot[:])
	}
	b, err := json.Marshal(&rec)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "encode inclusion close")
	}
	sdk.StateSetObject(inclusionCloseKey(req.BlockHeight, req.TxIndex), string(b))
	DeletePendingSpend(ps.Nonce)
	SetConfirmedNonce(ps.Nonce + 1)
	sdk.Log("withdrawal_lifecycle " + `{"action":"paidByInclusion","nonce":` + strconv.FormatUint(ps.Nonce, 10) +
		`,"from":"` + ps.From + `","amount":"` + ps.Amount.String() + `","asset":"` + ps.Asset + `","block":` +
		strconv.FormatUint(req.BlockHeight, 10) + `,"tx_index":` + strconv.FormatUint(req.TxIndex, 10) + `}`)
	return nil
}

// SettleWithdrawalReceiptParams names an ETH withdrawal confirmSpend closed on
// its inclusion proof by where it mined, with the proof of its own receipt.
type SettleWithdrawalReceiptParams struct {
	BlockHeight  uint64 `json:"block_height"`
	TxIndex      uint64 `json:"tx_index"`
	ReceiptProof string `json:"receipt_proof"`
}

// HandleSettleWithdrawalReceipt settles an inclusion-closed withdrawal from its
// own receipt, once. Permissionless: it moves only what the receipt shows. A
// reverted receipt refunds the value (refused while paused, as confirmSpend's
// revert refund is); either status settles the gas as confirmSpend would have.
func HandleSettleWithdrawalReceipt(p *SettleWithdrawalReceiptParams) error {
	key := inclusionCloseKey(p.BlockHeight, p.TxIndex)
	s := sdk.StateGetObject(key)
	if s == nil || *s == "" {
		return ce.NewContractError(ce.ErrIntent, "no withdrawal closed on inclusion at block "+
			strconv.FormatUint(p.BlockHeight, 10)+" index "+strconv.FormatUint(p.TxIndex, 10))
	}
	var rec inclusionClose
	if err := json.Unmarshal([]byte(*s), &rec); err != nil || rec.Amount == nil {
		return ce.NewContractError(ce.ErrInput, "unreadable inclusion-close record")
	}
	var receiptsRoot [32]byte
	if live := blocklist.GetHeader(p.BlockHeight); live != nil {
		if rec.ReceiptsRoot != "" && hex.EncodeToString(live.ReceiptsRoot[:]) != rec.ReceiptsRoot {
			return ce.NewContractError(ce.ErrTransaction, "the stored header's receipts root differs from the one the close saw")
		}
		receiptsRoot = live.ReceiptsRoot
	} else {
		if rec.ReceiptsRoot == "" {
			return ErrBlockNotFound // closed while paused: settled against the stored header only
		}
		root, err := hex.DecodeString(rec.ReceiptsRoot)
		if err != nil || len(root) != 32 {
			return ce.NewContractError(ce.ErrInput, "unreadable inclusion-close receipts root")
		}
		copy(receiptsRoot[:], root)
	}
	proofBytes, err := base64.StdEncoding.DecodeString(p.ReceiptProof)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "receipt_proof is not base64")
	}
	receiptBytes, err := mpt.VerifyProof(receiptsRoot, rlp.EncodeUint64(p.TxIndex), splitProofNodes(proofBytes))
	if err != nil {
		return ce.Prepend(err, "receipt proof")
	}
	r := receiptBytes
	if len(r) > 0 && r[0] <= 0x7f {
		r = r[1:]
	}
	items, err := rlp.DecodeList(r)
	if err != nil || len(items) < 1 {
		return ce.NewContractError(ce.ErrInput, "invalid receipt RLP")
	}
	ps := rec.spend()
	paid := items[0].AsUint64() == 1
	// The close let the withdrawal's generation stop counting as funded. One
	// purged before this settlement, and never ETH-swept (a sweep's balance
	// proof is taken after its withdrawals mined, so it carries what is left of
	// them), holds a reverted value and the unused gas at its retired address:
	// crediting either would back a balance with nothing the bridge can move.
	stranded := false
	if gen, purged := purgedSpendGen(ps); purged {
		if _, swept := ethSweptProofBlock(gen); !swept {
			stranded = true
			if !paid {
				return ce.NewContractError(ce.ErrIntent, "generation "+strconv.FormatUint(uint64(gen), 10)+
					" was purged before this reverted withdrawal was settled: its value is at the retired address")
			}
		}
	}
	if !paid {
		if isPaused() {
			return errRefundWhilePaused
		}
		refundRevertedWithdrawal(ps)
	}
	sdk.StateDeleteObject(key)
	cumulative, _ := receiptCumulativeGas(receiptBytes)
	if stranded {
		sdk.Log("gassettle|n=" + strconv.FormatUint(rec.Nonce, 10) + "|skipped=generation purged unswept")
	} else {
		finishWithdrawalGas(ps, rec.UserGas, new(big.Int), cumulative, rec.Price, p.BlockHeight, p.TxIndex)
	}
	status := "paid"
	if !paid {
		status = "reverted"
	}
	sdk.Log("withdrawal_lifecycle " + `{"action":"settledByReceipt","nonce":` + strconv.FormatUint(rec.Nonce, 10) +
		`,"block":` + strconv.FormatUint(p.BlockHeight, 10) + `,"tx_index":` + strconv.FormatUint(p.TxIndex, 10) +
		`,"status":"` + status + `"}`)
	return nil
}

// purgedSpendGen is the generation that sent ps when it is purged (SpendGen
// lists only fund-holding ones).
func purgedSpendGen(ps *PendingSpend) (uint32, bool) {
	addr, err := crypto.HexToAddress(ps.VaultAtQueue)
	if err != nil {
		return 0, false
	}
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return 0, false
	}
	for i := range vaults {
		if a, ok := GenAddress(&vaults[i]); ok && a == addr {
			return vaults[i].Generation, vaults[i].Status == VaultStatusPurged
		}
	}
	return 0, false
}
