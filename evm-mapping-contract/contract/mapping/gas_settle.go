package mapping

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
)

// EVM-FEE-1 (testnet 11-12, owner: "we cannot launch with a 12x fee"): a
// withdrawal prepays its L1 gas at the most the transaction can burn, its gas
// LIMIT x (2 x base fee + tip). The limit is sized for the worst recipient
// (250,000 on testnet: under Glamsterdam's EIP-8037 a send that creates its
// recipient costs ~207,000 gas), while a send to an existing account uses
// 21,000; nothing came back, so a user paid ~12x the gas used, and the rest sat
// in the vault credited to no one. Our BTC bridge charges the real miner fee
// (ACCT-1); THORChain books its surplus to the Reserve.
//
// Now the real cost is settled once the transaction is proven mined, from the
// proven receipt and header: gas used x the effective price (the block's base
// fee + the signed tip, capped at the signed fee cap). The unused part goes
// back to whoever prepaid it: the withdrawer up to their prepaid fee, the gas
// reserve for what it fronted (an ERC-20's gas, a fee bump); an ERC-20's gas
// fee paid in the token comes back pro rata. The prepaid amount, and so the
// limit and the price at which the transaction is signed, are unchanged, so a
// withdrawal is no more likely to sit unmined than before.
//
// A receipt holds the block's CUMULATIVE gas, so a transaction's own gas is its
// cumulative minus the previous receipt's. For the block's first transaction
// that is the cumulative itself and confirmSpend settles at once. Otherwise
// confirmSpend records the settlement (gs-{nonce}, listed in "gsl") and
// refundWithdrawalGas settles it with a proof of the previous receipt in the
// same block: a separate call, because confirmSpend's two proofs already come
// near the node's 8 KB payload cap in a large block (EVM-T1). Nothing is added
// to the pending withdrawal record (unmapETH's RC sits near the 10k limit the
// app sends): the reserve's share of a bumped fee and an ERC-20's token gas fee
// are kept beside it (gx-/gt-{nonce}).

// effectiveGasPrice is what the mined transaction paid per gas unit: the
// block's base fee plus the signed tip, never above the signed fee cap (legacy
// and EIP-2930: the gas price). 0 when the fee fields are unreadable, which
// settles nothing.
func effectiveGasPrice(tx *ParsedTx, baseFee uint64) uint64 {
	if tx.GasFeeCap == 0 {
		return 0
	}
	p := baseFee + tx.GasTipCap
	if p < baseFee || p > tx.GasFeeCap {
		return tx.GasFeeCap
	}
	return p
}

// receiptCumulativeGas reads a proven receipt's cumulative gas (field 1 of
// [status, cumulativeGasUsed, bloom, logs], after the type byte).
func receiptCumulativeGas(receipt []byte) (uint64, bool) {
	r := receipt
	if len(r) > 0 && r[0] <= 0x7f {
		r = r[1:]
	}
	items, err := rlp.DecodeList(r)
	if err != nil || len(items) < 2 {
		return 0, false
	}
	n, err := items[1].AsUint64Checked()
	return n, err == nil
}

// gasSettle is a mined withdrawal whose real gas cost is not settled yet.
type gasSettle struct {
	Nonce       uint64   `json:"n"`
	RefundTo    string   `json:"f"`
	Asset       string   `json:"a"`
	Vault       string   `json:"v"`
	GasCost     *big.Int `json:"c"`
	UserGas     *big.Int `json:"u,omitempty"`
	TokenGasFee *big.Int `json:"t,omitempty"`
	Cumulative  uint64   `json:"cum"`
	Price       uint64   `json:"p"`
	Block       uint64   `json:"h"`
	TxIndex     uint64   `json:"i"`
}

func gasSettleKey(nonce uint64) string {
	return constants.GasSettlePrefix + strconv.FormatUint(nonce, 10)
}

// spendGasShares splits what ps prepaid for gas: the withdrawer's part (an ETH
// withdrawal's fee, less what fee bumps drew from the reserve) and the token
// an ERC-20 withdrawal paid for its gas. Read before the pending spend (and
// with it gx-/gt-) is deleted.
func spendGasShares(ps *PendingSpend) (userGas, tokenGasFee *big.Int) {
	userGas, tokenGasFee = new(big.Int), new(big.Int)
	if ps.GasCost == nil {
		return
	}
	if ps.Asset == constants.NativeAsset {
		userGas.Sub(ps.GasCost, bigState(gasReserveExtraKey(ps.Nonce)))
		if userGas.Sign() < 0 {
			userGas.SetInt64(0)
		}
		return
	}
	tokenGasFee.Set(bigState(gasTokenFeeKey(ps.Nonce)))
	return
}

func gasReserveExtraKey(nonce uint64) string {
	return constants.GasReserveExtraPrefix + strconv.FormatUint(nonce, 10)
}

func gasTokenFeeKey(nonce uint64) string {
	return constants.GasTokenFeePrefix + strconv.FormatUint(nonce, 10)
}

func bigState(key string) *big.Int {
	if v := sdk.StateGetObject(key); v != nil {
		if n, ok := new(big.Int).SetString(*v, 10); ok && n.Sign() > 0 {
			return n
		}
	}
	return new(big.Int)
}

func addSpendReserveExtra(nonce uint64, amount *big.Int) {
	if amount == nil || amount.Sign() <= 0 {
		return
	}
	k := gasReserveExtraKey(nonce)
	sdk.StateSetObject(k, new(big.Int).Add(bigState(k), amount).String())
}

func setSpendTokenGasFee(nonce uint64, fee *big.Int) {
	sdk.StateSetObject(gasTokenFeeKey(nonce), fee.String())
}

func clearSpendGasShares(nonce uint64) {
	sdk.StateDeleteObject(gasReserveExtraKey(nonce))
	sdk.StateDeleteObject(gasTokenFeeKey(nonce))
}

// finishWithdrawalGas settles a confirmed withdrawal's real gas cost now (the
// block's first transaction, bridge not paused) or records it for
// refundWithdrawalGas. ps is the pending spend as it stood at confirmation.
func finishWithdrawalGas(ps *PendingSpend, userGas, tokenGasFee *big.Int, cumulative, price, block, txIndex uint64) {
	if price == 0 || ps.GasCost == nil || ps.GasCost.Sign() <= 0 {
		return
	}
	g := &gasSettle{Nonce: ps.Nonce, RefundTo: ps.refundAccount(), Asset: ps.Asset, Vault: ps.VaultAtQueue,
		GasCost: ps.GasCost, UserGas: userGas, TokenGasFee: tokenGasFee,
		Cumulative: cumulative, Price: price, Block: block, TxIndex: txIndex}
	if txIndex == 0 && !isPaused() {
		settleWithdrawalGas(g, cumulative)
		return
	}
	b, _ := json.Marshal(g)
	sdk.StateSetObject(gasSettleKey(ps.Nonce), string(b))
	setGasSettleList(append(gasSettleList(), strconv.FormatUint(ps.Nonce, 10)))
	sdk.Log("gassettle|n=" + strconv.FormatUint(ps.Nonce, 10) + "|h=" + strconv.FormatUint(block, 10) + "|i=" + strconv.FormatUint(txIndex, 10))
}

// settleWithdrawalGas refunds what g prepaid beyond gasUsed x its price.
func settleWithdrawalGas(g *gasSettle, gasUsed uint64) {
	real := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), new(big.Int).SetUint64(g.Price))
	unused := new(big.Int).Sub(g.GasCost, real)
	if unused.Sign() <= 0 {
		return
	}
	// The withdrawer pays the real cost up to their prepaid fee; the reserve
	// fronted the rest (an ERC-20's gas, a fee bump) and gets back what is left.
	userGas := new(big.Int)
	if g.UserGas != nil {
		userGas.Set(minBig(g.UserGas, g.GasCost))
	}
	userRefund := new(big.Int).Sub(userGas, minBig(real, userGas))
	reserveRefund := new(big.Int).Sub(unused, userRefund)
	if userRefund.Sign() > 0 {
		IncBalance(g.RefundTo, constants.NativeAsset, userRefund)
		trackRefund(constants.NativeAsset, userRefund)
	}
	if reserveRefund.Sign() > 0 {
		addGasReserve(reserveRefund)
		TrackReserveRestore(reserveRefund)
	}
	// The unused ETH never left the address that sent the withdrawal: a
	// superseded generation books it, as a refunded withdrawal's value is.
	bookSpendRefund(&PendingSpend{VaultAtQueue: g.Vault, Asset: constants.NativeAsset}, unused)
	tokenRefund := new(big.Int)
	if g.Asset != constants.NativeAsset && g.TokenGasFee != nil && g.TokenGasFee.Sign() > 0 {
		tokenRefund.Mul(g.TokenGasFee, unused)
		tokenRefund.Div(tokenRefund, g.GasCost)
		if tokenRefund.Sign() > 0 && DecBalance(constants.TokenGasFeeRecipient, g.Asset, tokenRefund) {
			IncBalance(g.RefundTo, g.Asset, tokenRefund)
		} else {
			tokenRefund.SetInt64(0)
		}
	}
	sdk.Log("gasrefund|n=" + strconv.FormatUint(g.Nonce, 10) + "|used=" + strconv.FormatUint(gasUsed, 10) +
		"|p=" + strconv.FormatUint(g.Price, 10) + "|u=" + userRefund.String() + "|r=" + reserveRefund.String() +
		"|t=" + tokenRefund.String() + "|to=" + g.RefundTo)
}

func gasSettleList() []string {
	s := sdk.StateGetObject(constants.GasSettleListKey)
	if s == nil || *s == "" {
		return nil
	}
	return strings.Split(*s, "|")
}

func setGasSettleList(l []string) {
	if len(l) == 0 {
		sdk.StateDeleteObject(constants.GasSettleListKey)
		return
	}
	sdk.StateSetObject(constants.GasSettleListKey, strings.Join(l, "|"))
}

// RefundWithdrawalGasParams settles a recorded withdrawal's gas: the receipt
// proof is of the transaction before it in the same block (none for index 0).
type RefundWithdrawalGasParams struct {
	Nonce        uint64 `json:"nonce"`
	ReceiptProof string `json:"receipt_proof"`
}

// HandleRefundWithdrawalGas settles the real gas cost of a mined withdrawal
// confirmSpend recorded. Permissionless: it credits only what the proofs show
// was prepaid and not burned, to whoever prepaid it, once.
func HandleRefundWithdrawalGas(p *RefundWithdrawalGasParams) error {
	if isPaused() {
		return errRefundWhilePaused
	}
	key := gasSettleKey(p.Nonce)
	s := sdk.StateGetObject(key)
	if s == nil || *s == "" {
		return ce.NewContractError(ce.ErrIntent, "no gas settlement recorded for withdrawal "+strconv.FormatUint(p.Nonce, 10))
	}
	var g gasSettle
	if err := json.Unmarshal([]byte(*s), &g); err != nil || g.GasCost == nil {
		return ce.NewContractError(ce.ErrInput, "unreadable gas settlement record")
	}
	prev := uint64(0)
	if g.TxIndex > 0 {
		header := blocklist.GetHeader(g.Block)
		if header == nil {
			return ErrBlockNotFound
		}
		proofBytes, err := base64.StdEncoding.DecodeString(p.ReceiptProof)
		if err != nil {
			return ce.WrapContractError(ce.ErrInput, err, "receipt_proof is not base64")
		}
		leaf, err := mpt.VerifyProof(header.ReceiptsRoot, rlp.EncodeUint64(g.TxIndex-1), splitProofNodes(proofBytes))
		if err != nil {
			return ce.Prepend(err, "previous receipt proof")
		}
		c, ok := receiptCumulativeGas(leaf)
		if !ok {
			return ce.NewContractError(ce.ErrInput, "unreadable previous receipt")
		}
		prev = c
	}
	if prev > g.Cumulative {
		return ce.NewContractError(ce.ErrInput, "previous receipt's cumulative gas is above the withdrawal's")
	}
	settleWithdrawalGas(&g, g.Cumulative-prev)
	sdk.StateDeleteObject(key)
	n := strconv.FormatUint(p.Nonce, 10)
	l := gasSettleList()
	for i, v := range l {
		if v == n {
			l = append(l[:i], l[i+1:]...)
			break
		}
	}
	setGasSettleList(l)
	return nil
}
