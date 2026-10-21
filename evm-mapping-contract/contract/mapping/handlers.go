package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"evm-mapping-contract/contract/abi"
	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"
)

// IsWhitelistedRelayer — W4 Cluster C CRIT #8 native-ETH frontrun mitigation
// (PARTIAL-CLOSES-AND-DEFERRALS.md item #1, v1 scope): native ETH path
// requires the caller to be a registered relayer.
func IsWhitelistedRelayer(account string) bool {
	if account == "" {
		return false
	}
	data := sdk.StateGetObject(constants.RelayerRegistryPrefix + crypto.CanonicalIdentity(account))
	return data != nil && *data == "1"
}

// SetRelayer / UnsetRelayer write / delete the per-relayer state entry.
// Called from the propose/execute dispatchAdmin switch in main.go after
// the operational-class timelock elapses.
func SetRelayer(account string) {
	sdk.StateSetObject(constants.RelayerRegistryPrefix+crypto.CanonicalIdentity(account), "1")
}

func UnsetRelayer(account string) {
	sdk.StateDeleteObject(constants.RelayerRegistryPrefix + crypto.CanonicalIdentity(account))
}

// AssertNotPaused — exported so main.go dispatchAdmin can gate every
// migrated handler with this BEFORE business logic, per W1 §D-C-9.
func AssertNotPaused() error {
	if isPaused() {
		return ce.NewContractError(ce.ErrInitialization, "contract is paused")
	}
	return nil
}

// HandleMap — W4 Cluster B CRIT #6 Sites 1+2+3+10 + W4 Cluster C CRIT #8:
// chainId threaded in for wrong-chain reject; native ETH path now also
// gated by relayer whitelist (ERC-20 stays permissionless because the
// Transfer-log proof binds depositor cryptographically).
func HandleMap(params *MapParams, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	if vaultAddress == ([20]byte{}) {
		return ce.NewContractError(ce.ErrInitialization, "vault address not configured")
	}

	req := &params.TxData

	switch req.DepositType {
	case "eth":
		// W4 Cluster C CRIT #8 (v1 relayer whitelist): native ETH has no
		// cryptographic depositor-to-L1 binding (the L1 tx sender is not
		// the L2 caller). Gate the path on a registered relayer so a
		// rogue L2 caller cannot route someone else's deposit. ERC-20
		// path stays permissionless because the Transfer-log proof binds
		// the depositor.
		caller := sdk.GetEnv().Caller.String()
		if !IsWhitelistedRelayer(caller) {
			return ce.NewContractError(ce.ErrAuth, "native ETH deposit: caller is not a whitelisted relayer")
		}
		// W4 Cluster B CRIT #6 Site 1: chainId passed in so VerifyETHDeposit
		// can reject wrong-chain txs before any state mutation. calldata is the
		// PROVEN L1 tx data field — the depositor-signed routing-intent channel.
		sender, amountBytes, calldata, txHash, err := VerifyETHDeposit(req, vaultAddress, chainId)
		if err != nil {
			return err
		}

		amount := new(big.Int).SetBytes(amountBytes)
		if amount.Sign() <= 0 {
			return ce.NewContractError(ce.ErrInput, "deposit amount must be positive")
		}

		// review6 follow-up: native-ETH routing intent is read from the PROVEN
		// L1 calldata (parsedTx.Data), which the depositor signed over — NOT
		// from params.Instructions, which the relayer supplies and could forge.
		// Empty calldata => no instructions => credit the sender's derived DID.
		instructions := parseCalldataInstructions(calldata)

		// to_reserve: the depositor directs the WHOLE deposit into the gas
		// reserve (proof-backed reserve funding). No user credit; Active and the
		// reserve grow together, preserving Active == User + Fee + reserve — the
		// trust-minimized replacement for a bare setGasReserve write.
		if hasToReserveInstruction(instructions) {
			addGasReserve(amount)
			TrackDeposit("eth", new(big.Int), amount)
			MarkObserved(req.BlockHeight, txHash, uint16(req.TxIndex))
			return nil
		}

		// Gas reserve tax: bps of ETH deposits, credited in full wei. big.Int
		// keeps exact precision (Div truncates toward zero) with no overflow.
		// Taken off the top BEFORE routing so the credit/swap and the supply
		// accounting all operate on the same net amount.
		gasTax := new(big.Int).Div(
			new(big.Int).Mul(amount, big.NewInt(constants.GasReserveDepositTaxBps)),
			big.NewInt(10000),
		)
		netAmount := new(big.Int).Sub(amount, gasTax)
		if gasTax.Sign() > 0 {
			addGasReserve(gasTax)
		}

		// Honor the depositor-signed instructions: deposit_to redirect, or a
		// swap_to/asset_out DEX swap. routeDeposit returns the L2 destination,
		// or "" when it dispatched the swap (which already credited the funds).
		dest := routeDeposit(sender, instructions, "eth", netAmount, chainId)
		if dest != "" {
			IncBalance(dest, "eth", netAmount)
		}
		TrackDeposit("eth", netAmount, gasTax)
		// CRIT #8 / W4 Cluster A: lock the observed slot only after the
		// deposit has been fully routed + credited + accounted. If any
		// earlier step errors, the slot stays open for the next attempt.
		MarkObserved(req.BlockHeight, txHash, uint16(req.TxIndex))
		return nil

	case "erc20":
		tokenAddr, err := crypto.HexToAddress(req.TokenAddress)
		if err != nil {
			return ce.Prepend(err, "token address")
		}

		// W4 Cluster B CRIT #6 Site 10: token registry keyed by (chainId, addr).
		tokenInfo := getTokenInfo(chainId, tokenAddr)
		if tokenInfo == nil {
			return ErrInvalidToken
		}

		// W4 Cluster B CRIT #6 Site 2: chainId threaded so VerifyERC20Deposit
		// can read the stored header's chainId and cross-check.
		sender, amountBytes, txHash, err := VerifyERC20Deposit(req, vaultAddress, tokenAddr, chainId)
		if err != nil {
			return err
		}

		amount := new(big.Int).SetBytes(amountBytes)
		if amount.Sign() <= 0 {
			return ce.NewContractError(ce.ErrArithmetic, "deposit amount invalid")
		}

		// review6 follow-up: ERC-20 deposits settle ONLY to the sender's derived
		// Magi account. A standard ERC-20 transfer exposes no depositor-signed
		// intent channel — the bridge proves a fixed-schema Transfer event, not
		// the depositor's calldata — so relayer-supplied instructions are
		// untrusted and ignored here. Cross-account routing / swaps for tokens
		// require a future depositor-signed mechanism (e.g. a deposit-wrapper
		// EVM contract that emits an instruction-bearing event).
		dest := crypto.AddressToDID(sender)
		IncBalance(dest, tokenInfo.Symbol, amount)
		TrackDeposit(tokenInfo.Symbol, amount, new(big.Int))
		// CRIT #8 / W4 Cluster A + CRIT #14 logIndex: lock observed slot
		// only after routing + credit succeed.
		MarkObserved(req.BlockHeight, txHash, uint16(req.LogIndex))
		return nil

	default:
		return ce.NewContractError(ce.ErrInput, "deposit_type must be 'eth' or 'erc20'")
	}
}

func HandleUnmapETH(params *TransferParams, vaultAddress [20]byte, chainId uint64) (string, error) {
	if isPaused() {
		return "", ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	if HasPendingWithdrawal() {
		return "", ce.NewContractError(ce.ErrIntent, "withdrawal pending: wait for confirmation")
	}

	env := sdk.GetEnv()
	if err := checkAuth(env); err != nil {
		return "", err
	}
	caller := env.Caller.String()

	amount, ok := new(big.Int).SetString(params.Amount, 10)
	if !ok || amount.Sign() <= 0 {
		return "", ce.NewContractError(ce.ErrInput, "invalid amount")
	}
	if amount.Cmp(big.NewInt(constants.MinETHWithdrawal)) < 0 {
		return "", ce.NewContractError(ce.ErrIntent, "below minimum ETH withdrawal")
	}

	toAddr, err := crypto.HexToAddress(params.To)
	if err != nil {
		return "", ce.Prepend(err, "'to' address")
	}
	// review2 #44: the zero address parses as a valid [20]byte; a
	// TSS-signed withdrawal to 0x000…0 burns the funds irrecoverably.
	// (Also review6 closure T2-14 / M70 — same finding, single guard suffices.)
	if toAddr == ([20]byte{}) {
		return "", ce.NewContractError(ce.ErrInput, "refusing withdrawal to zero address")
	}

	header, herr := pricingHeader()
	if herr != nil {
		return "", herr
	}

	gasReserve := getGasReserve()
	if gasReserve.Cmp(big.NewInt(constants.MinGasReserve)) < 0 {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient gas reserve")
	}

	gasTipCap := uint64(2_000_000_000) // 2 gwei
	// review2 HIGH #16: checked arithmetic — a negative (wrapped) fee here
	// inflated the user's balance instead of debiting it. The fee is now a
	// *big.Int in WEI, so it composes directly with the wei balance.
	// (Supersedes review6 L1/X3: big.Int fee math cannot overflow, so the
	// int64 SafeMul path the audit called for is unnecessary on this base.)
	gasFeeCap, feeWei, feeErr := safeGasFee(constants.ETHTransferGas, header.BaseFeePerGas, 2, gasTipCap)
	if feeErr != nil {
		return "", ce.NewContractError(ce.ErrArithmetic, "gas fee computation overflow")
	}

	if params.MaxFee != "" {
		maxFee, mok := new(big.Int).SetString(params.MaxFee, 10)
		if !mok {
			return "", ce.NewContractError(ce.ErrInput, "invalid max_fee")
		}
		// HIGH #40: reject negative max_fee instead of silently disabling the cap.
		if maxFee.Sign() < 0 {
			return "", ce.NewContractError(ce.ErrInput, "max_fee must be non-negative")
		}
		// HIGH #40: maxFee=0 must mean "no fees accepted" — a zero cap rejects
		// any positive computed fee. maxFee and the fee are both WEI.
		if feeWei.Cmp(maxFee) > 0 {
			return "", ce.NewContractError(ce.ErrInput, "fee exceeds max_fee")
		}
	}

	// big.Int/wei: the fee is full wei, same denomination as amount/balance.
	fee := feeWei

	// l1Value is what the signed L1 tx sends; userDebit is what the caller
	// pays on Magi. Uniform invariant either way: userDebit == l1Value + fee.
	//   DeductFee=false (fee on top):  l1Value = amount,       userDebit = amount + fee
	//   DeductFee=true  (fee netted):  l1Value = amount - fee, userDebit = amount
	// This makes every downstream path mode-agnostic: a reverted L1 tx
	// returns l1Value to the vault (refund ps.Amount); a proven-dropped tx
	// spent nothing (refund ps.Amount + ps.GasCost).
	l1Value := new(big.Int).Set(amount)
	userDebit := new(big.Int).Set(amount)
	if params.DeductFee {
		l1Value.Sub(l1Value, fee)
		if l1Value.Sign() <= 0 {
			return "", ce.NewContractError(ce.ErrIntent, "amount does not cover the L1 fee")
		}
	} else {
		userDebit.Add(amount, fee)
	}

	// Check balance BEFORE signing to prevent signed TX leak on insufficient funds.
	if GetBalance(caller, "eth").Cmp(userDebit) < 0 {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient balance")
	}

	nonce := GetPendingNonce()
	unsigned := BuildETHWithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, toAddr, l1Value)
	sighash := ComputeSighash(unsigned)

	if err := requireTssKey(); err != nil {
		return "", err
	}
	sdk.TssSignKey("primary", sighash)

	if !DecBalance(caller, "eth", userDebit) {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient balance")
	}
	// Custody accounting: the vault will pay out l1Value + gas ≈ userDebit
	// (gas estimated at the fee upper bound), all charged to the caller.
	// Active and User both shrink by the full debit; the L1 fee is real
	// custody outflow, not a Magi fee, so Supply.Fee is untouched.
	// (MED-133 corrupt-supply abort is enforced inside GetSupply now.)
	TrackWithdrawal("eth", userDebit)

	// W4 Cluster F D-F-3: snapshot CURRENT vault into VaultAtQueue. When
	// confirmSpend lands, HandleConfirmSpend ecrecovers against this
	// snapshot (NOT current vault) — a vault change (TSS key rotation)
	// between unmap and confirmSpend no longer orphans the pending
	// withdrawal (HIGH #29).
	StorePendingSpend(PendingSpend{
		Nonce:         nonce,
		Amount:        l1Value, // the L1 tx value — returns to the vault on revert
		From:          caller,
		To:            params.To,
		Asset:         "eth",
		UnsignedTxHex: hex.EncodeToString(unsigned),
		BlockHeight:   blocklist.GetLastHeight(),
		VaultAtQueue:  "0x" + hex.EncodeToString(vaultAddress[:]),
		GasCost:       fee, // prepaid L1 fee — refunded with Amount if the tx is proven dropped
	})
	SetPendingNonce(nonce + 1)

	return hex.EncodeToString(unsigned), nil
}

func HandleUnmapERC20(params *TransferParams, vaultAddress [20]byte, chainId uint64) (string, error) {
	if isPaused() {
		return "", ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	if HasPendingWithdrawal() {
		return "", ce.NewContractError(ce.ErrIntent, "withdrawal pending: wait for confirmation")
	}

	env := sdk.GetEnv()
	if err := checkAuth(env); err != nil {
		return "", err
	}
	caller := env.Caller.String()

	amount, ok := new(big.Int).SetString(params.Amount, 10)
	if !ok || amount.Sign() <= 0 {
		return "", ce.NewContractError(ce.ErrInput, "invalid amount")
	}
	if params.TokenAddress == "" {
		return "", ce.NewContractError(ce.ErrInput, "token_address required for ERC-20 withdrawal")
	}
	tokenAddr, err := crypto.HexToAddress(params.TokenAddress)
	if err != nil {
		return "", ce.Prepend(err, "token_address")
	}
	// W4 Cluster B CRIT #6 Site 10: token registry keyed by (chainId, addr).
	tokenInfo := getTokenInfo(chainId, tokenAddr)
	if tokenInfo == nil {
		return "", ErrInvalidToken
	}
	if amount.Cmp(big.NewInt(tokenInfo.MinWithdrawal)) < 0 {
		return "", ce.NewContractError(ce.ErrIntent, "below minimum withdrawal for this token")
	}

	recipientAddr, err := crypto.HexToAddress(params.To)
	if err != nil {
		return "", ce.Prepend(err, "recipient address")
	}
	// review2 #44: refuse the zero address (TSS-signed burn).
	// (Also review6 closure T2-14 / M70 — same finding, single guard suffices.)
	if recipientAddr == ([20]byte{}) {
		return "", ce.NewContractError(ce.ErrInput, "refusing withdrawal to zero address")
	}

	header, herr := pricingHeader()
	if herr != nil {
		return "", herr
	}

	gasReserve := getGasReserve()
	if gasReserve.Cmp(big.NewInt(constants.MinGasReserve)) < 0 {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient gas reserve for ERC-20 withdrawal")
	}

	gasTipCap := uint64(2_000_000_000)
	// review2 HIGH #16: checked arithmetic (see safeGasFee); gasCost is *big.Int WEI.
	// (Supersedes review6 L1/X3 — big.Int gas math cannot overflow.)
	gasFeeCap, gasCost, feeErr := safeGasFee(constants.ERC20TransferGas, header.BaseFeePerGas, 2, gasTipCap)
	if feeErr != nil {
		return "", ce.NewContractError(ce.ErrArithmetic, "gas fee computation overflow")
	}
	// MED-83 (M30-Scenario-5), ported to develop's wei model: enforce MaxFee on
	// the ERC-20 path too. Pre-fix only HandleUnmapETH honored MaxFee, so at a
	// baseFee spike the contract would deduct an unbounded gas cost from the
	// reserve regardless of the caller's stated cap. gasCost is already WEI here
	// (safeGasFee), the same denomination as MaxFee — mirror HandleUnmapETH.
	if params.MaxFee != "" {
		maxFee, mok := new(big.Int).SetString(params.MaxFee, 10)
		if !mok {
			return "", ce.NewContractError(ce.ErrInput, "invalid max_fee")
		}
		if maxFee.Sign() < 0 {
			return "", ce.NewContractError(ce.ErrInput, "max_fee must be non-negative")
		}
		if gasCost.Cmp(maxFee) > 0 {
			return "", ce.NewContractError(ce.ErrInput, "fee exceeds max_fee")
		}
	}

	// RV-6 (RV re-verify): the ERC-20 gas is paid out of the shared ETH reserve.
	// The MinGasReserve floor above is NOT enough — at a high base fee the gas
	// estimate can exceed the whole reserve, and the pre-fix deductGasReserve
	// clamped to 0 while Active("eth") was still debited the full estimate,
	// silently spending user-owned ETH and under-collateralizing the vault.
	// Require the reserve to actually cover this withdrawal's gas before signing.
	if getGasReserve().Cmp(gasCost) < 0 {
		return "", ce.NewContractError(ce.ErrBalance, "gas reserve cannot cover this withdrawal's L1 gas at the current base fee")
	}

	nonce := GetPendingNonce()
	unsigned := BuildERC20WithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, tokenAddr, recipientAddr, amount)
	sighash := ComputeSighash(unsigned)

	if err := requireTssKey(); err != nil {
		return "", err
	}
	sdk.TssSignKey("primary", sighash)

	if !DecBalance(caller, tokenInfo.Symbol, amount) {
		return "", ce.NewContractError(ce.ErrBalance, "insufficient token balance")
	}
	// ERC-20 unmap pays L1 gas out of the contract-wide gas-reserve pool
	// (deductGasReserve below), NOT out of the user's token balance — so the
	// token supply is debited by the bare amount only.
	TrackWithdrawal(tokenInfo.Symbol, amount)

	// big.Int/wei: gas reserve and gas cost are both full wei — deduct directly.
	// The reserve is ETH custody, so the spend is also booked against
	// Active("eth"); restored via TrackReserveRestore if the tx is proven dropped.
	deductGasReserve(gasCost)
	TrackReserveSpend(gasCost)

	// W4 Cluster F D-F-3: snapshot vault for ERC-20 path too.
	StorePendingSpend(PendingSpend{
		Nonce:         nonce,
		Amount:        amount,
		From:          caller,
		To:            params.To,
		Asset:         tokenInfo.Symbol,
		TokenAddress:  params.TokenAddress,
		UnsignedTxHex: hex.EncodeToString(unsigned),
		BlockHeight:   blocklist.GetLastHeight(),
		VaultAtQueue:  "0x" + hex.EncodeToString(vaultAddress[:]),
		GasCost:       gasCost, // wei reserve deducted; refunded on failed receipt (EVM-C4)
	})
	SetPendingNonce(nonce + 1)

	return hex.EncodeToString(unsigned), nil
}

// HandleConfirmSpend — W4 Cluster F D-F-3 (S-F-v17-2): vaultAddress
// parameter REMOVED. The handler reads ps.VaultAtQueue directly from
// the stored PendingSpend (snapshotted at queue time). A vault change (TSS
// key rotation) between unmap and confirmSpend no longer orphans the
// pending withdrawal —
// the TSS signature targeting the OLD vault still verifies against the
// OLD vault (HIGH #29 closure).
//
// W4 Cluster E CRIT #5 + HIGH #13 (D-E-1 + D-E-2): the request carries
// 4 intent fields verified BEFORE proof work (primary HIGH #13 gate).
//
// D8: not pause-gated, as the BTC mapping contract's confirmSpend settle. It
// records an L1 fact (the queued withdrawal mined; on a revert the value goes
// back to the withdrawer's L2 balance, which cannot leave while unmaps are
// paused) and authorizes no new spend. Gated, a pause outlasting the verifier's
// header retention pruned the mined withdrawal's header, after which nothing
// could confirm it or prove it dropped: every withdrawal stayed frozen.
func HandleConfirmSpend(req *ConfirmSpendRequest, chainId uint64) error {
	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return ce.NewContractError(ce.ErrIntent, "no pending spend at confirmed nonce")
	}

	// W4 Cluster E HIGH #13 entry-point intent binding (D-E-2 SERIOUS-1).
	// These 4 checks fire BEFORE any tx proof verification.
	if req.IntentNonce != confirmedNonce {
		return errors.New("intent fields do not match pending spend: nonce")
	}
	if req.IntentTo != ps.To {
		return errors.New("intent fields do not match pending spend: to")
	}
	intentAmt, iok := new(big.Int).SetString(req.IntentAmount, 10)
	if !iok || intentAmt.Cmp(ps.Amount) != 0 {
		return errors.New("intent fields do not match pending spend: amount")
	}
	if req.IntentAsset != ps.Asset {
		return errors.New("intent fields do not match pending spend: asset")
	}

	if req.BlockHeight <= ps.BlockHeight {
		return ce.NewContractError(ce.ErrIntent, "confirmation block must be after withdrawal block")
	}

	header := blocklist.GetHeader(req.BlockHeight)
	if header == nil {
		return ErrBlockNotFound
	}

	// --- Transaction proof: verify the tx matches the pending spend ---
	// EVM-T1: the tx is the proof's leaf, so it is not sent on its own.
	txProofBytes, err := base64.StdEncoding.DecodeString(req.TxProof)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "tx_proof is not base64")
	}

	txProof := splitProofNodes(txProofBytes)
	txKey := rlp.EncodeUint64(req.TxIndex)
	txBytes, err := mpt.VerifyProof(header.TransactionsRoot, txKey, txProof)
	if err != nil {
		return ce.Prepend(err, "tx proof")
	}

	parsedTx, err := parseTransaction(txBytes)
	if err != nil {
		return ce.Prepend(err, "parse proven tx")
	}
	if parsedTx.Nonce != ps.Nonce {
		return ce.NewContractError(ce.ErrTransaction, "tx nonce does not match pending spend")
	}
	if parsedTx.ChainId != chainId {
		return ce.NewContractError(ce.ErrTransaction, "tx chain id does not match contract chain id")
	}

	// CRIT #11 site 6 (SYSTEM, REJECT) + W4 Cluster F D-F-3 (HIGH #29):
	// vault TSS-sig recovery against ps.VaultAtQueue (snapshot at unmap
	// time), NOT the current vault. A vault change (TSS key rotation) between
	// unmap and confirmSpend no longer orphans the pending withdrawal.
	if ps.VaultAtQueue == "" || ps.VaultAtQueue == "0x0000000000000000000000000000000000000000" {
		return errors.New(
			"VaultAtQueue is zero — pre-upgrade PendingSpend entry; use clearNonce (with L1-proof-of-drop) or wait for W0 P0 state clearing",
		)
	}
	snapshottedVault, err := crypto.HexToAddress(ps.VaultAtQueue)
	if err != nil {
		return errors.New("VaultAtQueue parse failed: " + err.Error())
	}
	sighash := computeTxSighash(txBytes, parsedTx)
	recoveredSender, err := crypto.EcrecoverStrict(sighash, 27+parsedTx.V, padTo32(parsedTx.R), padTo32(parsedTx.S))
	if err != nil {
		return ce.Prepend(err, "ecrecover")
	}
	if recoveredSender == ([20]byte{}) {
		return ce.NewContractError(ce.ErrTransaction, "ecrecover returned zero address")
	}
	if recoveredSender != snapshottedVault {
		return ce.NewContractError(ce.ErrTransaction, "tx not signed by vault at queue time")
	}

	// D3: on a rolled withdrawal the roll (a 0-value self-transfer at the same
	// nonce) may be what mined. The vault's nonce is then spent, so the
	// withdrawal can never mine, and its value goes back to the withdrawer. A
	// withdrawal itself is never a 0-value transfer to the vault (an ETH one
	// carries its amount, an ERC-20 one goes to the token).
	if ps.Rolled && parsedTx.To == snapshottedVault && new(big.Int).SetBytes(parsedTx.Value).Sign() == 0 {
		refundDroppedWithdrawal(ps)
		DeletePendingSpend(confirmedNonce)
		SetConfirmedNonce(confirmedNonce + 1)
		sdk.Log("withdrawal_lifecycle " + `{"action":"rolledBack","nonce":` + strconv.FormatUint(confirmedNonce, 10) +
			`,"from":"` + ps.From + `","amount":"` + ps.Amount.String() + `","asset":"` + ps.Asset + `"}`)
		return nil
	}

	psTo, err := crypto.HexToAddress(ps.To)
	if err != nil {
		return ce.Prepend(err, "pending spend destination")
	}
	if ps.Asset == "eth" {
		if parsedTx.To != psTo {
			return ce.NewContractError(ce.ErrTransaction, "tx destination does not match pending spend")
		}
		// big.Int/wei: both the L1 tx value and ps.Amount are full wei.
		txAmountWei := new(big.Int).SetBytes(parsedTx.Value)
		if txAmountWei.Cmp(ps.Amount) != 0 {
			return ce.NewContractError(ce.ErrTransaction, "tx amount does not match pending spend")
		}
	} else {
		// ERC-20: tx.to is the token contract, value is 0, calldata is transfer(recipient, amount).
		tokenAddr, err := crypto.HexToAddress(ps.TokenAddress)
		if err != nil {
			return ce.Prepend(err, "pending spend token address")
		}
		if parsedTx.To != tokenAddr {
			return ce.NewContractError(ce.ErrTransaction, "tx token contract does not match pending spend")
		}
		if new(big.Int).SetBytes(parsedTx.Value).Sign() != 0 {
			return ce.NewContractError(ce.ErrTransaction, "erc20 tx must have zero value")
		}
		if len(parsedTx.Data) != 68 {
			return ce.NewContractError(ce.ErrTransaction, "erc20 calldata must be 68 bytes")
		}
		if !bytesEqual(parsedTx.Data[0:4], abi.TransferSelector) {
			return ce.NewContractError(ce.ErrTransaction, "erc20 calldata selector mismatch")
		}
		// First 12 bytes of address slot must be zero (left-padded address).
		for _, b := range parsedTx.Data[4:16] {
			if b != 0 {
				return ce.NewContractError(ce.ErrTransaction, "erc20 recipient padding non-zero")
			}
		}
		if !bytesEqual(parsedTx.Data[16:36], psTo[:]) {
			return ce.NewContractError(ce.ErrTransaction, "erc20 recipient does not match pending spend")
		}
		callAmount := new(big.Int).SetBytes(parsedTx.Data[36:68])
		if callAmount.Cmp(ps.Amount) != 0 {
			return ce.NewContractError(ce.ErrTransaction, "erc20 amount does not match pending spend")
		}
	}

	// --- Receipt proof: determine success or failure ---
	// EVM-T1: the receipt is the proof's leaf, so it is not sent on its own.
	receiptProofBytes, err := base64.StdEncoding.DecodeString(req.ReceiptProof)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "receipt_proof is not base64")
	}

	receiptProof := splitProofNodes(receiptProofBytes)
	receiptKey := rlp.EncodeUint64(req.TxIndex)
	receiptBytes, err := mpt.VerifyProof(header.ReceiptsRoot, receiptKey, receiptProof)
	if err != nil {
		return ce.Prepend(err, "receipt proof")
	}

	receiptToParse := receiptBytes
	if len(receiptToParse) > 0 && receiptToParse[0] <= 0x7f {
		receiptToParse = receiptToParse[1:]
	}
	items, err := rlp.DecodeList(receiptToParse)
	if err != nil || len(items) < 1 {
		return ce.NewContractError(ce.ErrInput, "invalid receipt RLP")
	}
	status := items[0].AsUint64()

	if status == 1 {
		DeletePendingSpend(confirmedNonce)
		SetConfirmedNonce(confirmedNonce + 1)
	} else {
		// Reverted receipt (status=0): the tx MINED, so the L1 gas was
		// genuinely paid to the miner — that custody is gone. Only the tx
		// VALUE (ps.Amount) returned to the vault; refund exactly that.
		// The gas cost stays borne by whoever funded it: the withdrawer's
		// prepaid fee (ETH path) or the gas reserve (ERC-20 path).
		//
		// Supersedes pentest EVM-C4's reserve refund here, which restored
		// the reserve counter for gas that HAD been spent, overstating the
		// reserve vs the real vault balance. The reserve/fee is restored
		// only where nothing was spent — the proven-dropped path
		// (refundDroppedWithdrawal). Reserve liveness is preserved: the
		// deposit tax keeps funding it, and dropped-tx restores now work.
		// big.Int/wei: IncBalance and the supply adds cannot overflow, so the
		// int64 best-effort/drift-marker path from 30710e4 is unnecessary here.
		IncBalance(ps.From, ps.Asset, ps.Amount)
		s := GetSupply(ps.Asset)
		s.Active.Add(s.Active, ps.Amount)
		s.User.Add(s.User, ps.Amount)
		SetSupply(ps.Asset, s)
		DeletePendingSpend(confirmedNonce)
		SetConfirmedNonce(confirmedNonce + 1)
	}

	return nil
}

func HandleTransfer(params *TransferParams) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	env := sdk.GetEnv()
	if err := checkAuth(env); err != nil {
		return err
	}
	caller := env.Caller.String()

	amount, ok := new(big.Int).SetString(params.Amount, 10)
	if !ok || amount.Sign() <= 0 {
		return ce.NewContractError(ce.ErrInput, "invalid amount")
	}

	// review2 #43 / A5: a recipient that is not a Magi identity (empty, or a
	// malformed name) would hold funds no one can sign for. Reject it.
	if err := requireValidRecipient(params.To); err != nil {
		return err
	}

	// E1 (RV re-verify): reject free-form assets that would inject ledger keys.
	if err := requireAllowedAsset(params.Asset); err != nil {
		return err
	}

	if !DecBalance(caller, params.Asset, amount) {
		return ce.NewContractError(ce.ErrBalance, "insufficient balance")
	}
	IncBalance(params.To, params.Asset, amount)
	return nil
}

func HandleTransferFrom(params *TransferParams) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	env := sdk.GetEnv()
	if err := checkAuth(env); err != nil {
		return err
	}
	caller := env.Caller.String()

	amount, ok := new(big.Int).SetString(params.Amount, 10)
	if !ok || amount.Sign() <= 0 {
		return ce.NewContractError(ce.ErrInput, "invalid amount")
	}

	// review2 #43 / A5: reject a recipient that is not a Magi identity.
	if err := requireValidRecipient(params.To); err != nil {
		return err
	}

	// E1 (RV re-verify): reject free-form assets that would inject ledger keys.
	if err := requireAllowedAsset(params.Asset); err != nil {
		return err
	}

	allowance := GetAllowance(params.From, caller, params.Asset)
	if allowance.Cmp(amount) < 0 {
		return ce.NewContractError(ce.ErrBalance, "insufficient allowance")
	}

	if !DecBalance(params.From, params.Asset, amount) {
		return ce.NewContractError(ce.ErrBalance, "insufficient balance")
	}
	SetAllowance(params.From, caller, params.Asset, new(big.Int).Sub(allowance, amount))
	IncBalance(params.To, params.Asset, amount)
	return nil
}

func HandleApprove(params *AllowanceParams) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	env := sdk.GetEnv()
	if err := checkAuth(env); err != nil {
		return err
	}
	caller := env.Caller.String()

	amount, ok := new(big.Int).SetString(params.Amount, 10)
	if !ok || amount.Sign() < 0 {
		return ce.NewContractError(ce.ErrInput, "invalid amount")
	}

	// E1 (RV re-verify): reject free-form assets that would inject ledger keys.
	if err := requireAllowedAsset(params.Asset); err != nil {
		return err
	}
	// ALLOW-1: the spender must be a Magi identity (see constants.AllowanceDelimiter).
	if err := requireValidSpender(params.Spender); err != nil {
		return err
	}

	SetAllowance(caller, params.Spender, params.Asset, amount)
	return nil
}

// Helpers

// parseCalldataInstructions interprets the PROVEN L1 transaction calldata of a
// native-ETH deposit (parsedTx.Data) as the depositor's routing instructions.
// Because the calldata is part of the depositor's signed, MPT-proven
// transaction, these instructions are bound to the depositor — unlike the
// relayer-supplied params.Instructions, which are no longer trusted or read.
//
// Wire format: UTF-8 "key=value" pairs separated by '&' (query-string style),
// e.g. "deposit_to=hive:alice", "swap_to=hive:alice&asset_out=hbd", or
// "to_reserve=1". A plain ETH transfer carries empty calldata, which yields no
// instructions and credits the sender's derived DID.
func parseCalldataInstructions(calldata []byte) []string {
	if len(calldata) == 0 {
		return nil
	}
	parts := strings.Split(string(calldata), "&")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// hasToReserveInstruction reports whether the depositor asked to route the whole
// deposit into the ETH gas reserve. Takes precedence over any other instruction.
func hasToReserveInstruction(instructions []string) bool {
	for _, instr := range instructions {
		if instr == "to_reserve=1" || instr == "to_reserve=true" {
			return true
		}
	}
	return false
}

// routeDeposit returns the L2 destination for a deposit, or dispatches a DEX
// swap (returning "") when swap_to/asset_out instructions are present.
//
// review6 follow-up: callers pass ONLY depositor-authorized instructions.
// Native ETH sources them from the PROVEN L1 calldata (parseCalldataInstructions
// in HandleMap), so honoring deposit_to / swap_to here is safe — the depositor
// signed them. ERC-20 no longer calls routeDeposit at all (it settles to the
// sender's DID) because a Transfer event carries no depositor-signed intent.
// chainId is threaded so the default DID derives from the deposit chain.
func routeDeposit(sender [20]byte, instructions []string, asset string, amount *big.Int, chainId uint64) string {
	did := crypto.AddressToDID(sender)
	dest := did
	var swapTo, assetOut, destChain string
	var minAmountOut *string

	// MED-66 (T2-7/CF-EVM-4) site 2: bound the instruction list. Routing needs
	// only a handful of directives; an over-cap list is an attacker paying dust
	// to force unbounded per-element string-slicing. Over the cap, skip
	// instruction parsing entirely and credit the depositor's own derived DID.
	// (Note: native-ETH instructions are now depositor-signed calldata — the
	// old H9 "ignore all eth instructions" stance was reversed by the
	// parseCalldataInstructions work; the bound still applies as a DoS guard.)
	if len(instructions) > constants.MaxDepositInstructions {
		return dest
	}
	for _, instr := range instructions {
		// A5: a destination that is not a Magi identity is ignored and the
		// deposit stays with the depositor. Refusing the map instead would
		// strand the ETH on L1, since the depositor-signed calldata is final.
		if len(instr) > 11 && instr[:11] == "deposit_to=" && validIdentity(instr[11:]) {
			dest = instr[11:]
		}
		if len(instr) > 8 && instr[:8] == "swap_to=" && validIdentity(instr[8:]) {
			swapTo = instr[8:]
		}
		if len(instr) > 10 && instr[:10] == "asset_out=" {
			assetOut = instr[10:]
		}
		if len(instr) > 18 && instr[:18] == "destination_chain=" {
			destChain = instr[18:]
		}
		// A8: forward the depositor's min_amount_out. The calldata is public
		// on L1 minutes before the map lands, so without a floor anyone could
		// move the pool first and the swap ran at whatever price was left.
		if len(instr) > 15 && instr[:15] == "min_amount_out=" {
			v := instr[15:]
			minAmountOut = &v
		}
	}

	if swapTo != "" && assetOut != "" {
		routerIdPtr := sdk.StateGetObject(constants.RouterContractIdKey)
		if routerIdPtr == nil || *routerIdPtr == "" {
			return dest
		}
		routerId := *routerIdPtr
		env := sdk.GetEnv()
		selfAddr := "contract:" + env.ContractId

		IncBalance(selfAddr, asset, amount)
		// MED-34 (M23-F18), ported to big.Int: grant the router allowance
		// ADDITIVELY rather than overwriting it, so a concurrent swap-routed
		// deposit's residual is not clobbered by a flat SetAllowance. Only THIS
		// call's contribution is removed on cleanup below. big.Int cannot
		// overflow, so no SafeAdd guard is needed.
		routerSpender := "contract:" + routerId
		prevAllowance := GetAllowance(selfAddr, routerSpender, asset)
		SetAllowance(selfAddr, routerSpender, asset, new(big.Int).Add(prevAllowance, amount))

		instrJSON, _ := json.Marshal(DexInstruction{
			Type:             "swap",
			Version:          "1.0.0",
			AssetIn:          asset,
			AmountIn:         amount.String(),
			AssetOut:         assetOut,
			Recipient:        swapTo,
			DestinationChain: destChain,
			MinAmountOut:     minAmountOut,
		})

		// A9 (RV re-verify): call the router with try/catch so a router that
		// ABORTS does not trap this deposit's whole `map` (pre-fix: an aborting
		// router reverted the entire deposit tx, the slot stayed unobserved, and
		// the depositor-signed L1 calldata could never be changed — the deposit
		// was permanently stuck). With Try, a router revert returns
		// {"ok":false,...} and its state is rolled back, so we can fall through
		// and credit the depositor in the original asset instead. (On a consensus
		// line where try/catch is not yet active the node ignores Try and the
		// legacy abort-propagates behaviour applies — no worse than before.)
		result := sdk.ContractCall(routerId, "execute", string(instrJSON), &sdk.ContractCallOptions{Try: true})
		// MED-34 (M23-F18): restore the allowance to the pre-grant snapshot
		// (prevAllowance) so exactly THIS call's additive grant is removed and
		// any concurrent routed deposit's residual survives. Magi WASM dispatch
		// is synchronous, so on SUCCESS the router already consumed `amount`
		// (slot == prevAllowance, so this is a no-op restore) and on FAILURE the
		// slot still reads prevAllowance+amount (this removes the grant; the
		// self-credit is reversed below).
		SetAllowance(selfAddr, routerSpender, asset, prevAllowance)

		if !tryCallSucceeded(result) {
			// Router call failed/reverted. Reverse the self-balance credit and
			// fall through to credit the depositor directly with the original asset.
			DecBalance(selfAddr, asset, amount)
			return dest
		}
		return ""
	}

	return dest
}

func isPaused() bool {
	data := sdk.StateGetObject(constants.PausedKey)
	return data != nil && *data == "1"
}

// tryCallSucceeded reports whether a try/catch ContractCall (A9) succeeded.
// With ContractCallOptions.Try the host returns a structured outcome
// {"ok":bool,"result":...,"error":...}; a nil return, an unparseable body, or
// "ok":false all mean the callee did not succeed. A plain (non-Try) call that
// aborts traps the caller and never returns here, so this is only reached with
// the structured body (or a genuine nil).
func tryCallSucceeded(result *string) bool {
	if result == nil {
		return false
	}
	// When try/catch is chain-active the host returns {"ok":bool,...}; branch on
	// it. When it is NOT active the node ignores Try and returns the callee's
	// RAW result on success (and traps on revert, so we never get here on
	// failure). So: an "ok" field present => use it; absent => any non-nil
	// result is a legacy success. Using a pointer distinguishes "ok":false from
	// a result that simply has no ok field.
	var outcome struct {
		Ok *bool `json:"ok"`
	}
	if err := json.Unmarshal([]byte(*result), &outcome); err != nil {
		return true // non-JSON raw success result (legacy, Try inactive)
	}
	if outcome.Ok != nil {
		return *outcome.Ok
	}
	return true
}

// E1 (RV re-verify): the ledger balance key is `a-{address}-{asset}` and the
// allowance key is `q-{owner}-{spender}-{asset}`. Because `asset` was free-form,
// a caller could pick an asset string that makes `a-{caller}-{asset}` collide
// with another account's key — e.g. caller `hive:milo`, asset `hpr-eth` aliases
// `a-hive:milo-hpr-eth`, the ETH balance of account `hive:milo-hpr`. Every
// balance/allowance-mutating user path must therefore reject any asset that is
// not the native "eth" or a token symbol this contract actually registered.
// RegisterToken writes the `as-{symbol}` marker so this check is O(1) and needs
// no symbol index. A fresh EVM deployment has no legacy balances to migrate.
func isAllowedAsset(asset string) bool {
	if asset == constants.NativeAsset {
		return true
	}
	if asset == "" {
		return false
	}
	marker := sdk.StateGetObject(constants.AllowedSymbolPrefix + asset)
	return marker != nil && *marker == "1"
}

func requireAllowedAsset(asset string) error {
	if !isAllowedAsset(asset) {
		return ce.NewContractError(ce.ErrInput, "unknown asset: must be 'eth' or a registered token symbol")
	}
	return nil
}

// getTokenInfo / RegisterToken — W4 Cluster B CRIT #6 Site 10: token
// registry now keyed by (chainId, addr) so the same ERC-20 address on
// different chains is a distinct registry entry. Pre-fix the registry
// was keyed only by addr, so a chainId pivot (or a deploy on a forked
// testnet) could silently inherit registrations.
func getTokenInfo(chainId uint64, addr [20]byte) *TokenInfo {
	key := constants.TokenRegistryPrefix + strconv.FormatUint(
		chainId,
		10,
	) + constants.DirPathDelimiter + hex.EncodeToString(
		addr[:],
	)
	data := sdk.StateGetObject(key)
	if data == nil {
		return nil
	}
	// Format: symbol|decimals|minWithdrawal
	fields := splitPipe(*data)
	if len(fields) < 2 {
		return nil
	}
	dec, _ := strconv.ParseUint(fields[1], 10, 8)
	info := &TokenInfo{Symbol: fields[0], Decimals: uint8(dec)}
	if len(fields) >= 3 {
		info.MinWithdrawal, _ = strconv.ParseInt(fields[2], 10, 64)
	}
	if info.MinWithdrawal <= 0 {
		info.MinWithdrawal = constants.MinUSDCWithdrawal
	}
	return info
}

// RegisterToken — W4 Cluster B CRIT #6 Site 10: store key now includes chainId.
func RegisterToken(chainId uint64, addr [20]byte, symbol string, decimals uint8, minWithdrawal int64) {
	key := constants.TokenRegistryPrefix + strconv.FormatUint(
		chainId,
		10,
	) + constants.DirPathDelimiter + hex.EncodeToString(
		addr[:],
	)
	sdk.StateSetObject(
		key,
		symbol+"|"+strconv.FormatUint(uint64(decimals), 10)+"|"+strconv.FormatInt(minWithdrawal, 10),
	)
	// E1 (RV re-verify): mark the symbol as an allowed ledger asset so
	// transfer/approve/unmapFrom can reject any other free-form asset string.
	sdk.StateSetObject(constants.AllowedSymbolPrefix+symbol, "1")
}

// checkAuth refuses a fund-moving call that the sender did not sign with active
// authority (A2). A posting signature also makes its signer the Caller, so
// without this a posting key (often held by front ends) could transfer, approve
// or unmap the account's funds. An L2 tx lists every DID that signed it in
// RequiredAuths, so a did:pkh signer passes. Mirrors checkAuth in the BTC
// mapping contract (mapping/utils.go).
// pricingHeader is the newest stored L1 header, for pricing a new withdrawal.
//
// LOW 10: it is refused when it is older than constants.MaxPricingHeaderAge
// against the L2 block time. A stalled verifier would otherwise price the
// withdrawal on an old base fee, and an underpriced withdrawal holds the single
// queue until an admin replaceWithdrawal. A block time the contract cannot read
// (the node always supplies one) skips the check.
func pricingHeader() (*blocklist.EthBlockHeader, error) {
	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return nil, ce.NewContractError(ce.ErrInitialization, "no block headers available")
	}
	if now, ok := blockTime(sdk.GetEnv().Timestamp); ok && now > header.Timestamp && now-header.Timestamp > constants.MaxPricingHeaderAge {
		return nil, ce.NewContractError(ce.ErrInitialization,
			"newest L1 header is "+strconv.FormatUint(now-header.Timestamp, 10)+"s old: withdrawals wait until the header feed catches up")
	}
	return header, nil
}

// blockTime parses the L2 block timestamp (Hive's "2006-01-02T15:04:05", UTC).
func blockTime(ts string) (uint64, bool) {
	for _, layout := range []string{"2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, ts); err == nil && t.Unix() > 0 {
			return uint64(t.Unix()), true
		}
	}
	return 0, false
}

// validIdentity reports whether addr is a Magi identity the runtime recognises
// (user, key, contract or system address), per the node's system.verify_address.
func validIdentity(addr string) bool {
	return sdk.VerifyAddress(addr) != string(sdk.AddressDomainUnknown)
}

func requireValidRecipient(to string) error {
	if !validIdentity(to) {
		return ce.NewContractError(ce.ErrInput, "invalid recipient address \""+to+"\"")
	}
	return nil
}

func requireValidSpender(spender string) error {
	if !validIdentity(spender) {
		return ce.NewContractError(ce.ErrInput, "invalid spender address \""+spender+"\"")
	}
	return nil
}

func checkAuth(env sdk.Env) error {
	if !slices.Contains(env.Sender.RequiredAuths, env.Sender.Address) {
		return ce.NewContractError(ce.ErrNoPermission, "active auth required to send funds")
	}
	return nil
}

// TssVaultAddress is the L1 address of the contract's "primary" TSS key: the
// vault.
//
// A18: the vault used to be an admin-set address (setVault) that nothing tied
// to the key the TSS group holds, and the bot only warned on a mismatch. An
// owner key, or a typo, could point deposits at an address the bridge cannot
// spend from. Now the bridge holds funds only at the key's own address. A
// deprecated key still owns its address, so deposits to it keep being credited;
// signing still needs the key active (requireTssKey). The address is cached per
// public key so the curve math runs once.
func TssVaultAddress() ([20]byte, bool) {
	parts := strings.Split(sdk.TssGetKey("primary"), ",")
	if len(parts) < 3 || (parts[0] != "active" && parts[0] != "deprecated") || parts[2] != "ecdsa" {
		return [20]byte{}, false
	}
	pubHex := strings.ToLower(strings.TrimPrefix(parts[1], "0x"))
	if c := sdk.StateGetObject(constants.VaultKeyCacheKey); c != nil {
		if i := strings.IndexByte(*c, '|'); i > 0 && (*c)[:i] == pubHex {
			if addr, err := crypto.HexToAddress((*c)[i+1:]); err == nil {
				return addr, true
			}
		}
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return [20]byte{}, false
	}
	addr, err := crypto.PubkeyAddress(pub)
	if err != nil {
		return [20]byte{}, false
	}
	sdk.StateSetObject(constants.VaultKeyCacheKey, pubHex+"|"+crypto.AddressToHex(addr))
	return addr, true
}

func requireTssKey() error {
	keyInfo := sdk.TssGetKey("primary")
	if keyInfo == "" || keyInfo == "fail" {
		return ce.NewContractError(ce.ErrAuth, "TSS key not available")
	}
	// A6 (RV re-verify): TssGetKey returns "status,pubkey,algo[,...]". Pre-fix we
	// only rejected ""/"fail", so a DEPRECATED (or "deleted") key passed: the
	// unmap debited the user and queued a pending spend, but the host then
	// refused to sign it and there is no cancel path for a never-signed spend —
	// funds stuck. Require the key be ACTIVE before committing any debit.
	status := keyInfo
	if i := strings.IndexByte(keyInfo, ','); i >= 0 {
		status = keyInfo[:i]
	}
	if status != "active" {
		return ce.NewContractError(ce.ErrAuth, "TSS key is not active (status: "+status+")")
	}
	return nil
}

func getGasReserve() *big.Int {
	data := sdk.StateGetObject(constants.GasReserveKey)
	if data == nil {
		return new(big.Int)
	}
	return parseAmount(*data)
}

func addGasReserve(amount *big.Int) {
	// big.Int/wei: the reserve accumulator is full wei and cannot overflow,
	// so the prior int64 clamp (EVM-C10) is no longer needed. This supersedes
	// review6 M8, whose SafeAdd64 guard only mattered for the int64 accumulator.
	current := getGasReserve()
	current.Add(current, amount)
	sdk.StateSetObject(constants.GasReserveKey, current.String())
}

func deductGasReserve(amount *big.Int) {
	// RV-6 (RV re-verify): abort on underflow instead of clamping to 0. The
	// pre-fix clamp hid an overdraw: TrackReserveSpend still debited the full
	// gas estimate from Active("eth"), so when the estimate exceeded the reserve
	// the gap came out of user-attributed ETH (Active < User) and the last ETH
	// holders could not withdraw. Callers now verify reserve >= gasCost BEFORE
	// signing, so reaching a negative here is a contract bug, not a user input.
	current := getGasReserve()
	if current.Cmp(amount) < 0 {
		sdk.Abort("gas reserve underflow on deductGasReserve: reserve " +
			current.String() + " < gas cost " + amount.String())
	}
	current.Sub(current, amount)
	sdk.StateSetObject(constants.GasReserveKey, current.String())
}

func HandleUnmapFrom(params *TransferParams, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	if HasPendingWithdrawal() {
		return ce.NewContractError(ce.ErrIntent, "withdrawal pending: wait for confirmation")
	}

	env := sdk.GetEnv()
	if err := checkAuth(env); err != nil {
		return err
	}
	caller := env.Caller.String()

	amount, ok := new(big.Int).SetString(params.Amount, 10)
	if !ok || amount.Sign() <= 0 {
		return ce.NewContractError(ce.ErrInput, "invalid amount")
	}
	if params.Asset == "eth" && amount.Cmp(big.NewInt(constants.MinETHWithdrawal)) < 0 {
		return ce.NewContractError(ce.ErrIntent, "below minimum ETH withdrawal")
	}

	if err := requireTssKey(); err != nil {
		return err
	}

	// Validate ALL inputs BEFORE any state mutations
	toAddr, err := crypto.HexToAddress(params.To)
	if err != nil {
		return ce.Prepend(err, "destination address")
	}
	// review2 #44: refuse the zero address (TSS-signed burn).
	// (Also review6 closure T2-14 / M70 — same finding, single guard suffices.)
	if toAddr == ([20]byte{}) {
		return ce.NewContractError(ce.ErrInput, "refusing withdrawal to zero address")
	}

	header, herr := pricingHeader()
	if herr != nil {
		return herr
	}

	// W4 Cluster C CRIT #7: compute gas pricing up front for BOTH paths so
	// the reserve floor check applies to ETH-path withdrawals (pre-fix the
	// floor check was only run on the ERC-20 path; the ETH path skipped it
	// entirely, drained the vault, and never deducted fees from the owner).
	gasTipCap := uint64(2_000_000_000)
	// review2 HIGH #16: checked cap (gasUnits=0 → just the gasFeeCap; the
	// per-path fees are computed with safeGasFee below). An extreme base fee
	// can't wrap uint64 into a tiny gasFeeCap and sign an under-priced tx.
	gasFeeCap, _, capErr := safeGasFee(0, header.BaseFeePerGas, 2, gasTipCap)
	if capErr != nil {
		return ce.NewContractError(ce.ErrArithmetic, "gas fee computation overflow")
	}

	var tokenAddr [20]byte
	if params.Asset != "eth" {
		if params.TokenAddress == "" {
			return ce.NewContractError(ce.ErrInput, "token_address required")
		}
		tokenAddr, err = crypto.HexToAddress(params.TokenAddress)
		if err != nil {
			return ce.Prepend(err, "token_address")
		}
		// W4 Cluster B CRIT #6 Site 10: token registry keyed by (chainId, addr).
		tokenInfo := getTokenInfo(chainId, tokenAddr)
		if tokenInfo == nil {
			return ErrInvalidToken
		}
		// RV-1 (RV re-verify): bind the DEBITED asset to the WITHDRAWN token.
		// Pre-fix this path debited params.Asset (free-form) but signed a
		// transfer of params.TokenAddress, so a caller with allowance on a cheap
		// asset could drain an expensive token. unmapERC20 already keys off
		// tokenInfo.Symbol; make unmapFrom match. (Also closes E1 on this path:
		// params.Asset is now forced to the registered symbol.)
		if params.Asset != tokenInfo.Symbol {
			return ce.NewContractError(ce.ErrInput, "asset does not match the token's registered symbol")
		}
		if amount.Cmp(big.NewInt(tokenInfo.MinWithdrawal)) < 0 {
			return ce.NewContractError(ce.ErrIntent, "below minimum withdrawal for this token")
		}
		if getGasReserve().Cmp(big.NewInt(constants.MinGasReserve)) < 0 {
			return ce.NewContractError(ce.ErrBalance, "insufficient gas reserve for ERC-20 withdrawal")
		}
	} else {
		// W4 Cluster C CRIT #7: ETH path now also enforces the gas reserve
		// floor + debits (amount + fee) from the owner.
		if getGasReserve().Cmp(big.NewInt(constants.MinGasReserve)) < 0 {
			return ce.NewContractError(ce.ErrTransaction, "insufficient gas reserve")
		}
	}

	// Cheap precondition; the binding check happens against the FULL debit
	// (amount + fee) once the fee is known, below — matching the BTC
	// mapping contract, where the allowance must cover finalAmt incl. fees
	// (utxo-mapping checkAndDeductBalance). Without that, a spender could
	// spend `fee` beyond what the owner authorized.
	allowance := GetAllowance(params.From, caller, params.Asset)
	if allowance.Cmp(amount) < 0 {
		return ce.NewContractError(ce.ErrBalance, "insufficient allowance")
	}

	// W4 Cluster C CRIT #7 (ETH path) — compute the gas fee and debit
	// (amount + fee) instead of just amount. Pre-fix, the ETH path
	// computed no fee and the vault absorbed the L1 mining cost on every
	// withdrawal. big.Int/wei: amount and fee are both full wei.
	//
	// Same uniform shape as HandleUnmapETH: userDebit == l1Value + ethFee,
	// with fee-on-top vs fee-netted (DeductFee) choosing where the fee sits.
	userDebit := new(big.Int).Set(amount)
	l1Value := new(big.Int).Set(amount)
	ethFee := new(big.Int)
	if params.Asset == "eth" {
		_, feeWei, feeErr := safeGasFee(constants.ETHTransferGas, header.BaseFeePerGas, 2, gasTipCap)
		if feeErr != nil {
			return ce.NewContractError(ce.ErrArithmetic, "gas fee computation overflow")
		}
		if params.MaxFee != "" {
			maxFee, mok := new(big.Int).SetString(params.MaxFee, 10)
			if !mok {
				return ce.NewContractError(ce.ErrInput, "invalid max_fee")
			}
			if maxFee.Sign() < 0 {
				return ce.NewContractError(ce.ErrInput, "max_fee must be non-negative")
			}
			if feeWei.Cmp(maxFee) > 0 {
				return ce.NewContractError(ce.ErrTransaction, "fee exceeds max_fee")
			}
		}
		if params.DeductFee {
			l1Value.Sub(l1Value, feeWei)
			if l1Value.Sign() <= 0 {
				return ce.NewContractError(ce.ErrIntent, "amount does not cover the L1 fee")
			}
		} else {
			userDebit.Add(amount, feeWei)
		}
		ethFee = feeWei
		if GetBalance(params.From, "eth").Cmp(userDebit) < 0 {
			return ce.NewContractError(ce.ErrTransaction, "insufficient balance in owner account")
		}
	}

	// Binding allowance check: the spender's authorization must cover the
	// FULL owner debit (value + fee), same as the BTC baseline.
	if allowance.Cmp(userDebit) < 0 {
		return ce.NewContractError(ce.ErrBalance, "insufficient allowance for amount plus fee")
	}

	// All validation passed — now mutate state
	if !DecBalance(params.From, params.Asset, userDebit) {
		return ce.NewContractError(ce.ErrBalance, "insufficient balance in owner account")
	}
	SetAllowance(params.From, caller, params.Asset, new(big.Int).Sub(allowance, userDebit))
	// Custody + user attribution shrink by the full debit (ETH: value + fee;
	// ERC-20: bare amount — its gas comes from the reserve below).
	TrackWithdrawal(params.Asset, userDebit)

	nonce := GetPendingNonce()

	var unsigned []byte
	var asset string
	var tokenAddress string
	pendingGasCost := ethFee
	if params.Asset == "eth" {
		unsigned = BuildETHWithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, toAddr, l1Value)
		asset = "eth"
	} else {
		// ERC-20: token-native units.
		unsigned = BuildERC20WithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, tokenAddr, toAddr, amount)
		asset = params.Asset
		tokenAddress = params.TokenAddress
		// review2 HIGH #16: checked gas cost in full wei for the reserve.
		_, gasReserveFee, feeErr := safeGasFee(constants.ERC20TransferGas, header.BaseFeePerGas, 2, gasTipCap)
		if feeErr != nil {
			return ce.NewContractError(ce.ErrArithmetic, "gas fee computation overflow")
		}
		// RV-6 (RV re-verify): require the reserve to actually cover this gas
		// before spending it (the MinGasReserve floor is not enough at a high
		// base fee; see unmapERC20). Prevents the reserve clamp from silently
		// under-collateralizing ETH custody.
		if getGasReserve().Cmp(gasReserveFee) < 0 {
			return ce.NewContractError(ce.ErrBalance, "gas reserve cannot cover this withdrawal's L1 gas at the current base fee")
		}
		// Reserve is ETH custody — book the spend against Active("eth");
		// restored via TrackReserveRestore if the tx is proven dropped.
		deductGasReserve(gasReserveFee)
		TrackReserveSpend(gasReserveFee)
		pendingGasCost = gasReserveFee
	}

	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// W4 Cluster F D-F-3: snapshot vault for HandleUnmapFrom path.
	StorePendingSpend(PendingSpend{
		Nonce:         nonce,
		Amount:        l1Value, // ETH: L1 tx value (== amount for ERC-20)
		From:          params.From,
		To:            params.To,
		Asset:         asset,
		TokenAddress:  tokenAddress,
		UnsignedTxHex: hex.EncodeToString(unsigned),
		BlockHeight:   blocklist.GetLastHeight(),
		VaultAtQueue:  "0x" + hex.EncodeToString(vaultAddress[:]),
		GasCost:       pendingGasCost, // prepaid fee (ETH) / reserve charge (ERC-20); restored on proven drop
	})
	SetPendingNonce(nonce + 1)
	return nil
}

func HandleIncreaseAllowance(params *AllowanceParams) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	env := sdk.GetEnv()
	if err := checkAuth(env); err != nil {
		return err
	}
	caller := env.Caller.String()

	amount, ok := new(big.Int).SetString(params.Amount, 10)
	if !ok || amount.Sign() <= 0 {
		return ce.NewContractError(ce.ErrInput, "invalid amount")
	}

	// E1 (RV re-verify): reject free-form assets that would inject ledger keys.
	if err := requireAllowedAsset(params.Asset); err != nil {
		return err
	}
	// ALLOW-1: the spender must be a Magi identity (see constants.AllowanceDelimiter).
	if err := requireValidSpender(params.Spender); err != nil {
		return err
	}

	current := GetAllowance(caller, params.Spender, params.Asset)
	SetAllowance(caller, params.Spender, params.Asset, new(big.Int).Add(current, amount))
	return nil
}

func HandleDecreaseAllowance(params *AllowanceParams) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	env := sdk.GetEnv()
	if err := checkAuth(env); err != nil {
		return err
	}
	caller := env.Caller.String()

	amount, ok := new(big.Int).SetString(params.Amount, 10)
	if !ok || amount.Sign() <= 0 {
		return ce.NewContractError(ce.ErrInput, "invalid amount")
	}

	// E1 (RV re-verify): reject free-form assets that would inject ledger keys.
	if err := requireAllowedAsset(params.Asset); err != nil {
		return err
	}
	// ALLOW-1: the spender must be a Magi identity (see constants.AllowanceDelimiter).
	if err := requireValidSpender(params.Spender); err != nil {
		return err
	}

	current := GetAllowance(caller, params.Spender, params.Asset)
	newVal := new(big.Int).Sub(current, amount)
	if newVal.Sign() < 0 {
		newVal.SetInt64(0)
	}
	SetAllowance(caller, params.Spender, params.Asset, newVal)
	return nil
}

// HandleReplaceWithdrawal — W4 Cluster E CRIT #27 + HIGH #26:
//   - now returns error (was void with mid-flow sdk.Revert pre-fix);
//   - assertNotPaused gate (CRIT #27 pause-guard gap closure);
//   - HexToAddress error propagated instead of silent 0x0 (HIGH #26).
func HandleReplaceWithdrawal(vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	rwEnv := sdk.GetEnv()
	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return ce.NewContractError(ce.ErrIntent, "no pending withdrawal to replace", "replaceWithdrawal")
	}
	if ps.Rolled {
		return ce.NewContractError(ce.ErrIntent, "the withdrawal is being rolled back (rollWithdrawal)", "replaceWithdrawal")
	}

	// MED-33 (M23-F16): rate-limit replaceWithdrawal so it cannot spam
	// unbounded TSS signing requests. Each call invokes sdk.TssSignKey; the
	// propose/execute timelock only governs the first hop, so once a proposal
	// is executable nothing stopped re-running it every block to burn TSS
	// resources. Reject if fewer than ReplaceWithdrawalCooldown blocks have
	// elapsed since the last replace. The cooldown is recorded only after the
	// signing succeeds (below), so a reverted attempt does not start the clock.
	//
	// round3 C-SM3: the cooldown is keyed PER confirmed-head nonce
	// ("rwlast-{confirmedNonce}") so it cannot bleed across distinct withdrawal
	// lifecycles. Each new withdrawal (a higher confirmedNonce) reads a fresh
	// empty key, so its FIRST fee-bump is never blocked by an unrelated prior
	// withdrawal's replace clock. No reset bookkeeping is needed.
	cooldownKey := constants.ReplaceWithdrawalLastKey + strconv.FormatUint(confirmedNonce, 10)
	if last := sdk.StateGetObject(cooldownKey); last != nil {
		lastH, _ := strconv.ParseUint(*last, 10, 64)
		if rwEnv.BlockHeight < lastH+constants.ReplaceWithdrawalCooldown {
			return errors.New("replaceWithdrawal: cooldown not elapsed since last replace")
		}
	}

	// Rebuild with 2x gas
	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return ce.NewContractError(ce.ErrInitialization, "no headers", "replaceWithdrawal")
	}

	// review6 L1/X3 (adversarial-review correction): HandleReplaceWithdrawal
	// was the 5th gas-fee site the audit's "four sites" missed. Route the
	// (3x baseFee + tip) calculation through the same overflow-checked
	// helper used in HandleUnmapETH / HandleUnmapERC20 / HandleUnmapFrom.
	// Dormant after H2 closed the oracle-fed-header surface, but the
	// arithmetic should still be bounded for defense-in-depth.
	gasTipCap := uint64(4_000_000_000) // doubled
	// review2 HIGH #16: replaceWithdrawal re-prices at 3x base fee. Route the
	// cap through the checked helper so an extreme base fee can't wrap uint64
	// into a tiny gasFeeCap and sign an under-priced replacement. gasUnits=0:
	// no fee is charged here — the reserve was deducted at the original unmap.
	gasFeeCap, _, feeErr := safeGasFee(0, header.BaseFeePerGas, 3, gasTipCap)
	if feeErr != nil {
		return ce.NewContractError(ce.ErrArithmetic, "gas fee cap overflow", "replaceWithdrawal")
	}

	// HIGH #26: surface destination-address parse errors instead of silently
	// signing a tx to the zero address.
	toAddr, herr := crypto.HexToAddress(ps.To)
	if herr != nil {
		return errors.New("pending spend destination parse failed: " + herr.Error())
	}

	var unsigned []byte
	if ps.Asset == "eth" {
		// big.Int/wei: ps.Amount is already wei.
		unsigned = BuildETHWithdrawalTx(chainId, confirmedNonce, gasTipCap, gasFeeCap, toAddr, ps.Amount)
	} else {
		tokenAddr, terr := crypto.HexToAddress(ps.TokenAddress)
		if terr != nil {
			return errors.New("pending spend token address parse failed: " + terr.Error())
		}
		unsigned = BuildERC20WithdrawalTx(chainId, confirmedNonce, gasTipCap, gasFeeCap, tokenAddr, toAddr, ps.Amount)
	}

	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// MED-33 (M23-F16): record the block of this successful replace so the
	// cooldown gate above can rate-limit the next one. round3 C-SM3: written
	// under the per-nonce key so the clock is scoped to THIS withdrawal.
	sdk.StateSetObject(cooldownKey, strconv.FormatUint(rwEnv.BlockHeight, 10))
	// Update pending spend with new signed TX
	ps.UnsignedTxHex = hex.EncodeToString(unsigned)
	StorePendingSpend(*ps)
	return nil
}

// HandleClearNonce — W4 Cluster E CRIT #27 (B-E-4 + S-E-v17-2):
//   - takes an L1ProofOfDrop so the proof field is reachable from the
//     propose/execute payload (pre-fix the wasmexport ignored its
//     input entirely with `_ *string`);
//   - assertNotPaused gate (CRIT #27);
//   - returns error instead of mid-flow sdk.Revert.
//
// refundDroppedWithdrawal makes the withdrawer whole for a PendingSpend
// whose L1 tx has been PROVEN dropped (verifyL1ProofOfDrop passed): the tx
// never executed, so NOTHING left custody. Shared by all three escape
// hatches (clearNonce / expireWithdrawal / cancelMyWithdrawal).
//
//   - ETH: the user paid ps.Amount + ps.GasCost (L1 value + prepaid fee) at
//     unmap — refund both, and restore Active/User by the same total.
//   - ERC-20: the user paid ps.Amount in tokens (refund + restore token
//     supply) and the gas reserve was charged ps.GasCost — the miner was
//     never paid, so restore the reserve and its Active("eth") booking.
//
// Contrast with HandleConfirmSpend's reverted-receipt branch, where the tx
// mined and the gas WAS paid: there only ps.Amount comes back.
// big.Int/wei: IncBalance and the supply adds cannot overflow, so the
// refund cannot fail and "state advanced => user was refunded" holds
// unconditionally (review6 X2's hard-fail guard is unnecessary here).
func refundDroppedWithdrawal(ps *PendingSpend) {
	// E9 (RV re-verify): refund the tx VALUE only, NOT the gas.
	//
	// Every path that reaches here (clearNonce / cancelMyWithdrawal /
	// expireWithdrawal) first passes verifyL1ProofOfDrop, and the only proof
	// type that verifier still accepts is Type-A (reverted_receipt): the tx
	// MINED and reverted, so the L1 gas was genuinely paid to the miner and that
	// custody is gone — exactly like HandleConfirmSpend's reverted-receipt
	// branch, which also returns value only. The pre-fix code added ps.GasCost
	// back to the user (ETH path) and restored the gas reserve (ERC-20 path),
	// refunding gas the vault had already spent — a slow drain a withdrawer
	// could farm by repeatedly submitting reverting withdrawals. Only a
	// genuinely-never-mined proof (Type-B, currently DISABLED/LOCKED per D-E-4)
	// would justify refunding gas; if it is ever re-enabled it must restore the
	// gas/reserve on its own path, not here.
	refund := new(big.Int).Set(ps.Amount)
	IncBalance(ps.From, ps.Asset, refund)
	sup := GetSupply(ps.Asset)
	sup.Active.Add(sup.Active, refund)
	sup.User.Add(sup.User, refund)
	SetSupply(ps.Asset, sup)
}

func HandleClearNonce(vaultAddress [20]byte, chainId uint64, proof L1ProofOfDrop) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrInitialization, "contract is paused")
	}
	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return ce.NewContractError(ce.ErrTransaction, "no pending nonce to clear", "clearNonce")
	}
	// L1-proof-of-drop gate: clearNonce previously had no proof anchor at
	// all. Verify the proof binds the cleared nonce to a reverted-receipt
	// or block-inclusion-without-tx event on L1.
	if err := verifyL1ProofOfDrop(&proof, ps, chainId); err != nil {
		return ce.WrapContractError(ce.ErrTransaction, err, "L1ProofOfDrop verify failed")
	}

	// Build 0-value self-transfer to advance nonce
	unsigned := BuildETHWithdrawalTx(
		chainId,
		confirmedNonce,
		4_000_000_000,
		100_000_000_000,
		vaultAddress,
		big.NewInt(0),
	)
	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// Proven-dropped refund: full make-whole (value + prepaid fee / reserve).
	// big.Int refundDroppedWithdrawal cannot overflow, so it subsumes 30710e4's
	// int64 X2 hard-fail guards; it also refunds the prepaid fee/reserve, which
	// the int64 value-only refund did not.
	refundDroppedWithdrawal(ps)
	// bug #8: NonceAdvance re-reads the PendingSpend and no-ops once it's
	// deleted, so advance BEFORE DeletePendingSpend (race-safe vs HandleExpireWithdrawal).
	NonceAdvance(ps, 1)
	SetPendingNonce(GetConfirmedNonce())
	DeletePendingSpend(confirmedNonce)
	sdk.Log(
		"withdrawal_lifecycle " + `{"action":"clearNonce","nonce":` + strconv.FormatUint(
			confirmedNonce,
			10,
		) + `,"from":"` + ps.From + `","proof_type":"` + proof.Type + `"}`,
	)
	return nil
}

// HandleExpireWithdrawal — W4 Cluster E CRIT #26 (D-E-3). Permissionless after
// ps.BlockHeight + WithdrawalExpiryWindow. Pre-window callers MUST supply a
// proof; post-window opportunistic proof acceptable. Same NonceAdvance CAS.
func HandleExpireWithdrawal(nonce uint64, proof L1ProofOfDrop, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	// F3a (restore review5): only the confirmed-head nonce is expirable. With
	// the single-outstanding-withdrawal invariant (HasPendingWithdrawal gates
	// new unmaps), the head is the only live PendingSpend; rejecting non-head
	// nonces prevents deleting a non-head entry without advancing the head.
	confirmedNonce := GetConfirmedNonce()
	if nonce != confirmedNonce {
		return errors.New("expireWithdrawal: target nonce is not the confirmed-nonce head")
	}
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return errors.New("no pending spend at nonce")
	}
	if ps.VaultAtQueue == "" || ps.VaultAtQueue == "0x0000000000000000000000000000000000000000" {
		return errors.New("legacy PendingSpend entry — clear via admin clearNonce/state procedure")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()
	isOriginalWithdrawer := crypto.SameIdentity(caller, ps.From)
	expiryHeight := ps.BlockHeight + constants.WithdrawalExpiryWindow
	hasExpired := blocklist.GetLastHeight() >= expiryHeight

	// Pre-window: only the original withdrawer may early-cancel. Post-window:
	// anyone may expire (the window is the gate for WHO).
	if !hasExpired && !isOriginalWithdrawer {
		return errors.New("expireWithdrawal: window not elapsed and caller is not original withdrawer")
	}

	// F3b: an L1-proof-of-drop is MANDATORY in ALL cases — a refund is only
	// issued against cryptographic proof that the L1 withdrawal did NOT send
	// funds (type A: reverted receipt; type B: the nonce slot was consumed by
	// a different tx). Previously the post-window path skipped the proof
	// entirely, so a withdrawal that SUCCEEDED on L1 but whose confirmSpend
	// lagged could be refunded on L2 (double-spend). The window governs only
	// WHO may call, never WHETHER proof is required.
	//
	// A genuinely-stuck/never-broadcast withdrawal (vault nonce never
	// advanced) cannot produce a type-A/B proof and therefore cannot be
	// expired here; rollWithdrawal (D3) is its escape: it consumes slot N with
	// a 0-value self-transfer and refunds only once that has mined. A naive
	// "nonce-not-advanced" account proof is NOT safe: an in-flight tx can mine
	// after any proof block, reopening the double-spend.
	if proof.Type == "" {
		return errors.New("expireWithdrawal: L1-proof-of-drop is mandatory (proves the L1 tx did not execute)")
	}
	if err := verifyL1ProofOfDrop(&proof, ps, chainId); err != nil {
		return errors.New("L1ProofOfDrop verify failed: " + err.Error())
	}

	// Proven-dropped refund: full make-whole (value + prepaid fee / reserve).
	// big.Int refundDroppedWithdrawal cannot overflow (subsumes 30710e4's int64
	// X2 guards) and also refunds the prepaid fee/reserve.
	refundDroppedWithdrawal(ps)
	// bug #8: advance BEFORE delete (NonceAdvance no-ops once PendingSpend gone).
	NonceAdvance(ps, 1)
	SetPendingNonce(GetConfirmedNonce())
	DeletePendingSpend(nonce)
	sdk.Log(
		"withdrawal_lifecycle " + `{"action":"expireWithdrawal","nonce":` + strconv.FormatUint(
			nonce,
			10,
		) + `,"from":"` + ps.From + `","caller":"` + caller + `","proof_type":"` + proof.Type + `"}`,
	)
	return nil
}

// HandleCancelMyWithdrawal — W4 Cluster E CRIT #26 companion. Only ps.From
// can call; proof MANDATORY.
func HandleCancelMyWithdrawal(nonce uint64, proof L1ProofOfDrop, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	// SM-4 (round4, defense-in-depth): require nonce == confirmed-head, matching
	// the guard in HandleExpireWithdrawal (~:1316-1318). With the
	// single-outstanding-withdrawal invariant (HasPendingWithdrawal gates new
	// unmaps), the confirmed nonce is always the only live PendingSpend, so
	// this is a no-op in normal flow. It closes the parity gap: without it a
	// non-head nonce lookup would silently find nil (GetPendingSpend returns nil)
	// and return "no pending spend" rather than a clear "wrong nonce" error —
	// leaving future code that relaxes the invariant unprotected. Hard-fail
	// keeps the semantics explicit and auditable.
	confirmedNonce := GetConfirmedNonce()
	if nonce != confirmedNonce {
		return errors.New("cancelMyWithdrawal: target nonce is not the confirmed-nonce head")
	}
	ps := GetPendingSpend(nonce)
	if ps == nil {
		return errors.New("no pending spend at nonce")
	}
	env := sdk.GetEnv()
	if !crypto.SameIdentity(env.Caller.String(), ps.From) {
		return errors.New("cancelMyWithdrawal: only the original withdrawer can cancel")
	}
	if proof.Type == "" {
		return errors.New("cancelMyWithdrawal: proof MANDATORY")
	}
	if err := verifyL1ProofOfDrop(&proof, ps, chainId); err != nil {
		return errors.New("L1ProofOfDrop verify failed: " + err.Error())
	}
	// TSS-sign self-transfer to roll the L1 vault nonce.
	unsigned := BuildETHWithdrawalTx(chainId, nonce, 4_000_000_000, 100_000_000_000, vaultAddress, big.NewInt(0))
	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// Proven-dropped refund: full make-whole (value + prepaid fee / reserve).
	// big.Int refundDroppedWithdrawal cannot overflow (subsumes 30710e4's int64
	// X2 guards) and also refunds the prepaid fee/reserve.
	refundDroppedWithdrawal(ps)
	// bug #8: advance BEFORE delete (NonceAdvance no-ops once PendingSpend gone).
	NonceAdvance(ps, 1)
	SetPendingNonce(GetConfirmedNonce())
	DeletePendingSpend(nonce)
	sdk.Log(
		"withdrawal_lifecycle " + `{"action":"cancelMyWithdrawal","nonce":` + strconv.FormatUint(
			nonce,
			10,
		) + `,"from":"` + ps.From + `","proof_type":"` + proof.Type + `"}`,
	)
	return nil
}

// HandleRollWithdrawal is the escape for a withdrawal that never mines (D3):
// TSS never signed it, nobody broadcast it, or it is priced out. The queue has
// one head, so such a withdrawal used to block every later one: the other
// escapes all need a Type-A proof, i.e. the withdrawal mined and reverted.
//
// Once the verified L1 chain is WithdrawalRollWindow blocks past the block the
// withdrawal was queued at, anyone may roll it: the TSS key signs a 0-value
// self-transfer from the vault at the withdrawal's nonce, which becomes the
// tx the bot broadcasts. Only one tx can mine at that nonce. If the withdrawal
// mines, confirmSpend settles it as usual; if the roll mines, confirmSpend
// refunds the value to the withdrawer. Nothing is refunded before an L1 proof
// of which one mined, so the roll cannot double-spend. Like replaceWithdrawal
// it can be repeated after ReplaceWithdrawalCooldown, to re-price the roll.
func HandleRollWithdrawal(nonce uint64, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return ce.NewContractError(ce.ErrIntent, "contract is paused")
	}
	confirmedNonce := GetConfirmedNonce()
	if nonce != confirmedNonce {
		return errors.New("rollWithdrawal: target nonce is not the confirmed-nonce head")
	}
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return errors.New("no pending spend at nonce")
	}
	snapshottedVault, err := crypto.HexToAddress(ps.VaultAtQueue)
	if err != nil || snapshottedVault == ([20]byte{}) {
		return errors.New("legacy PendingSpend entry — clear via admin clearNonce/state procedure")
	}
	// The roll must come from the address the withdrawal would spend from.
	if vaultAddress != snapshottedVault {
		return errors.New("rollWithdrawal: the TSS key no longer holds the vault this withdrawal was queued from")
	}
	if err := requireTssKey(); err != nil {
		return err
	}
	if last := blocklist.GetLastHeight(); last < ps.BlockHeight+constants.WithdrawalRollWindow {
		return errors.New("rollWithdrawal: the withdrawal was queued at L1 block " + strconv.FormatUint(ps.BlockHeight, 10) +
			"; it can be rolled from L1 block " + strconv.FormatUint(ps.BlockHeight+constants.WithdrawalRollWindow, 10))
	}
	env := sdk.GetEnv()
	cooldownKey := constants.ReplaceWithdrawalLastKey + strconv.FormatUint(confirmedNonce, 10)
	if last := sdk.StateGetObject(cooldownKey); last != nil {
		lastH, _ := strconv.ParseUint(*last, 10, 64)
		if env.BlockHeight < lastH+constants.ReplaceWithdrawalCooldown {
			return errors.New("rollWithdrawal: cooldown not elapsed since the last re-sign")
		}
	}
	header, err := pricingHeader()
	if err != nil {
		return err
	}
	gasTipCap := uint64(4_000_000_000)
	gasFeeCap, _, feeErr := safeGasFee(0, header.BaseFeePerGas, 3, gasTipCap)
	if feeErr != nil {
		return ce.NewContractError(ce.ErrArithmetic, "gas fee cap overflow", "rollWithdrawal")
	}
	unsigned := BuildETHWithdrawalTx(chainId, confirmedNonce, gasTipCap, gasFeeCap, snapshottedVault, big.NewInt(0))
	sdk.TssSignKey("primary", ComputeSighash(unsigned))
	sdk.StateSetObject(cooldownKey, strconv.FormatUint(env.BlockHeight, 10))
	ps.Rolled = true
	ps.UnsignedTxHex = hex.EncodeToString(unsigned)
	StorePendingSpend(*ps)
	sdk.Log("withdrawal_lifecycle " + `{"action":"rollWithdrawal","nonce":` + strconv.FormatUint(confirmedNonce, 10) +
		`,"from":"` + ps.From + `","caller":"` + env.Caller.String() + `"}`)
	return nil
}

// HandleClearTestnetState — W4 Cluster E D-E-8 (chain-gated to testnet via
// is_testnet state-key sentinel; mainnet redirects unset / != "true" reject).
func HandleClearTestnetState() error {
	isTestnet := sdk.StateGetObject(constants.IsTestnetKey)
	if isTestnet == nil || *isTestnet != "true" {
		return errors.New("clearTestnetState: not a testnet contract")
	}
	// Clear pending spends, nonces, and observed-list within MaxBlockRetention*2.
	confirmed := GetConfirmedNonce()
	pending := GetPendingNonce()
	for n := confirmed; n <= pending; n++ {
		DeletePendingSpend(n)
	}
	sdk.StateDeleteObject(constants.NonceConfirmedKey)
	sdk.StateDeleteObject(constants.NoncePendingKey)
	// Observed-list cleanup window.
	lastH := blocklist.GetLastHeight()
	startH := uint64(0)
	if lastH > uint64(constants.MaxBlockRetention*2) {
		startH = lastH - uint64(constants.MaxBlockRetention*2)
	}
	for h := startH; h <= lastH; h++ {
		// M21-22: observed entries are now per-entry keys + a cleanup manifest,
		// not a single o-{height} blob; ClearObservedBlock deletes all of them.
		ClearObservedBlock(h)
	}
	sdk.Log(
		"clearTestnetState_executed " + `{"action":"clearTestnetState","block_height":` + strconv.FormatUint(
			lastH,
			10,
		) + `}`,
	)
	return nil
}

// verifyL1ProofOfDrop — W4 Cluster E D-E-4 LOCKED. Type A: receipt-trie MPT
// proof + status==0 + tx-trie bind + vault-sender ecrecover (sound). Type B
// (block_inclusion_without_tx) is DISABLED as of round3 H-SM2: its premise
// ("vault advanced past TxNonce ⇒ original tx dropped") is unsound (a SUCCEEDED
// withdrawal also advances the nonce) → double-spend. It runs the H-SM1
// vault-binding then unconditionally rejects; re-enabling requires a sound
// redefinition + team review (LOCKED D-E-4). Both: blocklist.GetHeader forces
// block to be ZK-anchored; proof.TxNonce == ps.Nonce.
func verifyL1ProofOfDrop(proof *L1ProofOfDrop, ps *PendingSpend, chainId uint64) error {
	if proof == nil || ps == nil {
		return errors.New("nil proof or pending spend")
	}
	if proof.TxNonce != ps.Nonce {
		return errors.New("proof tx_nonce does not match pending spend nonce")
	}
	header := blocklist.GetHeader(proof.BlockHeight)
	if header == nil {
		return errors.New("proof block not anchored")
	}
	switch proof.Type {
	case L1ProofTypeRevertedReceipt:
		// review6 H10: Type A now requires BOTH (a) a receipt-trie proof
		// showing status=0 at TxIndex AND (b) a tx-trie proof showing the
		// raw tx at the same TxIndex with parsed.Nonce == proof.TxNonce
		// AND parsed.From == ps.VaultAtQueue. Pre-fix, only (a) was checked
		// and proof.TxNonce was a user-supplied claim unbound to the proven
		// receipt — an attacker could prove ANY reverted receipt and claim
		// ANY nonce, double-spending withdrawals on every proof-required
		// path (clearNonce, cancelMyWithdrawal, pre-window expireWithdrawal).
		// Now the tx-trie proof cryptographically binds the nonce + sender
		// to the proven L1 slot, closing the forgery class.
		// EVM-T1: base64 proofs; the receipt and the tx are the proven leaves.
		proofBytes, err := base64.StdEncoding.DecodeString(proof.ReceiptProof)
		if err != nil {
			return errors.New("receipt_proof is not base64")
		}
		receiptBytes, err := mpt.VerifyProof(
			header.ReceiptsRoot,
			mpt.RLPEncodeKey(proof.TxIndex),
			splitProofNodes(proofBytes),
		)
		if err != nil {
			return errors.New("receipt proof verification failed")
		}
		// Parse status: receipt RLP first field after type-byte strip is status.
		data := receiptBytes
		if len(data) > 0 && data[0] <= 0x7f {
			data = data[1:]
		}
		items, err := rlp.DecodeList(data)
		if err != nil || len(items) < 1 {
			return errors.New("malformed receipt")
		}
		if items[0].AsUint64() != 0 {
			return errors.New("receipt status != 0 — tx not reverted")
		}
		// review6 H10: bind the proven receipt to the L1 tx via the
		// transactions trie at the SAME TxIndex. The raw tx carries the
		// nonce + sender; verifying it lets us reject forged proofs where
		// proof.TxNonce is decoupled from the proven L1 slot.
		txProofBytes, err := base64.StdEncoding.DecodeString(proof.TxProof)
		if err != nil || len(txProofBytes) == 0 {
			return errors.New("Type A requires tx_proof (base64) for nonce binding")
		}
		txBytes, err := mpt.VerifyProof(header.TransactionsRoot, mpt.RLPEncodeKey(proof.TxIndex), splitProofNodes(txProofBytes))
		if err != nil {
			return errors.New("tx proof verification failed")
		}
		parsed, err := parseTransaction(txBytes)
		if err != nil {
			return errors.New("failed to parse proven tx: " + err.Error())
		}
		if chainId != 0 && parsed.ChainId != chainId {
			return errors.New("proof tx chain id mismatch")
		}
		if parsed.Nonce != proof.TxNonce {
			return errors.New("proven tx nonce does not match proof.tx_nonce — bind failed")
		}
		// Verify the proven tx originated from the snapshotted vault. Without
		// this, an attacker could prove a reverted receipt + a tx from any
		// OTHER address that happened to share TxIndex in some block — the
		// nonce would match by coincidence and the bind would silently pass.
		expectedVault := strings.ToLower(ps.VaultAtQueue)
		if !strings.HasPrefix(expectedVault, "0x") {
			expectedVault = "0x" + expectedVault
		}
		// DS-F1 (round4): switch to EcrecoverStrict (reject high-S) here and
		// at the Type-B mirror below. The vault binding does NOT dedup by sig
		// bytes, so a malleable-S replay could forge a second valid sender
		// binding from the same sig. Strict is the correct policy on every
		// withdrawal-proof surface; any genuinely-mined low-S tx passes
		// unchanged.
		sighash := computeTxSighash(txBytes, parsed)
		recoveryV := byte(27 + parsed.V)
		rPadded := padTo32(parsed.R)
		sPadded := padTo32(parsed.S)
		sender, err := crypto.EcrecoverStrict(sighash, recoveryV, rPadded, sPadded)
		if err != nil {
			return errors.New("ecrecover on proven tx failed: " + err.Error())
		}
		senderHex := "0x" + hex.EncodeToString(sender[:])
		if !strings.EqualFold(senderHex, expectedVault) {
			return errors.New("proven tx sender does not match vault-at-queue — wrong-vault proof")
		}
		return nil
	case L1ProofTypeBlockInclusion:
		txBytes, err := hex.DecodeString(proof.TxAtIndexHex)
		if err != nil {
			return errors.New("invalid tx_at_index_hex")
		}
		proofBytes, err := hex.DecodeString(proof.TxProofHex)
		if err != nil {
			return errors.New("invalid tx_proof_hex")
		}
		proven, err := mpt.VerifyProof(
			header.TransactionsRoot,
			mpt.RLPEncodeKey(proof.TxIndex),
			splitProofNodes(proofBytes),
		)
		if err != nil {
			return errors.New("tx proof verification failed")
		}
		if !bytesEqual(proven, txBytes) {
			return errors.New("tx does not match proof")
		}
		parsed, err := parseTransaction(txBytes)
		if err != nil {
			return errors.New("failed to parse proven tx: " + err.Error())
		}
		if chainId != 0 && parsed.ChainId != chainId {
			return errors.New("proof tx chain id mismatch")
		}
		if parsed.Nonce <= proof.TxNonce {
			return errors.New("proof tx nonce does not exceed cleared nonce — vault has not advanced")
		}
		// round3 H-SM1 (HIGH, double-spend): Type B previously returned nil here
		// with NO vault-sender binding — the sibling gap H10 closed on Type A.
		// Without this, ANY tx from ANY address sitting at some TxIndex of a
		// ZK-anchored block with nonce > ps.Nonce would pass, forging a drop.
		// Mirror the Type-A hardening (above ~1556-1571): ecrecover the proven
		// tx's sender and require it equals the snapshotted vault-at-queue.
		// DS-F1 (round4): EcrecoverStrict (mirror Type-A fix above); no sig-byte
		// dedup here, so high-S acceptance opens a malleable-S vault-bind bypass.
		expectedVault := strings.ToLower(ps.VaultAtQueue)
		if !strings.HasPrefix(expectedVault, "0x") {
			expectedVault = "0x" + expectedVault
		}
		sighash := computeTxSighash(txBytes, parsed)
		recoveryV := byte(27 + parsed.V)
		rPadded := padTo32(parsed.R)
		sPadded := padTo32(parsed.S)
		sender, err := crypto.EcrecoverStrict(sighash, recoveryV, rPadded, sPadded)
		if err != nil {
			return errors.New("ecrecover on proven tx failed: " + err.Error())
		}
		senderHex := "0x" + hex.EncodeToString(sender[:])
		if !strings.EqualFold(senderHex, expectedVault) {
			return errors.New("proven tx sender does not match vault-at-queue — wrong-vault proof")
		}
		// round3 H-SM2 (HIGH, double-spend, LOCKED-DESIGN D-E-4): even with the
		// H-SM1 vault binding above, Type B's PREMISE is unsound. EVM nonces are
		// strictly sequential, so the vault landing a tx at nonce > ps.Nonce only
		// proves nonce ps.Nonce was CONSUMED — it does NOT distinguish (a) the
		// original withdrawal tx mining successfully (recipient PAID on L1) from
		// (b) a same-nonce replacement. A SUCCEEDED withdrawal therefore satisfies
		// "a later nonce exists", letting the withdrawer (cancelMyWithdrawal /
		// post-window expireWithdrawal) collect an L2 refund BEFORE confirmSpend
		// lands → double-spend.
		//
		// A provably-sound conservative fix (prove the tx mined AT nonce ps.Nonce
		// is NOT the withdrawal payout) is NOT achievable surgically in this proof
		// shape: under the drop premise there is no tx at nonce ps.Nonce to point
		// at, and Type B's `parsed` tx is at a HIGHER nonce — a receipt check on it
		// would prove nothing about whether nonce ps.Nonce paid out. Redefining the
		// proof to carry the tx-at-nonce-N + a non-payment receipt is a full
		// semantic + wire-format change to a LOCKED design (D-E-4) that requires
		// team review. Until then, GATE/DISABLE Type B as the safe default. Type A
		// (reverted-receipt at nonce N, vault-bound) + the expiry window still
		// provide drop-recovery. The H-SM1 binding above is retained (runs first,
		// no dead code) so a future sound redefinition starts already hardened.
		return errors.New("Type-B (block_inclusion_without_tx) drop-proof is disabled pending team review (H-SM2: a higher-nonce tx does not prove the tx at the cleared nonce was dropped rather than paid out — double-spend). Use Type-A (reverted_receipt) or the expiry window.")
	default:
		return errors.New("unknown L1ProofOfDrop type: " + proof.Type)
	}
}

// ConfirmSpendSchemaJSON — W4 Cluster E CRIT #5 (D-E-1) canonical wire
// schema for the ConfirmSpendRequest payload (8 top-level fields; version 2
// since EVM-T1 dropped tx_hex/receipt_hex and moved the proofs to base64).
const ConfirmSpendSchemaJSON = `{"version":2,"type":"ConfirmSpendRequest","fields":[` +
	`{"name":"block_height","type":"uint64"},` +
	`{"name":"tx_index","type":"uint64"},` +
	`{"name":"tx_proof","type":"base64"},` +
	`{"name":"receipt_proof","type":"base64"},` +
	`{"name":"intent_nonce","type":"uint64"},` +
	`{"name":"intent_to","type":"string"},` +
	`{"name":"intent_amount","type":"string"},` +
	`{"name":"intent_asset","type":"string"}` +
	`]}`
