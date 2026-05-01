package mapping

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"evm-mapping-contract/contract/abi"
	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
	"math/big"
	"strconv"
)

func HandleMap(params *MapParams, vaultAddress [20]byte) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	if vaultAddress == ([20]byte{}) {
		return errors.New("vault address not configured")
	}

	req := &params.TxData

	switch req.DepositType {
	case "eth":
		sender, amountBytes, _, err := VerifyETHDeposit(req, vaultAddress)
		if err != nil {
			return err
		}

		amount := new(big.Int).SetBytes(amountBytes)
		if amount.Sign() <= 0 {
			return errors.New("deposit amount must be positive")
		}
		if !amount.IsInt64() || amount.Int64() <= 0 {
			return errors.New("deposit amount exceeds safe int64 range")
		}
		amountInt64 := amount.Int64()

		dest := routeDeposit(sender, params.Instructions, "eth", amountInt64)

		// Gas reserve tax: bps of ETH deposits.
		// Compute as (amount/10000)*bps + (amount%10000)*bps/10000 so we keep
		// full precision without ever producing an int64 overflow on amount*bps.
		gasTax := (amountInt64/10000)*constants.GasReserveDepositTaxBps +
			(amountInt64%10000)*constants.GasReserveDepositTaxBps/10000
		if gasTax > 0 {
			addGasReserve(gasTax)
			amountInt64 -= gasTax
		}

		if dest != "" {
			if err := IncBalance(dest, "eth", amountInt64); err != nil {
				return errors.New("balance overflow")
			}
		}
		TrackDeposit("eth", amountInt64, gasTax)
		return nil

	case "erc20":
		tokenAddr, err := crypto.HexToAddress(req.TokenAddress)
		if err != nil {
			return errors.New("invalid token address")
		}

		tokenInfo := getTokenInfo(tokenAddr)
		if tokenInfo == nil {
			return ErrInvalidToken
		}

		sender, amountBytes, _, err := VerifyERC20Deposit(req, vaultAddress, tokenAddr)
		if err != nil {
			return err
		}

		amount := new(big.Int).SetBytes(amountBytes)
		if amount.Sign() <= 0 || !amount.IsInt64() || amount.Int64() <= 0 {
			return errors.New("deposit amount invalid or exceeds safe range")
		}
		amountInt64 := amount.Int64()

		dest := routeDeposit(sender, params.Instructions, tokenInfo.Symbol, amountInt64)
		if dest != "" {
			if err := IncBalance(dest, tokenInfo.Symbol, amountInt64); err != nil {
				return errors.New("balance overflow")
			}
		}
		TrackDeposit(tokenInfo.Symbol, amountInt64, 0)
		return nil

	default:
		return errors.New("deposit_type must be 'eth' or 'erc20'")
	}
}

func HandleUnmapETH(params *TransferParams, vaultAddress [20]byte, chainId uint64) (string, error) {
	if isPaused() {
		return "", errors.New("contract is paused")
	}
	if HasPendingWithdrawal() {
		return "", errors.New("withdrawal pending: wait for confirmation")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return "", errors.New("invalid amount")
	}
	if amount < constants.MinETHWithdrawal {
		return "", errors.New("below minimum ETH withdrawal")
	}

	toAddr, err := crypto.HexToAddress(params.To)
	if err != nil {
		return "", errors.New("invalid 'to' address")
	}

	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return "", errors.New("no block headers available")
	}

	gasReserve := getGasReserve()
	if gasReserve < constants.MinGasReserve {
		return "", errors.New("insufficient gas reserve")
	}

	gasTipCap := uint64(2_000_000_000)                  // 2 gwei
	gasFeeCap := header.BaseFeePerGas*2 + gasTipCap
	fee, feeErr := safeCastGasFee(constants.ETHTransferGas, gasFeeCap)
	if feeErr != nil {
		return "", errors.New("gas fee too high")
	}

	if params.MaxFee != "" {
		maxFee, _ := strconv.ParseInt(params.MaxFee, 10, 64)
		if maxFee > 0 && fee > maxFee {
			return "", errors.New("fee exceeds max_fee")
		}
	}

	// Check balance BEFORE signing to prevent signed TX leak on insufficient funds
	totalDeduct := amount + fee
	if params.DeductFee {
		totalDeduct = amount
	}
	if GetBalance(caller, "eth") < totalDeduct {
		return "", errors.New("insufficient balance")
	}

	nonce := GetPendingNonce()
	amountBig := new(big.Int).SetInt64(amount)
	unsigned := BuildETHWithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, toAddr, amountBig)
	sighash := ComputeSighash(unsigned)

	if err := requireTssKey(); err != nil {
		return "", err
	}
	sdk.TssSignKey("primary", sighash)

	if !DecBalance(caller, "eth", totalDeduct) {
		return "", errors.New("insufficient balance")
	}
	TrackWithdrawal("eth", amount)

	// Store pending spend
	StorePendingSpend(PendingSpend{
		Nonce:       nonce,
		Amount:      amount,
		From:        caller,
		To:          params.To,
		Asset:       "eth",
		UnsignedTxHex: hex.EncodeToString(unsigned),
		BlockHeight: blocklist.GetLastHeight(),
	})
	SetPendingNonce(nonce + 1)

	return hex.EncodeToString(unsigned), nil
}

func HandleUnmapERC20(params *TransferParams, vaultAddress [20]byte, chainId uint64) (string, error) {
	if isPaused() {
		return "", errors.New("contract is paused")
	}
	if HasPendingWithdrawal() {
		return "", errors.New("withdrawal pending: wait for confirmation")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return "", errors.New("invalid amount")
	}
	if params.TokenAddress == "" {
		return "", errors.New("token_address required for ERC-20 withdrawal")
	}
	tokenAddr, err := crypto.HexToAddress(params.TokenAddress)
	if err != nil {
		return "", errors.New("invalid token_address")
	}
	tokenInfo := getTokenInfo(tokenAddr)
	if tokenInfo == nil {
		return "", ErrInvalidToken
	}
	if amount < tokenInfo.MinWithdrawal {
		return "", errors.New("below minimum withdrawal for this token")
	}

	recipientAddr, err := crypto.HexToAddress(params.To)
	if err != nil {
		return "", errors.New("invalid recipient address")
	}

	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return "", errors.New("no block headers available")
	}

	gasReserve := getGasReserve()
	if gasReserve < constants.MinGasReserve {
		return "", errors.New("insufficient gas reserve for ERC-20 withdrawal")
	}

	gasTipCap := uint64(2_000_000_000)
	gasFeeCap := header.BaseFeePerGas*2 + gasTipCap
	gasCost, gasCostErr := safeCastGasFee(constants.ERC20TransferGas, gasFeeCap)
	if gasCostErr != nil {
		return "", errors.New("gas fee too high")
	}

	nonce := GetPendingNonce()
	amountBig := new(big.Int).SetInt64(amount)
	unsigned := BuildERC20WithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, tokenAddr, recipientAddr, amountBig)
	sighash := ComputeSighash(unsigned)

	if err := requireTssKey(); err != nil {
		return "", err
	}
	sdk.TssSignKey("primary", sighash)

	if !DecBalance(caller, tokenInfo.Symbol, amount) {
		return "", errors.New("insufficient token balance")
	}
	TrackWithdrawal(tokenInfo.Symbol, amount)

	deductGasReserve(gasCost)

	StorePendingSpend(PendingSpend{
		Nonce:        nonce,
		Amount:       amount,
		From:         caller,
		To:           params.To,
		Asset:        tokenInfo.Symbol,
		TokenAddress: params.TokenAddress,
		UnsignedTxHex:  hex.EncodeToString(unsigned),
		BlockHeight:  blocklist.GetLastHeight(),
	})
	SetPendingNonce(nonce + 1)

	return hex.EncodeToString(unsigned), nil
}

func HandleConfirmSpend(req *ConfirmSpendRequest, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}

	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		return errors.New("no pending spend at confirmed nonce")
	}

	if req.BlockHeight <= ps.BlockHeight {
		return errors.New("confirmation block must be after withdrawal block")
	}

	header := blocklist.GetHeader(req.BlockHeight)
	if header == nil {
		return ErrBlockNotFound
	}

	// --- Transaction proof: verify the tx matches the pending spend ---
	txBytes, err := hex.DecodeString(req.TxHex)
	if err != nil {
		return errors.New("invalid tx_hex")
	}
	txProofBytes, err := hex.DecodeString(req.TxProofHex)
	if err != nil {
		return errors.New("invalid tx_proof_hex")
	}

	txProof := splitProofNodes(txProofBytes)
	txKey := rlp.EncodeUint64(req.TxIndex)
	provenTx, err := mpt.VerifyProof(header.TransactionsRoot, txKey, txProof)
	if err != nil {
		return errors.New("tx proof verification failed")
	}
	if !bytesEqual(provenTx, txBytes) {
		return errors.New("tx does not match proof")
	}

	parsedTx, err := parseTransaction(txBytes)
	if err != nil {
		return errors.New("failed to parse proven tx: " + err.Error())
	}
	if parsedTx.Nonce != ps.Nonce {
		return errors.New("tx nonce does not match pending spend")
	}
	if parsedTx.ChainId != chainId {
		return errors.New("tx chain id does not match contract chain id")
	}

	// Recover sender — the only valid signer of the vault's nonces is the vault itself.
	sighash := computeTxSighash(txBytes, parsedTx)
	recoveredSender, err := crypto.Ecrecover(sighash, 27+parsedTx.V, padTo32(parsedTx.R), padTo32(parsedTx.S))
	if err != nil {
		return errors.New("ecrecover failed: " + err.Error())
	}
	if recoveredSender == ([20]byte{}) {
		return errors.New("ecrecover returned zero address")
	}
	if recoveredSender != vaultAddress {
		return errors.New("tx not signed by vault")
	}

	psTo, err := crypto.HexToAddress(ps.To)
	if err != nil {
		return errors.New("invalid pending spend destination")
	}
	if ps.Asset == "eth" {
		if parsedTx.To != psTo {
			return errors.New("tx destination does not match pending spend")
		}
		txAmount := new(big.Int).SetBytes(parsedTx.Value)
		if !txAmount.IsInt64() || txAmount.Int64() != ps.Amount {
			return errors.New("tx amount does not match pending spend")
		}
	} else {
		// ERC-20: tx.to is the token contract, value is 0, calldata is transfer(recipient, amount).
		tokenAddr, err := crypto.HexToAddress(ps.TokenAddress)
		if err != nil {
			return errors.New("invalid pending spend token address")
		}
		if parsedTx.To != tokenAddr {
			return errors.New("tx token contract does not match pending spend")
		}
		if new(big.Int).SetBytes(parsedTx.Value).Sign() != 0 {
			return errors.New("erc20 tx must have zero value")
		}
		if len(parsedTx.Data) != 68 {
			return errors.New("erc20 calldata must be 68 bytes")
		}
		if !bytesEqual(parsedTx.Data[0:4], abi.TransferSelector) {
			return errors.New("erc20 calldata selector mismatch")
		}
		// First 12 bytes of address slot must be zero (left-padded address).
		for _, b := range parsedTx.Data[4:16] {
			if b != 0 {
				return errors.New("erc20 recipient padding non-zero")
			}
		}
		if !bytesEqual(parsedTx.Data[16:36], psTo[:]) {
			return errors.New("erc20 recipient does not match pending spend")
		}
		callAmount := new(big.Int).SetBytes(parsedTx.Data[36:68])
		if !callAmount.IsInt64() || callAmount.Int64() != ps.Amount {
			return errors.New("erc20 amount does not match pending spend")
		}
	}

	// --- Receipt proof: determine success or failure ---
	receiptBytes, err := hex.DecodeString(req.ReceiptHex)
	if err != nil {
		return errors.New("invalid receipt_hex")
	}
	receiptProofBytes, err := hex.DecodeString(req.ReceiptProofHex)
	if err != nil {
		return errors.New("invalid receipt_proof_hex")
	}

	receiptProof := splitProofNodes(receiptProofBytes)
	receiptKey := rlp.EncodeUint64(req.TxIndex)
	provenReceipt, err := mpt.VerifyProof(header.ReceiptsRoot, receiptKey, receiptProof)
	if err != nil {
		return errors.New("receipt proof verification failed")
	}
	if !bytesEqual(provenReceipt, receiptBytes) {
		return errors.New("receipt does not match proof")
	}

	receiptToParse := receiptBytes
	if len(receiptToParse) > 0 && receiptToParse[0] <= 0x7f {
		receiptToParse = receiptToParse[1:]
	}
	items, err := rlp.DecodeList(receiptToParse)
	if err != nil || len(items) < 1 {
		return errors.New("invalid receipt RLP")
	}
	status := items[0].AsUint64()

	if status == 1 {
		DeletePendingSpend(confirmedNonce)
		SetConfirmedNonce(confirmedNonce + 1)
	} else {
		// Best-effort refund. If IncBalance overflows (user already at int64 max),
		// we still clear pending state — otherwise the contract is permanently
		// jammed for a near-impossible scenario. Only update supply when the
		// refund actually landed so balance and supply stay consistent.
		if err := IncBalance(ps.From, ps.Asset, ps.Amount); err == nil {
			s := GetSupply(ps.Asset)
			s.Active += ps.Amount
			s.User += ps.Amount
			SetSupply(ps.Asset, s)
		}
		DeletePendingSpend(confirmedNonce)
		SetConfirmedNonce(confirmedNonce + 1)
	}

	return nil
}

func HandleTransfer(params *TransferParams) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return errors.New("invalid amount")
	}

	if !DecBalance(caller, params.Asset, amount) {
		return errors.New("insufficient balance")
	}
	if err := IncBalance(params.To, params.Asset, amount); err != nil {
		return errors.New("recipient balance overflow")
	}
	return nil
}

func HandleTransferFrom(params *TransferParams) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return errors.New("invalid amount")
	}

	allowance := GetAllowance(params.From, caller, params.Asset)
	if allowance < amount {
		return errors.New("insufficient allowance")
	}

	if !DecBalance(params.From, params.Asset, amount) {
		return errors.New("insufficient balance")
	}
	SetAllowance(params.From, caller, params.Asset, allowance-amount)
	if err := IncBalance(params.To, params.Asset, amount); err != nil {
		return errors.New("recipient balance overflow")
	}
	return nil
}

func HandleApprove(params *AllowanceParams) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount < 0 {
		return errors.New("invalid amount")
	}

	SetAllowance(caller, params.Spender, params.Asset, amount)
	return nil
}

// Helpers

func routeDeposit(sender [20]byte, instructions []string, asset string, amount int64) string {
	did := crypto.AddressToDID(sender, 1)
	dest := did
	var swapTo, assetOut, destChain string

	for _, instr := range instructions {
		if len(instr) > 11 && instr[:11] == "deposit_to=" {
			dest = instr[11:]
		}
		if len(instr) > 8 && instr[:8] == "swap_to=" {
			swapTo = instr[8:]
		}
		if len(instr) > 10 && instr[:10] == "asset_out=" {
			assetOut = instr[10:]
		}
		if len(instr) > 18 && instr[:18] == "destination_chain=" {
			destChain = instr[18:]
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

		if err := IncBalance(selfAddr, asset, amount); err != nil {
			return dest
		}
		SetAllowance(selfAddr, "contract:"+routerId, asset, amount)

		instrJSON, _ := json.Marshal(DexInstruction{
			Type:             "swap",
			Version:          "1.0.0",
			AssetIn:          asset,
			AmountIn:         strconv.FormatInt(amount, 10),
			AssetOut:         assetOut,
			Recipient:        swapTo,
			DestinationChain: destChain,
		})

		result := sdk.ContractCall(routerId, "execute", string(instrJSON), nil)
		SetAllowance(selfAddr, "contract:"+routerId, asset, 0)

		if result == nil {
			// Router call failed. Reverse the self-balance credit and fall through
			// to credit the depositor directly with the original asset.
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

func getTokenInfo(addr [20]byte) *TokenInfo {
	key := constants.TokenRegistryPrefix + hex.EncodeToString(addr[:])
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

func RegisterToken(addr [20]byte, symbol string, decimals uint8, minWithdrawal int64) {
	key := constants.TokenRegistryPrefix + hex.EncodeToString(addr[:])
	sdk.StateSetObject(key, symbol+"|"+strconv.FormatUint(uint64(decimals), 10)+"|"+strconv.FormatInt(minWithdrawal, 10))
}

func requireTssKey() error {
	keyInfo := sdk.TssGetKey("primary")
	if keyInfo == "" || keyInfo == "fail" {
		return errors.New("TSS key not available")
	}
	return nil
}

func getGasReserve() int64 {
	data := sdk.StateGetObject(constants.GasReserveKey)
	if data == nil {
		return 0
	}
	v, _ := strconv.ParseInt(*data, 10, 64)
	return v
}

func addGasReserve(amount int64) {
	current := getGasReserve()
	sdk.StateSetObject(constants.GasReserveKey, strconv.FormatInt(current+amount, 10))
}

func deductGasReserve(amount int64) {
	current := getGasReserve()
	newVal := current - amount
	if newVal < 0 {
		newVal = 0
	}
	sdk.StateSetObject(constants.GasReserveKey, strconv.FormatInt(newVal, 10))
}


func HandleUnmapFrom(params *TransferParams, vaultAddress [20]byte, chainId uint64) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	if HasPendingWithdrawal() {
		return errors.New("withdrawal pending: wait for confirmation")
	}

	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return errors.New("invalid amount")
	}
	if params.Asset == "eth" && amount < constants.MinETHWithdrawal {
		return errors.New("below minimum ETH withdrawal")
	}

	if err := requireTssKey(); err != nil {
		return err
	}

	// Validate ALL inputs BEFORE any state mutations
	toAddr, err := crypto.HexToAddress(params.To)
	if err != nil {
		return errors.New("invalid destination address")
	}

	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		return errors.New("no block headers available")
	}

	var tokenAddr [20]byte
	if params.Asset != "eth" {
		if params.TokenAddress == "" {
			return errors.New("token_address required")
		}
		tokenAddr, err = crypto.HexToAddress(params.TokenAddress)
		if err != nil {
			return errors.New("invalid token_address")
		}
		tokenInfo := getTokenInfo(tokenAddr)
		if tokenInfo == nil {
			return ErrInvalidToken
		}
		if amount < tokenInfo.MinWithdrawal {
			return errors.New("below minimum withdrawal for this token")
		}
		if getGasReserve() < constants.MinGasReserve {
			return errors.New("insufficient gas reserve for ERC-20 withdrawal")
		}
	}

	allowance := GetAllowance(params.From, caller, params.Asset)
	if allowance < amount {
		return errors.New("insufficient allowance")
	}

	// All validation passed — now mutate state
	if !DecBalance(params.From, params.Asset, amount) {
		return errors.New("insufficient balance in owner account")
	}
	SetAllowance(params.From, caller, params.Asset, allowance-amount)
	TrackWithdrawal(params.Asset, amount)

	gasTipCap := uint64(2_000_000_000)
	gasFeeCap := header.BaseFeePerGas*2 + gasTipCap
	nonce := GetPendingNonce()
	amountBig := new(big.Int).SetInt64(amount)

	var unsigned []byte
	var asset string
	var tokenAddress string
	if params.Asset == "eth" {
		unsigned = BuildETHWithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, toAddr, amountBig)
		asset = "eth"
	} else {
		unsigned = BuildERC20WithdrawalTx(chainId, nonce, gasTipCap, gasFeeCap, tokenAddr, toAddr, amountBig)
		asset = params.Asset
		tokenAddress = params.TokenAddress
		erc20Gas, erc20GasErr := safeCastGasFee(constants.ERC20TransferGas, gasFeeCap)
		if erc20GasErr != nil {
			sdk.Revert("gas fee too high", "unmapFrom")
		}
		deductGasReserve(erc20Gas)
	}

	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	StorePendingSpend(PendingSpend{
		Nonce:        nonce,
		Amount:       amount,
		From:         params.From,
		To:           params.To,
		Asset:        asset,
		TokenAddress: tokenAddress,
		UnsignedTxHex:  hex.EncodeToString(unsigned),
		BlockHeight:  blocklist.GetLastHeight(),
	})
	SetPendingNonce(nonce + 1)
	return nil
}

func HandleIncreaseAllowance(params *AllowanceParams) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return errors.New("invalid amount")
	}

	current := GetAllowance(caller, params.Spender, params.Asset)
	newVal, err := safeAdd64(current, amount)
	if err != nil {
		return errors.New("allowance overflow")
	}
	SetAllowance(caller, params.Spender, params.Asset, newVal)
	return nil
}

func HandleDecreaseAllowance(params *AllowanceParams) error {
	if isPaused() {
		return errors.New("contract is paused")
	}
	env := sdk.GetEnv()
	caller := env.Caller.String()

	amount, err := strconv.ParseInt(params.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return errors.New("invalid amount")
	}

	current := GetAllowance(caller, params.Spender, params.Asset)
	newVal := current - amount
	if newVal < 0 {
		newVal = 0
	}
	SetAllowance(caller, params.Spender, params.Asset, newVal)
	return nil
}

func HandleReplaceWithdrawal(vaultAddress [20]byte, chainId uint64) {
	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		sdk.Revert("no pending withdrawal to replace", "replaceWithdrawal")
		return
	}

	// Rebuild with 2x gas
	header := blocklist.GetHeader(blocklist.GetLastHeight())
	if header == nil {
		sdk.Revert("no headers", "replaceWithdrawal")
		return
	}

	gasTipCap := uint64(4_000_000_000) // doubled
	gasFeeCap := header.BaseFeePerGas*3 + gasTipCap

	toAddr, _ := crypto.HexToAddress(ps.To)
	amountBig := new(big.Int).SetInt64(ps.Amount)

	var unsigned []byte
	if ps.Asset == "eth" {
		unsigned = BuildETHWithdrawalTx(chainId, confirmedNonce, gasTipCap, gasFeeCap, toAddr, amountBig)
	} else {
		tokenAddr, _ := crypto.HexToAddress(ps.TokenAddress)
		unsigned = BuildERC20WithdrawalTx(chainId, confirmedNonce, gasTipCap, gasFeeCap, tokenAddr, toAddr, amountBig)
	}

	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// Update pending spend with new signed TX
	ps.UnsignedTxHex = hex.EncodeToString(unsigned)
	StorePendingSpend(*ps)
}

func HandleClearNonce(vaultAddress [20]byte, chainId uint64) {
	confirmedNonce := GetConfirmedNonce()
	ps := GetPendingSpend(confirmedNonce)
	if ps == nil {
		sdk.Revert("no pending nonce to clear", "clearNonce")
		return
	}

	// Build 0-value self-transfer to advance nonce
	unsigned := BuildETHWithdrawalTx(chainId, confirmedNonce, 4_000_000_000, 100_000_000_000, vaultAddress, big.NewInt(0))
	sighash := ComputeSighash(unsigned)
	sdk.TssSignKey("primary", sighash)

	// Best-effort refund: if the user's balance is at the int64 ceiling we cannot
	// credit them, but the contract MUST still advance the nonce or it will jam.
	// Only update supply when the refund actually landed, otherwise balance and
	// supply diverge.
	if err := IncBalance(ps.From, ps.Asset, ps.Amount); err == nil {
		sup := GetSupply(ps.Asset)
		sup.Active += ps.Amount
		sup.User += ps.Amount
		SetSupply(ps.Asset, sup)
	}
	DeletePendingSpend(confirmedNonce)
	SetConfirmedNonce(confirmedNonce + 1)
	SetPendingNonce(confirmedNonce + 1)
}
