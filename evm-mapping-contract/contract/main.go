package main

// EVM Mapping Contract — Magi/VSC
// - must import sdk or build fails

import (
	"encoding/json"
	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mapping"
	"evm-mapping-contract/sdk"
	"strconv"
)

var NetworkMode string

func main() {}

func vault() [20]byte {
	data := sdk.StateGetObject(constants.VaultAddressKey)
	if data == nil {
		return [20]byte{}
	}
	addr, _ := crypto.HexToAddress(*data)
	return addr
}

func chainId() uint64 {
	data := sdk.StateGetObject(constants.ChainIdKey)
	if data == nil {
		return 1
	}
	v, _ := strconv.ParseUint(*data, 10, 64)
	return v
}

// Admin gate: owner only. The legacy `did:vsc:oracle:eth` allowance was
// removed when the ZK verifier became the source of block headers; the
// remaining oracle-fed actions (addBlocks, replaceBlock) are kept for
// emergency use and during the verifier rollout.
func checkAdmin() {
	caller := sdk.GetEnv().Caller.String()
	owner := sdk.GetEnvKey("contract.owner")
	if owner == nil || caller != *owner {
		ce.CustomAbort(ce.NewContractError(ce.ErrNoPermission, "admin required"))
	}
}

func checkOwner() {
	caller := sdk.GetEnv().Caller.String()
	owner := sdk.GetEnvKey("contract.owner")
	if owner == nil || caller != *owner {
		ce.CustomAbort(ce.NewContractError(ce.ErrNoPermission, "owner required"))
	}
}

//go:wasmexport addBlocks
func addBlocks(input *string) *string {
	checkAdmin()
	var params blocklist.AddBlocksParams
	json.Unmarshal([]byte(*input), &params)
	if err := blocklist.HandleAddBlocks(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport map
func mapDeposit(input *string) *string {
	var params mapping.MapParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleMap(&params, vault()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport unmapETH
func unmapETH(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if _, err := mapping.HandleUnmapETH(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport unmapERC20
func unmapERC20(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if _, err := mapping.HandleUnmapERC20(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport confirmSpend
func confirmSpend(input *string) *string {
	var req mapping.ConfirmSpendRequest
	json.Unmarshal([]byte(*input), &req)
	if err := mapping.HandleConfirmSpend(&req, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport transfer
func transfer(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleTransfer(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport transferFrom
func transferFrom(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleTransferFrom(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport approve
func approve(input *string) *string {
	var params mapping.AllowanceParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleApprove(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport registerToken
func registerToken(input *string) *string {
	checkOwner()
	var params mapping.RegisterTokenParams
	json.Unmarshal([]byte(*input), &params)
	addr, err := crypto.HexToAddress(params.Address)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "invalid address"))
	}
	mapping.RegisterToken(addr, params.Symbol, params.Decimals, params.MinWithdrawal)
	return nil
}

//go:wasmexport registerPublicKey
func registerPublicKey(input *string) *string {
	checkOwner()
	sdk.StateSetObject(constants.PrimaryPublicKeyKey, *input)
	return nil
}

//go:wasmexport setVault
func setVault(input *string) *string {
	checkOwner()
	sdk.StateSetObject(constants.VaultAddressKey, *input)
	return nil
}

//go:wasmexport setChainId
func setChainIdAction(input *string) *string {
	checkOwner()
	sdk.StateSetObject(constants.ChainIdKey, *input)
	return nil
}

//go:wasmexport registerRouter
func registerRouter(input *string) *string {
	checkOwner()
	sdk.StateSetObject(constants.RouterContractIdKey, *input)
	return nil
}

//go:wasmexport setVerifierContract
func setVerifierContract(input *string) *string {
	checkOwner()
	var params struct {
		ContractId string `json:"contract_id"`
	}
	json.Unmarshal([]byte(*input), &params)
	sdk.StateSetObject(constants.VerifierContractIdKey, params.ContractId)
	return nil
}

//go:wasmexport adminMint
func adminMint(input *string) *string {
	checkOwner()
	var params struct {
		Address string `json:"address"`
		Asset   string `json:"asset"`
		Amount  int64  `json:"amount"`
	}
	json.Unmarshal([]byte(*input), &params)
	if params.Amount <= 0 || params.Address == "" || params.Asset == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "address, asset, and positive amount required"))
	}
	// review2 #42: AdminCredit also updates Supply so admin mints don't
	// desync balance vs. supply accounting.
	if err := mapping.AdminCredit(params.Address, params.Asset, params.Amount); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "balance overflow"))
	}
	return nil
}

//go:wasmexport setGasReserve
func setGasReserve(input *string) *string {
	checkOwner()
	sdk.StateSetObject(constants.GasReserveKey, *input)
	return nil
}

//go:wasmexport replaceBlock
func replaceBlock(input *string) *string {
	checkAdmin()
	var params blocklist.AddBlockEntry
	json.Unmarshal([]byte(*input), &params)
	if err := blocklist.HandleReplaceBlock(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport unmapFrom
func unmapFrom(input *string) *string {
	var params mapping.TransferParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleUnmapFrom(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport replaceWithdrawal
func replaceWithdrawal(_ *string) *string {
	checkAdmin()
	mapping.HandleReplaceWithdrawal(vault(), chainId())
	return nil
}

//go:wasmexport clearNonce
func clearNonce(_ *string) *string {
	checkAdmin()
	mapping.HandleClearNonce(vault(), chainId())
	return nil
}

//go:wasmexport increaseAllowance
func increaseAllowance(input *string) *string {
	var params mapping.AllowanceParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleIncreaseAllowance(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport decreaseAllowance
func decreaseAllowance(input *string) *string {
	var params mapping.AllowanceParams
	json.Unmarshal([]byte(*input), &params)
	if err := mapping.HandleDecreaseAllowance(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport createKey
func createKey(_ *string) *string {
	checkOwner()
	sdk.TssCreateKey("primary", "ecdsa", 365)
	return nil
}

//go:wasmexport renewKey
func renewKey(_ *string) *string {
	checkOwner()
	sdk.TssCreateKey("primary", "ecdsa", 365)
	return nil
}

//go:wasmexport seedBlocks
func seedBlocks(input *string) *string {
	checkOwner()
	if blocklist.GetLastHeight() > 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "seedBlocks only allowed when h=0"))
	}
	var params blocklist.AddBlockEntry
	json.Unmarshal([]byte(*input), &params)
	if err := blocklist.HandleSeedBlock(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport pause
func pause(_ *string) *string {
	checkOwner()
	sdk.StateSetObject(constants.PausedKey, "1")
	return nil
}

//go:wasmexport unpause
func unpause(_ *string) *string {
	checkOwner()
	sdk.StateDeleteObject(constants.PausedKey)
	return nil
}

//go:wasmexport getInfo
func getInfo(_ *string) *string { return nil }
