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

// unmarshalParams is the canonical wasmexport unmarshal step.
// Pentest finding F2: every wasmexport in this file used to call
// json.Unmarshal and discard the error, which let garbage JSON
// silently produce a zero-valued struct that the handler then
// ran on. This helper aborts the contract with an ErrJson-tagged
// ContractError so callers can tell parse errors apart from
// business-logic errors.
func unmarshalParams(input *string, dest interface{}) {
	if input == nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrJson, "payload required"))
	}
	if err := json.Unmarshal([]byte(*input), dest); err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrJson, err))
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
	unmarshalParams(input, &params)
	if err := blocklist.HandleAddBlocks(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport map
func mapDeposit(input *string) *string {
	var params mapping.MapParams
	unmarshalParams(input, &params)
	if err := mapping.HandleMap(&params, vault()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport unmapETH
func unmapETH(input *string) *string {
	var params mapping.TransferParams
	unmarshalParams(input, &params)
	if _, err := mapping.HandleUnmapETH(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport unmapERC20
func unmapERC20(input *string) *string {
	var params mapping.TransferParams
	unmarshalParams(input, &params)
	if _, err := mapping.HandleUnmapERC20(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport confirmSpend
func confirmSpend(input *string) *string {
	var req mapping.ConfirmSpendRequest
	unmarshalParams(input, &req)
	if err := mapping.HandleConfirmSpend(&req, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport transfer
func transfer(input *string) *string {
	var params mapping.TransferParams
	unmarshalParams(input, &params)
	if err := mapping.HandleTransfer(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport transferFrom
func transferFrom(input *string) *string {
	var params mapping.TransferParams
	unmarshalParams(input, &params)
	if err := mapping.HandleTransferFrom(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport approve
func approve(input *string) *string {
	var params mapping.AllowanceParams
	unmarshalParams(input, &params)
	if err := mapping.HandleApprove(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport registerToken
func registerToken(input *string) *string {
	checkOwner()
	var params mapping.RegisterTokenParams
	unmarshalParams(input, &params)
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
//
// Pentest finding EVM-C1: previously this accepted any string with
// no timelock, multisig, or target validation, and would silently
// overwrite an existing verifier on every call. A single owner-key
// compromise could redirect the bridge to an attacker-controlled
// verifier contract → arbitrary fake headers → fake deposits →
// drain the vault.
//
// The verifier is now immutable after first set: changing it
// requires redeploying the mapping contract. Owner-only first
// write is still allowed.
func setVerifierContract(input *string) *string {
	checkOwner()
	if existing := sdk.StateGetObject(constants.VerifierContractIdKey); existing != nil && *existing != "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInitialization,
			"verifier contract is immutable once set; redeploy to change"))
	}
	var params struct {
		ContractId string `json:"contract_id"`
	}
	unmarshalParams(input, &params)
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
	unmarshalParams(input, &params)
	if params.Amount <= 0 || params.Address == "" || params.Asset == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "address, asset, and positive amount required"))
	}
	if err := mapping.IncBalance(params.Address, params.Asset, params.Amount); err != nil {
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
	unmarshalParams(input, &params)
	if err := blocklist.HandleReplaceBlock(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport unmapFrom
func unmapFrom(input *string) *string {
	var params mapping.TransferParams
	unmarshalParams(input, &params)
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

//go:wasmexport cancelStuckWithdrawal
//
// Pentest finding EVM-C3: the previous design left the bridge
// permanently jammed if the admin key was unavailable or the
// oracle stopped feeding fresh base fees — clearNonce and
// replaceWithdrawal were both checkAdmin-gated. This is the
// permissionless escape hatch: anyone can cancel a pending
// withdrawal that's older than mapping.CancelStuckTTLBlocks.
// The TTL exceeds blocklist.MaxBlockRetention, so by the time
// it fires the withdrawal can no longer be confirmed (no
// header to verify against). Refunds the original sender,
// advances the confirmed nonce.
func cancelStuckWithdrawal(_ *string) *string {
	if err := mapping.HandleCancelStuckWithdrawal(); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport increaseAllowance
func increaseAllowance(input *string) *string {
	var params mapping.AllowanceParams
	unmarshalParams(input, &params)
	if err := mapping.HandleIncreaseAllowance(&params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport decreaseAllowance
func decreaseAllowance(input *string) *string {
	var params mapping.AllowanceParams
	unmarshalParams(input, &params)
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
	unmarshalParams(input, &params)
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
//
// Pentest finding F3: previously returned nil, which broke
// `register_token` on the DEX router (and any other contract that
// queries the bridge for asset metadata). The router expects a
// JSON {"name":"Ether","symbol":"ETH","decimals":"18"} for the
// primary mapping; matches the BTC mapping contract's getInfo
// shape and the dex-contracts/types.MappingContractInfoReturn.
func getInfo(_ *string) *string {
	info := `{"name":"Ether","symbol":"ETH","decimals":"18"}`
	return &info
}
