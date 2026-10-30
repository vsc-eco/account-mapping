package main

// EVM Mapping Contract — Magi/VSC
// - must import sdk or build fails

import (
	"encoding/json"
	"evm-mapping-contract/contract/admin"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mapping"
	"evm-mapping-contract/sdk"
	"math/big"
	"slices"
	"strconv"
	"strings"
)

var NetworkMode string

func main() {}

// vault is the L1 address of the TSS primary key (A18); zero until keygen.
func vault() [20]byte {
	addr, _ := mapping.TssVaultAddress()
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

// checkAdmin / checkOwner — W4 Cluster C v20 §BD SERIOUS-3:
// these two functions MUST remain separate. checkOwner is called from
// the propose/execute dispatcher; the Hive L1 2-of-3 multisig is
// enforced BEFORE the call reaches the contract. checkAdmin is the
// legacy name kept for compile compatibility with prior touch-points.
func checkAdmin() {
	checkOwner()
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
	env := sdk.GetEnv()
	owner := sdk.GetEnvKey("contract.owner")
	if owner == nil || env.Caller.String() != *owner {
		ce.CustomAbort(ce.NewContractError(ce.ErrNoPermission, "owner required"))
	}
	requireOwnerActive(env)
}

// requireOwnerActive aborts unless the owner signed this transaction with active
// authority (A2). A posting-only signature also makes the owner the Caller, so
// comparing Caller to the owner alone let the owner's posting key, rather than
// the multisig on its active authority, propose, execute and cancel admin
// actions. The caller of this helper has already checked that Caller is the
// owner. Mirrors requireOwnerActive in the BTC mapping contract.
func requireOwnerActive(env sdk.Env) {
	if !slices.Contains(env.Sender.RequiredAuths, env.Caller) {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "owner action requires active authority (posting authority cannot authorize it)"),
		)
	}
}

// checkOracleAccount and the OracleAccountKey state slot were removed in
// review6 H2 (see blocklist/blocks.go for the rationale). They guarded an
// oracle-trusted addBlocks path that no longer exists — headers come
// exclusively from the ZK header-verifier contract now.

// assertNotPaused — wraps the dispatchAdmin business logic for every gate
// touched by the propose/execute migration per W1 §D-C-9.
func assertNotPaused() {
	if err := mapping.AssertNotPaused(); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
}

// -----------------------------------------------------------------------------
// initContract — W4 Cluster C v21 SERIOUS-2 + NOTABLE-1.
// -----------------------------------------------------------------------------

type initContractParams struct {
	IsTestnet bool   `json:"is_testnet"`
	ChainId   uint64 `json:"chain_id"`
	// D6: optional first wiring. setVerifierContract and createKey carry the
	// 400K-block (~14 day) timelock, so a fresh bridge took two weeks to take
	// its first deposit. Nothing is held before init, so init may set them
	// once; every later change goes through propose/execute.
	VerifierContract string `json:"verifier_contract"`
	CreateKey        bool   `json:"create_key"`
}

//go:wasmexport initContract
func initContract(input *string) *string {
	if existing := sdk.StateGetObject(constants.InitMarkerKey); existing != nil && *existing == "1" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInitialization, "contract already initialized"))
	}
	env := sdk.GetEnv()
	owner := sdk.GetEnvKey("contract.owner")
	if owner == nil || env.Caller.String() != *owner {
		ce.CustomAbort(ce.NewContractError(ce.ErrNoPermission, "initContract requires deployer"))
	}
	requireOwnerActive(env)
	var params initContractParams
	if input != nil && *input != "" {
		if err := json.Unmarshal([]byte(*input), &params); err != nil {
			ce.CustomAbort(ce.WrapContractError(ce.ErrJson, err, "initContract"))
		}
	}
	// RV-2 (RV re-verify): the bridge chainId must be set at init. The old
	// setChainId action was removed (df458b7, "set once via initContract") but
	// initContract never actually set it, so chainId() fell back to 1 forever —
	// every non-mainnet (e.g. Sepolia) deposit was rejected as a chain mismatch
	// and testnet withdrawals would have been signed as chain-1 txs. Require a
	// non-zero chain_id here; it is immutable afterwards (no other writer).
	if params.ChainId == 0 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "initContract requires a non-zero chain_id"))
	}
	// A-1: the devnet_fasttimelock build (admin timelocks of a few blocks) is
	// a test fixture; it initializes only as a testnet bridge.
	if admin.FastTimelockBuild && !params.IsTestnet {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "this build has devnet timelocks (devnet_fasttimelock): initContract requires is_testnet"))
	}
	// A07: is_testnet unlocks clearTestnetState (wipes nonces, queue and observed
	// deposits). A bridge on Ethereum mainnet must never carry it.
	if params.IsTestnet && params.ChainId == 1 {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "is_testnet cannot be set on chain_id 1 (Ethereum mainnet)"))
	}
	sdk.StateSetObject(constants.ChainIdKey, strconv.FormatUint(params.ChainId, 10))
	// review6 H2: OracleAccountKey is no longer written at init — the
	// oracle-fed addBlocks path was removed; headers come from the ZK
	// header-verifier contract via setVerifierContract.
	if params.IsTestnet {
		sdk.StateSetObject("is_testnet", "true")
	}
	if params.VerifierContract != "" {
		sdk.StateSetObject(constants.VerifierContractIdKey, params.VerifierContract)
	}
	if params.CreateKey {
		createPrimaryKey()
	}
	sdk.StateSetObject(constants.InitMarkerKey, "1")
	return nil
}

// createPrimaryKey mints the next vault generation and requests its TSS key,
// whose address becomes the vault once the generation activates (A18, A01). On
// a fresh bridge that is generation 0, the "primary" key.
func createPrimaryKey() string {
	gen, name, err := mapping.MintNextGeneration(mapping.L1Height())
	if err != nil {
		ce.CustomAbort(err)
	}
	sdk.TssCreateKey(name, "ecdsa", 365)
	return "minted generation " + strconv.FormatUint(uint64(gen), 10) + ", key " + name + " (awaiting keygen)"
}

// renewVaultKeys renews every fund-holding generation's key that can be
// renewed, so a retiring generation's key cannot expire while it still holds
// funds (BTC D-2). A key that cannot be renewed is reported, not fatal.
func renewVaultKeys() string {
	names, skipped, err := mapping.RenewableVaultKeyNames()
	if err != nil {
		ce.CustomAbort(err)
	}
	for _, n := range names {
		sdk.TssRenewKey(n, 365)
	}
	out := "renewed keys: " + strings.Join(names, ",")
	if len(skipped) > 0 {
		sdk.Log("warn|renew-skipped|" + strings.Join(skipped, " "))
		out += "; skipped (unrenewable, fund-holding): " + strings.Join(skipped, " ")
	}
	return out
}

// checkOperator admits the owner or the appointed vault operator: the
// operational rotation ops an off-chain driver (the bot) calls. Mirrors the BTC
// contract.
func checkOperator() {
	caller := sdk.GetEnv().Caller.String()
	if owner := sdk.GetEnvKey("contract.owner"); owner != nil && caller == *owner {
		return
	}
	if op := sdk.StateGetObject(constants.VaultOperatorKey); op != nil && *op != "" && caller == *op {
		return
	}
	ce.CustomAbort(ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner or the vault operator"))
}

// A01 rotation ceremony, owner-only and direct like the BTC contract's: the
// owner can trigger a rotation but not choose its key (activation needs the
// TSS ceremony's key, its verified check signature and a reshare), so a
// timelock would add delay and no safety. Not pause-gated: a rotation is the
// answer to a suspected key compromise.

//go:wasmexport createKey
func createKey(_ *string) *string {
	checkOwner()
	// NN#3: no new generation while a superseded one still holds funds.
	funded, err := mapping.AnyFundedSupersededGen()
	if err != nil {
		ce.CustomAbort(err)
	}
	if funded {
		ce.CustomAbort(ce.NewContractError(ce.ErrTransaction,
			"cannot create a new key while a superseded generation still holds funds; drain it (migrateVault) first (NN#3)"))
	}
	out := createPrimaryKey()
	return &out
}

//go:wasmexport activateKey
func activateKey(_ *string) *string {
	checkOwner()
	activated, retired, had, err := mapping.ActivatePendingGeneration(mapping.L1Height())
	if err != nil {
		ce.CustomAbort(err)
	}
	out := "activated generation " + strconv.FormatUint(uint64(activated), 10)
	if had {
		out += "; generation " + strconv.FormatUint(uint64(retired), 10) + " now retiring"
	}
	sdk.Log("vaultactivate|g=" + strconv.FormatUint(uint64(activated), 10))
	return &out
}

//go:wasmexport discardPendingKey
func discardPendingKey(_ *string) *string {
	checkOwner()
	gen, err := mapping.DiscardPendingGeneration()
	if err != nil {
		ce.CustomAbort(err)
	}
	out := "discarded pending generation " + strconv.FormatUint(uint64(gen), 10)
	return &out
}

//go:wasmexport renewKey
func renewKey(_ *string) *string {
	checkOwner()
	out := renewVaultKeys()
	return &out
}

// setVaultOperator appoints (or, with an empty input, removes) the account that
// may call the operational rotation ops besides the owner.
//
//go:wasmexport setVaultOperator
func setVaultOperator(input *string) *string {
	checkOwner()
	op := ""
	if input != nil {
		op = strings.TrimSpace(*input)
	}
	if op == "" {
		sdk.StateDeleteObject(constants.VaultOperatorKey)
		return nil
	}
	if sdk.VerifyAddress(op) == string(sdk.AddressDomainUnknown) {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setVaultOperator: invalid account \""+op+"\""))
	}
	sdk.StateSetObject(constants.VaultOperatorKey, op)
	return nil
}

//go:wasmexport vaultInfo
func vaultInfo(_ *string) *string {
	out := mapping.VaultInfoJSON()
	return &out
}

// A01 operational ops: the owner or the vault operator (the bot) drives them.
// They are pause-gated, as the BTC contract's: each authorizes a new signature
// or retires state. Settlement (confirmSweep) is not.

type migrateVaultParams struct {
	EthProof *mapping.AccountProof `json:"eth_proof"`
}

//go:wasmexport migrateVault
func migrateVault(input *string) *string {
	checkOperator()
	assertNotPaused()
	var p migrateVaultParams
	if input != nil && *input != "" {
		unmarshalParams(input, &p)
	}
	out, err := mapping.HandleMigrateVault(chainId(), p.EthProof)
	if err != nil {
		ce.CustomAbort(err)
	}
	return &out
}

//go:wasmexport confirmSweep
func confirmSweep(input *string) *string {
	var req mapping.ConfirmSweepRequest
	unmarshalParams(input, &req)
	if err := mapping.HandleConfirmSweep(&req, chainId()); err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrInput, err))
	}
	return nil
}

type sweepIdParams struct {
	Gen   uint32 `json:"gen"`
	Nonce uint64 `json:"nonce"`
}

//go:wasmexport redriveSweep
func redriveSweep(input *string) *string {
	checkOperator()
	assertNotPaused()
	var p sweepIdParams
	unmarshalParams(input, &p)
	out, err := mapping.HandleRedriveSweep(p.Gen, p.Nonce, chainId())
	if err != nil {
		ce.CustomAbort(err)
	}
	return &out
}

//go:wasmexport retireVault
func retireVault(_ *string) *string {
	checkOperator()
	assertNotPaused()
	out, err := mapping.ReconcileRetiringVaults(chainId())
	if err != nil {
		ce.CustomAbort(err)
	}
	return &out
}

//go:wasmexport writeOffDust
func writeOffDust(_ *string) *string {
	checkOperator()
	assertNotPaused()
	out, err := mapping.HandleWriteOffDust()
	if err != nil {
		ce.CustomAbort(err)
	}
	return &out
}

type writeOffTokenParams struct {
	Gen    uint32 `json:"gen"`
	Symbol string `json:"symbol"`
}

//go:wasmexport writeOffToken
func writeOffToken(input *string) *string {
	checkOwner()
	assertNotPaused()
	var p writeOffTokenParams
	unmarshalParams(input, &p)
	out, err := mapping.HandleWriteOffToken(p.Gen, p.Symbol)
	if err != nil {
		ce.CustomAbort(err)
	}
	return &out
}

// -----------------------------------------------------------------------------
// User-facing wasmexports (NOT admin — no propose/execute wrapping)
// -----------------------------------------------------------------------------

// review6 closure (T2-10 / LOW-101): every user-facing wasmexport must
// hard-reject malformed JSON instead of silently treating it as
// zero-valued params. On this base the invariant is provided by the
// canonical unmarshalParams helper (pentest F2 fix, above), which also
// nil-checks the input and tags parse failures with ErrJson — so the
// per-export inline gates from the review6 commit are unnecessary.

//go:wasmexport map
func mapDeposit(input *string) *string {
	var params mapping.MapParams
	unmarshalParams(input, &params)
	if err := mapping.HandleMap(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrInput, err))
	}
	return nil
}

//go:wasmexport unmapETH
func unmapETH(input *string) *string {
	var params mapping.TransferParams
	unmarshalParams(input, &params)
	status, err := mapping.HandleUnmapETH(&params, vault(), chainId())
	if err != nil {
		ce.CustomAbort(err)
	}
	return &status // RP-11: "issued:{nonce}" or "queued:{seq}"
}

//go:wasmexport unmapERC20
func unmapERC20(input *string) *string {
	var params mapping.TransferParams
	unmarshalParams(input, &params)
	status, err := mapping.HandleUnmapERC20(&params, vault(), chainId())
	if err != nil {
		ce.CustomAbort(err)
	}
	return &status // RP-11: "issued:{nonce}" or "queued:{seq}"
}

// RP-11: move queued withdrawals into flight now. Permissionless: the bot calls
// it whenever the queue is non-empty and a slot is free (after a confirm, after
// a proof brings a fresh pricing header); anyone may. Only this call issues
// queued withdrawals. Never fails: when nothing can be issued it is a no-op.
//
//go:wasmexport drainWithdrawalQueue
func drainWithdrawalQueue(input *string) *string {
	// max: how many to issue in this call (default 1, at most
	// MaxInFlightWithdrawals). Each issue costs ~10-12k RC; set rc_limit to match.
	var p struct {
		Max int `json:"max"`
	}
	if input != nil && *input != "" {
		unmarshalParams(input, &p)
	}
	if p.Max <= 0 {
		p.Max = 1
	}
	if p.Max > int(constants.MaxInFlightWithdrawals) {
		p.Max = int(constants.MaxInFlightWithdrawals)
	}
	out := strconv.Itoa(mapping.DrainWithdrawalQueue(chainId(), p.Max))
	return &out // how many were issued
}

// RP-11: the owner of a queued (not yet issued) withdrawal takes it back.
//
//go:wasmexport cancelQueuedWithdrawal
func cancelQueuedWithdrawal(input *string) *string {
	var p mapping.CancelQueuedParams
	unmarshalParams(input, &p)
	if err := mapping.HandleCancelQueuedWithdrawal(p.Seq); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport confirmSpend
func confirmSpend(input *string) *string {
	var req mapping.ConfirmSpendRequest
	unmarshalParams(input, &req)
	// W4 Cluster F: HandleConfirmSpend signature has NO vaultAddress
	// parameter — it reads ps.VaultAtQueue from the stored PendingSpend.
	if err := mapping.HandleConfirmSpend(&req, chainId()); err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrInput, err))
	}
	return nil
}

//go:wasmexport transfer
func transfer(input *string) *string {
	var params mapping.TransferParams
	unmarshalParams(input, &params)
	if err := mapping.HandleTransfer(&params); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport transferFrom
func transferFrom(input *string) *string {
	var params mapping.TransferParams
	unmarshalParams(input, &params)
	if err := mapping.HandleTransferFrom(&params); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport approve
func approve(input *string) *string {
	var params mapping.AllowanceParams
	unmarshalParams(input, &params)
	if err := mapping.HandleApprove(&params); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport unmapFrom
func unmapFrom(input *string) *string {
	var params mapping.TransferParams
	unmarshalParams(input, &params)
	status, err := mapping.HandleUnmapFromStatus(&params, vault(), chainId())
	if err != nil {
		ce.CustomAbort(err)
	}
	return &status // RP-11: "issued:{nonce}" or "queued:{seq}"
}

//go:wasmexport increaseAllowance
func increaseAllowance(input *string) *string {
	var params mapping.AllowanceParams
	unmarshalParams(input, &params)
	if err := mapping.HandleIncreaseAllowance(&params); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport decreaseAllowance
func decreaseAllowance(input *string) *string {
	var params mapping.AllowanceParams
	unmarshalParams(input, &params)
	if err := mapping.HandleDecreaseAllowance(&params); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

// depositAddress returns the vault's MagiDeposit address (RP-7, EIP-55), where
// a deposit for an explicit Magi recipient is made; "" while there is no vault.
//
//go:wasmexport depositAddress
func depositAddress(_ *string) *string {
	v, ok := mapping.TssVaultAddress()
	out := ""
	if ok {
		out = crypto.ChecksumHex(mapping.DepositContractAddress(v))
	}
	return &out
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

// -----------------------------------------------------------------------------
// review6 H2: the `addBlocks` wasmexport (and the underlying
// blocklist.HandleAddBlocks) was REMOVED. Headers are sourced exclusively
// from the configured ZK header-verifier contract via the readState
// indirection in blocklist/blocks.go. See REVIEW6-VALIDATION.md for the
// architectural rationale (oracle-trusted writes were the unbacked-mint
// surface that composed with H10/H9/X3/L1).
//
// To bootstrap a fresh deployment, deploy the ZK header verifier first
// and pass its contract id into `execute` via a `setVerifierContract`
// payload (this path is already gated by the propose/execute timelock).
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// W4 Cluster C — propose / execute / cancel / expireProposal wasmexports.
// -----------------------------------------------------------------------------

//go:wasmexport propose
func propose(input *string) *string {
	checkOwner()
	var req admin.ProposeRequest
	if input != nil {
		json.Unmarshal([]byte(*input), &req)
	}
	payload, err := admin.DecodePayloadHex(req.PayloadHex)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInvalidHex, "payload_hex invalid"))
	}
	env := sdk.GetEnv()
	id, perr := admin.Propose(req.Action, payload, env.Caller.String(), env.BlockHeight)
	if perr != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, perr.Error()))
	}
	resp := admin.ProposeResponse{ProposalId: id, ExecHeight: 0}
	if pp := admin.LoadProposal(id); pp != nil {
		resp.ExecHeight = pp.ExecHeight
	}
	out, _ := json.Marshal(resp)
	s := string(out)
	return &s
}

//go:wasmexport execute
func execute(input *string) *string {
	checkOwner()
	var req admin.IdRequest
	if input != nil {
		json.Unmarshal([]byte(*input), &req)
	}
	env := sdk.GetEnv()
	pp, err := admin.ExecuteValidated(req.ProposalId, env.BlockHeight, env.Caller.String())
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	dispatchAdmin(pp.Action, pp.Payload)
	return nil
}

//go:wasmexport cancel
func cancel(input *string) *string {
	checkOwner()
	var req admin.IdRequest
	if input != nil {
		json.Unmarshal([]byte(*input), &req)
	}
	env := sdk.GetEnv()
	if err := admin.Cancel(req.ProposalId, env.Caller.String()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport expireProposal
func expireProposal(input *string) *string {
	var req admin.IdRequest
	if input != nil {
		json.Unmarshal([]byte(*input), &req)
	}
	env := sdk.GetEnv()
	if err := admin.ExpireProposal(req.ProposalId, env.BlockHeight, env.Caller.String()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

// -----------------------------------------------------------------------------
// W4 Cluster E withdrawal-lifecycle wasmexports.
// expireWithdrawal: CRIT #26 D-E-3 permissionless after WithdrawalExpiryWindow.
// cancelMyWithdrawal: CRIT #26 companion (only ps.From + mandatory proof).
// confirmSpendSchema: CRIT #5 D-E-1 schema introspection for the bot.
// -----------------------------------------------------------------------------

//go:wasmexport expireWithdrawal
func expireWithdrawal(input *string) *string {
	if input == nil || *input == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "expireWithdrawal: empty payload"))
	}
	var params mapping.ExpireWithdrawalParams
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "expireWithdrawal: bad payload"))
	}
	if err := mapping.HandleExpireWithdrawal(params.Nonce, params.Proof, chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport cancelMyWithdrawal
func cancelMyWithdrawal(input *string) *string {
	if input == nil || *input == "" {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "cancelMyWithdrawal: empty payload"))
	}
	var params mapping.CancelMyWithdrawalParams
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "cancelMyWithdrawal: bad payload"))
	}
	if err := mapping.HandleCancelMyWithdrawal(params.Nonce, params.Proof, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

// rollWithdrawal: D3 escape for a withdrawal that never mines (see
// mapping.HandleRollWithdrawal). Anyone, after WithdrawalRollWindow L1 blocks.
//
// E23: the vault goes live once the primary key has shown it can sign
// (mapping/vaultcheck.go).
//
//go:wasmexport requestVaultCheck
func requestVaultCheck(_ *string) *string {
	if err := mapping.HandleRequestVaultCheck(chainId()); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

type attestVaultParams struct {
	Signature string `json:"signature"`
}

//go:wasmexport attestVault
func attestVault(input *string) *string {
	var params attestVaultParams
	unmarshalParams(input, &params)
	if err := mapping.HandleAttestVault(params.Signature, chainId()); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport rollWithdrawal
func rollWithdrawal(input *string) *string {
	var params mapping.RollWithdrawalParams
	unmarshalParams(input, &params)
	if err := mapping.HandleRollWithdrawal(params.Nonce, vault(), chainId()); err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
	}
	return nil
}

//go:wasmexport confirmSpendSchema
func confirmSpendSchema(_ *string) *string {
	s := mapping.ConfirmSpendSchemaJSON
	return &s
}

// -----------------------------------------------------------------------------
// dispatchAdmin — invoked from execute() AFTER the timelock has elapsed.
// W4 Cluster E lifecycle handlers (expireWithdrawal/cancelMyWithdrawal/
// confirmSpendSchema + clearTestnetState) land in a subsequent commit.
// -----------------------------------------------------------------------------

func dispatchAdmin(action string, payload []byte) {
	switch action {

	// Fund-affecting (Long, 400K blocks)
	// setVault was removed (A18): the vault is the TSS primary key's address.

	case "setVerifierContract":
		assertNotPaused()
		var p struct {
			ContractId string `json:"contract_id"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setVerifierContract: bad payload"))
		}
		// Pentest finding EVM-C8 / MED-23 (M18-D22): an empty verifier id makes
		// blocklist.readState short-circuit to nil for EVERY header read —
		// silently nuking the ZK trust root and wedging all bridge ops with
		// "no block headers available". Reject so the verifier can only ever
		// land on a real, non-empty id.
		if p.ContractId == "" {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "verifier contract_id must be non-empty"))
		}
		// MED-134 (m59 F7): swapping the verifier instantly re-points every
		// header read at a new contract whose block heights need not match the
		// old one. Any in-flight withdrawal (its confirmSpend proof binds to a
		// height anchored under the OLD verifier) would become unconfirmable.
		// Refuse the swap while a withdrawal is pending so the operator must
		// first drain/expire the queue. RP-11: queued withdrawals count too,
		// they will be issued against the verifier's headers.
		if mapping.HasQueuedOrPendingWithdrawal() {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setVerifierContract: withdrawal pending — drain/expire before swapping verifier"))
		}
		sdk.StateSetObject(constants.VerifierContractIdKey, p.ContractId)

	case "createKey":
		// Kept for the timelocked path; the direct createKey export is the same
		// mint, behind the same NN#3 gate.
		if funded, err := mapping.AnyFundedSupersededGen(); err != nil || funded {
			ce.CustomAbort(ce.NewContractError(ce.ErrTransaction,
				"cannot create a new key while a superseded generation still holds funds (NN#3)"))
		}
		createPrimaryKey()

	case "renewKey":
		// CRIT #17 flag 1 / W4 Cluster F D-F-1: TssRenewKey extends
		// ExpiryEpoch (NOT TssCreateKey, which would be a no-op).
		// D7: allowed while paused: a pause that outlasts the key's expiry
		// window must not retire the key that holds every deposit. A01: every
		// fund-holding generation's key.
		renewVaultKeys()

	// Operator-tactical (28.8K blocks, 24h)
	// registerPublicKey was removed (A18): it stored a public key nothing read;
	// the key comes from the TSS group (TssGetKey).

	case "replaceWithdrawal":
		assertNotPaused()
		if err := mapping.HandleReplaceWithdrawal(vault(), chainId()); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
		}

	case "clearNonce":
		assertNotPaused()
		var p mapping.ClearNonceParams
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "clearNonce: bad payload"))
		}
		if err := mapping.HandleClearNonce(vault(), chainId(), p.Proof); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
		}

	// Operational (7.2K blocks, 6h)
	case "registerToken":
		assertNotPaused()
		var p mapping.RegisterTokenParams
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: bad payload"))
		}
		addr, herr := crypto.HexToAddress(p.Address)
		if herr != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: invalid address"))
		}
		// MED-21 (M18-D20): the registry record is pipe-delimited
		// (`symbol|decimals|minWithdrawal`). A symbol containing '|' splits the
		// stored record and corrupts the positional parse in getTokenInfo. Also
		// reject empty / over-long symbols so the stored record stays bounded
		// and well-formed.
		if p.Symbol == "" || len(p.Symbol) > constants.MaxTokenSymbolLen {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: symbol empty or too long"))
		}
		if strings.Contains(p.Symbol, "|") {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: symbol must not contain '|'"))
		}
		// E1 (RV re-verify): the balance key is `a-{addr}-{asset}` and the
		// allowed-symbol marker is `as-{symbol}`. A symbol containing the '-'
		// path delimiter (or ':' account-domain separator) could alias another
		// account's key or another symbol's marker, re-opening the key-injection
		// E1 closes. Real token symbols never need these characters.
		if strings.ContainsAny(p.Symbol, "-:") {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: symbol must not contain '-' or ':'"))
		}
		if p.Symbol == constants.NativeAsset {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: symbol must not shadow the native 'eth' asset"))
		}
		// MED-20 (M18-D9): bound MinWithdrawal. A negative value is nonsensical;
		// MaxInt64 (or anything above MaxTokenMinWithdrawal) makes every unmap
		// of this token revert at the min-withdrawal gate — an admin-induced
		// per-token DoS.
		if p.MinWithdrawal < 0 || p.MinWithdrawal > constants.MaxTokenMinWithdrawal {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: min_withdrawal out of range"))
		}
		// USDC-1 B: the revert fee is kept out of a reverted withdrawal's refund,
		// so it must not exceed the smallest withdrawal (the refund stays >= 0).
		effMin := p.MinWithdrawal
		if effMin <= 0 {
			effMin = constants.MinUSDCWithdrawal
		}
		if p.RevertFee < 0 || p.RevertFee > effMin {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: revert_fee must be between 0 and min_withdrawal"))
		}
		// USDC-GAS-1: 0 = ERC20TransferGas, else within the token gas bounds.
		if p.GasLimit != 0 && (p.GasLimit < constants.MinTokenGasLimit || p.GasLimit > constants.MaxTokenGasLimit) {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: gas_limit out of range"))
		}
		// The token's proving fee stays at most half its minimum deposit, as
		// setProofFee requires: otherwise raising min_withdrawal, setting a
		// large fee and lowering it again would let the fee take whole deposits.
		newFloor := big.NewInt((&mapping.TokenInfo{MinWithdrawal: effMin}).MinDeposit())
		if mapping.ProofFee(p.Symbol).Cmp(mapping.MaxProofFee(newFloor)) > 0 {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: min_withdrawal would put the proving fee above half the minimum deposit; lower the fee first"))
		}
		if err := mapping.RegisterTokenFull(chainId(), addr, p.Symbol, p.Decimals, p.MinWithdrawal, p.RevertFee, p.GasLimit); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerToken: "+err.Error()))
		}

	case "setETHGasLimit":
		// GLAM-1: the default L1 gas limit of an ETH withdrawal (an unmap may
		// set its own). Raise it when the chain prices account creation higher
		// (Glamsterdam, EIP-8037); a pending withdrawal keeps the limit it was
		// signed with.
		var p struct {
			GasLimit uint64 `json:"gas_limit"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setETHGasLimit: bad payload"))
		}
		if p.GasLimit < constants.ETHTransferGas || p.GasLimit > constants.MaxETHGasLimit {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setETHGasLimit: gas_limit out of range"))
		}
		mapping.SetETHGasLimit(p.GasLimit)

	case "setProofFee":
		// The proving fee of one asset ("eth" or a registered token's symbol),
		// in its smallest unit; 0 removes it. At most half the asset's smallest
		// creditable deposit, so a compromised owner key cannot take deposits
		// through it.
		var p struct {
			Asset  string `json:"asset"`
			Amount string `json:"amount"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setProofFee: bad payload"))
		}
		fee, ok := new(big.Int).SetString(p.Amount, 10)
		if !ok || fee.Sign() < 0 {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setProofFee: amount must be a non-negative integer"))
		}
		floor := mapping.ProofFeeFloor(p.Asset)
		if floor == nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setProofFee: unknown asset "+p.Asset))
		}
		if fee.Cmp(mapping.MaxProofFee(floor)) > 0 {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "setProofFee: amount above half the asset's minimum deposit"))
		}
		mapping.SetProofFee(p.Asset, fee)

	case "registerRouter":
		assertNotPaused()
		// MED-23 (M18-D22): reject an empty router id. routeDeposit treats an
		// empty/absent router id as "no router" and silently skips swap routing
		// (handlers.go:727); writing "" here would silently disable all swaps
		// rather than fail loud.
		if len(payload) == 0 {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerRouter: empty router id"))
		}
		sdk.StateSetObject(constants.RouterContractIdKey, string(payload))

	// setGasReserve REMOVED: the gas reserve is now funded exclusively by the
	// proof-backed `to_reserve` native-ETH deposit instruction (and the 1% ETH
	// deposit tax), both of which grow Active("eth") in lockstep with the
	// reserve. A bare admin write could bump the counter without moving Active,
	// breaking the Active == User + Fee + reserve invariant — the source of the
	// TrackReserveSpend divergence. See mapping.HandleMap's to_reserve branch.

	// review6 H2: `seedBlocks` and `setOracleAccount` cases removed. Header
	// state is owned by the ZK verifier contract; account-mapping no longer
	// accepts header writes from any caller (operator or oracle account).

	case "registerRelayer":
		assertNotPaused()
		var p struct {
			Account string `json:"account"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerRelayer: bad payload"))
		}
		if p.Account == "" {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerRelayer: empty account"))
		}
		// A5: a relayer must be a Magi identity that can sign the map call.
		if sdk.VerifyAddress(p.Account) == string(sdk.AddressDomainUnknown) {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "registerRelayer: invalid account \""+p.Account+"\""))
		}
		mapping.SetRelayer(p.Account)

	case "deregisterRelayer":
		assertNotPaused()
		var p struct {
			Account string `json:"account"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "deregisterRelayer: bad payload"))
		}
		if p.Account == "" {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, "deregisterRelayer: empty account"))
		}
		mapping.UnsetRelayer(p.Account)

	case "clearTestnetState":
		// W4 Cluster E D-E-8 chain-gated handler.
		assertNotPaused()
		if err := mapping.HandleClearTestnetState(); err != nil {
			ce.CustomAbort(ce.NewContractError(ce.ErrInput, err.Error()))
		}

	// Emergency (Immediate, 0 blocks)
	case "pause":
		sdk.StateSetObject(constants.PausedKey, "1")

	case "unpause":
		sdk.StateDeleteObject(constants.PausedKey)

	default:
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "dispatchAdmin: unknown action "+action))
	}
}
