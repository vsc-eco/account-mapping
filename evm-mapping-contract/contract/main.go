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

// createPrimaryKey requests the bridge's TSS key, whose address is the vault
// (A18).
func createPrimaryKey() { sdk.TssCreateKey("primary", "ecdsa", 365) }

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
	if _, err := mapping.HandleUnmapETH(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

//go:wasmexport unmapERC20
func unmapERC20(input *string) *string {
	var params mapping.TransferParams
	unmarshalParams(input, &params)
	if _, err := mapping.HandleUnmapERC20(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(err)
	}
	return nil
}

// RP-11: move queued withdrawals into flight now (permissionless; the bot
// calls it after a proof brings a fresh pricing header). Never fails: when
// nothing can be issued it is a no-op.
//
//go:wasmexport drainWithdrawalQueue
func drainWithdrawalQueue(input *string) *string {
	mapping.DrainWithdrawalQueue(chainId())
	return nil
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
	if err := mapping.HandleUnmapFrom(&params, vault(), chainId()); err != nil {
		ce.CustomAbort(err)
	}
	return nil
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
		assertNotPaused()
		createPrimaryKey()

	case "renewKey":
		// CRIT #17 flag 1 / W4 Cluster F D-F-1: TssRenewKey extends
		// ExpiryEpoch (NOT TssCreateKey, which would be a no-op).
		// D7: allowed while paused: a pause that outlasts the key's expiry
		// window must not retire the key that holds every deposit.
		sdk.TssRenewKey("primary", 365)

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
