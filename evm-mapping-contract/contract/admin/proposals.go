package admin

// W4 Cluster C — admin propose/execute timelock infrastructure.
// Implements:
//   - PendingProposal storage shape per W1-cluster-C-admin §D-C-4 (LOCKED).
//   - 4 timelock windows per W1 §D-C-3 (LOCKED): Long/Tactical/Operational/Immediate.
//   - propose / execute / cancel / expireProposal lifecycle per §D-C-6.
//   - Event emit shape per §D-C-7.
//   - Payload encoding spec per §D-C-5: canonical JSON marshaling of the
//     action's existing input struct. proposals.go does NOT marshal — that
//     happens at the propose() call site so the same struct types defined in
//     mapping/types.go (or equivalent) flow through unchanged.
//
// This package deliberately does NOT import the mapping package. The
// dispatchAdmin function lives in contract/main.go where it can call the
// per-action handler implementations directly. proposals.go owns the
// timelock + persistence + event-emit logic; dispatchAdmin owns the
// per-action routing.
//
// Per v10 user correction: Magi mainnet uses Hive-native multisig at the
// Hive account layer. proposals.go ONLY checks caller == contract.owner;
// the 2-of-3 weighted-authority enforcement happens at Hive L1 before the
// call reaches the contract. There is NO contract-internal multisig.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/sdk"
	"strconv"
)

// PendingProposal — VERBATIM from W1 §D-C-4 / W4 Step 1 (S-C-1 fix):
// PayloadHash is [32]byte (NOT string/[]byte), ProposalId is uint64
// (monotonic counter, NOT a hash) per v19 §AU.
type PendingProposal struct {
	ProposalId   uint64   `json:"proposal_id"`   // v19 §AU — monotonic counter; assigned at propose() time
	Action       string   `json:"action"`        // handler name, e.g. "setVerifierContract"
	PayloadHash  [32]byte `json:"payload_hash"`  // keccak256 of the action's input payload bytes
	Proposer     string   `json:"proposer"`      // hive account that proposed
	QueueHeight  uint64   `json:"queue_height"`  // block height when proposed
	ExecHeight   uint64   `json:"exec_height"`   // queueHeight + class-specific timelock
	ExpireHeight uint64   `json:"expire_height"` // execHeight + 7 days (auto-expire)
	Payload      []byte   `json:"payload"`       // serialized input bytes (D-C-5)
	Status       uint8    `json:"status"`        // 0=pending, 1=accepted, 2=cancelled, 3=expired
}

// Status constants per §D-C-4.
const (
	StatusPending   uint8 = 0
	StatusAccepted  uint8 = 1
	StatusCancelled uint8 = 2
	StatusExpired   uint8 = 3
)

// Timelock windows per W1 §D-C-3 (LOCKED) are defined in timelock_windows_prod.go
// (PRODUCTION, untagged: 400K / 28.8K / 7.2K / 0). They are overridden ONLY in a
// devnet test build via timelock_windows_devnet.go (//go:build devnet_fasttimelock)
// so setVerifierContract (TimelockLong) can be bootstrapped within a short devnet's
// block budget. A production build (no tag) ALWAYS uses the LOCKED values; the real
// timelock is tested separately on the untagged build (W6.3 admin / P2C-1).
const (
	// Auto-expire window: execHeight + 7 days worth of blocks (2 * tactical).
	// Per §D-C-4 "execHeight + 7 days (auto-expire)".
	ExpireWindowBlocks uint64 = 201_600 // 7 days at 3s blocks
)

// Action class enumeration (string actions are matched against this set).
//
// Per W4 §D-C-8 17-handler migration table:
//   Fund-affecting (Long, 400K):     setVerifierContract, createKey
//   Operator-tactical (28.8K, 24h):  replaceWithdrawal, clearNonce
//   (setVault and registerPublicKey were removed by A18: the vault is the TSS
//   primary key's address.)
//   Operational (7.2K, 6h):          registerToken, registerRouter, setETHGasLimit,
//                                     registerRelayer, deregisterRelayer,
//                                     clearTestnetState (Cluster E coord)
//   Emergency (0):                   pause, unpause, renewKey (D7)
//
// review6 H2: addBlocks / seedBlocks / setOracleAccount / replaceBlock are
//   all REMOVED — headers come from the ZK header-verifier contract only.
//   See blocklist/blocks.go for rationale.
// setChainId / adminMint are DROPPED (CRIT #6 / CRIT #9 v10).
func TimelockFor(action string) (uint64, error) {
	switch action {
	case "setVerifierContract", "createKey":
		return TimelockLong, nil
	case "replaceWithdrawal", "clearNonce":
		return TimelockTactical, nil
	case "registerToken", "registerRouter", "setETHGasLimit",
		"registerRelayer", "deregisterRelayer", "clearTestnetState":
		return TimelockOperational, nil
	// D7: renewKey only extends the vault key's life and moves nothing. The
	// key expires after 365 epochs (~91 days), retires 403,200 blocks after
	// that and can then never sign again, so a 400K-block timelock left an
	// owner who started the renewal after expiry ~3,200 blocks to spare. The
	// BTC mapping contract's renewKey is owner-only and immediate too.
	case "pause", "unpause", "renewKey":
		return TimelockImmediate, nil
	default:
		return 0, errors.New("unknown admin action: " + action)
	}
}

// proposalKey builds "pr-{id}" per §D-C-4.
func proposalKey(id uint64) string {
	return constants.ProposalPrefix + strconv.FormatUint(id, 10)
}

// nextProposalId reads / increments the KeyProposalCounter monotonic counter.
//
// ParseUint error handling (v19 scrutiny-C NOTABLE #4): the ParseUint error
// is intentionally discarded — a malformed counter resets to 1 via the
// init guard. This treats state corruption as first-time-init.
func nextProposalId() uint64 {
	nextStr := sdk.StateGetObject(constants.KeyProposalCounter)
	var nextId uint64
	if nextStr != nil {
		// parse error treated as zero (state corruption or first init)
		nextId, _ = strconv.ParseUint(*nextStr, 10, 64)
	}
	if nextId == 0 {
		nextId = 1
	}
	sdk.StateSetObject(constants.KeyProposalCounter, strconv.FormatUint(nextId+1, 10))
	return nextId
}

// LoadProposal fetches a PendingProposal by id, or nil if absent / corrupt.
func LoadProposal(id uint64) *PendingProposal {
	data := sdk.StateGetObject(proposalKey(id))
	if data == nil {
		return nil
	}
	pp := &PendingProposal{}
	if err := json.Unmarshal([]byte(*data), pp); err != nil {
		return nil
	}
	return pp
}

// StoreProposal persists a PendingProposal under its id key.
func StoreProposal(pp *PendingProposal) {
	jsonBytes, err := json.Marshal(pp)
	if err != nil {
		ce.CustomAbort(ce.NewContractError(ce.ErrInput, "proposal marshal failed"))
	}
	sdk.StateSetObject(proposalKey(pp.ProposalId), string(jsonBytes))
}

// hashPayload returns keccak256(payload) as a [32]byte.
func hashPayload(payload []byte) [32]byte {
	var out [32]byte
	h := sdk.Keccak256(payload)
	if len(h) >= 32 {
		copy(out[:], h[:32])
	}
	return out
}

// emit writes the §D-C-7 event JSON via sdk.Log (the underlying VSC host
// has no dedicated EmitEvent host fn at snapshot — events are emitted as
// structured log lines under a stable prefix that downstream indexers
// pick up). Field names are EXACT per §D-C-7.
func emit(pp *PendingProposal, actor string) {
	hashHex := "0x" + hex.EncodeToString(pp.PayloadHash[:])
	payload := map[string]string{
		"action":       pp.Action,
		"actor":        actor,
		"proposalId":   strconv.FormatUint(pp.ProposalId, 10),
		"payloadHash":  hashHex,
		"queueHeight":  strconv.FormatUint(pp.QueueHeight, 10),
		"execHeight":   strconv.FormatUint(pp.ExecHeight, 10),
		"status":       strconv.FormatUint(uint64(pp.Status), 10),
	}
	jsonBytes, _ := json.Marshal(payload)
	sdk.Log("admin_proposal " + string(jsonBytes))
}

// Propose creates a new PendingProposal record. Caller MUST have already
// passed checkOwner() — propose() does NOT re-check authority. Returns the
// new proposalId on success. Payload is the canonical JSON marshaling of
// the action's existing input struct (§D-C-5).
func Propose(action string, payload []byte, proposer string, blockHeight uint64) (uint64, error) {
	timelock, err := TimelockFor(action)
	if err != nil {
		return 0, err
	}
	id := nextProposalId()
	execHeight := blockHeight + timelock
	pp := &PendingProposal{
		ProposalId:   id,
		Action:       action,
		PayloadHash:  hashPayload(payload),
		Proposer:     proposer,
		QueueHeight:  blockHeight,
		ExecHeight:   execHeight,
		ExpireHeight: execHeight + ExpireWindowBlocks,
		Payload:      payload,
		Status:       StatusPending,
	}
	StoreProposal(pp)
	emit(pp, proposer)
	return id, nil
}

// ExecuteValidated loads + validates a proposal for execution. Caller MUST
// have already passed checkOwner(). Returns the PendingProposal (status
// flipped to Accepted and persisted) so the main.go dispatchAdmin switch
// can route on pp.Action with pp.Payload. The actual handler call happens
// in dispatchAdmin (in main.go) so this file does not import mapping.
func ExecuteValidated(id uint64, blockHeight uint64, actor string) (*PendingProposal, error) {
	pp := LoadProposal(id)
	if pp == nil {
		return nil, errors.New("proposal not found")
	}
	if pp.Status != StatusPending {
		return nil, errors.New("proposal not pending")
	}
	if blockHeight < pp.ExecHeight {
		return nil, errors.New("timelock not elapsed")
	}
	if blockHeight >= pp.ExpireHeight {
		return nil, errors.New("proposal expired")
	}
	// Defense-in-depth: re-verify payload hash matches stored payload.
	// A storage tamper between propose() and execute() would surface as a
	// hash mismatch. Payload is included in JSON; cheap to recompute.
	if hashPayload(pp.Payload) != pp.PayloadHash {
		return nil, errors.New("payload hash mismatch")
	}
	pp.Status = StatusAccepted
	StoreProposal(pp)
	emit(pp, actor)
	return pp, nil
}

// Cancel marks a pending proposal as cancelled. Caller MUST have already
// passed checkOwner(). Cancellation is irreversible at this layer; the
// owner can always propose a new instance.
func Cancel(id uint64, actor string) error {
	pp := LoadProposal(id)
	if pp == nil {
		return errors.New("proposal not found")
	}
	if pp.Status != StatusPending {
		return errors.New("proposal not pending")
	}
	pp.Status = StatusCancelled
	StoreProposal(pp)
	emit(pp, actor)
	return nil
}

// ExpireProposal — anyone-callable cleanup for proposals past their
// expireHeight. RC cost deters spam. Per §D-C-6: the name is
// `expireProposal` (NOT `expireWithdrawal` — that name belongs to Cluster
// E's withdrawal-lifecycle handler; both land in the same WASM binary so
// the names MUST stay distinct).
func ExpireProposal(id uint64, blockHeight uint64, actor string) error {
	pp := LoadProposal(id)
	if pp == nil {
		return errors.New("proposal not found")
	}
	if pp.Status != StatusPending {
		return errors.New("proposal not pending")
	}
	if blockHeight < pp.ExpireHeight {
		return errors.New("proposal not yet expired")
	}
	pp.Status = StatusExpired
	StoreProposal(pp)
	emit(pp, actor)
	return nil
}

// ProposeRequest is the input shape for the `propose` wasmexport.
// `payload_b64` carries the action input struct's canonical JSON, base16-
// encoded so wallets / SDKs can hand-construct propose calls without
// double-JSON-encoding the inner struct. Either field can be empty for
// no-arg actions (pause/unpause/createKey/renewKey/replaceWithdrawal/
// clearNonce — the empty-payload case is allowed and the hash is
// keccak256(empty bytes) which is a fixed value).
type ProposeRequest struct {
	Action     string `json:"action"`
	PayloadHex string `json:"payload_hex"`
}

// ProposeResponse is returned (as JSON in the wasmexport return string).
type ProposeResponse struct {
	ProposalId uint64 `json:"proposal_id"`
	ExecHeight uint64 `json:"exec_height"`
}

// ExecuteRequest / CancelRequest / ExpireRequest all just carry the id.
type IdRequest struct {
	ProposalId uint64 `json:"proposal_id"`
}

// DecodePayloadHex helper — wasmexport input strings are hex-encoded bytes.
// Returns (decodedBytes, error). An empty / missing string yields nil bytes
// (which hashes to keccak256-of-empty, a fixed sentinel — acceptable).
func DecodePayloadHex(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	// Strip optional 0x prefix.
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	return hex.DecodeString(s)
}
