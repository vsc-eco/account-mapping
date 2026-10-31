package mapping

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/sdk"
)

// A01: the EVM vault rolls keys like the BTC vault (vault rotation v2, itself
// THORChain's churn). Each generation is a fresh TSS key and so a fresh L1
// address; a superseded generation's funds are swept to the active one and the
// old key is left holding nothing. Before this the vault was one key reshared
// for good, so the shares of every past committee could still sign for all the
// funds (PRUNED A01, proven on devnet 2026-10-29).
//
// The registry is byte-for-byte the BTC contract's (91-byte entries under "v",
// counters "vn"/"va"), so the node reads both contracts with one decoder
// (go-vsc-node lib/btcvault). Backup is always zero here: an Ethereum address
// has no CSV backup path. Heights are Ethereum L1 block heights.

type VaultStatus uint8

const (
	VaultStatusPending  VaultStatus = 0
	VaultStatusActive   VaultStatus = 1
	VaultStatusRetiring VaultStatus = 2
	VaultStatusDraining VaultStatus = 3
	VaultStatusInactive VaultStatus = 4
	VaultStatusPurged   VaultStatus = 5
)

// CompressedPubKey is a 33-byte compressed secp256k1 public key.
type CompressedPubKey [33]byte

// Vault is one generation of the vault.
type Vault struct {
	Generation      uint32
	Primary         CompressedPubKey
	Backup          CompressedPubKey // zero on EVM; kept for the shared layout
	Status          VaultStatus
	Predecessor     uint32 // == Generation for a genesis vault
	CreatedHeight   uint32
	ActivatedHeight uint32
	RetiredHeight   uint32
	InactiveHeight  uint32 // purge-grace anchor
}

type VaultRegistry []Vault

// VaultEntrySize is the packed width of one registry entry: 4 gen + 33 primary +
// 33 backup + 1 status + 4 predecessor + 4x4 heights. It must equal the BTC
// contract's and the node's (lib/btcvault).
const VaultEntrySize = 91

func MarshalVaultRegistry(v VaultRegistry) []byte {
	buf := make([]byte, len(v)*VaultEntrySize)
	for i := range v {
		off := i * VaultEntrySize
		e := &v[i]
		binary.BigEndian.PutUint32(buf[off:], e.Generation)
		copy(buf[off+4:off+37], e.Primary[:])
		copy(buf[off+37:off+70], e.Backup[:])
		buf[off+70] = byte(e.Status)
		binary.BigEndian.PutUint32(buf[off+71:], e.Predecessor)
		binary.BigEndian.PutUint32(buf[off+75:], e.CreatedHeight)
		binary.BigEndian.PutUint32(buf[off+79:], e.ActivatedHeight)
		binary.BigEndian.PutUint32(buf[off+83:], e.RetiredHeight)
		binary.BigEndian.PutUint32(buf[off+87:], e.InactiveHeight)
	}
	return buf
}

func UnmarshalVaultRegistry(data []byte) (VaultRegistry, error) {
	if len(data)%VaultEntrySize != 0 {
		return nil, errors.New("invalid vault registry: length not a multiple of VaultEntrySize")
	}
	out := make(VaultRegistry, len(data)/VaultEntrySize)
	for i := range out {
		off := i * VaultEntrySize
		out[i].Generation = binary.BigEndian.Uint32(data[off:])
		copy(out[i].Primary[:], data[off+4:off+37])
		copy(out[i].Backup[:], data[off+37:off+70])
		out[i].Status = VaultStatus(data[off+70])
		out[i].Predecessor = binary.BigEndian.Uint32(data[off+71:])
		out[i].CreatedHeight = binary.BigEndian.Uint32(data[off+75:])
		out[i].ActivatedHeight = binary.BigEndian.Uint32(data[off+79:])
		out[i].RetiredHeight = binary.BigEndian.Uint32(data[off+83:])
		out[i].InactiveHeight = binary.BigEndian.Uint32(data[off+87:])
	}
	return out, nil
}

// VaultKeyName is the TSS key name of a generation: generation 0 keeps the
// bridge's original "primary" key, generation N is "primaryv<N>" (key names are
// alphanumeric). The node's key id is "<contractId>-" + this.
func VaultKeyName(gen uint32) string {
	if gen == 0 {
		return constants.VaultKeyBaseName
	}
	return constants.VaultKeyBaseName + "v" + strconv.FormatUint(uint64(gen), 10)
}

func stateBytes(key string) []byte {
	if s := sdk.StateGetObject(key); s != nil {
		return []byte(*s)
	}
	return nil
}

// vaultStateMemo is the registry as this call last read or wrote it. A
// contract call runs in a fresh wasm instance and every write goes through
// SaveVaultState, so it is never stale; it spares the re-reads one withdrawal
// makes (active key, vault address, issuance gate, availability: ~700 RC).
// Native tests clear it with the SDK's test state.
var vaultStateMemo *vaultStateSnap

type vaultStateSnap struct {
	vaults       VaultRegistry
	next, active uint32
}

func init() { sdk.OnTestReset(func() { vaultStateMemo = nil }) }

func memoVaultState(vaults VaultRegistry, next, active uint32) {
	vaultStateMemo = &vaultStateSnap{append(VaultRegistry(nil), vaults...), next, active}
}

// LoadVaultState reads the registry and its two counters. The caller gets its
// own copy and may change it.
func LoadVaultState() (VaultRegistry, uint32, uint32, error) {
	if m := vaultStateMemo; m != nil {
		return append(VaultRegistry(nil), m.vaults...), m.next, m.active, nil
	}
	var vaults VaultRegistry
	if raw := stateBytes(constants.VaultRegistryKey); len(raw) > 0 {
		v, err := UnmarshalVaultRegistry(raw)
		if err != nil {
			return nil, 0, 0, ce.NewContractError(ce.ErrStateAccess, "error decoding vault registry: "+err.Error())
		}
		vaults = v
	}
	var nextGen, activeGen uint32
	if s := stateBytes(constants.VaultNextGenKey); len(s) == 4 {
		nextGen = binary.BigEndian.Uint32(s)
	}
	if s := stateBytes(constants.VaultActiveGenKey); len(s) == 4 {
		activeGen = binary.BigEndian.Uint32(s)
	}
	memoVaultState(vaults, nextGen, activeGen)
	return vaults, nextGen, activeGen, nil
}

// SaveVaultState writes the registry and its counters.
func SaveVaultState(vaults VaultRegistry, nextGen, activeGen uint32) {
	memoVaultState(vaults, nextGen, activeGen)
	sdk.StateSetObject(constants.VaultRegistryKey, string(MarshalVaultRegistry(vaults)))
	var nb, ab [4]byte
	binary.BigEndian.PutUint32(nb[:], nextGen)
	binary.BigEndian.PutUint32(ab[:], activeGen)
	sdk.StateSetObject(constants.VaultNextGenKey, string(nb[:]))
	sdk.StateSetObject(constants.VaultActiveGenKey, string(ab[:]))
}

// tssKeyParts splits a TssGetKey response "status,pubkeyHex,algo[,checkSig[,reshared]]".
func tssKeyParts(name string) []string {
	return strings.Split(sdk.TssGetKey(name), ",")
}

// tssKeyPub returns a key's 33-byte public key when it is an ecdsa key in one of
// the given statuses.
func tssKeyPub(name string, statuses ...string) (CompressedPubKey, bool) {
	var pub CompressedPubKey
	parts := tssKeyParts(name)
	if len(parts) < 3 || parts[2] != "ecdsa" {
		return pub, false
	}
	ok := false
	for _, s := range statuses {
		ok = ok || parts[0] == s
	}
	if !ok {
		return pub, false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(parts[1], "0x"))
	if err != nil || len(raw) != 33 {
		return pub, false
	}
	copy(pub[:], raw)
	return pub, true
}

// FoldLegacyKeyIfNeeded folds the bridge's pre-rotation "primary" key into
// generation 0 when there is no registry yet (BTC FoldLegacyGen0IfNeeded): Active
// when the key has passed the vault check (attestVault), so a running bridge keeps
// its vault. Readers fold only that case. The ceremony ops (allowPending) also
// fold a key that never passed the check, as Pending, so it activates through
// activateKey like any new generation. Idempotent; never touches a populated
// registry, so a contract upgraded in place can never mint a divergent
// generation 0.
func FoldLegacyKeyIfNeeded(allowPending bool) bool {
	if m := vaultStateMemo; m != nil && len(m.vaults) > 0 {
		return false
	}
	if len(stateBytes(constants.VaultRegistryKey)) > 0 {
		return false
	}
	pub, ok := tssKeyPub(constants.VaultKeyBaseName, "active", "deprecated")
	if !ok {
		return false
	}
	gen0 := Vault{Generation: 0, Primary: pub, Status: VaultStatusPending, Predecessor: 0}
	if vaultVerified(hex.EncodeToString(pub[:])) {
		gen0.Status = VaultStatusActive
	} else if !allowPending {
		return false
	}
	SaveVaultState(VaultRegistry{gen0}, 1, 0)
	sdk.Log("vaultfold|gen0|s=" + strconv.Itoa(int(gen0.Status)))
	return true
}

func isZeroKey(k CompressedPubKey) bool { return k == CompressedPubKey{} }

func isGenesisVault(v *Vault) bool { return v.Predecessor == v.Generation }

func firstVaultWithStatus(vaults VaultRegistry, status VaultStatus) int {
	for i := range vaults {
		if vaults[i].Status == status {
			return i
		}
	}
	return -1
}

func countVaultsWithStatus(vaults VaultRegistry, status VaultStatus) int {
	n := 0
	for i := range vaults {
		if vaults[i].Status == status {
			n++
		}
	}
	return n
}

// isFundHoldingStatus: a generation that holds, or may still receive, funds
// (BTC isFundHoldingStatus). Its address is credited for deposits and its key
// kept renewed. Pending (nothing sent there yet) and Purged (address retired)
// are not.
func isFundHoldingStatus(s VaultStatus) bool {
	return s == VaultStatusActive || s == VaultStatusRetiring ||
		s == VaultStatusDraining || s == VaultStatusInactive
}

func isSupersededStatus(s VaultStatus) bool {
	return s == VaultStatusRetiring || s == VaultStatusDraining || s == VaultStatusInactive
}

// GenAddress is a generation's L1 address, cached per public key.
func GenAddress(v *Vault) ([20]byte, bool) {
	if isZeroKey(v.Primary) {
		return [20]byte{}, false
	}
	pubHex := hex.EncodeToString(v.Primary[:])
	cacheKey := constants.VaultAddrCachePrefix + strconv.FormatUint(uint64(v.Generation), 10)
	if c := sdk.StateGetObject(cacheKey); c != nil {
		if i := strings.IndexByte(*c, '|'); i > 0 && (*c)[:i] == pubHex {
			if addr, err := crypto.HexToAddress((*c)[i+1:]); err == nil {
				return addr, true
			}
		}
	}
	addr, err := crypto.PubkeyAddress(v.Primary[:])
	if err != nil {
		return [20]byte{}, false
	}
	sdk.StateSetObject(cacheKey, pubHex+"|"+crypto.AddressToHex(addr))
	return addr, true
}

// ActiveVault returns the active generation, folding a legacy key first.
func ActiveVault() (Vault, bool) {
	FoldLegacyKeyIfNeeded(false)
	vaults, _, activeGen, err := LoadVaultState()
	if err != nil {
		return Vault{}, false
	}
	for i := range vaults {
		if vaults[i].Status == VaultStatusActive && vaults[i].Generation == activeGen && !isZeroKey(vaults[i].Primary) {
			return vaults[i], true
		}
	}
	return Vault{}, false
}

// ActiveKeyName is the TSS key name of the active generation ("primary" before
// any rotation, and for a contract with no registry).
func ActiveKeyName() string {
	if v, ok := ActiveVault(); ok {
		return VaultKeyName(v.Generation)
	}
	return constants.VaultKeyBaseName
}

// SpendGen is the fund-holding generation a pending spend was issued from (the
// address in its VaultAtQueue). Its key, not necessarily the active one,
// signs the spend's replacement or roll (ROT-HALT-1: a generation finishes its
// own in-flight withdrawals after its cut-over).
func SpendGen(ps *PendingSpend) (fundHoldingGen, bool) {
	addr, err := crypto.HexToAddress(ps.VaultAtQueue)
	if err != nil || addr == ([20]byte{}) {
		return fundHoldingGen{}, false
	}
	for _, g := range FundHoldingGens() {
		if g.Address == addr {
			return g, true
		}
	}
	return fundHoldingGen{}, false
}

// spendKeyName is the TSS key that signs for ps: its generation's, else (a
// pre-rotation bridge) the active key.
func spendKeyName(ps *PendingSpend) string {
	if g, ok := SpendGen(ps); ok {
		return VaultKeyName(g.Generation)
	}
	return ActiveKeyName()
}

// fundHoldingGen is a fund-holding generation with its L1 address.
type fundHoldingGen struct {
	Vault
	Address [20]byte
}

// FundHoldingGens lists every generation whose address is credited for
// deposits, active first, then the superseded ones in registry order.
func FundHoldingGens() []fundHoldingGen {
	FoldLegacyKeyIfNeeded(false)
	vaults, _, _, err := LoadVaultState()
	if err != nil {
		return nil
	}
	var out []fundHoldingGen
	for _, want := range []bool{true, false} {
		for i := range vaults {
			v := vaults[i]
			if !isFundHoldingStatus(v.Status) || (v.Status == VaultStatusActive) != want {
				continue
			}
			if addr, ok := GenAddress(&v); ok {
				out = append(out, fundHoldingGen{Vault: v, Address: addr})
			}
		}
	}
	return out
}

type vaultInfoGen struct {
	Generation  uint32            `json:"generation"`
	Status      string            `json:"status"`
	Key         string            `json:"key"`
	Address     string            `json:"address,omitempty"`
	Predecessor uint32            `json:"predecessor"`
	Created     uint32            `json:"created"`
	Activated   uint32            `json:"activated,omitempty"`
	Retired     uint32            `json:"retired,omitempty"`
	Inactive    uint32            `json:"inactive,omitempty"`
	Books       map[string]string `json:"books,omitempty"`
	SweepNonce  *uint64           `json:"sweep_nonce,omitempty"`
}

type vaultInfo struct {
	Active      *uint32        `json:"active,omitempty"`
	Generations []vaultInfoGen `json:"generations"`
	OpenSweeps  []string       `json:"open_sweeps,omitempty"`
}

var vaultStatusNames = [...]string{"pending", "active", "retiring", "draining", "inactive", "purged"}

func (s VaultStatus) String() string {
	if int(s) < len(vaultStatusNames) {
		return vaultStatusNames[s]
	}
	return "unknown"
}

// VaultInfoJSON describes every generation for the bot and front ends: status,
// key, address, and for a superseded generation what it still holds.
func VaultInfoJSON() string {
	FoldLegacyKeyIfNeeded(false)
	vaults, _, activeGen, err := LoadVaultState()
	info := vaultInfo{Generations: []vaultInfoGen{}, OpenSweeps: openSweeps()}
	if err == nil {
		for i := range vaults {
			v := vaults[i]
			g := vaultInfoGen{
				Generation: v.Generation, Status: v.Status.String(), Key: VaultKeyName(v.Generation),
				Predecessor: v.Predecessor, Created: v.CreatedHeight, Activated: v.ActivatedHeight,
				Retired: v.RetiredHeight, Inactive: v.InactiveHeight,
			}
			if addr, ok := GenAddress(&v); ok {
				g.Address = crypto.AddressToHex(addr)
			}
			if v.Status == VaultStatusActive && v.Generation == activeGen {
				a := v.Generation
				info.Active = &a
			}
			if isSupersededStatus(v.Status) {
				g.Books = map[string]string{}
				for _, asset := range vaultAssets() {
					if b := VaultBook(v.Generation, asset); b.Sign() > 0 {
						g.Books[asset] = b.String()
					}
				}
				n := SweepNonce(v.Generation)
				g.SweepNonce = &n
			}
			info.Generations = append(info.Generations, g)
		}
	}
	out, _ := json.Marshal(info)
	return string(out)
}
