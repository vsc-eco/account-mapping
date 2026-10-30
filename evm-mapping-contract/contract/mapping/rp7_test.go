package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/rlp"
	"evm-mapping-contract/sdk"
)

// RP-7: a deposit through MagiDeposit credits the recipient its Deposit log
// names. Old code credited only the L1 sender (a smart wallet, custodian or
// contract, which cannot use that address on Magi) and had no "contract" type.

var (
	rp7Vault = [20]byte{0x88, 0xcb, 0xba, 0x6b, 0x5e, 0x5d, 0x2c, 0x20, 0xd9, 0xcf, 0xc5, 0x5f, 0x3b, 0x2f, 0xc1, 0x8d, 0x07, 0x3c, 0xcf, 0x14}
	rp7USDC  = [20]byte{19: 0xc0}
	rp7User  = [20]byte{0: 0xa1, 19: 0xce}
)

type rp7World struct {
	t       *testing.T
	headers map[uint64]string
	n       uint64
}

func newRP7World(t *testing.T) *rp7World {
	t.Helper()
	sdk.ResetStubState()
	sdk.ResetTestState()
	w := &rp7World{t: t, headers: map[uint64]string{}, n: 200}
	sdk.StateSetObject(constants.VerifierContractIdKey, "vsc1verifierstub")
	sdk.StubSetContractReadResponder(func(_, key string) *string {
		if key == constants.LastHeightKey {
			h := strconv.FormatUint(w.n, 10)
			return &h
		}
		if strings.HasPrefix(key, constants.BlockPrefix) {
			n, _ := strconv.ParseUint(strings.TrimPrefix(key, constants.BlockPrefix), 10, 64)
			if h, ok := w.headers[n]; ok {
				return &h
			}
		}
		return nil
	})
	sdk.StateSetObject(constants.TokenRegistryPrefix+"1-"+hex.EncodeToString(rp7USDC[:]), "USDC|6|1000")
	sdk.StateSetObject(constants.AllowedSymbolPrefix+"USDC", "1")
	SetSupply("eth", Supply{Active: new(big.Int), User: new(big.Int), Fee: new(big.Int)})
	SetSupply("USDC", Supply{Active: new(big.Int), User: new(big.Int), Fee: new(big.Int)})
	return w
}

func word32(v *big.Int) []byte {
	b := make([]byte, 32)
	v.FillBytes(b)
	return b
}

func addrTopic(a [20]byte) []byte {
	t := make([]byte, 32)
	copy(t[12:], a[:])
	return t
}

func rp7Log(emitter [20]byte, data []byte, topics ...[]byte) []byte {
	var ts [][]byte
	for _, t := range topics {
		ts = append(ts, rlp.EncodeBytes(t))
	}
	return rlp.EncodeList(rlp.EncodeBytes(emitter[:]), rlp.EncodeList(ts...), rlp.EncodeBytes(data))
}

func transferLog(token, from, to [20]byte, amount int64) []byte {
	return rp7Log(token, word32(big.NewInt(amount)), TransferEventSig[:], addrTopic(from), addrTopic(to))
}

// depositLog is MagiDeposit's Deposit log as solc encodes it.
func depositLog(dc, sender, token [20]byte, amount *big.Int, recipient string) []byte {
	data := append(word32(amount), word32(big.NewInt(64))...)
	data = append(data, word32(big.NewInt(int64(len(recipient))))...)
	padded := make([]byte, (len(recipient)+31)/32*32)
	copy(padded, recipient)
	data = append(data, padded...)
	return rp7Log(dc, data, depositEventSig[:], addrTopic(sender), addrTopic(token))
}

// mine plants a type-2 receipt with logs at TxIndex 1 of a new block.
func (w *rp7World) mine(status uint64, logs ...[]byte) (uint64, []byte, [][]byte) {
	w.n++
	receipt := append([]byte{0x02}, rlp.EncodeList(rlp.EncodeUint64(status), rlp.EncodeUint64(90_000),
		rlp.EncodeBytes(make([]byte, 256)), rlp.EncodeList(logs...))...)
	root, nodes := buildSingleLeafMPT(receipt)
	w.headers[w.n] = (&blocklist.EthBlockHeader{BlockNumber: w.n, ReceiptsRoot: root, BaseFeePerGas: 1e9, GasLimit: 30_000_000, ChainId: 1}).Serialize()
	return w.n, receipt, nodes
}

func mapContract(n uint64, nodes [][]byte, logIndex uint64) error {
	return HandleMap(&MapParams{TxData: VerificationRequest{BlockHeight: n, TxIndex: 1, LogIndex: logIndex, DepositType: "contract",
		ReceiptProof: base64.StdEncoding.EncodeToString(concatBytes(nodes))}}, rp7Vault, 1)
}

func mapERC20(n uint64, receipt []byte, nodes [][]byte, logIndex uint64) error {
	return HandleMap(&MapParams{TxData: VerificationRequest{BlockHeight: n, TxIndex: 1, LogIndex: logIndex, DepositType: "erc20",
		RawHex: hex.EncodeToString(receipt), MerkleProofHex: hex.EncodeToString(concatBytes(nodes)),
		TokenAddress: "0x" + hex.EncodeToString(rp7USDC[:])}}, rp7Vault, 1)
}

func TestRP7_DepositContractAddressIsTheCREATE2Address(t *testing.T) {
	code, _ := hex.DecodeString(constants.DepositCreationCode)
	if hex.EncodeToString(crypto.Keccak256(code)) != constants.DepositCreationCodeHash {
		t.Fatal("DepositCreationCode does not hash to DepositCreationCodeHash (l1-deposit pins the same hash)")
	}
	// cast create2 --deployer 0x4e59..956C --salt 0 --init-code <creation ++ abi(vault)>
	if got := crypto.ChecksumHex(DepositContractAddress(rp7Vault)); got != "0x992421A176328dACaAa0f50ee5c840d49bd16DD7" {
		t.Fatalf("MagiDeposit address for vault 0x88CB..CF14 = %s, want cast's 0x992421A176328dACaAa0f50ee5c840d49bd16DD7", got)
	}
}

func TestRP7_TokenDepositCreditsTheRecipientNotTheSender(t *testing.T) {
	for _, order := range []string{"contract first", "erc20 first"} {
		t.Run(order, func(t *testing.T) {
			w := newRP7World(t)
			dc := DepositContractAddress(rp7Vault)
			n, receipt, nodes := w.mine(1, transferLog(rp7USDC, rp7User, rp7Vault, 3_000_000), depositLog(dc, rp7User, rp7USDC, big.NewInt(3_000_000), "hive:bob"))
			if order == "erc20 first" {
				// Anyone can map: mapping the paying Transfer as a plain ERC-20
				// deposit must not credit the sender instead of the recipient.
				if err := mapERC20(n, receipt, nodes, 0); err == nil || !strings.Contains(err.Error(), "paid a MagiDeposit deposit") {
					t.Fatalf("erc20 map of the paying Transfer: %v, want refused", err)
				}
			}
			if err := mapContract(n, nodes, 1); err != nil {
				t.Fatalf("contract map: %v", err)
			}
			if got := GetBalance("hive:bob", "USDC"); got.Cmp(big.NewInt(3_000_000)) != 0 {
				t.Fatalf("hive:bob has %s USDC, want 3000000", got)
			}
			if got := GetBalance(crypto.AddressToDID(rp7User), "USDC"); got.Sign() != 0 {
				t.Fatalf("the sender was credited %s", got)
			}
			// Refused by the observed mark the contract map left on it (the
			// ERC-20 path checks that before its own pairing refusal).
			if err := mapERC20(n, receipt, nodes, 0); err == nil || !strings.Contains(err.Error(), "already processed") {
				t.Fatalf("the paying Transfer through the ERC-20 path after the contract map: %v", err)
			}
			if err := mapContract(n, nodes, 1); err == nil || !strings.Contains(err.Error(), "already processed") {
				t.Fatalf("contract map twice: %v", err)
			}
			if s := GetSupply("USDC"); s.Active.Cmp(big.NewInt(3_000_000)) != 0 || s.User.Cmp(big.NewInt(3_000_000)) != 0 {
				t.Fatalf("supply %+v, want 3000000 active and user", s)
			}
		})
	}
}

func TestRP7_ETHDepositCreditsTheRecipientLessTheReserveShare(t *testing.T) {
	w := newRP7World(t)
	n, _, nodes := w.mine(1, depositLog(DepositContractAddress(rp7Vault), rp7User, [20]byte{}, big.NewInt(1e18), "hive:bob"))
	if err := mapContract(n, nodes, 0); err != nil {
		t.Fatal(err)
	}
	if got := GetBalance("hive:bob", "eth"); got.Cmp(big.NewInt(99e16)) != 0 {
		t.Fatalf("hive:bob has %s wei, want 0.99 ETH (1%% to the reserve, as a plain ETH deposit)", got)
	}
	if getGasReserve().Cmp(big.NewInt(1e16)) != 0 {
		t.Fatalf("reserve %s, want 0.01 ETH", getGasReserve())
	}
	if err := mapContract(n, nodes, 0); err == nil || !strings.Contains(err.Error(), "already processed") {
		t.Fatalf("the same ETH deposit mapped twice: %v", err)
	}
	if got := GetBalance("hive:bob", "eth"); got.Cmp(big.NewInt(99e16)) != 0 {
		t.Fatalf("hive:bob has %s wei after a repeat map", got)
	}
}

func TestRP7_Refusals(t *testing.T) {
	w := newRP7World(t)
	dc := DepositContractAddress(rp7Vault)
	other := DepositContractAddress([20]byte{0x01})
	usdc := big.NewInt(3_000_000)
	for _, tc := range []struct {
		name, want string
		status     uint64
		logs       [][]byte
		li         uint64
	}{
		{"another vault's deposit contract", "not a Deposit log of this vault", 1, [][]byte{depositLog(other, rp7User, [20]byte{}, big.NewInt(1e18), "hive:bob")}, 0},
		{"a Transfer, not a Deposit", "not a Deposit log of this vault", 1, [][]byte{transferLog(rp7USDC, rp7User, rp7Vault, 3_000_000)}, 0},
		{"the paying transfer is short", "token transfer to the vault is not in the receipt", 1, [][]byte{transferLog(rp7USDC, rp7User, rp7Vault, 2_000_000), depositLog(dc, rp7User, rp7USDC, usdc, "hive:bob")}, 1},
		{"no paying transfer", "token transfer to the vault is not in the receipt", 1, [][]byte{depositLog(dc, rp7User, rp7USDC, usdc, "hive:bob")}, 0},
		{"paid to another address", "token transfer to the vault is not in the receipt", 1, [][]byte{transferLog(rp7USDC, rp7User, [20]byte{9}, 3_000_000), depositLog(dc, rp7User, rp7USDC, usdc, "hive:bob")}, 1},
		{"an unregistered token", "token not registered", 1, [][]byte{transferLog([20]byte{7}, rp7User, rp7Vault, 3_000_000), depositLog(dc, rp7User, [20]byte{7}, usdc, "hive:bob")}, 1},
		{"a reverted tx", "receipt status", 0, [][]byte{depositLog(dc, rp7User, [20]byte{}, big.NewInt(1e18), "hive:bob")}, 0},
		{"a zero amount", "must be positive", 1, [][]byte{depositLog(dc, rp7User, [20]byte{}, big.NewInt(0), "hive:bob")}, 0},
		{"log index past the logs", "log_index out of range", 1, [][]byte{depositLog(dc, rp7User, [20]byte{}, big.NewInt(1e18), "hive:bob")}, 1},
	} {
		n, _, nodes := w.mine(tc.status, tc.logs...)
		if err := mapContract(n, nodes, tc.li); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	if GetBalance("hive:bob", "eth").Sign() != 0 || GetBalance("hive:bob", "USDC").Sign() != 0 {
		t.Fatal("a refused deposit credited hive:bob")
	}
}

// A transfer the deposit contract did not pay with stays mappable as a plain
// ERC-20 deposit (credited to its sender), so nothing is stranded; an invalid
// recipient is credited to the sender (A5).
func TestRP7_OnlyThePayingTransferIsTakenFromTheERC20Path(t *testing.T) {
	w := newRP7World(t)
	dc := DepositContractAddress(rp7Vault)
	wallet := [20]byte{0: 0x5a, 19: 0xfe}
	n, receipt, nodes := w.mine(1,
		transferLog(rp7USDC, wallet, rp7Vault, 5_000_000), // a plain transfer in the same tx
		transferLog(rp7USDC, wallet, rp7Vault, 3_000_000), // paid the deposit below
		depositLog(dc, wallet, rp7USDC, big.NewInt(3_000_000), "hive:bob"))
	if err := mapContract(n, nodes, 2); err != nil {
		t.Fatal(err)
	}
	if err := mapERC20(n, receipt, nodes, 0); err != nil {
		t.Fatalf("the unrelated plain transfer: %v", err)
	}
	if err := mapERC20(n, receipt, nodes, 1); err == nil {
		t.Fatal("the paying transfer was mappable through the ERC-20 path")
	}
	if GetBalance("hive:bob", "USDC").Cmp(big.NewInt(3_000_000)) != 0 || GetBalance(crypto.AddressToDID(wallet), "USDC").Cmp(big.NewInt(5_000_000)) != 0 {
		t.Fatalf("bob %s wallet %s, want 3000000 and 5000000", GetBalance("hive:bob", "USDC"), GetBalance(crypto.AddressToDID(wallet), "USDC"))
	}

	n, _, nodes = w.mine(1, depositLog(dc, wallet, [20]byte{}, big.NewInt(1e18), "not a magi account"))
	if err := mapContract(n, nodes, 0); err != nil {
		t.Fatal(err)
	}
	if GetBalance(crypto.AddressToDID(wallet), "eth").Cmp(big.NewInt(99e16)) != 0 {
		t.Fatal("an invalid recipient was not credited to the sender")
	}
}

func TestRP7_AnotherChainsHeaderIsRefused(t *testing.T) {
	w := newRP7World(t)
	n, _, nodes := w.mine(1, depositLog(DepositContractAddress(rp7Vault), rp7User, [20]byte{}, big.NewInt(1e18), "hive:bob"))
	h, _ := blocklist.DeserializeHeader(w.headers[n])
	h.ChainId = 11155111
	w.headers[n] = h.Serialize()
	if err := mapContract(n, nodes, 0); err == nil || !strings.Contains(err.Error(), "chain id") {
		t.Fatalf("a deposit under a Sepolia-labelled header on chain 1: %v", err)
	}
}

func mapERC20B64(n uint64, nodes [][]byte, logIndex uint64) error {
	return HandleMap(&MapParams{TxData: VerificationRequest{BlockHeight: n, TxIndex: 1, LogIndex: logIndex, DepositType: "erc20",
		ReceiptProof: base64.StdEncoding.EncodeToString(concatBytes(nodes)), TokenAddress: "0x" + hex.EncodeToString(rp7USDC[:])}}, rp7Vault, 1)
}

// ERC20-PAYLOAD-1: an ERC-20 deposit maps from a base64 receipt proof (the
// receipt taken from its leaf), and the same deposit cannot then be mapped
// again in the hex form, or the reverse. A receipt with 30 logs fits the
// node's 8,192-byte payload only this way.
func TestERC20PAYLOAD1_Base64ReceiptProof(t *testing.T) {
	w := newRP7World(t)
	logs := [][]byte{transferLog(rp7USDC, rp7User, rp7Vault, 3_000_000)}
	for i := 0; i < 29; i++ { // an aggregator's swap logs around the transfer
		logs = append(logs, transferLog([20]byte{byte(i + 1)}, [20]byte{2}, [20]byte{3}, int64(i+1)))
	}
	n, receipt, nodes := w.mine(1, logs...)
	b64, _ := json.Marshal(VerificationRequest{BlockHeight: n, TxIndex: 1, DepositType: "erc20", TokenAddress: "0x" + hex.EncodeToString(rp7USDC[:]),
		ReceiptProof: base64.StdEncoding.EncodeToString(concatBytes(nodes))})
	hexForm, _ := json.Marshal(VerificationRequest{BlockHeight: n, TxIndex: 1, DepositType: "erc20", TokenAddress: "0x" + hex.EncodeToString(rp7USDC[:]),
		RawHex: hex.EncodeToString(receipt), MerkleProofHex: hex.EncodeToString(concatBytes(nodes))})
	if len(hexForm) <= 8192 || len(b64) > 8192 {
		t.Fatalf("payloads: hex %d B, base64 %d B; want the hex form over the 8,192 cap and base64 under it", len(hexForm), len(b64))
	}
	if err := mapERC20B64(n, nodes, 0); err != nil {
		t.Fatalf("base64 map: %v", err)
	}
	if got := GetBalance(crypto.AddressToDID(rp7User), "USDC"); got.Cmp(big.NewInt(3_000_000)) != 0 {
		t.Fatalf("credited %s, want 3000000", got)
	}
	if err := mapERC20(n, receipt, nodes, 0); err == nil || !strings.Contains(err.Error(), "already processed") {
		t.Fatalf("the hex form after the base64 map: %v, want already processed", err)
	}
	// A base64 proof that is not the block's receipt is refused.
	_, _, otherNodes := w.mine(1, transferLog(rp7USDC, rp7User, rp7Vault, 9))
	if err := mapERC20B64(n, otherNodes, 0); err == nil {
		t.Fatal("another block's receipt proof was accepted")
	}
}

// A transfer from one of the vault's own addresses (a migration sweep between
// generations, or a withdrawal paid to the vault) is not a deposit: crediting
// it mints the moved amount a second time (A01 devnet weather wave: the ETH
// sweep was mapped and the books ran 6 ETH over custody). Mapping is
// permissionless, so the contract refuses it on every deposit path.
func TestOwnTransfer_TheVaultsOwnTransferIsNotADeposit(t *testing.T) {
	w := newRP7World(t)
	n, _, nodes := w.mine(1, depositLog(DepositContractAddress(rp7Vault), rp7Vault, [20]byte{}, big.NewInt(1e18), "hive:bob"))
	if err := mapContract(n, nodes, 0); err == nil || !strings.Contains(err.Error(), "vault's own addresses") {
		t.Fatalf("a MagiDeposit deposit sent by the vault: %v", err)
	}
	n, receipt, nodes := w.mine(1, transferLog(rp7USDC, rp7Vault, rp7Vault, 5000))
	if err := mapERC20(n, receipt, nodes, 0); err == nil || !strings.Contains(err.Error(), "vault's own addresses") {
		t.Fatalf("a token transfer from the vault to the vault: %v", err)
	}
	if got := GetBalance(crypto.AddressToDID(rp7Vault), "USDC"); got.Sign() != 0 {
		t.Fatalf("the vault's own address was credited %s USDC", got)
	}
	if s := GetSupply("USDC"); s.User.Sign() != 0 || s.Active.Sign() != 0 {
		t.Fatalf("supply moved: %+v", s)
	}
	// A user's deposit still lands.
	n, receipt, nodes = w.mine(1, transferLog(rp7USDC, rp7User, rp7Vault, 5000))
	if err := mapERC20(n, receipt, nodes, 0); err != nil {
		t.Fatalf("a user's token deposit: %v", err)
	}
}
