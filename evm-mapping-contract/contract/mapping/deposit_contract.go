package mapping

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"

	"evm-mapping-contract/contract/blocklist"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/contract/crypto"
	"evm-mapping-contract/contract/mpt"
)

// RP-7: a deposit made through MagiDeposit is credited to the Magi recipient
// its Deposit log names, not to the L1 sender (a smart wallet, custodian or
// contract cannot use its own address on Magi). See constants/deposit_code.go.

var depositEventSig = func() [32]byte {
	var h [32]byte
	b, _ := hex.DecodeString(constants.DepositEventSigHex)
	copy(h[:], b)
	return h
}()

// DepositContractAddress is MagiDeposit's address for vault: CREATE2 through
// the deterministic deployment proxy, salt 0, init code = creation code ++
// abi.encode(vault).
func DepositContractAddress(vault [20]byte) [20]byte {
	code, _ := hex.DecodeString(constants.DepositCreationCode)
	var arg [32]byte
	copy(arg[12:], vault[:])
	initHash := crypto.Keccak256(append(code, arg[:]...))
	proxy, _ := hex.DecodeString(constants.Create2DeployerHex)
	buf := make([]byte, 0, 85)
	buf = append(buf, 0xff)
	buf = append(buf, proxy...)
	buf = append(buf, make([]byte, 32)...) // salt 0
	buf = append(buf, initHash...)
	var a [20]byte
	copy(a[:], crypto.Keccak256(buf)[12:])
	return a
}

// contractDeposit is a decoded MagiDeposit Deposit log.
type contractDeposit struct {
	sender, token [20]byte // token: zero for ETH
	amount        *big.Int
	recipient     string
}

// topicAddress reads a canonical address topic (12 zero bytes, then 20).
func topicAddress(t [32]byte) ([20]byte, bool) {
	var a [20]byte
	for i := 0; i < 12; i++ {
		if t[i] != 0 {
			return a, false
		}
	}
	copy(a[:], t[12:])
	return a, true
}

// parseDepositLog decodes l if it is a Deposit log emitted by dc, in the exact
// ABI encoding MagiDeposit's compiler produces: data = amount, offset 0x40,
// length, the recipient bytes zero-padded to 32.
func parseDepositLog(l ParsedLog, dc [20]byte) (*contractDeposit, bool) {
	if l.Address != dc || len(l.Topics) != 3 || l.Topics[0] != depositEventSig {
		return nil, false
	}
	sender, ok1 := topicAddress(l.Topics[1])
	token, ok2 := topicAddress(l.Topics[2])
	if !ok1 || !ok2 || len(l.Data) < 96 {
		return nil, false
	}
	off := new(big.Int).SetBytes(l.Data[32:64])
	n := new(big.Int).SetBytes(l.Data[64:96])
	if off.Cmp(big.NewInt(64)) != 0 || n.Sign() <= 0 || n.Cmp(big.NewInt(constants.MaxDepositRecipientLen)) > 0 {
		return nil, false
	}
	ln := int(n.Int64())
	if len(l.Data) != 96+(ln+31)/32*32 {
		return nil, false
	}
	for _, b := range l.Data[96+ln:] {
		if b != 0 {
			return nil, false
		}
	}
	return &contractDeposit{
		sender: sender, token: token,
		amount:    new(big.Int).SetBytes(l.Data[0:32]),
		recipient: string(l.Data[96 : 96+ln]),
	}, true
}

// pairedTransfer is the index of the Transfer log that a token Deposit log at
// i was paid with: the nearest Transfer emitted by the token in the
// MaxDepositPairDistance logs before i, which must move the amount from the
// sender to the vault (MagiDeposit's transferFrom). -1 when there is none.
func pairedTransfer(logs []ParsedLog, i int, d *contractDeposit, vault [20]byte) int {
	for j := i - 1; j >= 0 && j >= i-constants.MaxDepositPairDistance; j-- {
		l := logs[j]
		if l.Address != d.token || len(l.Topics) < 3 || l.Topics[0] != TransferEventSig {
			continue
		}
		from, ok1 := topicAddress(l.Topics[1])
		to, ok2 := topicAddress(l.Topics[2])
		if ok1 && ok2 && from == d.sender && to == vault && new(big.Int).SetBytes(l.Data).Cmp(d.amount) == 0 {
			return j
		}
		return -1
	}
	return -1
}

// transferPaysAContractDeposit reports whether Transfer log j paid a MagiDeposit
// token deposit (a Deposit log after it pairs with it). Such a transfer is
// credited through its Deposit log only; the plain ERC-20 path refuses it, or
// the sender would be credited too.
func transferPaysAContractDeposit(logs []ParsedLog, j int, vault [20]byte) bool {
	dc := DepositContractAddress(vault)
	for i := j + 1; i < len(logs) && i <= j+constants.MaxDepositPairDistance; i++ {
		if d, ok := parseDepositLog(logs[i], dc); ok && d.token != ([20]byte{}) && pairedTransfer(logs, i, d, vault) == j {
			return true
		}
	}
	return false
}

// handleContractDeposit credits a MagiDeposit deposit: the receipt (base64
// proof against the stored header's receipts root, leaf = the receipt) must
// hold, at LogIndex, a Deposit log from the vault's MagiDeposit. ETH pays the
// same reserve share as a plain ETH deposit; a token must be registered and its
// paying Transfer is marked observed too. An invalid recipient is credited to
// the sender's account (as deposit_to, A5).
func handleContractDeposit(req *VerificationRequest, vault [20]byte, chainId uint64) error {
	header := blocklist.GetHeader(req.BlockHeight)
	if header == nil {
		return ErrBlockNotFound
	}
	if header.ChainId != chainId {
		return ErrChainIdMismatch
	}
	proofBytes, err := base64.StdEncoding.DecodeString(req.ReceiptProof)
	if err != nil || len(proofBytes) == 0 {
		return ce.NewContractError(ce.ErrInput, "receipt_proof must be base64 (concatenated receipt-trie MPT nodes)")
	}
	receipt, err := mpt.VerifyProof(header.ReceiptsRoot, mpt.RLPEncodeKey(req.TxIndex), splitProofNodes(proofBytes))
	if err != nil {
		return ErrProofFailed
	}
	// The same observed key as an ERC-20 deposit (the receipt and its index),
	// so a Deposit log and the Transfer that paid it share one namespace.
	txHash := crypto.Keccak256Hash(append(append([]byte{}, receipt...),
		byte(req.TxIndex>>24), byte(req.TxIndex>>16), byte(req.TxIndex>>8), byte(req.TxIndex)))
	if req.LogIndex > 10000 {
		return ce.NewContractError(ce.ErrInput, "log_index out of range")
	}
	if IsObserved(req.BlockHeight, txHash, uint16(req.LogIndex)) {
		return ErrAlreadyObserved
	}
	logs, err := parseReceiptLogs(receipt)
	if err != nil {
		return err
	}
	if int(req.LogIndex) >= len(logs) {
		return ce.NewContractError(ce.ErrInput, "log_index out of range")
	}
	d, ok := parseDepositLog(logs[req.LogIndex], DepositContractAddress(vault))
	if !ok {
		return ce.NewContractError(ce.ErrInput, "not a Deposit log of this vault's MagiDeposit")
	}
	if d.amount.Sign() <= 0 {
		return ce.NewContractError(ce.ErrInput, "deposit amount must be positive")
	}
	dest := crypto.AddressToDID(d.sender)
	if validIdentity(d.recipient) {
		dest = d.recipient
	}
	if d.token == ([20]byte{}) {
		if err := checkMinDeposit(constants.NativeAsset, d.amount, constants.MinETHDeposit); err != nil {
			return err
		}
		gasTax := new(big.Int).Div(new(big.Int).Mul(d.amount, big.NewInt(constants.GasReserveDepositTaxBps)), big.NewInt(10000))
		net := new(big.Int).Sub(d.amount, gasTax)
		if gasTax.Sign() > 0 {
			addGasReserve(gasTax)
		}
		IncBalance(dest, constants.NativeAsset, takeDepositProofFee(constants.NativeAsset, net))
		TrackDeposit(constants.NativeAsset, net, gasTax)
	} else {
		info := getTokenInfo(chainId, d.token)
		if info == nil {
			return ErrInvalidToken
		}
		if err := checkMinDeposit(info.Symbol, d.amount, info.MinDeposit()); err != nil {
			return err
		}
		j := pairedTransfer(logs, int(req.LogIndex), d, vault)
		if j < 0 {
			return ce.NewContractError(ce.ErrInput, "the deposit's token transfer to the vault is not in the receipt")
		}
		if IsObserved(req.BlockHeight, txHash, uint16(j)) {
			return ErrAlreadyObserved
		}
		IncBalance(dest, info.Symbol, takeDepositProofFee(info.Symbol, d.amount))
		TrackDeposit(info.Symbol, d.amount, new(big.Int))
		MarkObserved(req.BlockHeight, txHash, uint16(j))
	}
	MarkObserved(req.BlockHeight, txHash, uint16(req.LogIndex))
	return nil
}
