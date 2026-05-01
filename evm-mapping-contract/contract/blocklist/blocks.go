package blocklist

import (
	"encoding/hex"
	"evm-mapping-contract/contract/constants"
	ce "evm-mapping-contract/contract/contracterrors"
	"evm-mapping-contract/sdk"
	"strconv"
)

type EthBlockHeader struct {
	BlockNumber      uint64
	StateRoot        [32]byte
	TransactionsRoot [32]byte
	ReceiptsRoot     [32]byte
	BaseFeePerGas    uint64
	GasLimit         uint64
	Timestamp        uint64
}

func (h *EthBlockHeader) Serialize() string {
	buf := make([]byte, 0, 128)
	buf = appendUint64(buf, h.BlockNumber)
	buf = append(buf, h.StateRoot[:]...)
	buf = append(buf, h.TransactionsRoot[:]...)
	buf = append(buf, h.ReceiptsRoot[:]...)
	buf = appendUint64(buf, h.BaseFeePerGas)
	buf = appendUint64(buf, h.GasLimit)
	buf = appendUint64(buf, h.Timestamp)
	return string(buf)
}

func DeserializeHeader(data string) (*EthBlockHeader, error) {
	buf := []byte(data)
	if len(buf) < 128 { // 8 + 32 + 32 + 32 + 8 + 8 + 8 = 128
		return nil, ce.NewContractError(ce.ErrStateAccess, "header data too short")
	}
	h := &EthBlockHeader{}
	offset := 0
	h.BlockNumber = readUint64(buf, &offset)
	copy(h.StateRoot[:], buf[offset:offset+32])
	offset += 32
	copy(h.TransactionsRoot[:], buf[offset:offset+32])
	offset += 32
	copy(h.ReceiptsRoot[:], buf[offset:offset+32])
	offset += 32
	h.BaseFeePerGas = readUint64(buf, &offset)
	h.GasLimit = readUint64(buf, &offset)
	h.Timestamp = readUint64(buf, &offset)
	return h, nil
}

func StoreHeader(header EthBlockHeader) {
	key := constants.BlockPrefix + strconv.FormatUint(header.BlockNumber, 10)
	sdk.StateSetObject(key, header.Serialize())
}

func GetHeader(blockNumber uint64) *EthBlockHeader {
	key := constants.BlockPrefix + strconv.FormatUint(blockNumber, 10)
	data := readState(key)
	if data == nil {
		return nil
	}
	h, err := DeserializeHeader(*data)
	if err != nil {
		return nil
	}
	return h
}

func DeleteHeader(blockNumber uint64) {
	key := constants.BlockPrefix + strconv.FormatUint(blockNumber, 10)
	sdk.StateDeleteObject(key)
}

func GetLastHeight() uint64 {
	data := readState(constants.LastHeightKey)
	if data == nil {
		return 0
	}
	h, err := strconv.ParseUint(*data, 10, 64)
	if err != nil {
		return 0
	}
	return h
}

// readState reads from the ZK verifier contract if configured, otherwise from own state.
// When a verifier contract ID is set, block headers come from the ZK-verified store.
// Falls back to own state for backward compatibility with the oracle BLS path.
func readState(key string) *string {
	vcid := sdk.StateGetObject(constants.VerifierContractIdKey)
	if vcid != nil && *vcid != "" {
		result := sdk.ContractStateGet(*vcid, key)
		if result == nil || *result == "" {
			return nil
		}
		return result
	}
	return sdk.StateGetObject(key)
}

func SetLastHeight(height uint64) {
	sdk.StateSetObject(constants.LastHeightKey, strconv.FormatUint(height, 10))
}

type AddBlocksParams struct {
	Blocks    []AddBlockEntry `json:"blocks"`
	LatestFee uint64          `json:"latest_fee"`
}

type AddBlockEntry struct {
	BlockNumber      uint64 `json:"block_number"`
	StateRoot        string `json:"state_root"`
	TransactionsRoot string `json:"transactions_root"`
	ReceiptsRoot     string `json:"receipts_root"`
	BaseFeePerGas    uint64 `json:"base_fee_per_gas"`
	GasLimit         uint64 `json:"gas_limit"`
	Timestamp        uint64 `json:"timestamp"`
}

func HandleAddBlocks(params *AddBlocksParams) error {
	lastHeight := GetLastHeight()

	if lastHeight == 0 {
		return ce.NewContractError(ce.ErrInitialization, "contract not seeded: call seedBlocks first")
	}

	for _, entry := range params.Blocks {
		if entry.BlockNumber != lastHeight+1 {
			return ce.NewContractError(ce.ErrInput, "block heights must be sequential")
		}

		stateRoot, err := hexTo32(entry.StateRoot)
		if err != nil {
			return ce.WrapContractError(ce.ErrInvalidHex, err, "state_root")
		}
		txRoot, err := hexTo32(entry.TransactionsRoot)
		if err != nil {
			return ce.WrapContractError(ce.ErrInvalidHex, err, "transactions_root")
		}
		rcptRoot, err := hexTo32(entry.ReceiptsRoot)
		if err != nil {
			return ce.WrapContractError(ce.ErrInvalidHex, err, "receipts_root")
		}

		header := EthBlockHeader{
			BlockNumber:      entry.BlockNumber,
			StateRoot:        stateRoot,
			TransactionsRoot: txRoot,
			ReceiptsRoot:     rcptRoot,
			BaseFeePerGas:    entry.BaseFeePerGas,
			GasLimit:         entry.GasLimit,
			Timestamp:        entry.Timestamp,
		}

		StoreHeader(header)
		lastHeight = entry.BlockNumber

		// Prune old headers
		if entry.BlockNumber > constants.MaxBlockRetention {
			pruneHeight := entry.BlockNumber - constants.MaxBlockRetention
			DeleteHeader(pruneHeight)
		}
	}

	SetLastHeight(lastHeight)
	return nil
}

func hexTo32(s string) ([32]byte, error) {
	var result [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return result, ce.NewContractError(ce.ErrInvalidHex, "invalid 32-byte hex")
	}
	copy(result[:], b)
	return result, nil
}

func appendUint64(buf []byte, v uint64) []byte {
	return append(buf,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
	)
}

func readUint64(buf []byte, offset *int) uint64 {
	v := uint64(buf[*offset])<<56 | uint64(buf[*offset+1])<<48 |
		uint64(buf[*offset+2])<<40 | uint64(buf[*offset+3])<<32 |
		uint64(buf[*offset+4])<<24 | uint64(buf[*offset+5])<<16 |
		uint64(buf[*offset+6])<<8 | uint64(buf[*offset+7])
	*offset += 8
	return v
}

func HandleSeedBlock(entry *AddBlockEntry) error {
	if entry.BlockNumber == 0 {
		return ce.NewContractError(ce.ErrInput, "seed block_number must be > 0")
	}
	txRoot, err := hexTo32(entry.TransactionsRoot)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "transactions_root")
	}
	rcptRoot, err := hexTo32(entry.ReceiptsRoot)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "receipts_root")
	}
	header := EthBlockHeader{
		BlockNumber:      entry.BlockNumber,
		TransactionsRoot: txRoot,
		ReceiptsRoot:     rcptRoot,
		BaseFeePerGas:    entry.BaseFeePerGas,
		GasLimit:         entry.GasLimit,
		Timestamp:        entry.Timestamp,
	}
	StoreHeader(header)
	SetLastHeight(entry.BlockNumber)
	return nil
}

func HandleReplaceBlock(entry *AddBlockEntry) error {
	existing := GetHeader(entry.BlockNumber)
	if existing == nil {
		return ce.NewContractError(ce.ErrStateAccess, "block not found for replacement")
	}

	stateRoot, err := hexTo32(entry.StateRoot)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "state_root")
	}
	txRoot, err := hexTo32(entry.TransactionsRoot)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "transactions_root")
	}
	rcptRoot, err := hexTo32(entry.ReceiptsRoot)
	if err != nil {
		return ce.WrapContractError(ce.ErrInvalidHex, err, "receipts_root")
	}

	header := EthBlockHeader{
		BlockNumber:      entry.BlockNumber,
		StateRoot:        stateRoot,
		TransactionsRoot: txRoot,
		ReceiptsRoot:     rcptRoot,
		BaseFeePerGas:    entry.BaseFeePerGas,
		GasLimit:         entry.GasLimit,
		Timestamp:        entry.Timestamp,
	}

	StoreHeader(header)
	return nil
}
