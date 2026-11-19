package monitor

import (
	"evm-mapping-contract/contract/rlp"
	"math/big"
	"strings"
)

// RPCTx represents a transaction from eth_getBlockByNumber with hydrated TXs.
//
// W4 Cluster A CRIT #1: the monitor's ETH path now fetches raw RLP bytes via
// eth_getRawTransactionByHash and stores them in `rawWireBytes`. EncodeTx
// short-circuits to those bytes when present so the tx-trie root we build
// is byte-identical to what the block producer included — re-encoding from
// hydrated JSON fields would risk a canonicalisation mismatch on access
// lists, blob hashes, or v-byte representation. The hydrated-JSON path is
// retained for tests / non-Path-C consumers.
type RPCTx struct {
	// rawWireBytes, when non-nil, is the canonical RLP of the tx as
	// returned by eth_getRawTransactionByHash. Setting this bypasses the
	// hydrated-JSON re-encode path entirely.
	rawWireBytes []byte

	ChainId              string `json:"chainId"`
	Nonce                string `json:"nonce"`
	GasPrice             string `json:"gasPrice"`
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         string `json:"maxFeePerGas"`
	Gas                  string `json:"gas"`
	To                   string `json:"to"`
	Value                string `json:"value"`
	Input                string `json:"input"`
	V                    string `json:"v"`
	R                    string `json:"r"`
	S                    string `json:"s"`
	Type                 string `json:"type"`
	Hash                 string `json:"hash"`
	AccessList           []struct {
		Address     string   `json:"address"`
		StorageKeys []string `json:"storageKeys"`
	} `json:"accessList"`
	MaxFeePerBlobGas    string   `json:"maxFeePerBlobGas"`
	BlobVersionedHashes []string `json:"blobVersionedHashes"`
	AuthorizationList   []struct {
		ChainId string `json:"chainId"`
		Address string `json:"address"`
		Nonce   string `json:"nonce"`
		YParity string `json:"yParity"`
		R       string `json:"r"`
		S       string `json:"s"`
	} `json:"authorizationList"`
}

// EncodeTx RLP-encodes a transaction from its JSON fields.
// Handles all TX types: legacy (0), access list (1), EIP-1559 (2), blob (3), set-code (4).
//
// W4 Cluster A CRIT #1: if `rawWireBytes` is set (populated by the monitor
// after eth_getRawTransactionByHash), return those bytes directly to
// preserve byte-for-byte parity with the block producer's encoding.
func EncodeTx(tx *RPCTx) []byte {
	if len(tx.rawWireBytes) > 0 {
		return tx.rawWireBytes
	}
	txType := HexToUint(tx.Type)
	switch txType {
	case 2:
		return encodeEIP1559Tx(tx)
	case 3:
		return encodeBlobTx(tx)
	case 4:
		return encodeSetCodeTx(tx)
	case 1:
		return encodeAccessListTx(tx)
	default:
		return encodeLegacyTx(tx)
	}
}

func encodeEIP1559Tx(tx *RPCTx) []byte {
	// F-MON-003 (MED #64): encodeAccessList returns nil when the RPC-supplied
	// access list exceeds the defensive cap. Propagate nil for the whole tx so
	// the caller fails safe (tx-trie root mismatch -> proof rejected) instead
	// of silently emitting a wrong-arity encoding.
	accessList := encodeAccessList(tx.AccessList)
	if accessList == nil {
		return nil
	}
	body := rlp.EncodeList(
		rlp.EncodeUint64(HexToUint(tx.ChainId)),
		rlp.EncodeUint64(HexToUint(tx.Nonce)),
		encodeBigHex(tx.MaxPriorityFeePerGas),
		encodeBigHex(tx.MaxFeePerGas),
		rlp.EncodeUint64(HexToUint(tx.Gas)),
		rlp.EncodeBytes(HexToBytes(tx.To)),
		encodeBigHex(tx.Value),
		rlp.EncodeBytes(HexToBytes(tx.Input)),
		accessList,
		encodeBigHex(tx.V),
		encodeBigHex(tx.R),
		encodeBigHex(tx.S),
	)
	return append([]byte{0x02}, body...)
}

func encodeAccessListTx(tx *RPCTx) []byte {
	// F-MON-003 (MED #64): see encodeEIP1559Tx — fail safe to nil if the
	// access list overflows its defensive cap.
	accessList := encodeAccessList(tx.AccessList)
	if accessList == nil {
		return nil
	}
	body := rlp.EncodeList(
		rlp.EncodeUint64(HexToUint(tx.ChainId)),
		rlp.EncodeUint64(HexToUint(tx.Nonce)),
		encodeBigHex(tx.GasPrice),
		rlp.EncodeUint64(HexToUint(tx.Gas)),
		rlp.EncodeBytes(HexToBytes(tx.To)),
		encodeBigHex(tx.Value),
		rlp.EncodeBytes(HexToBytes(tx.Input)),
		accessList,
		encodeBigHex(tx.V),
		encodeBigHex(tx.R),
		encodeBigHex(tx.S),
	)
	return append([]byte{0x01}, body...)
}

func encodeLegacyTx(tx *RPCTx) []byte {
	return rlp.EncodeList(
		rlp.EncodeUint64(HexToUint(tx.Nonce)),
		encodeBigHex(tx.GasPrice),
		rlp.EncodeUint64(HexToUint(tx.Gas)),
		rlp.EncodeBytes(HexToBytes(tx.To)),
		encodeBigHex(tx.Value),
		rlp.EncodeBytes(HexToBytes(tx.Input)),
		encodeBigHex(tx.V),
		encodeBigHex(tx.R),
		encodeBigHex(tx.S),
	)
}

func encodeBlobTx(tx *RPCTx) []byte {
	// F-MON-003 (MED #64): reject an RPC-supplied blob-hash list beyond the
	// protocol bound rather than driving an unbounded make. nil fails safe
	// (tx-trie root mismatch -> on-chain proof rejected) instead of OOMing.
	if len(tx.BlobVersionedHashes) > maxBlobHashesPerTx {
		return nil
	}
	// F-MON-003 (MED #64): see encodeEIP1559Tx — fail safe to nil if the
	// access list overflows its defensive cap.
	accessList := encodeAccessList(tx.AccessList)
	if accessList == nil {
		return nil
	}
	blobHashes := make([][]byte, len(tx.BlobVersionedHashes))
	for i, h := range tx.BlobVersionedHashes {
		blobHashes[i] = rlp.EncodeBytes(HexToBytes(h))
	}
	body := rlp.EncodeList(
		rlp.EncodeUint64(HexToUint(tx.ChainId)),
		rlp.EncodeUint64(HexToUint(tx.Nonce)),
		encodeBigHex(tx.MaxPriorityFeePerGas),
		encodeBigHex(tx.MaxFeePerGas),
		rlp.EncodeUint64(HexToUint(tx.Gas)),
		rlp.EncodeBytes(HexToBytes(tx.To)),
		encodeBigHex(tx.Value),
		rlp.EncodeBytes(HexToBytes(tx.Input)),
		accessList,
		encodeBigHex(tx.MaxFeePerBlobGas),
		rlp.EncodeList(blobHashes...),
		encodeBigHex(tx.V),
		encodeBigHex(tx.R),
		encodeBigHex(tx.S),
	)
	return append([]byte{0x03}, body...)
}

func encodeSetCodeTx(tx *RPCTx) []byte {
	// F-MON-003 (MED #64): bound the RPC-supplied authorization list. A
	// type-4 set-code tx cannot legitimately carry an unbounded list; reject
	// rather than allocate against attacker-controlled length.
	if len(tx.AuthorizationList) > maxAuthListEntries {
		return nil
	}
	// F-MON-003 (MED #64): see encodeEIP1559Tx — fail safe to nil if the
	// access list overflows its defensive cap.
	accessList := encodeAccessList(tx.AccessList)
	if accessList == nil {
		return nil
	}
	authItems := make([][]byte, len(tx.AuthorizationList))
	for i, a := range tx.AuthorizationList {
		authItems[i] = rlp.EncodeList(
			rlp.EncodeUint64(HexToUint(a.ChainId)),
			rlp.EncodeBytes(HexToBytes(a.Address)),
			rlp.EncodeUint64(HexToUint(a.Nonce)),
			encodeBigHex(a.YParity),
			encodeBigHex(a.R),
			encodeBigHex(a.S),
		)
	}
	body := rlp.EncodeList(
		rlp.EncodeUint64(HexToUint(tx.ChainId)),
		rlp.EncodeUint64(HexToUint(tx.Nonce)),
		encodeBigHex(tx.MaxPriorityFeePerGas),
		encodeBigHex(tx.MaxFeePerGas),
		rlp.EncodeUint64(HexToUint(tx.Gas)),
		rlp.EncodeBytes(HexToBytes(tx.To)),
		encodeBigHex(tx.Value),
		rlp.EncodeBytes(HexToBytes(tx.Input)),
		accessList,
		rlp.EncodeList(authItems...),
		encodeBigHex(tx.V),
		encodeBigHex(tx.R),
		encodeBigHex(tx.S),
	)
	return append([]byte{0x04}, body...)
}

func encodeAccessList(al []struct {
	Address     string   `json:"address"`
	StorageKeys []string `json:"storageKeys"`
}) []byte {
	if len(al) == 0 {
		return rlp.EncodeList()
	}
	// F-MON-003 (MED #64): bound the RPC-supplied access list (and each entry's
	// storage-key list) before driving an unbounded make. nil fails safe: the
	// tx-trie root will not match block.TransactionsRoot, so the on-chain proof
	// is rejected rather than the monitor OOMing on an attacker-sized reply.
	if len(al) > maxAccessListEntries {
		return nil
	}
	items := make([][]byte, len(al))
	for i, entry := range al {
		if len(entry.StorageKeys) > maxStorageKeysPerAccessEntry {
			return nil
		}
		keys := make([][]byte, len(entry.StorageKeys))
		for j, k := range entry.StorageKeys {
			keys[j] = rlp.EncodeBytes(HexToBytes(k))
		}
		items[i] = rlp.EncodeList(
			rlp.EncodeBytes(HexToBytes(entry.Address)),
			rlp.EncodeList(keys...),
		)
	}
	return rlp.EncodeList(items...)
}

func encodeBigHex(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	if s == "" || s == "0" {
		return rlp.EncodeBytes(nil)
	}
	b, ok := new(big.Int).SetString(s, 16)
	if !ok || b == nil {
		return rlp.EncodeBytes(nil)
	}
	return rlp.EncodeBigInt(b)
}
