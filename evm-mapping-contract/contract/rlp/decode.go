package rlp

import (
	ce "evm-mapping-contract/contract/contracterrors"
)

var (
	ErrTooShort      = ce.NewContractError(ce.ErrInput, "rlp: input too short")
	ErrNonCanonical  = ce.NewContractError(ce.ErrInput, "rlp: non-canonical encoding")
	ErrDepthExceeded = ce.NewContractError(ce.ErrInput, "rlp: max depth exceeded")
	ErrOversized    = ce.NewContractError(ce.ErrInput, "rlp: item exceeds max size")
)

const maxDepth = 20
const maxItemSize = 65536

type Item struct {
	Data     []byte
	Children []Item
	IsList   bool
}

func Decode(data []byte) (Item, int, error) {
	return decodeItem(data, 0, 0)
}

func DecodeList(data []byte) ([]Item, error) {
	item, _, err := decodeItem(data, 0, 0)
	if err != nil {
		return nil, err
	}
	if !item.IsList {
		return nil, ce.NewContractError(ce.ErrInput, "rlp: expected list")
	}
	return item.Children, nil
}

func decodeItem(data []byte, offset int, depth int) (Item, int, error) {
	if depth > maxDepth {
		return Item{}, 0, ErrDepthExceeded
	}
	if offset >= len(data) {
		return Item{}, 0, ErrTooShort
	}

	prefix := data[offset]

	switch {
	case prefix <= 0x7f:
		// Single byte [0x00, 0x7f]
		return Item{Data: data[offset : offset+1]}, offset + 1, nil

	case prefix <= 0xb7:
		// Short string [0x80, 0xb7]: length = prefix - 0x80
		strLen := int(prefix - 0x80)
		start := offset + 1
		end := start + strLen
		if end > len(data) {
			return Item{}, 0, ErrTooShort
		}
		if strLen > maxItemSize {
			return Item{}, 0, ErrOversized
		}
		// Canonical check: single byte [0x00, 0x7f] must use single-byte encoding
		if strLen == 1 && data[start] <= 0x7f {
			return Item{}, 0, ErrNonCanonical
		}
		// Canonical check: empty string must use 0x80, not 0x8100 etc
		if strLen == 0 {
			return Item{Data: nil}, end, nil
		}
		return Item{Data: data[start:end]}, end, nil

	case prefix <= 0xbf:
		// Long string [0xb8, 0xbf]: length of length = prefix - 0xb7
		lenLen := int(prefix - 0xb7)
		start := offset + 1
		if start+lenLen > len(data) {
			return Item{}, 0, ErrTooShort
		}
		strLen := decodeLength(data[start : start+lenLen])
		if strLen < 0 {
			return Item{}, 0, ErrNonCanonical
		}
		// Canonical: string len must require this many bytes
		if strLen <= 55 {
			return Item{}, 0, ErrNonCanonical
		}
		// Canonical: no leading zero bytes in length
		if data[start] == 0 {
			return Item{}, 0, ErrNonCanonical
		}
		dataStart := start + lenLen
		dataEnd := dataStart + strLen
		if dataEnd > len(data) {
			return Item{}, 0, ErrTooShort
		}
		if strLen > maxItemSize {
			return Item{}, 0, ErrOversized
		}
		return Item{Data: data[dataStart:dataEnd]}, dataEnd, nil

	case prefix <= 0xf7:
		// Short list [0xc0, 0xf7]: payload length = prefix - 0xc0
		listLen := int(prefix - 0xc0)
		start := offset + 1
		end := start + listLen
		if end > len(data) {
			return Item{}, 0, ErrTooShort
		}
		children, err := decodeChildren(data, start, end, depth+1)
		if err != nil {
			return Item{}, 0, err
		}
		return Item{IsList: true, Children: children}, end, nil

	default:
		// Long list [0xf8, 0xff]: length of length = prefix - 0xf7
		lenLen := int(prefix - 0xf7)
		start := offset + 1
		if start+lenLen > len(data) {
			return Item{}, 0, ErrTooShort
		}
		listLen := decodeLength(data[start : start+lenLen])
		if listLen < 0 {
			return Item{}, 0, ErrNonCanonical
		}
		if listLen <= 55 {
			return Item{}, 0, ErrNonCanonical
		}
		if data[start] == 0 {
			return Item{}, 0, ErrNonCanonical
		}
		payloadStart := start + lenLen
		payloadEnd := payloadStart + listLen
		if payloadEnd > len(data) {
			return Item{}, 0, ErrTooShort
		}
		children, err := decodeChildren(data, payloadStart, payloadEnd, depth+1)
		if err != nil {
			return Item{}, 0, err
		}
		return Item{IsList: true, Children: children}, payloadEnd, nil
	}
}

func decodeChildren(data []byte, start, end, depth int) ([]Item, error) {
	children := make([]Item, 0, 4)
	pos := start
	for pos < end {
		child, nextPos, err := decodeItem(data, pos, depth)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
		pos = nextPos
	}
	if pos != end {
		return nil, ce.NewContractError(ce.ErrInput, "rlp: list length mismatch")
	}
	return children, nil
}

func decodeLength(data []byte) int {
	result := 0
	for _, b := range data {
		result = (result << 8) | int(b)
	}
	return result
}

// DataAsUint64 interprets an RLP byte string as a big-endian uint64.
func (item *Item) AsUint64() uint64 {
	if item.Data == nil || len(item.Data) == 0 {
		return 0
	}
	result := uint64(0)
	for _, b := range item.Data {
		result = (result << 8) | uint64(b)
	}
	return result
}

// AsBytes returns the raw bytes of the item (empty slice if nil).
func (item *Item) AsBytes() []byte {
	if item.Data == nil {
		return []byte{}
	}
	return item.Data
}
