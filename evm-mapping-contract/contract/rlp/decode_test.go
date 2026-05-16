package rlp

import (
	"errors"
	"testing"
)

func TestDecodeSingleByte(t *testing.T) {
	// 0x42 = single byte 'B'
	item, end, err := Decode([]byte{0x42})
	if err != nil {
		t.Fatal(err)
	}
	if end != 1 {
		t.Fatalf("end=%d, want 1", end)
	}
	if len(item.Data) != 1 || item.Data[0] != 0x42 {
		t.Fatalf("data=%x, want 42", item.Data)
	}
}

func TestDecodeEmptyString(t *testing.T) {
	item, end, err := Decode([]byte{0x80})
	if err != nil {
		t.Fatal(err)
	}
	if end != 1 {
		t.Fatalf("end=%d, want 1", end)
	}
	if item.Data != nil {
		t.Fatalf("data=%x, want nil", item.Data)
	}
}

func TestDecodeShortString(t *testing.T) {
	// "dog" = 0x83 'd' 'o' 'g'
	data := []byte{0x83, 'd', 'o', 'g'}
	item, end, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if end != 4 {
		t.Fatalf("end=%d, want 4", end)
	}
	if string(item.Data) != "dog" {
		t.Fatalf("data=%s, want dog", item.Data)
	}
}

func TestDecodeEmptyList(t *testing.T) {
	item, end, err := Decode([]byte{0xc0})
	if err != nil {
		t.Fatal(err)
	}
	if end != 1 {
		t.Fatalf("end=%d, want 1", end)
	}
	if !item.IsList || len(item.Children) != 0 {
		t.Fatalf("expected empty list")
	}
}

func TestDecodeListOfStrings(t *testing.T) {
	// ["cat", "dog"] = 0xc8 0x83 'c' 'a' 't' 0x83 'd' 'o' 'g'
	data := []byte{0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g'}
	item, _, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if !item.IsList || len(item.Children) != 2 {
		t.Fatalf("expected list of 2, got %d", len(item.Children))
	}
	if string(item.Children[0].Data) != "cat" {
		t.Fatalf("child[0]=%s, want cat", item.Children[0].Data)
	}
	if string(item.Children[1].Data) != "dog" {
		t.Fatalf("child[1]=%s, want dog", item.Children[1].Data)
	}
}

func TestDecodeNestedList(t *testing.T) {
	// [[], [[]], [[], [[]]]]
	// 0xc7 0xc0 0xc1 0xc0 0xc3 0xc0 0xc1 0xc0
	data := []byte{0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0}
	item, _, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if !item.IsList || len(item.Children) != 3 {
		t.Fatalf("expected 3 children, got %d", len(item.Children))
	}
}

func TestDecodeUint(t *testing.T) {
	// 1024 = 0x82 0x04 0x00
	data := []byte{0x82, 0x04, 0x00}
	item, _, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if item.AsUint64() != 1024 {
		t.Fatalf("got %d, want 1024", item.AsUint64())
	}
}

func TestDecodeZero(t *testing.T) {
	// integer 0 = 0x80 (empty string = 0)
	data := []byte{0x80}
	item, _, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if item.AsUint64() != 0 {
		t.Fatalf("got %d, want 0", item.AsUint64())
	}
}

func TestNonCanonicalSingleByte(t *testing.T) {
	// 0x00 encoded as 0x8100 (should use single-byte form)
	_, _, err := Decode([]byte{0x81, 0x00})
	if !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("expected ErrNonCanonical, got %v", err)
	}
}

func TestDecodeLongString(t *testing.T) {
	// 56-byte string: 0xb8 0x38 [56 bytes]
	str := make([]byte, 56)
	for i := range str {
		str[i] = byte(i)
	}
	data := append([]byte{0xb8, 0x38}, str...)
	item, end, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if end != 58 {
		t.Fatalf("end=%d, want 58", end)
	}
	if len(item.Data) != 56 {
		t.Fatalf("len=%d, want 56", len(item.Data))
	}
}

func TestDecodeListWithNestedBytes(t *testing.T) {
	// List containing a 32-byte hash and a uint
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	// Encode: [hash, 1024]
	// hash: 0xa0 + 32 bytes = 33 bytes
	// 1024: 0x82 0x04 0x00 = 3 bytes
	// list payload = 36 bytes, 0xc0+36 = 0xe4
	payload := make([]byte, 0, 37)
	payload = append(payload, 0xe4) // list prefix
	payload = append(payload, 0xa0) // 32-byte string prefix
	payload = append(payload, hash...)
	payload = append(payload, 0x82, 0x04, 0x00) // 1024

	item, _, err := Decode(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !item.IsList || len(item.Children) != 2 {
		t.Fatalf("expected list of 2, got isList=%v len=%d", item.IsList, len(item.Children))
	}
	if len(item.Children[0].Data) != 32 {
		t.Fatalf("hash len=%d, want 32", len(item.Children[0].Data))
	}
	if item.Children[1].AsUint64() != 1024 {
		t.Fatalf("uint=%d, want 1024", item.Children[1].AsUint64())
	}
}
