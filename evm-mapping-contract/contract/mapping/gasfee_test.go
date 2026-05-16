package mapping

import (
	"math"
	"testing"
)

// review2 HIGH #16 — the withdrawal/gas-reserve fee was computed as
// int64(gasUnits * (baseFeePerGas*2 + gasTipCap)) with no overflow check.
// A high baseFeePerGas (>= ~219,604 gwei for the 21000-gas path) makes the
// uint64 product exceed MaxInt64; the int64 cast then wraps NEGATIVE, the
// fee/totalDeduct goes negative and the user's balance is inflated instead
// of debited. safeGasFee must reject every overflow rather than wrap.

const gwei = uint64(1_000_000_000)

func TestSafeGasFee_NormalValues(t *testing.T) {
	// 20 gwei base, 2 gwei tip, 21000 gas.
	cap_, fee, err := safeGasFee(21_000, 20*gwei, 2*gwei)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantCap := 20*gwei*2 + 2*gwei // 42 gwei
	if cap_ != wantCap {
		t.Fatalf("gasFeeCap = %d, want %d", cap_, wantCap)
	}
	wantFee := int64(21_000 * wantCap)
	if fee != wantFee {
		t.Fatalf("fee = %d, want %d", fee, wantFee)
	}
	if fee <= 0 {
		t.Fatalf("fee must be positive, got %d", fee)
	}
}

func TestSafeGasFee_RejectsInt64WrapFromHighBaseFee(t *testing.T) {
	// The reported threshold: baseFee >= ~219,604 gwei on the 21000-gas
	// path makes 21000*(2*base+tip) exceed MaxInt64.
	_, fee, err := safeGasFee(21_000, 219_604*gwei, 2*gwei)
	if err == nil {
		t.Fatalf("expected overflow error; got fee=%d (would wrap negative pre-fix)", fee)
	}
}

func TestSafeGasFee_RejectsGasFeeCapAddOverflow(t *testing.T) {
	if _, _, err := safeGasFee(21_000, math.MaxUint64-1, 1_000); err == nil {
		t.Fatalf("expected gas fee cap overflow error")
	}
}

func TestSafeGasFee_RejectsDoublingOverflow(t *testing.T) {
	// baseFeePerGas*2 alone overflows uint64.
	if _, _, err := safeGasFee(21_000, math.MaxUint64/2+1, 0); err == nil {
		t.Fatalf("expected doubling overflow error")
	}
}
