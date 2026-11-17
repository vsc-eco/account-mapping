package mapping

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The reason in the swapfail log line is cut at 160 bytes, never inside a
// multi-byte character (the line stays valid UTF-8 for every reader).
func TestTryCallError_CutsOnACharacterBoundary(t *testing.T) {
	long := `{"ok":false,"error":"` + strings.Repeat("a", 149) + strings.Repeat("é", 20) + `"}`
	got := tryCallError(&long)
	if !utf8.ValidString(got) {
		t.Fatalf("cut reason is not valid UTF-8: %q", got)
	}
	if len(got) > maxLogReason || len(got) < maxLogReason-3 {
		t.Fatalf("cut reason is %d bytes, want just under %d", len(got), maxLogReason)
	}
	if want := "reverted: " + strings.Repeat("a", 149); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
