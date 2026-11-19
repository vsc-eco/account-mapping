package sdk

import (
	"strings"
	"testing"

	"github.com/CosmWasm/tinyjson"
)

// Regression guard for A9: ContractCall serializes its options with the
// generated tinyjson encoder (sdk.go ContractCall), and sdk_tinyjson.go had not
// been regenerated after Try was added to ContractCallOptions. The encoder wrote
// only "intents", the host saw no "try", and a reverting router still trapped
// the deposit that routed through it. The contract's unit tests could not see
// this: the host-Go stub's contractCall ignores the options string.
func TestContractCallOptions_TryReachesTheHost(t *testing.T) {
	raw, err := tinyjson.Marshal(&ContractCallOptions{Try: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"try":true`) {
		t.Fatalf("options sent to the host = %s, want \"try\":true (regenerate sdk_tinyjson.go: make tinyjson)", raw)
	}

	var back ContractCallOptions
	if err := tinyjson.Unmarshal([]byte(`{"try":true}`), &back); err != nil {
		t.Fatal(err)
	}
	if !back.Try {
		t.Fatal(`{"try":true} decoded with Try=false (regenerate sdk_tinyjson.go: make tinyjson)`)
	}

	// Default stays abort-propagates: no "try" key unless the caller opts in.
	raw, err = tinyjson.Marshal(&ContractCallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "try") {
		t.Fatalf("options without Try = %s, want no \"try\" key", raw)
	}
}
