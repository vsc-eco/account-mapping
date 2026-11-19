package sdk

import "strings"

type Intent struct {
	Type string            `json:"type"`
	Args map[string]string `json:"args"`
}

type Sender struct {
	Address              Address   `json:"id"`
	RequiredAuths        []Address `json:"required_auths"`
	RequiredPostingAuths []Address `json:"required_posting_auths"`
}

//tinyjson:json
type ContractCallOptions struct {
	Intents []Intent `json:"intents,omitempty"`
	// Try opts the call into try/catch semantics: if the callee reverts, THIS
	// caller is NOT trapped — the call returns a structured outcome
	// ({"ok":false,...}) and every state/ledger effect of the callee is rolled
	// back. RC/gas are still charged. Default false keeps abort-propagates.
	Try bool `json:"try,omitempty"`
}

type AddressDomain string

const (
	AddressDomainUser     AddressDomain = "user"
	AddressDomainContract AddressDomain = "contract"
	AddressDomainSystem   AddressDomain = "system"
	AddressDomainKey      AddressDomain = "key"
	AddressDomainUnknown  AddressDomain = "unknown"
)

type Address string

func (a Address) String() string {
	return string(a)
}

func (a Address) Domain() AddressDomain {
	addressType := VerifyAddress(a.String())
	addressDomain := strings.Split(addressType, ":")[0]
	return AddressDomain(addressDomain)
}

func (a Address) IsValid() bool {
	return VerifyAddress(a.String()) != string(AddressDomainUnknown)
}
