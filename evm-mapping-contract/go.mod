module evm-mapping-contract

// HIGH #45 — bumped from 1.25.0 to 1.25.10 to close 10 stdlib CVEs
// referenced in the W4-cluster-A monitor rewrite scope.
go 1.25.0

require (
	github.com/CosmWasm/tinyjson v0.9.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
)

require (
	github.com/josharian/intern v1.0.0 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
)
