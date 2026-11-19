module evm-mapping-contract

// go is the floor the module accepts (1.25.0, like the other contract modules).
// toolchain is what builds the contract: 1.25.10, the HIGH #45 bump that closes
// 10 stdlib CVEs. The pinned TinyGo image carries 1.25.0 and fetches 1.25.10
// from this line, so the mainnet wasm is the one testnet ran.
go 1.25.0

toolchain go1.25.10

require (
	github.com/CosmWasm/tinyjson v0.9.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
)

require (
	github.com/josharian/intern v1.0.0 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
)
