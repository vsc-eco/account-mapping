//go:build devnet_fasttimelock

package admin

// DEVNET TEST FIXTURE ONLY (build tag `devnet_fasttimelock`). NEVER shipped.
//
// Shortens the admin timelocks so setVerifierContract (TimelockLong) elapses
// within a short devnet's block budget — required to wire the mock ZK header
// verifier and exercise the deposit / withdrawal / double-spend waves
// (W1/W2/W3). These waves test BRIDGE LOGIC, not the timelock DURATION.
//
// The PRODUCTION 400K timelock lives in timelock_windows_prod.go (untagged) and
// is unchanged; its enforcement (propose -> execute-before-ExecHeight rejected
// with "timelock not elapsed") is tested separately on the untagged production
// build (W6.3 admin / P2C-1). A grep for this tag must find ZERO references in
// any deploy/release path.
const (
	TimelockLong        uint64 = 5 // prod 400_000 — short so verifier wiring elapses on devnet
	TimelockTactical    uint64 = 4 // prod 28_800
	TimelockOperational uint64 = 3 // prod 7_200
	TimelockImmediate   uint64 = 0 // unchanged (emergency)
)

// FastTimelockBuild marks this build: initContract refuses to set it up
// without is_testnet (A-1), so a devnet wasm deployed by mistake cannot run a
// bridge whose owner actions wait a few blocks instead of up to 14 days.
const FastTimelockBuild = true
