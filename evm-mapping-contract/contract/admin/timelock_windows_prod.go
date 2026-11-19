//go:build !devnet_fasttimelock

package admin

// Timelock windows per W1 §D-C-3 (LOCKED) — PRODUCTION values (audited).
// Hive block cadence is ~3s; 28_800 blocks = 24h; 7_200 = 6h; 400_000 ≈ 14d.
// The ONLY override is the devnet_fasttimelock build tag (test fixture,
// timelock_windows_devnet.go) which never ships. Any production build (no tag)
// compiles THIS file.
const (
	TimelockLong        uint64 = 400_000 // Fund-affecting (~14 days)
	TimelockTactical    uint64 = 28_800  // Operator-tactical (~24 hours)
	TimelockOperational uint64 = 7_200   // Operational (~6 hours)
	TimelockImmediate   uint64 = 0       // Emergency: pause / unpause
)

// FastTimelockBuild is false in this build (see timelock_windows_devnet.go).
const FastTimelockBuild = false
