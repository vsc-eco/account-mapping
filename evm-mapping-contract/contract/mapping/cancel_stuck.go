package mapping

import (
	"errors"

	"evm-mapping-contract/contract/blocklist"
)

// CancelStuckTTLBlocks is the L1 block window after which a pending
// withdrawal becomes recoverable by anyone via HandleCancelStuckWithdrawal.
// Pentest finding EVM-C3 — the previous design left the bridge
// permanently jammed if the admin key was unavailable or the
// oracle stopped feeding fresh base fees. blocklist.MaxBlockRetention
// is 101 (about 20 minutes of ETH blocks); any withdrawal that
// hasn't confirmed inside ~2 retention windows can no longer be
// confirmed (no header to verify against), so it's safe to let
// users recover.
const CancelStuckTTLBlocks = uint64(202)

// HandleCancelStuckWithdrawal advances the confirmed nonce past
// a pending spend that has been waiting at least CancelStuckTTLBlocks
// L1 blocks. The user is refunded (same shape as the confirmSpend
// status=0 branch) and the slot is cleared so subsequent unmaps
// can proceed.
//
// Anyone can call this once the TTL elapses — there's no auth on
// the recovery path because:
//   - the action is constructive (refunds the original sender, not
//     the caller);
//   - the alternative (admin-only) was the original bug;
//   - the TTL prevents racing a still-confirmable withdrawal.
func HandleCancelStuckWithdrawal() error {
	if isPaused() {
		return errors.New("contract is paused")
	}

	confirmed := GetConfirmedNonce()
	pending := GetPendingNonce()
	if pending <= confirmed {
		return errors.New("no pending withdrawal to cancel")
	}

	ps := GetPendingSpend(confirmed)
	if ps == nil {
		return errors.New("no pending spend at confirmed nonce")
	}

	tip := blocklist.GetLastHeight()
	if tip < ps.BlockHeight {
		// Sanity: clock running backwards. Refuse rather than
		// risk underflow on the elapsed calculation.
		return errors.New("L1 tip is behind the pending spend's block height")
	}
	if tip-ps.BlockHeight < CancelStuckTTLBlocks {
		return errors.New("pending withdrawal not yet expired")
	}

	// Refund (same as the confirmSpend status=0 branch).
	if err := IncBalance(ps.From, ps.Asset, ps.Amount); err == nil {
		s := GetSupply(ps.Asset)
		s.Active += ps.Amount
		s.User += ps.Amount
		SetSupply(ps.Asset, s)
	}
	DeletePendingSpend(confirmed)
	SetConfirmedNonce(confirmed + 1)
	return nil
}
