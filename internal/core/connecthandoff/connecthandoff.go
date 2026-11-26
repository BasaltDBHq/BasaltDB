// Package connecthandoff holds the types the handoff domain's port to the
// connect service is written in: the signed CollectAddress and ReportReach
// requests, the collected address with its hold's phase, and the refusals
// (CONTRACT.md, Connect refusals) as the engine's own error values. The
// adapter (internal/handoff/out/connectrpc) fills and maps them;
// internal/handoff signs the requests and decides on the answers. Types
// only.
package connecthandoff

import (
	"errors"
	"fmt"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// CollectRequest is a signed CollectAddress call. EnginePublicKey and
// Signature are base64url without padding; Time is RFC 3339 in UTC.
type CollectRequest struct {
	SetupID         string
	EnginePublicKey string
	Time            string
	Signature       string
}

// ReachReport is a signed ReportReach call. Address is the canonical form
// that was signed; Result is REACHABLE or UNREACHABLE and Reason is empty
// when the engine reached it. EnginePublicKey, Time and Signature are as in
// CollectRequest.
type ReachReport struct {
	SetupID         string
	EnginePublicKey string
	Time            string
	Address         setupcode.Address
	Result          string
	Reason          string
	Signature       string
}

// The phases of a hold (CONTRACT.md, Connect, The reach check).
const (
	// HoldPreview is CheckSetup's hold: the person has not approved yet,
	// so the engine only checks, probes and reports.
	HoldPreview = "PREVIEW"
	// HoldSetUp is RunSetup's hold: the setup ran, and the engine asks the
	// person about the database after a probe that passed.
	HoldSetUp = "SET_UP"
)

// Collected is an address the connect service handed over, unchecked (see
// Address.Check and Probe), with its hold's phase: HoldPreview, HoldSetUp,
// or anything else the service sent, which the engine treats as a preview.
type Collected struct {
	Address setupcode.Address
	Phase   string
	// TrustRoot is the SHA-256 of the certificate authority the person
	// trusted on the connect page for the address's host, or "". It adds
	// no trust by itself: Prober.Approve checks it against the chain the
	// engine reads.
	TrustRoot string
}

// SetUp reports whether the address is the setup's own: only then may the
// engine ask the person about it. Any phase but SET_UP is a preview.
func (c Collected) SetUp() bool { return c.Phase == HoldSetUp }

var (
	// ErrNotHeld is HANDOFF_UNKNOWN: no hold for this setup and key (the
	// setup has not run, the hold expired or the service restarted).
	ErrNotHeld = errors.New("the connect service holds no address for this setup yet")
	// ErrClockSkew is CLOCK_SKEW: the engine's clock is more than 5 minutes
	// off the service's.
	ErrClockSkew = errors.New("the clock of the bot's machine is more than 5 minutes off")
)

// RateLimitedError is RATE_LIMITED: wait After before the next call.
type RateLimitedError struct{ After time.Duration }

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("the connect service asks to wait %s before collecting again", e.After)
}
