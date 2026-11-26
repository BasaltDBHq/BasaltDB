package handoff

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/connecthandoff"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// ServiceURL is the connect service the engine collects from.
const ServiceURL = "https://" + channel.ConnectAudience

// collectTimeout bounds one CollectAddress or ReportReach call.
const collectTimeout = 20 * time.Second

// The refusals CollectAddress and ReportReach answer with (CONTRACT.md,
// Connect refusals), as the connect service's adapter maps them.
var (
	// ErrNotHeld is HANDOFF_UNKNOWN: no hold for this setup and key (the
	// setup has not run, the hold expired or the service restarted).
	ErrNotHeld = connecthandoff.ErrNotHeld
	// ErrClockSkew is CLOCK_SKEW: the engine's clock is more than 5 minutes
	// off the service's.
	ErrClockSkew = connecthandoff.ErrClockSkew
)

// RateLimitedError is RATE_LIMITED: wait After before the next call.
type RateLimitedError = connecthandoff.RateLimitedError

// Client calls the connect service's CollectAddress and ReportReach.
type Client struct {
	rpc    SetupService
	signer Signer
	now    func() time.Time
}

// NewClient is a client of the connect service that rpc calls
// (out/connectrpc, at ServiceURL outside tests), signing with signer. The
// signed audience is always the contract's, whatever address rpc calls.
func NewClient(rpc SetupService, signer Signer, now func() time.Time) *Client {
	if signer == nil || now == nil {
		panic("handoff: a client needs a signer and a clock")
	}
	return &Client{rpc: rpc, signer: signer, now: now}
}

var b64 = base64.RawURLEncoding

// The phases of a hold (CONTRACT.md, Connect, The reach check).
const (
	// HoldPreview is CheckSetup's hold: the person has not approved yet,
	// so the engine only checks, probes and reports.
	HoldPreview = connecthandoff.HoldPreview
	// HoldSetUp is RunSetup's hold: the setup ran, and the engine asks the
	// person about the database after a probe that passed.
	HoldSetUp = connecthandoff.HoldSetUp
)

// Collected is an address the connect service handed over, unchecked (see
// Address.Check and Probe), with its hold's phase; SetUp reports whether it
// is the setup's own.
type Collected = connecthandoff.Collected

// Collect asks for the address of setupID, whose code's fingerprint is
// fingerprint: the address the service holds and its phase, ErrNotHeld,
// ErrClockSkew, a *RateLimitedError, or another error for a service that
// did not answer.
func (c *Client) Collect(ctx context.Context, setupID, fingerprint string) (Collected, error) {
	at := c.at()
	sig, err := c.signer.Sign(channel.ContextConnectCollect, channel.ConnectCollectBody(setupID, fingerprint, at))
	if err != nil {
		return Collected{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	return c.rpc.CollectAddress(ctx, connecthandoff.CollectRequest{
		SetupID: setupID, EnginePublicKey: b64.EncodeToString(c.signer.PublicKeySPKI()), Time: at, Signature: b64.EncodeToString(sig),
	})
}

func (c *Client) at() string { return c.now().UTC().Truncate(time.Second).Format(time.RFC3339) }

// Report tells the service whether the engine reached a, which passed the
// shape rules (CONTRACT.md, Connect, The reach check): r.Reason is empty
// when r reached it. The address is sent and signed in its canonical form.
// The refusals are Collect's.
func (c *Client) Report(ctx context.Context, setupID, fingerprint string, a setupcode.Address, r Reach) error {
	at, canon := c.at(), a.Canonical()
	result := ResultReachable
	if r.Reason != "" {
		result = ResultUnreachable
	}
	body := channel.ConnectReachBody(setupID, fingerprint, at, canon.Host, canon.Port, canon.Database, canon.SupabaseRef, result, r.Reason)
	sig, err := c.signer.Sign(channel.ContextConnectReach, body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	return c.rpc.ReportReach(ctx, connecthandoff.ReachReport{
		SetupID: setupID, EnginePublicKey: b64.EncodeToString(c.signer.PublicKeySPKI()), Time: at,
		Address: canon, Result: result, Reason: r.Reason, Signature: b64.EncodeToString(sig),
	})
}
