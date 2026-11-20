package handoff

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"

	connectv1 "github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1"
	"github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1/connectv1connect"
	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// ServiceURL is the connect service the engine collects from.
const ServiceURL = "https://" + channel.ConnectAudience

// collectTimeout bounds one CollectAddress call.
const collectTimeout = 20 * time.Second

// Signer signs with the engine's signing key: *channel.EngineKeys.
type Signer interface {
	Sign(context channel.SigningContext, body []byte) ([]byte, error)
	PublicKeySPKI() []byte
}

// The refusals CollectAddress and ReportReach answer with (CONTRACT.md, Connect refusals).
const (
	reasonHandoffUnknown = "HANDOFF_UNKNOWN"
	reasonClockSkew      = "CLOCK_SKEW"
	reasonRateLimited    = "RATE_LIMITED"
)

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

// Client calls the connect service's CollectAddress and ReportReach.
type Client struct {
	rpc    connectv1connect.SetupServiceClient
	signer Signer
	now    func() time.Time
}

// NewClient is a client of the service at baseURL (ServiceURL outside
// tests), signing with signer. The signed audience is always the
// contract's, whatever baseURL is.
func NewClient(httpClient *http.Client, baseURL string, signer Signer, now func() time.Time) *Client {
	if signer == nil || now == nil {
		panic("handoff: a client needs a signer and a clock")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: collectTimeout}
	}
	return &Client{rpc: connectv1connect.NewSetupServiceClient(httpClient, baseURL), signer: signer, now: now}
}

var b64 = base64.RawURLEncoding

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
	Address Address
	Phase   string
}

// SetUp reports whether the address is the setup's own: only then may the
// engine ask the person about it. Any phase but SET_UP is a preview.
func (c Collected) SetUp() bool { return c.Phase == HoldSetUp }

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
	res, err := c.rpc.CollectAddress(ctx, connect.NewRequest(&connectv1.CollectAddressRequest{
		SetupId: setupID, EnginePublicKey: b64.EncodeToString(c.signer.PublicKeySPKI()), Time: at, Signature: b64.EncodeToString(sig),
	}))
	if err != nil {
		return Collected{}, collectError(err)
	}
	t := res.Msg.GetAddress()
	if t == nil {
		return Collected{}, errors.New("the connect service answered without an address")
	}
	return Collected{
		Address: Address{Host: t.GetHost(), Port: int(t.GetPort()), Database: t.GetDatabase(), SupabaseRef: t.GetSupabaseRef()},
		Phase:   res.Msg.GetPhase(),
	}, nil
}

func (c *Client) at() string { return c.now().UTC().Truncate(time.Second).Format(time.RFC3339) }

// Report tells the service whether the engine reached a, which passed the
// shape rules (CONTRACT.md, Connect, The reach check): r.Reason is empty
// when r reached it. The address is sent and signed in its canonical form.
// The refusals are Collect's.
func (c *Client) Report(ctx context.Context, setupID, fingerprint string, a Address, r Reach) error {
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
	_, err = c.rpc.ReportReach(ctx, connect.NewRequest(&connectv1.ReportReachRequest{
		SetupId: setupID, EnginePublicKey: b64.EncodeToString(c.signer.PublicKeySPKI()), Time: at,
		Address: &connectv1.Target{Host: canon.Host, Port: int32(canon.Port), Database: canon.Database, SupabaseRef: canon.SupabaseRef},
		Result:  result, Reason: r.Reason, Signature: b64.EncodeToString(sig),
	}))
	if err != nil {
		return collectError(err)
	}
	return nil
}

// collectError maps the service's refusal to the engine's errors. The
// service's message is never passed on: it is not the engine's to trust.
func collectError(err error) error {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return fmt.Errorf("the connect service did not answer: %w", err)
	}
	for _, d := range ce.Details() {
		v, derr := d.Value()
		if derr != nil {
			continue
		}
		r, ok := v.(*connectv1.Refusal)
		if !ok {
			continue
		}
		switch r.GetReason() {
		case reasonHandoffUnknown:
			return ErrNotHeld
		case reasonClockSkew:
			return ErrClockSkew
		case reasonRateLimited:
			return &RateLimitedError{After: time.Duration(max(r.GetRetryAfterSeconds(), 1)) * time.Second}
		}
	}
	return fmt.Errorf("the connect service refused the call (%s)", ce.Code())
}
