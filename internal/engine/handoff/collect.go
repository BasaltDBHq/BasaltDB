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

// The refusals CollectAddress answers with (CONTRACT.md, Connect refusals).
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

// Client calls the connect service's CollectAddress.
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

// Collect asks for the address of setupID, whose code's fingerprint is
// fingerprint: the address the service holds (unchecked: see Address.Check
// and Probe), ErrNotHeld, ErrClockSkew, a *RateLimitedError, or another
// error for a service that did not answer.
func (c *Client) Collect(ctx context.Context, setupID, fingerprint string) (Address, error) {
	at := c.now().UTC().Truncate(time.Second).Format(time.RFC3339)
	sig, err := c.signer.Sign(channel.ContextConnectCollect, channel.ConnectCollectBody(setupID, fingerprint, at))
	if err != nil {
		return Address{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	res, err := c.rpc.CollectAddress(ctx, connect.NewRequest(&connectv1.CollectAddressRequest{
		SetupId: setupID, EnginePublicKey: b64.EncodeToString(c.signer.PublicKeySPKI()), Time: at, Signature: b64.EncodeToString(sig),
	}))
	if err != nil {
		return Address{}, collectError(err)
	}
	t := res.Msg.GetAddress()
	if t == nil {
		return Address{}, errors.New("the connect service answered without an address")
	}
	return Address{Host: t.GetHost(), Port: int(t.GetPort()), Database: t.GetDatabase(), SupabaseRef: t.GetSupabaseRef()}, nil
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
	return fmt.Errorf("the connect service refused the collect (%s)", ce.Code())
}
