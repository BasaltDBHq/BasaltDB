// Package connectrpc is the handoff domain's transport to the connect
// service: the generated ConnectRPC client of its SetupService over HTTPS.
// It implements handoff.SetupService: it builds the proto requests from the
// calls handoff.Client signs, and maps the service's refusals to the
// engine's errors in internal/core/connecthandoff.
package connectrpc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"

	connectv1 "github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1"
	"github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1/connectv1connect"
	"github.com/basaltdbhq/basaltdb/internal/core/connecthandoff"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// requestTimeout bounds one call when the caller gives no HTTP client.
const requestTimeout = 20 * time.Second

// The refusals CollectAddress and ReportReach answer with (CONTRACT.md, Connect refusals).
const (
	reasonHandoffUnknown = "HANDOFF_UNKNOWN"
	reasonClockSkew      = "CLOCK_SKEW"
	reasonRateLimited    = "RATE_LIMITED"
)

// Client is the connect service's SetupService, for handoff.Client.
type Client struct {
	rpc connectv1connect.SetupServiceClient
}

// New is a client of the SetupService at baseURL (handoff.ServiceURL
// outside tests) through httpClient, or a client with requestTimeout when
// httpClient is nil.
func New(httpClient *http.Client, baseURL string) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	}
	return &Client{rpc: connectv1connect.NewSetupServiceClient(httpClient, baseURL)}
}

// CollectAddress asks for the address the service holds for req's setup.
func (c *Client) CollectAddress(ctx context.Context, req connecthandoff.CollectRequest) (connecthandoff.Collected, error) {
	res, err := c.rpc.CollectAddress(ctx, connect.NewRequest(&connectv1.CollectAddressRequest{
		SetupId: req.SetupID, EnginePublicKey: req.EnginePublicKey, Time: req.Time, Signature: req.Signature,
	}))
	if err != nil {
		return connecthandoff.Collected{}, refusal(err)
	}
	t := res.Msg.GetAddress()
	if t == nil {
		return connecthandoff.Collected{}, errors.New("the connect service answered without an address")
	}
	return connecthandoff.Collected{
		Address:   setupcode.Address{Host: t.GetHost(), Port: int(t.GetPort()), Database: t.GetDatabase(), SupabaseRef: t.GetSupabaseRef()},
		Phase:     res.Msg.GetPhase(),
		TrustRoot: res.Msg.GetTrustRoot(),
	}, nil
}

// ReportReach tells the service whether the engine reached req.Address.
func (c *Client) ReportReach(ctx context.Context, req connecthandoff.ReachReport) error {
	a := req.Address
	_, err := c.rpc.ReportReach(ctx, connect.NewRequest(&connectv1.ReportReachRequest{
		SetupId: req.SetupID, EnginePublicKey: req.EnginePublicKey, Time: req.Time,
		Address: &connectv1.Target{Host: a.Host, Port: int32(a.Port), Database: a.Database, SupabaseRef: a.SupabaseRef},
		Result:  req.Result, Reason: req.Reason, Signature: req.Signature,
	}))
	if err != nil {
		return refusal(err)
	}
	return nil
}

// ReportRemoved tells the service that the engine removed itself. A
// service that does not serve the call yet (an older deploy) answers
// unimplemented, which maps to an error that is no refusal: the engine
// exits all the same, and the page waits as it did before.
func (c *Client) ReportRemoved(ctx context.Context, req connecthandoff.RemovedReport) error {
	_, err := c.rpc.ReportRemoved(ctx, connect.NewRequest(&connectv1.ReportRemovedRequest{
		SetupId: req.SetupID, EnginePublicKey: req.EnginePublicKey, Time: req.Time,
		Result: req.Result, Reason: req.Reason, Signature: req.Signature,
	}))
	if err != nil {
		return refusal(err)
	}
	return nil
}

// refusal maps the service's refusal to the engine's errors. The service's
// message is never passed on: it is not the engine's to trust.
func refusal(err error) error {
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
			return connecthandoff.ErrNotHeld
		case reasonClockSkew:
			return connecthandoff.ErrClockSkew
		case reasonRateLimited:
			return &connecthandoff.RateLimitedError{After: time.Duration(max(r.GetRetryAfterSeconds(), 1)) * time.Second}
		}
	}
	return fmt.Errorf("the connect service refused the call (%s)", ce.Code())
}
