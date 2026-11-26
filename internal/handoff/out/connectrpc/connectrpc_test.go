package connectrpc_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	connectv1 "github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1"
	"github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1/connectv1connect"
	"github.com/basaltdbhq/basaltdb/internal/core/connecthandoff"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/handoff/out/connectrpc"
)

var _ handoff.SetupService = (*connectrpc.Client)(nil)

// setupService answers CollectAddress and ReportReach with collect and
// reach, and records the requests.
type setupService struct {
	connectv1connect.UnimplementedSetupServiceHandler
	collect   func() (*connectv1.CollectAddressResponse, error)
	reach     error
	collected *connectv1.CollectAddressRequest
	reported  *connectv1.ReportReachRequest
}

func (s *setupService) CollectAddress(_ context.Context, r *connect.Request[connectv1.CollectAddressRequest]) (*connect.Response[connectv1.CollectAddressResponse], error) {
	s.collected = r.Msg
	res, err := s.collect()
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (s *setupService) ReportReach(_ context.Context, r *connect.Request[connectv1.ReportReachRequest]) (*connect.Response[connectv1.ReportReachResponse], error) {
	s.reported = r.Msg
	if s.reach != nil {
		return nil, s.reach
	}
	return connect.NewResponse(&connectv1.ReportReachResponse{}), nil
}

func serve(t *testing.T, s *setupService) *connectrpc.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(connectv1connect.NewSetupServiceHandler(s))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return connectrpc.New(srv.Client(), srv.URL)
}

func refused(t *testing.T, code connect.Code, r *connectv1.Refusal) error {
	t.Helper()
	e := connect.NewError(code, errors.New("the service's own words"))
	if r != nil {
		d, err := connect.NewErrorDetail(r)
		require.NoError(t, err)
		e.AddDetail(d)
	}
	return e
}

func TestCollectAddressSendsTheSignedCallAndReadsTheAnswer(t *testing.T) {
	s := &setupService{collect: func() (*connectv1.CollectAddressResponse, error) {
		return &connectv1.CollectAddressResponse{
			Address: &connectv1.Target{Host: "db.example.com", Port: 6543, Database: "app", SupabaseRef: "ref"},
			Phase:   connecthandoff.HoldSetUp, TrustRoot: "root",
		}, nil
	}}
	got, err := serve(t, s).CollectAddress(context.Background(), connecthandoff.CollectRequest{SetupID: "id", EnginePublicKey: "key", Time: "at", Signature: "sig"})
	require.NoError(t, err)
	require.Equal(t, connecthandoff.Collected{
		Address: setupcode.Address{Host: "db.example.com", Port: 6543, Database: "app", SupabaseRef: "ref"},
		Phase:   connecthandoff.HoldSetUp, TrustRoot: "root",
	}, got)
	require.True(t, got.SetUp())
	require.Equal(t, "id", s.collected.GetSetupId())
	require.Equal(t, "key", s.collected.GetEnginePublicKey())
	require.Equal(t, "at", s.collected.GetTime())
	require.Equal(t, "sig", s.collected.GetSignature())
}

func TestCollectAddressWithoutAnAddressFails(t *testing.T) {
	s := &setupService{collect: func() (*connectv1.CollectAddressResponse, error) {
		return &connectv1.CollectAddressResponse{Phase: connecthandoff.HoldPreview}, nil
	}}
	_, err := serve(t, s).CollectAddress(context.Background(), connecthandoff.CollectRequest{})
	require.EqualError(t, err, "the connect service answered without an address")
}

func TestReportReachSendsTheSignedReport(t *testing.T) {
	s := &setupService{}
	err := serve(t, s).ReportReach(context.Background(), connecthandoff.ReachReport{
		SetupID: "id", EnginePublicKey: "key", Time: "at", Signature: "sig",
		Address: setupcode.Address{Host: "db.example.com", Port: 5432, Database: "app", SupabaseRef: "ref"},
		Result:  "UNREACHABLE", Reason: "BECAUSE",
	})
	require.NoError(t, err)
	r := s.reported
	require.Equal(t, []string{"id", "key", "at", "sig", "UNREACHABLE", "BECAUSE"},
		[]string{r.GetSetupId(), r.GetEnginePublicKey(), r.GetTime(), r.GetSignature(), r.GetResult(), r.GetReason()})
	require.Equal(t, []any{"db.example.com", int32(5432), "app", "ref"},
		[]any{r.GetAddress().GetHost(), r.GetAddress().GetPort(), r.GetAddress().GetDatabase(), r.GetAddress().GetSupabaseRef()})
}

// Both calls map the service's refusals to the engine's own errors, with the
// same identity handoff decides on, and never pass the service's message on.
func TestRefusalsMapToTheEnginesErrors(t *testing.T) {
	cases := []struct {
		name   string
		answer func(t *testing.T) error
		check  func(t *testing.T, err error)
	}{
		{"handoff unknown", func(t *testing.T) error {
			return refused(t, connect.CodeNotFound, &connectv1.Refusal{Reason: "HANDOFF_UNKNOWN"})
		}, func(t *testing.T, err error) {
			require.ErrorIs(t, err, handoff.ErrNotHeld)
			require.EqualError(t, err, "the connect service holds no address for this setup yet")
		}},
		{"clock skew", func(t *testing.T) error {
			return refused(t, connect.CodeFailedPrecondition, &connectv1.Refusal{Reason: "CLOCK_SKEW"})
		}, func(t *testing.T, err error) {
			require.ErrorIs(t, err, handoff.ErrClockSkew)
			require.EqualError(t, err, "the clock of the bot's machine is more than 5 minutes off")
		}},
		{"rate limited", func(t *testing.T) error {
			return refused(t, connect.CodeResourceExhausted, &connectv1.Refusal{Reason: "RATE_LIMITED", RetryAfterSeconds: 7})
		}, func(t *testing.T, err error) {
			var rl *handoff.RateLimitedError
			require.ErrorAs(t, err, &rl)
			require.Equal(t, 7*time.Second, rl.After)
			require.EqualError(t, err, "the connect service asks to wait 7s before collecting again")
		}},
		{"rate limited without a wait waits a second", func(t *testing.T) error {
			return refused(t, connect.CodeResourceExhausted, &connectv1.Refusal{Reason: "RATE_LIMITED"})
		}, func(t *testing.T, err error) {
			var rl *handoff.RateLimitedError
			require.ErrorAs(t, err, &rl)
			require.Equal(t, time.Second, rl.After)
		}},
		{"another reason", func(t *testing.T) error {
			return refused(t, connect.CodePermissionDenied, &connectv1.Refusal{Reason: "BAD_SIGNATURE"})
		}, func(t *testing.T, err error) {
			require.EqualError(t, err, "the connect service refused the call (permission_denied)")
		}},
		{"no refusal detail", func(t *testing.T) error {
			return refused(t, connect.CodeInternal, nil)
		}, func(t *testing.T, err error) {
			require.EqualError(t, err, "the connect service refused the call (internal)")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/collect", func(t *testing.T) {
			answer := tc.answer(t)
			s := &setupService{collect: func() (*connectv1.CollectAddressResponse, error) { return nil, answer }}
			_, err := serve(t, s).CollectAddress(context.Background(), connecthandoff.CollectRequest{})
			tc.check(t, err)
		})
		t.Run(tc.name+"/reach", func(t *testing.T) {
			s := &setupService{reach: tc.answer(t)}
			tc.check(t, serve(t, s).ReportReach(context.Background(), connecthandoff.ReachReport{}))
		})
	}
}

// The client reports a service it cannot reach as a ConnectRPC error, so a
// dead service reads as refused with code unavailable, as it did before the
// adapter held the mapping.
func TestAServiceThatIsGoneIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c := connectrpc.New(nil, url)
	_, err := c.CollectAddress(context.Background(), connecthandoff.CollectRequest{})
	require.EqualError(t, err, "the connect service refused the call (unavailable)")
	require.EqualError(t, c.ReportReach(context.Background(), connecthandoff.ReachReport{}), "the connect service refused the call (unavailable)")
}
