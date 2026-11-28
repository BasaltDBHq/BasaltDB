package app

import (
	"context"
	"encoding/base64"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/handoff/out/connectrpc"
	"github.com/basaltdbhq/basaltdb/internal/testkit/connecttest"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// The removal hand-off over the wire, with no database: the connect
// service holds a REMOVED hold for the engine's removal link, the engine
// collects it signed with its key, finds its role gone, confirms, and its
// ReportRemoved is what the page then reads. A hold of the same code made
// up by the service while the role still logs in removes nothing.
func TestSelfRemoveOverTheConnectProtocol(t *testing.T) {
	t.Parallel()
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	target := setupcode.Target{Host: "db.example.com", Port: 5432, Database: "shop"}
	now := time.Now()
	id, expires, err := setupcode.NewSetupID(now, nil)
	require.NoError(t, err)
	p := setupcode.Payload{
		Format: setupcode.Format, SetupID: id, Kind: setupcode.KindAgent, Prefix: "basalt", Target: &target,
		Guard: setupcode.Guard{From: 1, To: 1}, Build: "0.1.0", ExpiresAt: expires,
		Engine: &setupcode.Engine{PublicKey: base64.RawURLEncoding.EncodeToString(keys.PublicKeySPKI())},
		Agent:  &setupcode.Agent{Name: "bot", StatementTimeoutMs: 30000},
	}
	code, err := setupcode.Encode(p)
	require.NoError(t, err)
	rm := config.Removal{SetupID: id, ExpiresAt: expires, Code: code, Fingerprint: p.Fingerprint()}

	srv, base := connecttest.Start(t)
	client := handoff.NewClient(connectrpc.New(nil, base), keys, time.Now)
	run := func(login error) []handoff.Removed {
		var got []handoff.Removed
		r := handoff.NewSelfRemove(handoff.SelfRemoveOptions{
			Agent: "bot", Credential: setupcode.Address(target), Collector: client,
			Login:     func(context.Context) error { return login },
			Pending:   func() (config.Removal, bool, error) { return rm, true, nil },
			Confirmed: func(_ context.Context, r handoff.Removed) bool { got = append(got, r); return true },
			Log:       slog.New(slog.DiscardHandler), Now: time.Now,
		})
		r.Step(context.Background())
		return got
	}

	require.Empty(t, run(handoff.ErrLoginRefused), "no hold yet")
	srv.ForgeRemoved(id, p.Engine.PublicKey, rm.Fingerprint, setup.Target(target))
	require.Empty(t, run(nil), "the role still logs in: a hold alone removes nothing")
	got := run(handoff.ErrLoginRefused)
	require.Len(t, got, 1)
	require.NoError(t, got[0].Report(context.Background(), handoff.RemovedAll, ""))
	kept, ok := srv.RemovedReport(id)
	require.True(t, ok)
	require.Equal(t, handoff.RemovedAll, kept.Result)
}
