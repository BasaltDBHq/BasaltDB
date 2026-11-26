package handoff

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// certSetup is a certificateChanged AGENT code for db, made now.
func certSetup(t *testing.T, now time.Time) config.Setup {
	t.Helper()
	co, err := setupcode.Decode(fixtureCode)
	require.NoError(t, err)
	id, expires, err := setupcode.NewSetupID(now, rand.Reader)
	require.NoError(t, err)
	target := setupcode.Target{Host: db.Host, Port: db.Port, Database: db.Database}
	p := setupcode.Payload{
		Format: setupcode.Format, SetupID: id, Kind: setupcode.KindAgent, Prefix: "basalt", Target: &target,
		Guard: setupcode.Guard{To: 1}, Build: "0.1.0", ExpiresAt: expires, Engine: co.Engine,
		Agent: &setupcode.Agent{Name: "lead_bot", Write: []string{"public.leads"}, Read: []string{}, StatementTimeoutMs: 30000},
	}
	code, err := setupcode.Encode(p)
	require.NoError(t, err)
	return config.Setup{SetupID: id, Kind: string(setupcode.KindAgent), GuardVersion: 1, ExpiresAt: expires, Code: code, Fingerprint: p.Fingerprint(), CertificateChanged: true}
}

// holdCollector answers every collect with one hold.
type holdCollector struct {
	hold Collected
	err  error
}

func (c holdCollector) Collect(context.Context, string, string) (Collected, error) {
	return c.hold, c.err
}

func (holdCollector) Report(context.Context, string, string, setupcode.Address, Reach) error {
	return nil
}

// repinFiles record what the engine would write.
type fakeRepinFiles struct {
	mu       sync.Mutex
	setup    config.Setup
	replaced []Pin
}

func (f *fakeRepinFiles) PendingSetup() (config.Setup, bool, error) { return f.setup, true, nil }

func (f *fakeRepinFiles) ReplacePin(_ string, top *x509.Certificate, caOnly bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replaced = append(f.replaced, Pin{Top: top, CAOnly: caOnly})
	return nil
}

// The engine replaces its own pin only on a SET_UP hold of the
// credential's own database whose trustRoot its own reading of the chain
// shows; another top, another database or a preview pins nothing.
func TestRepin(t *testing.T) {
	t.Parallel()
	now := time.Now()
	oldCA, _ := trustprofiletest.Chain(t, db.Host)
	ownPin := trustprofiletest.Profile(t, trustprofile.Operator, trustprofile.PinName(db.Host), []string{"=" + db.Host}, oldCA)
	other, _ := trustprofiletest.Chain(t, db.Host)

	run := func(t *testing.T, hold Collected, credential setupcode.Address) (*trustServer, *fakeRepinFiles, *Repin) {
		t.Helper()
		s := newTrustServer(t, db.Host, ownPin)
		setup := certSetup(t, now)
		files := &fakeRepinFiles{setup: setup}
		r, err := NewRepin(RepinOptions{
			Setup: setup, Credential: credential, Collector: holdCollector{hold: hold}, Prober: s.prober, Files: files,
			Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now },
		})
		require.NoError(t, err)
		r.Step(context.Background())
		return s, files, r
	}

	t.Run("another server's top", func(t *testing.T) {
		t.Parallel()
		// newTrustServer makes a fresh chain each time: this top is not the
		// one the engine reads.
		probe := newTrustServer(t, db.Host)
		_, files, r := run(t, Collected{Address: db, Phase: HoldSetUp, TrustRoot: probe.fingerprint()}, db)
		require.Empty(t, files.replaced)
		require.Equal(t, ProblemTrustRootMismatch, r.Problem())
	})
	t.Run("own reading", func(t *testing.T) {
		t.Parallel()
		s := newTrustServer(t, db.Host, ownPin)
		setup := certSetup(t, now)
		files := &fakeRepinFiles{setup: setup}
		r, err := NewRepin(RepinOptions{
			Setup: setup, Credential: db, Collector: holdCollector{hold: Collected{Address: db, Phase: HoldSetUp, TrustRoot: s.fingerprint()}},
			Prober: s.prober, Files: files, Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now },
		})
		require.NoError(t, err)
		require.False(t, r.Step(context.Background()), "done: collecting stops")
		require.True(t, r.Done())
		require.Len(t, files.replaced, 1)
		require.True(t, files.replaced[0].Top.Equal(s.leaf))
		require.Equal(t, int32(1), s.dials.Load(), "the handshake alone, no login")
	})
	t.Run("another top", func(t *testing.T) {
		t.Parallel()
		_, files, r := run(t, Collected{Address: db, Phase: HoldSetUp, TrustRoot: trustprofile.DERSHA256(other)}, db)
		require.Empty(t, files.replaced)
		require.Equal(t, ProblemTrustRootMismatch, r.Problem())
		require.False(t, r.Done())
	})
	t.Run("another database", func(t *testing.T) {
		t.Parallel()
		elsewhere := setupcode.Address{Host: "other.example.com", Port: 5432, Database: "app"}
		s, files, _ := run(t, Collected{Address: elsewhere, Phase: HoldSetUp, TrustRoot: trustprofile.DERSHA256(other)}, db)
		require.Empty(t, files.replaced)
		require.Zero(t, s.dials.Load(), "nothing is read for another database")
	})
	t.Run("preview", func(t *testing.T) {
		t.Parallel()
		s, files, _ := run(t, Collected{Address: db, Phase: HoldPreview, TrustRoot: trustprofile.DERSHA256(other)}, db)
		require.Empty(t, files.replaced)
		require.Zero(t, s.dials.Load())
	})
	t.Run("no trust root", func(t *testing.T) {
		t.Parallel()
		s, files, _ := run(t, Collected{Address: db, Phase: HoldSetUp}, db)
		require.Empty(t, files.replaced)
		require.Zero(t, s.dials.Load())
	})
}

// Only a certificateChanged code with a target and an engine key is
// collected for.
func TestNewRepinRefuses(t *testing.T) {
	t.Parallel()
	setup := certSetup(t, time.Now())
	setup.CertificateChanged = false
	_, err := NewRepin(RepinOptions{
		Setup: setup, Credential: db, Collector: holdCollector{}, Prober: Prober{}, Files: &fakeRepinFiles{},
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
	})
	require.ErrorIs(t, err, ErrNotCertificateChanged)
	_, err = NewRepin(RepinOptions{
		Setup: fixtureSetup(), Credential: db, Collector: holdCollector{}, Prober: Prober{}, Files: &fakeRepinFiles{},
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
	})
	require.Error(t, err)
}
