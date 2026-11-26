package status

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/engineos"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/laststop"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgerrors"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// statusNow is the clock of every test.
var statusNow = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

// testSetupCode and testFingerprint stand for a pending setup code (in the
// codec's alphabet) and its fingerprint.
const (
	testSetupCode   = "basalt-setup.1.eJzLSM3JyVcozy_KSQEAGgQEXQ.Ab3_x9"
	testFingerprint = "a1b2 c3d4 e5f6 0718 293a"
)

// errNoRole is the store's answer to a role that cannot log in.
var errNoRole = store.MapError(&pgconn.PgError{Code: "28P01", Message: "password authentication failed"})

// fakeProbe is a Probe with a fixed answer.
type fakeProbe struct {
	st  guardmodel.Status
	err error
	// recorded and recordedErr answer SetupRecorded.
	recorded    bool
	recordedErr error
	latest      *guardmodel.AgentSetup
}

func (p *fakeProbe) LedgerBytes(context.Context) (int64, error) { return 0, nil }

func (p *fakeProbe) ReinstallNotice(context.Context, int) (string, bool, error) {
	return "", false, nil
}

func (p *fakeProbe) GuardStatus(context.Context) (guardmodel.Status, error) { return p.st, p.err }

func (p *fakeProbe) SetupRecorded(context.Context, uuid.UUID) (bool, error) {
	return p.recorded, p.recordedErr
}

func (p *fakeProbe) LatestSetup(context.Context) (guardmodel.AgentSetup, bool, error) {
	if p.latest == nil {
		return guardmodel.AgentSetup{}, false, nil
	}
	return *p.latest, true, nil
}

// keys answers Passkeys with n passkeys.
type keys struct{ n int }

func (k keys) Passkeys(context.Context) ([]passkey.Credential, error) {
	return testKeys()[:k.n], nil
}

// testKeys are eight fixed-for-the-run P-256 credentials with ids 1..8,
// registered on the default local pages.
var testKeys = sync.OnceValue(func() []passkey.Credential {
	out := make([]passkey.Credential, 8)
	for i := range out {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		// On the default local pages, where the agent's links open unless a
		// test sets another pages base.
		out[i] = passkey.Credential{ID: []byte{byte(i + 1)}, PublicKey: &k.PublicKey, Relying: passkey.Relying{RPID: "localhost", Origin: links.DefaultLocal}}
	}
	return out
})

// currentGuard is a guard that is installed and up to date.
func currentGuard() guardmodel.Status {
	b := guard.LatestVersion()
	return guardmodel.Status{State: guardmodel.GuardOK, Installed: b, Build: b}
}

func pendingSetup(kind string, expires time.Time) *config.Setup {
	return &config.Setup{
		SetupID: "0193a4c2-7d1e-7c3a-9f00-0000000000e5", Kind: kind, GuardVersion: guard.LatestVersion(),
		ExpiresAt: expires.UTC().Format(time.RFC3339), Code: testSetupCode, Fingerprint: testFingerprint,
	}
}

func findProblem(t *testing.T, r guidance.StatusReport, code string) guidance.Problem {
	t.Helper()
	for _, p := range r.Problems {
		if p.Code == code {
			return p
		}
	}
	require.Failf(t, "problem missing", "no %s in %+v", code, r.Problems)
	return guidance.Problem{}
}

// settings are what newService builds the status use case from.
type settings struct {
	core Core
	deps Deps
}

// option changes the settings before the service is built.
type option func(*settings)

// newService builds the status use case for the agent bot with the settings
// every test shares, a probe that reports a current guard, one passkey and
// the clock statusNow. opts change the core and the deps before the service
// is built.
func newService(opts ...option) *Service {
	cmds := guidance.NewCommands("bot", "", config.DefaultPath("linux"), "linux", osservice.Manager())
	s := settings{
		core: Core{
			Name: "bot", Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow },
			Commands: cmds, Errors: pgerrors.Map(), PagesBase: links.DefaultLocal, LinkBudget: links.DefaultBudget,
		},
		deps: Deps{
			Passkeys: keys{n: 1}, Probe: &fakeProbe{st: currentGuard()},
			LatestGuardVersion: guard.LatestVersion,
		},
	}
	for _, opt := range opts {
		opt(&s)
	}
	return New(s.core, &s.deps)
}

// commandsAt are the commands of the agent bot on linux, with the engine
// config at configPath ("" for the platform default).
func commandsAt(configPath string) guidance.Commands {
	return guidance.NewCommands("bot", configPath, config.DefaultPath("linux"), "linux", osservice.Manager())
}

// statusCredential is a credential file path no status output may hold.
const statusCredential = "/etc/basalt/agents/bot.url"

func testEngineHost() EngineHost {
	return EngineHost{
		LatestGuardVersion: guard.LatestVersion,
		ReadLastStop:       engine.LastStopReader(engineos.OS{}),
		StartHoldOffUntil: func(stop guidance.LastStop, configPath string, now time.Time) (time.Time, bool) {
			return laststop.StartHoldOffUntil(servicespec.LastStopFileRecord{Reason: stop.Reason, At: stop.At, EngineSHA256: stop.EngineSHA256}, configPath, now)
		},
	}
}
