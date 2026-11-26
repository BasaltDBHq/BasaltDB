package plugin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgerrors"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault"
)

// serviceSettings are what a test sets before the service is built: the
// plugin use case's own core and deps, the status it reads, and the delivery
// use case it sits on.
type serviceSettings struct {
	core     Core
	deps     Deps
	links    linksvc.Core
	delivery linksvc.Deps
	status   *fakeStatus
	reads    *fakeReads
}

// option edits the settings a service is built from.
type option func(*serviceSettings)

// fakeStatus is the status use case as the plugin use case reads it.
type fakeStatus struct {
	sameUser, devLocalPages bool
	vaultState              string
}

func (f *fakeStatus) SameUser() bool      { return f.sameUser }
func (f *fakeStatus) DevLocalPages() bool { return f.devLocalPages }
func (f *fakeStatus) VaultState() string  { return f.vaultState }
func (*fakeStatus) GuardStatus(context.Context) (guardmodel.Status, error) {
	v := guard.LatestVersion()
	return guardmodel.Status{State: guardmodel.GuardOK, Installed: v, Build: v}, nil
}

// fakeReads is the part of the approval group the delivery use case reads:
// the person's passkeys.
type fakeReads struct{ creds []passkey.Credential }

func (f *fakeReads) Passkeys(context.Context) ([]passkey.Credential, error) { return f.creds, nil }

func (*fakeReads) FindApproval(context.Context, uuid.UUID) (action.Approval, error) {
	return action.Approval{}, errors.New("no approval")
}

func (*fakeReads) HasColumns() bool { return false }

func (*fakeReads) ColumnOrder(context.Context, []string) (map[string][]string, error) {
	return map[string][]string{}, nil
}

// admitted admits every call.
type admitted struct{}

func (admitted) Admit(context.Context) error { return nil }

// agentOperated is an engine whose operatedBy is AGENT.
func agentOperated(s *serviceSettings) {
	s.core.Commands = s.core.Commands.OperatedBy("AGENT")
	s.links.Commands = s.core.Commands
}

// withoutLocalPages is an engine that serves no local pages.
func withoutLocalPages(s *serviceSettings) { s.core.PagesOrigin, s.links.PagesOrigin = "", "" }

// withPagesOrigin sets the origin of the pages the engine serves.
func withPagesOrigin(origin string) option {
	return func(s *serviceSettings) { s.core.PagesOrigin, s.links.PagesOrigin = origin, origin }
}

// withPasskeys is a person with n passkeys registered on the default local pages.
func withPasskeys(n int) option {
	return func(s *serviceSettings) { s.reads.creds = testCredentials(n) }
}

// withPasskeyOrigins is a person with one passkey per origin.
func withPasskeyOrigins(origins ...string) option {
	return func(s *serviceSettings) {
		out := append([]passkey.Credential(nil), testCredentials(len(origins))...) // the shared keys stay as they are
		for i, o := range origins {
			out[i].Relying = passkey.Relying{Origin: o}
		}
		s.reads.creds = out
	}
}

// withSameUser is an engine run as the person's own OS user.
func withSameUser(s *serviceSettings) { s.status.sameUser = true }

// withDevLocalPages is an engine with devLocalPages set.
func withDevLocalPages(s *serviceSettings) { s.status.devLocalPages = true }

// withVault sets the Vault state status reports.
func withVault(state string) option { return func(s *serviceSettings) { s.status.vaultState = state } }

// withRelay sets the Vault link relay.
func withRelay(r linksvc.LinkRelay) option { return func(s *serviceSettings) { s.delivery.Relay = r } }

// withRequests sets the engine-kept plugin requests.
func withRequests(r PluginRequests) option { return func(s *serviceSettings) { s.deps.Requests = r } }

// withApprovals sets the guard's plugin approvals.
func withApprovals(a PluginApprovalStore) option {
	return func(s *serviceSettings) { s.deps.Approvals = a }
}

// newService builds the plugin use case on a real delivery use case, with the
// settings a test sets after goos and configPath (the platform default config
// when configPath is empty): a person-operated engine with local pages, one
// passkey and the guard current.
func newService(t *testing.T, goos, configPath string, opts ...option) *Service {
	t.Helper()
	cmds := guidance.NewCommands("bot", configPath, config.DefaultPath(goos), goos, osservice.Manager())
	now := func() time.Time { return time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC) }
	st := serviceSettings{
		core: Core{
			Name: "bot", Now: now, Commands: cmds, Errors: pgerrors.Map(), PagesOrigin: "http://localhost:7878",
		},
		deps:   Deps{ApprovalsVersion: guard.PluginApprovalsVersion},
		status: &fakeStatus{vaultState: "OFF"},
		reads:  &fakeReads{creds: testCredentials(1)},
	}
	st.links = linksvc.Core{
		Name: "bot", Log: slog.New(slog.DiscardHandler), Now: now, Commands: cmds, Errors: st.core.Errors,
		PagesBase: links.DefaultLocal, PagesOrigin: st.core.PagesOrigin,
	}
	st.delivery = linksvc.Deps{
		Notifier: linksvc.NoNotifier{}, Links: links.NewSecrets(time.Now, rand.Reader), Poll: time.Millisecond,
		Relay:         linksvc.NoRelay{NotConnected: vault.ErrNotConnected},
		VaultConflict: vault.IsConflict, ErrVaultNotConnected: vault.ErrNotConnected,
	}
	for _, opt := range opts {
		opt(&st)
	}
	failure := func(_ string, _ map[string]any, err error) *toolresult.ToolError {
		return st.core.Errors.ToolError(err)
	}
	delivery := linksvc.New(st.links, &st.delivery, st.reads, failure)
	return New(st.core, &st.deps, delivery, st.status, admitted{})
}

// testService is a service with what it takes to build it again under other
// options.
type testService struct {
	*Service
	t            *testing.T
	goos, config string
	opts         []option
}

func newTestService(t *testing.T, goos, config string, opts ...option) *testService {
	t.Helper()
	return &testService{Service: newService(t, goos, config, opts...), t: t, goos: goos, config: config, opts: opts}
}

// with is a new service over the same options and then opts.
func (s *testService) with(opts ...option) *Service {
	s.t.Helper()
	return newService(s.t, s.goos, s.config, append(append([]option(nil), s.opts...), opts...)...)
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

// testCredentials are the first n of them, with distinct keys and ids.
func testCredentials(n int) []passkey.Credential { return testKeys()[:n] }
