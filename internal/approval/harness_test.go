package approval

import (
	"context"
	"crypto/rand"
	"log/slog"
	"runtime"
	"testing"
	"time"

	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgerrors"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault"
)

// settings are what a test sets before the service is built: the approval
// use case's own core, store and deps, and the delivery use case it sits on.
type settings struct {
	core     Core
	store    Store
	deps     Deps
	links    linksvc.Core
	delivery linksvc.Deps
}

// option edits the settings a service is built from.
type option func(*settings)

// pagesOrigin is the origin of the pages the engine serves ("" serves none).
func pagesOrigin(origin string) option { return func(s *settings) { s.links.PagesOrigin = origin } }

// linkBudget is the character budget of a link.
func linkBudget(n int) option { return func(s *settings) { s.core.LinkBudget = n } }

// withOperatedBy is an engine whose operatedBy is by.
func withOperatedBy(by string) option {
	return func(s *settings) {
		s.core.Commands = s.core.Commands.OperatedBy(by)
		s.links.Commands = s.core.Commands
	}
}

// withCommands sets the commands the messages name.
func withCommands(c guidance.Commands) option {
	return func(s *settings) { s.core.Commands, s.links.Commands = c, c }
}

// withNow fixes the clock.
func withNow(now time.Time) option {
	return func(s *settings) { s.core.Now = func() time.Time { return now } }
}

// newService builds the approval use case on a real delivery use case, with
// the settings a test sets after goos and configPath (the platform default
// config when configPath is empty).
func newService(t *testing.T, goos, configPath string, opts ...option) *Service {
	t.Helper()
	if goos == "" {
		goos = runtime.GOOS
	}
	cmds := guidance.NewCommands("bot", configPath, config.DefaultPath(goos), goos, osservice.Manager())
	st := settings{
		core: Core{
			Name: "bot", Log: slog.New(slog.DiscardHandler), Now: time.Now, Commands: cmds, Errors: pgerrors.Map(),
			PagesBase: links.DefaultLocal, LinkBudget: links.DefaultBudget,
		},
		store: catalogStore{},
		deps:  Deps{SortSpec: ledger.ApprovalSortSpec},
	}
	st.links = linksvc.Core{Name: "bot", Log: st.core.Log, Now: st.core.Now, Commands: cmds, Errors: st.core.Errors, PagesBase: st.core.PagesBase}
	st.delivery = linksvc.Deps{
		Notifier: linksvc.NoNotifier{}, Links: links.NewSecrets(time.Now, rand.Reader), Poll: time.Second,
		Relay:         linksvc.NoRelay{NotConnected: vault.ErrNotConnected},
		VaultConflict: vault.IsConflict, ErrVaultNotConnected: vault.ErrNotConnected,
	}
	for _, opt := range opts {
		opt(&st)
	}
	st.links.Now = st.core.Now
	set := StoreSet{Records: st.store, Holds: st.store, Proofs: st.store}
	failure := func(_ string, _ map[string]any, err error) *toolresult.ToolError {
		return st.core.Errors.ToolError(err)
	}
	delivery := linksvc.New(st.links, &st.delivery, storeReads{st.store}, failure)
	return New(st.core, set, &st.deps, delivery, noReverts{}, foundRuns{}, admitted{})
}

// storeReads is what the delivery use case reads of the approval records,
// from the store as the app wires it; the pages show the rows' field order.
type storeReads struct{ Records }

func (storeReads) HasColumns() bool { return false }

func (storeReads) ColumnOrder(context.Context, []string) (map[string][]string, error) {
	return map[string][]string{}, nil
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

// catalogStore is the approvals store the cases need: the failure is raised
// by the test, so only the lookups the use case makes while building steps
// answer.
type catalogStore struct{ Store }

func (catalogStore) Passkeys(context.Context) ([]passkey.Credential, error) { return nil, nil }

// foundRuns finds every run.
type foundRuns struct{}

func (foundRuns) CheckRun(context.Context, uuid.UUID) error { return nil }

// admitted admits every call.
type admitted struct{}

func (admitted) Admit(context.Context) error { return nil }

// noReverts lists no open revert.
type noReverts struct{}

func (noReverts) ListOpenReverts(context.Context, action.RevertListParams) (pagination.Page[action.Revert], error) {
	return pagination.Page[action.Revert]{}, nil
}

func (noReverts) PendingRevert(context.Context, *revertsvc.PendingRevert, bool) error { return nil }

// WithdrawRevert finds no revert to withdraw.
func (noReverts) WithdrawRevert(context.Context, uuid.UUID, string) (action.Withdrawal, bool, error) {
	return action.Withdrawal{}, false, nil
}
