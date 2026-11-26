package revert

import (
	"context"
	"crypto/rand"
	"log/slog"
	"runtime"
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
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgerrors"
	"github.com/basaltdbhq/basaltdb/internal/platform/vault"
)

// settings are what a test sets before the service is built: the revert use
// case's own core and deps, and the delivery use case it sits on.
type settings struct {
	core     Core
	store    Store
	deps     Deps
	links    linksvc.Core
	delivery linksvc.Deps
	runs     RunFinder
	timeout  time.Duration
}

// option edits the settings a service is built from.
type option func(*settings)

// pagesOrigin is the origin of the pages the engine serves ("" serves none).
func pagesOrigin(origin string) option { return func(s *settings) { s.links.PagesOrigin = origin } }

// linkBudget is the character budget of a link.
func linkBudget(n int) option { return func(s *settings) { s.core.LinkBudget = n } }

// withStore binds the revert store.
func withStore(st Store) option { return func(s *settings) { s.store = st } }

// withRuns binds the finder of the agent's runs.
func withRuns(r RunFinder) option { return func(s *settings) { s.runs = r } }

// withStatementTimeout is the agent's statement timeout the describe use case reports.
func withStatementTimeout(d time.Duration) option { return func(s *settings) { s.timeout = d } }

// withReceipts signs the receipts with signer.
func withReceipts(signer linksvc.ReceiptSigner) option {
	return func(s *settings) { s.delivery.Receipts = signer }
}

// withNow fixes the clock.
func withNow(now time.Time) option {
	return func(s *settings) {
		s.core.Now, s.links.Now = func() time.Time { return now }, func() time.Time { return now }
	}
}

// withOperatedBy is an engine whose operatedBy is by.
func withOperatedBy(by string) option {
	return func(s *settings) {
		s.core.Commands = s.core.Commands.OperatedBy(by)
		s.links.Commands = s.core.Commands
	}
}

// newService builds the revert use case on a real delivery use case, with
// the settings a test sets after goos and configPath (the platform default
// config when configPath is empty).
func newService(t *testing.T, goos, configPath string, opts ...option) *Service {
	t.Helper()
	if goos == "" {
		goos = runtime.GOOS
	}
	cmds := guidance.NewCommands("bot", configPath, config.DefaultPath(goos), goos, osservice.Manager())
	st := settings{
		core:  Core{Name: "bot", Log: slog.New(slog.DiscardHandler), Now: time.Now, Commands: cmds, Errors: pgerrors.Map()},
		store: struct{ Store }{},
		deps: Deps{
			AfterAnswer: vault.AfterAnswer, RotateSession: vault.RotateSession,
		},
		runs: foundRuns{},
	}
	st.core.PagesBase, st.core.LinkBudget = links.DefaultLocal, links.DefaultBudget
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
	failure := func(_ string, _ map[string]any, err error) *toolresult.ToolError {
		return st.core.Errors.ToolError(err)
	}
	delivery := linksvc.New(st.links, &st.delivery, noApprovals{}, failure)
	return New(st.core, storeSet(st.store), &st.deps, st.runs, delivery, describing{st.timeout}, admitted{})
}

// storeSet is the store set over st, as the wiring builds it.
func storeSet(st Store) StoreSet {
	return StoreSet{
		Limits: Limits{Prepare: guardmodel.MCPPrepareTimeout}, Records: st, Undo: st, Proofs: st,
	}
}

// noApprovals is the approvals the delivery use case reads: none.
type noApprovals struct{}

func (noApprovals) Passkeys(context.Context) ([]passkey.Credential, error) { return nil, nil }
func (noApprovals) FindApproval(context.Context, uuid.UUID) (action.Approval, error) {
	return action.Approval{}, ledger.ErrApprovalNotFound
}
func (noApprovals) HasColumns() bool { return false }
func (noApprovals) ColumnOrder(context.Context, []string) (map[string][]string, error) {
	return map[string][]string{}, nil
}

// foundRuns finds every run.
type foundRuns struct{}

func (foundRuns) FindRun(context.Context, uuid.UUID) (action.Run, error) { return action.Run{}, nil }

// noRuns is a RunFinder that finds none of the agent's runs.
type noRuns struct{}

func (noRuns) FindRun(context.Context, uuid.UUID) (action.Run, error) {
	return action.Run{}, action.ErrRunNotFound
}

// describing reports the statement timeout.
type describing struct{ timeout time.Duration }

func (d describing) StatementTimeout() time.Duration { return d.timeout }

// admitted admits every call.
type admitted struct{}

func (admitted) Admit(context.Context) error { return nil }
