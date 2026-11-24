package agent

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/agent/out/sqllang"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// noChecker is a statement check these tests never ask: it refuses every
// statement.
type noChecker struct{}

func (noChecker) Check(string, action.Tool) (action.Statement, error) {
	return action.Statement{}, errors.New("these tests check no statement")
}

// settings are what a test sets before the service is built.
type settings struct {
	core  Core
	store StoreSet
}

// option edits the settings a service is built from.
type option func(*settings)

// withOperatedBy is an engine whose operatedBy is by.
func withOperatedBy(by string) option {
	return func(s *settings) { s.core.Commands = s.core.Commands.OperatedBy(by) }
}

// withRLS sets the row-level security check.
func withRLS(c Visibility) option { return func(s *settings) { s.store.Visibility = c } }

func testManager() guidance.ServiceManager {
	return guidance.ServiceManager{StartCommand: osservice.StartCommand, RestartArgs: osservice.RestartArgs}
}

// newTestService builds the service the tests run on: configPath "" is the
// platform default config.
func newTestService(t *testing.T, goos, configPath string, opts ...option) *Service {
	t.Helper()
	st := settings{
		core: Core{
			Name: "bot", Log: slog.New(slog.DiscardHandler), Now: time.Now,
			Commands: guidance.NewCommands("bot", configPath, config.DefaultPath(goos), goos, testManager()),
		},
		store: StoreSet{Kind: action.StorePostgres, Family: agentstore.FamilySQL, Language: sqllang.New(noChecker{})},
	}
	for _, opt := range opts {
		opt(&st)
	}
	return New(st.core, st.store, nil, func() *guidance.UpdateInfo { return nil })
}

// fakeRLS is a Visibility over fixed hidden tables.
type fakeRLS struct {
	hidden map[string]bool
	err    error
	asked  int
}

// Hides names a hidden table as the database does: quoted.
func (f *fakeRLS) Hides(_ context.Context, table string) (string, error) {
	f.asked++
	if f.hidden[table] {
		return `"` + strings.ReplaceAll(table, ".", `"."`) + `"`, f.err
	}
	return "", f.err
}
