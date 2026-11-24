package agent

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/agent/out/sqllang"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// kindStore is a store of one kind: the use cases these tests run read
// nothing else of it.
type kindStore struct {
	Store
	kind action.StoreKind
}

func (k kindStore) Kind() action.StoreKind { return k.kind }

// settings are what a test sets before the service is built.
type settings struct {
	core     Core
	describe DescribeDeps
	write    WriteDeps
}

// option edits the settings a service is built from.
type option func(*settings)

// withOperatedBy is an engine whose operatedBy is by.
func withOperatedBy(by string) option {
	return func(s *settings) { s.core.Commands = s.core.Commands.OperatedBy(by) }
}

// withRLS sets the row-level security check.
func withRLS(c RLSChecker) option { return func(s *settings) { s.write.RLS = c } }

func testManager() guidance.ServiceManager {
	return guidance.ServiceManager{StartCommand: osservice.StartCommand, RestartArgs: osservice.RestartArgs}
}

// newTestService builds the service the tests run on: configPath "" is the
// platform default config.
func newTestService(t *testing.T, goos, configPath string, opts ...option) *Service {
	t.Helper()
	st := settings{core: Core{
		Name: "bot", Store: kindStore{kind: action.StorePostgres}, Language: sqllang.New(nil), Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Commands: guidance.NewCommands("bot", configPath, config.DefaultPath(goos), goos, testManager()),
	}}
	for _, opt := range opts {
		opt(&st)
	}
	return New(st.core, &st.describe, &st.write, func() *guidance.UpdateInfo { return nil })
}

// fakeRLS is a RLSChecker over fixed hidden tables.
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
