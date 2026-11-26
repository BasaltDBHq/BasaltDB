package app

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/lib/sysdns"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// The connect probe is wired with the reader of a refused login's server
// message, so Supabase's pooler not knowing the role counts as a refusal
// there as in basalt init --remote.
func TestWireHandoffReadsTheServerMessage(t *testing.T) {
	t.Parallel()
	o := wireHandoff(handoffOptions{})
	require.NotNil(t, o.Prober.Errors)
	noTenant := fmt.Errorf("failed to connect: %w", &pgconn.PgError{Code: setup.SQLStateInternal, Message: setup.SupavisorNoTenant})
	require.True(t, setup.LoginRefused(o.Prober.Errors, noTenant))
	require.True(t, setup.LoginProves(o.Prober.Errors, "verify-full", false, noTenant))
}

// The connect probe is wired with the system's DNS and the chain read: the
// handoff service reaches the network only through them.
func TestWireHandoffFillsTheNetwork(t *testing.T) {
	t.Parallel()
	o := wireHandoff(handoffOptions{})
	require.Equal(t, sysdns.Resolver{}, o.Prober.Resolver)
	require.NotNil(t, o.Prober.ReadChain)
}

// The engine's setup finisher is built with the same reader, so the
// pooler not knowing the role is a setup not run yet there too.
func TestAgentFinisherReadsTheServerMessage(t *testing.T) {
	t.Parallel()
	f := agentFinisher("/etc/basalt/engine.json", "bot", "/etc/basalt/bot.url", nil,
		handoff.LoginTarget{}, noPassword{}, func() {}, slog.New(slog.DiscardHandler))
	require.NotNil(t, f.Errors)
	noTenant := fmt.Errorf("failed to connect: %w", &pgconn.PgError{Code: setup.SQLStateInternal, Message: setup.SupavisorNoTenant})
	require.True(t, setup.LoginRefused(f.Errors, noTenant))
}

type noPassword struct{}

func (noPassword) Set(string) {}
