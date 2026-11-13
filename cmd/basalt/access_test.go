//go:build linux || darwin

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/pgcatalog"
)

type accessLedger struct {
	emptyLedger
	access pgcatalog.Access
}

func (l accessLedger) ListAccess(context.Context) (pgcatalog.Access, error) { return l.access, nil }

func runAccessOver(t *testing.T, a pgcatalog.Access, args ...string) result {
	t.Helper()
	socket := personSocketFor(t, personUIDForTest, accessLedger{access: a})
	return serviceRun(t, socket, runAccess, append([]string{"--agent", "bot"}, args...)...)
}

func TestAccessPrintsGrantCommands(t *testing.T) {
	t.Parallel()
	r := runAccessOver(t, pgcatalog.Access{
		Read:       []string{"public.leads"},
		Write:      []string{"public.orders"},
		NotGranted: []string{"public.invoices"},
	})
	require.Equal(t, exitOK, r.code, r.stderr)
	for _, section := range []string{"Can read", "Can write", "Not granted"} {
		require.Contains(t, r.stdout, section)
	}
	require.Contains(t, r.stdout, "public.leads")
	require.Contains(t, r.stdout, "public.orders")
	require.Contains(t, r.stdout, "public.invoices")
	require.Contains(t, r.stdout, "basalt init --agent bot --read=public.invoices")
	require.NotContains(t, r.stdout, "--read public.leads")
	require.True(t, strings.HasSuffix(r.stdout, "These names are not shown to the agent.\n"), r.stdout)
}

func TestAccessBadTableName(t *testing.T) {
	t.Parallel()
	r := runAccessOver(t, pgcatalog.Access{NotGranted: []string{`public."odd name"`}})
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, `public."odd name"`)
	require.Contains(t, r.stdout, "grant by hand")
	require.NotContains(t, r.stdout, "basalt init")
}

func TestAccessGroupsBySchemaWhenThereAreSeveral(t *testing.T) {
	t.Parallel()
	r := runAccessOver(t, pgcatalog.Access{
		Read:       []string{"public.leads", "sales.deals"},
		NotGranted: []string{"auth.users"},
	})
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "public\n")
	require.Contains(t, r.stdout, "sales\n")
	one := runAccessOver(t, pgcatalog.Access{Read: []string{"public.leads"}})
	require.NotContains(t, one.stdout, "public\n", "one schema needs no header")
}

func TestAccessSaysNoneForAnEmptySection(t *testing.T) {
	t.Parallel()
	r := runAccessOver(t, pgcatalog.Access{Read: []string{"public.leads"}})
	require.Contains(t, r.stdout, "Not granted\n  none")
}

func TestAccessJSON(t *testing.T) {
	t.Parallel()
	r := runAccessOver(t, pgcatalog.Access{Read: []string{"public.leads"}}, "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.JSONEq(t, `{"read":["public.leads"],"write":[],"notGranted":[]}`, r.stdout)
}

func TestAccessDirectModeUsesTheAgentCredential(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	initAgent(t, d, cfgPath)

	r := cli(t, nil, "", "access", "--agent", "bot", "--config", cfgPath)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "Can read\n")
	require.Contains(t, r.stdout, "public.leads")
	require.NotContains(t, r.stdout, "basalt_meta")
	require.True(t, strings.HasSuffix(r.stdout, "These names are not shown to the agent.\n"), r.stdout)
}
