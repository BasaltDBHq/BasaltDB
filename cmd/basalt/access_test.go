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

func TestAccessPrintsTheTablesAndHowToGrantOne(t *testing.T) {
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
	require.Contains(t, r.stdout, "  public.invoices\n")
	require.Equal(t, 1, strings.Count(r.stdout, accessGrantHint+"\n"))
	require.NotContains(t, r.stdout, "basalt init", "a person runs no command to grant a table")
	require.NotContains(t, r.stdout, "--read=")
	require.True(t, strings.HasSuffix(r.stdout, "These names are not shown to the agent.\n"), r.stdout)
}

func TestAccessSaysNothingAboutGrantsWithNothingUngranted(t *testing.T) {
	t.Parallel()
	r := runAccessOver(t, pgcatalog.Access{Read: []string{"public.leads"}})
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotContains(t, r.stdout, accessGrantHint)
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
