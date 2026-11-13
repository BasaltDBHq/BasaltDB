//go:build linux || darwin

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
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
	// The saved init flags are unreadable here, so only the flag is printed:
	// a full init command would reset the agent's saved flags.
	require.Contains(t, r.stdout, "public.invoices  --read=public.invoices\n")
	require.NotContains(t, r.stdout, "basalt init --agent")
	require.NotContains(t, r.stdout, grantsDoNotStack, "the flag-only path keeps its own hint")
	require.Equal(t, 1, strings.Count(r.stdout, "Add each table to this agent's existing --read list (comma-separated) in the basalt init command you set it up with; init keeps only the last --read.\n"))
	require.NotContains(t, r.stdout, "--read=public.leads")
	require.True(t, strings.HasSuffix(r.stdout, "These names are not shown to the agent.\n"), r.stdout)
}

func TestAccessBadTableName(t *testing.T) {
	t.Parallel()
	// The name as Postgres prints it, quoted where it must be.
	r := runAccessOver(t, pgcatalog.Access{NotGranted: []string{`"Sales"."Order Items"`}})
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, `"Sales"."Order Items"  grant by hand`)
	require.Contains(t, r.stdout, "grant by hand")
	require.NotContains(t, r.stdout, "--read=")
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

func TestAccessDirectModeKeepsTheSavedFlagsInTheGrant(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	initAgent(t, d, cfgPath)
	d.Exec(t, `CREATE TABLE public.invoices (id int)`)

	r := cli(t, nil, "", "access", "--agent", "bot", "--config", cfgPath)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "public.invoices  basalt init ")
	require.Contains(t, r.stdout, "--write=public.leads", "the saved write list is extended, not replaced")
	require.Contains(t, r.stdout, "--read=public.invoices")
	require.Contains(t, r.stdout, "--prefix")
	require.Contains(t, r.stdout, "--os-user")
	require.NotContains(t, r.stdout, "Add each table to this agent's existing --read list")
	require.Contains(t, r.stdout, grantsDoNotStack)
}

// grantsDoNotStack is the line under Not granted when it prints runnable
// commands: each is the saved setup plus one table, so running two leaves
// only the second.
const grantsDoNotStack = "Each command adds one table to the saved setup as it is now; to grant several, list them comma-separated in one command, or run basalt access again after each grant.\n"

func TestAccessSaysGrantCommandsDoNotStack(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	cfgPath := tempConfig(t)
	initAgent(t, d, cfgPath)
	d.Exec(t, `CREATE TABLE public.invoices (id int); CREATE TABLE public.refunds (id int)`)

	r := cli(t, nil, "", "access", "--agent", "bot", "--config", cfgPath)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "public.invoices  basalt init ")
	require.Contains(t, r.stdout, "public.refunds  basalt init ")
	require.Equal(t, 1, strings.Count(r.stdout, grantsDoNotStack), r.stdout)
	require.NotContains(t, r.stdout, "Add each table to this agent's existing --read list")
}

func TestAccessSaysNothingOnStackingWithoutARunnableCommand(t *testing.T) {
	t.Parallel()
	cmds, err := agent.NewCommands("bot", "", "linux", []string{"--write=public.leads"})
	require.NoError(t, err)
	var out strings.Builder
	printAccess(&out, pgcatalog.Access{NotGranted: []string{`"Sales"."Order Items"`, `"Sales"."Refunds"`}}, cmds, true)
	require.Contains(t, out.String(), "grant by hand")
	require.NotContains(t, out.String(), grantsDoNotStack)
}

func TestAccessAgentOperatedEnginePrintsTheSetupCodeRoute(t *testing.T) {
	t.Parallel()
	cmds, err := agent.NewCommands("bot", "", "linux", []string{"--write=public.leads"})
	require.NoError(t, err)
	cmds = cmds.OperatedBy("AGENT")
	want, err := cmds.RemoteGrant("read", "public.invoices")
	require.NoError(t, err)
	var out strings.Builder
	printAccess(&out, pgcatalog.Access{NotGranted: []string{"public.invoices"}}, cmds, true)
	require.Contains(t, out.String(), want)
	require.Contains(t, want, "--remote")
	require.Contains(t, out.String(), grantsDoNotStack)
	require.NotContains(t, out.String(), "Add each table to this agent's existing --read list")
}
