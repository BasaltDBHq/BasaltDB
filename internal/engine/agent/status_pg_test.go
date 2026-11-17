package agent_test

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// guardWithout is a database whose guard lacks migration version, as an
// engine built with migs sees it: the version is not recorded in
// schema_version (its objects stay, which the engine never looks at to
// decide). It returns the agent's MCP server, as the engine builds it, and
// the admin to change the guard with.
func guardWithout(t *testing.T, version int, migs []guard.Migration) (harness, *guardtest.DB) {
	t.Helper()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE leads (id bigint PRIMARY KEY, name text); INSERT INTO leads VALUES (1, 'Ada')`)
	a := d.NewAgent(t, "bot", []string{"public.leads"}, []string{"public.leads"})
	d.Exec(t, `DELETE FROM basalt_meta.schema_version WHERE version = $1`, version)

	svc := pgService(t, a.URL, withDeps(func(d *agent.Deps, pool *pgxpool.Pool) {
		d.Probe = agent.DBProbe{Q: pool, Migrations: migs}
	})).Svc
	return harness{server: mcp.NewServer(mcp.Info{Name: "basalt"}, agent.Tools(svc)...)}, d
}

// nextBuild is this build's migrations and one more version, the one a
// real guard lacks, as an engine built with it sees the guard.
func nextBuild(breaking bool) (int, []guard.Migration) {
	next := guard.LatestVersion() + 1
	return next, append(guard.Migrations(), guard.Migration{Version: next, Breaking: breaking})
}

func TestAGuardMissingABreakingMigrationServesOnlyStatus(t *testing.T) {
	t.Parallel()
	latest, build := nextBuild(true)
	h, d := guardWithout(t, latest, build)

	for _, tool := range []struct {
		name string
		args map[string]any
	}{
		{"run_start", map[string]any{"intent": "check leads"}},
		{"query", map[string]any{"sql": "SELECT id FROM leads"}},
		{"write", map[string]any{"sql": "UPDATE leads SET name = $1 WHERE id = $2", "params": []any{"Bo", 1}, "intent": "rename"}},
		{"list_runs", map[string]any{}},
	} {
		body, isError := h.call(t, tool.name, tool.args)
		requireToolError(t, body, isError, agent.CodeUnavailable, "GUARD_OUTDATED", "")
		steps := body["nextSteps"].([]any)
		require.Len(t, steps, 3, tool.name)
		require.Equal(t, "basalt upgrade --agent bot", steps[0].(map[string]any)["command"], tool.name)
	}
	body, isError := h.call(t, "status", map[string]any{})
	require.False(t, isError, "%v", body)
	g := body["guard"].(map[string]any)
	require.Equal(t, guard.GuardOutdated, g["state"])
	require.Equal(t, []any{jsonNumber(latest)}, g["missingBreaking"])
	require.Equal(t, false, body["ready"])

	// basalt upgrade records the version: the next call is served, no restart.
	d.Exec(t, `INSERT INTO basalt_meta.schema_version (version) VALUES ($1)`, latest)
	body, isError = h.call(t, "query", map[string]any{"sql": "SELECT id FROM leads"})
	require.False(t, isError, "%v", body)
	body, isError = h.call(t, "status", map[string]any{})
	require.False(t, isError)
	require.Equal(t, guard.GuardOK, body["guard"].(map[string]any)["state"])
}

func TestAGuardMissingOnlyANonBreakingMigrationIsServedWithTheWarning(t *testing.T) {
	t.Parallel()
	latest, build := nextBuild(false)
	h, _ := guardWithout(t, latest, build)
	requireServedWithTheWarning(t, h, latest)
}

// TestEveryNonBreakingMigrationIsServedWithoutIt is the test a non-breaking
// flag needs (CONTRACT.md, basalt_meta, AE-11): each migration this build
// flags non-breaking is left out of a real guard, and the agent is still
// served, with GUARD_UPGRADE_AVAILABLE.
func TestEveryNonBreakingMigrationIsServedWithoutIt(t *testing.T) {
	t.Parallel()
	for _, m := range guard.Migrations() {
		if m.Breaking {
			continue
		}
		h, _ := guardWithout(t, m.Version, guard.Migrations())
		requireServedWithTheWarning(t, h, m.Version)
	}
}

func requireServedWithTheWarning(t *testing.T, h harness, version int) {
	t.Helper()
	body, isError := h.call(t, "run_start", map[string]any{"intent": "check leads"})
	require.False(t, isError, "%v", body)
	warnings := body["warnings"].([]any)
	require.Len(t, warnings, 1)
	require.Equal(t, mcp.WarningGuardUpgradeAvailable, warnings[0].(map[string]any)["code"])
	runID := body["runId"]
	body, isError = h.call(t, "query", map[string]any{"sql": "SELECT id FROM leads", "runId": runID})
	require.False(t, isError, "%v", body)

	// A write through the guard is applied, and a write the guard holds is
	// held for the person's approval: the guard's write path works without
	// the missing migration.
	body, isError = h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET name = $1 WHERE id = $2", "params": []any{"Bo", 1}, "intent": "rename", "runId": runID,
	})
	require.False(t, isError, "%v", body)
	require.Equal(t, "APPLIED", body["status"])
	body, isError = h.call(t, "write", map[string]any{
		"sql": "DELETE FROM leads WHERE id = $1", "params": []any{1}, "intent": "drop the lead", "runId": runID,
	})
	requireToolError(t, body, isError, agent.CodeApprovalRequired, "", "")
	require.NotEmpty(t, body["approval"].(map[string]any)["approvalId"], "the delete is held with an approval")

	body, isError = h.call(t, "status", map[string]any{})
	require.False(t, isError)
	g := body["guard"].(map[string]any)
	require.Equal(t, guard.GuardUpgradeAvailable, g["state"])
	require.Equal(t, []any{jsonNumber(version)}, g["missingNonBreaking"])
	require.Equal(t, true, body["ready"], "a WARNING leaves the agent ready")
}

func TestStatusOnAFullGuard(t *testing.T) {
	t.Parallel()
	_, agentURL := testDB(t)
	svc := pgService(t, agentURL, withDeps(func(d *agent.Deps, pool *pgxpool.Pool) {
		d.Probe = agent.DBProbe{Q: pool, Migrations: guard.Migrations()}
	})).Svc
	r, err := svc.Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, guard.GuardOK, r.Guard.State)
	require.Equal(t, guard.LatestVersion(), *r.Guard.Installed)
	require.False(t, r.Passkeys.Registered)
	require.Equal(t, 0, *r.Passkeys.Active)
	require.Len(t, r.Problems, 1)
	require.Equal(t, "NO_PASSKEY", r.Problems[0].Code)
	require.True(t, r.Ready, "no passkey is a WARNING")
	require.Equal(t, "NONE", r.Setup.State)
}

// jsonNumber is n as the harness decodes numbers.
func jsonNumber(n int) json.Number { return json.Number(strconv.Itoa(n)) }
