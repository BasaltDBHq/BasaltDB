package agent_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
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

	pool, err := agentdb.NewPool(context.Background(), a.URL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	limits := sqlguard.DefaultLimits()
	store := agentdb.NewStore(pool, limits, time.Now)
	svc := agent.NewService(agent.Deps{
		Name: "bot", Reader: agentdb.NewReader(pool, limits, time.Now), Store: store, Reads: store, Approvals: store, Reverts: store,
		Log: slog.New(slog.DiscardHandler), Now: time.Now,
		Probe: agent.DBProbe{Q: pool, Migrations: migs},
	})
	return harness{server: mcp.NewServer(mcp.Info{Name: "basalt"}, agent.Tools(svc)...)}, d
}

// withNonBreaking is migs with version flagged non-breaking.
func withNonBreaking(migs []guard.Migration, version int) []guard.Migration {
	out := append([]guard.Migration(nil), migs...)
	for i := range out {
		if out[i].Version == version {
			out[i].Breaking = false
		}
	}
	return out
}

func TestAGuardMissingABreakingMigrationServesOnlyStatus(t *testing.T) {
	t.Parallel()
	latest := guard.LatestVersion()
	h, d := guardWithout(t, latest, guard.Migrations())

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
	latest := guard.LatestVersion()
	h, _ := guardWithout(t, latest, withNonBreaking(guard.Migrations(), latest))
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
	body, isError = h.call(t, "query", map[string]any{"sql": "SELECT id FROM leads", "runId": body["runId"]})
	require.False(t, isError, "%v", body)

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
	pool, err := agentdb.NewPool(context.Background(), agentURL, 2)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	limits := sqlguard.DefaultLimits()
	store := agentdb.NewStore(pool, limits, time.Now)
	svc := agent.NewService(agent.Deps{
		Name: "bot", Reader: agentdb.NewReader(pool, limits, time.Now), Store: store, Reads: store, Approvals: store, Reverts: store,
		Log: slog.New(slog.DiscardHandler), Now: time.Now, Probe: agent.DBProbe{Q: pool, Migrations: guard.Migrations()},
	})
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
