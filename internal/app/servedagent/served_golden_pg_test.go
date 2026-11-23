package servedagent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// The served surface is pinned byte for byte: the tools an MCP client lists,
// and what each tool answers on a real database, success or error. A change
// that moves the store behind another interface must leave every file in
// testdata/served as it is.

// unreachableCodes are the error codes in api/mcp/tools/*.json that a test
// database cannot produce through the service, with the reason.
var unreachableCodes = map[string]string{
	"apply_revert_batch REVERT_EXPIRED": "needs a signed plan past its deadline; the clock is the database's",
	"apply_revert_batch UNAVAILABLE":    "needs the database to be down",
	"apply_revert_batch INTERNAL":       "needs a failure the engine does not expect",
	"confirm_database INVALID_ARGUMENT": "a served agent has no database waiting; pinned by TestConfirmDatabaseOnAServedAgent",
	"confirm_database UNAVAILABLE":      "answered by a connect-only agent, which serves no database; see TestConnectOnlyConfirmDatabase",
	"confirm_database INTERNAL":         "needs a failure the engine does not expect",
	"describe INVALID_ARGUMENT":         "pinned by testdata/describe",
	"describe NOT_FOUND":                "pinned by testdata/describe",
	"describe QUERY_TIMEOUT":            "needs a catalog too large to read in time; see TestDescribeSearchScale",
	"describe UNAVAILABLE":              "needs the database to be down",
	"describe INTERNAL":                 "needs a failure the engine does not expect",
	"list_pending UNAVAILABLE":          "needs the database to be down",
	"list_pending INTERNAL":             "needs a failure the engine does not expect",
	"list_pending QUERY_TIMEOUT":        "needs a statement timeout inside a ledger read",
	"list_runs UNAVAILABLE":             "needs the database to be down",
	"list_runs INTERNAL":                "needs a failure the engine does not expect",
	"preview_revert QUERY_TIMEOUT":      "needs a statement timeout inside a ledger read",
	"preview_revert UNAVAILABLE":        "needs the database to be down",
	"preview_revert INTERNAL":           "needs a failure the engine does not expect",
	"query UNAVAILABLE":                 "needs the database to be down",
	"query INTERNAL":                    "needs a failure the engine does not expect",
	"request_revert REVERT_EXPIRED":     "needs a prepared revert past its deadline; the clock is the database's",
	"request_revert REVERT_INVALID":     "the agent signs nothing; needs a reissue of a widened revert that races the person's signature or reject on the page (reset_revert)",
	"request_revert QUERY_TIMEOUT":      "needs a statement timeout inside a ledger read",
	"request_revert UNAVAILABLE":        "needs the database to be down",
	"request_revert INTERNAL":           "needs a failure the engine does not expect",
	"revert_plan QUERY_TIMEOUT":         "needs a statement timeout inside a ledger read",
	"revert_plan UNAVAILABLE":           "needs the database to be down",
	"revert_plan INTERNAL":              "needs a failure the engine does not expect",
	"run_history QUERY_TIMEOUT":         "needs a statement timeout inside a ledger read",
	"run_history UNAVAILABLE":           "needs the database to be down",
	"run_history INTERNAL":              "needs a failure the engine does not expect",
	"run_start UNAVAILABLE":             "needs the database to be down",
	"run_start INTERNAL":                "needs a failure the engine does not expect",
	"status INVALID_ARGUMENT":           "status takes no arguments",
	"status INTERNAL":                   "needs a failure the engine does not expect",
	"write APPROVAL_EXPIRED":            "needs a held write past its deadline; the clock is the database's",
	"write QUERY_TIMEOUT":               "needs a write that runs past the statement timeout",
	"write UNAVAILABLE":                 "needs the database to be down",
	"write INTERNAL":                    "needs a failure the engine does not expect",
	"request_plugin NOT_FOUND":          "the harness keeps no engine-kept plugins; tools_plugin_test.go and the engine's plugin_requests tests cover request_plugin",
	"request_plugin UNAVAILABLE":        "needs the database to be down",
	"request_plugin INTERNAL":           "needs a failure the engine does not expect",
}

// declaredErrors reads every served tool's error codes from the contract's
// tool files, as "tool CODE". PLANNED tools are left out.
func declaredErrors(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "api", "mcp", "tools", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	out := make([]string, 0, len(files))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		var tool struct {
			Name   string   `json:"name"`
			Status string   `json:"status"`
			Errors []string `json:"errors"`
		}
		require.NoError(t, json.Unmarshal(raw, &tool), f)
		if tool.Status == "PLANNED" {
			continue // not served yet, so no scenario can reach it
		}
		for _, code := range tool.Errors {
			out = append(out, tool.Name+" "+code)
		}
	}
	sort.Strings(out)
	return out
}

// requireEveryToolAndErrorPinned checks the scenarios reached every served
// tool with a success and every declared error code, or say why not.
func requireEveryToolAndErrorPinned(t *testing.T, gs ...*servedGolden) {
	t.Helper()
	codes, tools := map[string]bool{}, map[string]bool{}
	for _, g := range gs {
		for k := range g.codes {
			codes[k] = true
		}
		for k := range g.tools {
			tools[k] = true
		}
	}
	for _, e := range declaredErrors(t) {
		_, skipped := unreachableCodes[e]
		require.True(t, codes[e] != skipped, "%s: pinned by a golden, or listed in unreachableCodes with a reason, not both and not neither", e)
	}
	for _, tool := range []string{
		"run_start", "run_history", "list_runs", "list_pending", "query", "write",
		"preview_revert", "request_revert", "revert_plan", "apply_revert_batch", "status",
	} {
		require.True(t, tools[tool], "%s has no success golden", tool)
	}
}

func (h harness) toolsList(t *testing.T) map[string]any {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, h.server.Serve(context.Background(),
		bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")), &out))
	var resp struct {
		Result map[string]any `json:"result"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &resp), out.String())
	return resp.Result
}

func TestServedToolsListGolden(t *testing.T) {
	t.Parallel()
	_, agentURL := testDB(t)
	h := newHarness(t, agentURL, sqlguard.DefaultLimits())
	requireGoldenFile(t, "served", "tools_list", h.toolsList(t))
}

func TestServedScenarioGolden(t *testing.T) {
	t.Parallel()
	large := servedLargePlan(t)
	main, _ := servedMainScenario(t)
	requireEveryToolAndErrorPinned(t, main, large)
}

// servedMainScenario drives one agent through reads, writes, a held write,
// refusals, history and a revert, and pins every answer.
func servedMainScenario(t *testing.T) (*servedGolden, agentEnv) {
	t.Helper()
	e := agentHarness(t)
	g := newServedGolden(t, "served/main", e.h)
	ctx := context.Background()

	run := g.callOK("run_start", "run_start", map[string]any{"intent": "Tidy the lead list"})
	runID := str(t, run["runId"])

	g.callOK("query_rows", "query", map[string]any{
		"sql": "SELECT id, status FROM leads WHERE id <= 3 ORDER BY id", "runId": runID,
	})
	g.callErr("query_ddl_refused", "query", map[string]any{"sql": "DROP TABLE leads", "runId": runID}, "STATEMENT_REFUSED")
	g.callErr("query_row_limit", "query", map[string]any{
		"sql": "SELECT g FROM generate_series(1, 1001) g", "runId": runID,
	}, "QUERY_TIMEOUT")
	g.callErr("query_bad_column", "query", map[string]any{"sql": "SELECT nope FROM leads", "runId": runID}, "SQL_ERROR")
	g.callErr("query_not_granted", "query", map[string]any{"sql": "SELECT amount FROM payroll", "runId": runID}, "PERMISSION_DENIED")
	g.callErr("query_no_sql", "query", map[string]any{"runId": runID}, "INVALID_ARGUMENT")

	g.callOK("write_one_row", "write", map[string]any{
		"sql": "UPDATE leads SET status = $1 WHERE id = $2", "params": []any{"merged", 4},
		"intent": "Lead 4 duplicates lead 3", "runId": runID,
	})
	held := map[string]any{
		"sql": "UPDATE leads SET status = $1 WHERE id BETWEEN $2 AND $3", "params": []any{"closed", 21, 31},
		"intent": "Leads 21 to 31 went cold", "runId": runID,
	}
	heldBody := g.callErr("write_held", "write", held, "APPROVAL_REQUIRED")
	approvalID := str(t, approvalOf(t, heldBody)["approvalId"])
	g.callErr("write_over_fifty_rows", "write", map[string]any{
		"sql": "UPDATE leads SET score = 1 WHERE id <= 60", "intent": "Reset every score", "runId": runID,
	}, "ROW_LIMIT_EXCEEDED")
	g.callErr("write_no_intent", "write", map[string]any{
		"sql": "UPDATE leads SET status = 'x' WHERE id = 5", "runId": runID,
	}, "INTENT_REQUIRED")
	g.callErr("write_ddl_refused", "write", map[string]any{
		"sql": "DROP TABLE leads", "intent": "Tidy up", "runId": runID,
	}, "STATEMENT_REFUSED")
	g.callErr("write_not_granted", "write", map[string]any{
		"sql": "UPDATE payroll SET amount = 0", "intent": "Pay nobody", "runId": runID,
	}, "PERMISSION_DENIED")
	g.callErr("write_bad_column", "write", map[string]any{
		"sql": "UPDATE leads SET nope = 1 WHERE id = 5", "intent": "Set a column that is not there", "runId": runID,
	}, "SQL_ERROR")
	g.callErr("write_no_sql", "write", map[string]any{"intent": "Nothing", "runId": runID}, "INVALID_ARGUMENT")

	// A stale write: the agent read row 42, a person changed it, the agent writes.
	g.callOK("query_row_to_be_stale", "query", map[string]any{
		"sql": "SELECT id, status FROM leads WHERE id = $1", "params": []any{42}, "runId": runID,
	})
	e.d.Exec(t, `UPDATE public.leads SET status = 'won' WHERE id = 42`)
	g.callErr("write_stale_read", "write", map[string]any{
		"sql": "UPDATE leads SET status = $1 WHERE id = $2", "params": []any{"lost", 42},
		"intent": "No answer", "runId": runID,
	}, "STALE_READ")

	// The held write, not yet signed, then with an approval that does not exist.
	unsigned := map[string]any{"approvalId": approvalID, "waitForApproval": 0}
	for k, v := range held {
		unsigned[k] = v
	}
	g.callErr("write_approval_not_signed", "write", unsigned, "APPROVAL_INVALID")
	unknown := map[string]any{"approvalId": uuid.Must(uuid.NewV7()).String(), "waitForApproval": 0}
	for k, v := range held {
		unknown[k] = v
	}
	g.callErr("write_approval_unknown", "write", unknown, "APPROVAL_INVALID")
	g.callErr("write_unknown_run", "write", map[string]any{
		"sql": "UPDATE leads SET status = 'x' WHERE id = 5", "intent": "Nowhere", "runId": uuid.Must(uuid.NewV7()).String(),
	}, "NOT_FOUND")

	g.callOK("list_pending", "list_pending", map[string]any{"runId": runID})
	g.callErr("list_pending_unknown_run", "list_pending", map[string]any{"runId": uuid.Must(uuid.NewV7()).String()}, "NOT_FOUND")
	g.callOK("run_history", "run_history", map[string]any{"runId": runID})
	g.callErr("run_history_unknown_run", "run_history", map[string]any{"runId": uuid.Must(uuid.NewV7()).String()}, "NOT_FOUND")
	g.callOK("list_runs", "list_runs", map[string]any{})
	g.callOK("status", "status", map[string]any{})

	// The person approves the held write on the page; the agent applies it.
	require.NoError(t, relayApproval(e.svc, signLink(t, str(t, approvalOf(t, heldBody)["approvalUrl"]), e.person)))
	applied := map[string]any{"approvalId": approvalID}
	for k, v := range held {
		applied[k] = v
	}
	g.callOK("write_held_applied", "write", applied)

	g.callOK("preview_revert_run", "preview_revert", map[string]any{"runId": runID})

	// Another agent's run reads as not found, exactly like an unknown one.
	other := e.d.NewAgent(t, "other", leads, leads)
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: uuid.Must(uuid.NewV7()), Text: "Other's work"}
	require.NoError(t, guard.StartRun(ctx, other.Conn, in))
	require.NoError(t, guardtest.Guarded(ctx, other.Conn, in, `UPDATE public.leads SET status = 'won' WHERE id = 76`))
	g.callErr("preview_revert_other_agents_run", "preview_revert", map[string]any{"runId": in.RunID.String()}, "NOT_FOUND")
	g.callErr("request_revert_other_agents_run", "request_revert", map[string]any{"runId": in.RunID.String(), "intent": "Undo"}, "NOT_FOUND")

	// A run that only read has nothing to revert.
	readOnly := g.callOK("run_start_read_only", "run_start", map[string]any{"intent": "Only look"})
	g.callOK("query_in_read_only_run", "query", map[string]any{"sql": "SELECT id FROM leads WHERE id = 1", "runId": str(t, readOnly["runId"])})
	g.callErr("preview_revert_nothing", "preview_revert", map[string]any{"runId": str(t, readOnly["runId"])}, "NOTHING_TO_REVERT")
	g.callErr("request_revert_nothing", "request_revert", map[string]any{"runId": str(t, readOnly["runId"]), "intent": "Undo"}, "NOTHING_TO_REVERT")

	requested := g.callOK("request_revert", "request_revert", map[string]any{"runId": runID, "intent": "Undo the tidy-up"})
	_ = requested
	g.callErr("request_revert_no_argument", "request_revert", map[string]any{"intent": "Undo"}, "INVALID_ARGUMENT")
	g.callErr("request_revert_unknown_revert", "request_revert", map[string]any{"revertId": uuid.Must(uuid.NewV7()).String()}, "NOT_FOUND")
	g.callOK("request_revert_still_pending", "request_revert", map[string]any{
		"revertId": str(t, requested["revertId"]), "waitForSignature": 0,
	})
	// The agent never carries the person's signature: the page relays it.
	g.callErr("request_revert_signature_refused", "request_revert", map[string]any{
		"revertId": str(t, requested["revertId"]), "signature": "basalt-revert.1.abc",
	}, "INVALID_ARGUMENT")
	g.callErr("revert_plan_unknown", "revert_plan", map[string]any{"revertId": uuid.Must(uuid.NewV7()).String()}, "NOT_FOUND")
	g.callErr("list_runs_bad_time", "list_runs", map[string]any{"startTime": "not a time"}, "INVALID_ARGUMENT")
	g.callErr("run_start_no_intent", "run_start", map[string]any{}, "INVALID_ARGUMENT")
	g.callErr("preview_revert_no_argument", "preview_revert", map[string]any{}, "INVALID_ARGUMENT")
	g.callErr("run_history_no_run", "run_history", map[string]any{}, "INVALID_ARGUMENT")
	g.callErr("list_pending_bad_kind", "list_pending", map[string]any{"kind": "NOPE"}, "INVALID_ARGUMENT")
	g.callErr("revert_plan_no_revert", "revert_plan", map[string]any{}, "INVALID_ARGUMENT")
	g.callErr("apply_revert_batch_no_lines", "apply_revert_batch", map[string]any{"revertId": uuid.Must(uuid.NewV7()).String()}, "INVALID_ARGUMENT")
	g.callErr("apply_revert_batch_not_signed", "apply_revert_batch", map[string]any{
		"revertId": str(t, requested["revertId"]), "lines": []any{1},
	}, "REVERT_INVALID")
	// request_plugin on this harness, which keeps no engine-kept plugins: a
	// call with no form is refused for its arguments, and a removal for the
	// engine it runs on.
	g.callErr("request_plugin_no_form", "request_plugin", map[string]any{}, "INVALID_ARGUMENT")
	g.callErr("request_plugin_not_served", "request_plugin", map[string]any{"name": "local-ner", "remove": true}, "PLUGIN_REFUSED")
	return g, e
}

// servedLargePlan pins a large revert: its plan before and after the person
// signs, and a batch applied.
func servedLargePlan(t *testing.T) *servedGolden {
	t.Helper()
	e := newBatchEnv(t)
	g := newServedGolden(t, "served/large", e.h)
	id := e.prep.RevertID.String()
	g.callOK("revert_plan_unsigned", "revert_plan", map[string]any{"revertId": id, "limit": 3})
	g.callErr("apply_revert_batch_unsigned", "apply_revert_batch", map[string]any{"revertId": id, "lines": []any{1, 2, 3}}, "REVERT_INVALID")
	e.sign(t)
	g.callOK("revert_plan_signed_pending", "revert_plan", map[string]any{"revertId": id, "pending": true, "limit": 3})
	g.callOK("apply_revert_batch", "apply_revert_batch", map[string]any{"revertId": id, "lines": []any{1, 2, 3}})
	g.callOK("revert_plan_after_batch", "revert_plan", map[string]any{"revertId": id, "limit": 5})
	return g
}
