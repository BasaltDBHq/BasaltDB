package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/links/linkstest"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
)

// What the engine records in basalt_meta, and what the page API answers,
// pinned as golden files next to the served surface: a change to how the
// engine reaches its database must leave both as they are.

// dumpLedger reads the change record and the hash-chained ledger as the
// admin, in the order they were written, without the hashes (they depend
// on ids and times), and normalises what differs from run to run.
func dumpLedger(t *testing.T, d *guardtest.DB) map[string]any {
	t.Helper()
	norm := newRunNormalizer()
	read := func(query string) []any {
		t.Helper()
		rows, err := d.Admin.Query(context.Background(), query)
		require.NoError(t, err)
		defer rows.Close()
		var out []any
		for rows.Next() {
			var raw []byte
			require.NoError(t, rows.Scan(&raw))
			var row map[string]any
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			require.NoError(t, dec.Decode(&row))
			out = append(out, norm.walk(row, ""))
		}
		require.NoError(t, rows.Err())
		return out
	}
	return map[string]any{
		"changes": read(`SELECT to_jsonb(c) - 'tx' - 'stmt_ts' - 'at' - 'duration_ms' - 'credential_id'
			FROM basalt_meta.changes c ORDER BY c.at, c.change_id`),
		"ledger": read(`SELECT to_jsonb(l) - 'at' - 'values_hash' - 'prev_hash' - 'hash' - 'table_oid'
			FROM basalt_meta.ledger l ORDER BY l.seq`),
	}
}

func TestLedgerRowsGolden(t *testing.T) {
	t.Parallel()
	_, e := servedMainScenario(t)
	requireGoldenFile(t, "ledger", "main_scenario", dumpLedger(t, e.d))
}

// pageCall is one request to the engine's local pages and what came back.
type pageCall struct {
	t    *testing.T
	p    localPages
	norm *runNormalizer
	n    int
}

func (c *pageCall) golden(name, method, path string, status int, body any) {
	c.t.Helper()
	c.n++
	requireGoldenFile(c.t, "pages", name, map[string]any{
		"request": method + " " + c.norm.text(path), "status": status, "body": c.norm.walk(body, ""),
	})
}

func (c *pageCall) get(name, path, secret string) {
	c.t.Helper()
	var body map[string]any
	status := c.p.get(path, secret, &body)
	c.golden(name, http.MethodGet, path, status, body)
}

func (c *pageCall) post(name, path, secret string, req any) {
	c.t.Helper()
	raw, err := json.Marshal(req)
	require.NoError(c.t, err)
	var body map[string]any
	status := c.p.post(path, pageOrigin, secret, raw, &body)
	c.golden(name, http.MethodPost, path, status, body)
}

func TestPageAPIBodiesGolden(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	e := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	c := &pageCall{t: t, p: newLocalPages(t, e), norm: newRunNormalizer()}

	// A held write: the request the approval page reads.
	body, isError := e.h.call(t, "write", holdWrite(t, e.h, nil))
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	approvalID := str(t, approvalOf(t, body)["approvalId"])
	approvalSecret := linkstest.SecretOf(str(t, approvalOf(t, body)["approvalUrl"]))
	c.get("approval_request", "/api/v1/approvals/"+approvalID, approvalSecret)
	c.get("approval_request_without_secret", "/api/v1/approvals/"+approvalID, "")

	// A revert of the agent's own run: the request the revert page reads.
	runID, _ := winLeads(t, e.h, "71, 72, 73")
	out, isError := e.h.call(t, "request_revert", map[string]any{"runId": runID, "intent": "Undo the lead merge"})
	require.False(t, isError, "%v", out)
	revertID := uuid.MustParse(str(t, out["revertId"]))
	secret := linkstest.SecretOf(str(t, out["revertUrl"]))
	c.get("revert_request", revertPath(revertID), secret)

	// Applying with a signature from a key the database does not know.
	var req revert.Request
	require.Equal(t, http.StatusOK, c.p.get(revertPath(revertID), secret, &req))
	forger, err := passkeytest.New(e.person.Credential().Relying)
	require.NoError(t, err)
	forger.ID = e.person.ID
	as, err := forger.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	c.post("revert_apply_bad_assertion", revertPath(revertID)+"/apply", secret, reverttest.NewResponse(revertID, as))

	// A widen with no proof from the person.
	task := uuid.Must(uuid.NewV7())
	c.post("revert_rescope_without_proof", scopePath(revertID), secret, agent.ScopeRequest{
		Select: revert.Select{Scope: revert.ScopeTask, ScopeID: task, Agents: []string{e.a.Role}},
	})

	// The person rejects it on the page.
	note := "Not now"
	c.post("revert_reject", rejectPath(revertID), secret, agent.RejectRequest{Note: &note})
	c.get("revert_request_after_reject", revertPath(revertID), secret)

	requireGoldenFile(t, "pages", "ledger_after_pages", dumpLedger(t, d))
}
