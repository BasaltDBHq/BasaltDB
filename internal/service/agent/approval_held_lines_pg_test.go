package agent_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
)

// The contract's own example (Large values): a held DELETE of a row with a
// 2 MB value is held, its line carries the value whole (the page and the
// CLI show it by size and sha256), and once the person signs it is applied.
func TestAHeldDeleteOfALargeValueIsApproved(t *testing.T) {
	t.Parallel()
	e := largeRequestEnv(t)
	ctx := context.Background()
	run, isError := e.h.call(t, "run_start", map[string]any{"intent": "Drop the large doc"})
	require.False(t, isError, "%v", run)
	args := map[string]any{
		"sql": "DELETE FROM public.docs WHERE id = $1", "params": []any{1},
		"intent": "Doc 1 is obsolete", "runId": str(t, run["runId"]),
	}
	body, isError := e.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "REQUEST_TOO_LARGE", "")
	id := uuid.MustParse(str(t, approvalOf(t, body)["approvalId"]))

	// What the person's CLI and the pages API read: not budgeted, whole.
	held, err := ledger.FindApproval(ctx, e.a.Conn, id)
	require.NoError(t, err)
	require.Len(t, held.Lines, 1)
	var line struct {
		Old map[string]json.RawMessage `json:"old"`
	}
	require.NoError(t, json.Unmarshal([]byte(held.Lines[0]), &line))
	sum := sha256.Sum256([]byte(strings.Repeat("x", bigValue)))
	require.Equal(t, "(1.9 MiB, sha256 "+hex.EncodeToString(sum[:])+")", largevalue.Summary(line.Old["body"], "body"),
		"the line carries the value whole, so it is shown by its size and hash")

	as, err := e.person.Sign(approval.Challenge(held.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.SubmitApproval(ctx, e.a.Conn, id, as)
	require.NoError(t, err)

	args["approvalId"] = id.String()
	body, isError = e.h.call(t, "write", args)
	require.False(t, isError, "%v", body)
	require.Equal(t, "APPLIED", body["status"])
	var left int
	require.NoError(t, e.d.Admin.QueryRow(ctx, `SELECT count(id)::int FROM public.docs WHERE id = 1`).Scan(&left))
	require.Zero(t, left)
}

// A held write's lines over the cap are refused as STATEMENT_REFUSED
// HOLD_TOO_LARGE, with the person told why: never INTERNAL. Not parallel:
// it moves a 64 MiB row under the engine's statement timeout.
func TestAHeldWriteOverTheLineCapIsRefused(t *testing.T) {
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.docs (id int PRIMARY KEY, body text);
		INSERT INTO public.docs VALUES (1, repeat('x', 67108864)), (2, 'two')`)
	tables := []string{"public.docs"}
	e := agentHarnessFor(t, d, d.NewAgent(t, "bot", tables, tables))
	body, isError := e.h.call(t, "write", map[string]any{"sql": "DELETE FROM public.docs WHERE id = 1", "intent": "Drop the huge doc"})
	requireToolError(t, body, isError, "STATEMENT_REFUSED", "HOLD_TOO_LARGE", "")
	require.Equal(t, []string{"STOP", "ASK_PERSON"}, actions(t, body))
	require.Contains(t, body["personMessage"], "too large to hold for your approval")
}

// A wait on a held write reads each poll on its own budget: an approval of
// about 750 KB of lines, polled for 3 seconds, ends WAIT_ENDED, not
// SIZE_LIMIT (one budget would run out after about 20 polls).
func TestAnApprovalWaitReadsEachPollOnItsOwnBudget(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.notes (id int PRIMARY KEY, body text);
		INSERT INTO public.notes SELECT g, repeat('x', 15000) FROM generate_series(1, 60) g`)
	tables := []string{"public.notes"}
	e := agentHarnessFor(t, d, d.NewAgent(t, "bot", tables, tables), "http://localhost:7878")
	run, isError := e.h.call(t, "run_start", map[string]any{"intent": "Clear old notes"})
	require.False(t, isError, "%v", run)
	args := map[string]any{"sql": "DELETE FROM public.notes WHERE id <= 50", "intent": "Notes 1 to 50 are stale", "runId": str(t, run["runId"])}
	body, isError := e.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "HELD", "")
	args["approvalId"] = str(t, approvalOf(t, body)["approvalId"])
	args["waitForApproval"] = 3
	body, isError = e.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "WAIT_ENDED", "")
}
