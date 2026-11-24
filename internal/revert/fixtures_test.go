package revert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

const (
	caseRunID    = "0193a4c2-7d1e-7c3a-9f00-0000000000a1"
	caseRevertID = "0193a4c2-7d1e-7c3a-9f00-0000000000b2"
	caseChangeID = "0193a4c2-7d1e-7c3a-9f00-0000000000c3"
	caseApproval = "0193a4c2-7d1e-7c3a-9f00-0000000000d4"
)

const caseShortLink = "http://localhost:7878/approvals/" + caseApproval + "#s=AAAAAAAAAAAAAAAAAAAAAA"

// catalogReverts and catalogApprovals are the stores the cases need: the
// failure is raised by the test, so only the lookups the engine makes while
// building steps answer.
type catalogReverts struct {
	Store
	lines []string
	by    uuid.UUID
}

func (r catalogReverts) PreviewRevert(context.Context, action.Scope, string, int) (action.PreviewPage, error) {
	out := action.PreviewPage{Lines: len(r.lines), AllAlreadyReverted: true, CursorFound: true}
	for _, text := range r.lines {
		l, err := revert.ParseLine(text)
		if err != nil {
			return action.PreviewPage{}, err
		}
		if l.Action == revert.ActionRestore {
			out.Restore++
		}
		out.AllAlreadyReverted = out.AllAlreadyReverted && l.Conflict != nil && *l.Conflict == revert.ConflictAlreadyReverted
	}
	return out, nil
}

func (r catalogReverts) RevertedBy(context.Context, action.Scope) (uuid.UUID, error) {
	return r.by, nil
}

func caseRevert(signed bool) action.Revert {
	r := action.Revert{
		ID: uuid.MustParse(caseRevertID), Status: "PENDING", Scope: "RUN", ScopeID: uuid.MustParse(caseRunID),
		ExpiresAt: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC),
	}
	if signed {
		at := r.ExpiresAt
		r.SignedAt = &at
	}
	return r
}

const alreadyRevertedLine = `{"op": "UPDATE", "key": {"id": 3}, "now": {"id": 3}, "set": {"id": 3}, "table": "public.leads", ` +
	`"action": "SKIP", "cascaded": false, "conflict": "ALREADY_REVERTED", "sqlState": null, "changeIds": ["` + caseChangeID + `"]}`

const changedAfterLine = `{"op": "UPDATE", "key": {"id": 3}, "now": {"id": 3}, "set": {"id": 3}, "table": "public.leads", ` +
	`"action": "SKIP", "cascaded": false, "conflict": "CHANGED_AFTER", "sqlState": null, "changeIds": ["` + caseChangeID + `"]}`

const localPages = "http://localhost:8787"

func revertOf(t *testing.T, intent string, lines []string, batched bool) action.Revert {
	t.Helper()
	rows := len(lines)
	binding := fmt.Sprintf(`{"kind": "REVERT", "rows": %d, "intent": %q, "select": {"runs": null, "scope": "RUN", "agents": ["basalt_agent_bot"], "tables": null, "scopeId": %q}, "skipped": 0, "widened": false, `+
		`"database": "app", "revertId": %q, "rowsHash": "14caa48f26bad4a8e9febd038704ee65a3922fad6a0a1b5f30d16a49cb27db80", `+
		`"expiresAt": "2026-11-11T07:02:11.123456Z", "requestedBy": "basalt_agent_bot"}`, rows, intent, caseRunID, caseRevertID)
	if batched {
		binding = strings.Replace(binding, `"skipped": 0`, `"skipped": 0, "batched": true, "sampleHash": "14caa48f26bad4a8e9febd038704ee65a3922fad6a0a1b5f30d16a49cb27db80"`, 1)
		binding = strings.Replace(binding, fmt.Sprintf(`"rows": %d`, rows), `"rows": 1200`, 1)
	}
	r := caseRevert(false)
	r.Rows, r.BindingText, r.Lines, r.Batched = rows, binding, lines, batched
	return r
}

func revertLines(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		sum := sha256.Sum256(fmt.Appendf(nil, "restore %d", i))
		sum2 := sha256.Sum256(sum[:])
		out = append(out, fmt.Sprintf(`{"op": "INSERT", "key": {"id": %d}, "now": null, "set": {"id": %d, "note": "%s%s"}, "table": "public.leads", `+
			`"action": "RESTORE", "cascaded": false, "conflict": null, "sqlState": null, "changeIds": ["%s"]}`,
			i, i, hex.EncodeToString(sum[:]), hex.EncodeToString(sum2[:]), caseChangeID))
	}
	return out
}

func caseBindingText(t *testing.T, batched bool) string {
	t.Helper()
	rows, skipped := 3, 1
	if batched {
		rows, skipped = 1209, 1
	}
	raw, err := json.Marshal(revert.Binding{
		Kind: revert.KindRevert, RevertID: uuid.MustParse(caseRevertID), Database: "app",
		Select: revert.Select{Scope: revert.ScopeRun, ScopeID: uuid.MustParse(caseRunID), Agents: []string{"bot"}}, Intent: strings.Repeat("The agent set the wrong status. ", 30),
		Rows: rows, Skipped: skipped, RowsHash: strings.Repeat("a", 64), ExpiresAt: caseRevert(false).ExpiresAt, RequestedBy: "bot",
		Batched: batched, SampleHash: map[bool]string{true: strings.Repeat("b", 64)}[batched],
	})
	require.NoError(t, err)
	return string(raw)
}

func caseRevertWith(t *testing.T, status string) action.Revert {
	t.Helper()
	r := caseRevert(false)
	r.Status, r.Rows, r.Skipped, r.BindingText = status, 3, 1, caseBindingText(t, false)
	return r
}

func testManager() guidance.ServiceManager {
	return guidance.ServiceManager{StartCommand: osservice.StartCommand, RestartArgs: osservice.RestartArgs}
}
