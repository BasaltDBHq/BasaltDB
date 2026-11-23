package revert_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec/linkcodectest"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
)

var update = flag.Bool("update", false, "rewrite testdata/fixtures.json")

const fixturesFile = "testdata/fixtures.json"

var (
	revertID = uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000d4")
	runID    = uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000b2")
	change1  = "0193a4c2-7d1e-7c3a-9f00-0000000000e1"
	change2  = "0193a4c2-7d1e-7c3a-9f00-0000000000e2"
)

// revertLines are four lines as Postgres's jsonb text prints them, in
// COLLATE "C" order: a redacted cascaded row to delete, a cascaded note to
// re-insert, a lead to restore, and a lead a person edited after the agent
// (skipped). Non-ASCII text checks every client hashes UTF-8 bytes.
func revertLines() []string {
	return []string{
		`{"op": "DELETE", "table": "public.note_tags", "action": "RESTORE", "rowHash": "` + strings.Repeat("ab", sha256.Size) + `", "cascaded": true, "conflict": null, "redacted": true, "changeIds": ["` + change1 + `"]}`,
		`{"op": "INSERT", "key": {"id": 5}, "now": null, "set": {"id": 5, "note": "note 5 — 日本 🚀", "lead_id": 3}, "table": "public.lead_notes", "action": "RESTORE", "cascaded": true, "conflict": null, "sqlState": null, "changeIds": ["` + change1 + `"]}`,
		`{"op": "UPDATE", "key": {"id": 3}, "now": {"id": 3, "name": "Café ✓ lead", "status": "merged"}, "set": {"id": 3, "name": "Café ✓ lead", "status": "open"}, "table": "public.leads", "action": "RESTORE", "cascaded": false, "conflict": null, "sqlState": null, "changeIds": ["` + change1 + `", "` + change2 + `"]}`,
		`{"op": "UPDATE", "key": {"id": 7}, "now": {"id": 7, "name": "Edited by a person", "status": "won"}, "set": {"id": 7, "name": "Lead 7", "status": "open"}, "table": "public.leads", "action": "SKIP", "cascaded": false, "conflict": "CHANGED_AFTER", "sqlState": null, "changeIds": ["` + change2 + `"]}`,
	}
}

func bindingText(lines []string) string {
	return fmt.Sprintf(`{"kind": "REVERT", "rows": 3, "intent": "Undo the bad merge", "select": {"runs": null, "scope": "RUN", "agents": ["basalt_agent_bot"], "tables": null, "scopeId": %q}, "skipped": 1, "widened": false, "database": "app", "revertId": %q, "rowsHash": %q, "expiresAt": "2026-11-11T07:02:11.123456Z", "requestedBy": "basalt_agent_bot"}`,
		runID.String(), revertID.String(), approval.RowsHash(lines))
}

// Size of the batched fixture plan: more lines than one call takes.
const (
	planSkips    = 10
	planRestores = 1490
)

// planLines is a large plan in signed (byte) order: planSkips rows a
// person edited and planRestores rows to restore.
func planLines() []string {
	lines := make([]string, 0, planSkips+planRestores)
	for i := range planSkips + planRestores {
		action, conflict := `"RESTORE"`, `null`
		if i < planSkips {
			action, conflict = `"SKIP"`, `"CHANGED_AFTER"`
		}
		lines = append(lines, fmt.Sprintf(`{"op": "UPDATE", "key": {"id": %d}, "now": {"id": %d, "v": "agent"}, "set": {"id": %d, "v": "before"}, "table": "public.items", "action": %s, "cascaded": false, "conflict": %s, "sqlState": null, "changeIds": [%q]}`,
			i+1, i+1, i+1, action, conflict, change1))
	}
	sort.Strings(lines)
	return lines
}

func batchedBinding(all, sample []string) string {
	return fmt.Sprintf(`{"kind": "REVERT", "rows": %d, "intent": "Undo the bulk load", "select": {"runs": null, "scope": "RUN", "agents": ["basalt_agent_bot"], "tables": null, "scopeId": %q}, "batched": true, "skipped": %d, "widened": false, "database": "app", "revertId": %q, "rowsHash": %q, "expiresAt": "2026-11-11T07:02:11.123456Z", "sampleHash": %q, "requestedBy": "basalt_agent_bot"}`,
		planRestores, runID.String(), planSkips, revertID.String(), approval.RowsHash(all), approval.RowsHash(sample))
}

func planSample(t *testing.T) ([]string, []string) {
	t.Helper()
	all := planLines()
	sample, err := reverttest.Sample(all)
	require.NoError(t, err)
	return all, sample
}

func seq(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// fixtures is shared with the revert page's JavaScript tests
// (web/lib/revert.test.mjs), so Go and the page agree byte for byte.
type fixtures struct {
	Request struct {
		RevertID      string   `json:"revertId"`
		Binding       string   `json:"binding"`
		Lines         []string `json:"lines"`
		CredentialIDs []string `json:"credentialIds"`
		Fragment      string   `json:"fragment"`
		RowsHash      string   `json:"rowsHash"`
		Challenge     string   `json:"challenge"`
	} `json:"request"`
	Response struct {
		RevertID          string `json:"revertId"`
		CredentialID      string `json:"credentialId"`
		AuthenticatorData string `json:"authenticatorData"`
		ClientDataJSON    string `json:"clientDataJson"`
		Signature         string `json:"signature"`
		// JSON is the body the page posts to the engine.
		JSON string `json:"json"`
	} `json:"response"`
	// Batched is a large plan's link: the binding and the sample.
	Batched struct {
		RevertID   string `json:"revertId"`
		Binding    string `json:"binding"`
		Fragment   string `json:"fragment"`
		SampleHash string `json:"sampleHash"`
		Lines      int    `json:"lines"`
		Skipped    int    `json:"skipped"`
	} `json:"batched"`
	// BatchedSkips is a large plan with more SKIP lines than a sample holds:
	// its sample still carries every RESTORE line (decision RSS-1).
	BatchedSkips struct {
		Fragment  string `json:"fragment"`
		Fragment2 string `json:"fragment2"` // the same request in format 2
		Rows      int    `json:"rows"`
		Skipped   int    `json:"skipped"`
	} `json:"batchedSkips"`
	// Rescope are widen proofs' challenges (CONTRACT.md, Rescope, widen
	// and reject): the page builds the normalized select text, derives the
	// rescope key from the new link secret and hashes the challenge the
	// passkey signs, byte for byte as the guard checks it.
	Rescope []rescopeFixture `json:"rescope"`
}

// rescopeFixture is one widen challenge. Select is the descriptor as a
// page may send it; SelectText is Postgres's normalized text of it
// (basalt_meta._revert_select_norm, checked in internal/adapter/outbound/postgres/guard), which the
// proof signs.
type rescopeFixture struct {
	Name       string          `json:"name"`
	RevertID   string          `json:"revertId"`
	Nonce      string          `json:"nonce"`
	NewSecret  string          `json:"newSecret"`
	Select     json.RawMessage `json:"select"`
	SelectText string          `json:"selectText"`
	RescopeKey string          `json:"rescopeKey"`
	Challenge  string          `json:"challenge"`
}

// rescopeCases are the widen fixtures' inputs: every agent of a task, the
// page's widen; and a descriptor whose lists need sorting, deduplicating
// and lowercasing, so the page's normalization is checked against the
// guard's.
var rescopeCases = []struct{ name, sel, text string }{
	{
		name: "every agent of a task",
		sel:  `{"scope": "TASK", "scopeId": "0193a4c2-7d1e-7c3a-9f00-0000000000c1", "agents": null, "runs": null, "tables": null}`,
		text: `{"runs": null, "scope": "TASK", "agents": null, "tables": null, "scopeId": "0193a4c2-7d1e-7c3a-9f00-0000000000c1"}`,
	},
	{
		name: "lists sorted, deduplicated, ids lowercase",
		sel: `{"scope": "TASK", "scopeId": "0193A4C2-7D1E-7C3A-9F00-0000000000C1", "agents": ["basalt_agent_sync", "basalt_agent_bot", "basalt_agent_sync"], ` +
			`"runs": ["0193a4c2-7d1e-7c3a-9f00-0000000000b3", "0193A4C2-7D1E-7C3A-9F00-0000000000B2"], "tables": ["public.notes", "public.Leads", "public.leads", "public.notes"]}`,
		text: `{"runs": ["0193a4c2-7d1e-7c3a-9f00-0000000000b2", "0193a4c2-7d1e-7c3a-9f00-0000000000b3"], "scope": "TASK", "agents": ["basalt_agent_bot", "basalt_agent_sync"], ` +
			`"tables": ["public.Leads", "public.leads", "public.notes"], "scopeId": "0193a4c2-7d1e-7c3a-9f00-0000000000c1"}`,
	},
}

func buildRescope(t *testing.T) []rescopeFixture {
	t.Helper()
	out := make([]rescopeFixture, 0, len(rescopeCases))
	for i, c := range rescopeCases {
		secret := seq(16, byte(0x40+i))
		nonce := seq(16, byte(0x60+i))
		key, err := revert.RescopeKey(secret)
		require.NoError(t, err)
		out = append(out, rescopeFixture{
			Name: c.name, RevertID: revertID.String(),
			Nonce: passkey.Bytes(nonce).String(), NewSecret: passkey.Bytes(secret).String(),
			Select: json.RawMessage(c.sel), SelectText: c.text, RescopeKey: hex.EncodeToString(key),
			Challenge: passkey.Bytes(reverttest.RescopeChallenge(revertID, nonce, key, c.text)).String(),
		})
	}
	return out
}

// Size of the batchedSkips fixture plan.
const (
	skipsPlanSkips    = 1500
	skipsPlanRestores = 50
)

// mixedBinding is the binding of a batched plan of mixedLines(skips, rows).
func mixedBinding(all, sample []string, skips, rows int) string {
	return fmt.Sprintf(`{"kind": "REVERT", "rows": %d, "intent": "Undo the bulk load", "select": {"runs": null, "scope": "RUN", "agents": ["basalt_agent_bot"], "tables": null, "scopeId": %q}, "batched": true, "skipped": %d, "widened": false, "database": "app", "revertId": %q, "rowsHash": %q, "expiresAt": "2026-11-11T07:02:11.123456Z", "sampleHash": %q, "requestedBy": "basalt_agent_bot"}`,
		rows, runID.String(), skips, revertID.String(), approval.RowsHash(all), approval.RowsHash(sample))
}

func buildFixtures(t *testing.T) fixtures {
	t.Helper()
	var f fixtures
	lines := revertLines()
	binding := bindingText(lines)
	req := revert.Request{RevertID: revertID, Binding: binding, Lines: lines, CredentialIDs: []passkey.Bytes{seq(16, 1)}}
	// The page's fixtures keep format 1, which the pages still read; format 2
	// has its shared vectors in api/mcp/links/compact-request.json.
	frag, err := linkcodectest.Encode(linkcodec.Format1, req)
	require.NoError(t, err)
	f.Request.RevertID = revertID.String()
	f.Request.Binding = binding
	f.Request.Lines = lines
	f.Request.CredentialIDs = []string{passkey.Bytes(seq(16, 1)).String()}
	f.Request.Fragment = frag
	f.Request.RowsHash = approval.RowsHash(lines)
	f.Request.Challenge = passkey.Bytes(approval.Challenge(binding)).String()

	resp := revert.Response{
		RevertID:          revertID,
		CredentialID:      seq(16, 1),
		AuthenticatorData: seq(37, 0x10),
		ClientDataJSON:    []byte(`{"type":"webauthn.get","challenge":"` + f.Request.Challenge + `","origin":"https://basaltvault.app","crossOrigin":false}`),
		Signature:         seq(70, 0x30),
	}
	body, err := json.Marshal(resp)
	require.NoError(t, err)
	f.Response.RevertID = revertID.String()
	f.Response.CredentialID = resp.CredentialID.String()
	f.Response.AuthenticatorData = resp.AuthenticatorData.String()
	f.Response.ClientDataJSON = resp.ClientDataJSON.String()
	f.Response.Signature = resp.Signature.String()
	f.Response.JSON = string(body)

	all, sample := planSample(t)
	plan := revert.Request{RevertID: revertID, Binding: batchedBinding(all, sample), Lines: sample}
	f.Batched.Fragment, err = linkcodectest.Encode(linkcodec.Format1, plan)
	require.NoError(t, err)
	f.Batched.RevertID = revertID.String()
	f.Batched.Binding = plan.Binding
	f.Batched.SampleHash = approval.RowsHash(sample)
	f.Batched.Lines = len(all)
	f.Batched.Skipped = planSkips

	all = mixedLines(skipsPlanSkips, skipsPlanRestores)
	sample, err = reverttest.Sample(all)
	require.NoError(t, err)
	plan = revert.Request{RevertID: revertID, Binding: mixedBinding(all, sample, skipsPlanSkips, skipsPlanRestores), Lines: sample}
	f.BatchedSkips.Fragment, err = linkcodectest.Encode(linkcodec.Format1, plan)
	require.NoError(t, err)
	f.BatchedSkips.Fragment2, err = plan.Fragment()
	require.NoError(t, err)
	f.BatchedSkips.Rows = skipsPlanRestores
	f.BatchedSkips.Skipped = skipsPlanSkips
	f.Rescope = buildRescope(t)
	return f
}

// TestGolden keeps testdata/fixtures.json in step with the Go encoders. Run
// with -update after a deliberate format change, then make web-check.
func TestGolden(t *testing.T) {
	t.Parallel()
	got, err := json.MarshalIndent(buildFixtures(t), "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')
	if *update {
		require.NoError(t, os.WriteFile(fixturesFile, got, 0o600))
	}
	want, err := os.ReadFile(fixturesFile)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "run go test ./internal/core/revert -update")
}

func TestParseLine(t *testing.T) {
	t.Parallel()
	lines := revertLines()
	require.True(t, sort.StringsAreSorted(lines), "fixture lines must be in byte order, as COLLATE \"C\" returns them")

	redacted, err := revert.ParseLine(lines[0])
	require.NoError(t, err)
	require.True(t, redacted.Redacted)
	require.Equal(t, revert.ActionRestore, redacted.Action)
	require.Empty(t, redacted.Set)

	restore, err := revert.ParseLine(lines[2])
	require.NoError(t, err)
	require.Equal(t, approval.OpUpdate, restore.Op)
	require.Len(t, restore.ChangeIDs, 2)
	require.JSONEq(t, `{"id": 3, "name": "Café ✓ lead", "status": "open"}`, string(restore.Set))

	skip, err := revert.ParseLine(lines[3])
	require.NoError(t, err)
	require.Equal(t, revert.ActionSkip, skip.Action)
	require.Equal(t, revert.ConflictChangedAfter, *skip.Conflict)
}

func TestParseLineRefuses(t *testing.T) {
	t.Parallel()
	ok := revertLines()[2]
	cases := map[string]string{
		"op":                      strings.Replace(ok, `"op": "UPDATE"`, `"op": "MERGE"`, 1),
		"action":                  strings.Replace(ok, `"RESTORE"`, `"MAYBE"`, 1),
		"RESTORE with a conflict": strings.Replace(ok, `"conflict": null`, `"conflict": "ROW_GONE"`, 1),
		"SKIP without a conflict": strings.Replace(ok, `"RESTORE"`, `"SKIP"`, 1),
		"unknown conflict":        strings.Replace(strings.Replace(ok, `"RESTORE"`, `"SKIP"`, 1), `"conflict": null`, `"conflict": "BAD_LUCK"`, 1),
		"no change ids":           strings.Replace(ok, `["`+change1+`", "`+change2+`"]`, `[]`, 1),
		"no table":                strings.Replace(ok, `"public.leads"`, `""`, 1),
		"unknown field":           strings.Replace(ok, `{"op"`, `{"x": 1, "op"`, 1),
		"approval line":           `{"op": "DELETE", "key": {"id": 3}, "old": {"id": 3}, "set": null, "table": "public.leads", "cascaded": false}`,
	}
	for name, line := range cases {
		_, err := revert.ParseLine(line)
		require.ErrorIs(t, err, approval.ErrInvalid, name)
	}
}

func TestRequestRoundTrip(t *testing.T) {
	t.Parallel()
	f := buildFixtures(t)
	url, err := revert.Request{RevertID: revertID, Binding: f.Request.Binding, Lines: f.Request.Lines}.URL(links.DefaultLocal)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(url, "http://localhost:8787/reverts/"+revertID.String()+"#2."), url)

	_, frag, ok := strings.Cut(url, "#")
	require.True(t, ok)
	req, b, err := reverttest.ParseRequest(frag)
	require.NoError(t, err)
	require.Equal(t, f.Request.Lines, req.Lines)
	require.Equal(t, revertID, b.RevertID)
	require.Equal(t, revert.ScopeRun, b.Select.Scope)
	require.Equal(t, runID, b.Select.ScopeID)
	require.Equal(t, []string{"basalt_agent_bot"}, b.Select.Agents)
	require.False(t, b.Widened)
	require.Nil(t, b.Proposed)
	require.Equal(t, 3, b.Rows)
	require.Equal(t, 1, b.Skipped)
	require.Equal(t, "2026-11-11T07:02:11.123456Z", b.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000000Z"))
}

func TestRequestRefusesMismatch(t *testing.T) {
	t.Parallel()
	lines := revertLines()
	binding := bindingText(lines)
	encode := func(r revert.Request) string {
		frag, err := r.Fragment()
		require.NoError(t, err)
		return frag
	}
	changed := append([]string{}, lines...)
	changed[3] = strings.Replace(changed[3], `"won"`, `"lost"`, 1)
	// Turning the skipped row into a restored one keeps the count of lines
	// but not the hash: the person signed that row as left alone.
	unskipped := append([]string{}, lines...)
	unskipped[3] = strings.Replace(strings.Replace(unskipped[3], `"SKIP"`, `"RESTORE"`, 1), `"CHANGED_AFTER"`, `null`, 1)

	cases := []struct {
		name, fragment, detail string
	}{
		{"a line changed after signing", encode(revert.Request{RevertID: revertID, Binding: binding, Lines: changed}), "rowsHash"},
		{"a skipped row turned into a restore", encode(revert.Request{RevertID: revertID, Binding: binding, Lines: unskipped}), "rowsHash"},
		{"a line dropped", encode(revert.Request{RevertID: revertID, Binding: binding, Lines: lines[:3]}), "3 lines, binding 4"},
		{"lines reordered", encode(revert.Request{RevertID: revertID, Binding: binding, Lines: []string{lines[1], lines[0], lines[2], lines[3]}}), "rowsHash"},
		{"another revert id (format 1)", encodeV1(t, revert.Request{RevertID: runID, Binding: binding, Lines: lines}), "binding for"},
		{"approval binding", encode(revert.Request{RevertID: revertID, Binding: strings.Replace(binding, `"REVERT"`, `"APPROVE"`, 1), Lines: lines}), "kind"},
		{"restore count", encode(revert.Request{RevertID: revertID, Binding: strings.Replace(strings.Replace(binding, `"rows": 3`, `"rows": 2`, 1), `"skipped": 1`, `"skipped": 2`, 1), Lines: lines}), "RESTORE lines"},
		{"wrong version", "3." + strings.TrimPrefix(encode(revert.Request{RevertID: revertID, Binding: binding, Lines: lines}), "2."), "must start with"},
		{"not base64url", "2.@@@", "base64url"},
		{"format 1 json in format 2", "2." + strings.TrimPrefix(fixtureFormat1(t), "1."), "shapes, lines"},
		{"only a binding", compactFragment(t, binding), "no lines"},
		{"a revert line rebuilt wrong", format2Swap(t), "rowsHash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := reverttest.ParseRequest(tc.fragment)
			require.ErrorIs(t, err, approval.ErrInvalid)
			require.ErrorContains(t, err, tc.detail)
		})
	}
}

func TestBindingLimits(t *testing.T) {
	t.Parallel()
	binding := bindingText(revertLines())
	cases := map[string]struct{ binding, detail string }{
		"over the line cap":        {strings.Replace(binding, `"skipped": 1`, `"skipped": 998`, 1), "out of 1..1000"},
		"nothing to restore":       {strings.Replace(binding, `"rows": 3`, `"rows": 0`, 1), "rows 0"},
		"negative skipped":         {strings.Replace(binding, `"skipped": 1`, `"skipped": -1`, 1), "skipped -1"},
		"unknown scope":            {strings.Replace(binding, `"RUN"`, `"DATABASE"`, 1), "scope"},
		"no agents":                {strings.Replace(binding, `["basalt_agent_bot"]`, `[]`, 1), "agents"},
		"rowsHash not hex":         {strings.Replace(binding, approval.RowsHash(revertLines()), "xyz", 1), "rowsHash"},
		"unknown field":            {strings.Replace(binding, `{"kind"`, `{"x": 1, "kind"`, 1), "unknown field"},
		"an approval's fields":     {`{"kind": "REVERT", "approvalId": "` + revertID.String() + `"}`, "unknown field"},
		"the old top-level scope":  {strings.Replace(binding, `"widened": false`, `"widened": false, "scope": "RUN"`, 1), "unknown field"},
		"the reserved store key":   {strings.Replace(binding, `"tables": null`, `"tables": null, "store": "x"`, 1), "unknown field"},
		"runs on a run scope":      {strings.Replace(binding, `"runs": null`, `"runs": ["`+runID.String()+`"]`, 1), "lists runs"},
		"widened not set":          {strings.Replace(binding, `"agents": ["basalt_agent_bot"]`, `"agents": ["basalt_agent_bot", "basalt_agent_sync"]`, 1), "widened false"},
		"every agent, not widened": {strings.Replace(binding, `"agents": ["basalt_agent_bot"]`, `"agents": null`, 1), "widened false"},
		"widened without agentRows": {strings.Replace(strings.Replace(binding, `"agents": ["basalt_agent_bot"]`, `"agents": null`, 1),
			`"widened": false`, `"widened": true`, 1), "agentRows"},
		"agentRows not widened": {strings.Replace(binding, `"widened": false`, `"widened": false, "agentRows": {"basalt_agent_bot": 4}`, 1), "agentRows"},
		"empty run proposal":    {strings.Replace(strings.Replace(binding, `"rows": 3`, `"rows": 0`, 1), `"skipped": 1`, `"skipped": 0`, 1), "rows 0"},
	}
	for name, tc := range cases {
		_, err := revert.ParseBinding(tc.binding)
		require.ErrorIs(t, err, approval.ErrInvalid, name)
		require.ErrorContains(t, err, tc.detail, name)
	}
}

// A widened select and an empty task proposal parse; the binding of a
// rescoped revert carries what the agent proposed.
func TestBindingScopes(t *testing.T) {
	t.Parallel()
	binding := bindingText(revertLines())
	widened := strings.Replace(strings.Replace(binding, `"agents": ["basalt_agent_bot"]`, `"agents": null`, 1),
		`"widened": false`, `"widened": true, "proposed": {"runs": null, "scope": "RUN", "agents": ["basalt_agent_bot"], "tables": ["public.leads"], "scopeId": "`+runID.String()+`"}, "agentRows": {"basalt_agent_bot": 3, "basalt_agent_sync": 1}`, 1)
	b, err := revert.ParseBinding(widened)
	require.NoError(t, err)
	require.True(t, b.Widened)
	require.Nil(t, b.Select.Agents)
	require.Equal(t, []string{"public.leads"}, b.Proposed.Tables)
	require.Equal(t, map[string]int{"basalt_agent_bot": 3, "basalt_agent_sync": 1}, b.AgentRows)

	task := strings.NewReplacer(`"scope": "RUN"`, `"scope": "TASK"`, `"rows": 3`, `"rows": 0`, `"skipped": 1`, `"skipped": 0`).Replace(binding)
	b, err = revert.ParseBinding(task)
	require.NoError(t, err)
	require.True(t, b.Empty())
	require.Zero(t, b.Lines())
}

func TestSampleSkipsFirst(t *testing.T) {
	t.Parallel()
	all, sample := planSample(t)
	require.Len(t, sample, revert.MaxLines)
	for i, text := range sample {
		l, err := revert.ParseLine(text)
		require.NoError(t, err)
		want := revert.ActionRestore
		if i < planSkips {
			want = revert.ActionSkip
		}
		require.Equal(t, want, l.Action, i)
	}
	require.True(t, sort.StringsAreSorted(sample[planSkips:]))
	require.Equal(t, sample[planSkips], all[0], "restores keep signed order")

	small, err := reverttest.Sample(revertLines())
	require.NoError(t, err)
	require.Equal(t, []string{revertLines()[3], revertLines()[0], revertLines()[1], revertLines()[2]}, small)
}

// mixedLines is a plan of skips SKIP lines and restores RESTORE lines,
// interleaved, in the order given (Sample does not sort).
func mixedLines(skips, restores int) []string {
	lines := make([]string, 0, skips+restores)
	for i := 0; skips > 0 || restores > 0; i++ {
		action, conflict := `"RESTORE"`, `null`
		if skips > 0 && (i%2 == 0 || restores == 0) {
			action, conflict = `"SKIP"`, `"CHANGED_AFTER"`
			skips--
		} else {
			restores--
		}
		lines = append(lines, fmt.Sprintf(`{"op": "UPDATE", "key": {"id": %d}, "now": {"id": %d, "v": "agent"}, "set": {"id": %d, "v": "before"}, "table": "public.items", "action": %s, "cascaded": false, "conflict": %s, "sqlState": null, "changeIds": [%q]}`,
			i+1, i+1, i+1, action, conflict, change1))
	}
	return lines
}

// TestSampleShowsBothKinds: a large plan's sample keeps room for 500 SKIP
// and 500 RESTORE lines, and a kind with fewer leaves its room to the other
// (decision RSS-1), so SKIP lines can never crowd out every RESTORE line.
func TestSampleShowsBothKinds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		skips, restores         int
		wantSkips, wantRestores int
	}{
		{1500, 50, 950, 50},
		{2000, 2000, 500, 500},
		{10, 3000, 10, 990},
		{3000, 0, 1000, 0},
		{1000, 1, 999, 1},
		{500, 501, 500, 500},
		{600, 401, 599, 401},
	}
	for _, tc := range cases {
		name := fmt.Sprintf("%d skips, %d restores", tc.skips, tc.restores)
		s, r := revert.SampleCounts(tc.skips, tc.restores)
		require.Equal(t, [2]int{tc.wantSkips, tc.wantRestores}, [2]int{s, r}, name)

		all := mixedLines(tc.skips, tc.restores)
		sample, err := reverttest.Sample(all)
		require.NoError(t, err, name)
		require.Len(t, sample, tc.wantSkips+tc.wantRestores, name)
		skips, restores := []string{}, []string{}
		for _, text := range all {
			l, err := revert.ParseLine(text)
			require.NoError(t, err)
			if l.Action == revert.ActionSkip {
				skips = append(skips, text)
			} else {
				restores = append(restores, text)
			}
		}
		require.Equal(t, skips[:tc.wantSkips], sample[:tc.wantSkips], "%s: SKIP lines first, in signed order", name)
		require.Equal(t, restores[:tc.wantRestores], sample[tc.wantSkips:], "%s: then RESTORE lines, in signed order", name)
	}
}

// TestBatchedRequestChecksTheSplit: a request's sample must split as
// SampleCounts gives for the binding's skipped and rows.
func TestBatchedRequestChecksTheSplit(t *testing.T) {
	t.Parallel()
	all := mixedLines(skipsPlanSkips, skipsPlanRestores)
	sample, err := reverttest.Sample(all)
	require.NoError(t, err)
	binding := func(lines []string) string {
		return mixedBinding(all, lines, skipsPlanSkips, skipsPlanRestores)
	}
	b, err := revert.Request{RevertID: revertID, Binding: binding(sample), Lines: sample}.Check()
	require.NoError(t, err)
	require.Equal(t, 50, b.Rows)

	// The sample before RSS-1: the first 1000 SKIP lines and no RESTORE line.
	var skipsOnly []string
	for _, text := range all {
		if strings.Contains(text, `"SKIP"`) && len(skipsOnly) < revert.MaxLines {
			skipsOnly = append(skipsOnly, text)
		}
	}
	_, err = revert.Request{RevertID: revertID, Binding: binding(skipsOnly), Lines: skipsOnly}.Check()
	require.ErrorIs(t, err, approval.ErrInvalid)
	require.ErrorContains(t, err, "request has 1000 SKIP lines, the binding's sample 950")
}

func TestBatchedRequestRoundTrip(t *testing.T) {
	t.Parallel()
	f := buildFixtures(t)
	req, b, err := reverttest.ParseRequest(f.Batched.Fragment)
	require.NoError(t, err)
	require.True(t, b.Batched)
	require.Equal(t, planSkips+planRestores, b.Lines())
	require.Equal(t, f.Batched.SampleHash, b.SampleHash)
	require.Len(t, req.Lines, revert.MaxLines)
}

// format2Swap returns the fixture request in format 2 with two values of
// its last line swapped, so the lines rebuild but no longer hash to the
// binding's rowsHash.
func format2Swap(t *testing.T) string {
	t.Helper()
	lines := revertLines()
	c := linkcodec.Compact(append([]string{bindingText(lines)}, lines...))
	last := c.Lines[len(c.Lines)-1]
	require.False(t, last.Verbatim)
	last.Values[0], last.Values[1] = last.Values[1], last.Values[0]
	frag, err := linkcodectest.Encode(linkcodec.Format2, c)
	require.NoError(t, err)
	return frag
}

// encodeV1 encodes r in format 1, which carries the revert id apart from
// the binding.
func encodeV1(t *testing.T, r revert.Request) string {
	t.Helper()
	frag, err := linkcodectest.Encode(linkcodec.Format1, r)
	require.NoError(t, err)
	return frag
}

func fixtureFormat1(t *testing.T) string {
	t.Helper()
	return buildFixtures(t).Request.Fragment
}

// compactFragment encodes texts in format 2 as they are.
func compactFragment(t *testing.T, texts ...string) string {
	t.Helper()
	frag, err := linkcodectest.Encode(linkcodec.Format2, linkcodec.Compact(texts))
	require.NoError(t, err)
	return frag
}

func TestRequestReadsFormat1(t *testing.T) {
	t.Parallel()
	f := buildFixtures(t)
	require.True(t, strings.HasPrefix(f.Request.Fragment, "1."))
	req, _, err := reverttest.ParseRequest("#" + f.Request.Fragment)
	require.NoError(t, err)
	require.Equal(t, f.Request.Lines, req.Lines)
	require.Len(t, req.CredentialIDs, 1, "format 1 still carries credential ids")
}

func TestBatchedRequestFormat2(t *testing.T) {
	t.Parallel()
	all, sample := planSample(t)
	plan := revert.Request{RevertID: revertID, Binding: batchedBinding(all, sample), Lines: sample, CredentialIDs: []passkey.Bytes{seq(16, 1)}}
	v1, err := linkcodectest.Encode(linkcodec.Format1, plan)
	require.NoError(t, err)
	v2, err := plan.Fragment()
	require.NoError(t, err)
	require.Less(t, len(v2), len(v1), "format 2 is shorter")
	req, b, err := reverttest.ParseRequest(v2)
	require.NoError(t, err)
	require.True(t, b.Batched)
	require.Equal(t, sample, req.Lines)
	require.Equal(t, []passkey.Bytes{seq(16, 1)}, req.CredentialIDs, "format 2 carries the credential ids, so the page offers only those passkeys")
}

// TestBatchedSkipsFormat2: the batchedSkips fixture round-trips in format 2
// as in format 1, its sample split as RSS-1 gives (the page runs the same
// fixture in web/lib/revert.test.mjs).
func TestBatchedSkipsFormat2(t *testing.T) {
	t.Parallel()
	f := buildFixtures(t).BatchedSkips
	v1, b1, err := reverttest.ParseRequest(f.Fragment)
	require.NoError(t, err)
	v2, b2, err := reverttest.ParseRequest(f.Fragment2)
	require.NoError(t, err)
	require.Equal(t, b1, b2)
	require.Equal(t, v1.Binding, v2.Binding)
	require.Equal(t, v1.Lines, v2.Lines)
	s, r := revert.SampleCounts(b2.Skipped, b2.Rows)
	require.Equal(t, [2]int{950, 50}, [2]int{s, r})
}

// FuzzParseRequest: whatever a revert link carries, parsing never panics,
// and a request it accepts hashes to its binding.
func FuzzParseRequest(f *testing.F) {
	lines := revertLines()
	req := revert.Request{RevertID: revertID, Binding: bindingText(lines), Lines: lines}
	v1, err := linkcodectest.Encode(linkcodec.Format1, req)
	require.NoError(f, err)
	v2, err := req.Fragment()
	require.NoError(f, err)
	f.Add(v1)
	f.Add(v2)
	f.Add("2.")
	f.Add("2.@@@")
	f.Fuzz(func(t *testing.T, fragment string) {
		req, b, err := reverttest.ParseRequest(fragment)
		if err != nil {
			require.ErrorIs(t, err, approval.ErrInvalid)
			return
		}
		require.Equal(t, b.RowsHash, approval.RowsHash(req.Lines))
	})
}

func TestBatchedRequestRefuses(t *testing.T) {
	t.Parallel()
	all, sample := planSample(t)
	binding := batchedBinding(all, sample)
	changed := slices.Clone(sample)
	changed[500] = strings.Replace(changed[500], `"agent"`, `"person"`, 1)
	restoreFirst := append(slices.Clone(sample[planSkips:planSkips+1]), sample[:planSkips]...)
	restoreFirst = append(restoreFirst, sample[planSkips+1:]...)
	fewerSkips := slices.Clone(sample)
	fewerSkips[planSkips-1] = sample[len(sample)-1]
	cases := []struct {
		name    string
		binding string
		lines   []string
		detail  string
	}{
		{"a sample line changed", binding, changed, "sampleHash"},
		{"a line short", binding, sample[:revert.MaxLines-1], "a batched plan's sample has 1000"},
		{"restore before skip", batchedBinding(all, restoreFirst), restoreFirst, "SKIP lines before RESTORE"},
		{"a skip missing", batchedBinding(all, fewerSkips), fewerSkips, "SKIP lines"},
		{"every line instead of the sample", binding, all, "sample has 1000"},
	}
	for _, tc := range cases {
		_, err := revert.Request{RevertID: revertID, Binding: tc.binding, Lines: tc.lines}.Check()
		require.ErrorIs(t, err, approval.ErrInvalid, tc.name)
		require.ErrorContains(t, err, tc.detail, tc.name)
	}
}

func TestBatchedBindingLimits(t *testing.T) {
	t.Parallel()
	all, sample := planSample(t)
	binding := batchedBinding(all, sample)
	small := bindingText(revertLines())
	cases := map[string]struct{ binding, detail string }{
		"batched with few lines": {strings.Replace(binding, `"rows": 1490`, `"rows": 990`, 1), "only a plan of more than 1000"},
		"batched without sample": {strings.Replace(binding, approval.RowsHash(sample), "", 1), "sampleHash"},
		"sample without batched": {strings.Replace(small, `"kind"`, `"sampleHash": "`+approval.RowsHash(sample)+`", "kind"`, 1), "not batched"},
		"large but not batched":  {strings.Replace(binding, `"batched": true, `, ``, 1), "not batched"},
	}
	for name, tc := range cases {
		_, err := revert.ParseBinding(tc.binding)
		require.ErrorIs(t, err, approval.ErrInvalid, name)
		require.ErrorContains(t, err, tc.detail, name)
	}
}

func TestRequestOverMaxLinesRejected(t *testing.T) {
	t.Parallel()
	lines := make([]string, revert.MaxLines+1)
	for i := range lines {
		lines[i] = revertLines()[3]
	}
	binding := strings.Replace(strings.Replace(bindingText(lines), `"rows": 3`, `"rows": 1`, 1), `"skipped": 1`, `"skipped": 1000`, 1)
	_, err := revert.Request{RevertID: revertID, Binding: binding, Lines: lines}.Check()
	require.ErrorContains(t, err, "out of 1..1000")
}

func TestDecodeResponseRefuses(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		"",
		`{"revertId":"` + revertID.String() + `"}`,
		`{"revertId":"nope","credentialId":"AQ","authenticatorData":"AQ","clientDataJson":"AQ","signature":"AQ"}`,
		`{"revertId":"` + revertID.String() + `","credentialId":"AQ","authenticatorData":"AQ","clientDataJson":"AQ","signature":"AQ","extra":1}`,
	} {
		_, err := revert.DecodeResponse([]byte(body))
		require.ErrorIs(t, err, approval.ErrInvalid, body)
	}
}
