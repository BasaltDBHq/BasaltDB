package revert_test

import (
	"crypto/sha256"
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

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
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
	return fmt.Sprintf(`{"kind": "REVERT", "rows": 3, "scope": "RUN", "agents": ["basalt_agent_bot"], "intent": "Undo the bad merge", "scopeId": %q, "skipped": 1, "database": "app", "revertId": %q, "rowsHash": %q, "expiresAt": "2026-11-11T07:02:11.123456Z", "requestedBy": "basalt_agent_bot"}`,
		runID.String(), revertID.String(), revert.RowsHash(lines))
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
	return fmt.Sprintf(`{"kind": "REVERT", "rows": %d, "scope": "RUN", "agents": ["basalt_agent_bot"], "intent": "Undo the bulk load", "batched": true, "scopeId": %q, "skipped": %d, "database": "app", "revertId": %q, "rowsHash": %q, "expiresAt": "2026-11-11T07:02:11.123456Z", "sampleHash": %q, "requestedBy": "basalt_agent_bot"}`,
		planRestores, runID.String(), planSkips, revertID.String(), revert.RowsHash(all), revert.RowsHash(sample))
}

func planSample(t *testing.T) ([]string, []string) {
	t.Helper()
	all := planLines()
	sample, err := revert.Sample(all)
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
		Code              string `json:"code"`
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
}

func buildFixtures(t *testing.T) fixtures {
	t.Helper()
	var f fixtures
	lines := revertLines()
	binding := bindingText(lines)
	req := revert.Request{RevertID: revertID, Binding: binding, Lines: lines, CredentialIDs: []passkey.Bytes{seq(16, 1)}}
	// The page's fixtures keep format 1, which the pages still read; format 2
	// has its shared vectors in api/mcp/links/compact-request.json.
	frag, err := linkcodec.Encode(linkcodec.Format1, req)
	require.NoError(t, err)
	f.Request.RevertID = revertID.String()
	f.Request.Binding = binding
	f.Request.Lines = lines
	f.Request.CredentialIDs = []string{passkey.Bytes(seq(16, 1)).String()}
	f.Request.Fragment = frag
	f.Request.RowsHash = revert.RowsHash(lines)
	f.Request.Challenge = passkey.Bytes(revert.Challenge(binding)).String()

	resp := revert.Response{
		RevertID:          revertID,
		CredentialID:      seq(16, 1),
		AuthenticatorData: seq(37, 0x10),
		ClientDataJSON:    []byte(`{"type":"webauthn.get","challenge":"` + f.Request.Challenge + `","origin":"https://basaltvault.app","crossOrigin":false}`),
		Signature:         seq(70, 0x30),
	}
	code, err := resp.Code()
	require.NoError(t, err)
	f.Response.RevertID = revertID.String()
	f.Response.CredentialID = resp.CredentialID.String()
	f.Response.AuthenticatorData = resp.AuthenticatorData.String()
	f.Response.ClientDataJSON = resp.ClientDataJSON.String()
	f.Response.Signature = resp.Signature.String()
	f.Response.Code = code

	all, sample := planSample(t)
	plan := revert.Request{RevertID: revertID, Binding: batchedBinding(all, sample), Lines: sample}
	f.Batched.Fragment, err = linkcodec.Encode(linkcodec.Format1, plan)
	require.NoError(t, err)
	f.Batched.RevertID = revertID.String()
	f.Batched.Binding = plan.Binding
	f.Batched.SampleHash = revert.RowsHash(sample)
	f.Batched.Lines = len(all)
	f.Batched.Skipped = planSkips
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
	require.Equal(t, string(want), string(got), "run go test ./internal/revert -update")
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
		require.ErrorIs(t, err, revert.ErrInvalid, name)
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
	req, b, err := revert.ParseRequest(frag)
	require.NoError(t, err)
	require.Equal(t, f.Request.Lines, req.Lines)
	require.Equal(t, revertID, b.RevertID)
	require.Equal(t, revert.ScopeRun, b.Scope)
	require.Equal(t, runID, b.ScopeID)
	require.Equal(t, []string{"basalt_agent_bot"}, b.Agents)
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
			_, _, err := revert.ParseRequest(tc.fragment)
			require.ErrorIs(t, err, revert.ErrInvalid)
			require.ErrorContains(t, err, tc.detail)
		})
	}
}

func TestBindingLimits(t *testing.T) {
	t.Parallel()
	binding := bindingText(revertLines())
	cases := map[string]struct{ binding, detail string }{
		"over the line cap":    {strings.Replace(binding, `"skipped": 1`, `"skipped": 998`, 1), "out of 1..1000"},
		"nothing to restore":   {strings.Replace(binding, `"rows": 3`, `"rows": 0`, 1), "rows 0"},
		"negative skipped":     {strings.Replace(binding, `"skipped": 1`, `"skipped": -1`, 1), "skipped -1"},
		"unknown scope":        {strings.Replace(binding, `"RUN"`, `"DATABASE"`, 1), "scope"},
		"no agents":            {strings.Replace(binding, `["basalt_agent_bot"]`, `[]`, 1), "agents"},
		"rowsHash not hex":     {strings.Replace(binding, revert.RowsHash(revertLines()), "xyz", 1), "rowsHash"},
		"unknown field":        {strings.Replace(binding, `{"kind"`, `{"x": 1, "kind"`, 1), "unknown field"},
		"an approval's fields": {`{"kind": "REVERT", "approvalId": "` + revertID.String() + `"}`, "unknown field"},
	}
	for name, tc := range cases {
		_, err := revert.ParseBinding(tc.binding)
		require.ErrorIs(t, err, revert.ErrInvalid, name)
		require.ErrorContains(t, err, tc.detail, name)
	}
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

	small, err := revert.Sample(revertLines())
	require.NoError(t, err)
	require.Equal(t, []string{revertLines()[3], revertLines()[0], revertLines()[1], revertLines()[2]}, small)
}

func TestBatchedRequestRoundTrip(t *testing.T) {
	t.Parallel()
	f := buildFixtures(t)
	req, b, err := revert.ParseRequest(f.Batched.Fragment)
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
	frag, err := linkcodec.Encode(linkcodec.Format2, c)
	require.NoError(t, err)
	return frag
}

// encodeV1 encodes r in format 1, which carries the revert id apart from
// the binding.
func encodeV1(t *testing.T, r revert.Request) string {
	t.Helper()
	frag, err := linkcodec.Encode(linkcodec.Format1, r)
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
	frag, err := linkcodec.Encode(linkcodec.Format2, linkcodec.Compact(texts))
	require.NoError(t, err)
	return frag
}

func TestRequestReadsFormat1(t *testing.T) {
	t.Parallel()
	f := buildFixtures(t)
	require.True(t, strings.HasPrefix(f.Request.Fragment, "1."))
	req, _, err := revert.ParseRequest("#" + f.Request.Fragment)
	require.NoError(t, err)
	require.Equal(t, f.Request.Lines, req.Lines)
	require.Len(t, req.CredentialIDs, 1, "format 1 still carries credential ids")
}

func TestBatchedRequestFormat2(t *testing.T) {
	t.Parallel()
	all, sample := planSample(t)
	plan := revert.Request{RevertID: revertID, Binding: batchedBinding(all, sample), Lines: sample, CredentialIDs: []passkey.Bytes{seq(16, 1)}}
	v1, err := linkcodec.Encode(linkcodec.Format1, plan)
	require.NoError(t, err)
	v2, err := plan.Fragment()
	require.NoError(t, err)
	require.Less(t, len(v2), len(v1), "format 2 is shorter")
	req, b, err := revert.ParseRequest(v2)
	require.NoError(t, err)
	require.True(t, b.Batched)
	require.Equal(t, sample, req.Lines)
	require.Empty(t, req.CredentialIDs, "format 2 leaves out credential ids: the passkeys are discoverable")
}

// FuzzParseRequest: whatever a revert link carries, parsing never panics,
// and a request it accepts hashes to its binding.
func FuzzParseRequest(f *testing.F) {
	lines := revertLines()
	req := revert.Request{RevertID: revertID, Binding: bindingText(lines), Lines: lines}
	v1, err := linkcodec.Encode(linkcodec.Format1, req)
	require.NoError(f, err)
	v2, err := req.Fragment()
	require.NoError(f, err)
	f.Add(v1)
	f.Add(v2)
	f.Add("2.")
	f.Add("2.@@@")
	f.Fuzz(func(t *testing.T, fragment string) {
		req, b, err := revert.ParseRequest(fragment)
		if err != nil {
			require.ErrorIs(t, err, revert.ErrInvalid)
			return
		}
		require.Equal(t, b.RowsHash, revert.RowsHash(req.Lines))
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
		require.ErrorIs(t, err, revert.ErrInvalid, tc.name)
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
		"batched without sample": {strings.Replace(binding, revert.RowsHash(sample), "", 1), "sampleHash"},
		"sample without batched": {strings.Replace(small, `"kind"`, `"sampleHash": "`+revert.RowsHash(sample)+`", "kind"`, 1), "not batched"},
		"large but not batched":  {strings.Replace(binding, `"batched": true, `, ``, 1), "not batched"},
	}
	for name, tc := range cases {
		_, err := revert.ParseBinding(tc.binding)
		require.ErrorIs(t, err, revert.ErrInvalid, name)
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

// TestVerifyWithSoftwareKey signs a revert's challenge with a software
// passkey, carries it through the response code, and verifies it like
// apply_revert will.
func TestVerifyWithSoftwareKey(t *testing.T) {
	t.Parallel()
	binding := bindingText(revertLines())
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)

	as, err := person.Sign(revert.Challenge(binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	code, err := revert.NewResponse(revertID, as).Code()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(code, "basalt-revert.1."))
	resp, err := revert.ParseResponse("\n" + code + " ")
	require.NoError(t, err)

	count, err := revert.Verify(binding, person.Credential(), resp)
	require.NoError(t, err)
	require.Equal(t, uint32(1), count)

	t.Run("another binding", func(t *testing.T) {
		t.Parallel()
		other := strings.Replace(binding, "Undo the bad merge", "Undo everything", 1)
		_, err := revert.Verify(other, person.Credential(), resp)
		require.ErrorIs(t, err, passkey.ErrRejected)
	})
	t.Run("another revert id", func(t *testing.T) {
		t.Parallel()
		moved := resp
		moved.RevertID = runID
		_, err := revert.Verify(binding, person.Credential(), moved)
		require.ErrorContains(t, err, "binding for")
	})
	t.Run("an approval code is not a revert code", func(t *testing.T) {
		t.Parallel()
		approvalCode, err := approval.NewResponse(revertID, as).Code()
		require.NoError(t, err)
		_, err = revert.ParseResponse(approvalCode)
		require.ErrorIs(t, err, revert.ErrInvalid)
	})
	t.Run("a signature over an approval binding", func(t *testing.T) {
		t.Parallel()
		approvalBinding := `{"kind": "APPROVE"}`
		signed, err := person.Sign(revert.Challenge(approvalBinding), passkeytest.FlagsUPUV, nil)
		require.NoError(t, err)
		_, err = revert.Verify(binding, person.Credential(), revert.NewResponse(revertID, signed))
		require.ErrorIs(t, err, passkey.ErrRejected)
	})
	t.Run("an agent's own key", func(t *testing.T) {
		t.Parallel()
		agent, err := passkeytest.New(passkey.Production)
		require.NoError(t, err)
		agent.ID = person.ID
		forged, err := agent.Sign(revert.Challenge(binding), passkeytest.FlagsUPUV, nil)
		require.NoError(t, err)
		_, err = revert.Verify(binding, person.Credential(), revert.NewResponse(revertID, forged))
		require.ErrorContains(t, err, "bad passkey signature")
	})
}

func TestParseResponseRefuses(t *testing.T) {
	t.Parallel()
	for _, code := range []string{
		"",
		"basalt-approval.1.e30",
		revert.ResponsePrefix + passkey.Bytes(`{"revertId":"`+revertID.String()+`"}`).String(),
		revert.ResponsePrefix + passkey.Bytes(`{"revertId":"nope","credentialId":"AQ","authenticatorData":"AQ","clientDataJson":"AQ","signature":"AQ"}`).String(),
	} {
		_, err := revert.ParseResponse(code)
		require.ErrorIs(t, err, revert.ErrInvalid, code)
	}
}
