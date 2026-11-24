package linkcodec_test

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approval/approvaltest"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec/linkcodectest"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
)

var update = flag.Bool("update", false, "rewrite api/mcp/links/compact-request.json")

// vectorsFile holds format 2's shared vectors: the contract test, this test
// and the pages' tests (web/lib/codec.test.mjs) all read it.
const vectorsFile = "../../../api/mcp/links/compact-request.json"

const (
	kindApprove = "APPROVE"
	kindRevert  = "REVERT"
	// deepNesting is one level past the deepest array a value may hold.
	deepNesting = 33
	// longName makes 51 texts rebuild past 1 MiB from a small link.
	longName = 21_000
)

type validVector struct {
	Name     string          `json:"name"`
	Kind     string          `json:"kind"`
	Fragment string          `json:"fragment"`
	Payload  json.RawMessage `json:"payload"`
	Binding  string          `json:"binding"`
	Lines    []string        `json:"lines"`
	// CredentialIDs are the ids the link carries, base64url; none when
	// absent.
	CredentialIDs []string `json:"credentialIds,omitempty"`
}

type invalidVector struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Fragment string `json:"fragment"`
}

type vectors struct {
	Description string          `json:"description"`
	Valid       []validVector   `json:"valid"`
	Invalid     []invalidVector `json:"invalid"`
}

// pageFixture reads the request of a package's page fixtures, which hold
// lines as Postgres prints them.
func pageFixture(t *testing.T, file string) (string, []string) {
	t.Helper()
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	var f struct {
		Request struct {
			Binding string   `json:"binding"`
			Lines   []string `json:"lines"`
		} `json:"request"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	return f.Request.Binding, f.Request.Lines
}

// valueLines are preview lines with every kind of value format 2 carries,
// and one whose spacing is not jsonb's, which travels as its text.
func valueLines() []string {
	return []string{
		`{"op":"INSERT","key":null,"old":null,"set":{"id":1},"table":"public.t","cascaded":false}`,
		`{"op": "INSERT", "key": null, "old": null, "set": {}, "table": "public.empty", "cascaded": false}`,
		`{"op": "UPDATE", "key": {"id": 9}, "old": {"id": 9, "big": 9007199254740993, "doc": {"a": [1, 2], "b": null}, "neg": -42, "flag": true, "note": "tab\there \"quoted\" back\\slash \u0001 é 日本 🚀", "tags": ["x", "y", []], "price": 1.50}, "set": {"price": 2.00}, "table": "public.items", "cascaded": false}`,
	}
}

func approvalBinding(lines []string) string {
	return fmt.Sprintf(`{"kind": "APPROVE", "rows": %d, "agent": "basalt_agent_bot", "runId": "0193a4c2-7d1e-7c3a-9f00-0000000000b2", "intent": "Fix <prices> & notes", "params": [2.00, "x"], "taskId": null, "database": "app", "rowsHash": %q, "expiresAt": "2026-11-12T06:02:11.123456Z", "statement": "UPDATE public.items SET price = $1 WHERE id = 9", "approvalId": "0193a4c2-7d1e-7c3a-9f00-0000000000a1", "assignedColumns": ["price"]}`,
		len(lines), approval.RowsHash(lines))
}

func fragmentOf(t *testing.T, v any) string {
	t.Helper()
	frag, err := linkcodectest.Encode(linkcodec.Format2, v)
	require.NoError(t, err)
	return frag
}

// rawFragment deflates text as it is, which may not be JSON or UTF-8.
func rawFragment(t *testing.T, text string, trailing string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	require.NoError(t, err)
	_, err = w.Write([]byte(text))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	buf.WriteString(trailing)
	return linkcodec.Format2 + passkey.Bytes(buf.Bytes()).String()
}

func validOf(t *testing.T, name, kind, binding string, lines []string, ids ...passkey.Bytes) validVector {
	t.Helper()
	frag, err := linkcodec.EncodeRequest(binding, lines, ids)
	require.NoError(t, err)
	c := linkcodec.Compact(append([]string{binding}, lines...))
	c.CredentialIDs = ids
	payload, err := json.Marshal(c)
	require.NoError(t, err)
	v := validVector{Name: name, Kind: kind, Fragment: frag, Payload: payload, Binding: binding, Lines: lines}
	for _, id := range ids {
		v.CredentialIDs = append(v.CredentialIDs, id.String())
	}
	return v
}

// shaped returns the compact form of the binding and lines, for a test to
// break.
func shaped(binding string, lines []string) linkcodec.Lines {
	return linkcodec.Compact(append([]string{binding}, lines...))
}

func buildVectors(t *testing.T) vectors {
	t.Helper()
	aBinding, aLines := pageFixture(t, "../approval/testdata/fixtures.json")
	rBinding, rLines := pageFixture(t, "../revert/testdata/fixtures.json")
	vLines := valueLines()
	vBinding := approvalBinding(vLines)
	v := vectors{
		Description: "Shared cases for CONTRACT.md, Approvals, Format 2. valid: fragment decodes to payload (the inflated JSON) and rebuilds to binding and lines exactly; kind is the binding's kind (APPROVE for the approval page, REVERT for the revert page). invalid: the page of that kind refuses the fragment, by the format's rules or by the checks every request gets (rowsHash, kind). Go's internal/core/linkcodec tests write this file (go test ./internal/core/linkcodec -update) and run it; the pages' tests run it too.",
		Valid: []validVector{
			validOf(t, "an approval: the pages' fixture", kindApprove, aBinding, aLines),
			validOf(t, "a revert: the pages' fixture", kindRevert, rBinding, rLines),
			validOf(t, "every kind of value, and a line that travels as its text", kindApprove, vBinding, vLines),
			validOf(t, "an approval with the database's credential ids", kindApprove, aBinding, aLines, idOf(1, 16), idOf(2, 32)),
			validOf(t, "a revert with the database's credential ids", kindRevert, rBinding, rLines, idOf(3, 20)),
		},
	}

	add := func(name, kind, frag string) {
		v.Invalid = append(v.Invalid, invalidVector{Name: name, Kind: kind, Fragment: frag})
	}
	// mutate breaks the compact form of the value lines.
	mutate := func(fn func(c *linkcodec.Lines)) string {
		c := shaped(vBinding, vLines)
		fn(&c)
		return fragmentOf(t, c)
	}
	last := func(c *linkcodec.Lines) *linkcodec.Line { return &c.Lines[len(c.Lines)-1] }
	setValue := func(raw string) func(c *linkcodec.Lines) {
		return func(c *linkcodec.Lines) { last(c).Values[2] = json.RawMessage(raw) }
	}
	format1, err := linkcodectest.Encode(linkcodec.Format1, approval.Request{Binding: vBinding, Lines: vLines})
	require.NoError(t, err)
	tooMany := make([]string, approval.MaxRows+1)
	for i := range tooMany {
		tooMany[i] = vLines[1]
	}
	deep := strings.Repeat("[", deepNesting) + strings.Repeat("]", deepNesting)
	long := linkcodec.Lines{Shapes: []linkcodec.Shape{{{Name: strings.Repeat("n", longName)}}}}
	for range approval.MaxRows + 1 {
		long.Lines = append(long.Lines, linkcodec.Line{Values: []json.RawMessage{json.RawMessage("1")}})
	}
	changed := shaped(vBinding, vLines)
	last(&changed).Values[0] = json.RawMessage(`"DELETE"`)

	add("format 1 JSON after 2.", kindApprove, linkcodec.Format2+strings.TrimPrefix(format1, linkcodec.Format1))
	withIDs := func(ids any) string {
		return fragmentOf(t, []any{shaped(vBinding, vLines).Shapes, shaped(vBinding, vLines).Lines, ids})
	}
	add("an empty credential id list", kindApprove, withIDs([]string{}))
	add("a credential id twice", kindApprove, withIDs([]string{"AQID", "AQID"}))
	add("a credential id that is not base64url", kindApprove, withIDs([]string{"AQ=="}))
	add("an empty credential id", kindApprove, withIDs([]string{""}))
	add("credential ids that are not a list", kindApprove, withIDs("AQID"))
	add("101 credential ids", kindApprove, withIDs(manyIDs(linkcodec.MaxCredentialIDs+1)))
	add("a fourth element", kindApprove, fragmentOf(t, []any{shaped(vBinding, vLines).Shapes, shaped(vBinding, vLines).Lines, []string{"AQID"}, []string{}}))
	add("an object instead of [shapes, texts]", kindApprove, fragmentOf(t, map[string]any{"shapes": shaped(vBinding, vLines).Shapes, "lines": shaped(vBinding, vLines).Lines}))
	add("only the binding", kindApprove, fragmentOf(t, linkcodec.Compact([]string{vBinding})))
	add("51 preview lines", kindApprove, fragmentOf(t, linkcodec.Compact(append([]string{approvalBinding(tooMany)}, tooMany...))))
	add("a shape index past the shapes", kindApprove, mutate(func(c *linkcodec.Lines) { last(c).Shape = len(c.Shapes) }))
	add("a negative shape index", kindApprove, mutate(func(c *linkcodec.Lines) { last(c).Shape = -1 }))
	add("one value too few", kindApprove, mutate(func(c *linkcodec.Lines) { last(c).Values = last(c).Values[1:] }))
	add("one value too many", kindApprove, mutate(func(c *linkcodec.Lines) { last(c).Values = append(last(c).Values, json.RawMessage("1")) }))
	add("an unused shape", kindApprove, mutate(func(c *linkcodec.Lines) { c.Shapes = append(c.Shapes, linkcodec.Shape{{Name: "x"}}) }))
	add("a shape with no entries", kindApprove, mutate(func(c *linkcodec.Lines) { c.Shapes[last(c).Shape] = linkcodec.Shape{} }))
	add("a fraction as a value", kindApprove, mutate(setValue("1.5")))
	add("an integer past 2^53 - 1", kindApprove, mutate(setValue("9007199254740992")))
	add("negative zero", kindApprove, mutate(setValue("-0")))
	add("an object value other than raw", kindApprove, mutate(setValue(`{"text": "1"}`)))
	add("arrays nested 33 deep", kindApprove, mutate(setValue(deep)))
	add("texts that rebuild past 1 MiB", kindApprove, fragmentOf(t, long))
	add("bytes after the deflate stream", kindApprove, rawFragment(t, string(mustJSON(t, shaped(vBinding, vLines))), "x"))
	add("JSON after the request", kindApprove, rawFragment(t, string(mustJSON(t, shaped(vBinding, vLines)))+" []", ""))
	add("not UTF-8", kindApprove, rawFragment(t, "[[], [\"\xff\"]]", ""))
	add("a line break in the base64url", kindApprove, strings.Replace(validOf(t, "", kindApprove, vBinding, vLines).Fragment, "2.", "2.\n", 1))
	add("a value changed, so rowsHash differs", kindApprove, fragmentOf(t, changed))
	add("an approval on the revert page", kindRevert, validOf(t, "", kindApprove, aBinding, aLines).Fragment)
	return v
}

// idTexts is ids in base64url, nil for none.
func idTexts(ids []passkey.Bytes) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

// idOf is an n-byte credential id filled with b.
func idOf(b byte, n int) passkey.Bytes {
	return bytes.Repeat([]byte{b}, n)
}

// manyIDs is n distinct credential ids, base64url.
func manyIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = passkey.Bytes{byte(i), byte(i >> 8), 1}.String()
	}
	return out
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return raw
}

func parse(kind, fragment string) (string, []string, []passkey.Bytes, error) {
	if kind == kindRevert {
		r, _, err := reverttest.ParseRequest(fragment)
		return r.Binding, r.Lines, r.CredentialIDs, err
	}
	r, _, err := approvaltest.ParseRequest(fragment)
	return r.Binding, r.Lines, r.CredentialIDs, err
}

// TestVectors keeps the shared vectors in step with the Go encoder and runs
// them through the Go decoders.
func TestVectors(t *testing.T) {
	t.Parallel()
	got, err := json.MarshalIndent(buildVectors(t), "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')
	if *update {
		require.NoError(t, os.WriteFile(vectorsFile, got, 0o600))
	}
	want, err := os.ReadFile(vectorsFile)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "run go test ./internal/core/linkcodec -update")

	var v vectors
	require.NoError(t, json.Unmarshal(want, &v))
	for _, tc := range v.Valid {
		binding, lines, ids, err := parse(tc.Kind, tc.Fragment)
		require.NoError(t, err, tc.Name)
		require.Equal(t, tc.CredentialIDs, idTexts(ids), tc.Name)
		require.Equal(t, tc.Binding, binding, tc.Name)
		require.Equal(t, tc.Lines, lines, tc.Name)
		sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
		require.Contains(t, binding, hex.EncodeToString(sum[:]), tc.Name)
	}
	for _, tc := range v.Invalid {
		_, _, _, err := parse(tc.Kind, tc.Fragment)
		require.ErrorIs(t, err, approval.ErrInvalid, tc.Name)
	}
}
