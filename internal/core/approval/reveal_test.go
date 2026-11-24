package approval_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approval/approvaltest"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec/linkcodectest"
)

const revealFile = "testdata/reveal.json"

var revealID = uuid.MustParse("0193a3f0-0000-7000-8000-000000000001")

func counting(start byte) []byte {
	b := make([]byte, 16)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// The key and both challenges match values computed independently (RFC
// 5869 HKDF and sha256 in Python's hmac and hashlib), so Go, the page and
// Postgres are checked against the same vector.
func TestRevealKeyAndChallenge(t *testing.T) {
	t.Parallel()
	key, err := approval.RevealKey(counting(0))
	require.NoError(t, err)
	require.Equal(t, "10ab07b083d16ab69eb9fdff08c23623b83a2c93f77d8d584c57ec2cdc66e1fd", hex.EncodeToString(key))

	rowsHash := "abababababababababababababababababababababababababababababababab"
	got, err := approvaltest.RevealChallenge(approval.KindApprove, revealID, counting(100), key, rowsHash)
	require.NoError(t, err)
	require.Equal(t, "b238a10109ab85bbff9f9bbe9084e6fb23fa77705366ea19bfb13319525998ec", hex.EncodeToString(got))
	got, err = approvaltest.RevealChallenge(approval.KindRevert, revealID, counting(100), key, rowsHash)
	require.NoError(t, err)
	require.Equal(t, "6003a5c9d6c593716594dcaa011cf9a82e2b371ac8a737c2abdbf93731c44708", hex.EncodeToString(got))

	other, err := approval.RevealKey(append([]byte{1}, counting(0)[1:]...))
	require.NoError(t, err)
	require.NotEqual(t, key, other)
}

func TestRevealChallengeRefusesBadInput(t *testing.T) {
	t.Parallel()
	key, err := approval.RevealKey(counting(0))
	require.NoError(t, err)
	hash := hex.EncodeToString(make([]byte, sha256.Size))
	for name, call := range map[string]func() error{
		"kind": func() error {
			_, err := approvaltest.RevealChallenge("APPLY", revealID, counting(100), key, hash)
			return err
		},
		"short nonce": func() error {
			_, err := approvaltest.RevealChallenge(approval.KindApprove, revealID, counting(100)[:15], key, hash)
			return err
		},
		"short key": func() error {
			_, err := approvaltest.RevealChallenge(approval.KindApprove, revealID, counting(100), key[:31], hash)
			return err
		},
		"upper hash": func() error {
			_, err := approvaltest.RevealChallenge(approval.KindApprove, revealID, counting(100), key, "AB"+hash[2:])
			return err
		},
		"short hash": func() error {
			_, err := approvaltest.RevealChallenge(approval.KindApprove, revealID, counting(100), key, hash[2:])
			return err
		},
		"short secret": func() error { _, err := approval.RevealKey(counting(0)[:15]); return err },
		"long secret":  func() error { _, err := approval.RevealKey(append(counting(0), 0)); return err },
	} {
		require.ErrorIs(t, call(), approval.ErrInvalid, name)
	}
}

// revealVectors are shared with the pages (web/lib/codec.test.mjs): the
// challenges, and revealed rows with the result each must get.
type revealVectors struct {
	Challenges []challengeVector `json:"challenges"`
	Rows       []rowVector       `json:"rows"`
}

type challengeVector struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	ID           string `json:"id"`
	Nonce        string `json:"nonce"`
	RevealSecret string `json:"revealSecret"`
	RevealKey    string `json:"revealKey"`
	RowsHash     string `json:"rowsHash"`
	Challenge    string `json:"challenge"`
}

// rowVector is one revealed row against the redacted line it answers.
// Result is CHECKED, UNVERIFIED or REFUSED.
type rowVector struct {
	Name   string          `json:"name"`
	Line   string          `json:"line"`
	Row    json.RawMessage `json:"row"`
	Result string          `json:"result"`
}

const (
	resultChecked    = "CHECKED"
	resultUnverified = "UNVERIFIED"
	resultRefused    = "REFUSED"
)

func rowHashOf(row string) string {
	sum := sha256.Sum256([]byte(row))
	return hex.EncodeToString(sum[:])
}

func approvalLine(hash string) string {
	return fmt.Sprintf(`{"op": "DELETE", "table": "public.lead_notes", "rowHash": %q, "cascaded": true, "redacted": true}`, hash)
}

func revertLine(hash string) string {
	return fmt.Sprintf(`{"op": "INSERT", "table": "public.lead_notes", "action": "RESTORE", "rowHash": %q, "cascaded": true, "conflict": null, "redacted": true, "changeIds": ["0193a3f0-0000-7000-8000-0000000000c1"]}`, hash)
}

func buildRevealVectors(t *testing.T) revealVectors {
	t.Helper()
	var v revealVectors
	// The revert vector signs a large plan's rowsHash (over all 1500
	// lines), never its sampleHash.
	for i, c := range []struct{ name, kind, rowsHash string }{
		{"approval", approval.KindApprove, approval.RowsHash([]string{approvalLine(rowHashOf(`[{"id": 7}, {"id": 7}, null]`))})},
		{"revert, large plan", approval.KindRevert, approval.RowsHash(make([]string, 1500))},
	} {
		secret, nonce := counting(byte(16*i)), counting(byte(100+16*i))
		key, err := approval.RevealKey(secret)
		require.NoError(t, err)
		id := uuid.MustParse(fmt.Sprintf("0193a3f0-0000-7000-8000-00000000000%d", i+1))
		ch, err := approvaltest.RevealChallenge(c.kind, id, nonce, key, c.rowsHash)
		require.NoError(t, err)
		v.Challenges = append(v.Challenges, challengeVector{
			Name: c.name, Kind: c.kind, ID: id.String(), Nonce: base64.RawURLEncoding.EncodeToString(nonce),
			RevealSecret: base64.RawURLEncoding.EncodeToString(secret), RevealKey: hex.EncodeToString(key),
			RowsHash: c.rowsHash, Challenge: base64.RawURLEncoding.EncodeToString(ch),
		})
	}

	note := `[{"id": 8}, {"id": 8, "body": "call back", "lead_id": 4}, null]`
	restore := `[{"id": 8}, null, {"id": 8, "body": "call back \"Ana\"", "lead_id": 4}]`
	secretOld := `[{"id": 9}, {"id": 9, "pin": null, "lead_id": 4}, null]`
	secretBoth := `[{"id": 9}, {"id": 9, "pin": "1234", "lead_id": 4}, {"pin": null}]`
	unchecked := approvalLine(rowHashOf(`[{"id": 9}, {"id": 9, "pin": "1234", "lead_id": 4}, null]`))
	row := func(r string, cols ...string) json.RawMessage {
		b, err := json.Marshal(approval.RevealedRow{Row: r, SecretColumns: cols})
		require.NoError(t, err)
		return b
	}
	noteJSON, err := json.Marshal(note)
	require.NoError(t, err)
	v.Rows = []rowVector{
		{"approval row that hashes to its line", approvalLine(rowHashOf(note)), row(note), resultChecked},
		{"revert row that hashes to its line", revertLine(rowHashOf(restore)), row(restore), resultChecked},
		{"a changed value", approvalLine(rowHashOf(note)), row(`[{"id": 8}, {"id": 8, "body": "call later", "lead_id": 4}, null]`), resultRefused},
		{"a re-serialized row", approvalLine(rowHashOf(note)), row(`[{"id":8},{"id":8,"body":"call back","lead_id":4},null]`), resultRefused},
		{"a SECRET column nulled", unchecked, row(secretOld, "pin"), resultUnverified},
		{"a SECRET column with a value", unchecked, row(secretBoth, "pin"), resultRefused},
		{"a SECRET column the row does not contain", unchecked, row(secretOld, "ssn"), resultRefused},
		{"a SECRET column named twice", unchecked, row(secretOld, "pin", "pin"), resultRefused},
		{"a SECRET column with an empty name", unchecked, row(secretOld, ""), resultRefused},
		{"a line that is not redacted", `{"op": "DELETE", "key": {"id": 8}, "old": {"id": 8}, "set": null, "table": "public.leads", "cascaded": false}`, row(note), resultRefused},
		{"a row that is not three values", approvalLine(rowHashOf(`[{"id": 8}, null]`)), row(`[{"id": 8}, null]`), resultRefused},
		{"a row with a scalar value", approvalLine(rowHashOf(`[{"id": 8}, 5, null]`)), row(`[{"id": 8}, 5, null]`), resultRefused},
		{"a row that is not JSON", approvalLine(rowHashOf(`[{"id": 8}`)), row(`[{"id": 8}`), resultRefused},
		{
			"an empty secretColumns", approvalLine(rowHashOf(note)),
			json.RawMessage(`{"line": 0, "row": ` + string(noteJSON) + `, "secretColumns": []}`), resultRefused,
		},
		{"a line whose keys differ in case", strings.Replace(approvalLine(rowHashOf(note)), `"redacted"`, `"REDACTED"`, 1), row(note), resultRefused},
		{"a line whose rowHash key differs in case", strings.Replace(approvalLine(rowHashOf(note)), `"rowHash"`, `"RowHash"`, 1), row(note), resultRefused},
	}
	return v
}

// TestRevealVectors keeps testdata/reveal.json in step with the Go codec.
// Run with -update after a deliberate change, then rerun the pages' tests.
func TestRevealVectors(t *testing.T) {
	t.Parallel()
	v := buildRevealVectors(t)
	got, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')
	if *update {
		require.NoError(t, os.WriteFile(revealFile, got, 0o600))
	}
	want, err := os.ReadFile(revealFile)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "run go test ./internal/core/approval -update")
}

func TestCheckRevealedRow(t *testing.T) {
	t.Parallel()
	for _, c := range buildRevealVectors(t).Rows {
		checked, err := approval.CheckRevealedRow(c.Line, decodeRow(t, c.Row))
		switch c.Result {
		case resultRefused:
			require.ErrorIs(t, err, approval.ErrInvalid, c.Name)
		case resultChecked:
			require.NoError(t, err, c.Name)
			require.True(t, checked, c.Name)
		case resultUnverified:
			require.NoError(t, err, c.Name)
			require.False(t, checked, c.Name, "a row with SECRET columns is never checked")
		}
	}
}

// decodeRow decodes a vector's row strictly, as the engine's answer is
// read: unknown or miscased keys are refused.
func decodeRow(t *testing.T, raw json.RawMessage) approval.RevealedRow {
	t.Helper()
	var r approval.RevealedRow
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&r))
	return r
}

func TestCheckRevealAnswer(t *testing.T) {
	t.Parallel()
	note := `[{"id": 8}, {"id": 8, "body": "x"}, null]`
	visible := `{"op": "DELETE", "key": {"id": 4}, "old": {"id": 4}, "set": null, "table": "public.leads", "cascaded": false}`
	lines := []string{approvalLine(rowHashOf(note)), visible, approvalLine(rowHashOf(note))}
	ok := approval.RevealedRow{Line: 0, Row: note}
	second := approval.RevealedRow{Line: 2, Row: note}

	checked, err := approval.CheckRevealAnswer(lines, approval.RevealAnswer{Rows: []approval.RevealedRow{ok, second}})
	require.NoError(t, err)
	require.Equal(t, []bool{true, true}, checked)

	for name, rows := range map[string][]approval.RevealedRow{
		"a line out of range":    {{Line: 3, Row: note}},
		"a negative line":        {{Line: -1, Row: note}},
		"a line that is visible": {{Line: 1, Row: note}},
		"a line twice":           {ok, ok},
		"lines out of order":     {second, ok},
		"a row that fails":       {{Line: 0, Row: `[{"id": 9}, {"id": 9, "body": "x"}, null]`}},
	} {
		_, err := approval.CheckRevealAnswer(lines, approval.RevealAnswer{Rows: rows})
		require.ErrorIs(t, err, approval.ErrInvalid, name)
	}
}

// The engine's request carries revealNonce only when it has one.
func TestRequestRevealNonce(t *testing.T) {
	t.Parallel()
	r := approval.Request{ApprovalID: revealID, Binding: "{}", Lines: []string{"x"}}
	out, err := json.Marshal(r)
	require.NoError(t, err)
	require.NotContains(t, string(out), "revealNonce")
	r.RevealNonce = counting(100)
	out, err = json.Marshal(r)
	require.NoError(t, err)
	require.Contains(t, string(out), `"revealNonce":"ZGVmZ2hpamtsbW5vcHFycw"`)
	var back approval.Request
	require.NoError(t, json.Unmarshal(out, &back))
	require.Equal(t, r.RevealNonce, back.RevealNonce)
}

// A long link never carries revealNonce: only the engine serves it. The
// Go parser refuses it as the pages do.
func TestParseRequestRefusesRevealNonce(t *testing.T) {
	t.Parallel()
	lines := previewLines()
	req := approval.Request{ApprovalID: approvalID, Binding: bindingText(lines), Lines: lines}
	frag, err := linkcodectest.Encode(linkcodec.Format1, req)
	require.NoError(t, err)
	_, _, err = approvaltest.ParseRequest(frag)
	require.NoError(t, err)
	for name, bad := range map[string]approval.Request{
		"revealNonce": {ApprovalID: req.ApprovalID, Binding: req.Binding, Lines: lines, RevealNonce: counting(100)},
		"columns":     {ApprovalID: req.ApprovalID, Binding: req.Binding, Lines: lines, Columns: approval.ColumnOrder{"public.leads": {"id"}}},
	} {
		frag, err = linkcodectest.Encode(linkcodec.Format1, bad)
		require.NoError(t, err)
		_, _, err = approvaltest.ParseRequest(frag)
		require.ErrorIs(t, err, approval.ErrInvalid, name)
	}
}

// A link that names columns at all is refused, an empty or null one too.
func TestParseRequestRefusesEmptyColumns(t *testing.T) {
	t.Parallel()
	lines := previewLines()
	for _, columns := range []any{nil, map[string]any{}, []any{}} {
		frag, err := linkcodectest.Encode(linkcodec.Format1, map[string]any{
			"approvalId": approvalID, "binding": bindingText(lines), "lines": lines, "columns": columns,
		})
		require.NoError(t, err)
		_, _, err = approvaltest.ParseRequest(frag)
		require.ErrorIs(t, err, approval.ErrInvalid, "%v", columns)
	}
}
