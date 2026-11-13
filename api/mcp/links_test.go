package mcpcontract_test

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
)

// shortSecretLen is the length of a short link's secret: 16 bytes in
// base64url without padding (CONTRACT.md, Link secrets).
const shortSecretLen = 22

var (
	encodedSpace = regexp.MustCompile(`(?i)%(20|09|0a|0d)`)
	pasteLines   = regexp.MustCompile("\r\n|\n|\r| ")
)

// TestLinkSchemas checks the link schema (CONTRACT.md, Showing links) follows
// the wire rules.
func TestLinkSchemas(t *testing.T) {
	t.Parallel()
	checkPayloadSchemas(t, "links", []string{"link.schema.json", "compact-request.schema.json"})
}

// TestLinksBesidePersonMessage checks every personMessage in the tool and
// error schemas has a links array of link.schema.json next to it
// (CONTRACT.md, Showing links). Its 500-character limit, which does not count
// URL lines, is checked by an engine test, not here.
func TestLinksBesidePersonMessage(t *testing.T) {
	t.Parallel()
	tools := mcpcontract.MustLoad()
	files := make([]string, 0, len(tools)+2)
	files = append(files, "errors/tool-error.schema.json", "errors/warning.schema.json")
	for _, tool := range tools {
		files = append(files, tool.File)
	}
	found := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		var schema any
		require.NoError(t, json.Unmarshal(raw, &schema))
		found += requireLinksBesidePersonMessage(t, f, schema)
	}
	require.Positive(t, found, "no personMessage found in the schemas")
}

func requireLinksBesidePersonMessage(t *testing.T, where string, node any) int {
	t.Helper()
	found := 0
	switch v := node.(type) {
	case map[string]any:
		if props, ok := v["properties"].(map[string]any); ok {
			if _, ok := props["personMessage"].(map[string]any); ok {
				found++
				links, ok := props["links"].(map[string]any)
				require.True(t, ok, "%s: personMessage needs links next to it", where)
				require.Equal(t, "array", links["type"], where)
				items, ok := links["items"].(map[string]any)
				require.True(t, ok, "%s: links.items", where)
				ref, _ := items["$ref"].(string)
				require.Equal(t, "link.schema.json", filepath.Base(ref), "%s: links.items", where)
				_, err := os.Stat(filepath.Join(filepath.Dir(where), ref))
				require.NoError(t, err, "%s: $ref %s", where, ref)
			}
		}
		for _, child := range v {
			found += requireLinksBesidePersonMessage(t, where, child)
		}
	case []any:
		for _, child := range v {
			found += requireLinksBesidePersonMessage(t, where, child)
		}
	}
	return found
}

type repairCase struct {
	Name  string  `json:"name"`
	Input string  `json:"input"`
	Want  *string `json:"want"`
}

type repairCases struct {
	Description string       `json:"description"`
	Fragments   []repairCase `json:"fragments"`
	Pastes      []repairCase `json:"pastes"`
}

// TestLinkRepairCases checks the shared cases the pages run against the rules
// of CONTRACT.md, Showing links, The pages repair what they can, written out
// here once so a case cannot drift from the rules.
func TestLinkRepairCases(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("links/link-repair.json")
	require.NoError(t, err)
	var c repairCases
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&c))
	require.NotEmpty(t, c.Fragments)
	require.NotEmpty(t, c.Pastes)

	names := map[string]bool{}
	for _, tc := range append(append([]repairCase{}, c.Fragments...), c.Pastes...) {
		require.False(t, names[tc.Name], "case names are unique: %q", tc.Name)
		names[tc.Name] = true
	}
	for _, tc := range c.Fragments {
		require.NotNil(t, tc.Want, "fragment case %q: want is a string", tc.Name)
		require.Equal(t, *tc.Want, repairFragment(tc.Input), "fragment case %q", tc.Name)
	}
	for _, tc := range c.Pastes {
		got, ok := linkFromPaste(tc.Input)
		if tc.Want == nil {
			require.False(t, ok, "paste case %q: no link", tc.Name)
			continue
		}
		require.True(t, ok, "paste case %q: a link", tc.Name)
		require.Equal(t, *tc.Want, got, "paste case %q", tc.Name)
	}
}

// repairFragment applies the fragment repair steps 2 to 4 to the text after
// the first #.
func repairFragment(f string) string {
	f = encodedSpace.ReplaceAllString(f, "")
	f = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '>' || r == '*' || r == '\\' {
			return -1
		}
		return r
	}, f)
	for _, prefix := range []string{"1.", "2."} {
		if rest, ok := strings.CutPrefix(f, prefix); ok {
			return prefix + base64urlRun(rest)
		}
	}
	if rest, ok := strings.CutPrefix(f, "s="); ok {
		if run := base64urlRun(rest); len(run) >= shortSecretLen {
			return "s=" + run[:shortSecretLen]
		}
	}
	return f
}

// linkFromPaste applies the paste steps: the first line holding a link, then
// the following lines of only base64url characters, up to an empty line.
func linkFromPaste(text string) (string, bool) {
	lines := pasteLines.Split(text, -1)
	for i := range lines {
		lines[i] = strings.TrimSpace(strings.NewReplacer(">", "", "*", "", "\\", "").Replace(lines[i]))
	}
	for i, line := range lines {
		start, prefix := firstLinkPrefix(line)
		if start < 0 {
			continue
		}
		rest := line[start+len(prefix):]
		run := base64urlRun(rest)
		if len(run) == len(rest) {
			for _, next := range lines[i+1:] {
				if next == "" || base64urlRun(next) != next {
					break
				}
				run += next
			}
		}
		if prefix == "#s=" && len(run) > shortSecretLen {
			run = run[:shortSecretLen]
		}
		return repairFragment(strings.TrimPrefix(prefix, "#") + run), true
	}
	return "", false
}

// firstLinkPrefix returns where the earliest of #1., #2. and #s= starts in
// line, and which it is; -1 when there is none.
func firstLinkPrefix(line string) (int, string) {
	start, prefix := -1, ""
	for _, p := range []string{"#1.", "#2.", "#s="} {
		if i := strings.Index(line, p); i >= 0 && (start < 0 || i < start) {
			start, prefix = i, p
		}
	}
	return start, prefix
}

// base64urlRun returns the leading base64url characters of s.
func base64urlRun(s string) string {
	end := strings.IndexFunc(s, func(r rune) bool { return !isBase64url(r) })
	if end < 0 {
		return s
	}
	return s[:end]
}

func isBase64url(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_'
}

type compactVector struct {
	Name     string          `json:"name"`
	Kind     string          `json:"kind"`
	Fragment string          `json:"fragment"`
	Payload  json.RawMessage `json:"payload"`
	Binding  string          `json:"binding"`
	Lines    []string        `json:"lines"`
	// CredentialIDs are the ids a valid vector's link carries, if any.
	CredentialIDs []string `json:"credentialIds,omitempty"`
}

type compactVectors struct {
	Description string          `json:"description"`
	Valid       []compactVector `json:"valid"`
	Invalid     []compactVector `json:"invalid"`
}

// TestCompactRequestVectors checks format 2's shared vectors (CONTRACT.md,
// Approvals, Format 2) against the parts of the format that need no
// rebuild: every valid fragment is 2. and the base64url of the deflate-raw
// of its payload, [shapes, texts] (with the credential ids third when it
// names any), and its lines hash to its
// binding's rowsHash. The codec's own tests (internal/linkcodec and the
// pages) rebuild every vector.
func TestCompactRequestVectors(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("links/compact-request.json")
	require.NoError(t, err)
	var c compactVectors
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&c))
	require.NotEmpty(t, c.Valid)
	require.NotEmpty(t, c.Invalid)

	names := map[string]bool{}
	for _, tc := range append(append([]compactVector{}, c.Valid...), c.Invalid...) {
		require.False(t, names[tc.Name], "vector names are unique: %q", tc.Name)
		names[tc.Name] = true
		require.Contains(t, []string{"APPROVE", "REVERT"}, tc.Kind, tc.Name)
		require.True(t, strings.HasPrefix(tc.Fragment, "2."), tc.Name)
	}
	for _, tc := range c.Valid {
		compressed, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(tc.Fragment, "2."))
		require.NoError(t, err, tc.Name)
		inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
		require.NoError(t, err, tc.Name)
		require.JSONEq(t, string(tc.Payload), string(inflated), tc.Name)

		var pair []json.RawMessage
		require.NoError(t, json.Unmarshal(tc.Payload, &pair), tc.Name)
		if len(tc.CredentialIDs) == 0 {
			require.Len(t, pair, 2, "%s: [shapes, texts]", tc.Name)
		} else {
			require.Len(t, pair, 3, "%s: [shapes, texts, credentialIds]", tc.Name)
			var ids []string
			require.NoError(t, json.Unmarshal(pair[2], &ids), tc.Name)
			require.Equal(t, tc.CredentialIDs, ids, tc.Name)
		}

		var binding struct {
			Kind     string `json:"kind"`
			RowsHash string `json:"rowsHash"`
		}
		require.NoError(t, json.Unmarshal([]byte(tc.Binding), &binding), tc.Name)
		require.Equal(t, tc.Kind, binding.Kind, tc.Name)
		sum := sha256.Sum256([]byte(strings.Join(tc.Lines, "\n")))
		require.Equal(t, binding.RowsHash, hex.EncodeToString(sum[:]), tc.Name)
	}
}
