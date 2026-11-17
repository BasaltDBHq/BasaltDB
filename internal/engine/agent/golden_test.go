package agent_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// updateGolden rewrites every golden file the tests compare with
// (testdata/describe, testdata/served, testdata/ledger).
var updateGolden = flag.Bool("update", false, "rewrite the golden files under testdata/")

// goldenNormal replaces what changes from run to run (the database name,
// fingerprints, scan counters and sizes) so the answers can be compared.
func goldenNormal(v any, key string) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = goldenNormal(val, k)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = goldenNormal(val, key)
		}
		return out
	}
	switch key {
	case "database", "fingerprint", "tableBytes", "totalBytes", "seqScans", "indexScans", "lastAnalyzed", "sizeBytes", "scans":
		return "<" + key + ">"
	}
	return v
}

// requireGoldenFile compares v, encoded as indented JSON, with
// testdata/<dir>/<name>.json; -update rewrites the file.
func requireGoldenFile(t *testing.T, dir, name string, v any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(v))
	got := buf.Bytes()
	file := filepath.Join("testdata", dir, name+".json")
	if *updateGolden {
		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
		require.NoError(t, os.WriteFile(file, got, 0o600))
	}
	want, err := os.ReadFile(file)
	require.NoError(t, err, "run with -update to write %s", file)
	require.Equal(t, string(want), string(got), "%s (run with -update to rewrite)", file)
}

func requireGolden(t *testing.T, name string, body map[string]any) {
	t.Helper()
	requireGoldenFile(t, "describe", name, goldenNormal(body, ""))
}

var (
	goldenUUID     = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	goldenTime     = regexp.MustCompile(`\d{4}-\d\d-\d\d[T ]\d\d:\d\d(:\d\d(\.\d+)?)?(Z|[+-]\d\d(:\d\d)?| UTC)?`)
	goldenRole     = regexp.MustCompile(`\bbt[0-9a-f]{12}_`)
	goldenEngine   = regexp.MustCompile(`receipt from engine [^.]+\.`)
	goldenXmin     = regexp.MustCompile(`xmin[: ]\d+|now \d+\b`)
	goldenFragment = regexp.MustCompile(`#[^\s"'<>)]+`)
	// goldenBlob is a request's encoded body: a long run of base64url
	// characters that carries the binding and the person's challenge.
	goldenBlob = regexp.MustCompile(`^\d\.[A-Za-z0-9_.-]{100,}$`)
)

// goldenPlaceholders are keys whose value changes from run to run whatever
// it is: it is replaced by "<key>".
var goldenPlaceholders = map[string]bool{
	"durationMs": true, "database": true, "fingerprint": true, "hash": true, "rowsHash": true,
	"signature": true, "receipt": true, "approval": true, "code": false,
}

// runNormalizer replaces what differs from one run to the next in a served
// body: ids by numbers in order of first appearance (so which ids are the
// same stays visible), timestamps, xmin values, link secrets (a link's
// fragment) and the keys in goldenPlaceholders.
type runNormalizer struct{ ids map[string]int }

func newRunNormalizer() *runNormalizer { return &runNormalizer{ids: map[string]int{}} }

func (n *runNormalizer) text(s string) string {
	if strings.HasPrefix(s, "basalt-request ") {
		return "<request block>"
	}
	if goldenBlob.MatchString(s) {
		return "<request text>"
	}
	s = goldenFragment.ReplaceAllString(s, "#<fragment>")
	s = goldenUUID.ReplaceAllStringFunc(s, func(id string) string {
		k, ok := n.ids[id]
		if !ok {
			k = len(n.ids) + 1
			n.ids[id] = k
		}
		return fmt.Sprintf("<id-%d>", k)
	})
	s = goldenEngine.ReplaceAllString(s, "receipt from engine <engine>.")
	s = goldenRole.ReplaceAllString(s, "<prefix>_")
	s = goldenTime.ReplaceAllString(s, "<time>")
	return goldenXmin.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "now") {
			return "now <n>"
		}
		return m[:5] + "<n>"
	})
}

func (n *runNormalizer) walk(v any, key string) any {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(x))
		for _, k := range keys {
			out[k] = n.walk(x[k], k)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = n.walk(val, key)
		}
		return out
	case string:
		if goldenPlaceholders[key] {
			return "<" + key + ">"
		}
		return n.text(x)
	}
	if goldenPlaceholders[key] && v != nil {
		return "<" + key + ">"
	}
	return v
}

// servedGolden compares each step of a scenario with its golden file and
// remembers which (tool, error code) pairs the scenario reached.
type servedGolden struct {
	t     *testing.T
	dir   string
	h     harness
	norm  *runNormalizer
	steps int
	codes map[string]bool
	tools map[string]bool
}

func newServedGolden(t *testing.T, dir string, h harness) *servedGolden {
	t.Helper()
	return &servedGolden{t: t, dir: dir, h: h, norm: newRunNormalizer(), codes: map[string]bool{}, tools: map[string]bool{}}
}

// call runs one tool call and compares its result, as the agent sees it,
// with the golden file named after the step's number and name.
func (g *servedGolden) call(name, tool string, args any) map[string]any {
	g.t.Helper()
	body, isError := g.h.call(g.t, tool, args)
	g.steps++
	if isError {
		code, _ := body["code"].(string)
		g.codes[tool+" "+code] = true
	} else {
		g.tools[tool] = true
	}
	requireGoldenFile(g.t, g.dir, fmt.Sprintf("%02d_%s", g.steps, name), map[string]any{
		"tool": tool, "isError": isError, "body": g.norm.walk(body, ""),
	})
	return body
}

// callOK is call for a step that must succeed.
func (g *servedGolden) callOK(name, tool string, args any) map[string]any {
	g.t.Helper()
	body := g.call(name, tool, args)
	require.NotContains(g.t, body, "code", "%s: %v", name, body)
	return body
}

// callErr is call for a step that must fail with code.
func (g *servedGolden) callErr(name, tool string, args any, code string) map[string]any {
	g.t.Helper()
	body := g.call(name, tool, args)
	require.Equal(g.t, code, body["code"], "%s: %v", name, body)
	return body
}
