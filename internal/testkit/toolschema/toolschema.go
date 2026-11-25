// Package toolschema checks a tool's answer against the outputSchema of its
// contract file (api/mcp/tools/<tool>.json) with a full JSON Schema
// validator, so a closed schema refuses a field the contract does not name.
package toolschema

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/testkit/contractdoc"
)

// Output is the compiled outputSchema of tool. Its references resolve as
// in the tool's file, so ../values/... reads the contract's value schemas.
func Output(t *testing.T, tool string) *jsonschema.Schema {
	t.Helper()
	root, err := contractdoc.Root()
	require.NoError(t, err)
	dir := filepath.Join(root, "api", "mcp", "tools")
	raw, err := os.ReadFile(filepath.Join(dir, tool+".json"))
	require.NoError(t, err)
	var file struct {
		OutputSchema json.RawMessage `json:"outputSchema"`
	}
	require.NoError(t, json.Unmarshal(raw, &file))
	require.NotEmpty(t, file.OutputSchema, "%s has an outputSchema", tool)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(file.OutputSchema))
	require.NoError(t, err)
	// The outputSchema is its own document: its #/$defs are its own.
	id := "file://" + filepath.ToSlash(filepath.Join(dir, tool+".output.json"))
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseRegexpEngine(goRegexp)
	require.NoError(t, c.AddResource(id, doc))
	sch, err := c.Compile(id)
	require.NoError(t, err)
	return sch
}

// ecmaEscape is an ECMA-262 \uXXXX escape, which Go's regexp spells
// \x{XXXX}; longRepeat is a repeat bound over Go's limit of 1000.
var (
	ecmaEscape = regexp.MustCompile(`\\u([0-9A-Fa-f]{4})`)
	longRepeat = regexp.MustCompile(`\{([0-9]+),([0-9]{4,})\}`)
)

// goRegexp compiles a schema's ECMA-262 pattern with Go's regexp. A repeat
// bound over 1000 becomes open ({m,}): the contract's own tests check those
// lengths, and this package checks the fields an answer carries.
func goRegexp(s string) (jsonschema.Regexp, error) {
	s = ecmaEscape.ReplaceAllString(s, `\x{$1}`)
	s = longRepeat.ReplaceAllString(s, `{$1,}`)
	return regexp.Compile(s)
}

// Validate checks v, encoded as JSON, against sch.
func Validate(t *testing.T, sch *jsonschema.Schema, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	require.NoError(t, err)
	require.NoError(t, sch.Validate(inst), string(raw))
}

// Refuses checks that sch refuses v, encoded as JSON.
func Refuses(t *testing.T, sch *jsonschema.Schema, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	require.NoError(t, err)
	require.Error(t, sch.Validate(inst), string(raw))
}
