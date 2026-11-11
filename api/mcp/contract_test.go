package mcpcontract_test

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
)

var (
	camelCase     = regexp.MustCompile(`^[a-z][a-zA-Z0-9]*$`)
	screamingCase = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	toolName      = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	errorCodeRow  = regexp.MustCompile("^\\| `([A-Z][A-Z0-9_]*)` \\|")
	milestones    = map[string]bool{"M1": true, "M1.5": true, "M2": true, "M3": true, "M4.1": true}
)

// contractErrorCodes reads the codes from CONTRACT.md's "Error codes" table,
// so a tool cannot declare a code the contract does not define.
func contractErrorCodes(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile("../../CONTRACT.md")
	require.NoError(t, err)
	codes := map[string]bool{}
	inSection := false
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.HasPrefix(line, "## ") {
			inSection = line == "## Error codes"
			continue
		}
		if m := errorCodeRow.FindStringSubmatch(line); inSection && m != nil {
			codes[m[1]] = true
		}
	}
	require.NotEmpty(t, codes, "no error codes found in CONTRACT.md")
	return codes
}

func TestToolContracts(t *testing.T) {
	t.Parallel()
	tools, err := mcpcontract.Load()
	require.NoError(t, err)
	require.NotEmpty(t, tools)
	codes := contractErrorCodes(t)

	for _, tool := range tools {
		t.Run(tool.Name, func(t *testing.T) {
			t.Parallel()
			require.Regexp(t, toolName, tool.Name)
			require.Equal(t, tool.Name+".json", path.Base(tool.File), "file name must match the tool name")
			require.Contains(t, []string{mcpcontract.StatusImplemented, mcpcontract.StatusPlanned}, tool.Status)
			require.True(t, milestones[tool.Milestone], "unknown milestone %q", tool.Milestone)
			require.NotEmpty(t, tool.Description)

			requireClosedObject(t, "inputSchema", tool.InputSchema)
			require.NotNil(t, tool.OutputSchema, "outputSchema")
			walkSchema(t, "inputSchema", tool.InputSchema)
			walkSchema(t, "outputSchema", tool.OutputSchema)

			require.Contains(t, tool.Errors, "INVALID_ARGUMENT", "every tool validates its arguments")
			for _, code := range tool.Errors {
				require.True(t, codes[code], "error code %s is not in CONTRACT.md", code)
			}
		})
	}
}

func TestM1ToolsHaveContracts(t *testing.T) {
	t.Parallel()
	tools := mcpcontract.MustLoad()
	for _, name := range []string{"run_start", "query", "write", "run_history"} {
		tool, ok := mcpcontract.Find(tools, name)
		require.True(t, ok, name)
		require.Equal(t, "M1", tool.Milestone, name)
	}
}

func TestM2ToolsHaveContracts(t *testing.T) {
	t.Parallel()
	tool, ok := mcpcontract.Find(mcpcontract.MustLoad(), "list_pending")
	require.True(t, ok)
	require.Equal(t, "M2", tool.Milestone)
}

func TestM3ToolsHaveContracts(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"preview_revert", "revert_plan", "apply_revert_batch"} {
		tool, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
		require.True(t, ok, name)
		require.Equal(t, "M3", tool.Milestone, name)
	}
}

// TestApprovalSchemas checks the approval-flow payload schemas follow the
// wire rules (CONTRACT.md, Approvals): camelCase properties, SCREAMING_SNAKE_CASE
// enums, closed objects.
// TestAgentRevertToolsHaveContracts: agent-assisted revert (owner
// decisions N12-R1 to N12-R9) lands contract first, so both tools are
// PLANNED until the engine serves them.
func TestAgentRevertToolsHaveContracts(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"list_runs", "request_revert"} {
		tool, ok := mcpcontract.Find(mcpcontract.MustLoad(), name)
		require.True(t, ok, name)
		require.Equal(t, "M4.1", tool.Milestone, name)
		require.Equal(t, mcpcontract.StatusPlanned, tool.Status, name)
	}
	// N12-R7, N12-R8: an agent requests reverts of its own changes or runs
	// only (no task scope), and may deliver the person's signed code.
	tool, ok := mcpcontract.Find(mcpcontract.MustLoad(), "request_revert")
	require.True(t, ok)
	props, ok := tool.InputSchema["properties"].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, props, "taskId")
	require.Contains(t, props, "signature")
}

func TestApprovalSchemas(t *testing.T) {
	t.Parallel()
	checkPayloadSchemas(t, "approval", []string{
		"approval-request.schema.json", "approval-response.schema.json", "binding.schema.json",
		"preview-line.schema.json", "registration-request.schema.json", "registration-response.schema.json",
	})
}

// TestRevertSchemas checks the revert-flow payload schemas (CONTRACT.md,
// Revert) follow the same wire rules.
func TestRevertSchemas(t *testing.T) {
	t.Parallel()
	checkPayloadSchemas(t, "revert", []string{
		"revert-binding.schema.json", "revert-line.schema.json",
		"revert-request.schema.json", "revert-response.schema.json",
	})
}

// checkPayloadSchemas checks dir holds exactly the named schema files and that
// each has an $id and a description, camelCase properties, SCREAMING_SNAKE_CASE
// enums and closed objects.
func checkPayloadSchemas(t *testing.T, dir string, want []string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.schema.json"))
	require.NoError(t, err)
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	require.ElementsMatch(t, want, names)
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(f)
			require.NoError(t, err)
			var schema map[string]any
			require.NoError(t, json.Unmarshal(raw, &schema))
			require.NotEmpty(t, schema["$id"])
			require.NotEmpty(t, schema["description"])
			walkSchema(t, f, schema)
			requireObjectsClosed(t, f, schema)
		})
	}
}

// requireObjectsClosed checks every object schema that declares properties
// also sets additionalProperties: false.
func requireObjectsClosed(t *testing.T, where string, node any) {
	t.Helper()
	switch v := node.(type) {
	case map[string]any:
		if _, ok := v["properties"].(map[string]any); ok {
			require.Equal(t, false, v["additionalProperties"], "%s must set additionalProperties: false", where)
		}
		for k, child := range v {
			if k == "properties" {
				for name, prop := range child.(map[string]any) {
					requireObjectsClosed(t, where+"."+name, prop)
				}
				continue
			}
			requireObjectsClosed(t, where+"."+k, child)
		}
	case []any:
		for _, child := range v {
			requireObjectsClosed(t, where, child)
		}
	}
}

// TestErrorSchemas checks the error body, next step and warning schemas
// (CONTRACT.md, Next steps) follow the same wire rules.
func TestErrorSchemas(t *testing.T) {
	t.Parallel()
	checkPayloadSchemas(t, "errors", []string{
		"next-step.schema.json", "tool-error.schema.json", "warning.schema.json",
	})
}

// TestErrorBodyCodes checks the error body schema's code enum is exactly the
// codes of CONTRACT.md's "Error codes" table.
func TestErrorBodyCodes(t *testing.T) {
	t.Parallel()
	schema := readJSON(t, "errors/tool-error.schema.json")
	props, ok := schema["properties"].(map[string]any)
	require.True(t, ok)
	code, ok := props["code"].(map[string]any)
	require.True(t, ok)
	enum, ok := code["enum"].([]any)
	require.True(t, ok)
	got := map[string]bool{}
	for _, c := range enum {
		s, ok := c.(string)
		require.True(t, ok)
		got[s] = true
	}
	require.Equal(t, contractErrorCodes(t), got)
}

// TestNextStepActions checks the next step schema's action enum is exactly
// the actions ActorActions allows.
func TestNextStepActions(t *testing.T) {
	t.Parallel()
	schema := readJSON(t, "errors/next-step.schema.json")
	props, ok := schema["properties"].(map[string]any)
	require.True(t, ok)
	action, ok := props["action"].(map[string]any)
	require.True(t, ok)
	enum, ok := action["enum"].([]any)
	require.True(t, ok)
	want := []any{}
	for _, actor := range []string{mcpcontract.ActorAgent, mcpcontract.ActorPerson} {
		for _, a := range mcpcontract.ActorActions[actor] {
			want = append(want, a)
		}
	}
	require.ElementsMatch(t, want, enum)
}

// TestNextStepsCatalog checks every error code has next steps, every step
// pairs an actor with one of its actions, entries are unique, and the
// catalog matches CONTRACT.md's "Next steps per code" tables.
func TestNextStepsCatalog(t *testing.T) {
	t.Parallel()
	catalog, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	tools := mcpcontract.MustLoad()

	codes := contractErrorCodes(t)
	covered := map[string]bool{}
	errorKeys := map[string]bool{}
	for _, e := range catalog.Errors {
		key := e.Code + "/" + e.Reason + "/" + e.Tool
		require.False(t, errorKeys[key], "duplicate catalog entry %s", key)
		errorKeys[key] = true
		require.True(t, codes[e.Code], "catalog code %s is not in CONTRACT.md", e.Code)
		if e.Reason != "" {
			require.Regexp(t, screamingCase, e.Reason, key)
		}
		if e.Tool != "" {
			tool, ok := mcpcontract.Find(tools, e.Tool)
			require.True(t, ok, "%s: unknown tool", key)
			require.Contains(t, tool.Errors, e.Code, "%s: the tool does not declare the code", key)
		}
		requireSteps(t, key, e.Steps)
		covered[e.Code] = true
	}
	for code := range codes {
		require.True(t, covered[code], "error code %s has no next steps in api/mcp/errors/next-steps.json", code)
	}

	resultKeys := map[string]bool{}
	for _, r := range catalog.Results {
		key := r.Tool + "/" + r.Case
		require.False(t, resultKeys[key], "duplicate catalog entry %s", key)
		resultKeys[key] = true
		_, ok := mcpcontract.Find(tools, r.Tool)
		require.True(t, ok, "%s: unknown tool", key)
		require.Regexp(t, screamingCase, r.Case, key)
		requireSteps(t, key, r.Steps)
	}
	for _, w := range catalog.Warnings {
		resultKeys[w.Code+"/"] = true
		require.Regexp(t, screamingCase, w.Code)
		requireSteps(t, w.Code, w.Steps)
	}

	docErrors, docResults := contractNextSteps(t)
	require.Equal(t, errorKeys, docErrors, "CONTRACT.md \"Next steps per code\" and next-steps.json differ")
	require.Equal(t, resultKeys, docResults, "CONTRACT.md results and warnings table and next-steps.json differ")
}

// TestNextStepsEntry checks a tool's own entry wins over the entry for every
// tool, and the entry for every tool is the fallback.
func TestNextStepsEntry(t *testing.T) {
	t.Parallel()
	catalog, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)

	own, ok := catalog.ErrorEntry("QUERY_TIMEOUT", "TIME_LIMIT", "preview_revert")
	require.True(t, ok)
	require.Equal(t, "preview_revert", own.Tool)

	general, ok := catalog.ErrorEntry("QUERY_TIMEOUT", "TIME_LIMIT", "query")
	require.True(t, ok)
	require.Empty(t, general.Tool)

	_, ok = catalog.ErrorEntry("QUERY_TIMEOUT", "NO_SUCH_REASON", "query")
	require.False(t, ok)
}

// TestToolSchemaRefs checks every file $ref in a tool contract names a
// schema file that exists (refs inside the file, "#/...", are skipped).
func TestToolSchemaRefs(t *testing.T) {
	t.Parallel()
	for _, tool := range mcpcontract.MustLoad() {
		raw, err := os.ReadFile(tool.File)
		require.NoError(t, err)
		var schema any
		require.NoError(t, json.Unmarshal(raw, &schema))
		for _, ref := range schemaRefs(schema) {
			_, err := os.Stat(filepath.Join(filepath.Dir(tool.File), ref))
			require.NoError(t, err, "%s: $ref %s", tool.Name, ref)
		}
	}
}

func requireSteps(t *testing.T, where string, steps []mcpcontract.StepKind) {
	t.Helper()
	require.NotEmpty(t, steps, "%s has no steps", where)
	for _, s := range steps {
		actions, ok := mcpcontract.ActorActions[s.Actor]
		require.True(t, ok, "%s: unknown actor %q", where, s.Actor)
		require.Contains(t, actions, s.Action, "%s: %s cannot %s", where, s.Actor, s.Action)
	}
}

var (
	nextStepsErrorRow  = regexp.MustCompile("^\\| `([A-Z][A-Z0-9_]*)` \\| (?:`([A-Z][A-Z0-9_]*)`|—) \\| (?:`([a-z_]+)`|—) \\|")
	nextStepsResultRow = regexp.MustCompile("^\\| `([a-z_]+)`(?: item)? \\| `([A-Z][A-Z0-9_]*)`")
	nextStepsWarnRow   = regexp.MustCompile("^\\| `([A-Z][A-Z0-9_]*)` \\| — \\|")
)

// contractNextSteps reads the keys of CONTRACT.md's "Next steps per code"
// tables: code/reason/tool for errors, tool/case for results and code/ for
// warnings.
func contractNextSteps(t *testing.T) (map[string]bool, map[string]bool) {
	t.Helper()
	raw, err := os.ReadFile("../../CONTRACT.md")
	require.NoError(t, err)
	errs, results := map[string]bool{}, map[string]bool{}
	inSection, inResults := false, false
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.HasPrefix(line, "#") {
			inSection = line == "### Next steps per code"
			continue
		}
		if !inSection {
			continue
		}
		if strings.HasPrefix(line, "Results and warnings") {
			inResults = true
			continue
		}
		if !inResults {
			if m := nextStepsErrorRow.FindStringSubmatch(line); m != nil {
				errs[m[1]+"/"+m[2]+"/"+m[3]] = true
			}
			continue
		}
		if m := nextStepsResultRow.FindStringSubmatch(line); m != nil {
			results[m[1]+"/"+m[2]] = true
			continue
		}
		if m := nextStepsWarnRow.FindStringSubmatch(line); m != nil {
			results[m[1]+"/"] = true
		}
	}
	require.NotEmpty(t, errs, "no next steps found in CONTRACT.md")
	require.NotEmpty(t, results, "no result next steps found in CONTRACT.md")
	return errs, results
}

// schemaRefs returns every $ref value in a schema, at any depth.
func schemaRefs(node any) []string {
	var refs []string
	switch v := node.(type) {
	case map[string]any:
		if ref, ok := v["$ref"].(string); ok && !strings.HasPrefix(ref, "#") {
			refs = append(refs, ref)
		}
		for _, child := range v {
			refs = append(refs, schemaRefs(child)...)
		}
	case []any:
		for _, child := range v {
			refs = append(refs, schemaRefs(child)...)
		}
	}
	return refs
}

func readJSON(t *testing.T, file string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	var v map[string]any
	require.NoError(t, json.Unmarshal(raw, &v))
	return v
}

func TestCheckServed(t *testing.T) {
	t.Parallel()
	tools := []mcpcontract.Tool{
		{Name: "done", Status: mcpcontract.StatusImplemented},
		{Name: "later", Status: mcpcontract.StatusPlanned},
	}
	require.NoError(t, mcpcontract.CheckServed(tools, []string{"done"}))
	require.NoError(t, mcpcontract.CheckServed(tools, []string{"done", "later"}))

	err := mcpcontract.CheckServed(tools, nil)
	require.ErrorContains(t, err, `"done" is IMPLEMENTED but not served`)

	err = mcpcontract.CheckServed(tools, []string{"done", "rogue"})
	require.ErrorContains(t, err, `"rogue" is served but has no contract`)
}

func TestCheckServedNoToolsYet(t *testing.T) {
	t.Parallel()
	// Until a tool is IMPLEMENTED, a server with no tools matches the contract.
	tools := mcpcontract.MustLoad()
	served := []string{}
	for _, tool := range tools {
		if tool.Status == mcpcontract.StatusImplemented {
			served = append(served, tool.Name)
		}
	}
	require.NoError(t, mcpcontract.CheckServed(tools, served))
}

// requireClosedObject checks an input schema rejects unknown arguments and
// lists only declared properties as required.
func requireClosedObject(t *testing.T, where string, schema map[string]any) {
	t.Helper()
	require.Equal(t, "object", schema["type"], where)
	require.Equal(t, false, schema["additionalProperties"], "%s must set additionalProperties: false", where)
	props, ok := schema["properties"].(map[string]any)
	require.True(t, ok, "%s.properties", where)
	required, _ := schema["required"].([]any)
	for _, r := range required {
		name, ok := r.(string)
		require.True(t, ok, "%s.required entries are strings", where)
		require.Contains(t, props, name, "%s requires undeclared %q", where, name)
	}
}

// walkSchema checks every property name is camelCase and every enum value is
// SCREAMING_SNAKE_CASE, at any depth.
func walkSchema(t *testing.T, where string, node any) {
	t.Helper()
	switch v := node.(type) {
	case map[string]any:
		if props, ok := v["properties"].(map[string]any); ok {
			for name := range props {
				require.Regexp(t, camelCase, name, "%s: property %q is not camelCase", where, name)
			}
		}
		if enum, ok := v["enum"].([]any); ok {
			for _, e := range enum {
				s, ok := e.(string)
				require.True(t, ok, "%s: enum values are strings", where)
				require.Regexp(t, screamingCase, s, "%s: enum value %q is not SCREAMING_SNAKE_CASE", where, s)
			}
		}
		for k, child := range v {
			walkSchema(t, where+"."+k, child)
		}
	case []any:
		for _, child := range v {
			walkSchema(t, where, child)
		}
	}
}
