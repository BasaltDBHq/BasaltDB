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
	milestones    = map[string]bool{"M1": true, "M1.5": true, "M2": true, "M3": true}
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
