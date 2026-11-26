package mcpcontract_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
)

// notLists are tools whose result has items but is not a page of a list,
// each with its reason. An entry that no longer has items fails.
var notLists = map[string]string{
	"apply_revert_batch": "items are the lines this batch applied, at most maxBatch; the plan itself is paged by revert_plan",
}

// listShapeFindings names the tools whose output has an items array but
// whose input lacks limit or cursor, or whose output lacks nextCursor.
func listShapeFindings(tools []mcpcontract.Tool) map[string][]string {
	out := map[string][]string{}
	for _, tool := range tools {
		outProps, _ := tool.OutputSchema["properties"].(map[string]any)
		items, _ := outProps["items"].(map[string]any)
		if items == nil || items["type"] != "array" {
			continue
		}
		inProps, _ := tool.InputSchema["properties"].(map[string]any)
		var missing []string
		for _, in := range []string{"limit", "cursor"} {
			if _, ok := inProps[in]; !ok {
				missing = append(missing, "input "+in)
			}
		}
		if _, ok := outProps["nextCursor"]; !ok {
			missing = append(missing, "output nextCursor")
		}
		out[tool.Name] = missing
	}
	return out
}

// TestListToolsArePaged holds every list tool to the list rules: a tool
// that returns items takes limit and cursor and returns nextCursor.
func TestListToolsArePaged(t *testing.T) {
	t.Parallel()
	tools, err := mcpcontract.LoadAll()
	require.NoError(t, err)
	findings := listShapeFindings(tools)
	require.NotEmpty(t, findings, "no tool returns items: the rule checks nothing")
	for _, name := range slices.Sorted(maps.Keys(findings)) {
		missing := findings[name]
		if _, ok := notLists[name]; ok {
			require.NotEmpty(t, missing, "%s is paged now: remove it from notLists", name)
			continue
		}
		require.Empty(t, missing, "%s returns items, so it is a list: it takes limit and cursor and returns nextCursor", name)
	}
	for name, reason := range notLists {
		require.NotEmpty(t, reason, "notLists entry %s has no reason", name)
		require.Contains(t, findings, name, "notLists entry %s returns no items: remove it", name)
	}
}

func TestListShapeCatchesAnUnpagedList(t *testing.T) {
	t.Parallel()
	obj := func(props ...string) map[string]any {
		p := map[string]any{}
		for _, k := range props {
			p[k] = map[string]any{"type": "string"}
		}
		if slices.Contains(props, "items") {
			p["items"] = map[string]any{"type": "array"}
		}
		return map[string]any{"type": "object", "properties": p}
	}
	got := listShapeFindings([]mcpcontract.Tool{
		{Name: "paged", InputSchema: obj("limit", "cursor"), OutputSchema: obj("items", "nextCursor")},
		{Name: "unpaged", InputSchema: obj("cursor"), OutputSchema: obj("items")},
		{Name: "single", InputSchema: obj(), OutputSchema: obj("runId")},
	})
	require.Equal(t, map[string][]string{
		"paged":   nil,
		"unpaged": {"input limit", "output nextCursor"},
	}, got)
}
