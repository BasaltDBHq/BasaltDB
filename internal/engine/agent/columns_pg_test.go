package agent_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// The pages' GET requests carry each table's columns in table order
// (attnum), unsigned and for display only, and the approval the agent's
// config name. jsonb reorders a row's keys (leads: id, name, score,
// status), so only this map gives the page the table's order. A table the
// agent cannot read is listed too: its column names are in pg_attribute,
// which the agent role reads itself.
func TestPagesRequestsCarryTheColumnOrder(t *testing.T) {
	t.Parallel()
	s := newRevealSetup(t)
	want := map[string][]string{
		"public.leads":      {"id", "name", "status", "score"},
		"public.lead_notes": {"id", "lead_id", "note"},
		"public.note_tags":  {"id", "note_id", "tag"},
	}

	// Lead 20 has notes and no tags; lead 5's revert restores its tags too.
	req, b := s.approvalRequest(t)
	require.Equal(t, map[string][]string{"public.leads": want["public.leads"], "public.lead_notes": want["public.lead_notes"]}, req.Columns)
	require.Equal(t, "bot", req.AgentName)
	require.NotEqual(t, req.AgentName, b.Agent, "the binding signs the role")
	var line struct {
		Old json.RawMessage `json:"old"`
	}
	require.NoError(t, json.Unmarshal([]byte(req.Lines[0]), &line))
	require.Regexp(t, `"score": \d+, "status"`, string(line.Old), "the rows carry jsonb order, not the table's")

	rv, _ := s.revertRequest(t)
	require.Equal(t, want, rv.Columns)

	// Neither field is signed: the binding and the lines are the ones the
	// long link carries, which has neither.
	long, err := req.Fragment()
	require.NoError(t, err)
	require.NotContains(t, long, "columns")
}
