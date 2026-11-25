package store

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
)

// A held request re-runs as the binding carries it: the statement as
// signed, the op the SQL policy reads from it, and parameters with numbers
// kept exact, as the write tool decodes them.
func TestHeldStatementReadsTheBindingsRequest(t *testing.T) {
	t.Parallel()
	const sql = "DELETE FROM public.leads WHERE id = $1 AND score = $2 AND note = $3"
	run, err := heldStatement(approval.HeldRequest{
		Kind: approval.RequestSQL, Statement: sql,
		Params: []json.RawMessage{json.RawMessage(`12345678901234567890`), json.RawMessage(`1.50`), json.RawMessage(`"left"`)},
	})
	require.NoError(t, err)
	require.Equal(t, action.OpDelete, run.op)
	require.Equal(t, sql, run.sql)
	require.Equal(t, []any{json.Number("12345678901234567890"), json.Number("1.50"), "left"}, run.params)

	run, err = heldStatement(approval.HeldRequest{Kind: approval.RequestSQL, Statement: "UPDATE public.leads SET status = 'gone'"})
	require.NoError(t, err)
	require.Equal(t, action.OpUpdate, run.op)
	require.Equal(t, []any{}, run.params, "no parameters")
}

// A held statement the SQL policy no longer passes, or a parameter that
// does not decode, keeps the error the reveal gave before.
func TestHeldStatementRefusals(t *testing.T) {
	t.Parallel()
	_, err := heldStatement(approval.HeldRequest{Kind: approval.RequestSQL, Statement: "DROP TABLE public.leads"})
	require.ErrorContains(t, err, "the held statement no longer parses: ")
	var re *action.RefusalError
	require.ErrorAs(t, err, &re, "the policy's refusal is wrapped")

	_, err = heldStatement(approval.HeldRequest{
		Kind: approval.RequestSQL, Statement: "DELETE FROM public.leads WHERE id = $1", Params: []json.RawMessage{json.RawMessage(`{`)},
	})
	require.ErrorContains(t, err, "a held parameter: ")
}
