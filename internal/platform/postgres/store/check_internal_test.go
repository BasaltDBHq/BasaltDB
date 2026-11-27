package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgstatement"
)

// The policy's refusal reasons are contract enums: action lists the same
// strings, so a refusal keeps its reason through the store's check.
func TestRefusalReasonsMatchThePolicy(t *testing.T) {
	t.Parallel()
	for policy, neutral := range map[pgstatement.Reason]action.RefusalReason{
		pgstatement.ReasonParseError:         action.ReasonParseError,
		pgstatement.ReasonMultipleStatements: action.ReasonMultipleStatements,
		pgstatement.ReasonWrongTool:          action.ReasonWrongTool,
		pgstatement.ReasonDDL:                action.ReasonDDL,
		pgstatement.ReasonUtility:            action.ReasonUtility,
		pgstatement.ReasonSelectInto:         action.ReasonSelectInto,
		pgstatement.ReasonLockingRead:        action.ReasonLockingRead,
		pgstatement.ReasonMerge:              action.ReasonMerge,
		pgstatement.ReasonDataModifyingWith:  action.ReasonDataModifyingWith,
		pgstatement.ReasonFunction:           action.ReasonFunction,
		pgstatement.ReasonNotRepeatable:      action.ReasonNotRepeatable,
	} {
		require.Equal(t, string(policy), string(neutral))
	}
	_, err := Check("DROP TABLE t", action.ToolWrite)
	var re *action.RefusalError
	require.ErrorAs(t, err, &re)
	require.Equal(t, action.ReasonDDL, re.Reason)
}
