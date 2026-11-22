package postgres

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
)

// The policy's refusal reasons are contract enums: action lists the same
// strings, so a refusal keeps its reason through the store's check.
func TestRefusalReasonsMatchThePolicy(t *testing.T) {
	t.Parallel()
	for policy, neutral := range map[sqlguard.Reason]action.RefusalReason{
		sqlguard.ReasonParseError:         action.ReasonParseError,
		sqlguard.ReasonMultipleStatements: action.ReasonMultipleStatements,
		sqlguard.ReasonWrongTool:          action.ReasonWrongTool,
		sqlguard.ReasonDDL:                action.ReasonDDL,
		sqlguard.ReasonUtility:            action.ReasonUtility,
		sqlguard.ReasonSelectInto:         action.ReasonSelectInto,
		sqlguard.ReasonLockingRead:        action.ReasonLockingRead,
		sqlguard.ReasonMerge:              action.ReasonMerge,
		sqlguard.ReasonDataModifyingWith:  action.ReasonDataModifyingWith,
		sqlguard.ReasonFunction:           action.ReasonFunction,
		sqlguard.ReasonNotRepeatable:      action.ReasonNotRepeatable,
	} {
		require.Equal(t, string(policy), string(neutral))
	}
	_, err := Check("DROP TABLE t", action.ToolWrite)
	var re *action.RefusalError
	require.ErrorAs(t, err, &re)
	require.Equal(t, action.ReasonDDL, re.Reason)
}
