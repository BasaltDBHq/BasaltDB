package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// The statement check refuses with the store-neutral reasons: a refusal
// reaches the service as an *action.RefusalError.
func TestCheckRefusesWithTheActionReason(t *testing.T) {
	t.Parallel()
	stmt, err := (&Store{}).Check("DROP TABLE t", action.ToolWrite)
	var re *action.RefusalError
	require.ErrorAs(t, err, &re)
	require.Equal(t, action.ReasonDDL, re.Reason)
	require.Equal(t, action.OpOther, stmt.Op)
}
