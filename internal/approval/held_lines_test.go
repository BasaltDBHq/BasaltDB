package approval

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// HoldTooLarge refuses lines over the cap and lets any lines within it
// through, however long one line is.
func TestHoldTooLarge(t *testing.T) {
	t.Parallel()
	require.Nil(t, HoldTooLarge(nil))
	require.Nil(t, HoldTooLarge([]string{strings.Repeat("x", 1000)}))
	require.Nil(t, HoldTooLarge([]string{strings.Repeat("x", 64<<10+1)}), "a line over 64 KiB is within the cap")
	require.Nil(t, HoldTooLarge([]string{strings.Repeat("x", guardmodel.MaxHeldLinesBytes)}), "exactly the cap")

	over := HoldTooLarge([]string{strings.Repeat("x", guardmodel.MaxHeldLinesBytes/2), strings.Repeat("y", guardmodel.MaxHeldLinesBytes/2+1)})
	require.NotNil(t, over)
	require.Equal(t, guidance.CodeStatementRefused, over.Code)
	require.Equal(t, action.ReasonHoldTooLarge, over.Reason)
	require.Contains(t, over.Message, "at most 64.0 MiB")
}

// The person's message says what to do: make the change themselves or have
// the agent write fewer rows.
func TestHoldTooLargeTellsThePerson(t *testing.T) {
	t.Parallel()
	over := HoldTooLarge([]string{strings.Repeat("x", guardmodel.MaxHeldLinesBytes+1)})
	for _, operatedBy := range []string{"", mcpcontract.OperatedByAgent} {
		s := newService(t, "linux", "", withOperatedBy(operatedBy))

		b := guidance.NewSteps()
		msg := s.HoldTooLargeSteps(b, over)
		require.NoError(t, guidance.CheckPersonMessage(msg))
		require.Contains(t, msg, "Make the change yourself")
		require.NotContains(t, msg, "update the guard")
		steps, err := b.Build()
		require.NoError(t, err)
		require.Len(t, steps, 2)
	}
}
