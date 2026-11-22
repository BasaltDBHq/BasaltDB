package agent

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/store/postgres"
)

// holdTooLarge refuses lines over the cap before the hold, and maps an
// older guard's per-line refusal (BS008 with a line over 64 KiB) to
// HOLD_TOO_LARGE; any other error stays as it is.
func TestHoldTooLarge(t *testing.T) {
	t.Parallel()
	small := []string{strings.Repeat("x", 1000)}
	wide := []string{strings.Repeat("x", guard.MaxHeldLineBytesBefore37+1)}
	bs008 := postgres.MapError(&pgconn.PgError{Code: "BS008", Message: "LEDGER_INPUT_INVALID", Detail: "each line must be the jsonb text of a preview line"})

	require.Nil(t, holdTooLarge(small, nil))
	require.Nil(t, holdTooLarge(wide, nil), "within the cap: the hold decides")
	require.Nil(t, holdTooLarge(small, bs008), "a small line's invalid input is not a size refusal")
	require.Nil(t, holdTooLarge(wide, errors.New("connection reset")))

	over := holdTooLarge([]string{strings.Repeat("x", guard.MaxHeldLinesBytes/2), strings.Repeat("y", guard.MaxHeldLinesBytes/2+1)}, nil)
	require.NotNil(t, over)
	require.Equal(t, CodeStatementRefused, over.Code)
	require.Equal(t, ReasonHoldTooLarge, over.Reason)
	require.Contains(t, over.Message, "at most 64.0 MiB")
	require.NotContains(t, over.Message, olderGuardNote)

	older := holdTooLarge(wide, bs008)
	require.NotNil(t, older)
	require.Equal(t, ReasonHoldTooLarge, older.Reason)
	require.Contains(t, older.Message, olderGuardNote)
}

// The person's message says what to do: on an older guard, upgrade it
// (the command on an engine the person runs); otherwise make the change
// themselves or have the agent write fewer rows.
func TestHoldTooLargeTellsThePerson(t *testing.T) {
	t.Parallel()
	older := holdTooLarge([]string{strings.Repeat("x", guard.MaxHeldLineBytesBefore37+1)}, postgres.MapError(&pgconn.PgError{Code: "BS008"}))
	over := holdTooLarge([]string{strings.Repeat("x", guard.MaxHeldLinesBytes+1)}, nil)
	for _, operatedBy := range []string{"", mcpcontract.OperatedByAgent} {
		s := operatedService(t, "linux", "", operatedBy)

		b := NewSteps()
		msg := s.holdTooLargeSteps(b, older)
		require.NoError(t, CheckPersonMessage(msg))
		require.Contains(t, msg, "64 KiB")
		require.NotContains(t, msg, "basalt ", "the person runs no command: the agent gives a link")
		require.Contains(t, msg, "update the guard")

		b = NewSteps()
		msg = s.holdTooLargeSteps(b, over)
		require.NoError(t, CheckPersonMessage(msg))
		require.Contains(t, msg, "Make the change yourself")
		steps, err := b.Build()
		require.NoError(t, err)
		require.Len(t, steps, 2)
	}
}
