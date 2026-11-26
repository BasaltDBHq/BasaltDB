package app

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// TestRevertReadsTheStatementTimeoutFromTheStore: the statement timeout a
// revert's answer names is the agent's store limits, and none for an agent
// served without store data, as the agent use case reported it.
func TestRevertReadsTheStatementTimeoutFromTheStore(t *testing.T) {
	t.Parallel()
	a := agentDeps{Limits: action.Limits{StatementTimeout: 5 * time.Second}}
	require.Zero(t, storeStatementLimit(a).StatementTimeout(), "no store data, no limit")
	a.Data = postgresStore{}
	require.Equal(t, 5*time.Second, storeStatementLimit(a).StatementTimeout())
}

// TestDeliveryReadsTheColumnOrderOnlyWhenWired: the pages read the field
// order through the column-order adapter, and show the rows' order without
// one.
func TestDeliveryReadsTheColumnOrderOnlyWhenWired(t *testing.T) {
	t.Parallel()
	s := &Service{}
	require.False(t, s.approvalReads().HasColumns())
	s.deps.Approval.Columns = fixedColumns{"public.t": {"id", "name"}}
	reads := s.approvalReads()
	require.True(t, reads.HasColumns())
	cols, err := reads.ColumnOrder(context.Background(), []string{"public.t"})
	require.NoError(t, err)
	require.Equal(t, map[string][]string{"public.t": {"id", "name"}}, cols)
}

// fixedColumns is a column order over fixed resources.
type fixedColumns map[string][]string

func (f fixedColumns) ColumnOrder(context.Context, []string) (map[string][]string, error) {
	return f, nil
}
