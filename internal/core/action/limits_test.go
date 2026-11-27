package action_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

func TestLimits(t *testing.T) {
	t.Parallel()
	l := action.DefaultLimits()
	require.NoError(t, l.Validate())
	require.Equal(t, 5*time.Second, l.StatementTimeout)

	require.Error(t, action.Limits{StatementTimeout: 0, ReadRowLimit: 10}.Validate())
	require.Error(t, action.Limits{StatementTimeout: time.Hour, ReadRowLimit: 10}.Validate())
	require.Error(t, action.Limits{StatementTimeout: time.Second, ReadRowLimit: 0}.Validate())
	require.Error(t, action.Limits{StatementTimeout: time.Second, ReadRowLimit: 1_000_000}.Validate())
}
