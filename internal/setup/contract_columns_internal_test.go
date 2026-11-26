package setup

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// Run refuses a column label with a column name that is not plain before
// it reads anything, as the local setup page does; plain names pass.
func TestColumnNamesAreCheckedBeforeAnyRead(t *testing.T) {
	t.Parallel()
	label := guardmodel.Label{Class: "PUBLIC"}
	require.NoError(t, checkColumnNames(ContractRunInput{}))
	require.NoError(t, checkColumnNames(ContractRunInput{ColumnClasses: []ContractColumnClass{{Table: "public.leads", Column: "email", Label: label}}}))
	for _, name := range []string{"", strings.Repeat("a", 64), "email\x1f"} {
		err := checkColumnNames(ContractRunInput{ColumnClasses: []ContractColumnClass{{Table: "public.leads", Column: name, Label: label}}})
		var e *SetuprunRefusalError
		require.True(t, errors.As(err, &e), "name %q", name)
		require.Equal(t, SetuprunCodeAnswersInvalid, e.Code)
		require.Equal(t, "the column labels: a class, entity type or phone region the page does not set; nothing changed", e.Message)
	}
}
