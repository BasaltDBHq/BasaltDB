package setup

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Run refuses a column label with a column name that is not plain before
// it reads anything, as the local setup page does; plain names pass.
func TestColumnNamesAreCheckedBeforeAnyRead(t *testing.T) {
	t.Parallel()
	label := Label{Class: "PUBLIC"}
	require.NoError(t, checkColumnNames(RunInput{}))
	require.NoError(t, checkColumnNames(RunInput{ColumnClasses: []ColumnClass{{Table: "public.leads", Column: "email", Label: label}}}))
	for _, name := range []string{"", strings.Repeat("a", 64), "email\x1f"} {
		err := checkColumnNames(RunInput{ColumnClasses: []ColumnClass{{Table: "public.leads", Column: name, Label: label}}})
		var e *Error
		require.True(t, errors.As(err, &e), "name %q", name)
		require.Equal(t, CodeAnswersInvalid, e.Code)
		require.Equal(t, "the column labels: a class, entity type or phone region the page does not set; nothing changed", e.Message)
	}
}
