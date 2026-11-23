package setup

import (
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	setuprun "github.com/basaltdbhq/basaltdb/internal/setup"
)

// An older install the build cannot use is its own code, GUARD_UNUSABLE,
// listed in Codes, with the setup's text unchanged.
func TestGuardUnusableIsItsOwnCode(t *testing.T) {
	t.Parallel()
	require.Equal(t, "GUARD_UNUSABLE", CodeGuardUnusable)
	require.True(t, slices.Contains(Codes(), CodeGuardUnusable))
	const msg = "the database has an older BasaltDB install that this version cannot use. Remove it first, then set up again: https://example.test/remove says how. Nothing changed."
	err := asError(&setuprun.SetuprunRefusalError{Code: setuprun.SetuprunCodeGuardUnusable, Err: errors.New("unusable"), Message: msg})
	var e *Error
	require.True(t, errors.As(err, &e))
	require.Equal(t, CodeGuardUnusable, e.Code)
	require.Equal(t, msg, e.Message)
}
