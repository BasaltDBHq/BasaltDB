package setup

import (
	"context"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
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

// An unconfirmed commit reaches the caller as SETUP_UNCONFIRMED, listed in
// Codes, with the setup's text unchanged: never that nothing changed.
func TestSetupUnconfirmedIsItsOwnCode(t *testing.T) {
	t.Parallel()
	lost := &setuprun.UnconfirmedError{Err: io.ErrUnexpectedEOF}
	err := asError(setuprun.Refused(context.Background(), store, nil, setupcode.Payload{}, lost))
	var e *Error
	require.True(t, errors.As(err, &e))
	require.Equal(t, CodeSetupUnconfirmed, e.Code)
	require.Equal(t, "the database did not confirm the setup, so it may or may not have run. Check the setup again to see which", e.Message)
	require.NotContains(t, e.Message, "othing changed")
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Contains(t, Codes(), CodeSetupUnconfirmed)
}
