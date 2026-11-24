package setup

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	setuprun "github.com/basaltdbhq/basaltdb/internal/setup"
)

// A failure of the database reaches the person as a fixed sentence with its
// SQLSTATE; its own words stay in the error Unwrap returns. A refusal the
// package worded keeps its sentence.
func TestSetupFailedCarriesNoDatabaseWords(t *testing.T) {
	t.Parallel()
	pg := &pgconn.PgError{Code: "42501", Message: "permission denied for schema secret_words"}
	err := asError(fmt.Errorf("init step 2: %w", pg))
	var e *Error
	require.True(t, errors.As(err, &e))
	require.Equal(t, CodeSetupFailed, e.Code)
	require.Equal(t, "The admin role lacks a privilege the setup needs (Postgres error 42501, setup, statement 2); nothing changed.", e.Message)
	require.NotContains(t, e.Message, "secret_words")
	require.ErrorIs(t, err, pg)

	plain := asError(errors.New("read tcp: connection reset by peer"))
	require.Equal(t, "Reading the database or running the setup failed; nothing changed.", plain.Error())

	worded := &setuprun.SetuprunRefusalError{Code: CodeSetupFailed, Err: pg, Message: "Removing BasaltDB failed, for example because one of its roles still has privileges in another database; nothing changed."}
	require.Equal(t, worded.Message, asError(worded).Error())

	missing := asError(setuprun.PasskeyFailed(setupcode.Payload{}, pg))
	require.True(t, errors.As(missing, &e))
	require.Equal(t, CodePasskeyNotRegistered, e.Code)
	require.Contains(t, e.Message, "the setup ran but no passkey was registered (Postgres error 42501).")
	require.NotContains(t, e.Message, "secret_words")
}
