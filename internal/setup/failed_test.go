package setup_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// SETUP_FAILED's sentence names the Postgres error and the step, the
// script's statement included, and never the database's words.
func TestFailedMessage(t *testing.T) {
	t.Parallel()
	pg := &pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint \"secret_words\""}
	err := fmt.Errorf("init step 4: %w", pg)
	require.Equal(t, "23505", setup.SQLStateOf(err))
	require.Empty(t, setup.SQLStateOf(errors.New("connection reset")))
	require.Equal(t, "setup, statement 4", setup.FailedStep("setup", err))
	require.Equal(t, "setup", setup.FailedStep("setup", pg))
	require.Equal(t, "setup", setup.FailedStep("setup", nil))

	require.Equal(t, "Reading the database or running the setup failed (Postgres error 23505, setup, statement 4); nothing changed.",
		setup.FailedMessage(setup.FailedStep("setup", err), setup.SQLStateOf(err)))
	require.Equal(t, "The admin role lacks a privilege the setup needs (Postgres error 42501, install script); nothing changed.",
		setup.FailedMessage("install script", "42501"))
	require.Equal(t, "Reading the database or running the setup failed; nothing changed.", setup.FailedMessage("setup", ""))
}
