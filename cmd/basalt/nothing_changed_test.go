package main

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// A failed install (init with a setup code, upgrade) ends with "nothing
// changed" as its own sentence after the guard's detail and hint, and after
// a semicolon otherwise; never "…by it.; nothing changed".
func TestNothingChangedReadsAsSentences(t *testing.T) {
	t.Parallel()
	pg := &pgconn.PgError{
		Severity: "ERROR", Code: "BS007", Message: "NOT_ALLOWED",
		Detail: "table public.nopk has no primary key; the guard keys ledger rows by it",
		Hint:   "add a primary key, or revoke the agent's write privileges on it",
	}
	require.Equal(t, "ERROR: NOT_ALLOWED (SQLSTATE BS007): table public.nopk has no primary key; the guard keys ledger rows by it. "+
		"add a primary key, or revoke the agent's write privileges on it. Nothing changed.",
		nothingChanged(withGuardDetail(pg)).Error())
	require.Equal(t, "connection reset; nothing changed", nothingChanged(withGuardDetail(errors.New("connection reset"))).Error())
	require.Equal(t, "ERROR: boom (SQLSTATE XX000); nothing changed",
		nothingChanged(withGuardDetail(&pgconn.PgError{Severity: "ERROR", Code: "XX000", Message: "boom"})).Error())
}
