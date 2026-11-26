package pluginledger

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// The database's answers map to the plugin's typed ones: an undefined
// function is a guard too old, an undefined table or schema no guard, a
// guard error its refusal, any other answer a plain one; each keeps the
// store's code and message and wraps the database's error.
func TestStoreErrorMapsTheDatabaseAnswers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code string
		want pluginmodel.StoreReason
	}{
		{"42883", pluginmodel.StoreGuardOutdated},
		{"42P01", pluginmodel.StoreGuardMissing},
		{"3F000", pluginmodel.StoreGuardMissing},
		{"BS008", pluginmodel.StoreRefused},
		{"BS007", pluginmodel.StoreRefused},
		{"23505", pluginmodel.StoreAnswered},
	}
	for _, c := range cases {
		pg := &pgconn.PgError{Code: c.code, Message: "the message", Detail: guard.DetailTooManyPending}
		err := MapError(fmt.Errorf("record: %w", pg))
		se := pluginmodel.StoreErrorOf(err)
		require.NotNil(t, se, c.code)
		require.Equal(t, c.want, se.Reason, c.code)
		require.Equal(t, c.code, se.Code)
		require.Equal(t, "the message", se.Message)
		require.ErrorIs(t, err, pg)
		require.Same(t, se, pluginmodel.StoreErrorOf(MapError(err)), "an answer is mapped once")
	}
}

// An error the database did not answer is left as it is: it is not a
// store answer, so the host can tell it from one.
func TestStoreErrorLeavesErrorsWithoutAnAnswer(t *testing.T) {
	t.Parallel()
	require.NoError(t, MapError(nil))
	for _, err := range []error{
		errors.New("cannot decode"),
		context.DeadlineExceeded,
		&pgconn.ConnectError{},
	} {
		require.Equal(t, err, MapError(err))
		require.Nil(t, pluginmodel.StoreErrorOf(MapError(err)))
	}
}

// Opening a plugin approval tells a full queue and an unknown agent apart by
// the guard's NOT_ALLOWED detail; any other refusal stays a refusal.
func TestOpenApprovalErrorReadsTheGuardsDetails(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code, detail string
		want         pluginmodel.StoreReason
	}{
		{"BS007", guard.DetailTooManyPending, pluginmodel.StoreTooManyPending},
		{"BS007", guard.DetailUnknownAgent, pluginmodel.StoreUnknownAgent},
		{"BS007", "something else", pluginmodel.StoreRefused},
		{"BS008", guard.DetailTooManyPending, pluginmodel.StoreRefused},
		{"42883", guard.DetailTooManyPending, pluginmodel.StoreGuardOutdated},
	}
	for _, c := range cases {
		err := openApprovalError(&pgconn.PgError{Code: c.code, Message: "NOT_ALLOWED", Detail: c.detail})
		se := pluginmodel.StoreErrorOf(err)
		require.NotNil(t, se, c.code+" "+c.detail)
		require.Equal(t, c.want, se.Reason, c.code+" "+c.detail)
	}
	plain := errors.New("no answer")
	require.Equal(t, plain, openApprovalError(plain))
}
