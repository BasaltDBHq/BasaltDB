package store

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
)

// guardErr is the guard's answer as Postgres raises it.
func guardErr(sqlState, message, detail, hint string) error {
	return &pgconn.PgError{Code: sqlState, Message: message, Detail: detail, Hint: hint}
}

func revertInvalid(detail string) error { return guardErr("BS005", "REVERT_INVALID", detail, "") }

func revertExpired() error {
	return guardErr("BS005", "REVERT_EXPIRED", "revert 0193a3f0-0000-7000-8000-000000000001 expired at 2026-11-25 10:00:00+00; prepare it again", "")
}

func scopeRefusedErr(detail, hint string) error {
	return guardErr("BS011", "SCOPE_REFUSED", detail, hint)
}

func statementTimeout() error {
	return guardErr("57014", "canceling statement due to statement timeout", "", "")
}

// refusalRow is one guard answer to one revert call: the refusal the
// adapter maps it to, or none (reason "") when the service reads the
// mapped error as it is.
type refusalRow struct {
	name              string
	mapping           func(error) error
	err               error
	reason            action.RevertReason
	detail, storeCode string
}

// Each revert call maps the guard's answers the way the revert use case
// told them apart: the call decides what an answer means. Every answer is
// mapped after MapError and keeps the mapped error in its chain.
func TestRevertRefusalsPerCall(t *testing.T) {
	t.Parallel()
	const (
		filterHint   = "public.ghost has no change of yours in this scope"
		shapeHint    = "tables are schema.table names"
		readsOnly    = "RUN 0193a3f0-0000-7000-8000-000000000002 changed no rows that a revert could restore"
		allSkipped   = "every row of RUN 0193a3f0-0000-7000-8000-000000000002 would be skipped"
		rowsChanged  = "rows changed since the preview; nothing was reverted, prepare the revert again"
		applied      = "revert already applied"
		rejected     = "the person rejected this revert; nothing was reverted"
		signedBatch  = "revert already signed; the agent applies it in batches"
		signedScope  = "revert already signed; its scope can no longer change"
		noSuchRevert = "no such revert"
	)
	rows := []refusalRow{
		{"find: not prepared by the role", findRevertRefusal, ledger.ErrRevertNotFound, action.RevertNotFound, "", ""},
		{"find: any other error", findRevertRefusal, errors.New("conn closed"), "", "", ""},

		{"prepare: not own change", prepareRefusal, scopeRefusedErr("NOT_OWN_CHANGE", "x"), action.RevertNotOwnChange, "x", ""},
		{"prepare: not own run", prepareRefusal, scopeRefusedErr("NOT_OWN_RUN", "x"), action.RevertNotOwnRun, "x", ""},
		{"prepare: not own task", prepareRefusal, scopeRefusedErr("NOT_OWN_TASK", "x"), action.RevertNotOwnTask, "x", ""},
		{"prepare: filter", prepareRefusal, scopeRefusedErr("FILTER", filterHint), action.RevertFilter, filterHint, ""},
		{"prepare: filter cap", prepareRefusal, scopeRefusedErr("FILTER_CAP", "at most 50"), action.RevertFilterCap, "at most 50", ""},
		{"prepare: table name shape", prepareRefusal, scopeRefusedErr("SHAPE", shapeHint), action.RevertFilter, shapeHint, ""},
		{"prepare: run id shape", prepareRefusal, scopeRefusedErr("SHAPE", "runs are run ids"), action.RevertInvalid, "runs are run ids", ""},
		{"prepare: agents shape", prepareRefusal, scopeRefusedErr("SHAPE", "agents are role names"), action.RevertInvalid, "agents are role names", ""},
		{"prepare: other shape", prepareRefusal, scopeRefusedErr("SHAPE", "scopeId is a uuid"), action.RevertInvalid, "scopeId is a uuid", ""},
		{"prepare: store reserved", prepareRefusal, scopeRefusedErr("STORE_RESERVED", "x"), action.RevertInvalid, "x", ""},
		{"prepare: descriptor", prepareRefusal, scopeRefusedErr("DESCRIPTOR", "x"), action.RevertInvalid, "x", ""},
		{"prepare: reads only", prepareRefusal, guardErr("BS009", "NOTHING_TO_REVERT", readsOnly, ""), action.RevertReadsOnly, "NOTHING_TO_REVERT: " + readsOnly, ""},
		{"prepare: every row skipped", prepareRefusal, guardErr("BS009", "NOTHING_TO_REVERT", allSkipped, ""), action.RevertNothing, "NOTHING_TO_REVERT: " + allSkipped, ""},
		{"prepare: time limit", prepareRefusal, statementTimeout(), action.RevertTimedOut, "", "57014"},
		{"prepare: empty proposal", prepareRefusal, action.ErrEmptyProposal, "", "", ""},
		{"prepare: permission denied", prepareRefusal, guardErr("42501", "permission denied", "", ""), "", "", ""},

		{"apply: expired", applyRevertRefusal, revertExpired(), action.RevertExpiredReason, "", ""},
		{"apply: no row to restore", applyRevertRefusal, guardErr("BS009", "NOTHING_TO_REVERT", "RUN x has no row to restore in this scope", ""), action.RevertNothing, "", ""},
		{"apply: rows changed", applyRevertRefusal, revertInvalid(rowsChanged), action.RevertRowsChanged, rowsChanged, ""},
		{"apply: passkey revoked", applyRevertRefusal, revertInvalid("passkey revoked"), action.RevertPasskeyRevoked, "passkey revoked", ""},
		{"apply: already applied", applyRevertRefusal, revertInvalid(applied), action.RevertAlreadySigned, applied, ""},
		{"apply: already signed", applyRevertRefusal, revertInvalid(signedBatch), action.RevertAlreadySigned, signedBatch, ""},
		{"apply: no such revert", applyRevertRefusal, revertInvalid(noSuchRevert), action.RevertSignature, noSuchRevert, ""},
		{"apply: rejected", applyRevertRefusal, revertInvalid(rejected), action.RevertSignature, rejected, ""},
		{"apply: bad signature", applyRevertRefusal, revertInvalid("signature does not verify"), action.RevertSignature, "signature does not verify", ""},
		{"apply: time limit", applyRevertRefusal, statementTimeout(), "", "", ""},
		{"apply: scope refused", applyRevertRefusal, scopeRefusedErr("SHAPE", "x"), "", "", ""},

		{"rescope: shape", rescopeRevertRefusal, scopeRefusedErr("SHAPE", shapeHint), action.RevertInvalid, shapeHint, ""},
		{"rescope: descriptor", rescopeRevertRefusal, scopeRefusedErr("DESCRIPTOR", "x"), action.RevertInvalid, "x", ""},
		{"rescope: filter", rescopeRevertRefusal, scopeRefusedErr("FILTER", filterHint), action.RevertInvalid, filterHint, ""},
		{"rescope: widen refused", rescopeRevertRefusal, revertInvalid("WIDEN_REFUSED"), action.RevertWidenRefused, "WIDEN_REFUSED", ""},
		{"rescope: expired", rescopeRevertRefusal, revertExpired(), action.RevertExpiredReason, "", ""},
		{"rescope: time limit", rescopeRevertRefusal, statementTimeout(), action.RevertTimedOut, "", "57014"},
		{"rescope: no such revert", rescopeRevertRefusal, revertInvalid(noSuchRevert), "", "", ""},
		{"rescope: already signed", rescopeRevertRefusal, revertInvalid(signedScope), "", "", ""},
		{"rescope: every row skipped", rescopeRevertRefusal, guardErr("BS009", "NOTHING_TO_REVERT", allSkipped, ""), "", "", ""},

		{"reject: widen refused", rejectRevertRefusal, revertInvalid("WIDEN_REFUSED"), action.RevertWidenRefused, "WIDEN_REFUSED", ""},
		{"reject: no such revert", rejectRevertRefusal, revertInvalid(noSuchRevert), action.RevertNotFound, noSuchRevert, ""},
		{"reject: expired", rejectRevertRefusal, revertExpired(), action.RevertExpiredReason, "", ""},
		{"reject: applied", rejectRevertRefusal, revertInvalid(applied), action.RevertNotPending, applied, ""},
		{"reject: rejected", rejectRevertRefusal, revertInvalid(rejected), action.RevertNotPending, rejected, ""},
		{"reject: signed", rejectRevertRefusal, revertInvalid(signedScope), action.RevertNotPending, signedScope, ""},
		{"reject: reveal refused", rejectRevertRefusal, revertInvalid("REVEAL_REFUSED"), action.RevertNotPending, "REVEAL_REFUSED", ""},
		{"reject: note too long", rejectRevertRefusal, guardErr("BS008", "LEDGER_INPUT_INVALID", "a reject note is at most 500 characters", ""), "", "", ""},

		{"reveal: refused", revealRevertRowsRefusal, revertInvalid("REVEAL_REFUSED"), action.RevertRevealRefused, "REVEAL_REFUSED", ""},
		{"reveal: no such revert", revealRevertRowsRefusal, revertInvalid(noSuchRevert), action.RevertNotFound, noSuchRevert, ""},
		{"reveal: expired", revealRevertRowsRefusal, revertExpired(), action.RevertExpiredReason, "", ""},
		{"reveal: signed", revealRevertRowsRefusal, revertInvalid("revert already signed"), action.RevertNotPending, "revert already signed", ""},
		{"reveal: widen refused", revealRevertRowsRefusal, revertInvalid("WIDEN_REFUSED"), action.RevertNotPending, "WIDEN_REFUSED", ""},
		{"reveal: time limit", revealRevertRowsRefusal, statementTimeout(), "", "", ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			mapped := MapError(row.err)
			out := row.mapping(mapped)
			refused := action.RevertRefusalOf(out)
			if row.reason == "" {
				require.Nil(t, refused, "%v", out)
				require.Equal(t, mapped, out, "returned as MapError made it")
				return
			}
			require.NotNil(t, refused, "%v", out)
			require.Equal(t, row.reason, refused.Reason)
			if row.detail != "" {
				require.Equal(t, row.detail, refused.Detail)
			}
			require.Equal(t, row.storeCode, refused.StoreCode)
			require.Same(t, mapped, refused.Err, "wraps the mapped error")
			require.Equal(t, mapped.Error(), out.Error(), "keeps the store's text")
			require.ErrorIs(t, out, row.err)
		})
	}
}

// The store's own error stays readable through a refusal: the tool error
// mapping reads its code and SQLSTATE as before.
func TestRevertRefusalKeepsTheStoreError(t *testing.T) {
	t.Parallel()
	out := applyRevertRefusal(MapError(revertInvalid("signature does not verify")))
	var se *action.StoreError
	require.ErrorAs(t, out, &se)
	require.Equal(t, action.CodeRevertInvalid, se.Code)
	require.Equal(t, "BS005", se.SQLState)
}
