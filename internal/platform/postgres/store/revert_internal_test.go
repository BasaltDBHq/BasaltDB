package store

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
)

// guardErr is the guard's answer as Postgres raises it.
func guardErr(sqlState, message, detail, hint string) error {
	return &pgconn.PgError{Code: sqlState, Message: message, Detail: detail, Hint: hint}
}

func revertInvalid(detail string) error { return guardErr("BS005", "REVERT_INVALID", detail, "") }

// revertRefused is REVERT_INVALID with a typed detail and its sentence.
func revertRefused(code, hint string) error { return guardErr("BS005", "REVERT_INVALID", code, hint) }

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
	reason            revertstore.RevertReason
	detail, storeCode string
}

// Each revert call maps the guard's answers the way the revert use case
// told them apart: the call decides what an answer means. Every answer is
// mapped after MapError and keeps the mapped error in its chain.
func TestRevertRefusalsPerCall(t *testing.T) {
	t.Parallel()
	const (
		filterHint   = "public.ghost has no change of yours in this scope"
		nameHint     = "leads is not a schema.table name"
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
		{"find: not prepared by the role", findRevertRefusal, ledger.ErrRevertNotFound, revertstore.RevertNotFound, "", ""},
		{"find: any other error", findRevertRefusal, errors.New("conn closed"), "", "", ""},

		{"prepare: not own change", prepareRefusal, scopeRefusedErr("NOT_OWN_CHANGE", "x"), revertstore.RevertNotOwnChange, "x", ""},
		{"prepare: not own run", prepareRefusal, scopeRefusedErr("NOT_OWN_RUN", "x"), revertstore.RevertNotOwnRun, "x", ""},
		{"prepare: not own task", prepareRefusal, scopeRefusedErr("NOT_OWN_TASK", "x"), revertstore.RevertNotOwnTask, "x", ""},
		{"prepare: filter", prepareRefusal, scopeRefusedErr("FILTER", filterHint), revertstore.RevertFilter, filterHint, ""},
		{"prepare: filter cap", prepareRefusal, scopeRefusedErr("FILTER_CAP", "at most 50"), revertstore.RevertFilterCap, "at most 50", ""},
		{"prepare: table name", prepareRefusal, scopeRefusedErr("NAME", nameHint), revertstore.RevertFilterName, nameHint, ""},
		// Told apart by the detail, never the hint: a SHAPE with the hint an
		// older guard gave a bad name, or any hint, is RevertInvalid.
		{"prepare: table name shape, older guard", prepareRefusal, scopeRefusedErr("SHAPE", shapeHint), revertstore.RevertInvalid, shapeHint, ""},
		{"prepare: table name, any hint", prepareRefusal, scopeRefusedErr("NAME", "x"), revertstore.RevertFilterName, "x", ""},
		{"prepare: run id shape", prepareRefusal, scopeRefusedErr("SHAPE", "runs are run ids"), revertstore.RevertInvalid, "runs are run ids", ""},
		{"prepare: agents shape", prepareRefusal, scopeRefusedErr("SHAPE", "agents are role names"), revertstore.RevertInvalid, "agents are role names", ""},
		{"prepare: other shape", prepareRefusal, scopeRefusedErr("SHAPE", "scopeId is a uuid"), revertstore.RevertInvalid, "scopeId is a uuid", ""},
		{"prepare: store reserved", prepareRefusal, scopeRefusedErr("STORE_RESERVED", "x"), revertstore.RevertInvalid, "x", ""},
		{"prepare: descriptor", prepareRefusal, scopeRefusedErr("DESCRIPTOR", "x"), revertstore.RevertInvalid, "x", ""},
		{"prepare: reads only", prepareRefusal, guardErr("BS009", "NOTHING_TO_REVERT", "READS_ONLY", readsOnly), revertstore.RevertReadsOnly, "NOTHING_TO_REVERT: " + readsOnly, ""},
		// Told apart by the detail, never the words: the sentence as the
		// detail, as a guard before version 11 gave it, is every row skipped.
		{"prepare: reads only words, untyped", prepareRefusal, guardErr("BS009", "NOTHING_TO_REVERT", readsOnly, ""), revertstore.RevertNothing, "NOTHING_TO_REVERT: " + readsOnly, ""},
		{"prepare: every row skipped", prepareRefusal, guardErr("BS009", "NOTHING_TO_REVERT", allSkipped, ""), revertstore.RevertNothing, "NOTHING_TO_REVERT: " + allSkipped, ""},
		{"prepare: time limit", prepareRefusal, statementTimeout(), revertstore.RevertTimedOut, "", "57014"},
		{"prepare: empty proposal", prepareRefusal, revertstore.ErrEmptyProposal, "", "", ""},
		{"prepare: permission denied", prepareRefusal, guardErr("42501", "permission denied", "", ""), "", "", ""},

		{"apply: expired", applyRevertRefusal, revertExpired(), revertstore.RevertExpiredReason, "", ""},
		{"apply: no row to restore", applyRevertRefusal, guardErr("BS009", "NOTHING_TO_REVERT", "RUN x has no row to restore in this scope", ""), revertstore.RevertNothing, "", ""},
		{"apply: rows changed", applyRevertRefusal, revertRefused("ROWS_CHANGED", rowsChanged), revertstore.RevertRowsChanged, rowsChanged, ""},
		{"apply: passkey revoked", applyRevertRefusal, revertRefused("PASSKEY_REVOKED", "passkey revoked"), revertstore.RevertPasskeyRevoked, "passkey revoked", ""},
		{"apply: already applied", applyRevertRefusal, revertRefused("ALREADY_APPLIED", applied), revertstore.RevertAlreadySigned, applied, ""},
		{"apply: already signed", applyRevertRefusal, revertRefused("ALREADY_SIGNED", signedBatch), revertstore.RevertAlreadySigned, signedBatch, ""},
		// Told apart by the detail, never the words: a sentence as the
		// detail, as a guard before version 11 gave it, is a refused signature.
		{"apply: rows changed words, untyped", applyRevertRefusal, revertInvalid(rowsChanged), revertstore.RevertSignature, rowsChanged, ""},
		{"apply: passkey revoked words, untyped", applyRevertRefusal, revertInvalid("passkey revoked"), revertstore.RevertSignature, "passkey revoked", ""},
		{"apply: already words, untyped", applyRevertRefusal, revertInvalid(applied), revertstore.RevertSignature, applied, ""},
		{"apply: no such revert", applyRevertRefusal, revertRefused("NO_SUCH_REVERT", noSuchRevert), revertstore.RevertSignature, noSuchRevert, ""},
		{"apply: no such revert, any hint", applyRevertRefusal, revertRefused("NO_SUCH_REVERT", "x"), revertstore.RevertSignature, "x", ""},
		{"apply: withdrawn", applyRevertRefusal, revertRefused("WITHDRAWN", "the agent withdrew this request: x; nothing changed"), revertstore.RevertWithdrawnReason, "the agent withdrew this request: x; nothing changed", ""},
		{"apply: rejected", applyRevertRefusal, revertInvalid(rejected), revertstore.RevertSignature, rejected, ""},
		{"apply: bad signature", applyRevertRefusal, revertInvalid("signature does not verify"), revertstore.RevertSignature, "signature does not verify", ""},
		{"apply: time limit", applyRevertRefusal, statementTimeout(), "", "", ""},
		{"apply: scope refused", applyRevertRefusal, scopeRefusedErr("SHAPE", "x"), "", "", ""},

		{"rescope: shape", rescopeRevertRefusal, scopeRefusedErr("SHAPE", shapeHint), revertstore.RevertInvalid, shapeHint, ""},
		{"rescope: table name", rescopeRevertRefusal, scopeRefusedErr("NAME", nameHint), revertstore.RevertInvalid, nameHint, ""},
		{"rescope: descriptor", rescopeRevertRefusal, scopeRefusedErr("DESCRIPTOR", "x"), revertstore.RevertInvalid, "x", ""},
		{"rescope: filter", rescopeRevertRefusal, scopeRefusedErr("FILTER", filterHint), revertstore.RevertInvalid, filterHint, ""},
		{"rescope: widen refused", rescopeRevertRefusal, revertInvalid("WIDEN_REFUSED"), revertstore.RevertWidenRefused, "WIDEN_REFUSED", ""},
		{"rescope: expired", rescopeRevertRefusal, revertExpired(), revertstore.RevertExpiredReason, "", ""},
		{"rescope: time limit", rescopeRevertRefusal, statementTimeout(), revertstore.RevertTimedOut, "", "57014"},
		{"rescope: no such revert", rescopeRevertRefusal, revertRefused("NO_SUCH_REVERT", noSuchRevert), "", "", ""},
		{"rescope: already signed", rescopeRevertRefusal, revertInvalid(signedScope), "", "", ""},
		{"rescope: withdrawn", rescopeRevertRefusal, revertRefused("WITHDRAWN", "the agent withdrew this request: x; nothing changed"), revertstore.RevertWithdrawnReason, "the agent withdrew this request: x; nothing changed", ""},
		{"rescope: every row skipped", rescopeRevertRefusal, guardErr("BS009", "NOTHING_TO_REVERT", allSkipped, ""), "", "", ""},

		{"reject: widen refused", rejectRevertRefusal, revertInvalid("WIDEN_REFUSED"), revertstore.RevertWidenRefused, "WIDEN_REFUSED", ""},
		{"reject: no such revert", rejectRevertRefusal, revertRefused("NO_SUCH_REVERT", noSuchRevert), revertstore.RevertNotFound, noSuchRevert, ""},
		{"reject: no such revert, any hint", rejectRevertRefusal, revertRefused("NO_SUCH_REVERT", "x"), revertstore.RevertNotFound, "x", ""},
		// Told apart by the detail, never the words: the sentence as the
		// detail, as a guard before version 13 gave it, is not pending.
		{"reject: no such revert words, untyped", rejectRevertRefusal, revertInvalid(noSuchRevert), revertstore.RevertNotPending, noSuchRevert, ""},
		{"reject: withdrawn", rejectRevertRefusal, revertRefused("WITHDRAWN", "the agent withdrew this request: x; nothing changed"), revertstore.RevertWithdrawnReason, "the agent withdrew this request: x; nothing changed", ""},
		{"reject: expired", rejectRevertRefusal, revertExpired(), revertstore.RevertExpiredReason, "", ""},
		{"reject: applied", rejectRevertRefusal, revertInvalid(applied), revertstore.RevertNotPending, applied, ""},
		{"reject: rejected", rejectRevertRefusal, revertInvalid(rejected), revertstore.RevertNotPending, rejected, ""},
		{"reject: signed", rejectRevertRefusal, revertInvalid(signedScope), revertstore.RevertNotPending, signedScope, ""},
		{"reject: reveal refused", rejectRevertRefusal, revertInvalid("REVEAL_REFUSED"), revertstore.RevertNotPending, "REVEAL_REFUSED", ""},
		{"reject: note too long", rejectRevertRefusal, guardErr("BS008", "LEDGER_INPUT_INVALID", "a reject note is at most 500 characters", ""), "", "", ""},

		{"reveal: refused", revealRevertRowsRefusal, revertInvalid("REVEAL_REFUSED"), revertstore.RevertRevealRefused, "REVEAL_REFUSED", ""},
		{"reveal: no such revert", revealRevertRowsRefusal, revertRefused("NO_SUCH_REVERT", noSuchRevert), revertstore.RevertNotFound, noSuchRevert, ""},
		{"reveal: no such revert words, untyped", revealRevertRowsRefusal, revertInvalid(noSuchRevert), revertstore.RevertNotPending, noSuchRevert, ""},
		{"reveal: withdrawn", revealRevertRowsRefusal, revertRefused("WITHDRAWN", "the agent withdrew this request: x; nothing changed"), revertstore.RevertWithdrawnReason, "the agent withdrew this request: x; nothing changed", ""},
		{"reveal: expired", revealRevertRowsRefusal, revertExpired(), revertstore.RevertExpiredReason, "", ""},
		{"reveal: signed", revealRevertRowsRefusal, revertInvalid("revert already signed"), revertstore.RevertNotPending, "revert already signed", ""},
		{"reveal: widen refused", revealRevertRowsRefusal, revertInvalid("WIDEN_REFUSED"), revertstore.RevertNotPending, "WIDEN_REFUSED", ""},
		{"reveal: time limit", revealRevertRowsRefusal, statementTimeout(), "", "", ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			mapped := MapError(row.err)
			out := row.mapping(mapped)
			refused := revertstore.RevertRefusalOf(out)
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
	require.Equal(t, "BS005", se.StoreCode)
}

// A typed detail (version 11) is for the engine: MapError says the guard's
// sentence as it said it before the detail was typed, and keeps the
// catalog reason the sentence had. A rescope passes the error through, so
// the page reads this message.
func TestTypedDetailsKeepTheirSentence(t *testing.T) {
	t.Parallel()
	const (
		readsOnly   = "RUN 0193a3f0-0000-7000-8000-000000000002 changed no rows that a revert could restore"
		rowsChanged = "rows changed since the preview; nothing was reverted, prepare the revert again"
	)
	cases := []struct {
		name                  string
		err                   error
		code, message, reason string
	}{
		{"reads only", guardErr("BS009", "NOTHING_TO_REVERT", "READS_ONLY", readsOnly), action.CodeNothingToRevert, "NOTHING_TO_REVERT: " + readsOnly, ""},
		{"rows changed", revertRefused("ROWS_CHANGED", rowsChanged), action.CodeRevertInvalid, "REVERT_INVALID: " + rowsChanged, action.ReasonRowsChanged},
		{"already applied", revertRefused("ALREADY_APPLIED", "revert already applied"), action.CodeRevertInvalid, "REVERT_INVALID: revert already applied", action.ReasonPlanFinished},
		{"already signed", revertRefused("ALREADY_SIGNED", "revert already signed; the agent applies it in batches"), action.CodeRevertInvalid, "REVERT_INVALID: revert already signed; the agent applies it in batches", action.ReasonPlanFinished},
		{"passkey revoked", revertRefused("PASSKEY_REVOKED", "passkey revoked"), action.CodeRevertInvalid, "REVERT_INVALID: passkey revoked", action.ReasonBadSignature},
		{"no such revert", revertRefused("NO_SUCH_REVERT", "no such revert"), action.CodeRevertInvalid, "REVERT_INVALID: no such revert", action.ReasonNotThisAgent},
		{"no such revert, any hint", revertRefused("NO_SUCH_REVERT", "x"), action.CodeRevertInvalid, "REVERT_INVALID: x", action.ReasonNotThisAgent},
		// The sentence alone, as a guard before version 13 gave it, is a
		// signature the guard did not accept: the words no longer matter.
		{"no such revert words, untyped", revertInvalid("no such revert"), action.CodeRevertInvalid, "REVERT_INVALID: no such revert", action.ReasonBadSignature},
		{"no such approval", noSuchApprovalErr("no such approval"), action.CodeApprovalInvalid, "APPROVAL_INVALID: no such approval", action.ReasonNotThisAgent},
		{"no such approval, any hint", noSuchApprovalErr("x"), action.CodeApprovalInvalid, "APPROVAL_INVALID: x", action.ReasonNotThisAgent},
		{"no such approval words, untyped", approvalInvalid("no such approval"), action.CodeApprovalInvalid, "APPROVAL_INVALID: no such approval", action.ReasonBadSignature},
		// An untyped detail keeps its sentence, a hint said after it.
		{"every row skipped", guardErr("BS009", "NOTHING_TO_REVERT", "x", "y"), action.CodeNothingToRevert, "NOTHING_TO_REVERT: x (hint: y)", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var se *action.StoreError
			require.ErrorAs(t, MapError(tc.err), &se)
			require.Equal(t, tc.message, se.Message)
			require.Equal(t, tc.code, se.Code)
			require.Equal(t, tc.reason, se.Reason)
		})
	}
	// A signed revert's nothing to revert says the sentence, never the code.
	refused := revertstore.RevertRefusalOf(applyRevertRefusal(MapError(guardErr("BS009", "NOTHING_TO_REVERT", "READS_ONLY", readsOnly))))
	require.NotNil(t, refused)
	require.Equal(t, revertstore.RevertNothing, refused.Reason)
	require.Equal(t, readsOnly, refused.Detail)
}
