package store

import (
	"context"
	"errors"
	"strconv"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
)

// previewRevertRaw is PreviewRevert before MapError.
func (s *Store) previewRevertRaw(ctx context.Context, scope revertstore.Scope, after string, limit int) (revertstore.PreviewPage, error) {
	var page revertstore.PreviewPage
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setTimeout(ctx, tx, s.limits); err != nil {
			return err
		}
		var err error
		page, err = guard.PreviewRevertPage(ctx, tx, scope, after, limit)
		if err != nil {
			return err
		}
		return errPreviewRollback
	})
	if !errors.Is(err, errPreviewRollback) {
		return revertstore.PreviewPage{}, err
	}
	return page, nil
}

// prepareRevertRaw is PrepareRevert before MapError.
func (s *Store) prepareRevertRaw(ctx context.Context, scope revertstore.Scope, intent string, timeout time.Duration) (revertstore.PreparedRevert, error) {
	var p revertstore.PreparedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var err error
		p, err = guard.PrepareRevertWithin(ctx, savepoint{tx}, scope, intent, timeout)
		if err != nil {
			return err
		}
		if p.LineCount == 0 {
			return revertstore.ErrEmptyProposal
		}
		return nil
	})
	if err != nil {
		return revertstore.PreparedRevert{}, err
	}
	return p, nil
}

// rescopeRevertRaw is RescopeRevert before MapError.
func (s *Store) rescopeRevertRaw(ctx context.Context, req revertstore.RescopeRequest, timeout time.Duration) (revertstore.RescopedRevert, error) {
	var out revertstore.RescopedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setStatementTimeout(ctx, tx, timeout); err != nil {
			return err
		}
		var err error
		out, err = guard.RescopeRevert(ctx, tx, req)
		return err
	})
	return out, err
}

// resetRevertRaw is ResetRevert before MapError.
func (s *Store) resetRevertRaw(ctx context.Context, id uuid.UUID, timeout time.Duration) (revertstore.RescopedRevert, error) {
	var out revertstore.RescopedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setStatementTimeout(ctx, tx, timeout); err != nil {
			return err
		}
		var err error
		out, err = guard.ResetRevert(ctx, tx, id)
		return err
	})
	return out, err
}

// setStatementTimeout sets statement_timeout for tx only.
func setStatementTimeout(ctx context.Context, tx pgx.Tx, timeout time.Duration) error {
	q, args, err := psql.Select().
		Column(sq.Expr("pg_catalog.set_config('statement_timeout', ?, true)", strconv.FormatInt(timeout.Milliseconds(), 10))).
		ToSql()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, q, args...)
	return err
}

// savepoint begins a savepoint in tx where a guard helper begins a
// transaction, so its work commits or rolls back with tx.
type savepoint struct{ tx pgx.Tx }

func (s savepoint) BeginTx(ctx context.Context, _ pgx.TxOptions) (pgx.Tx, error) {
	return s.tx.Begin(ctx)
}

// hasChangeRaw is HasChange before MapError.
func (s *Store) hasChangeRaw(ctx context.Context, id uuid.UUID) (bool, error) {
	return s.exists(ctx, "basalt_meta.agent_changes", sq.Eq{"change_id": id.String()})
}

// hasTaskRunRaw is HasTaskRun before MapError.
func (s *Store) hasTaskRunRaw(ctx context.Context, id uuid.UUID) (bool, error) {
	return s.exists(ctx, "basalt_meta.agent_runs", sq.Eq{"task_id": id.String()})
}

// exists reports whether the agent's view from has a row matching where.
func (s *Store) exists(ctx context.Context, from string, where sq.Eq) (bool, error) {
	q, args, err := psql.Select().
		Column(sq.Expr("EXISTS (?)", psql.Select("1").From(from).Where(where))).
		ToSql()
	if err != nil {
		return false, err
	}
	var ok bool
	err = s.db.QueryRow(ctx, q, args...).Scan(&ok)
	return ok, err
}

// revertedByRaw is RevertedBy before MapError.
func (s *Store) revertedByRaw(ctx context.Context, scope revertstore.Scope) (uuid.UUID, error) {
	column := map[revert.Scope]string{
		revert.ScopeChange: "c.change_id", revert.ScopeRun: "c.run_id", revert.ScopeTask: "c.task_id",
	}[scope.Kind]
	if column == "" {
		return uuid.Nil, nil
	}
	// Raw join: squirrel cannot express a lateral unnest of the array column.
	q, args, err := psql.Select("rb").
		From("basalt_meta.agent_changes c").
		CrossJoin("LATERAL unnest(c.reverted_by) rb").
		Where(sq.Eq{column: scope.ID.String()}).
		OrderBy("rb DESC").
		Limit(1).
		ToSql()
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = s.db.QueryRow(ctx, q, args...).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}

// findRevertRaw is FindRevert before MapError.
func (s *Store) findRevertRaw(ctx context.Context, id uuid.UUID) (action.Revert, error) {
	return ledger.FindRevert(ctx, s.db, id)
}

// revertLinesRaw is RevertLines before MapError.
func (s *Store) revertLinesRaw(ctx context.Context, p action.RevertLineParams) (pagination.Page[action.RevertLine], error) {
	return ledger.ListRevertLinesMarked(ctx, s.db, p)
}

// applyRevertBatchRaw is ApplyRevertBatch before MapError.
func (s *Store) applyRevertBatchRaw(ctx context.Context, id uuid.UUID, lines []int) (revertstore.BatchResult, error) {
	var out revertstore.BatchResult
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := setTimeout(ctx, tx, s.limits); err != nil {
			return err
		}
		var err error
		out, err = guard.ApplyRevertBatch(ctx, tx, id, lines)
		return err
	})
	return out, err
}

// applyRevertRaw is ApplyRevert before MapError.
func (s *Store) applyRevertRaw(ctx context.Context, id uuid.UUID, a passkey.Assertion) (revertstore.AppliedRevert, error) {
	var out revertstore.AppliedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := guard.SetTimeouts(ctx, tx, s.limits.StatementTimeout); err != nil {
			return err
		}
		var err error
		out, err = guard.ApplyRevert(ctx, tx, id, a)
		return err
	})
	return out, err
}

// revertNonceRaw is RevertNonce before MapError.
func (s *Store) revertNonceRaw(ctx context.Context, id uuid.UUID) ([]byte, error) {
	return guard.RevertNonce(ctx, s.db, id)
}

// rejectRevertRaw is RejectRevert before MapError.
func (s *Store) rejectRevertRaw(ctx context.Context, id uuid.UUID, note string, token []byte) (revertstore.RejectedRevert, error) {
	r, err := guard.RejectRevert(ctx, s.db, id, note, token)
	return r, err
}

// revealNonceRaw is RevealNonce before MapError.
func (s *Store) revealNonceRaw(ctx context.Context, kind string, id uuid.UUID) ([]byte, error) {
	return guard.RevealNonce(ctx, s.db, kind, id)
}

// revealRevertRowsRaw is RevealRevertRows before MapError.
func (s *Store) revealRevertRowsRaw(ctx context.Context, id uuid.UUID, proof passkey.Assertion, key []byte) (revertstore.RevealedRevert, error) {
	var out revertstore.RevealedRevert
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var err error
		out, err = guard.RevealRevertRows(ctx, tx, id, proof, key)
		return err
	})
	return out, err
}

// The guard's answers to a revert call, mapped to the revert's own
// refusals (revertstore.RevertRefusalError) after MapError. Each port method has its
// own mapping, in the order the revert use case told the guard's answers
// apart: one guard answer means different things on different calls
// (REVERT_INVALID "no such revert" is an unknown revert on reject and
// reveal, a refused signature on apply). An answer no mapping names is
// returned as MapError made it.

// revertNotFoundDetail is the guard's detail for a revert the calling role
// did not prepare, or none (_revert_lock_pending). The guard gives it no
// typed detail: _revert_invalid raises the sentence itself, unlike the
// details of applyReasons, WIDEN_REFUSED and REVEAL_REFUSED. So the match
// is on the exact sentence until a guard version gives it a code.
const revertNotFoundDetail = "no such revert"

// scopeReasons are the revert reasons of the guard's SCOPE_REFUSED details
// on a preview or a prepare; any other detail is RevertInvalid. NAME, a
// tables entry that is not one schema.table name, is the agent's filter
// refused for the name's form, the hint naming the entry.
var scopeReasons = map[string]revertstore.RevertReason{
	guard.ScopeName:         revertstore.RevertFilterName,
	guard.ScopeNotOwnChange: revertstore.RevertNotOwnChange,
	guard.ScopeNotOwnRun:    revertstore.RevertNotOwnRun,
	guard.ScopeNotOwnTask:   revertstore.RevertNotOwnTask,
	guard.ScopeFilter:       revertstore.RevertFilter,
	guard.ScopeFilterCap:    revertstore.RevertFilterCap,
}

// nothingSentence is the guard's sentence for a NOTHING_TO_REVERT: the
// hint of a typed detail (READS_ONLY), the detail otherwise.
func nothingSentence(se *action.StoreError) string {
	if se.Detail == guard.NothingReadsOnly {
		return se.Hint
	}
	return se.Detail
}

// applyReasons are the revert reasons of apply_revert's typed
// REVERT_INVALID details.
var applyReasons = map[string]revertstore.RevertReason{
	guard.RevertAlreadyApplied: revertstore.RevertAlreadySigned,
	guard.RevertAlreadySigned:  revertstore.RevertAlreadySigned,
	guard.RevertPasskeyRevoked: revertstore.RevertPasskeyRevoked,
	guard.RevertRowsChanged:    revertstore.RevertRowsChanged,
}

// guardAnswer is the store error in err, mapped by MapError, nil when err
// has none.
func guardAnswer(err error) *action.StoreError {
	var se *action.StoreError
	if !errors.As(err, &se) {
		return nil
	}
	return se
}

// refusal is err refused for reason, with the store's text detail.
func refusal(err error, reason revertstore.RevertReason, detail string) error {
	return &revertstore.RevertRefusalError{Reason: reason, Detail: detail, Err: err}
}

// timedOut is err refused as RevertTimedOut, with its SQLSTATE, when the
// guard's statement ran into its time limit (QUERY_TIMEOUT TIME_LIMIT),
// and nil otherwise.
func timedOut(err error, se *action.StoreError) *revertstore.RevertRefusalError {
	if se.Code != action.CodeQueryTimeout || se.Reason != action.ReasonTimeLimit {
		return nil
	}
	return &revertstore.RevertRefusalError{Reason: revertstore.RevertTimedOut, StoreCode: se.StoreCode, Err: err}
}

// findRevertRefusal maps FindRevert's error: a revert the role did not
// prepare is RevertNotFound.
func findRevertRefusal(err error) error {
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return refusal(err, revertstore.RevertNotFound, "")
	}
	return err
}

// PrepareError is a guard answer to preview_revert or prepare_revert as
// PreviewRevert and PrepareRevert return it: MapError, then
// prepareRefusal. Exported so tests outside the adapter compare another
// store's refusals with Postgres's own mapping.
func PrepareError(err error) error { return prepareRefusal(MapError(err)) }

// prepareRefusal maps PreviewRevert's and PrepareRevert's errors: a scope
// the guard refused, by its detail (the hint says why; NAME, a badly formed
// table name, is the agent's filter refused for its form), nothing to
// revert (detail READS_ONLY: the scope changed no rows; any other: every
// row would be skipped), and the time limit. A nothing to revert keeps the
// guard's whole answer as its detail: its code and the sentence.
func prepareRefusal(err error) error {
	se := guardAnswer(err)
	if se == nil {
		return err
	}
	switch guard.Code(se.LedgerCode) {
	case guard.CodeScopeRefused:
		reason, ok := scopeReasons[se.Detail]
		if !ok {
			reason = revertstore.RevertInvalid
		}
		return refusal(err, reason, se.Hint)
	case guard.CodeNothingToRevert:
		if se.Detail == guard.NothingReadsOnly {
			return refusal(err, revertstore.RevertReadsOnly, se.Message)
		}
		return refusal(err, revertstore.RevertNothing, se.Message)
	default:
		if out := timedOut(err, se); out != nil {
			return out
		}
		return err
	}
}

// applyRevertRefusal maps ApplyRevert's errors: an expired revert, a
// signed revert with no row to restore, and every REVERT_INVALID, told
// apart by the guard's typed detail (applyReasons), the hint the sentence;
// any other detail is a signature the guard did not accept.
func applyRevertRefusal(err error) error {
	se := guardAnswer(err)
	if se == nil {
		return err
	}
	code := guard.Code(se.LedgerCode)
	switch {
	case code == guard.CodeRevertExpired:
		return refusal(err, revertstore.RevertExpiredReason, se.Detail)
	case code == guard.CodeNothingToRevert:
		return refusal(err, revertstore.RevertNothing, nothingSentence(se))
	case code != guard.CodeRevertInvalid:
		return err
	}
	if reason, ok := applyReasons[se.Detail]; ok {
		return refusal(err, reason, se.Hint)
	}
	return refusal(err, revertstore.RevertSignature, se.Detail)
}

// rescopeRevertRefusal maps RescopeRevert's errors: any scope the guard
// refused (the hint says why), a failed proof or token check, an expired
// revert, and the time limit.
func rescopeRevertRefusal(err error) error {
	se := guardAnswer(err)
	if se == nil {
		return err
	}
	code := guard.Code(se.LedgerCode)
	switch {
	case code == guard.CodeScopeRefused:
		return refusal(err, revertstore.RevertInvalid, se.Hint)
	case code == guard.CodeRevertInvalid && se.Detail == guard.RevertWidenRefused:
		return refusal(err, revertstore.RevertWidenRefused, se.Detail)
	case code == guard.CodeRevertExpired:
		return refusal(err, revertstore.RevertExpiredReason, se.Detail)
	}
	if out := timedOut(err, se); out != nil {
		return out
	}
	return err
}

// rejectRevertRefusal maps RejectRevert's errors: a failed scope token
// check, a revert the role did not prepare, an expired revert, and any
// other REVERT_INVALID (signed, applied or rejected meanwhile).
func rejectRevertRefusal(err error) error {
	return pendingRefusal(err, guard.RevertWidenRefused, revertstore.RevertWidenRefused)
}

// revealRevertRowsRefusal maps RevealRevertRows's errors: a failed reveal
// proof, a revert the role did not prepare, an expired revert, and any
// other REVERT_INVALID (signed, applied or rejected meanwhile).
func revealRevertRowsRefusal(err error) error {
	return pendingRefusal(err, guard.RevealRefused, revertstore.RevertRevealRefused)
}

// pendingRefusal maps the errors of a page call on a revert that must
// still wait for the person: REVERT_INVALID with detail proofDetail is
// proofReason.
func pendingRefusal(err error, proofDetail string, proofReason revertstore.RevertReason) error {
	se := guardAnswer(err)
	if se == nil {
		return err
	}
	code := guard.Code(se.LedgerCode)
	switch {
	case code == guard.CodeRevertInvalid && se.Detail == proofDetail:
		return refusal(err, proofReason, se.Detail)
	case code == guard.CodeRevertInvalid && se.Detail == revertNotFoundDetail:
		return refusal(err, revertstore.RevertNotFound, se.Detail)
	case code == guard.CodeRevertExpired:
		return refusal(err, revertstore.RevertExpiredReason, se.Detail)
	case code == guard.CodeRevertInvalid:
		return refusal(err, revertstore.RevertNotPending, se.Detail)
	}
	return err
}
