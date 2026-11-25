package pluginledger

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// SQLSTATEs that say the guard is older than the call needs, or missing.
const (
	sqlstateUndefinedFunction = "42883"
	sqlstateUndefinedTable    = "42P01"
	sqlstateInvalidSchemaName = "3F000"
)

// MapError maps the database's answer in err to the plugin's typed one
// (pluginmodel.StoreError), wrapping err: an undefined function is a guard
// older than the call, an undefined table or schema a missing guard, a
// guard error the guard's refusal, and any other a plain answer. An error
// the database did not answer (no PgError in its chain), or one already
// mapped, is returned as it is. Every Ledger method maps its errors; the
// app maps the agent's admission with it too, whose probe reads the same
// database.
func MapError(err error) error {
	if err == nil || pluginmodel.StoreErrorOf(err) != nil {
		return err
	}
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return err
	}
	se := &pluginmodel.StoreError{Reason: pluginmodel.StoreAnswered, Code: pg.Code, Message: pg.Message, Err: err}
	switch pg.Code {
	case sqlstateUndefinedFunction:
		se.Reason = pluginmodel.StoreGuardOutdated
	case sqlstateUndefinedTable, sqlstateInvalidSchemaName:
		se.Reason = pluginmodel.StoreGuardMissing
	default:
		if _, ok := guard.CodeOf(err); ok {
			se.Reason = pluginmodel.StoreRefused
		}
	}
	return se
}

// openApprovalError is MapError for open_plugin_approval, whose
// NOT_ALLOWED details name a full approval queue and an unknown agent.
func openApprovalError(err error) error {
	err = MapError(err)
	se := pluginmodel.StoreErrorOf(err)
	if se == nil || se.Reason != pluginmodel.StoreRefused {
		return err
	}
	var pg *pgconn.PgError
	if code, _ := guard.CodeOf(err); code != guard.CodeNotAllowed || !errors.As(err, &pg) {
		return err
	}
	switch pg.Detail {
	case guard.DetailTooManyPending:
		se.Reason = pluginmodel.StoreTooManyPending
	case guard.DetailUnknownAgent:
		se.Reason = pluginmodel.StoreUnknownAgent
	}
	return err
}
