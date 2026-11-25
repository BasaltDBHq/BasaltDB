package store

import (
	"context"
	"errors"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/sqlguard"
)

// Check parses sql and applies the engine's SQL policy for tool
// (sqlguard.Check). It returns the checked statement, whose handle carries
// the row sources Read versions, or an *action.RefusalError with as
// much of the statement as was classified (a refused statement's op is
// still recorded).
func (s *Store) Check(sql string, tool action.Tool) (action.Statement, error) {
	return Check(sql, tool)
}

// Check is Store.Check, which needs no connection.
func Check(sql string, tool action.Tool) (action.Statement, error) {
	stmt, err := sqlguard.Check(sql, sqlguard.Tool(tool))
	return statementOf(stmt), refusalOf(err)
}

// holdColumns returns the columns whose new values the person's approval
// binds for a held write: the ones it assigns, or for an INSERT without a
// column list every column of its table (TableColumns). A write whose
// values change between runs is refused (*action.RefusalError
// NOT_REPEATABLE): a held write is run again when the person signs.
func (s *Store) holdColumns(ctx context.Context, sql string, params []any) ([]string, error) {
	h, err := sqlguard.CheckRepeatable(sql, params)
	if err != nil {
		return nil, refusalOf(err)
	}
	if h.Assigned != nil {
		return h.Assigned, nil
	}
	return s.TableColumns(ctx, h.Table)
}

// statementOf is the checked statement as the service takes it: the row
// sources a recorded read versions travel as its opaque handle.
func statementOf(stmt sqlguard.Statement) action.Statement {
	return action.Statement{Op: action.Op(stmt.Op), Tables: stmt.Tables, ParamCount: stmt.ParamCount, Handle: stmt.RowSources}
}

// refusalOf is a policy refusal as an *action.RefusalError with the
// same reason; any other error as it is.
func refusalOf(err error) error {
	var re *sqlguard.RefusalError
	if !errors.As(err, &re) {
		return err
	}
	return &action.RefusalError{Reason: action.RefusalReason(re.Reason), Detail: re.Detail}
}
