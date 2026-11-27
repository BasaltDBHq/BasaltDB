package store

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgstatement"
)

// Check parses sql and applies the engine's SQL policy for tool
// (pgstatement.Check). It returns the checked statement, whose handle carries
// the row sources Read versions, or an *action.RefusalError with as
// much of the statement as was classified (a refused statement's op is
// still recorded).
func (s *Store) Check(sql string, tool action.Tool) (action.Statement, error) {
	return Check(sql, tool)
}

// Check is Store.Check, which needs no connection.
func Check(sql string, tool action.Tool) (action.Statement, error) {
	stmt, err := pgstatement.Check(sql, tool)
	return statementOf(stmt), err
}

// HeldFrom reports whether held is exactly what holdPlan made of sent: sent
// with the times it fixed, and for an INSERT without a column list the
// columns it added from the table's defaults, read again from the catalog
// (pgstatement.FixedFrom). The agent may send its own text again with the
// approval.
func (s *Store) HeldFrom(ctx context.Context, held, sent string) (bool, error) {
	h, err := pgstatement.CheckRepeatable(sent, nil)
	if err != nil {
		return false, nil //nolint:nilerr // a statement the hold refuses was not held
	}
	var columns []pgstatement.Column
	if h.Assigned == nil {
		if columns, err = s.TableColumns(ctx, h.Table); err != nil {
			return false, err
		}
	}
	return pgstatement.FixedFrom(held, sent, columns), nil
}

// holdPlan returns the request a held write is held as, and the columns
// whose new values the person's approval binds: the ones it assigns, or
// for an INSERT without a column list every column of its table
// (TableColumns). The time functions it uses (now(), CURRENT_TIMESTAMP,
// ...) are evaluated once, here, and held as typed literals, and so are
// those in the defaults of the columns such an INSERT leaves out
// (pgstatement.PlanTimes), so the preview, the held statement and the applied
// write carry the same value. A write with another value that changes
// between runs is refused (*action.RefusalError NOT_REPEATABLE): a held
// write is run again when the person signs.
func (s *Store) holdPlan(ctx context.Context, req agentstore.Request) (agentstore.Request, []string, error) {
	h, err := pgstatement.CheckRepeatable(req.Text, req.Params)
	if err != nil {
		return req, nil, err
	}
	assigned := h.Assigned
	var columns []pgstatement.Column
	if assigned == nil {
		if columns, err = s.TableColumns(ctx, h.Table); err != nil {
			return req, nil, err
		}
		assigned = make([]string, 0, len(columns))
		for _, c := range columns {
			if !c.Generated {
				assigned = append(assigned, c.Name)
			}
		}
	}
	fix, err := pgstatement.PlanTimes(req.Text, columns)
	if err != nil {
		return req, nil, err
	}
	if fix.Eval == "" {
		return req, assigned, nil
	}
	values, err := s.fixedTimes(ctx, fix.Eval)
	if err != nil {
		return req, nil, err
	}
	text, err := fix.Apply(values)
	if err != nil {
		return req, nil, err
	}
	// The held statement is checked again when it applies: refuse it now
	// rather than hold a write that could never apply.
	if _, err := pgstatement.Check(text, action.ToolWrite); err != nil {
		return req, nil, err
	}
	return agentstore.Request{Text: text, Params: req.Params}, assigned, nil
}

// statementOf is the checked statement as the service takes it: the row
// sources a recorded read versions travel as its opaque handle.
func statementOf(stmt pgstatement.Statement) action.Statement {
	return action.Statement{Op: stmt.Op, Tables: stmt.Tables, Target: stmt.Target, ParamCount: stmt.ParamCount, Handle: stmt.RowSources}
}
