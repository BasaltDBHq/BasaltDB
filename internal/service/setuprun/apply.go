package setuprun

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ApplyInitTx runs the script in the caller's transaction and refuses to
// commit while any agent-writable table or cascade target is left
// unguarded. The after statements run last, once that check passed (a
// setup code's record_setup).
func ApplyInitTx(ctx context.Context, b Backend, tx pgx.Tx, script Script, after ...Statement) error {
	if err := b.ApplyScript(ctx, tx, script); err != nil {
		return err
	}
	if err := checkCovered(ctx, b, tx); err != nil {
		return err
	}
	for _, st := range after {
		if err := b.Run(ctx, tx, st.SQL); err != nil {
			return fmt.Errorf("record the setup: %w", err)
		}
	}
	return nil
}

// checkCovered refuses, inside the install's transaction, while any
// agent-writable table or cascade target is left unguarded.
func checkCovered(ctx context.Context, b Backend, tx pgx.Tx) error {
	uncovered, err := b.UncoveredTables(ctx, tx)
	if err != nil {
		return err
	}
	if len(uncovered) > 0 {
		tables := make([]string, 0, len(uncovered))
		for _, u := range uncovered {
			tables = append(tables, u.Table+" ("+u.Why+")")
		}
		return fmt.Errorf("tables left unguarded: %s", strings.Join(tables, ", "))
	}
	return nil
}

// detailedError is a database error followed by the Detail and Hint the
// guard raised with it, which pgconn.PgError.Error leaves out.
type detailedError struct {
	err    error
	detail string
}

func (e *detailedError) Error() string { return e.err.Error() + ": " + e.detail }

func (e *detailedError) Unwrap() error { return e.err }

// WithGuardDetail adds the Detail and Hint of a database error to its text,
// so a refusal says which table is wrong and how to fix it ("table crm.nopk
// has no primary key; ..." and "add a primary key, or revoke ..."), not only
// "NOT_ALLOWED (SQLSTATE BS007)". An error with neither, or already
// carrying them, is returned as it is.
func WithGuardDetail(err error) error {
	var pg *pgconn.PgError
	var done *detailedError
	if err == nil || errors.As(err, &done) || !errors.As(err, &pg) || (pg.Detail == "" && pg.Hint == "") {
		return err
	}
	return &detailedError{err: err, detail: Sentences(pg.Detail, pg.Hint)}
}

// NothingChanged ends a failed install's error with "nothing changed": as a
// sentence after the guard's detail and hint (which end with a period), or
// after a semicolon otherwise.
func NothingChanged(err error) error {
	var done *detailedError
	if errors.As(err, &done) {
		return fmt.Errorf("%w Nothing changed.", err) //nolint:staticcheck,revive // full sentences after the database's message, shown as is
	}
	return fmt.Errorf("%w; nothing changed", err)
}

// Sentences joins the non-empty parts with one space, each ending with a
// period.
func Sentences(parts ...string) string {
	var out []string
	for _, s := range parts {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.HasSuffix(s, ".") {
			s += "."
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

// demoSchema is the schema of the M4 demo data (examples/demo/seed.sql).
const demoSchema = "basalt_demo."

// MissingTablesHint turns the guard's list of missing write and read
// tables into one refusal naming the database, and points at the demo seed
// when a demo table is missing. Other errors pass through.
func MissingTablesHint(b Backend, err error, database string) error {
	missing, ok := b.MissingTables(err)
	if !ok {
		return err
	}
	noun, verb := "table", "it"
	if len(missing) > 1 {
		noun, verb = "tables", "them"
	}
	msg := fmt.Sprintf("%s %s not found in database %q; create %s first", noun, strings.Join(missing, ", "), database, verb)
	for _, t := range missing {
		if strings.HasPrefix(t, demoSchema) {
			msg += " (basalt init --demo creates the sample tables)"
			break
		}
	}
	return refuse(CodeTablesMissing, msg)
}
