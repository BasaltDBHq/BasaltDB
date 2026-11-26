package setupstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// The setup contract's side of the database (the setup service's
// ContractBackend, for pkg/setup): the setup's transaction on the admin
// connection, the column labels, the trust pin, the passkeys and who the
// connection is. The local setup page's backend shares the label, trust pin
// and passkey calls.

// Port is the admin connection conn as the setup's query port.
func Port(conn *pgx.Conn) sqlport.Port { return pgquerier.Neutralize(conn) }

// BeginTx begins a transaction on the connection q runs on, and returns
// its query port.
func (Store) BeginTx(ctx context.Context, q sqlport.Port) (sqlport.Port, error) {
	conn, err := connOf(q)
	if err != nil {
		return nil, err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return pgquerier.Neutralize(tx), nil
}

// CommitTx commits the transaction BeginTx made.
func (Store) CommitTx(ctx context.Context, tx sqlport.Port) error {
	t, err := unwrapTx(tx)
	if err != nil {
		return err
	}
	return t.Commit(ctx)
}

// RollbackTx rolls the transaction BeginTx made back; after a commit, a
// no-op.
func (Store) RollbackTx(ctx context.Context, tx sqlport.Port) error {
	t, err := unwrapTx(tx)
	if err != nil {
		return err
	}
	return t.Rollback(ctx)
}

// ConnectedAs is what q reached, as the server says it:
// current_database() and session_user.
func (Store) ConnectedAs(ctx context.Context, q sqlport.Port) (database, user string, err error) {
	// A catalog function and a SQL keyword squirrel cannot express.
	err = q.QueryRow(ctx, `SELECT pg_catalog.current_database()::text, session_user::text`).Scan(&database, &user)
	return database, user, err
}

// PasskeysInstalled reports whether the database has the guard's passkeys
// table.
func (Store) PasskeysInstalled(ctx context.Context, q sqlport.Port) (bool, error) {
	var installed bool
	// Plain SQL: a catalog presence check.
	err := q.QueryRow(ctx, "SELECT pg_catalog.to_regclass('basalt_meta.passkeys') IS NOT NULL").Scan(&installed)
	return installed, err
}

func (Store) ReadLabels(ctx context.Context, q sqlport.Port, n guardmodel.Names, tables []string) ([]guardmodel.ColumnLabel, error) {
	conn, err := connOf(q)
	if err != nil {
		return nil, err
	}
	return guard.ReadLabels(ctx, conn, n, tables)
}

func (Store) ReadReadableLabels(ctx context.Context, q sqlport.Port, n guardmodel.Names) ([]guardmodel.ColumnLabel, error) {
	conn, err := connOf(q)
	if err != nil {
		return nil, err
	}
	return guard.ReadReadableLabels(ctx, conn, n)
}

func (Store) ReadableTables(ctx context.Context, q sqlport.Port, n guardmodel.Names) ([]string, error) {
	tx, err := unwrapTx(q)
	if err != nil {
		return nil, err
	}
	return guard.ReadableTables(ctx, tx, n)
}

func (Store) WriteLabels(ctx context.Context, q sqlport.Port, n guardmodel.Names, tables []string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error) {
	tx, err := unwrapTx(q)
	if err != nil {
		return 0, err
	}
	return guard.WriteLabels(ctx, tx, n, tables, changes, restPublic, at)
}

func (Store) RecordTrustPin(ctx context.Context, q sqlport.Port, host string, port int, sha256 string) error {
	return guard.RecordTrustPin(ctx, pgquerier.Unwrap(q), host, port, sha256)
}

func (Store) ActivePasskeys(ctx context.Context, q sqlport.Port) ([]guardmodel.RegisteredPasskey, error) {
	return guard.ActivePasskeys(ctx, pgquerier.Unwrap(q))
}

func (Store) RegisterPasskey(ctx context.Context, q sqlport.Port, cred passkey.Credential, label string) error {
	return guard.RegisterPasskey(ctx, pgquerier.Unwrap(q), cred, label)
}

// connOf is the connection q runs on: the reads that open transactions of
// their own need it.
func connOf(q sqlport.Port) (*pgx.Conn, error) {
	c, ok := pgquerier.Unwrap(q).(*pgx.Conn)
	if !ok {
		return nil, errors.New("setupstore: the call needs a connection, not a transaction")
	}
	return c, nil
}
