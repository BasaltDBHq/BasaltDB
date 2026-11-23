package setup

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// Querier is the admin connection or transaction a plan or an apply runs on.
// It is an alias of the interface itself, so an adapter that cannot import
// this package still implements SetuprunBackend.
type Querier = interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ActivePasskey is an active passkey as the doctor lists it.
type ActivePasskey struct {
	Credential passkey.Credential
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// ErrForeignCredential is a credential file's string that makes the driver
// read a file of its own: it is never connected with.
var ErrForeignCredential = errors.New("the credential names a file the driver would read")
