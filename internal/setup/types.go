package setup

import (
	"context"
	"errors"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// Rows, Row and Result are the parts of a query's answer the setup code
// reads. They are written as unnamed interfaces so that any adapter's types
// of the same shape are the same types, with no import of this package.
type (
	Rows = interface {
		Close()
		Err() error
		Next() bool
		Scan(dest ...any) error
	}
	Row    = interface{ Scan(dest ...any) error }
	Result = interface{ RowsAffected() int64 }
)

// Querier is the admin connection or transaction a plan or an apply runs on.
// It is an alias of the interface itself, so an adapter that cannot import
// this package still implements Backend.
type Querier = interface {
	Exec(ctx context.Context, sql string, args ...any) (Result, error)
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) Row
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
