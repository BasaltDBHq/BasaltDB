package setup

import "context"

// Conn is a connection a setup's adapter opened to the person's database:
// the query port the backend's calls run on, its transactions and its
// close. The setup runs no SQL on it itself.
type Conn interface {
	Port() Querier
	Begin(ctx context.Context) (Tx, error)
	Close(ctx context.Context) error
}

// Tx is a transaction on a Conn, or a savepoint in one (Begin). Rolling
// back a transaction that already ended is not an error.
type Tx interface {
	Port() Querier
	Begin(ctx context.Context) (Tx, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// Target is what a connection string names, as the driver parses it: the
// first host, its port, the database and the user, and the driver's
// fallbacks after the first.
type Target struct {
	Host      string
	Port      int
	Database  string
	User      string
	Fallbacks []HostPort
}

// HostPort is one host of a connection string and its port.
type HostPort struct {
	Host string
	Port int
}
