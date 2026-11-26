package pgdial

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Target is what a connection string names, as the driver parses it (its
// query parameters and the environment included): the first host, its port,
// the database and the user, and the fallbacks the driver would try after
// the first. It opens nothing.
type Target struct {
	Host     string
	Port     int
	Database string
	User     string
	// Fallbacks are the driver's fallbacks after the first, each a host and
	// its port (one host can come twice, with and without TLS).
	Fallbacks []HostPort
}

// HostPort is one host of a connection string and its port.
type HostPort struct {
	Host string
	Port int
}

// ParseTarget is the Target of dsn.
func ParseTarget(dsn string) (Target, error) {
	pc, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return Target{}, err
	}
	t := Target{Host: pc.Host, Port: int(pc.Port), Database: pc.Database, User: pc.User}
	for _, fb := range pc.Fallbacks {
		t.Fallbacks = append(t.Fallbacks, HostPort{Host: fb.Host, Port: int(fb.Port)})
	}
	return t, nil
}

// ExplainWith is what verifies the certificate of dsn's first host with
// set's profiles (trustprofile.Explain), dsn parsed as the driver parses it.
func ExplainWith(dsn string, set *trustprofile.Set) (trustprofile.Applied, error) {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return trustprofile.Applied{}, err
	}
	return trustprofile.Explain(cfg, set), nil
}

// ConnectPinned opens one connection to dsn that trusts only p's
// certificate for its host (ConnConfigPinned).
func ConnectPinned(ctx context.Context, dsn string, p *trustprofile.Profile) (*pgx.Conn, error) {
	cfg, err := ConnConfigPinned(dsn, p)
	if err != nil {
		return nil, err
	}
	return pgx.ConnectConfig(ctx, cfg)
}
