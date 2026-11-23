package pgdial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Login makes one login with dsn, trusting set's profiles (nil: Trust's), to
// the address ip only and over dial when it is set; when roots is set, every
// TLS attempt verifies the server's certificate against roots alone. A login
// that succeeds is closed at once. It is the hand-off probe's port
// (handoff.Prober.Login); a refusal comes back as pgx's error, which carries
// the SQLSTATE.
func Login(ctx context.Context, dsn string, set *trustprofile.Set, ip string, dial func(ctx context.Context, network, addr string) (net.Conn, error), roots *x509.CertPool) error {
	cfg, err := connConfigTrusting(dsn, set)
	if err != nil {
		return err
	}
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{ip}, nil }
	if dial != nil {
		cfg.DialFunc = dial
	}
	if roots != nil {
		setRoots(&cfg.Config, roots)
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	return conn.Close(ctx)
}

// setRoots verifies every TLS attempt of cfg against roots.
func setRoots(cfg *pgconn.Config, roots *x509.CertPool) {
	set := func(t *tls.Config) {
		if t != nil {
			t.RootCAs = roots
		}
	}
	set(cfg.TLSConfig)
	for _, fb := range cfg.Fallbacks {
		set(fb.TLSConfig)
	}
}
