package pgdial

import (
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// TrustOf is what verifies the certificate of dsn's first host (TrustOfConfig).
func TrustOf(dsn string) (trustprofile.Applied, []trustprofile.Refused, error) {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return trustprofile.Applied{}, nil, err
	}
	a, refused := TrustOfConfig(cfg)
	return a, refused, nil
}
