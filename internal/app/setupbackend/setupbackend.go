// Package setupbackend is the setup page's access to the person's
// Postgres, the connection and its trust, and the engine's trust files: it
// forwards each call of the setup's Backend to the adapter that does it.
package setupbackend

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/demo"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgpii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Backend implements localsetup's Backend: the setup store (which is also
// internal/setup's backend) and the connection, trust and passkey calls localsetup
// makes itself.
type Backend struct{ setupstore.Store }

// Connections and their trust.

func (Backend) Connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	return pgdial.Connect(ctx, dsn)
}

// ReadCredential reads the agent's connection string and refuses one with
// parameters that make the driver read a file, in one step: as root, the
// read is never used without the check.
func (Backend) ReadCredential(path string) (string, error) {
	dsn, err := config.ReadCredential(path)
	if err != nil {
		return "", err
	}
	if pgdial.CheckForeignDSN(dsn) != nil {
		return "", setup.ErrForeignCredential
	}
	return dsn, nil
}

func (Backend) Trust() *trustprofile.Set { return pgdial.Trust() }
func (Backend) ConnConfigPinned(dsn string, p *trustprofile.Profile) (*pgx.ConnConfig, error) {
	return pgdial.ConnConfigPinned(dsn, p)
}
func (Backend) ConnectionKeys() []string              { return pgdial.ConnectionKeys() }
func (Backend) ConnectionKey(key string) bool         { return pgdial.ConnectionKey(key) }
func (Backend) CertificateNotVerified(err error) bool { return pgdial.CertificateNotVerified(err) }
func (Backend) PinFile(configPath, host string, cert *x509.Certificate, caOnly bool) (*trustprofile.Profile, []string, error) {
	return trustdir.Pin(configPath, host, cert, caOnly)
}

func (Backend) PinFileNew(configPath, host string, cert *x509.Certificate, caOnly bool) (bool, error) {
	return trustdir.PinNew(configPath, host, cert, caOnly)
}

// The guard's install.

func (Backend) AgentStatus(ctx context.Context, q setup.Querier, migs []guardmodel.Migration) (guardmodel.Status, error) {
	return guard.AgentStatus(ctx, pgquerier.Unwrap(q), migs)
}

func (Backend) RepairScript(n guardmodel.Names, agent, password string, timeoutMs int64) (guardmodel.Script, error) {
	return guard.RepairScript(n, agent, password, timeoutMs)
}

func (Backend) NewPassword() string { return guard.NewPassword() }
func (Backend) AgentConnString(adminURL, role, password string) (string, error) {
	return guard.AgentConnString(adminURL, role, password)
}

// Trust pins recorded in the database.

func (Backend) RecordTrustPin(ctx context.Context, q setup.Querier, host string, port int, sha256 string) error {
	return guard.RecordTrustPin(ctx, pgquerier.Unwrap(q), host, port, sha256)
}

func (Backend) RecordedTrustPin(ctx context.Context, q setup.Querier, host string, port int) (string, bool, error) {
	return guard.RecordedTrustPin(ctx, pgquerier.Unwrap(q), host, port)
}

func (Backend) RecordedTrustPinTx(ctx context.Context, tx pgx.Tx, n guardmodel.Names, host string, port int) (string, bool, error) {
	return guard.RecordedTrustPinTx(ctx, tx, n, host, port)
}

// Column labels.

func (Backend) PIIUnclassified(ctx context.Context, q setup.Querier) ([]guardmodel.UnclassifiedColumn, error) {
	return guard.PIIUnclassified(ctx, pgquerier.Unwrap(q))
}

func (Backend) ReadLabels(ctx context.Context, conn *pgx.Conn, n guardmodel.Names, tables []string) ([]guardmodel.ColumnLabel, error) {
	return guard.ReadLabels(ctx, conn, n, tables)
}

func (Backend) WriteLabels(ctx context.Context, tx pgx.Tx, n guardmodel.Names, tables []string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error) {
	return guard.WriteLabels(ctx, tx, n, tables, changes, restPublic, at)
}

func (Backend) AgentUnlabeled(ctx context.Context, tx pgx.Tx, n guardmodel.Names, role string) ([]guardmodel.AgentColumn, error) {
	return guard.AgentUnlabeled(ctx, tx, n, role)
}

func (Backend) WriteAgentLabels(ctx context.Context, tx pgx.Tx, n guardmodel.Names, role string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error) {
	return guard.WriteAgentLabels(ctx, tx, n, role, changes, restPublic, at)
}

// The classifier's reads.

func (Backend) PIIColumns(ctx context.Context, conn *pgx.Conn, listed []piistore.Column) ([]piistore.Column, error) {
	return pgpii.Columns(ctx, pgquerier.Neutralize(conn), listed)
}

func (Backend) PIISampler(conn *pgx.Conn, timeout time.Duration, maxChars int) func(context.Context, piistore.Column) (piistore.Sample, error) {
	return pgpii.Sampler{ReadOnly: pgquerier.ReadOnlyTx(conn), Timeout: timeout, MaxChars: maxChars}.Sample
}

// Passkeys.

func (Backend) ActivePasskeys(ctx context.Context, q setup.Querier) ([]guardmodel.RegisteredPasskey, error) {
	return guard.ActivePasskeys(ctx, pgquerier.Unwrap(q))
}

func (Backend) RegisterPasskey(ctx context.Context, q setup.Querier, cred passkey.Credential, label string) error {
	return guard.RegisterPasskey(ctx, pgquerier.Unwrap(q), cred, label)
}

func (Backend) RevokePasskey(ctx context.Context, q setup.Querier, credentialID []byte, force bool) (int, error) {
	return guard.RevokePasskey(ctx, pgquerier.Unwrap(q), credentialID, force)
}

func (Backend) ListPasskeys(ctx context.Context, q setup.Querier) ([]setup.ActivePasskey, error) {
	keys, err := ledger.ListPasskeys(ctx, pgquerier.Unwrap(q))
	if err != nil {
		return nil, err
	}
	out := make([]setup.ActivePasskey, len(keys))
	for i, k := range keys {
		out[i] = setup.ActivePasskey{Credential: k.Credential, Label: k.Label, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt}
	}
	return out, nil
}

// The sample schema.

func (Backend) DemoTables() []string { return demo.Tables }

func (Backend) SeedDemo(ctx context.Context, tx pgx.Tx) (guardmodel.DemoPlan, error) {
	return demo.Seed(ctx, tx)
}

func (Backend) DemoCounts(ctx context.Context, q setup.Querier) (int, int, error) {
	return demo.Counts(ctx, pgquerier.Unwrap(q))
}
