// Package setupbackend is the setup page's access to the person's
// Postgres, the connection and its trust, and the engine's trust files: it
// forwards each call of the setup's Backend to the adapter that does it.
package setupbackend

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/demo"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/setupstore"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/service/setuprun"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Backend implements localsetup's Backend: the setup store (which is also
// setuprun's backend) and the connection, trust and passkey calls localsetup
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
		return "", setuprun.ErrForeignCredential
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

func (Backend) AgentStatus(ctx context.Context, q setuprun.Querier, migs []guardmodel.Migration) (guardmodel.Status, error) {
	return guard.AgentStatus(ctx, q, migs)
}

func (Backend) RepairScript(n guardmodel.Names, agent, password string, timeoutMs int64) (guardmodel.Script, error) {
	return guard.RepairScript(n, agent, password, timeoutMs)
}

func (Backend) NewPassword() string { return guard.NewPassword() }
func (Backend) AgentConnString(adminURL, role, password string) (string, error) {
	return guard.AgentConnString(adminURL, role, password)
}

// Trust pins recorded in the database.

func (Backend) RecordTrustPin(ctx context.Context, q setuprun.Querier, host string, port int, sha256 string) error {
	return guard.RecordTrustPin(ctx, q, host, port, sha256)
}

func (Backend) RecordedTrustPin(ctx context.Context, q setuprun.Querier, host string, port int) (string, bool, error) {
	return guard.RecordedTrustPin(ctx, q, host, port)
}

func (Backend) RecordedTrustPinTx(ctx context.Context, tx pgx.Tx, n guardmodel.Names, host string, port int) (string, bool, error) {
	return guard.RecordedTrustPinTx(ctx, tx, n, host, port)
}

// Column labels.

func (Backend) PIIUnclassified(ctx context.Context, q setuprun.Querier) ([]guardmodel.UnclassifiedColumn, error) {
	return guard.PIIUnclassified(ctx, q)
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

// Passkeys.

func (Backend) ActivePasskeys(ctx context.Context, q setuprun.Querier) ([]guardmodel.RegisteredPasskey, error) {
	return guard.ActivePasskeys(ctx, q)
}

func (Backend) RegisterPasskey(ctx context.Context, q setuprun.Querier, cred passkey.Credential, label string) error {
	return guard.RegisterPasskey(ctx, q, cred, label)
}

func (Backend) RevokePasskey(ctx context.Context, q setuprun.Querier, credentialID []byte, force bool) (int, error) {
	return guard.RevokePasskey(ctx, q, credentialID, force)
}

func (Backend) ListPasskeys(ctx context.Context, q setuprun.Querier) ([]setuprun.ActivePasskey, error) {
	keys, err := ledger.ListPasskeys(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]setuprun.ActivePasskey, len(keys))
	for i, k := range keys {
		out[i] = setuprun.ActivePasskey{Credential: k.Credential, Label: k.Label, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt}
	}
	return out, nil
}

// The sample schema.

func (Backend) DemoTables() []string { return demo.Tables }

func (Backend) SeedDemo(ctx context.Context, tx pgx.Tx) (guardmodel.DemoPlan, error) {
	return demo.Seed(ctx, tx)
}

func (Backend) DemoCounts(ctx context.Context, q setuprun.Querier) (int, int, error) {
	return demo.Counts(ctx, q)
}
