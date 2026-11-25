package localsetup

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Backend is what the setup reads and writes outside this package: the
// person's Postgres (the guard's install, labels, passkeys, pins, and the
// sample schema), the connection and its trust, and the engine's trust
// files. The engine wires it (internal/app); each method is the call it
// is named after, unchanged.
// Backend is what the local setup needs from its adapters, beyond what
// setup.SetuprunBackend gives the shared run: the admin connection and its trust,
// the credential files, and the guard's reads and writes of one install.
// ReadCredential is not a plain read: it refuses a connection string that
// makes the driver read a file (passfile, sslrootcert).
type Backend interface {
	setup.SetuprunBackend
	// Connections and their trust.
	Connect(ctx context.Context, dsn string) (*pgx.Conn, error)
	Trust() *trustprofile.Set
	ConnConfigPinned(dsn string, p *trustprofile.Profile) (*pgx.ConnConfig, error)
	// ReadCredential reads the agent's connection string at path and
	// refuses one that makes the driver read a file
	// (setup.ErrForeignCredential), so a root engine never connects
	// with what another user wrote.
	ReadCredential(path string) (string, error)
	ConnectionKeys() []string
	ConnectionKey(key string) bool
	CertificateNotVerified(err error) bool
	// PinFile and PinFileNew write the engine's trust profile for host.
	PinFile(configPath, host string, cert *x509.Certificate, caOnly bool) (*trustprofile.Profile, []string, error)
	PinFileNew(configPath, host string, cert *x509.Certificate, caOnly bool) (bool, error)

	// The guard's install.
	AgentStatus(ctx context.Context, q setup.Querier, migs []guardmodel.Migration) (guardmodel.Status, error)
	RepairScript(n guardmodel.Names, agent, password string, timeoutMs int64) (guardmodel.Script, error)
	NewPassword() string
	AgentConnString(adminURL, role, password string) (string, error)

	// Trust pins recorded in the database.
	RecordTrustPin(ctx context.Context, q setup.Querier, host string, port int, sha256 string) error
	RecordedTrustPin(ctx context.Context, q setup.Querier, host string, port int) (string, bool, error)
	RecordedTrustPinTx(ctx context.Context, tx pgx.Tx, n guardmodel.Names, host string, port int) (string, bool, error)

	// Column labels.
	PIIUnclassified(ctx context.Context, q setup.Querier) ([]guardmodel.UnclassifiedColumn, error)
	ReadLabels(ctx context.Context, conn *pgx.Conn, n guardmodel.Names, tables []string) ([]guardmodel.ColumnLabel, error)
	WriteLabels(ctx context.Context, tx pgx.Tx, n guardmodel.Names, tables []string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error)
	AgentUnlabeled(ctx context.Context, tx pgx.Tx, n guardmodel.Names, role string) ([]guardmodel.AgentColumn, error)
	WriteAgentLabels(ctx context.Context, tx pgx.Tx, n guardmodel.Names, role string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error)

	// The classifier's reads.
	// PIIColumns fills the listed columns (by namespace, resource, name and
	// data type) with their Kind, Key and Generated from the store's
	// catalog. It always returns len(listed) columns with a Kind; a failed
	// catalog read leaves Key and Generated unset and is the error.
	PIIColumns(ctx context.Context, conn *pgx.Conn, listed []piistore.Column) ([]piistore.Column, error)
	// PIISampler reads a column's sample on conn: each read in a read-only
	// transaction under timeout, each value cut to maxChars characters.
	PIISampler(conn *pgx.Conn, timeout time.Duration, maxChars int) func(ctx context.Context, col piistore.Column) (piistore.Sample, error)

	// Passkeys.
	ActivePasskeys(ctx context.Context, q setup.Querier) ([]guardmodel.RegisteredPasskey, error)
	RegisterPasskey(ctx context.Context, q setup.Querier, cred passkey.Credential, label string) error
	RevokePasskey(ctx context.Context, q setup.Querier, credentialID []byte, force bool) (int, error)
	// ListPasskeys lists the active passkeys the connection's role may read.
	ListPasskeys(ctx context.Context, q setup.Querier) ([]setup.ActivePasskey, error)

	// The sample schema.
	DemoTables() []string
	SeedDemo(ctx context.Context, tx pgx.Tx) (guardmodel.DemoPlan, error)
	DemoCounts(ctx context.Context, q setup.Querier) (leads, notes int, err error)
}
