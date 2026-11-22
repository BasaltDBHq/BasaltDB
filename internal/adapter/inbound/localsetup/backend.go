package localsetup

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/service/setuprun"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Backend is what the setup reads and writes outside this package: the
// person's Postgres (the guard's install, labels, passkeys, pins, and the
// sample schema), the connection and its trust, and the engine's trust
// files. The engine wires it (internal/app); each method is the call it
// is named after, unchanged.
type Backend interface {
	setuprun.Backend
	// Connections and their trust.
	Connect(ctx context.Context, dsn string) (*pgx.Conn, error)
	Trust() *trustprofile.Set
	ConnConfigPinned(dsn string, p *trustprofile.Profile) (*pgx.ConnConfig, error)
	// ReadCredential reads the agent's connection string at path and
	// refuses one that makes the driver read a file
	// (setuprun.ErrForeignCredential), so a root engine never connects
	// with what another user wrote.
	ReadCredential(path string) (string, error)
	ConnectionKeys() []string
	ConnectionKey(key string) bool
	CertificateNotVerified(err error) bool
	// PinFile and PinFileNew write the engine's trust profile for host.
	PinFile(configPath, host string, cert *x509.Certificate, caOnly bool) (*trustprofile.Profile, []string, error)
	PinFileNew(configPath, host string, cert *x509.Certificate, caOnly bool) (bool, error)

	// The guard's install.
	AgentStatus(ctx context.Context, q setuprun.Querier, migs []guardmodel.Migration) (guardmodel.Status, error)
	RepairScript(n guardmodel.Names, agent, password string, timeoutMs int64) (setuprun.Script, error)
	// UnusableInstall reports whether err is CheckUsable's refusal of an
	// older or partial install.
	NewPassword() string
	AgentConnString(adminURL, role, password string) (string, error)

	// Trust pins recorded in the database.
	RecordTrustPin(ctx context.Context, q setuprun.Querier, host string, port int, sha256 string) error
	RecordedTrustPin(ctx context.Context, q setuprun.Querier, host string, port int) (string, bool, error)
	RecordedTrustPinTx(ctx context.Context, tx pgx.Tx, n guardmodel.Names, host string, port int) (string, bool, error)

	// Column labels.
	PIIUnclassified(ctx context.Context, q setuprun.Querier) ([]guardmodel.UnclassifiedColumn, error)
	ReadLabels(ctx context.Context, conn *pgx.Conn, n guardmodel.Names, tables []string) ([]guardmodel.ColumnLabel, error)
	WriteLabels(ctx context.Context, tx pgx.Tx, n guardmodel.Names, tables []string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error)
	AgentUnlabeled(ctx context.Context, tx pgx.Tx, n guardmodel.Names, role string) ([]guardmodel.AgentColumn, error)
	WriteAgentLabels(ctx context.Context, tx pgx.Tx, n guardmodel.Names, role string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error)

	// Passkeys.
	ActivePasskeys(ctx context.Context, q setuprun.Querier) ([]setuprun.RegisteredPasskey, error)
	RegisterPasskey(ctx context.Context, q setuprun.Querier, cred passkey.Credential, label string) error
	RevokePasskey(ctx context.Context, q setuprun.Querier, credentialID []byte, force bool) (int, error)
	// ListPasskeys lists the active passkeys the connection's role may read.
	ListPasskeys(ctx context.Context, q setuprun.Querier) ([]setuprun.ActivePasskey, error)

	// The sample schema.
	DemoTables() []string
	SeedDemo(ctx context.Context, tx pgx.Tx) (setuprun.DemoPlan, error)
	DemoCounts(ctx context.Context, q setuprun.Querier) (leads, notes int, err error)
}
