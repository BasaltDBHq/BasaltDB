package localsetup

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Conn and Tx are the connections and transactions the backend opens
// (setup.Conn, setup.Tx).
type (
	Conn = setup.Conn
	Tx   = setup.Tx
)

// CatalogTable is one table of an install's listing, as the catalog has it
// (an alias of the struct, as the store declares it).
type CatalogTable = struct {
	Name  string
	Owner string
	Mine  bool
	Keyed bool
	Plain bool
}

// Backend is what the local setup needs from its adapters, beyond what
// setup.SetuprunBackend gives the shared run: the connections and their
// trust, the credential files, and the guard's reads and writes of one
// install. The engine wires it (internal/app). Every call that reads or
// writes the database runs on the query port it is given (Conn.Port,
// Tx.Port). ReadCredential is not a plain read: it refuses a connection
// string that makes the driver read a file (passfile, sslrootcert).
type Backend interface {
	setup.SetuprunBackend
	// Connections and their trust.
	Connect(ctx context.Context, dsn string) (Conn, error)
	// ConnectPinned opens dsn trusting only p's certificate for its host.
	ConnectPinned(ctx context.Context, dsn string, p *trustprofile.Profile) (Conn, error)
	Trust() *trustprofile.Set
	// ParseTarget is what dsn names, as the driver parses it.
	ParseTarget(dsn string) (setup.Target, error)
	// ExplainTrust is what verifies the certificate of dsn's first host with
	// set's profiles.
	ExplainTrust(dsn string, set *trustprofile.Set) (trustprofile.Applied, error)
	// ConnHost is the host and port conn reached.
	ConnHost(conn Conn) (host string, port int)
	// ConnCertificate is conn's certificate for the confirm step: kind is
	// what the dial verified it with, provider the built-in profile's name
	// with certProvider. It returns the kind shown and the issuer.
	ConnCertificate(conn Conn, kind, provider string) (shown, issuer string)
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

	// The database's errors.
	// DatabaseError is the message and detail of the database error in
	// err; false when err carries none.
	DatabaseError(err error) (message, detail string, ok bool)
	// CommitAnswered reports whether a failed commit's outcome is known:
	// answered with an error, turned into a rollback, or never sent.
	CommitAnswered(err error) bool

	// The session and the catalog.
	CurrentUser(ctx context.Context, q setup.Querier) (string, error)
	SessionUser(ctx context.Context, q setup.Querier) (string, error)
	CurrentUserAndDatabase(ctx context.Context, q setup.Querier) (user, database string, err error)
	// IsMember reports whether role is a member of group.
	IsMember(ctx context.Context, q setup.Querier, role, group string) (bool, error)
	// ListTables reads at most limit tables of schemas, in schema and table
	// order.
	ListTables(ctx context.Context, q setup.Querier, schemas []string, limit int) ([]CatalogTable, error)
	// ListColumns reads at most limit ordinary columns of tables, in the
	// tables' order and then the columns'.
	ListColumns(ctx context.Context, q setup.Querier, tables []string, limit int) ([]piistore.Column, error)

	// The guard's install.
	AgentStatus(ctx context.Context, q setup.Querier, migs []guardmodel.Migration) (guardmodel.Status, error)
	RepairScript(n guardmodel.Names, agent, password string, timeoutMs int64) (guardmodel.Script, error)
	NewPassword() string
	AgentConnString(adminURL, role, password string) (string, error)

	// Trust pins recorded in the database.
	RecordTrustPin(ctx context.Context, q setup.Querier, host string, port int, sha256 string) error
	RecordedTrustPin(ctx context.Context, q setup.Querier, host string, port int) (string, bool, error)
	// RecordedTrustPinTx runs on a transaction's port.
	RecordedTrustPinTx(ctx context.Context, tx setup.Querier, n guardmodel.Names, host string, port int) (string, bool, error)

	// Column labels. ReadLabels runs on a connection's port; the others on
	// a transaction's.
	PIIUnclassified(ctx context.Context, q setup.Querier) ([]guardmodel.UnclassifiedColumn, error)
	ReadLabels(ctx context.Context, conn setup.Querier, n guardmodel.Names, tables []string) ([]guardmodel.ColumnLabel, error)
	WriteLabels(ctx context.Context, tx setup.Querier, n guardmodel.Names, tables []string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error)
	AgentUnlabeled(ctx context.Context, tx setup.Querier, n guardmodel.Names, role string) ([]guardmodel.AgentColumn, error)
	WriteAgentLabels(ctx context.Context, tx setup.Querier, n guardmodel.Names, role string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error)

	// The classifier's reads, on a connection's port.
	// PIIColumns fills the listed columns (by namespace, resource, name and
	// data type) with their Kind, Key and Generated from the store's
	// catalog. It always returns len(listed) columns with a Kind; a failed
	// catalog read leaves Key and Generated unset and a domain's base type
	// unread (so a domain over text gets its own type's kind and goes
	// unsampled), and is the error.
	PIIColumns(ctx context.Context, conn setup.Querier, listed []piistore.Column) ([]piistore.Column, error)
	// PIISampler reads a column's sample on conn: each read in a read-only
	// transaction under timeout, each value cut to maxChars characters.
	PIISampler(conn setup.Querier, timeout time.Duration, maxChars int) func(ctx context.Context, col piistore.Column) (piistore.Sample, error)

	// Passkeys.
	ActivePasskeys(ctx context.Context, q setup.Querier) ([]guardmodel.RegisteredPasskey, error)
	RegisterPasskey(ctx context.Context, q setup.Querier, cred passkey.Credential, label string) error
	RevokePasskey(ctx context.Context, q setup.Querier, credentialID []byte, force bool) (int, error)
	// ListPasskeys lists the active passkeys the connection's role may read.
	ListPasskeys(ctx context.Context, q setup.Querier) ([]setup.ActivePasskey, error)

	// The sample schema.
	DemoTables() []string
	// SeedDemo runs on a transaction's port.
	SeedDemo(ctx context.Context, tx setup.Querier) (guardmodel.DemoPlan, error)
	DemoCounts(ctx context.Context, q setup.Querier) (leads, notes int, err error)
}
