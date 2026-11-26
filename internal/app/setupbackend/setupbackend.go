// Package setupbackend is the setup page's access to the person's
// Postgres, the connection and its trust, and the engine's trust files: it
// forwards each call of the setup's Backend to the adapter that does it.
package setupbackend

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/demo"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgpii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/enginefiles"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
	psetup "github.com/basaltdbhq/basaltdb/pkg/setup"
	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Backend implements localsetup's Backend: the setup store (which is also
// internal/setup's backend) and the connection, trust and passkey calls localsetup
// makes itself.
type Backend struct {
	setupstore.Store
	enginefiles.Files
}

// Connections and their trust.

func (Backend) Connect(ctx context.Context, dsn string) (setup.Conn, error) {
	return Wrap(pgdial.Connect(ctx, dsn))
}

func (Backend) ConnectPinned(ctx context.Context, dsn string, p *trustprofile.Profile) (setup.Conn, error) {
	return Wrap(pgdial.ConnectPinned(ctx, dsn, p))
}

func (Backend) ParseTarget(dsn string) (setup.Target, error) {
	t, err := pgdial.ParseTarget(dsn)
	if err != nil {
		return setup.Target{}, err
	}
	out := setup.Target{Host: t.Host, Port: t.Port, Database: t.Database, User: t.User}
	for _, fb := range t.Fallbacks {
		out.Fallbacks = append(out.Fallbacks, setup.HostPort{Host: fb.Host, Port: fb.Port})
	}
	return out, nil
}

func (Backend) ExplainTrust(dsn string, set *trustprofile.Set) (trustprofile.Applied, error) {
	return pgdial.ExplainWith(dsn, set)
}

func (Backend) ConnHost(c setup.Conn) (string, int) {
	cfg := pgxConn(c).Config()
	return cfg.Host, int(cfg.Port)
}

func (Backend) ConnCertificate(c setup.Conn, kind, provider string) (string, string) {
	cert := psetup.CertificateOf(pgxConn(c), psetup.CertificateKind(kind), provider)
	return string(cert.Kind), cert.Issuer
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

func (Backend) Trust() *trustprofile.Set              { return pgdial.Trust() }
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

func (Backend) RecordedTrustPinTx(ctx context.Context, q setup.Querier, n guardmodel.Names, host string, port int) (string, bool, error) {
	tx, err := pgxTx(q)
	if err != nil {
		return "", false, err
	}
	return guard.RecordedTrustPinTx(ctx, tx, n, host, port)
}

// Column labels.

func (Backend) PIIUnclassified(ctx context.Context, q setup.Querier) ([]guardmodel.UnclassifiedColumn, error) {
	return guard.PIIUnclassified(ctx, pgquerier.Unwrap(q))
}

func (Backend) ReadLabels(ctx context.Context, q setup.Querier, n guardmodel.Names, tables []string) ([]guardmodel.ColumnLabel, error) {
	conn, err := pgxConnOf(q)
	if err != nil {
		return nil, err
	}
	return guard.ReadLabels(ctx, conn, n, tables)
}

func (Backend) WriteLabels(ctx context.Context, q setup.Querier, n guardmodel.Names, tables []string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error) {
	tx, err := pgxTx(q)
	if err != nil {
		return 0, err
	}
	return guard.WriteLabels(ctx, tx, n, tables, changes, restPublic, at)
}

func (Backend) AgentUnlabeled(ctx context.Context, q setup.Querier, n guardmodel.Names, role string) ([]guardmodel.AgentColumn, error) {
	tx, err := pgxTx(q)
	if err != nil {
		return nil, err
	}
	return guard.AgentUnlabeled(ctx, tx, n, role)
}

func (Backend) WriteAgentLabels(ctx context.Context, q setup.Querier, n guardmodel.Names, role string, changes []guardmodel.LabelChange, restPublic bool, at time.Time) (int, error) {
	tx, err := pgxTx(q)
	if err != nil {
		return 0, err
	}
	return guard.WriteAgentLabels(ctx, tx, n, role, changes, restPublic, at)
}

// The classifier's reads.

func (Backend) PIIColumns(ctx context.Context, q setup.Querier, listed []piistore.Column) ([]piistore.Column, error) {
	return pgpii.Columns(ctx, q, listed)
}

func (Backend) PIISampler(q setup.Querier, timeout time.Duration, maxChars int) func(context.Context, piistore.Column) (piistore.Sample, error) {
	conn, err := pgxConnOf(q)
	if err != nil {
		return func(context.Context, piistore.Column) (piistore.Sample, error) { return piistore.Sample{}, err }
	}
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

// FetchChain reads the chain host:port presents with the TLS handshake alone.
func (Backend) FetchChain(ctx context.Context, host string, port int) ([]*x509.Certificate, error) {
	return trustpin.Fetch(ctx, nil, host, port)
}

// SuggestColumns runs the PII classifier over cols with its default
// options, keeping no value.
func (Backend) SuggestColumns(ctx context.Context, cols []piistore.Column, sample setup.SampleFunc) ([]setup.ColumnSuggestion, error) {
	results, err := pii.SuggestAll(ctx, cols, pii.SampleFunc(sample), pii.Options{})
	if err != nil {
		return nil, err
	}
	out := make([]setup.ColumnSuggestion, len(results))
	for i, r := range results {
		out[i] = setup.ColumnSuggestion{
			Column: r.Column, Class: r.Suggestion.Class, EntityType: r.Suggestion.EntityType,
			PhoneRegion: r.Suggestion.PhoneRegion, Reason: r.Suggestion.Reason,
		}
	}
	return out, nil
}

// The sample schema.

func (Backend) DemoTables() []string { return demo.Tables }

func (Backend) SeedDemo(ctx context.Context, q setup.Querier) (guardmodel.DemoPlan, error) {
	tx, err := pgxTx(q)
	if err != nil {
		return guardmodel.DemoPlan{}, err
	}
	return demo.Seed(ctx, tx)
}

func (Backend) DemoCounts(ctx context.Context, q setup.Querier) (int, int, error) {
	return demo.Counts(ctx, pgquerier.Unwrap(q))
}

// The admin and agent connections.

// conn is a pgx connection as the setup's Conn.
type conn struct{ c *pgx.Conn }

// tx is a pgx transaction, or a savepoint in one, as the setup's Tx.
type tx struct{ t pgx.Tx }

// Wrap is a connection pgx opened as the setup's Conn; an error stays the
// error, with no connection.
func Wrap(c *pgx.Conn, err error) (setup.Conn, error) {
	if err != nil {
		return nil, err
	}
	return conn{c}, nil
}

func (c conn) Port() setup.Querier                         { return pgquerier.Neutralize(c.c) }
func (c conn) Close(ctx context.Context) error             { return c.c.Close(ctx) }
func (c conn) Begin(ctx context.Context) (setup.Tx, error) { return begin(ctx, c.c) }

func (t tx) Port() setup.Querier                         { return pgquerier.Neutralize(t.t) }
func (t tx) Begin(ctx context.Context) (setup.Tx, error) { return begin(ctx, t.t) }
func (t tx) Commit(ctx context.Context) error            { return t.t.Commit(ctx) }

// Rollback of a transaction that already ended is not an error.
func (t tx) Rollback(ctx context.Context) error {
	if err := t.t.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

func begin(ctx context.Context, b interface {
	Begin(ctx context.Context) (pgx.Tx, error)
},
) (setup.Tx, error) {
	t, err := b.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return tx{t}, nil
}

// pgxConn is the pgx connection of a Conn this package made.
func pgxConn(c setup.Conn) *pgx.Conn {
	pc, ok := c.(conn)
	if !ok {
		panic("setupbackend: a connection this package did not open")
	}
	return pc.c
}

// pgxConnOf is the pgx connection a connection's query port runs on.
func pgxConnOf(q setup.Querier) (*pgx.Conn, error) {
	c, ok := pgquerier.Unwrap(q).(*pgx.Conn)
	if !ok {
		return nil, errors.New("setupbackend: the call needs a connection, not a transaction")
	}
	return c, nil
}

// pgxTx is the pgx transaction a transaction's query port runs on.
func pgxTx(q setup.Querier) (pgx.Tx, error) {
	t, ok := pgquerier.Unwrap(q).(pgx.Tx)
	if !ok {
		return nil, errors.New("setupbackend: the call needs a transaction, not a connection")
	}
	return t, nil
}
