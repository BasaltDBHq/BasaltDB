// Package setupbackend is the setup page's access to the person's
// Postgres, the connection and its trust, and the engine's trust files: it
// forwards each call of the setup's Backend to the adapter that does it.
package setupbackend

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/demo"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/trustdir"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/service/setuprun"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Backend implements the setup's Backend with the engine's adapters.
// Backend implements localsetup's Backend and setuprun's. It registers itself
// with setuprun, so an engine that imports this package runs setups on it.
type Backend struct{}

func init() { setuprun.Use(Backend{}) }

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

func (Backend) InstalledPrefix(ctx context.Context, q setuprun.Querier) (string, error) {
	return guard.InstalledPrefix(ctx, q)
}

func (Backend) InstalledVersion(ctx context.Context, q setuprun.Querier) (int, error) {
	return guard.InstalledVersion(ctx, q)
}
func (Backend) LatestVersion() int                 { return guard.LatestVersion() }
func (Backend) Migrations() []guardmodel.Migration { return guard.Migrations() }
func (Backend) AgentStatus(ctx context.Context, q setuprun.Querier, migs []guardmodel.Migration) (guardmodel.Status, error) {
	return guard.AgentStatus(ctx, q, migs)
}

func (Backend) AgentRoleExists(ctx context.Context, q setuprun.Querier, n guardmodel.Names, agent string) (bool, error) {
	return guard.AgentRoleExists(ctx, q, n, agent)
}

func (Backend) AgentBlindTables(ctx context.Context, q setuprun.Querier, n guardmodel.Names, spec guardmodel.AgentSpec) ([]setuprun.BlindTable, error) {
	blind, err := guard.AgentBlindTables(ctx, q, n, spec)
	return fromBlind(blind), err
}

func (Backend) PlanInit(ctx context.Context, q setuprun.Querier, opts setuprun.InitOptions) (setuprun.Script, error) {
	script, err := guard.PlanInit(ctx, q, guard.InitOptions{Names: opts.Names, Agent: opts.Agent, AgentPolicies: toBlind(opts.AgentPolicies), UpTo: opts.UpTo})
	return fromScript(script), err
}

func (Backend) RepairScript(n guardmodel.Names, agent, password string, timeoutMs int64) (setuprun.Script, error) {
	script, err := guard.RepairScript(n, agent, password, timeoutMs)
	return fromScript(script), err
}

func (Backend) CheckUsable(ctx context.Context, q setuprun.Querier) error {
	return guard.CheckUsable(ctx, q)
}
func (Backend) UnusableInstall(err error) bool { return errors.Is(err, guard.ErrUnusableInstall) }
func (Backend) RemoveOldInstallDoc() string    { return guard.RemoveOldInstallDoc }
func (Backend) NewPassword() string            { return guard.NewPassword() }
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

func (Backend) ActivePasskeys(ctx context.Context, q setuprun.Querier) ([]setuprun.RegisteredPasskey, error) {
	keys, err := guard.ActivePasskeys(ctx, q)
	out := make([]setuprun.RegisteredPasskey, len(keys))
	for i, k := range keys {
		out[i] = setuprun.RegisteredPasskey(k)
	}
	return out, err
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

func (Backend) DemoSchema() string   { return demo.Schema }
func (Backend) DemoTables() []string { return demo.Tables }
func (Backend) SeedDemo(ctx context.Context, tx pgx.Tx) (setuprun.DemoPlan, error) {
	plan, err := demo.Seed(ctx, tx)
	return setuprun.DemoPlan(plan), err
}

func (Backend) DemoCounts(ctx context.Context, q setuprun.Querier) (int, int, error) {
	return demo.Counts(ctx, q)
}

func fromScript(s guard.Script) setuprun.Script {
	out := setuprun.Script{Statements: make([]setuprun.Statement, len(s.Statements)), Warnings: s.Warnings}
	for i, st := range s.Statements {
		out.Statements[i] = setuprun.Statement(st)
	}
	return out
}

func fromBlind(in []guard.BlindTable) []setuprun.BlindTable {
	if in == nil {
		return nil
	}
	out := make([]setuprun.BlindTable, len(in))
	for i, b := range in {
		out[i] = setuprun.BlindTable(b)
	}
	return out
}

func toBlind(in []setuprun.BlindTable) []guard.BlindTable {
	if in == nil {
		return nil
	}
	out := make([]guard.BlindTable, len(in))
	for i, b := range in {
		out[i] = guard.BlindTable(b)
	}
	return out
}

// The rest of setuprun.Backend.

func (Backend) StatusAt(installed int, migs []guardmodel.Migration) guardmodel.Status {
	return guard.StatusAt(installed, migs)
}

func (Backend) SetupsFor(ctx context.Context, q setuprun.Querier, id uuid.UUID, role string) ([]setupcode.RecordedSetup, error) {
	return guard.SetupsFor(ctx, q, id, role)
}

func (Backend) RecordSetupStatement(n guardmodel.Names, s guardmodel.Setup) (setuprun.Statement, error) {
	st, err := guard.RecordSetupStatement(n, s)
	return setuprun.Statement(st), err
}

func (Backend) SetupRefusal(err error) (string, bool) { return guard.SetupRefusal(err) }

func (Backend) AgentRoles(ctx context.Context, q setuprun.Querier, n guardmodel.Names) ([]string, error) {
	return guard.AgentRoles(ctx, q, n)
}

func (Backend) RoleStatementTimeout(ctx context.Context, q setuprun.Querier, role string) (setuprun.RoleTimeouts, error) {
	t, err := guard.RoleStatementTimeout(ctx, q, role)
	return setuprun.RoleTimeouts(t), err
}

func (Backend) GrantedTables(ctx context.Context, q setuprun.Querier, role string) ([]string, error) {
	return guard.GrantedTables(ctx, q, role)
}

func (Backend) AllTablesIn(ctx context.Context, q setuprun.Querier, schema string) (setuprun.SchemaTables, error) {
	t, err := guard.AllTablesIn(ctx, q, schema)
	return setuprun.SchemaTables(t), err
}

func (Backend) RLSBlindTables(ctx context.Context, q setuprun.Querier, role string, tables []string) ([]string, error) {
	return guard.RLSBlindTables(ctx, q, role, tables)
}

func (Backend) MissingTables(err error) ([]string, bool) {
	var missing *guard.MissingTablesError
	if !errors.As(err, &missing) {
		return nil, false
	}
	return missing.Tables, true
}

func (Backend) PlanUninstall(ctx context.Context, q setuprun.Querier, n guardmodel.Names) ([]string, error) {
	return guard.PlanUninstall(ctx, q, n)
}

func (Backend) UncoveredTables(ctx context.Context, q setuprun.Querier) ([]setuprun.Uncovered, error) {
	list, err := guard.UncoveredTables(ctx, q)
	out := make([]setuprun.Uncovered, len(list))
	for i, u := range list {
		out[i] = setuprun.Uncovered(u)
	}
	return out, err
}

func (Backend) Engines(ctx context.Context, q setuprun.Querier, admin bool) ([]setuprun.RecordedEngine, error) {
	list, err := guard.Engines(ctx, q, admin)
	out := make([]setuprun.RecordedEngine, len(list))
	for i, e := range list {
		out[i] = setuprun.RecordedEngine(e)
	}
	return out, err
}

func (Backend) RecordEngineStatement(publicKey []byte, guardVersion int) setuprun.Statement {
	return setuprun.Statement(guard.RecordEngineStatement(publicKey, guardVersion))
}

func (Backend) DemoPlanDrop(ctx context.Context, q setuprun.Querier) ([]string, error) {
	return demo.PlanDrop(ctx, q)
}

func (Backend) DemoApplyDrop(ctx context.Context, tx pgx.Tx, drops []string) (bool, error) {
	return demo.ApplyDrop(ctx, tx, drops)
}
