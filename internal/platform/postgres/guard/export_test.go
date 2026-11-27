package guard

import (
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// AgentAdoptSQL is the SQL init runs before taking over an existing agent
// role, for tests that run it as an admin who is not a superuser.
func AgentAdoptSQL(n guardmodel.Names, agent string, spec guardmodel.AgentSpec) (string, error) {
	role, err := n.Agent(agent)
	if err != nil {
		return "", err
	}
	st, err := agentAdoptStatement(n, role, spec)
	return st.SQL, err
}

// ReportRow and InstallRecord are what ReadReinstalls reads, for the tests
// of AssembleReinstalls.
type (
	ReportRow     = reportRow
	InstallRecord = installRecord
)

// AssembleReinstalls is assembleReinstalls.
func AssembleReinstalls(self string, rows []ReportRow, recs map[uuid.UUID]InstallRecord, kept []SetAside) Reinstalls {
	return assembleReinstalls(self, rows, recs, kept)
}

// PluginEventsSQL is schema version 3's SQL as the install runs it, for the
// test that runs it twice.
func PluginEventsSQL(n guardmodel.Names) string {
	return renderSQL(n, migrations[versionPluginEvents-1].sql)
}

// PluginTrustRemovedSQL is schema version 4's SQL as the install runs it.
func PluginTrustRemovedSQL(n guardmodel.Names) string {
	return renderSQL(n, migrations[versionPluginTrustRemoved-1].sql)
}

// PluginApprovalsSQL is schema version 5's SQL as the install runs it.
func PluginApprovalsSQL(n guardmodel.Names) string {
	return renderSQL(n, migrations[versionPluginApprovals-1].sql)
}

// ReleaseVersion is the version that adds schema_version.release, for the
// test of an update from before it.
const ReleaseVersion = versionRelease

// StoreNeutralSQL is schema version 10's SQL as the install runs it.
func StoreNeutralSQL(n guardmodel.Names) string {
	return renderSQL(n, migrations[versionStoreNeutral-1].sql)
}

// ScopeRefusal returns the detail (ScopeShape, ScopeNotOwnRun, ...) and the
// guard's explanation of a SCOPE_REFUSED error, and false for any other
// error.
func ScopeRefusal(err error) (detail, hint string, ok bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != sqlstateScopeRefused {
		return "", "", false
	}
	return pg.Detail, pg.Hint, true
}
