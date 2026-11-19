package guard

import "github.com/google/uuid"

// AgentAdoptSQL is the SQL init runs before taking over an existing agent
// role, for tests that run it as an admin who is not a superuser.
func AgentAdoptSQL(n Names, agent string, spec AgentSpec) (string, error) {
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
func PluginEventsSQL(n Names) string { return n.render(migrations[versionPluginEvents-1].sql) }

// PluginTrustRemovedSQL is schema version 4's SQL as the install runs it.
func PluginTrustRemovedSQL(n Names) string {
	return n.render(migrations[versionPluginTrustRemoved-1].sql)
}

// PluginApprovalsSQL is schema version 5's SQL as the install runs it.
func PluginApprovalsSQL(n Names) string {
	return n.render(migrations[versionPluginApprovals-1].sql)
}
