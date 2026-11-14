package guard

// VersionSetups is the guard version that added record_setup.
const VersionSetups = versionSetups

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

// VersionRevertScope is basalt_meta version 20, for the migration tests.
const VersionRevertScope = versionRevertScope

// VersionPinnedTrigger is basalt_meta version 34, for the migration tests.
const VersionPinnedTrigger = versionPinnedTrigger

// VersionPinnedReverts is basalt_meta version 35, for the migration tests.
const VersionPinnedReverts = versionPinnedReverts

// VersionReinstalls is basalt_meta version 36, for the migration tests.
const VersionReinstalls = versionReinstalls

// ReportRow and InstallRecord are what ReadReinstalls reads, for the tests
// of AssembleReinstalls.
type (
	ReportRow     = reportRow
	InstallRecord = installRecord
)

// AssembleReinstalls is assembleReinstalls.
func AssembleReinstalls(self string, rows []ReportRow, recs map[uint32]InstallRecord, kept []SetAside) Reinstalls {
	return assembleReinstalls(self, rows, recs, kept)
}
