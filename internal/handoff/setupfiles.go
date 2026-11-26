package handoff

// AgentFiles reaches an agent's credential file, and for the setup
// finisher its .pending, its .lock and the engine config the finisher
// clears the setup from (FinishFiles): by path (handofffiles.PathFiles) or, started as
// root, through opened directories (handofffiles.RootFiles).
type AgentFiles interface {
	FinishFiles
	ReadCredential() (string, error)
	Close()
}
