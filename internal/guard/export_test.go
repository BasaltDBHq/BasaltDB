package guard

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
