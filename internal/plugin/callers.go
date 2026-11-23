package plugin

import "github.com/basaltdbhq/basaltdb/internal/config"

// KeepsEntries reports whether the engine keeps plugin entries of its own:
// a service engine, and an agent-operated engine that runs as the agent's
// own OS user (the bot's computer). A person-operated engine that runs as
// the person's own OS user keeps none (SAME_USER_MODE).
func KeepsEntries(cfg config.Config) bool {
	return cfg.Service() || cfg.AgentOperated()
}

// Callers are the OS users whose agents may change plugins: on a service
// engine the person's (personUids); on an agent-operated engine that runs
// as the agent's own OS user, that user, which every agent of the engine
// runs as. An agent-operated service engine admits nobody here:
// request_plugin refuses it AGENT_OPERATED before it asks.
func Callers(cfg config.Config, euid uint32) []uint32 {
	if cfg.Service() {
		return cfg.PersonUIDs
	}
	return []uint32{euid}
}
