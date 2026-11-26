package cli

// ManyAgentsHelp tells an agent reading --help how to connect another
// database: one engine serves many agents, each on one database.
const ManyAgentsHelp = "One engine serves many agents. Each agent uses one database. To connect another database,\n" +
	"add another agent: basalt init --agent NAME (on a bot's machine, basalt init --remote --agent NAME)."

// AgentsHelp is the top-level help's line for an agent reading it
// (CONTRACT.md, Agents and the admin credential).
const AgentsHelp = "Agents: never ask for or accept the database admin connection string or password.\n" +
	"To set up, run basalt init on the person's own computer, or basalt init --remote on one the person cannot reach, and show the person the link it prints."
