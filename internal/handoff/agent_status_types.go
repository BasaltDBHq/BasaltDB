package handoff

// Problem codes of the status tool (api/mcp/errors/next-steps.json, problems).
const (
	problemSetupNotRun        = "SETUP_NOT_RUN"
	problemSetupExpired       = "SETUP_EXPIRED"
	problemSetupChangePending = "SETUP_CHANGE_PENDING"
	// The problems of a connect-only setup (CONTRACT.md, The engine and a
	// connect-only code).
	problemConfirmDatabase    = "CONFIRM_DATABASE"
	problemDatabaseRefused    = "DATABASE_REFUSED"
	problemUnreachableFromBot = "DATABASE_UNREACHABLE_FROM_BOT"
	problemSetupNotFound      = "SETUP_NOT_FOUND"
)

// Setup states of the status tool.
const (
	SetupNone    = "NONE"
	setupPending = "PENDING"
	SetupExpired = "EXPIRED"
	SetupDone    = "DONE"
	// setupConfirmDatabase: a connect-only setup's database was collected
	// and probed, and waits for the person's confirmation.
	setupConfirmDatabase = "CONFIRM_DATABASE"
	// setupRefused: the person said the collected database is not theirs.
	setupRefused = "REFUSED"
)
