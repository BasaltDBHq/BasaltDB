package handoff

const (
	ProblemSetupNotRun = "SETUP_NOT_RUN"
)

const (
	ProblemSetupExpired = "SETUP_EXPIRED"
)

const (
	ProblemSetupChangePending = "SETUP_CHANGE_PENDING"
)

const (
	// The problems of a connect-only setup (CONTRACT.md, The engine and a
	// connect-only code).
	ProblemConfirmDatabase = "CONFIRM_DATABASE"
)

const (
	ProblemDatabaseRefused = "DATABASE_REFUSED"
)

const (
	ProblemUnreachableFromBot = "DATABASE_UNREACHABLE_FROM_BOT"
)

const (
	ProblemSetupNotFound = "SETUP_NOT_FOUND"
)

// Setup states of the status tool.
const (
	SetupNone    = "NONE"
	SetupPending = "PENDING"
	SetupExpired = "EXPIRED"
	SetupDone    = "DONE"
	// setupConfirmDatabase: a connect-only setup's database was collected
	// and probed, and waits for the person's confirmation.
	SetupConfirmDatabase = "CONFIRM_DATABASE"
	// setupRefused: the person said the collected database is not theirs.
	SetupRefused = "REFUSED"
)
