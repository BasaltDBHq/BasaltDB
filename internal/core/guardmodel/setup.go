package guardmodel

import (
	"time"

	"github.com/google/uuid"
)

// Setup kinds (CONTRACT.md, The setup code).
const (
	SetupInstall = "INSTALL"
	SetupAgent   = "AGENT"
	SetupUpgrade = "UPGRADE"
)

// Setup is one setup code to record (guard.RecordSetupStatement).
type Setup struct {
	// ID is the code's setupId (a UUIDv7).
	ID   uuid.UUID
	Kind string
	// Agent is the agent's name (not its role); empty for SetupUpgrade.
	Agent string
	// GuardVersion is the code's guard.to.
	GuardVersion int
	ExpiresAt    time.Time
}

// AgentSetup is a setup recorded for the calling agent role (or an UPGRADE).
type AgentSetup struct {
	SetupID uuid.UUID
	Kind    string
}
